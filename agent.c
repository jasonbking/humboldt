/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <synch.h>
#include <thread.h>
#include <string.h>
#include <strings.h>
#include <ucred.h>
#include <priv.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <dirent.h>
#include <port.h>

#include "softtoken.h"
#include "bunyan.h"
#include "libssh/sshbuf.h"
#include "libssh/sshkey.h"
#include "libssh/authfd.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>

/*
 * This is the "agent" process in the soft-token. It is forked off by the
 * "supervisor" process and is responsible for listening for clients on the
 * UNIX socket the supervisor bound inside the zone, dealing with clients, and
 * performing crypto operations for the clients inside the zone.
 *
 * Key material is provided to the agent by the supervisor on an as-needed
 * basis, by decrypting it and placing into shared pages. When the agent is
 * done using the key material, the supervisor clears the pages again. We get
 * the addresses of the allocated shared pages by looking in the "token_slots"
 * global linked list, which the supervisor built up before forking to create
 * us.
 *
 * The agent is multi-threaded in order to deal with multiple clients
 * effectively. We start up a pool of threads (currently fixed size) that all
 * loop in port_get() handling clients. Whichever thread finishes reading in
 * an entire command from the client does the crypto operations associated with
 * it, begins to write out the reply, and then returns to port_get().
 *
 * The other thing the supervisor provides us with after forking is one end of
 * a pipe() that we use to communicate with it. We can send commands on the
 * pipe to ask the supervisor to lock and unlock keys (and populate or zero the
 * shared memory segments associated). We currently manage the use of this
 * pipe through the main thread which also handles accept()ing new connections.
 *
 * The protocol we speak to clients of the UDS is the OpenSSH agent protocol.
 * We re-use a lot of code from OpenSSH here, and you'll see similarities in the
 * overall approach we take to dealing with data and crypto. "ssh-agent.c" is
 * a good place to cross-reference to understand the protocol and operations.
 */

enum port_events {
	EVENT_WANT_UNLOCK = 1,
	EVENT_WANT_LOCK,
	EVENT_STOP
};

struct client_state {
	zoneid_t cs_zid;
	int cs_fd;
	struct sockaddr_un cs_peer;
	ucred_t *cs_ucred;
	struct sshbuf *cs_in;
	struct sshbuf *cs_out;
	struct sshbuf *cs_req;
	int cs_events;
	struct client_state *cs_next;
	struct client_state *cs_prev;
};

enum as_state {
	AS_UNLOCKED,
	AS_LOCKING,
	AS_LOCKED,
	AS_UNLOCKING
};
struct agent_slot {
	mutex_t as_mtx;
	uint8_t as_cookie;
	enum as_state as_state;
	cond_t as_stchg;
	struct timespec as_lastused;
	struct timespec as_renew;
	size_t as_ref;
	uint8_t as_renew_cookie;
};

static int acport;
static int mport;
static uint8_t last_cookie;

static mutex_t clients_mtx;
static struct client_state *clients;
static int clport;

static const char *zone_uuid;
static const char *zone_alias;
static const char *zone_owner;
static nvlist_t *zone_tags;

#define	N_THREADS	8
static thread_t reactor_threads[N_THREADS];
static thread_t acceptor_thread;

extern void tspec_subtract(struct timespec *result, const struct timespec *x,
    const struct timespec *y);

static inline uint8_t
next_cookie(void)
{
	if (++last_cookie == 0)
		return (++last_cookie);
	return (last_cookie);
}

static void
close_client(struct client_state *cl)
{
	mutex_enter(&clients_mtx);
	if (cl->cs_prev != NULL)
		cl->cs_prev->cs_next = cl->cs_next;
	if (cl->cs_next != NULL)
		cl->cs_next->cs_prev = cl->cs_prev;
	if (clients == cl)
		clients = cl->cs_next;
	mutex_exit(&clients_mtx);

	VERIFY0(close(cl->cs_fd));
	cl->cs_events = 0;
	sshbuf_free(cl->cs_in);
	sshbuf_free(cl->cs_out);
	ucred_free(cl->cs_ucred);
	if (cl->cs_req != NULL)
		sshbuf_free(cl->cs_req);
	free(cl);
}

enum msg_err {
	ERR_NOERROR = 0,
	ERR_INCOMPLETE,
	ERR_BADMSG
};

static void
send_status(struct client_state *cl, boolean_t success)
{
	VERIFY0(sshbuf_put_u32(cl->cs_out, 1));
	VERIFY0(sshbuf_put_u8(cl->cs_out, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE));
}

static void
process_request_identities(struct client_state *cl)
{
	struct sshbuf *msg;
	struct token_slot *slot;
	size_t n = 0;
	char namebuf[256];

	msg = sshbuf_new();
	VERIFY3P(msg, !=, NULL);

	for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
		n++;
		if (slot->ts_type == SLOT_ASYM_AUTH &&
		    slot->ts_certdata->tsd_len > 0) {
			n++;
		}
		if (slot->ts_type == SLOT_ASYM_AUTH &&
		    slot->ts_chaindata->tsd_len > 0) {
			n++;
		}
	}

	VERIFY0(sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER));
	VERIFY0(sshbuf_put_u32(msg, n));

	for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
		u_char *blob;
		size_t blen;

		VERIFY0(sshkey_to_blob(slot->ts_public, &blob, &blen));
		VERIFY0(sshbuf_put_string(msg, blob, blen));
		free(blob);

		VERIFY0(sshbuf_put_cstring(msg, slot->ts_name));

		if (slot->ts_type == SLOT_ASYM_AUTH &&
		    slot->ts_certdata->tsd_len > 0) {
			VERIFY0(sshbuf_put_string(msg,
			    slot->ts_certdata->tsd_data,
			    slot->ts_certdata->tsd_len));
			strlcpy(namebuf, slot->ts_name, sizeof (namebuf));
			strlcat(namebuf, "-cert", sizeof (namebuf));
			VERIFY0(sshbuf_put_cstring(msg, namebuf));
		}
		if (slot->ts_type == SLOT_ASYM_AUTH &&
		    slot->ts_chaindata->tsd_len > 0) {
			VERIFY0(sshbuf_put_string(msg,
			    slot->ts_chaindata->tsd_data,
			    slot->ts_chaindata->tsd_len));
			strlcpy(namebuf, slot->ts_name, sizeof (namebuf));
			strlcat(namebuf, "-parent-cert", sizeof (namebuf));
			VERIFY0(sshbuf_put_cstring(msg, namebuf));
		}
	}
	VERIFY0(sshbuf_put_stringb(cl->cs_out, msg));
	sshbuf_free(msg);
}

static int
validate_cert_payload(struct client_state *cl, struct token_slot *slot,
    u_char *data, size_t dlen)
{
	X509_CINF *cinf = NULL;
	X509_NAME *issu, *subj, *nm;
	X509_NAME_ENTRY *ent;
	ASN1_OBJECT *obj;
	X509_EXTENSION *ext;
	time_t *tm;
	ASN1_STRING *str;
	const char *d, *ou;
	u_char *ptr;
	size_t len;
	int nid, i, count, kcnt, ki;
	char tmp[256];
	const char *uuid = NULL, *hostname = NULL;
	boolean_t issu_has_uuid = B_FALSE, subj_has_uuid = B_FALSE,
	    subj_has_title = B_FALSE, has_basic = B_FALSE, has_ku = B_FALSE;

	/*
	 * The node-sshpk-agent code sends a "test" string to decide whether
	 * we actually support RSA with SHA256 or not.
	 */
	if (dlen == 4 && bcmp(data, "test", 4) == 0) {
		return (0);
	}

	ptr = data;
	if (d2i_X509_CINF(&cinf, &ptr, dlen) == NULL) {
		char errbuf[128];
		unsigned long err = ERR_peek_last_error();
		ERR_load_crypto_strings();
		ERR_error_string(err, errbuf);

		bunyan_log(WARN, "d2i_X509_CINF on sign payload failed",
		    "openssl_err", BNY_STRING, errbuf,
		    NULL);
		return (EINVAL);
	}
	VERIFY(cinf != NULL);

	if (ptr < (data + dlen)) {
		bunyan_log(WARN, "sign payload has extra data",
		    "payload_len", BNY_UINT, dlen,
		    "consumed", BNY_UINT, (ptr - data),
		    NULL);
		X509_CINF_free(cinf);
		return (EINVAL);
	}

	if (OBJ_obj2nid(cinf->signature->algorithm) !=
	    NID_sha256WithRSAEncryption) {
		bunyan_log(WARN, "sign payload sets wrong algo",
		    "nid", BNY_INT, cinf->signature->algorithm,
		    NULL);
		X509_CINF_free(cinf);
		return (EINVAL);
	}

	if (X509_cmp_current_time(cinf->validity->notBefore) > 0)
		goto err;
	if (X509_cmp_current_time(cinf->validity->notAfter) <= 0)
		goto err;

	tm = time(NULL);
	tm += 305;
	if (X509_cmp_time(cinf->validity->notAfter, tm) >= 0)
		goto err;

	issu = cinf->issuer;
	subj = cinf->subject;

	if (cl->cs_zid == GLOBAL_ZONEID) {
		uuid = getenv("SYSTEM_UUID");
		VERIFY(uuid != NULL);
		VERIFY3U(strlen(uuid), >, 0);

		hostname = getenv("SYSTEM_HOSTNAME");
		VERIFY(hostname != NULL);

		count = X509_NAME_entry_count(issu);
		for (i = 0; i < count; ++i) {
			ent = X509_NAME_get_entry(issu, i);
			VERIFY(ent != NULL);

			obj = X509_NAME_ENTRY_get_object(ent);
			VERIFY(obj != NULL);
			str = X509_NAME_ENTRY_get_data(ent);
			VERIFY(str != NULL);
			d = ASN1_STRING_data(str);
			VERIFY(d != NULL);

			switch (OBJ_obj2nid(obj)) {
			case NID_commonName:
				if (strcmp(d, hostname) != 0)
					goto err;
				break;
			case NID_title:
				if (strcmp(d, slot->ts_name) != 0)
					goto err;
				break;
			case NID_userId:
				if (strcmp(d, uuid) != 0)
					goto err;
				issu_has_uuid = B_TRUE;
				break;
			case NID_domainComponent:
				if (strcmp(d, getenv("SYSTEM_DC")) != 0)
					goto err;
				break;
			default:
				goto err;
			}
		}

	} else {
		count = X509_NAME_entry_count(issu);
		for (i = 0; i < count; ++i) {
			ent = X509_NAME_get_entry(issu, i);
			VERIFY(ent != NULL);

			obj = X509_NAME_ENTRY_get_object(ent);
			VERIFY(obj != NULL);
			str = X509_NAME_ENTRY_get_data(ent);
			VERIFY(str != NULL);
			d = ASN1_STRING_data(str);
			VERIFY(d != NULL);

			switch (OBJ_obj2nid(obj)) {
			case NID_commonName:
				if (strcmp(d, zone_uuid) != 0)
					goto err;
				issu_has_uuid = B_TRUE;
				break;
			case NID_title:
				if (strcmp(d, slot->ts_name) != 0)
					goto err;
				break;
			case NID_userId:
				if (strcmp(d, zone_owner) != 0)
					goto err;
				break;
			case NID_domainComponent:
				if (strcmp(d, getenv("SYSTEM_DC")) != 0)
					goto err;
				break;
			default:
				goto err;
			}
		}
	}

	if (!issu_has_uuid)
		goto err;

	if (cl->cs_zid == GLOBAL_ZONEID) {
		X509_CINF_free(cinf);
		return (0);
	}

	count = X509_NAME_entry_count(subj);
	for (i = 0; i < count; ++i) {
		ent = X509_NAME_get_entry(subj, i);
		VERIFY(ent != NULL);

		obj = X509_NAME_ENTRY_get_object(ent);
		VERIFY(obj != NULL);
		str = X509_NAME_ENTRY_get_data(ent);
		VERIFY(str != NULL);
		d = ASN1_STRING_data(str);
		VERIFY(d != NULL);

		switch (OBJ_obj2nid(obj)) {
		case NID_commonName:
			if (strcmp(d, zone_uuid) != 0)
				goto err;
			subj_has_uuid = B_TRUE;
			break;
		case NID_title:
			if (strcmp(d, "in-zone.key") != 0)
				goto err;
			subj_has_title = B_TRUE;
			break;
		case NID_userId:
			if (strcmp(d, zone_owner) != 0)
				goto err;
			break;
		case NID_domainComponent:
			if (strcmp(d, getenv("SYSTEM_DC")) != 0)
				goto err;
			break;
		case NID_organizationalUnitName:
			if (!nvlist_lookup_string(zone_tags, "sdc_role", &ou) &&
			    strcmp(d, ou) == 0) {
				break;
			}
			if (!nvlist_lookup_string(zone_tags, "manta_role",
			    &ou) && strcmp(d, ou) == 0) {
				break;
			}
			if (!nvlist_lookup_string(zone_tags, "role", &ou)) {
				const size_t rlen = strlen(d);
				const char *ptr = strstr(ou, d);
				if (ptr != NULL && (ptr == ou ||
				    *(ptr - 1) == ',') && (ptr[rlen] == ',' ||
				    ptr[rlen] == '\0')) {
					break;
				}
			}
			goto err;
		default:
			goto err;
		}
	}

	if (!subj_has_uuid || !subj_has_title)
		goto err;

	count = X509v3_get_ext_count(cinf->extensions);
	if (count < 1)
		goto err;
	for (i = 0; i < count; ++i) {
		BASIC_CONSTRAINTS *basic;
		ASN1_BIT_STRING *keyusage;

		ext = X509v3_get_ext(cinf->extensions, i);
		VERIFY(ext != NULL);

		obj = X509_EXTENSION_get_object(ext);
		VERIFY(obj != NULL);

		switch (OBJ_obj2nid(obj)) {
		case NID_basic_constraints:
			basic = (BASIC_CONSTRAINTS *)X509V3_EXT_d2i(ext);
			if (basic->ca != 0) {
				BASIC_CONSTRAINTS_free(basic);
				goto err;
			}
			has_basic = B_TRUE;
			BASIC_CONSTRAINTS_free(basic);
			break;
		case NID_key_usage:
			keyusage = (ASN1_BIT_STRING *)X509V3_EXT_d2i(ext);
			/* Bit 5 = keyCertSign */
			if (ASN1_BIT_STRING_get_bit(keyusage, 5)) {
				ASN1_BIT_STRING_free(keyusage);
				goto err;
			}
			/* Bit 6 = cRLSign */
			if (ASN1_BIT_STRING_get_bit(keyusage, 6)) {
				ASN1_BIT_STRING_free(keyusage);
				goto err;
			}
			has_ku = B_TRUE;
			ASN1_BIT_STRING_free(keyusage);
			break;
		case NID_ext_key_usage:
			break;
		default:
			goto err;
		}
	}

	if (!has_basic || !has_ku)
		goto err;

	X509_CINF_free(cinf);
	return (0);

err:
	X509_CINF_free(cinf);
	return (EPERM);

}

static void
process_sign_request(struct client_state *cl)
{
	struct sshbuf *msg, *kbuf;
	struct sshkey *key;
	struct sshkey *privkey;
	struct token_slot *slot;
	u_char *blob, *data, *sig = NULL;
	size_t blen, dlen, slen = 0;
	int rv;
	uint32_t flags, compat = 0;
	struct agent_slot *a;
	const char *alg = NULL;

	VERIFY0(sshbuf_get_string(cl->cs_req, &blob, &blen));
	VERIFY0(sshbuf_get_string(cl->cs_req, &data, &dlen));
	VERIFY0(sshbuf_get_u32(cl->cs_req, &flags));

	/*if (flags & SSH_AGENT_OLD_SIGNATURE)
		compat = SSH_BUG_SIGBLOB;*/

	VERIFY0(sshkey_from_blob(blob, blen, &key));
	for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
		if (sshkey_equal_public(key, slot->ts_public))
			break;
	}
	if (slot == NULL) {
		send_status(cl, B_FALSE);
		goto out;
	}

	switch (slot->ts_type) {
	case SLOT_ASYM_CERT_SIGN:
		rv = validate_cert_payload(cl, slot, data, dlen);
		if (rv != 0) {
			send_status(cl, B_FALSE);
			goto out;
		}
		break;
	case SLOT_ASYM_AUTH:
		break;
	default:
		send_status(cl, B_FALSE);
		goto out;
	}

	a = slot->ts_agent;
	mutex_enter(&a->as_mtx);

	/*
	 * The shared pages are mapped PROT_NONE on our side until the data is
	 * in use. While the refcount > 0, we change it to PROT_READ. Whichever
	 * thread is responsible for decrementing the refcnt to 0 changes it
	 * back to PROT_NONE.
	 *
	 * This way while the key material is waiting to be re-locked (during
	 * the 5-sec timeout period), it's not trivially readable in this
	 * process.
	 */
	if (++a->as_ref == 1) {
		VERIFY0(mprotect(slot->ts_data, slot->ts_datasize, PROT_READ));
	}

	VERIFY0(clock_gettime(CLOCK_MONOTONIC, &a->as_lastused));

	/*
	 * Wait until the key is unlocked. Send the message to the main thread
	 * to request the unlock if necessary.
	 */
	while (a->as_state != AS_UNLOCKED) {
		if (a->as_state == AS_LOCKED) {
			a->as_cookie = next_cookie();
			a->as_state = AS_UNLOCKING;
			VERIFY0(port_send(mport, EVENT_WANT_UNLOCK, slot));
			VERIFY0(cond_broadcast(&a->as_stchg));
		}
		do {
			rv = cond_wait(&a->as_stchg, &a->as_mtx);
		} while (rv == EINTR);
		VERIFY0(rv);
	}
	VERIFY3U(a->as_state, ==, AS_UNLOCKED);
	VERIFY3U(slot->ts_data->tsd_len, >, 0);

	mutex_exit(&a->as_mtx);

	kbuf = sshbuf_from((const void *)slot->ts_data->tsd_data,
	    slot->ts_data->tsd_len);
	VERIFY3P(kbuf, !=, NULL);
	VERIFY0(sshkey_private_deserialize(kbuf, &privkey));
	sshbuf_free(kbuf);

	/* We're done with the shared memory now, so we can release it. */
	mutex_enter(&a->as_mtx);
	if (--a->as_ref == 0) {
		VERIFY0(mprotect(slot->ts_data, slot->ts_datasize, PROT_NONE));
	}
	mutex_exit(&a->as_mtx);

	if (privkey->type == KEY_RSA) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			alg = "rsa-sha2-256";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			alg = "rsa-sha2-512";
	}
	VERIFY0(sshkey_sign(privkey, &sig, &slen, data, dlen, alg, compat));
	sshkey_free(privkey);

	msg = sshbuf_new();
	VERIFY3P(msg, !=, NULL);

	VERIFY0(sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE));
	VERIFY0(sshbuf_put_string(msg, sig, slen));
	VERIFY0(sshbuf_put_stringb(cl->cs_out, msg));

	sshbuf_free(msg);
out:
	free(blob);
	free(data);
	sshkey_free(key);
	if (sig != NULL)
		explicit_bzero(sig, slen);
	free(sig);
}

static int
try_process_message(struct client_state *cl)
{
	const uint8_t *cp;
	size_t len;
	int rv;
	uint8_t type;
	pid_t clientpid;

	if (sshbuf_len(cl->cs_in) < 5)
		return (ERR_INCOMPLETE);

	cp = sshbuf_ptr(cl->cs_in);
	len = cp[0] << 24 | cp[1] << 16 | cp[2] << 8 | cp[3];
	if (len > 256 * 1024) {
		close_client(cl);
		return (ERR_BADMSG);
	}

	if (sshbuf_len(cl->cs_in) < len + 4)
		return (ERR_INCOMPLETE);

	sshbuf_reset(cl->cs_req);
	rv = sshbuf_get_stringb(cl->cs_in, cl->cs_req);
	VERIFY0(rv);
	rv = sshbuf_get_u8(cl->cs_req, &type);
	VERIFY0(rv);

	bunyan_set(
	    "client_pid", BNY_INT, (int)ucred_getpid(cl->cs_ucred),
	    "client_euid", BNY_INT, (int)ucred_geteuid(cl->cs_ucred),
	    "type", BNY_INT, (int)type,
	    NULL);

	bunyan_log(TRACE, "processing message from client", NULL);

	switch (type) {
	case SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request(cl);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(cl);
		break;
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
		break;
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
	case SSH2_AGENTC_REMOVE_IDENTITY:
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		bunyan_log(DEBUG, "unsupported operation", NULL);
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
		break;
	default:
		bunyan_log(ERROR, "client sent unknown message type", NULL);
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
	}
	return (0);
}

struct acceptor_args {
	zoneid_t a_zid;
	int a_listensock;
};

static void *
accept_reactor(void *arg)
{
	int rv;
	int sockfd, listensock;
	struct client_state *cl;
	struct sockaddr_un raddr;
	size_t raddrlen;
	port_event_t ev;
	struct acceptor_args *args;
	zoneid_t zid, theirzid;

	VERIFY(arg != NULL);
	args = (struct acceptor_args *)arg;

	listensock = args->a_listensock;
	zid = args->a_zid;

	while (1) {
		rv = port_get(acport, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			assert(rv == 0);
		}

		if (ev.portev_source == PORT_SOURCE_USER) {
			if (ev.portev_events == EVENT_STOP) {
				return (NULL);
			}
			VERIFY0(ev.portev_events);
			continue;
		}

		VERIFY3S(ev.portev_source, ==, PORT_SOURCE_FD);
		VERIFY3S(ev.portev_object, ==, listensock);

		/* A new connection has arrived. */
		raddrlen = sizeof (raddr);
		bzero(&raddr, sizeof (raddr));
		sockfd = accept(listensock, (struct sockaddr *)&raddr,
		    &raddrlen);
		assert(sockfd > 0);

		cl = calloc(1, sizeof (struct client_state));
		assert(cl != NULL);
		bcopy(&raddr, &cl->cs_peer, raddrlen);
		if (getpeerucred(sockfd, &cl->cs_ucred) != 0) {
			bunyan_log(ERROR,
			    "failed to get peer ucred",
			    "errno", BNY_INT, errno, NULL);
			free(cl);
			assert(close(sockfd) == 0);
			goto rearmlisten;
		}
		theirzid = ucred_getzoneid(cl->cs_ucred);
		if (theirzid != zid) {
			bunyan_log(ERROR,
			    "zoneid of client doesn't match server",
			    "client_zoneid", BNY_INT, theirzid, NULL);
			free(cl);
			VERIFY0(close(sockfd));
			goto rearmlisten;
		}
		cl->cs_zid = zid;
		cl->cs_fd = sockfd;
		cl->cs_in = sshbuf_new();
		assert(cl->cs_in != NULL);
		cl->cs_out = sshbuf_new();
		assert(cl->cs_in != NULL);
		cl->cs_req = sshbuf_new();
		assert(cl->cs_in != NULL);
		cl->cs_events = POLLIN;

		mutex_enter(&clients_mtx);
		if (clients != NULL)
			clients->cs_prev = cl;
		cl->cs_next = clients;
		clients = cl;
		mutex_exit(&clients_mtx);

		VERIFY0(port_associate(clport,
		    PORT_SOURCE_FD, cl->cs_fd, cl->cs_events, cl));
rearmlisten:
		VERIFY0(port_associate(acport,
		    PORT_SOURCE_FD, listensock, POLLIN, NULL));
	}
}

static void *
client_reactor(void *arg)
{
	port_event_t ev;
	timespec_t to;
	struct client_state *cl;
	size_t len;
	char *buf = calloc(1, 4096);
	int buflen = 4096;
	int rv;
	assert(buf != NULL);

	while (1) {
		rv = port_get(clport, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			assert(rv == 0);
		}

		if (ev.portev_source == PORT_SOURCE_USER) {
			if (ev.portev_events == EVENT_STOP) {
				return (NULL);
			}
			VERIFY0(ev.portev_events);
			continue;
		}

		cl = (struct client_state *)ev.portev_user;
		assert(cl != NULL);
		assert(cl->cs_fd == ev.portev_object);
		cl->cs_events = POLLIN;

		if ((ev.portev_events & POLLOUT) != 0 &&
		    sshbuf_len(cl->cs_out) > 0) {
			len = write(cl->cs_fd,
			    sshbuf_ptr(cl->cs_out),
			    sshbuf_len(cl->cs_out));
			if (len == -1 && (errno == EAGAIN ||
			    errno == EWOULDBLOCK || errno == EINTR)) {
				cl->cs_events |= POLLOUT;
				goto rearm;
			}
			if (len <= 0) {
				close_client(cl);
				continue;
			}
			VERIFY0(sshbuf_consume(cl->cs_out, len));
			if (sshbuf_len(cl->cs_out) > 0)
				cl->cs_events |= POLLOUT;
		}

		if ((ev.portev_events & POLLIN) != 0) {
			len = read(cl->cs_fd, buf, buflen);
			if (len == -1 && (errno == EAGAIN ||
			    errno == EWOULDBLOCK || errno == EINTR)) {
				goto rearm;
			}
			if (len <= 0) {
				close_client(cl);
				continue;
			}
			VERIFY0(sshbuf_put(cl->cs_in, buf, len));
			explicit_bzero(buf, len);
			rv = try_process_message(cl);
			if (rv == ERR_BADMSG)
				continue;
			if (sshbuf_len(cl->cs_out) > 0)
				cl->cs_events |= POLLOUT;
		}

rearm:
		VERIFY0(port_associate(clport,
		    PORT_SOURCE_FD, cl->cs_fd, cl->cs_events, cl));
	}

	return (NULL);
}

void
agent_main(zoneid_t zid, nvlist_t *zinfo, int listensock, int ctlfd)
{
	int portfd;
	struct ctl_cmd cmd;
	enum ctl_cmd_type cmdtype;
	port_event_t ev;
	timespec_t to;
	int sockfd;
	struct client_state *cl;
	int i, rv;
	zoneid_t theirzid;
	struct token_slot *slot;
	struct agent_slot *as;
	struct timespec tout, now, delta;
	priv_set_t *pset;
	boolean_t was_renew;
	struct acceptor_args aa;

	bunyan_set_name("agent");

	/*
	 * Lock all our memory into RAM so it can't be swapped out. We're
	 * going to be doing crypto operations and dealing with key material,
	 * so we don't want anything to be swappable.
	 */
	VERIFY0(mlockall(MCL_CURRENT | MCL_FUTURE));

	/* Start listening on our UNIX socket inside the zone. */
	VERIFY0(listen(listensock, 10));

	/*
	 * We use this port for events on this thread: messages from parent
	 * processes, and requests to communicate with the parent (e.g. asking
	 * it to unlock a key).
	 */
	portfd = port_create();
	assert(portfd > 0);
	mport = portfd;

	/*
	 * This port is for client connections. We'll create a thread pool
	 * shortly that loops in port_get() on it.
	 */
	clport = port_create();
	assert(clport > 0);

	/* This port is for accepting new sockets. */
	acport = port_create();
	VERIFY(acport > 0);

	/* Now that we've made our ports and are listening, drop privs. */

	(void) mkdir(TOKEN_CHROOT_DIR, 0700);
	VERIFY0(chroot(TOKEN_CHROOT_DIR));

	VERIFY0(setgroups(0, NULL));
	VERIFY0(setgid(GID_NOBODY));
	VERIFY0(seteuid(UID_NOBODY));

	pset = priv_allocset();
	assert(pset != NULL);

	/*
	 * We drop everything we can here; we don't need to open any new
	 * sockets or files in this process from now on.
	 */
	priv_basicset(pset);
	VERIFY0(priv_delset(pset, PRIV_PROC_EXEC));
	VERIFY0(priv_delset(pset, PRIV_PROC_INFO));
	VERIFY0(priv_delset(pset, PRIV_PROC_FORK));
	VERIFY0(priv_delset(pset, PRIV_PROC_SESSION));
	VERIFY0(priv_delset(pset, PRIV_FILE_LINK_ANY));
	VERIFY0(priv_delset(pset, PRIV_FILE_READ));
	VERIFY0(priv_delset(pset, PRIV_FILE_WRITE));
	VERIFY0(priv_delset(pset, PRIV_NET_ACCESS));

	VERIFY0(setppriv(PRIV_SET, PRIV_PERMITTED, pset));
	VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, pset));

	priv_freeset(pset);

	if (zinfo != NULL) {
		VERIFY0(nvlist_lookup_string(zinfo, "uuid", &zone_uuid));
		VERIFY0(nvlist_lookup_string(zinfo, "alias", &zone_alias));
		VERIFY0(nvlist_lookup_string(zinfo, "owner_uuid", &zone_owner));
		VERIFY0(nvlist_lookup_nvlist(zinfo, "tags", &zone_tags));
	}

	/*
	 * This protects the list of client state structs (one per incoming UDS
	 * connection from inside the zone).
	 */
	VERIFY0(mutex_init(&clients_mtx, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL));

	/* Finish setting up our key slots. */
	for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
		/*
		 * Set all the shared pages to PROT_NONE until we unlock the
		 * keys.
		 */
		VERIFY0(mprotect(slot->ts_data,
		    slot->ts_datasize + sizeof (struct token_slot_data),
		    PROT_NONE));

		/* Reading certs is ok */
		VERIFY0(mprotect(slot->ts_certdata, MAX_CERT_LEN, PROT_READ));
		VERIFY0(mprotect(slot->ts_chaindata, MAX_CHAIN_LEN,
		    PROT_READ));

		/*
		 * Allocate the local agent-side state about each key and
		 * initialise it.
		 */
		slot->ts_agent = calloc(1, sizeof (struct agent_slot));
		VERIFY3P(slot->ts_agent, !=, NULL);
		VERIFY0(mutex_init(&slot->ts_agent->as_mtx,
		    USYNC_THREAD | LOCK_ERRORCHECK, NULL));
		VERIFY0(cond_init(&slot->ts_agent->as_stchg, USYNC_THREAD, 0));
		slot->ts_agent->as_state = AS_LOCKED;
		VERIFY0(clock_gettime(CLOCK_MONOTONIC,
		    &slot->ts_agent->as_renew));
		slot->ts_agent->as_renew.tv_sec -= 60;
	}

	/*
	 * Open up our worker thread pool. These will sit in port_get() on the
	 * clport event port we created above, waiting for client work to do.
	 */
	for (i = 0; i < N_THREADS; ++i) {
		VERIFY0(thr_create(NULL, 0, client_reactor, NULL, 0,
		    &reactor_threads[i]));
	}

	bzero(&aa, sizeof (aa));
	aa.a_listensock = listensock;
	aa.a_zid = zid;
	/* The acceptor thread. */
	VERIFY0(thr_create(NULL, 0, accept_reactor, &aa, 0,
	    &acceptor_thread));

	/* Timeout for port_get() */
	bzero(&tout, sizeof (tout));
	tout.tv_sec = 2;

	VERIFY0(port_associate(acport,
	    PORT_SOURCE_FD, listensock, POLLIN, NULL));
	VERIFY0(port_associate(portfd,
	    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));

	while (1) {
		rv = port_get(portfd, &ev, &tout);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else if (rv == -1 && errno == ETIME) {
			goto checklock;
		} else {
			VERIFY0(rv);
		}
		if (ev.portev_source == PORT_SOURCE_USER) {
			/* Commands coming from other threads */
			switch (ev.portev_events) {
			case EVENT_WANT_UNLOCK:
				bzero(&cmd, sizeof (cmd));
				slot = (struct token_slot *)ev.portev_user;
				cmd.cc_type = CMD_UNLOCK_KEY;
				mutex_enter(&slot->ts_agent->as_mtx);
				cmd.cc_cookie = slot->ts_agent->as_cookie;
				mutex_exit(&slot->ts_agent->as_mtx);
				cmd.cc_p1 = slot->ts_id;
				VERIFY0(write_cmd(ctlfd, &cmd));
				break;
			case EVENT_WANT_LOCK:
				bzero(&cmd, sizeof (cmd));
				slot = (struct token_slot *)ev.portev_user;
				cmd.cc_type = CMD_LOCK_KEY;
				mutex_enter(&slot->ts_agent->as_mtx);
				cmd.cc_cookie = slot->ts_agent->as_cookie;
				mutex_exit(&slot->ts_agent->as_mtx);
				cmd.cc_p1 = slot->ts_id;
				VERIFY0(write_cmd(ctlfd, &cmd));
				break;
			default:
				VERIFY0(ev.portev_events);
			}

		} else if (ev.portev_object == ctlfd) {
			/*
			 * Commands (or responses) coming from the parent (the
			 * soft-token supervisor)
			 */
			VERIFY0(read_cmd(ctlfd, &cmd));
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_STATUS:
				/*
				 * A response to a previous command. This is
				 * either a resonse to a LOCK or an UNLOCK
				 * command, so find the slot it was for.
				 */
				as = NULL;
				was_renew = B_FALSE;
				for (slot = token_slots; slot != NULL;
				    slot = slot->ts_next) {
					as = slot->ts_agent;
					mutex_enter(&as->as_mtx);
					if (as->as_cookie == cmd.cc_cookie) {
						/* NOTE: no mutex_exit */
						break;
					}
					if (as->as_renew_cookie ==
					    cmd.cc_cookie) {
						/* NOTE: no mutex_exit */
						was_renew = B_TRUE;
						break;
					}
					mutex_exit(&as->as_mtx);
				}
				if (as != NULL && !was_renew) {
					as->as_cookie = 0;
					VERIFY3U(cmd.cc_p1, ==, STATUS_OK);
					switch (as->as_state) {
					case AS_UNLOCKING:
						as->as_state = AS_UNLOCKED;
						break;
					case AS_LOCKING:
						as->as_state = AS_LOCKED;
						break;
					default:
						assert(0);
					}
					VERIFY0(cond_broadcast(&as->as_stchg));
					mutex_exit(&as->as_mtx);
				}
				if (as != NULL && was_renew) {
					as->as_renew_cookie = 0;
					if (cmd.cc_p1 == STATUS_OK) {
						VERIFY0(clock_gettime(
						    CLOCK_MONOTONIC,
						    &as->as_renew));
					}
					mutex_exit(&as->as_mtx);
				}
				break;
			case CMD_SHUTDOWN:
				/*
				 * Parent is asking us to wind up and stop
				 * operation.
				 */
				bunyan_log(TRACE, "posting stop events", NULL);
				VERIFY0(port_send(acport, EVENT_STOP, NULL));
				for (i = 0; i < N_THREADS; ++i) {
					VERIFY0(port_send(clport,
					    EVENT_STOP, NULL));
				}
				VERIFY0(thr_join(acceptor_thread, NULL, NULL));
				for (i = 0; i < N_THREADS; ++i) {
					VERIFY0(thr_join(reactor_threads[i],
					    NULL, NULL));
				}
				exit(0);
				break;
			default:
				bunyan_log(ERROR,
				    "parent sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				break;
			}
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));

		} else {
			assert(0);
		}

		/*
		 * After each event we handle (or every 1sec), we want to check
		 * through all the unlocked keys and see if any have been
		 * unused for >=5sec.
		 *
		 * If they're an idle key, we should lock them so they're no
		 * longer present in memory.
		 */
checklock:
		VERIFY0(clock_gettime(CLOCK_MONOTONIC, &now));
		for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
			as = slot->ts_agent;
			mutex_enter(&as->as_mtx);
			tspec_subtract(&delta, &now, &as->as_renew);
			if (delta.tv_sec >= 60 && as->as_renew_cookie == 0) {
				as->as_renew_cookie = next_cookie();

				bunyan_log(INFO,
				    "renewing certificate",
				    "slot_name", BNY_STRING, slot->ts_name,
				    NULL);

				bzero(&cmd, sizeof (cmd));
				cmd.cc_type = CMD_RENEW_CERT;
				cmd.cc_cookie = as->as_renew_cookie;
				cmd.cc_p1 = slot->ts_id;
				VERIFY0(write_cmd(ctlfd, &cmd));
			}
			if (as->as_state != AS_UNLOCKED || as->as_ref > 0) {
				mutex_exit(&as->as_mtx);
				continue;
			}
			tspec_subtract(&delta, &now, &as->as_lastused);
			if (delta.tv_sec >= 5) {
				bunyan_log(TRACE,
				    "key has been idle, locking",
				    "keyname", BNY_STRING, slot->ts_name,
				    "idle_sec", BNY_INT, (int)delta.tv_sec,
				    NULL);
				as->as_cookie = next_cookie();
				as->as_state = AS_LOCKING;
				VERIFY0(port_send(mport, EVENT_WANT_LOCK,
				    slot));
				VERIFY0(cond_broadcast(&as->as_stchg));
			}
			mutex_exit(&as->as_mtx);
		}
	}
}

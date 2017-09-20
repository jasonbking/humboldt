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
#include <dirent.h>
#include <port.h>

#include "softtoken.h"
#include "bunyan.h"
#include "sshbuf.h"
#include "sshkey.h"

#define SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#define SSH_AGENTC_RSA_CHALLENGE		3
#define SSH_AGENT_RSA_RESPONSE			4
#define SSH_AGENT_FAILURE			5
#define SSH_AGENT_SUCCESS			6
#define SSH_AGENTC_ADD_RSA_IDENTITY		7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY		8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

#define SSH2_AGENTC_REQUEST_IDENTITIES		11
#define SSH2_AGENT_IDENTITIES_ANSWER		12
#define SSH2_AGENTC_SIGN_REQUEST		13
#define SSH2_AGENT_SIGN_RESPONSE		14
#define SSH2_AGENTC_ADD_IDENTITY		17
#define SSH2_AGENTC_REMOVE_IDENTITY		18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED 26

#define	SSH_AGENT_CONSTRAIN_LIFETIME		1
#define	SSH_AGENT_CONSTRAIN_CONFIRM		2

#define SSH2_AGENT_FAILURE			30

#define SSH_COM_AGENT2_FAILURE			102

#define	SSH_AGENT_OLD_SIGNATURE			0x01
#define	SSH_AGENT_RSA_SHA2_256			0x02
#define	SSH_AGENT_RSA_SHA2_512			0x04

enum port_events {
	EVENT_WANT_UNLOCK = 1,
	EVENT_WANT_LOCK
};

struct client_state {
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
	size_t as_ref;
};

static int mport;
static uint8_t last_cookie;

static mutex_t clients_mtx;
static struct client_state *clients;
static int clport;

#define	N_THREADS	8
static thread_t reactor_threads[N_THREADS];

extern void tspec_subtract(struct timespec *result, const struct timespec *x,
    const struct timespec *y);

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

	msg = sshbuf_new();
	VERIFY3P(msg, !=, NULL);

	VERIFY0(sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER));
	VERIFY0(sshbuf_put_u32(msg, slot_n));

	for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
		u_char *blob;
		size_t blen;

		VERIFY0(sshkey_to_blob(slot->ts_public, &blob, &blen));
		VERIFY0(sshbuf_put_string(msg, blob, blen));
		free(blob);

		VERIFY0(sshbuf_put_cstring(msg, slot->ts_name));
	}
	VERIFY0(sshbuf_put_stringb(cl->cs_out, msg));
	sshbuf_free(msg);
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

	a = slot->ts_agent;
	mutex_enter(&a->as_mtx);
	++a->as_ref;
	VERIFY0(clock_gettime(CLOCK_MONOTONIC, &a->as_lastused));
	while (a->as_state != AS_UNLOCKED) {
		if (a->as_state == AS_LOCKED) {
			a->as_cookie = (++last_cookie);
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

	mutex_enter(&a->as_mtx);
	--a->as_ref;
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
}

void
agent_main(zoneid_t zid, int listensock, int ctlfd)
{
	int portfd;
	struct ctl_cmd cmd;
	enum ctl_cmd_type cmdtype;
	port_event_t ev;
	timespec_t to;
	int sockfd;
	struct sockaddr_un raddr;
	size_t raddrlen;
	struct client_state *cl;
	int i, rv;
	zoneid_t theirzid;
	struct token_slot *slot;
	struct agent_slot *as;
	struct timespec tout, now, delta;

	bunyan_set_name("agent");

	VERIFY0(listen(listensock, 10));

	portfd = port_create();
	assert(portfd > 0);
	mport = portfd;

	clport = port_create();
	assert(clport > 0);

	bzero(&tout, sizeof (tout));
	tout.tv_sec = 2;

	VERIFY0(mutex_init(&clients_mtx, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL));

	for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
		slot->ts_agent = calloc(1, sizeof (struct agent_slot));
		VERIFY3P(slot->ts_agent, !=, NULL);
		VERIFY0(mutex_init(&slot->ts_agent->as_mtx,
		    USYNC_THREAD | LOCK_ERRORCHECK, NULL));
		VERIFY0(cond_init(&slot->ts_agent->as_stchg, USYNC_THREAD, 0));
		slot->ts_agent->as_state = AS_LOCKED;
	}

	for (i = 0; i < N_THREADS; ++i) {
		VERIFY0(thr_create(NULL, 0, client_reactor, NULL, 0,
		    &reactor_threads[i]));
	}

	VERIFY0(port_associate(portfd,
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
			switch (ev.portev_events) {
			case EVENT_WANT_UNLOCK:
				bzero(&cmd, sizeof (cmd));
				slot = (struct token_slot *)ev.portev_user;
				cmd.cc_type = CMD_UNLOCK_KEY;
				mutex_enter(&slot->ts_agent->as_mtx);
				cmd.cc_cookie = slot->ts_agent->as_cookie;
				mutex_exit(&slot->ts_agent->as_mtx);
				cmd.cc_p1 = slot->ts_id;
				write_cmd(ctlfd, &cmd);
				break;
			case EVENT_WANT_LOCK:
				bzero(&cmd, sizeof (cmd));
				slot = (struct token_slot *)ev.portev_user;
				cmd.cc_type = CMD_LOCK_KEY;
				mutex_enter(&slot->ts_agent->as_mtx);
				cmd.cc_cookie = slot->ts_agent->as_cookie;
				mutex_exit(&slot->ts_agent->as_mtx);
				cmd.cc_p1 = slot->ts_id;
				write_cmd(ctlfd, &cmd);
				break;
			default:
				VERIFY0(ev.portev_events);
			}

		} else if (ev.portev_object == ctlfd) {
			read_cmd(ctlfd, &cmd);
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_STATUS:
				for (slot = token_slots; slot != NULL;
				    slot = slot->ts_next) {
					as = slot->ts_agent;
					mutex_enter(&as->as_mtx);
					if (as->as_cookie == cmd.cc_cookie) {
						as->as_cookie = 0;
						VERIFY3U(cmd.cc_p1, ==,
						    STATUS_OK);
						switch (as->as_state) {
						case AS_UNLOCKING:
							as->as_state =
							    AS_UNLOCKED;
							break;
						case AS_LOCKING:
							as->as_state =
							    AS_LOCKED;
							break;
						default:
							assert(0);
						}
						VERIFY0(cond_broadcast(
						    &as->as_stchg));
						mutex_exit(&as->as_mtx);
						break;
					}
					mutex_exit(&as->as_mtx);
				}
				break;
			case CMD_SHUTDOWN:
				break;
			default:
				bunyan_log(ERROR,
				    "parent sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				break;
			}
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));

		} else if (ev.portev_object == listensock) {
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
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, listensock, POLLIN, NULL));

		} else {
			assert(0);
		}
checklock:
		VERIFY0(clock_gettime(CLOCK_MONOTONIC, &now));
		for (slot = token_slots; slot != NULL; slot = slot->ts_next) {
			as = slot->ts_agent;
			mutex_enter(&as->as_mtx);
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
				as->as_cookie = (++last_cookie);
				as->as_state = AS_LOCKING;
				VERIFY0(port_send(mport, EVENT_WANT_LOCK,
				    slot));
				VERIFY0(cond_broadcast(&as->as_stchg));
			}
			mutex_exit(&as->as_mtx);
		}
	}
}

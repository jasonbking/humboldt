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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/fork.h>
#include <sys/wait.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <dirent.h>
#include <port.h>

#include <wintypes.h>
#include <winscard.h>

#include <librename.h>
#include <libnvpair.h>

#include "softtoken.h"
#include "bunyan.h"
#include "sshkey.h"
#include "ykccid.h"

#include "sshkey.h"
#include "cipher.h"
#include "sshbuf.h"
#include "crypto_api.h"

/*
 * The "supervisor" process is a child of the soft-token manager. There is one
 * supervisor process per soft-token instance (so, per zone generally). The
 * supervisor is a privileged process that retains access to the HW token for
 * the duration of its operation. Its responsibility is to mediate access to
 * to the key material for its child, the agent, which processes the actual
 * connections from clients.
 *
 * The supervisor maps a set of shared pages that are inherited by the agent
 * child, of sufficient size to hold the key material. Upon a request from the
 * agent, the supervisor "unlocks" the key by decrypting it and writing the
 * plain-text key material out into the shared memory pages.
 *
 * This request for unlock comes to the supervisor via a pipe that it creates
 * before forking the agent child.
 */

struct token_slot *token_slots = NULL;
size_t slot_n = 0;

static inline char
hex_digit(char nybble)
{
	if (nybble >= 0xA)
		return ('a' + (nybble - 0xA));
	return ('0' + nybble);
}

static char *
hex_buffer(const char *buf, size_t len)
{
	char *obuf = calloc(1, len * 2 + 1);
	size_t i, j;
	for (i = 0, j = 0; i < len; ++i) {
		obuf[j++] = hex_digit((buf[i] & 0xf0) >> 4);
		obuf[j++] = hex_digit(buf[i] & 0x0f);
	}
	obuf[j++] = 0;
	return (obuf);
}

static char *
expand_key_and_replace(char *input, size_t inlen, size_t outlen)
{
	char *out;
	size_t pos, len;
	char buf[crypto_hash_sha512_BYTES];

	out = calloc(1, outlen);
	VERIFY3P(out, !=, NULL);

	explicit_bzero(&buf, sizeof (buf));
	crypto_hash_sha512(buf, input, inlen);
	do {
		len = crypto_hash_sha512_BYTES;
		if (len > outlen)
			len = outlen;
		bcopy(buf, out, len);
		pos += len;
		outlen -= len;
		if (outlen > 0)
			crypto_hash_sha512(buf, buf, sizeof (buf));
	} while (outlen > 0);
	explicit_bzero(&buf, sizeof (buf));
	explicit_bzero(input, inlen);
	free(input);
	return (out);
}

static void
encrypt_and_write_key(struct sshkey *skey, struct yubikey *yk, const char *dir,
    struct token_slot *info)
{
	int rv, i;
	char *chal, *key, *iv, *encdata, *packdata;
	u_char *pubblob;
	size_t challen, keylen, keysz, ivlen, authlen, blocksz, enclen;
	size_t packlen, publen;
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;
	nvlist_t *nv;
	const char *ciphername = "chacha20-poly1305@openssh.com";
	struct sshbuf *buf;
	librename_atomic_t *rast;
	FILE *f;
	struct sshkey *pubkey;

	VERIFY0(sshkey_demote(skey, &pubkey));
	VERIFY0(sshkey_to_blob(pubkey, &pubblob, &publen));
	sshkey_free(pubkey);

	buf = sshbuf_new();
	VERIFY3P(buf, !=, NULL);

	/* Generate the random challenge value that we'll give to the token */
	challen = 64;
	chal = calloc(1, challen);
	VERIFY3P(chal, !=, NULL);
	arc4random_buf(chal, challen);

	/* Get some cipher metadata so we know what sizes things should be */
	cipher = cipher_by_name(ciphername);
	VERIFY3P(cipher, !=, NULL);

	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);

	/* Generate an IV for the cipher to use later */
	ivlen = cipher_ivlen(cipher);
	iv = calloc(1, ivlen);
	VERIFY3P(iv, !=, NULL);
	arc4random_buf(iv, ivlen);

	/*
	 * Now feed our challenge through the HW token to generate our real
	 * key material. It might be too short for what the cipher actually
	 * needs.
	 */
	keysz = cipher_keylen(cipher);
	key = calloc(1, keysz);
	VERIFY3P(key, !=, NULL);

	ykc_txn_begin(yk);
	VERIFY0(ykc_select(yk));
	keylen = keysz;
	VERIFY0(ykc_hmac(yk, 1, chal, challen, key, &keylen));
	VERIFY3U(keylen, <, keysz);
	ykc_txn_end(yk);

	/*
	 * If it is too short, expand it by hashing it with SHA-512 until we
	 * have enough material.
	 */
	if (keylen < keysz)
		key = expand_key_and_replace(key, keylen, keysz);

	rv = sshkey_private_serialize(skey, buf);
	VERIFY0(rv);
	/* Add PKCS#5 style padding to the end of the serialized private key */
	i = 0;
	while (sshbuf_len(buf) % blocksz) {
		rv = sshbuf_put_u8(buf, ++i & 0xff);
		VERIFY0(rv);
	}

	rv = cipher_init(&cctx, cipher, key, keysz, iv, ivlen, 1);
	VERIFY0(rv);
	enclen = sshbuf_len(buf) + authlen;
	encdata = calloc(1, enclen);
	rv = cipher_crypt(cctx, 0, encdata, sshbuf_ptr(buf), sshbuf_len(buf),
	    0, authlen);
	VERIFY0(rv);
	sshbuf_reset(buf);
	cipher_free(cctx);

	/*
	 * Now we've got the encdata blob, time to build the nvlist up that
	 * we'll pack and write out on disk.
	 */
	VERIFY0(nvlist_alloc(&nv, NV_UNIQUE_NAME, 0));

	VERIFY0(nvlist_add_uint8(nv, "version", 1));
	VERIFY0(nvlist_add_uint8(nv, "algo", info->ts_algo));
	VERIFY0(nvlist_add_uint8(nv, "type", info->ts_type));

	VERIFY0(nvlist_add_byte_array(nv, "challenge", chal, challen));
	VERIFY0(nvlist_add_uint32(nv, "yk_serial", yk->yk_serial));
	VERIFY0(nvlist_add_uint8(nv, "yk_slot", 1));

	VERIFY0(nvlist_add_string(nv, "encalgo", ciphername));
	VERIFY0(nvlist_add_byte_array(nv, "encdata", encdata, enclen));
	VERIFY0(nvlist_add_byte_array(nv, "iv", iv, ivlen));

	VERIFY0(nvlist_add_byte_array(nv, "pubkey", pubblob, publen));

	packdata = NULL;
	packlen = 0;
	VERIFY0(nvlist_pack(nv, &packdata, &packlen, NV_ENCODE_XDR, 0));
	VERIFY3P(packdata, !=, NULL);
	VERIFY3U(packlen, >, 0);

	/*
	 * Use atomic rename to write out the key file, so we never end up with
	 * a "half-written" key.
	 */
	rv = librename_atomic_init(dir, info->ts_name, NULL, 0600, 0, &rast);
	VERIFY0(rv);
	f = fdopen(librename_atomic_fd(rast), "w");
	VERIFY3S(fwrite(packdata, packlen, 1, f), ==, 1);
	VERIFY0(fflush(f));
	rv = librename_atomic_commit(rast);
	VERIFY0(rv);
	librename_atomic_fini(rast);

	/* Make sure to explicit_bzero any buffers that held sensitive data. */
	explicit_bzero(key, keysz);
	free(key);
	explicit_bzero(chal, challen);
	free(chal);
	explicit_bzero(iv, ivlen);
	free(iv);
	explicit_bzero(encdata, enclen);
	free(encdata);
	free(pubblob);
	sshbuf_free(buf);
}

/*
 * "Locks" a key, by zeroing out the shared memory segment our child gets the
 * key data from.
 */
static int
lock_key(struct token_slot *slot)
{
	explicit_bzero(slot->ts_data, slot->ts_datasize);
	bunyan_log(DEBUG, "locked key",
	    "keyname", BNY_STRING, slot->ts_name, NULL);
	return (0);
}

/*
 * Unlocks a key by decrypting it and writing it into the shared memory segment
 * so our child process (running agent_main()) can use it.
 */
static int
unlock_key(struct token_slot *slot)
{
	struct yubikey *ykb, *yk;
	nvlist_t *nv = slot->ts_nvl;
	int rv, i;
	SCARDCONTEXT ctx;
	uchar_t *chal, *key, *iv, *encdata;
	uint_t challen, keysz, ivlen, authlen, blocksz, enclen;
	size_t keylen;
	const struct sshcipher *cipher;
	struct sshbuf *buf;
	struct sshkey *pkey, *pubkey;
	struct sshcipher_ctx *cctx;
	char *ciphername;
	uint32_t serial;
	uint8_t slotn;
	struct bunyan_timers *tms;

	tms = bny_timers_new();
	VERIFY3P(tms, !=, NULL);
	VERIFY0(bny_timer_begin(tms));

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	assert(rv == SCARD_S_SUCCESS);

	VERIFY0(bny_timer_next(tms, "scard_establish"));

	ykb = ykc_find(ctx);
	assert(ykb != NULL);
	yk = ykb;

	VERIFY0(bny_timer_next(tms, "find_yubikeys"));

	VERIFY0(nvlist_lookup_uint32(nv, "yk_serial", &serial));
	VERIFY0(nvlist_lookup_uint8(nv, "yk_slot", &slotn));
	do {
		const uint16_t mask =
		    (slotn == 1 ? CONFIG1_VALID : CONFIG2_VALID);
		if (yk->yk_serial == serial && (yk->yk_touchlvl & mask) != 0)
			break;
		yk = yk->yk_next;
	} while (yk != NULL);
	VERIFY3P(yk, !=, NULL);

	VERIFY0(nvlist_lookup_string(nv, "encalgo", &ciphername));
	cipher = cipher_by_name(ciphername);
	VERIFY3P(cipher, !=, NULL);

	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);

	VERIFY0(nvlist_lookup_byte_array(nv, "challenge", &chal, &challen));
	VERIFY0(nvlist_lookup_byte_array(nv, "iv", &iv, &ivlen));
	VERIFY3S(ivlen, ==, cipher_ivlen(cipher));

	keysz = cipher_keylen(cipher);
	key = calloc(1, keysz);
	VERIFY3P(key, !=, NULL);

	ykc_txn_begin(yk);
	VERIFY0(ykc_select(yk));
	keylen = keysz;
	VERIFY0(ykc_hmac(yk, slotn, chal, challen, key, &keylen));
	VERIFY3U(keylen, <, keysz);
	ykc_txn_end(yk);

	ykc_release(ykb);

	if (keylen < keysz)
		key = expand_key_and_replace(key, keylen, keysz);

	VERIFY0(bny_timer_next(tms, "hmac_kd"));

	VERIFY0(nvlist_lookup_byte_array(nv, "encdata", &encdata, &enclen));

	VERIFY0(cipher_init(&cctx, cipher, key, keysz, iv, ivlen, 0));

	slot->ts_data->tsd_len = enclen - authlen;
	VERIFY0(cipher_crypt(cctx, 0, (u_char *)slot->ts_data->tsd_data,
	    encdata, enclen - authlen, 0, authlen));

	cipher_free(cctx);
	explicit_bzero(key, keysz);
	free(key);

	VERIFY0(bny_timer_next(tms, "decrypt"));

	buf = sshbuf_from((const void *)slot->ts_data->tsd_data,
	    slot->ts_data->tsd_len);
	VERIFY3P(buf, !=, NULL);
	VERIFY0(sshkey_private_deserialize(buf, &pkey));
	VERIFY3S(sshkey_equal_public(pkey, slot->ts_public), ==, 1);
	sshkey_free(pkey);
	sshbuf_free(buf);

	VERIFY0(bny_timer_next(tms, "verify"));

	bunyan_log(DEBUG, "unlocked key",
	    "keyname", BNY_STRING, slot->ts_name,
	    "timers", BNY_TIMERS, tms, NULL);
	bny_timers_free(tms);

	return (0);
}

static void
generate_keys(const char *zonename, const char *keydir)
{
	struct sshkey *authkey;
	struct sshkey *certkey;
	struct yubikey *yk;
	int rv, i;
	SCARDCONTEXT ctx;
	struct token_slot tpl;
	bzero(&tpl, sizeof (tpl));

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	assert(rv == SCARD_S_SUCCESS);

	yk = ykc_find(ctx);
	assert(yk != NULL);
	assert(yk->yk_next == NULL);

	rv = sshkey_generate(KEY_ED25519, 256, &authkey);
	VERIFY0(rv);
	tpl.ts_type = SLOT_ASYM_AUTH;
	tpl.ts_algo = ALGO_ED_25519;
	tpl.ts_name = "auth.key";
	encrypt_and_write_key(authkey, yk, keydir, &tpl);
	sshkey_free(authkey);

	rv = sshkey_generate(KEY_RSA, 2048, &certkey);
	VERIFY0(rv);
	tpl.ts_type = SLOT_ASYM_CERT_SIGN;
	tpl.ts_algo = ALGO_RSA_2048;
	tpl.ts_name = "cert.key";
	encrypt_and_write_key(certkey, yk, keydir, &tpl);
	sshkey_free(certkey);

	ykc_release(yk);
}

static void
read_key_file(const char *nm, const char *fn)
{
	uchar_t *pubkey;
	uint_t publen;
	nvlist_t *nvl;
	char *shm;
	FILE *f;
	long sz;
	struct token_slot *ts;
	char *buf, *name;
	uint8_t val;
	int rv;

	bunyan_log(TRACE, "unpacking key file",
	    "filename", BNY_STRING, nm, NULL);

	f = fopen(fn, "r");
	if (f == NULL) {
		bunyan_log(ERROR, "error opening key file",
		    "filename", BNY_STRING, nm,
		    "errno", BNY_INT, errno,
		    "strerror", BNY_STRING, strerror(errno),
		    NULL);
		return;
	}

	VERIFY0(fseek(f, 0L, SEEK_END));
	sz = ftell(f);
	VERIFY0(fseek(f, 0L, SEEK_SET));

	if (sz > 1*1024*1024 || sz < 0) {
		bunyan_log(ERROR, "bad length of key file",
		    "filename", BNY_STRING, nm, NULL);
		return;
	}

	buf = calloc(1, sz);
	assert(buf != NULL);

	assert(fread(buf, sz, 1, f) == 1);
	fclose(f);

	if ((rv = nvlist_unpack(buf, sz, &nvl, 0)) != 0) {
		bunyan_log(ERROR, "key file is not an nvlist",
		    "filename", BNY_STRING, nm,
		    "code", BNY_INT, rv, NULL);
		return;
	}

	free(buf);

	VERIFY0(nvlist_lookup_uint8(nvl, "version", &val));
	if (val != 1) {
		bunyan_log(ERROR, "key file is wrong version",
		    "filename", BNY_STRING, nm,
		    "version", BNY_INT, (int)val, NULL);
		return;
	}

	/*
	 * The decrypted key data is always smaller than the nvlist was, so
	 * we'll just allocate that much shared memory for it.
	 */
	shm = mmap(0, sz + sizeof (struct token_slot_data),
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	assert(shm != NULL);
	explicit_bzero(shm, sz);
	VERIFY0(mlock(shm, sz));

	ts = calloc(1, sizeof (struct token_slot));
	assert(ts != NULL);
	name = calloc(1, strlen(nm) + 1);
	assert(name != NULL);
	strcpy(name, nm);
	ts->ts_name = name;
	ts->ts_nvl = nvl;
	ts->ts_data = (struct token_slot_data *)shm;
	ts->ts_datasize = sz;

	VERIFY0(nvlist_lookup_uint8(nvl, "type", &val));
	VERIFY3U(val, >, 0);
	VERIFY3U(val, <, SLOT_MAX);
	ts->ts_type = val;
	VERIFY0(nvlist_lookup_uint8(nvl, "algo", &val));
	VERIFY3U(val, >, 0);
	VERIFY3U(val, <, ALGO_MAX);
	ts->ts_algo = val;

	VERIFY0(nvlist_lookup_byte_array(nvl, "pubkey", &pubkey, &publen));
	VERIFY0(sshkey_from_blob(pubkey, publen, &ts->ts_public));

	bunyan_log(TRACE, "unpack ok",
	    "filename", BNY_STRING, nm, NULL);

	ts->ts_next = token_slots;
	token_slots = ts;
	ts->ts_id = (++slot_n);
}

static void
make_slots(const char *zonename)
{
	char keydir[PATH_MAX];
	char fn[PATH_MAX];
	DIR *dirp;
	struct dirent *dp;
	pid_t kid, w;
	int stat;

	/*
	 * Walk through the zone keys directory and interpret each file as a
	 * key data file. These are formatted as a packed nvlist.
	 */
	snprintf(keydir, sizeof (keydir), TOKEN_KEYS_DIR, zonename);

again:
	if ((dirp = opendir(keydir)) != NULL) {
		do {
			if ((dp = readdir(dirp)) != NULL) {
				if (dp->d_name[0] == '.') {
					continue;
				}
				snprintf(fn, sizeof (fn), "%s/%s", keydir,
				    dp->d_name);

				read_key_file(dp->d_name, fn);
			}
		} while (dp != NULL);

		closedir(dirp);
	}

	if (token_slots == NULL) {
		bunyan_log(INFO, "generating keys for zone", NULL);

		kid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
		assert(kid != -1);
		if (kid == 0) {
			(void) mkdir(keydir, 0700);
			generate_keys(zonename, keydir);
			exit(0);
		}

		do {
			w = waitpid(kid, &stat, 0);
		} while (w == -1 && errno == EINTR);
		assert(WIFEXITED(stat));
		assert(WEXITSTATUS(stat) == 0);
		goto again;
	}
}

void
read_cmd(int fd, struct ctl_cmd *cmd)
{
	size_t off = 0, rem = sizeof (*cmd);
	int rv;
	bzero(cmd, sizeof (*cmd));
	do {
		rv = read(fd, ((char *)cmd) + off, rem);
		if (rv > 0) {
			off += rv;
			rem -= rv;
		}
	} while ((rv != -1 || errno == EINTR || errno == EAGAIN) && rem > 0);
	bunyan_log(TRACE, "received cmd",
	    "cookie", BNY_INT, cmd->cc_cookie,
	    "type", BNY_INT, cmd->cc_type,
	    "p1", BNY_INT, cmd->cc_p1,
	    NULL);
}

void
write_cmd(int fd, const struct ctl_cmd *cmd)
{
	size_t off = 0, rem = sizeof (*cmd);
	int rv;
	bunyan_log(TRACE, "sending cmd",
	    "cookie", BNY_INT, cmd->cc_cookie,
	    "type", BNY_INT, cmd->cc_type,
	    "p1", BNY_INT, cmd->cc_p1,
	    NULL);
	do {
		rv = write(fd, ((const char *)cmd) + off, rem);
		if (rv > 0) {
			off += rv;
			rem -= rv;
		}
	} while ((rv != -1 || errno == EINTR || errno == EAGAIN) && rem > 0);
}

static void
supervisor_loop(int ctlfd, int kidfd, int listensock)
{
	int portfd;
	port_event_t ev;
	timespec_t to;
	int rv;
	struct ctl_cmd cmd, rcmd;
	size_t len;
	enum ctl_cmd_type cmdtype;
	int idx;
	struct token_slot *ts;

	bzero(&to, sizeof (to));

	portfd = port_create();
	assert(portfd > 0);

	VERIFY0(port_associate(portfd,
	    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));
	VERIFY0(port_associate(portfd,
	    PORT_SOURCE_FD, kidfd, POLLIN, NULL));

	while (1) {
		rv = port_get(portfd, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			VERIFY0(rv);
		}
		if (ev.portev_object == ctlfd) {
			read_cmd(ctlfd, &cmd);
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_SHUTDOWN:
				break;
			default:
				bunyan_log(ERROR,
				    "parent sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				continue;
			}
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));

		} else if (ev.portev_object == kidfd) {
			read_cmd(kidfd, &cmd);
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_UNLOCK_KEY:
			case CMD_LOCK_KEY:
				for (ts = token_slots; ts != NULL;
				    ts = ts->ts_next) {
					if (ts->ts_id == cmd.cc_p1)
						break;
				}
				if (ts != NULL) {
					if (cmdtype == CMD_UNLOCK_KEY)
						rv = unlock_key(ts);
					else
						rv = lock_key(ts);
					if (rv == 0) {
						bzero(&rcmd, sizeof (rcmd));
						rcmd.cc_cookie = cmd.cc_cookie;
						rcmd.cc_type = CMD_STATUS;
						rcmd.cc_p1 = STATUS_OK;
						write_cmd(kidfd, &rcmd);
						break;
					}
				}

				bzero(&rcmd, sizeof (rcmd));
				rcmd.cc_cookie = cmd.cc_cookie;
				rcmd.cc_type = CMD_STATUS;
				rcmd.cc_p1 = STATUS_ERROR;
				write_cmd(kidfd, &rcmd);
				break;
			default:
				bunyan_log(ERROR,
				    "child sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				continue;
			}
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, kidfd, POLLIN, NULL));

		} else {
			assert(0);
		}
	}
}

void
supervisor_main(zoneid_t zid, int ctlfd)
{
	char zonename[ZONENAME_MAX];
	char sockdir[PATH_MAX];
	struct sockaddr_un addr;
	int listensock;
	ssize_t len;
	pid_t kid;
	int kidpipe[2];
	struct token_slot *slot;
	priv_set_t *pset;

	bunyan_set_name("supervisor");

	/*
	 * Early drop of privs before we fork our child or do any work.
	 * We have to keep quite a bit of stuff here, but we can let go of
	 * some of it later after we've forked.
	 */
	pset = priv_allocset();
	assert(pset != NULL);

	priv_basicset(pset);

	VERIFY0(priv_delset(pset, PRIV_PROC_EXEC));
	VERIFY0(priv_delset(pset, PRIV_PROC_INFO));
	VERIFY0(priv_delset(pset, PRIV_PROC_SESSION));
	VERIFY0(priv_delset(pset, PRIV_FILE_LINK_ANY));
	/* We need these for dealing with the socket and key files. */
	VERIFY0(priv_addset(pset, PRIV_FILE_DAC_READ));
	VERIFY0(priv_addset(pset, PRIV_FILE_DAC_WRITE));
	VERIFY0(priv_addset(pset, PRIV_FILE_DAC_SEARCH));
	/* Our child will need these to do mlockall() and drop privs. */
	VERIFY0(priv_addset(pset, PRIV_PROC_LOCK_MEMORY));
	VERIFY0(priv_addset(pset, PRIV_PROC_CHROOT));
	VERIFY0(priv_addset(pset, PRIV_PROC_SETID));

	VERIFY0(setppriv(PRIV_SET, PRIV_PERMITTED, pset));
	VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, pset));

	len = getzonenamebyid(zid, zonename, sizeof (zonename));
	assert(len > 0);
	zonename[len] = '\0';

	bunyan_log(DEBUG, "starting supervisor for zone",
	    "zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	/*
	 * Lock all our memory into RAM so it can't be swapped out. We're
	 * going to be doing crypto operations and dealing with key material,
	 * so we don't want anything to be swappable.
	 */
	VERIFY0(mlockall(MCL_CURRENT | MCL_FUTURE));

	/* Open the socket directory and make our listen socket. */
	snprintf(sockdir, sizeof (sockdir), TOKEN_SOCKET_DIR, zonename);
	(void) mkdir(sockdir, 0700);

	listensock = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(listensock > 0);
	bzero(&addr, sizeof (addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof (addr.sun_path) - 1,
	    TOKEN_SOCKET_PATH, zonename);
	(void) unlink(addr.sun_path);
	VERIFY0(bind(listensock, (struct sockaddr *)&addr, sizeof (addr)));

	bunyan_set("zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	bunyan_log(DEBUG, "zonecontrol socket created",
	    "sockpath", BNY_STRING, addr.sun_path, NULL);

	/* Now open up our key files and establish the shared pages. */
	make_slots(zonename);

	VERIFY0(pipe(kidpipe));

	/* And create the actual agent process. */
	kid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
	assert(kid != -1);
	if (kid == 0) {
		VERIFY0(close(kidpipe[0]));
		VERIFY0(close(ctlfd));
		agent_main(zid, listensock, kidpipe[1]);
		bunyan_log(ERROR, "agent_main returned", NULL);
		exit(1);
	}
	VERIFY0(close(kidpipe[1]));

	/*
	 * Now that we've finished forking we can give up the privs we only
	 * kept to give to our child.
	 */
	VERIFY0(priv_delset(pset, PRIV_PROC_FORK));
	VERIFY0(priv_delset(pset, PRIV_PROC_LOCK_MEMORY));
	VERIFY0(priv_delset(pset, PRIV_PROC_CHROOT));
	VERIFY0(priv_delset(pset, PRIV_PROC_SETID));
	/* We still need this for PCSCd */
	/*VERIFY0(priv_delset(pset, PRIV_NET_ACCESS));*/

	VERIFY0(setppriv(PRIV_SET, PRIV_PERMITTED, pset));
	VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, pset));
	priv_freeset(pset);

	supervisor_loop(ctlfd, kidpipe[0], listensock);
}

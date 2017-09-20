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

	challen = 64;
	chal = calloc(1, challen);
	VERIFY3P(chal, !=, NULL);
	arc4random_buf(chal, challen);

	cipher = cipher_by_name(ciphername);
	VERIFY3P(cipher, !=, NULL);

	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);

	ivlen = cipher_ivlen(cipher);
	iv = calloc(1, ivlen);
	VERIFY3P(iv, !=, NULL);
	arc4random_buf(iv, ivlen);

	keysz = cipher_keylen(cipher);
	key = calloc(1, keysz);
	VERIFY3P(key, !=, NULL);

	ykc_txn_begin(yk);
	VERIFY0(ykc_select(yk));
	keylen = keysz;
	VERIFY0(ykc_hmac(yk, 1, chal, challen, key, &keylen));
	VERIFY3U(keylen, <, keysz);
	ykc_txn_end(yk);

	if (keylen < keysz)
		key = expand_key_and_replace(key, keylen, keysz);

	rv = cipher_init(&cctx, cipher, key, keysz, iv, ivlen, 1);
	VERIFY0(rv);

	rv = sshkey_private_serialize(skey, buf);
	VERIFY0(rv);
	i = 0;
	while (sshbuf_len(buf) % blocksz) {
		rv = sshbuf_put_u8(buf, ++i & 0xff);
		VERIFY0(rv);
	}
	enclen = sshbuf_len(buf) + authlen;
	encdata = calloc(1, enclen);
	rv = cipher_crypt(cctx, 0, encdata, sshbuf_ptr(buf), sshbuf_len(buf),
	    0, authlen);
	VERIFY0(rv);
	sshbuf_reset(buf);
	cipher_free(cctx);

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

	rv = librename_atomic_init(dir, info->ts_name, NULL, 0600, 0, &rast);
	VERIFY0(rv);
	f = fdopen(librename_atomic_fd(rast), "w");
	VERIFY3S(fwrite(packdata, packlen, 1, f), ==, 1);
	VERIFY0(fflush(f));
	rv = librename_atomic_commit(rast);
	VERIFY0(rv);
	librename_atomic_fini(rast);

	free(pubblob);
	explicit_bzero(key, keysz);
	free(key);
	explicit_bzero(chal, challen);
	free(chal);
	explicit_bzero(iv, ivlen);
	free(iv);
	explicit_bzero(encdata, enclen);
	free(encdata);
	sshbuf_free(buf);
}

static int
lock_key(struct token_slot *slot)
{
	explicit_bzero(slot->ts_data, slot->ts_datasize);
	bunyan_log(DEBUG, "locked key",
	    "keyname", BNY_STRING, slot->ts_name, NULL);
	return (0);
}

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
make_slots(const char *zonename)
{
	struct token_slot *ts;
	char keydir[PATH_MAX];
	char fn[PATH_MAX];
	DIR *dirp;
	struct dirent *dp;
	FILE *f;
	long sz;
	char *buf, *name;
	uchar_t *pubkey;
	uint_t publen;
	nvlist_t *nvl;
	char *shm;
	uint8_t val;

	/*
	 * Walk through the zone keys directory and interpret each file as a
	 * key data file. These are formatted as a packed nvlist.
	 */
	snprintf(keydir, sizeof (keydir), "/zones/%s/keys", zonename);

again:
	if ((dirp = opendir(keydir)) != NULL) {
		do {
			if ((dp = readdir(dirp)) != NULL) {
				if (dp->d_name[0] == '.') {
					continue;
				}
				snprintf(fn, sizeof (fn), "%s/%s", keydir,
				    dp->d_name);
				bunyan_log(TRACE, "unpacking key file",
				    "filename", BNY_STRING, dp->d_name, NULL);

				f = fopen(fn, "r");
				assert(f != NULL);

				VERIFY0(fseek(f, 0L, SEEK_END));
				sz = ftell(f);
				VERIFY0(fseek(f, 0L, SEEK_SET));
				assert(sz < 1*1024*1024);

				buf = calloc(1, sz);
				assert(buf != NULL);

				assert(fread(buf, sz, 1, f) == 1);
				fclose(f);

				VERIFY0(nvlist_unpack(buf, sz, &nvl, 0));

				free(buf);

				VERIFY0(nvlist_lookup_uint8(nvl, "version",
				    &val));
				if (val != 1)
					continue;

				/*
				 * The decrypted key data is always smaller than
				 * the nvlist was, so we'll just allocate that
				 * much shared memory for it.
				 */
				shm = mmap(0,
				    sz + sizeof (struct token_slot_data),
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANON, -1, 0);
				assert(shm != NULL);
				explicit_bzero(shm, sz);

				ts = calloc(1, sizeof (struct token_slot));
				assert(ts != NULL);
				name = calloc(1, strlen(dp->d_name));
				assert(name != NULL);
				strcpy(name, dp->d_name);
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

				VERIFY0(nvlist_lookup_byte_array(nvl, "pubkey",
				    &pubkey, &publen));
				VERIFY0(sshkey_from_blob(pubkey, publen,
				    &ts->ts_public));

				bunyan_log(TRACE, "unpack ok",
				    "filename", BNY_STRING, dp->d_name, NULL);

				ts->ts_next = token_slots;
				token_slots = ts;
				ts->ts_id = (++slot_n);
			}
		} while (dp != NULL);

		closedir(dirp);
	}

	if (token_slots == NULL) {
		pid_t kid, w;
		int stat;

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

	bunyan_set_name("supervisor");

	len = getzonenamebyid(zid, zonename, sizeof (zonename));
	assert(len > 0);
	zonename[len] = '\0';

	bunyan_log(DEBUG, "starting supervisor for zone",
	    "zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	/* Open the socket directory and make our listen socket. */
	snprintf(sockdir, sizeof (sockdir), "/var/zonecontrol/%s", zonename);
	(void) mkdir(sockdir, 0700);

	listensock = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(listensock > 0);
	bzero(&addr, sizeof (addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof (addr.sun_path) - 1,
	    "/var/zonecontrol/%s/token.sock", zonename);
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

	supervisor_loop(ctlfd, kidpipe[0], listensock);
}

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <wintypes.h>
#include <winscard.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/errno.h>
#include <strings.h>

#include "sshkey.h"
#include "sshbuf.h"
#include "digest.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tlv.h"
#include "piv.h"
#include "bunyan.h"

boolean_t debug = B_FALSE;
static boolean_t parseable = B_FALSE;
static uint8_t *guid = NULL;
static const char *pin = NULL;

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;

static uint8_t *
parse_hex(const char *str, uint *outlen)
{
	const int len = strlen(str);
	uint8_t *data = calloc(1, len / 2 + 1);
	int idx = 0;
	int shift = 4;
	int i;
	for (i = 0; i < len; ++i) {
		const char c = str[i];
		boolean_t skip = B_FALSE;
		if (c >= '0' && c <= '9') {
			data[idx] |= (c - '0') << shift;
		} else if (c >= 'a' && c <= 'f') {
			data[idx] |= (c - 'a' + 0xa) << shift;
		} else if (c >= 'A' && c <= 'F') {
			data[idx] |= (c - 'A' + 0xA) << shift;
		} else if (c == ':' || c == ' ' || c == '\t' ||
		    c == '\n' || c == '\r') {
			skip = B_TRUE;
		} else {
			fprintf(stderr, "error: invalid hex digit: '%c'\n", c);
			exit(1);
		}
		if (skip == B_FALSE) {
			if (shift == 4) {
				shift = 0;
			} else if (shift == 0) {
				++idx;
				shift = 4;
			}
		}
	}
	if (shift == 0) {
		fprintf(stderr, "error: odd number of hex digits "
		    "(incomplete)\n");
		exit(1);
	}
	*outlen = idx;
	return (data);
}

static uint8_t *
read_stdin(size_t limit, size_t *outlen)
{
	uint8_t *buf = calloc(1, limit * 3);
	size_t n;

	n = fread(buf, 1, limit * 3 - 1, stdin);
	if (!feof(stdin)) {
		fprintf(stderr, "error: input too long (max %d bytes)\n",
		    limit);
		exit(1);
	}

	if (n > limit) {
		fprintf(stderr, "error: input too long (max %d bytes)\n",
		    limit);
		exit(1);
	}

	*outlen = n;
	return (buf);
}

static void
assert_pin(struct piv_token *pk)
{
	int rv;
	uint retries;

	if (pin != NULL) {
		rv = piv_verify_pin(selk, pin, &retries);
		if (rv == EACCES) {
			fprintf(stderr, "error: invalid PIN code (%d attempts "
			    "remaining)\n", retries);
			exit(3);
		} else if (rv != 0) {
			fprintf(stderr, "error: failed to verify PIN\n");
			exit(3);
		}
	}
}

extern char *buf_to_hex(const uint8_t *buf, size_t len);

static void
cmd_list(SCARDCONTEXT ctx)
{
	struct piv_token *pk;
	struct piv_slot *cert;
	int i, rv;
	char *buf;

	for (pk = ks; pk != NULL; pk = pk->pt_next) {
		assert(piv_txn_begin(pk) == 0);
		piv_read_all_certs(pk);
		piv_txn_end(pk);

		buf = buf_to_hex(pk->pt_guid, sizeof (pk->pt_guid));
		printf("PIV card in '%s': guid = %s\n",
		    pk->pt_rdrname, buf);
		free(buf);
		if (pk->pt_alg_count > 0) {
			printf("  * supports: ");
			for (i = 0; i < pk->pt_alg_count; ++i) {
				switch (pk->pt_algs[i]) {
				case PIV_ALG_3DES:
					printf("3DES ");
					break;
				case PIV_ALG_RSA1024:
					printf("RSA1024 ");
					break;
				case PIV_ALG_RSA2048:
					printf("RSA2048 ");
					break;
				case PIV_ALG_AES128:
					printf("AES128 ");
					break;
				case PIV_ALG_AES192:
					printf("AES192 ");
					break;
				case PIV_ALG_AES256:
					printf("AES256 ");
					break;
				case PIV_ALG_ECCP256:
					printf("ECCP256 ");
					break;
				case PIV_ALG_ECCP384:
					printf("ECCP384 ");
					break;
				}
			}
			printf("\n");
		}
		for (cert = pk->pt_slots; cert != NULL; cert = cert->ps_next) {
			printf("  * slot %02X: %s (%s %d)\n", cert->ps_slot,
			    cert->ps_subj, sshkey_type(cert->ps_pubkey),
			    sshkey_size(cert->ps_pubkey));
		}
	}
}

static void
cmd_pubkey(uint slotid)
{
	struct piv_slot *cert;
	char *buf;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric signing\n", slotid);
		exit(3);
	}

	for (cert = selk->pt_slots; cert != NULL; cert = cert->ps_next) {
		if (cert->ps_slot == slotid)
			break;
	}
	if (cert == NULL) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	}

	rv = sshkey_write(cert->ps_pubkey, stdout);
	if (rv != 0) {
		fprintf(stderr, "error: failed to write out key\n");
		exit(1);
	}
	buf = buf_to_hex(selk->pt_guid, sizeof (selk->pt_guid));
	fprintf(stdout, " PIV_slot_%02X@%s \"%s\"\n", slotid, buf,
	    cert->ps_subj);
	free(buf);
	exit(0);
}

static void
cmd_sign(uint slotid)
{
	struct piv_slot *cert;
	uint8_t *buf, *sig;
	int hashalg;
	struct ssh_digest_ctx *hctx;
	size_t nread, dglen, inplen, siglen;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric signing\n", slotid);
		exit(3);
	}

	piv_txn_begin(selk);
	rv = piv_read_cert(selk, slotid);
	piv_txn_end(selk);

	cert = piv_get_slot(selk, slotid);

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	switch (cert->ps_alg) {
	case PIV_ALG_RSA1024:
		inplen = 128;
		dglen = 32;
		hashalg = SSH_DIGEST_SHA256;
		break;
	case PIV_ALG_RSA2048:
		inplen = 256;
		dglen = 32;
		hashalg = SSH_DIGEST_SHA256;
		break;
	case PIV_ALG_ECCP256:
		hashalg = SSH_DIGEST_SHA256;
		inplen = (dglen = 32);
		break;
	case PIV_ALG_ECCP384:
		hashalg = SSH_DIGEST_SHA384;
		inplen = (dglen = 48);
		break;
	default:
		assert(0);
	}

	hctx = ssh_digest_start(hashalg);
	assert(hctx != NULL);

	buf = calloc(1, 8192);
	assert(buf != NULL);
	do {
		nread = fread(buf, 1, 8192, stdin);
		assert(ssh_digest_update(hctx, buf, nread) == 0);
	} while (!(nread == 0 || (nread == -1 && !(errno == EINTR))));

	assert(ssh_digest_final(hctx, buf, dglen) == 0);

	/*
	 * If it's an RSA signature, we have to generate the PKCS#1 style
	 * padded signing blob around the hash.
	 *
	 * ECDSA is so much nicer than this. Why can't we just use it? Oh,
	 * because Java ruined everything. Right.
	 */
	if (cert->ps_alg == PIV_ALG_RSA1024 ||
	    cert->ps_alg == PIV_ALG_RSA2048) {
		int nid;
		/*
		 * Roll up your sleeves, folks, we're going in (to the dank
		 * and musty corners of OpenSSL where few dare tread)
		 */
		X509_SIG digestInfo;
		X509_ALGOR algor;
		ASN1_TYPE parameter;
		ASN1_OCTET_STRING digest;
		uint8_t *tmp, *out;

		tmp = calloc(1, inplen);
		assert(tmp != NULL);
		out = NULL;

		/*
		 * XXX: I thought this should be sha256WithRSAEncryption?
		 *      but that doesn't work lol
		 */
		nid = NID_sha256;
		bcopy(buf, tmp, dglen);
		digestInfo.algor = &algor;
		digestInfo.algor->algorithm = OBJ_nid2obj(nid);
		digestInfo.algor->parameter = &parameter;
		digestInfo.algor->parameter->type = V_ASN1_NULL;
		digestInfo.algor->parameter->value.ptr = NULL;
		digestInfo.digest = &digest;
		digestInfo.digest->data = tmp;
		digestInfo.digest->length = (int)dglen;
		nread = i2d_X509_SIG(&digestInfo, &out);

		/*
		 * There is another undocumented openssl function that does
		 * this padding bit, but eh.
		 */
		memset(buf, 0xFF, inplen);
		buf[0] = 0x00;
		/* The second byte is the block type -- 0x01 here means 0xFF */
		buf[1] = 0x01;
		buf[inplen - nread - 1] = 0x00;
		bcopy(out, buf + (inplen - nread), nread);

		free(tmp);
		OPENSSL_free(out);
	}

	piv_txn_begin(selk);
	assert_pin(selk);
	rv = piv_sign_prehash(selk, cert, buf, inplen, &sig, &siglen);
	piv_txn_end(selk);
	if (rv == EPERM) {
		fprintf(stderr, "error: key in slot %02X requires PIN\n",
		    slotid);
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: piv_sign_hash returned %d\n", rv);
		exit(1);
	}

	fwrite(sig, 1, siglen, stdout);

	free(buf);
	exit(0);
}

static void
cmd_ecdh(uint slotid)
{
	struct piv_slot *cert;
	struct sshkey *pubkey;
	uint8_t *buf, *ptr, *secret;
	size_t nread, boff, seclen;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for ECDH\n", slotid);
		exit(3);
	}

	piv_txn_begin(selk);
	rv = piv_read_cert(selk, slotid);
	piv_txn_end(selk);

	cert = piv_get_slot(selk, slotid);

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	switch (cert->ps_alg) {
	case PIV_ALG_ECCP256:
	case PIV_ALG_ECCP384:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X does not contain an EC "
		    "key\n", slotid);
		exit(1);
	}

	buf = read_stdin(8192, &boff);
	assert(buf != NULL);

	pubkey = sshkey_new(cert->ps_pubkey->type);
	assert(pubkey != NULL);
	ptr = buf;
	rv = sshkey_read(pubkey, &ptr);
	if (rv != 0) {
		fprintf(stderr, "error: failed to parse public key: %d\n",
		    rv);
		exit(1);
	}

	piv_txn_begin(selk);
	assert_pin(selk);
	rv = piv_ecdh(selk, cert, pubkey, &secret, &seclen);
	piv_txn_end(selk);
	if (rv == EPERM) {
		fprintf(stderr, "error: key in slot %02X requires PIN\n",
		    slotid);
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: piv_ecdh returned %d\n", rv);
		exit(1);
	}

	fwrite(secret, 1, seclen, stdout);

	exit(0);
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: pivtool [options] <operation>\n"
	    "Available operations:\n"
	    "  list                   Lists PIV tokens present\n"
	    "  pubkey <slot>          Outputs a public key in SSH format\n"
	    "  sign <slot>            Signs data on stdin\n"
	    "  ecdh <slot>            Do ECDH with pubkey on stdin\n"
	    "\n"
	    "Options:\n"
	    "  --pin|-p               PIN code to authenticate with\n"
	    "  --debug|-d             Spit out lots of debug info to stderr\n"
	    "                         (incl. APDU trace)\n"
	    "  --parseable|-P         Generate parseable output from 'list'\n"
	    "  --guid|-g              GUID of the PIV token to use\n");
	exit(3);
}

//const char *optstring = "d(debug)P(parseable)g:(guid)p:(pin)";
const char *optstring = "dPg:p:";

int
main(int argc, char *argv[])
{
	LONG rv;
	SCARDCONTEXT ctx;
	extern char *optarg;
	extern int optind, optopt, opterr;
	int c;
	uint len;

	bunyan_init();
	bunyan_set_name("pivtool");

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(TRACE);
			break;
		case 'c':
			/*acc_code = parse_hex(optarg, &len);*/
			if (len != 6) {
				fprintf(stderr, "error: acc code must be "
				    "6 bytes in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'g':
			guid = parse_hex(optarg, &len);
			if (len != 16) {
				fprintf(stderr, "error: GUID must be 16 bytes "
				    "in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'p':
			pin = optarg;
			break;
		case 'P':
			parseable = B_TRUE;
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "error: operation required\n");
		usage();
	}

	const char *op = argv[optind++];

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEstablishContext failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}

	ks = piv_enumerate(ctx);

	if (strcmp(op, "list") == 0) {
		if (optind < argc)
			usage();
		cmd_list(ctx);
		return (0);
	}

	if (ks == NULL) {
		fprintf(stderr, "error: no PIV cards present\n");
		return (1);
	}
	if (guid != NULL) {
		for (selk = ks; selk != NULL; selk = selk->pt_next) {
			if (bcmp(selk->pt_guid, guid, 16) == 0)
				break;
		}
	}
	if (selk == NULL) {
		selk = ks;
		if (selk->pt_next != NULL) {
			fprintf(stderr, "error: multiple PIV cards present; "
			    "you must provide -g|--guid to select one\n");
			return (3);
		}
	}

	if (strcmp(op, "sign") == 0) {
		uint slotid;

		if (optind >= argc)
			usage();
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc)
			usage();

		cmd_sign(slotid);

	} else if (strcmp(op, "pubkey") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_pubkey(slotid);

	} else if (strcmp(op, "ecdh") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_ecdh(slotid);

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	return (0);
}

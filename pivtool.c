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
#include <errno.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>

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
static uint min_retries = 2;
static const char *pin = NULL;
static const uint8_t DEFAULT_ADMIN_KEY[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const uint8_t *admin_key = DEFAULT_ADMIN_KEY;

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
static struct piv_slot *override = NULL;

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
	uint retries = min_retries;

	if (pin != NULL) {
		rv = piv_verify_pin(pk, pin, &retries);
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

extern char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

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

		buf = buf_to_hex(pk->pt_guid, sizeof (pk->pt_guid), B_FALSE);
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
				case PIV_ALG_ECCP256_SHA1:
					printf("ECCP256-SHA1 ");
					break;
				case PIV_ALG_ECCP256_SHA256:
					printf("ECCP256-SHA256 ");
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
cmd_generate(uint slotid, enum piv_alg alg)
{
	struct piv_slot *slot;
	char *buf;
	int rv;
	struct sshkey *pub;
	X509 *cert;
	EVP_PKEY *pkey;
	X509_NAME *subj;
	const char *name;
	enum sshdigest_types hashalg;
	int nid;
	ASN1_TYPE null_parameter;
	uint8_t *tbs = NULL, *sig, *cdata = NULL;
	size_t tbslen, siglen, cdlen;
	uint flags;
	BIGNUM *serial;
	ASN1_INTEGER *serial_asn1;

	switch (slotid) {
	case 0x9A:
		name = "PIV Authentication";
		break;
	case 0x9C:
		name = "Digital Signature";
		break;
	case 0x9D:
		name = "Key Management";
		break;
	case 0x9E:
		name = "Card Authentication";
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric crypto\n", slotid);
		exit(3);
	}

	piv_txn_begin(selk);
	rv = piv_auth_admin(selk, admin_key, 24);
	if (rv == 0)
		rv = piv_generate(selk, slotid, alg, &pub);

	if (rv != 0) {
		piv_txn_end(selk);
		fprintf(stderr, "error: key generation failed (%d)\n", rv);
		exit(1);
	}

	pkey = EVP_PKEY_new();
	assert(pkey != NULL);
	if (pub->type == KEY_RSA) {
		RSA *copy = RSA_new();
		assert(copy != NULL);
		copy->e = BN_dup(pub->rsa->e);
		assert(copy->e != NULL);
		copy->n = BN_dup(pub->rsa->n);
		assert(copy->n != NULL);
		rv = EVP_PKEY_assign_RSA(pkey, copy);
		assert(rv == 1);
		nid = NID_sha256WithRSAEncryption;
	} else if (pub->type == KEY_ECDSA) {
		EC_KEY *copy = EC_KEY_dup(pub->ecdsa);
		rv = EVP_PKEY_assign_EC_KEY(pkey, copy);
		assert(rv == 1);
		nid = NID_ecdsa_with_SHA256;
	} else {
		assert(0);
	}

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	assert(serial != NULL);
	assert(BN_pseudo_rand(serial, 64, 0, 0) == 1);
	assert(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);

	cert = X509_new();
	assert(cert != NULL);
	assert(X509_set_version(cert, 2) == 1);
	assert(X509_set_serialNumber(cert, serial_asn1) == 1);
	assert(X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL);
	assert(X509_gmtime_adj(X509_get_notAfter(cert), 315360000L) != NULL);

	subj = X509_NAME_new();
	assert(subj != NULL);
	assert(X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
	    (unsigned char *)name, -1, -1, 0) == 1);
	assert(X509_set_subject_name(cert, subj) == 1);
	assert(X509_set_issuer_name(cert, subj) == 1);

	assert(X509_set_pubkey(cert, pkey) == 1);

	cert->sig_alg->algorithm = OBJ_nid2obj(nid);
	cert->cert_info->signature->algorithm = cert->sig_alg->algorithm;
	if (pub->type == KEY_RSA) {
		bzero(&null_parameter, sizeof (null_parameter));
		null_parameter.type = V_ASN1_NULL;
		null_parameter.value.ptr = NULL;
		cert->sig_alg->parameter = &null_parameter;
		cert->cert_info->signature->parameter = &null_parameter;
	}

	cert->cert_info->enc.modified = 1;
	tbslen = i2d_X509_CINF(cert->cert_info, &tbs);
	assert(tbs != NULL);
	assert(tbslen > 0);

	hashalg = SSH_DIGEST_SHA256;
	assert_pin(selk);
	rv = piv_sign(selk, override, tbs, tbslen, &hashalg, &sig, &siglen);

	if (rv == EPERM) {
		piv_txn_end(selk);
		fprintf(stderr, "error: slot in %02X requires a PIN\n",
		    slotid);
		exit(1);
	} else if (rv != 0) {
		piv_txn_end(selk);
		fprintf(stderr, "error: failed to sign cert with key\n");
		exit(1);
	}

	if (hashalg != SSH_DIGEST_SHA256) {
		piv_txn_end(selk);
		fprintf(stderr, "error: card requires hash-on-card and does "
		    "not support SHA256\n");
		exit(1);
	}

	M_ASN1_BIT_STRING_set(cert->signature, sig, siglen);
	cert->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;

	cdlen = i2d_X509(cert, &cdata);
	assert(cdata != NULL);
	assert(cdlen > 0);

	flags = PIV_COMP_NONE;
	rv = piv_write_cert(selk, slotid, cdata, cdlen, flags);
	piv_txn_end(selk);

	if (rv != 0) {
		fprintf(stderr, "error: failed to write cert\n");
		exit(1);
	}

	rv = sshkey_write(pub, stdout);
	if (rv != 0) {
		fprintf(stderr, "error: failed to write out key\n");
		exit(1);
	}
	buf = buf_to_hex(selk->pt_guid, sizeof (selk->pt_guid), B_FALSE);
	fprintf(stdout, " PIV_slot_%02X@%s\n", slotid, buf);
	free(buf);

	exit(0);
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

	rv = sshkey_write(cert->ps_pubkey, stdout);
	if (rv != 0) {
		fprintf(stderr, "error: failed to write out key\n");
		exit(1);
	}
	buf = buf_to_hex(selk->pt_guid, sizeof (selk->pt_guid), B_FALSE);
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
	enum sshdigest_types hashalg;
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

	if (override == NULL) {
		piv_txn_begin(selk);
		rv = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	buf = read_stdin(8192, &inplen);
	assert(buf != NULL);

	piv_txn_begin(selk);
	assert_pin(selk);
	hashalg = 0;
	rv = piv_sign(selk, cert, buf, inplen, &hashalg, &sig, &siglen);
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
cmd_box(uint slotid)
{
	struct piv_slot *slot;
	struct piv_ecdh_box *box;
	int rv;
	size_t len;
	uint8_t *buf;

	piv_txn_begin(selk);
	rv = piv_read_cert(selk, slotid);
	piv_txn_end(selk);
	if (rv == ENOENT) {
		fprintf(stderr, "error: slot %02X does not contain a key\n",
		    slotid);
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: slot %02X reading cert failed\n",
		    slotid);
		exit(1);
	}

	slot = piv_get_slot(selk, slotid);
	VERIFY3P(slot, !=, NULL);

	box = piv_box_new();
	VERIFY3P(box, !=, NULL);

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);
	VERIFY0(piv_box_set_data(box, buf, len));
	explicit_bzero(buf, len);
	free(buf);

	VERIFY0(piv_box_seal(selk, slot, box));

	VERIFY0(piv_box_to_binary(box, &buf, &len));
	piv_box_free(box);

	fwrite(buf, 1, len, stdout);
	explicit_bzero(buf, len);
	free(buf);
	exit(0);
}

static void
cmd_unbox(void)
{
	struct piv_token *tk;
	struct piv_slot *sl;
	struct piv_ecdh_box *box;
	int rv;
	size_t len;
	uint8_t *buf;
	char *guid;

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);

	if (piv_box_from_binary(buf, len, &box)) {
		fprintf(stderr, "error: failed parsing ecdh box\n");
		exit(1);
	}
	free(buf);

	rv = piv_box_find_token(ks, box, &tk, &sl);
	if (rv == ENOENT) {
		fprintf(stderr, "error: no token found on system that can "
		    "unlock this box\n");
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to communicate with token\n");
		exit(1);
	}

	piv_txn_begin(tk);
	assert_pin(tk);
	rv = piv_box_open(tk, sl, box);
	piv_txn_end(tk);

	if (rv == EPERM) {
		guid = buf_to_hex(tk->pt_guid, sizeof (tk->pt_guid), B_FALSE);
		fprintf(stderr, "error: token %s slot %02X requires a PIN\n",
		    guid, sl->ps_slot);
		free(guid);
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to communicate with token\n");
		exit(1);
	}

	VERIFY0(piv_box_take_data(box, &buf, &len));
	fwrite(buf, 1, len, stdout);
	explicit_bzero(buf, len);
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

	if (override == NULL) {
		piv_txn_begin(selk);
		rv = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

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

const char *
_umem_debug_init()
{
	return ("guards");
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
	    "  generate <slot>        Generate a new private key and a\n"
	    "                         self-signed cert\n"
	    "  box <slot>             Encrypts stdin data with an ECDH box\n"
	    "  unbox                  Decrypts stdin data with an ECDH box\n"
	    "                         Chooses token and slot automatically\n"
	    "\n"
	    "Options:\n"
	    "  --pin|-P <code>        PIN code to authenticate with\n"
	    "  --debug|-d             Spit out lots of debug info to stderr\n"
	    "                         (incl. APDU trace)\n"
	    "  --parseable|-p         Generate parseable output from 'list'\n"
	    "  --guid|-g              GUID of the PIV token to use\n"
	    "  --algorithm|-a <algo>  Override algorithm for the slot and\n"
	    "                         don't use the certificate\n");
	exit(3);
}

const char *optstring =
    "d(debug)"
    "p(parseable)"
    "g:(guid)"
    "P:(pin)"
    "a:(algorithm)"
    "f(force)";

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
		case 'f':
			min_retries = 0;
			break;
		case 'a':
			override = calloc(1, sizeof (struct piv_slot));
			if (strcasecmp(optarg, "rsa1024") == 0) {
				override->ps_alg = PIV_ALG_RSA1024;
			} else if (strcasecmp(optarg, "rsa2048") == 0) {
				override->ps_alg = PIV_ALG_RSA2048;
			} else if (strcasecmp(optarg, "eccp256") == 0) {
				override->ps_alg = PIV_ALG_ECCP256;
			} else if (strcasecmp(optarg, "eccp384") == 0) {
				override->ps_alg = PIV_ALG_ECCP384;
			} else if (strcasecmp(optarg, "3des") == 0) {
				override->ps_alg = PIV_ALG_3DES;
			} else {
				fprintf(stderr, "error: invalid algorithm\n");
				exit(3);
			}
			/* ps_slot will be set after we've parsed the slot */
			break;
		case 'g':
			guid = parse_hex(optarg, &len);
			if (len != 16) {
				fprintf(stderr, "error: GUID must be 16 bytes "
				    "in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'P':
			pin = optarg;
			break;
		case 'p':
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
	if (selk == NULL && strcmp(op, "unbox") != 0) {
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

		if (override != NULL)
			override->ps_slot = slotid;

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

		if (override != NULL)
			override->ps_slot = slotid;

		cmd_ecdh(slotid);

	} else if (strcmp(op, "box") == 0) {
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

		if (override != NULL)
			override->ps_slot = slotid;

		cmd_box(slotid);

	} else if (strcmp(op, "unbox") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		cmd_unbox();

	} else if (strcmp(op, "generate") == 0) {
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

		if (override == NULL) {
			fprintf(stderr, "error: algorithm required\n");
			usage();
		}
		override->ps_slot = slotid;

		cmd_generate(slotid, override->ps_alg);

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	return (0);
}

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
#include "digest.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tlv.h"

boolean_t debug = B_FALSE;
static boolean_t parseable = B_FALSE;
static uint8_t *guid = NULL;

static struct pivkey *ks = NULL;
static struct pivkey *selk = NULL;

enum iso_class {
	CLA_ISO = 0x00,
	CLA_CHAIN = 0x10
};

enum iso_sel_p1 {
	SEL_APP_AID = 0x04
};

enum iso_ins {
	/* Standard commands from ISO7816-4 */
	INS_SELECT = 0xA4,
	INS_GET_DATA = 0xCB,
	INS_VERIFY = 0x20,
	INS_CHANGE_PIN = 0x24,
	INS_RESET_PIN = 0x2C,
	INS_GEN_AUTH = 0x87,
	INS_PUT_DATA = 0xDB,
	INS_GEN_ASYM = 0x47,
	INS_CONTINUE = 0xC0,

	/* YubicoPIV specific */
	INS_SET_MGMT = 0xFF,
	INS_IMPORT_ASYM = 0xFE,
	INS_GET_VER = 0xFD,
};

enum iso_sw {
	SW_NO_ERROR = 0x9000,
	SW_FUNC_NOT_SUPPORTED = 0x6A81,
	SW_CONDITIONS_NOT_SATISFIED = 0x6985,
	SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982,
	SW_BYTES_REMAINING_00 = 0x6100,
	SW_WARNING_NO_CHANGE_00 = 0x6200,
	SW_WARNING_00 = 0x6300,
	SW_FILE_NOT_FOUND = 0x6A82,
};

enum piv_sel_tag {
	PIV_TAG_APT = 0x61,
	PIV_TAG_AID = 0x4F,
	PIV_TAG_AUTHORITY = 0x79,
	PIV_TAG_APP_LABEL = 0x50,
	PIV_TAG_URI = 0x5F50,
	PIV_TAG_ALGS = 0xAC,
};

enum piv_tags {
	PIV_TAG_CARDCAP = 0x5FC107,
	PIV_TAG_CHUID = 0x5FC102,
	PIV_TAG_SECOBJ = 0x5FC106,
	PIV_TAG_KEYHIST = 0x5FC10C,
	PIV_TAG_DISCOV = 0x7E,
	PIV_TAG_CERT_9A = 0x5FC105,
	PIV_TAG_CERT_9C = 0x5FC10A,
	PIV_TAG_CERT_9D = 0x5FC10B,
	PIV_TAG_CERT_9E = 0x5FC101,
};

enum gen_auth_tag {
	GA_TAG_WITNESS = 0x80,
	GA_TAG_CHALLENGE = 0x81,
	GA_TAG_RESPONSE = 0x82,
	GA_TAG_EXP = 0x85,
};

enum piv_alg {
	PIV_ALG_3DES = 0x03,
	PIV_ALG_RSA1024 = 0x06,
	PIV_ALG_RSA2048 = 0x07,
	PIV_ALG_AES128 = 0x08,
	PIV_ALG_AES192 = 0x0A,
	PIV_ALG_AES256 = 0x0C,
	PIV_ALG_ECCP256 = 0x11,
	PIV_ALG_ECCP384 = 0x14,
};

enum piv_cert_comp {
	PIV_COMP_GZIP = 1,
	PIV_COMP_NONE = 0,
};

enum piv_certinfo_flags {
	PIV_CI_X509 = (1 << 2),
	PIV_CI_COMPTYPE = 0x03,
};

const uint8_t AID_PIV[] = {
	0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

struct buffer {
	uint8_t *b_data;
	size_t b_offset;
	size_t b_size;
	size_t b_len;
};

struct apdu {
	enum iso_class a_cls;
	enum iso_ins a_ins;
	uint8_t a_p1;
	uint8_t a_p2;

	struct buffer a_cmd;
	uint16_t a_sw;
	struct buffer a_reply;
};

struct pivcert {
	struct pivcert *pc_next;
	uint8_t pc_slot;
	enum piv_alg pc_alg;
	X509 *pc_x509;
	const char *pc_subj;
	struct sshkey *pc_pubkey;
};

struct pivkey {
	struct pivkey *pk_next;
	const char *pk_rdrname;
	SCARDHANDLE pk_cardhdl;
	DWORD pk_proto;
	SCARD_IO_REQUEST pk_sendpci;
	boolean_t pk_intxn;

	uint8_t pk_guid[16];
	enum piv_alg pk_algs[32];
	size_t pk_alg_count;

	struct pivcert *pk_certs;
};

static void
dump_hex(FILE *stream, const uint8_t *buf, int len)
{
	int i;
	for (i = 0; i < len; ++i) {
		fprintf(stream, "%02x", buf[i]);
	}
}

static uint8_t *
apdu_to_buffer(struct apdu *apdu, uint *outlen)
{
	struct buffer *d = &(apdu->a_cmd);
	uint8_t *buf = calloc(1, 5 + d->b_len);
	buf[0] = apdu->a_cls;
	buf[1] = apdu->a_ins;
	buf[2] = apdu->a_p1;
	buf[3] = apdu->a_p2;
	if (d->b_data == NULL) {
		buf[4] = 0;
		*outlen = 5;
		return (buf);
	} else {
		assert(d->b_len < 256 && d->b_len > 0);
		buf[4] = d->b_len;
		bcopy(d->b_data + d->b_offset, buf + 5, d->b_len);
		*outlen = d->b_len + 5;
		return (buf);
	}
}

static struct apdu *
make_apdu(enum iso_class cls, enum iso_ins ins, uint8_t p1, uint8_t p2)
{
	struct apdu *a = calloc(1, sizeof (struct apdu));
	a->a_cls = cls;
	a->a_ins = ins;
	a->a_p1 = p1;
	a->a_p2 = p2;
	return (a);
}

static void
free_apdu(struct apdu *a)
{
	if (a->a_reply.b_data != NULL)
		free(a->a_reply.b_data);
	free(a);
}

static int
transceive_apdu(struct pivkey *key, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;

	boolean_t freedata = B_FALSE;
	DWORD recvLength;
	uint8_t *cmd;
	struct buffer *r = &(apdu->a_reply);

	assert(key->pk_intxn == B_TRUE);

	cmd = apdu_to_buffer(apdu, &cmdLen);
	assert(cmd != NULL);
	if (cmd == NULL || cmdLen < 5)
		return (ENOMEM);

	if (r->b_data == NULL) {
		r->b_data = calloc(1, MAX_APDU_SIZE);
		r->b_size = MAX_APDU_SIZE;
		r->b_offset = 0;
		freedata = B_TRUE;
	}
	recvLength = r->b_size - r->b_offset;
	assert(r->b_data != NULL);

	if (debug == B_TRUE) {
		fprintf(stderr, "> ");
		dump_hex(stderr, cmd, cmdLen);
		fprintf(stderr, "\n");
	}

	rv = SCardTransmit(key->pk_cardhdl, &key->pk_sendpci, cmd,
	    cmdLen, NULL, r->b_data + r->b_offset, &recvLength);
	free(cmd);

	if (debug == B_TRUE) {
		fprintf(stderr, "< ");
		dump_hex(stderr, r->b_data + r->b_offset, recvLength);
		fprintf(stderr, "\n");
	}

	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardTransmit(%s) failed: %s\n",
		    key->pk_rdrname, pcsc_stringify_error(rv));
		if (freedata) {
			free(r->b_data);
			bzero(r, sizeof (struct buffer));
		}
		return (rv);
	}
	recvLength -= 2;

	r->b_len = recvLength;
	apdu->a_sw = (r->b_data[r->b_offset + recvLength] << 8) |
	    r->b_data[r->b_offset + recvLength + 1];

	return (0);
}

static int
transceive_apdu_chain(struct pivkey *pk, struct apdu *apdu)
{
	int rv;
	size_t offset;
	size_t rem;

	assert(pk->pk_intxn == B_TRUE);

	rem = apdu->a_cmd.b_len;
	while (rem > 0) {
		if (rem > 0xFF) {
			apdu->a_cls |= CLA_CHAIN;
			apdu->a_cmd.b_len = 0xFF;
		} else {
			apdu->a_cls &= ~CLA_CHAIN;
			apdu->a_cmd.b_len = rem;
		}
		rv = transceive_apdu(pk, apdu);
		if (rv != 0)
			return (rv);
		if ((apdu->a_sw & 0xFF00) == SW_NO_ERROR ||
		    (apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00 ||
		    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
		    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
			apdu->a_cmd.b_offset += apdu->a_cmd.b_len;
			rem -= apdu->a_cmd.b_len;
		} else {
			return (0);
		}
	}

	offset = apdu->a_reply.b_offset;

	while ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00) {
		apdu->a_cls = CLA_ISO;
		apdu->a_ins = INS_CONTINUE;
		apdu->a_p1 = 0;
		apdu->a_p2 = 0;
		apdu->a_cmd.b_data = NULL;
		apdu->a_reply.b_offset += apdu->a_reply.b_len;
		assert(apdu->a_reply.b_offset < apdu->a_reply.b_size);

		rv = transceive_apdu(pk, apdu);
		if (rv != 0)
			return (rv);
	}

	apdu->a_reply.b_len += apdu->a_reply.b_offset - offset;
	apdu->a_reply.b_offset = offset;

	return (0);
}

static int
piv_sign_hash(struct pivkey *pk, uint slotid, uint8_t *hash, size_t hashlen,
    uint8_t **signature, size_t *siglen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	struct pivcert *pc;
	uint8_t *buf;

	for (pc = pk->pk_certs; pc != NULL; pc = pc->pc_next) {
		if (pc->pc_slot == slotid)
			break;
	}
	if (pc == NULL)
		return (ENOENT);

	assert(pk->pk_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x7C, hashlen + 16);
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	tlv_pushl(tlv, GA_TAG_CHALLENGE, hashlen);
	tlv_write(tlv, hash, 0, hashlen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = make_apdu(CLA_ISO, INS_GEN_AUTH, pc->pc_alg, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = transceive_apdu_chain(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu_chain(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		tlv_free(tlv);
		free_apdu(apdu);
		return (1);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			if (debug == B_TRUE) {
				fprintf(stderr, "card in %s returned wrong tag"
				    " to INS_GEN_AUTH\n", pk->pk_rdrname);
			}
			tlv_skip(tlv);
			tlv_free(tlv);
			free_apdu(apdu);
			return (1);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			free_apdu(apdu);
			return (1);
		}

		*siglen = tlv_rem(tlv);
		buf = calloc(1, *siglen);
		assert(buf != NULL);
		*siglen = tlv_read(tlv, buf, 0, *siglen);
		*signature = buf;

		tlv_end(tlv);
		tlv_end(tlv);
		tlv_free(tlv);

		rv = 0;
	} else {
		if (debug == B_TRUE) {
			fprintf(stderr, "card in %s returned sw = %04x to "
			    "INS_GEN_AUTH\n", pk->pk_rdrname, apdu->a_sw);
		}
		rv = 1;
	}

	free_apdu(apdu);

	return (rv);
}

static int
piv_read_cert(struct pivkey *pk, uint slotid)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;
	uint8_t *ptr;
	size_t len;
	X509 *cert;
	struct pivcert *pc;
	EVP_PKEY *pkey;
	uint8_t certinfo = 0;

	assert(pk->pk_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	switch (slotid) {
	case 0x9A:
		tlv_write_uint(tlv, PIV_TAG_CERT_9A);
		break;
	case 0x9C:
		tlv_write_uint(tlv, PIV_TAG_CERT_9C);
		break;
	case 0x9D:
		tlv_write_uint(tlv, PIV_TAG_CERT_9D);
		break;
	case 0x9E:
		tlv_write_uint(tlv, PIV_TAG_CERT_9E);
		break;
	default:
		assert(0);
	}
	tlv_pop(tlv);

	apdu = make_apdu(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = transceive_apdu_chain(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu_chain(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		tlv_free(tlv);
		free_apdu(apdu);
		return (1);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			if (debug == B_TRUE) {
				fprintf(stderr, "card in %s returned tag "
				    " to INS_GET_DATA\n", pk->pk_rdrname);
			}
			tlv_skip(tlv);
			tlv_free(tlv);
			free_apdu(apdu);
			return (1);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			if (tag == 0x71) {
				certinfo = tlv_read_byte(tlv);
				tlv_end(tlv);
				continue;
			}
			if (tag == 0x70) {
				ptr = tlv_ptr(tlv);
				len = tlv_rem(tlv);
			}
			tlv_skip(tlv);
		}
		tlv_end(tlv);

		if ((certinfo & PIV_CI_X509) != 0) {
			if (debug == B_TRUE) {
				fprintf(stderr, "cert in slot %02X of PIV card "
				    "in %s is not x509, ignoring\n",
				    slotid, pk->pk_rdrname);
			}
			tlv_free(tlv);
			free_apdu(apdu);
			return (1);
		}

		if ((certinfo & PIV_CI_COMPTYPE) != PIV_COMP_NONE) {
			if (debug == B_TRUE) {
				fprintf(stderr, "cert in slot %02X of PIV card "
				    "in %s is compressed, ignoring\n",
				    slotid, pk->pk_rdrname);
			}
			tlv_free(tlv);
			free_apdu(apdu);
			return (1);
		}

		cert = d2i_X509(NULL, &ptr, len);
		if (cert == NULL) {
			char errbuf[128];
			unsigned long err = ERR_peek_last_error();
			if (debug == B_TRUE) {
				ERR_load_crypto_strings();
				ERR_error_string(err, errbuf);
				fprintf(stderr, "openssl: %s\n", errbuf);
			}
			tlv_free(tlv);
			free_apdu(apdu);
			return (1);
		}

		tlv_free(tlv);

		for (pc = pk->pk_certs; pc != NULL; pc = pc->pc_next) {
			if (pc->pc_slot == slotid)
				break;
		}
		if (pc == NULL) {
			pc = calloc(1, sizeof (struct pivcert));
			assert(pc != NULL);
			pc->pc_next = pk->pk_certs;
			pk->pk_certs = pc;
		} else {
			fprintf(stderr, "got existing slot, freeing data\n");
			OPENSSL_free(pc->pc_subj);
			X509_free(pc->pc_x509);
			sshkey_free(pc->pc_pubkey);
		}
		pc->pc_slot = slotid;
		pc->pc_x509 = cert;
		pc->pc_subj = X509_NAME_oneline(
		    X509_get_subject_name(cert), NULL, 0);
		pkey = X509_get_pubkey(cert);
		assert(pkey != NULL);
		assert(sshkey_from_evp_pkey(pkey, KEY_UNSPEC,
		    &pc->pc_pubkey) == 0);

		switch (pc->pc_pubkey->type) {
		case KEY_ECDSA:
			switch (sshkey_size(pc->pc_pubkey)) {
			case 256:
				pc->pc_alg = PIV_ALG_ECCP256;
				break;
			case 384:
				pc->pc_alg = PIV_ALG_ECCP384;
				break;
			default:
				assert(0);
			}
			break;
		case KEY_RSA:
			switch (sshkey_size(pc->pc_pubkey)) {
			case 1024:
				pc->pc_alg = PIV_ALG_RSA1024;
				break;
			case 2048:
				pc->pc_alg = PIV_ALG_RSA2048;
				break;
			default:
				assert(0);
			}
			break;
		default:
			assert(0);
		}

		rv = 0;
	} else {
		if (debug == B_TRUE) {
			fprintf(stderr, "card in %s returned sw = %04x to "
			    "INS_GET_DATA\n", pk->pk_rdrname, apdu->a_sw);
		}
		rv = 1;
	}

	free_apdu(apdu);

	return (rv);
}

static void
read_all_certs(struct pivkey *pk)
{
	piv_read_cert(pk, 0x9A);
	piv_read_cert(pk, 0x9C);
	piv_read_cert(pk, 0x9D);
	piv_read_cert(pk, 0x9E);
}

static int
piv_read_chuid(struct pivkey *pk)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;

	assert(pk->pk_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, PIV_TAG_CHUID);
	tlv_pop(tlv);

	apdu = make_apdu(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = transceive_apdu(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		tlv_free(tlv);
		free_apdu(apdu);
		return (1);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			if (debug == B_TRUE) {
				fprintf(stderr, "card in %s returned tag "
				    " to INS_GET_DATA\n", pk->pk_rdrname);
			}
			free_apdu(apdu);
			return (1);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			switch (tag) {
			case 0xEE:	/* Buffer Length */
			case 0x30:	/* FASC-N */
			case 0x32:	/* Org Ident */
			case 0x33:	/* DUNS */
			case 0x35:	/* Expiration date */
			case 0x36:	/* Cardholder UUID */
			case 0x3E:	/* Signature */
			case 0xFE:	/* CRC */
				tlv_skip(tlv);
				break;
			case 0x34:	/* Card GUID */
				assert(tlv_read(tlv, pk->pk_guid, 0,
				    sizeof (pk->pk_guid)) ==
				    sizeof (pk->pk_guid));
				tlv_end(tlv);
				break;
			default:
				assert(0);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;
	} else {
		if (debug == B_TRUE) {
			fprintf(stderr, "card in %s returned sw = %04x to "
			    "INS_GET_DATA\n", pk->pk_rdrname, apdu->a_sw);
		}
		rv = 1;
	}

	free_apdu(apdu);

	return (rv);
}

static int
piv_select(struct pivkey *pk)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;

	assert(pk->pk_intxn == B_TRUE);

	apdu = make_apdu(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);
	apdu->a_cmd.b_data = (uint8_t *)AID_PIV;
	apdu->a_cmd.b_len = sizeof (AID_PIV);

	rv = transceive_apdu(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		free_apdu(apdu);
		return (1);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != PIV_TAG_APT) {
			if (debug == B_TRUE) {
				fprintf(stderr, "card in %s returned bad app "
				    "info tag to INS_SELECT\n", pk->pk_rdrname);
			}
			free_apdu(apdu);
			return (1);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			switch (tag) {
			case PIV_TAG_AID:
				tlv_skip(tlv);
				break;
			case PIV_TAG_AUTHORITY:
				tlv_skip(tlv);
				break;
			case PIV_TAG_APP_LABEL:
				tlv_skip(tlv);
				break;
			case PIV_TAG_URI:
				tlv_skip(tlv);
				break;
			case PIV_TAG_ALGS:
				if (pk->pk_alg_count > 0) {
					tlv_skip(tlv);
					break;
				}
				while (!tlv_at_end(tlv)) {
					tag = tlv_read_tag(tlv);
					if (tag == 0x80) {
						idx = pk->pk_alg_count++;
						pk->pk_algs[idx] =
						    tlv_read_uint(tlv);
						tlv_end(tlv);
					} else if (tag == 0x06) {
						tlv_skip(tlv);
					} else {
						assert(0);
					}
				}
				tlv_end(tlv);
				break;
			default:
				assert(0);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;
	} else {
		if (debug == B_TRUE) {
			fprintf(stderr, "card in %s returned sw = %04x to "
			    "INS_SELECT\n", pk->pk_rdrname, apdu->a_sw);
		}
		rv = 1;
	}

	free_apdu(apdu);

	return (rv);
}

static void
piv_begin_txn(struct pivkey *key)
{
	assert(key->pk_intxn == B_FALSE);
	LONG rv;
	rv = SCardBeginTransaction(key->pk_cardhdl);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardBeginTransaction(%s) failed: %s\n",
		    key->pk_rdrname, pcsc_stringify_error(rv));
		exit(1);
	}
	key->pk_intxn = B_TRUE;
}

static void
piv_end_txn(struct pivkey *key)
{
	assert(key->pk_intxn == B_TRUE);
	LONG rv;
	rv = SCardEndTransaction(key->pk_cardhdl, SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEndTransaction(%s) failed: %s\n",
		    key->pk_rdrname, pcsc_stringify_error(rv));
		exit(1);
	}
	key->pk_intxn = B_FALSE;
}

static void
find_all_pivkeys(SCARDCONTEXT ctx)
{
	DWORD rv, readersLen;
	LPTSTR readers, thisrdr;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders failed: %s\n",
		    pcsc_stringify_error(rv));
		exit(1);
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders failed: %s\n",
		    pcsc_stringify_error(rv));
		exit(1);
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		struct pivkey *key;
		DWORD activeProtocol;

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			if (debug == B_TRUE) {
				fprintf(stderr, "SCardConnect(%s) failed: %s\n",
				    thisrdr, pcsc_stringify_error(rv));
			}
			continue;
		}

		key = calloc(1, sizeof (struct pivkey));
		key->pk_cardhdl = card;
		key->pk_rdrname = thisrdr;
		key->pk_proto = activeProtocol;

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			key->pk_sendpci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			key->pk_sendpci = *SCARD_PCI_T1;
			break;
		default:
			assert(0);
		}

		piv_begin_txn(key);
		rv = piv_select(key);
		if (rv == 0)
			rv = piv_read_chuid(key);
		if (rv == 0)
			read_all_certs(key);
		piv_end_txn(key);

		if (rv == 0) {
			key->pk_next = ks;
			ks = key;
		} else {
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}
}

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
read_stdin(uint limit, uint *outlen)
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
cmd_list(SCARDCONTEXT ctx)
{
	struct pivkey *pk;
	struct pivcert *cert;
	int i;

	for (pk = ks; pk != NULL; pk = pk->pk_next) {
		printf("PIV card in '%s': guid = ",
		    pk->pk_rdrname);
		dump_hex(stdout, pk->pk_guid, sizeof (pk->pk_guid));
		fprintf(stdout, "\n");
		if (pk->pk_alg_count > 0) {
			printf("  * supports: ");
			for (i = 0; i < pk->pk_alg_count; ++i) {
				switch (pk->pk_algs[i]) {
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
		for (cert = pk->pk_certs; cert != NULL; cert = cert->pc_next) {
			printf("  * slot %02X: %s (%s %d)\n", cert->pc_slot,
			    cert->pc_subj, sshkey_type(cert->pc_pubkey),
			    sshkey_size(cert->pc_pubkey));
		}
	}
}

static void
cmd_pubkey(uint slotid)
{
	struct pivcert *cert;
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

	for (cert = selk->pk_certs; cert != NULL; cert = cert->pc_next) {
		if (cert->pc_slot == slotid)
			break;
	}
	if (cert == NULL) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	}

	rv = sshkey_write(cert->pc_pubkey, stdout);
	if (rv != 0) {
		fprintf(stderr, "error: failed to write out key\n");
		exit(1);
	}
	fprintf(stdout, " PIV_slot_%02X@", slotid);
	dump_hex(stdout, selk->pk_guid, sizeof (selk->pk_guid));
	fprintf(stdout, " \"%s\"\n", cert->pc_subj);
	exit(0);
}

static void
cmd_sign(uint slotid)
{
	struct pivcert *cert;
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

	for (cert = selk->pk_certs; cert != NULL; cert = cert->pc_next) {
		if (cert->pc_slot == slotid)
			break;
	}
	if (cert == NULL) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	}

	switch (cert->pc_alg) {
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

	if (cert->pc_alg == PIV_ALG_RSA1024 ||
	    cert->pc_alg == PIV_ALG_RSA2048) {
		int nid;
		X509_SIG digestInfo;
		X509_ALGOR algor;
		ASN1_TYPE parameter;
		ASN1_OCTET_STRING digest;
		uint8_t *tmp, *out;

		tmp = calloc(1, inplen);
		assert(tmp != NULL);
		out = NULL;

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

		memset(buf, 0xFF, inplen);
		buf[0] = 0x00;
		buf[1] = 0x01;
		buf[inplen - nread - 1] = 0x00;
		bcopy(out, buf + (inplen - nread), nread);

		free(tmp);
		OPENSSL_free(out);
	}

	piv_begin_txn(selk);
	rv = piv_sign_hash(selk, slotid, buf, inplen, &sig, &siglen);
	piv_end_txn(selk);
	if (rv != 0) {
		fprintf(stderr, "error: piv_sign_hash returned %d\n", rv);
		exit(1);
	}

	fwrite(sig, 1, siglen, stdout);

	free(buf);
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
	    "\n"
	    "Options:\n"
	    "  --debug|-d             Spit out lots of debug info to stderr\n"
	    "                         (incl. APDU trace)\n"
	    "  --parseable|-p         Generate parseable output from 'list'\n"
	    "  --guid|-g              GUID of the PIV token to use\n");
	exit(3);
}

const char *optstring = "d(debug)p(parseable)g:(guid)";

int
main(int argc, char *argv[])
{
	LONG rv;
	SCARDCONTEXT ctx;
	extern char *optarg;
	extern int optind, optopt, opterr;
	int c;
	uint len;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			debug = B_TRUE;
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
			parseable = B_TRUE;
			break;
		}
	}

	if (optind >= argc)
		usage();

	const char *op = argv[optind++];

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEstablishContext failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}

	find_all_pivkeys(ctx);

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
		for (selk = ks; selk != NULL; selk = selk->pk_next) {
			if (bcmp(selk->pk_guid, guid, 16) == 0)
				break;
		}
	}
	if (selk == NULL) {
		selk = ks;
		if (selk->pk_next != NULL) {
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

		if (optind >= argc)
			usage();
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc)
			usage();

		cmd_pubkey(slotid);

	} else {
		usage();
	}

	return (0);
}

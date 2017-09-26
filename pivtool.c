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

#include "tlv.h"

boolean_t debug = B_FALSE;
static boolean_t parseable = B_FALSE;

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

const uint8_t AID_PIV[] = {
	0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

struct apdu {
	enum iso_class a_cls;
	enum iso_ins a_ins;
	uint8_t a_p1;
	uint8_t a_p2;

	uint8_t *a_data;
	uint a_dataoff;
	uint8_t a_datalen;

	uint16_t a_sw;
	uint8_t *a_reply;
	uint a_replylen;
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
};

static void
dump_hex(FILE *stream, const uint8_t *buf, int len)
{
	int i;
	for (i = 0; i < len; ++i) {
		fprintf(stream, "%02x", buf[i]);
	}
	fprintf(stream, "\n");
}

static uint8_t *
apdu_to_buffer(struct apdu *apdu, uint *outlen)
{
	uint8_t *buf = calloc(1, 5 + apdu->a_datalen);
	buf[0] = apdu->a_cls;
	buf[1] = apdu->a_ins;
	buf[2] = apdu->a_p1;
	buf[3] = apdu->a_p2;
	if (apdu->a_data == NULL) {
		buf[4] = 0;
		*outlen = 5;
		return (buf);
	} else {
		buf[4] = apdu->a_datalen;
		bcopy(apdu->a_data + apdu->a_dataoff, buf + 5, apdu->a_datalen);
		*outlen = apdu->a_datalen + 5;
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
	if (a->a_reply != NULL)
		free(a->a_reply);
	free(a);
}

static int
transceive_apdu(struct pivkey *key, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;
	DWORD recvLength;
	assert(key->pk_intxn == B_TRUE);
	uint8_t *recvBuffer = calloc(1, MAX_APDU_SIZE);
	uint8_t *cmd = apdu_to_buffer(apdu, &cmdLen);
	if (cmd == NULL || cmdLen < 5)
		return (ENOMEM);

	if (debug == B_TRUE) {
		fprintf(stderr, "> ");
		dump_hex(stderr, cmd, cmdLen);
	}

	recvLength = MAX_APDU_SIZE;
	rv = SCardTransmit(key->pk_cardhdl, &key->pk_sendpci, cmd,
	    cmdLen, NULL, recvBuffer, &recvLength);

	if (debug == B_TRUE) {
		fprintf(stderr, "< ");
		dump_hex(stderr, recvBuffer, recvLength);
	}

	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardTransmit(%s) failed: %s\n",
		    key->pk_rdrname, pcsc_stringify_error(rv));
		free(cmd);
		free(recvBuffer);
		cmd = NULL;
		return (rv);
	}
	recvLength -= 2;

	apdu->a_reply = recvBuffer;
	apdu->a_replylen = recvLength;
	apdu->a_sw = (recvBuffer[recvLength] << 8) | recvBuffer[recvLength + 1];

	return (0);
}

static int
piv_test_cert(struct pivkey *pk, uint slotid)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;

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
	apdu->a_data = tlv_buf(tlv);
	apdu->a_datalen = tlv_len(tlv);

	rv = transceive_apdu(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		tlv_free(tlv);
		free_apdu(apdu);
		return (1);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00) {
		rv = 0;
	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		rv = ENOENT;
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
piv_read_cert(struct pivkey *pk, uint slotid, char **dest, size_t *len)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;
	char *buf;
	size_t bufptr = 0;

	buf = calloc(1, MAX_APDU_SIZE);
	assert(buf != NULL);

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
	apdu->a_data = tlv_buf(tlv);
	apdu->a_datalen = tlv_len(tlv);

	rv = transceive_apdu(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		tlv_free(tlv);
		free_apdu(apdu);
		free(buf);
		return (1);
	}

	tlv_free(tlv);

	while ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00) {
		bcopy(apdu->a_reply, buf + bufptr, apdu->a_replylen);
		bufptr += apdu->a_replylen;

		apdu_free(apdu);
		apdu = make_apdu(CLA_ISO, INS_CONTINUE, 0, 0);
		rv = transceive_apdu(pk, apdu);
		if (rv != 0) {
			fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
			    pk->pk_rdrname, rv);
			free_apdu(apdu);
			free(buf);
			return (1);
		}
	}

	bcopy(apdu->a_reply, buf + bufptr, apdu->a_replylen);
	bufptr += apdu->a_replylen;

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(buf, 0, bufptr);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			if (debug == B_TRUE) {
				fprintf(stderr, "card in %s returned tag "
				    " to INS_GET_DATA\n", pk->pk_rdrname);
			}
			free_apdu(apdu);
			return (1);
		}
		*len = tlv_rem(tlv);
		*dest = calloc(1, *len);
		assert(*dest != NULL);
		*len = tlv_read(tlv, *dest, 0, *len);
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
	free(buf);

	return (rv);
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
	apdu->a_data = tlv_buf(tlv);
	apdu->a_datalen = tlv_len(tlv);

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
		tlv = tlv_init(apdu->a_reply, 0, apdu->a_replylen);
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
	apdu->a_data = (uint8_t *)AID_PIV;
	apdu->a_datalen = sizeof (AID_PIV);

	rv = transceive_apdu(pk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    pk->pk_rdrname, rv);
		free_apdu(apdu);
		return (1);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply, 0, apdu->a_replylen);
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
	int i;
	for (pk = ks; pk != NULL; pk = pk->pk_next) {
		printf("PIV card in '%s': guid = ",
		    pk->pk_rdrname);
		dump_hex(stdout, pk->pk_guid, sizeof (pk->pk_guid));
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
		piv_begin_txn(pk);
		if (piv_test_cert(pk, 0x9A) == 0)
			printf("  * cert in slot 9A\n");
		if (piv_test_cert(pk, 0x9C) == 0)
			printf("  * cert in slot 9C\n");
		if (piv_test_cert(pk, 0x9D) == 0)
			printf("  * cert in slot 9D\n");
		if (piv_test_cert(pk, 0x9E) == 0)
			printf("  * cert in slot 9E\n");
		piv_end_txn(pk);
	}
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: pivtool [options] <operation>\n"
	    "Available operations:\n"
	    "  list                   Lists PIV tokens present\n"
	    "\n"
	    "Options:\n"
	    "  --hex-out|-x           Outputs on stdout are in hex\n"
	    "  --hex-in|-X            Inputs on stdin are in hex\n"
	    "  --serial|-s <#>        Select a specific Yubikey by serial #\n"
	    "  --debug|-d             Spit out lots of debug info to stderr\n"
	    "                         (incl. APDU trace)\n"
	    "  --parseable|-p         Generate parseable output from 'list'\n"
	    "  --acc-code|-c <..>     Provide access code for programming\n"
	    "  --set-acc-code|-C <..> Set the slot access code\n");
	exit(3);
}

const char *optstring = "d(debug)p(parseable)";

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

	} else {
		usage();
	}

	return (0);
}

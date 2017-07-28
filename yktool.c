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
#include <strings.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/errno.h>

static boolean_t debug = B_FALSE;
static boolean_t hex_out = B_FALSE;
static boolean_t hex_in = B_FALSE;
static boolean_t parseable = B_FALSE;
static uint8_t *acc_code = NULL;
static uint8_t *new_acc_code = NULL;

static struct yubikey *yks = NULL;
static struct yubikey *selyk = NULL;

enum iso_class {
	CLA_ISO = 0x00,
	CLA_CHAIN = 0x10
};

enum iso_sel_p1 {
	SEL_APP_AID = 0x04
};

enum iso_ins {
	INS_SELECT = 0xA4,
	INS_API_REQ = 0x01,
	INS_OTP = 0x02,
	INS_STATUS = 0x03,
	INS_NDEF = 0x04
};

enum yk_cmd {
	CMD_SET_CONF_1 = 0x01,
	CMD_SET_CONF_2 = 0x03,
	CMD_UPDATE_CONF_1 = 0x04,
	CMD_UPDATE_CONF_2 = 0x05,
	CMD_SWAP = 0x06,
	CMD_GET_SERIAL = 0x10,
	CMD_DEV_CONF = 0x11,
	CMD_SET_SCAN_MAP = 0x12,
	CMD_GET_YK4_CAPS = 0x13,

	CMD_OTP_1 = 0x20,
	CMD_OTP_2 = 0x28,

	CMD_HMAC_1 = 0x30,
	CMD_HMAC_2 = 0x38
};

const uint8_t PGM_SEQ_INVALID = 0x00;

const uint16_t CONFIG1_VALID = 0x01;
const uint16_t CONFIG1_TOUCH = 0x04;
const uint16_t CONFIG2_VALID = 0x02;
const uint16_t CONFIG2_TOUCH = 0x08;

enum iso_sw {
	SW_NO_ERROR = 0x9000,
	SW_CONDITIONS_NOT_SATISFIED = 0x6985
};

const uint8_t AID_YUBIOTP[] = {
	0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

const uint32_t MAX_APDU_SIZE = 16384;

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

struct yubikey {
	struct yubikey *yk_next;
	const char *yk_rdrname;
	uint8_t yk_version[3];
	uint8_t yk_pgmseq;
	SCARDHANDLE yk_cardhdl;
	DWORD yk_proto;
	uint16_t yk_touchlvl;
	SCARD_IO_REQUEST yk_sendpci;
	boolean_t yk_intxn;
	uint32_t yk_serial;
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
	uint8_t *buf = calloc(5 + apdu->a_datalen, 1);
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
	struct apdu *a = calloc(sizeof (struct apdu), 1);
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
transceive_apdu(struct yubikey *ykey, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;
	DWORD recvLength;
	assert(ykey->yk_intxn == B_TRUE);
	uint8_t *recvBuffer = calloc(MAX_APDU_SIZE, 1);
	uint8_t *cmd = apdu_to_buffer(apdu, &cmdLen);
	if (cmd == NULL || cmdLen < 5)
		return (ENOMEM);

	if (debug == B_TRUE) {
		fprintf(stderr, "> ");
		dump_hex(stderr, cmd, cmdLen);
	}

	recvLength = MAX_APDU_SIZE;
	rv = SCardTransmit(ykey->yk_cardhdl, &ykey->yk_sendpci, cmd,
	    cmdLen, NULL, recvBuffer, &recvLength);

	if (debug == B_TRUE) {
		fprintf(stderr, "< ");
		dump_hex(stderr, recvBuffer, recvLength);
	}

	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardTransmit(%s) failed: %s\n",
		    ykey->yk_rdrname, pcsc_stringify_error(rv));
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
yubikey_select(struct yubikey *ykey)
{
	int rv;
	struct apdu *apdu;

	assert(ykey->yk_intxn == B_TRUE);

	apdu = make_apdu(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);
	apdu->a_data = (uint8_t *)AID_YUBIOTP;
	apdu->a_datalen = sizeof (AID_YUBIOTP);

	rv = transceive_apdu(ykey, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    ykey->yk_rdrname, rv);
		free_apdu(apdu);
		return (1);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
	} else {
		if (debug == B_TRUE) {
			fprintf(stderr, "card in %s returned sw = %04x to "
			    "INS_SELECT\n", ykey->yk_rdrname, apdu->a_sw);
		}
		rv = 1;
	}

	free_apdu(apdu);

	return (rv);
}

static int
yubikey_read_serial(struct yubikey *ykey)
{
	int rv;
	struct apdu *apdu;

	apdu = make_apdu(CLA_ISO, INS_API_REQ, CMD_GET_SERIAL, 0);
	rv = transceive_apdu(ykey, apdu);

	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    ykey->yk_rdrname, rv);
		free_apdu(apdu);
		return (1);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		if (apdu->a_replylen != 4) {
			if (debug) {
				fprintf(stderr, "yubikey in %s returned short "
				    "serial number: %d bytes (expect 4)\n",
				    ykey->yk_rdrname, apdu->a_replylen);
			}
			free_apdu(apdu);
			return (1);
		}
		const uint8_t *reply = apdu->a_reply;
		ykey->yk_serial = reply[3] | (reply[2] << 8) |
		    (reply[1] << 16) | (reply[0] << 24);
		free_apdu(apdu);
		return (0);

	} else {
		if (debug) {
			fprintf(stderr, "yubikey in %s returned sw = %04x to "
			    "CMD_GET_SERIAL\n", ykey->yk_rdrname, apdu->a_sw);
		}
		free_apdu(apdu);
		return (1);
	}
}

static int
yubikey_read_status(struct yubikey *ykey)
{
	int rv;
	struct apdu *apdu;

	apdu = make_apdu(CLA_ISO, INS_STATUS, 0, 0);
	rv = transceive_apdu(ykey, apdu);

	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    ykey->yk_rdrname, rv);
		free_apdu(apdu);
		return (1);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		if (apdu->a_replylen != 6) {
			if (debug) {
				fprintf(stderr, "yubikey in %s returned short "
				    "status structure: %d bytes (expect 6)\n",
				    ykey->yk_rdrname, apdu->a_replylen);
			}
			free_apdu(apdu);
			return (1);
		}
		const uint8_t *reply = apdu->a_reply;
		ykey->yk_version[0] = reply[0];
		ykey->yk_version[1] = reply[1];
		ykey->yk_version[2] = reply[2];

		ykey->yk_pgmseq = reply[3];

		ykey->yk_touchlvl = reply[4] | (reply[5] << 8);

		free_apdu(apdu);
		return (0);
	} else {
		if (debug) {
			fprintf(stderr, "yubikey in %s returned sw = %04x "
			    "to INS_STATUS\n", ykey->yk_rdrname, apdu->a_sw);
		}
		free_apdu(apdu);
		return (1);
	}
}

static void
yubikey_begin_txn(struct yubikey *ykey)
{
	assert(ykey->yk_intxn == B_FALSE);
	LONG rv;
	rv = SCardBeginTransaction(ykey->yk_cardhdl);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardBeginTransaction(%s) failed: %s\n",
		    ykey->yk_rdrname, pcsc_stringify_error(rv));
		exit(1);
	}
	ykey->yk_intxn = B_TRUE;
}

static void
yubikey_end_txn(struct yubikey *ykey)
{
	assert(ykey->yk_intxn == B_TRUE);
	LONG rv;
	rv = SCardEndTransaction(ykey->yk_cardhdl, SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEndTransaction(%s) failed: %s\n",
		    ykey->yk_rdrname, pcsc_stringify_error(rv));
		exit(1);
	}
	ykey->yk_intxn = B_FALSE;
}

static void
find_all_yubikeys(SCARDCONTEXT ctx)
{
	DWORD rv, readersLen;
	LPTSTR readers, thisrdr;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders failed: %s\n",
		    pcsc_stringify_error(rv));
		exit(1);
	}
	readers = calloc(readersLen, 1);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardListReaders failed: %s\n",
		    pcsc_stringify_error(rv));
		exit(1);
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		struct yubikey *ykey;
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

		ykey = calloc(sizeof (struct yubikey), 1);
		ykey->yk_cardhdl = card;
		ykey->yk_rdrname = thisrdr;
		ykey->yk_proto = activeProtocol;

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			ykey->yk_sendpci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			ykey->yk_sendpci = *SCARD_PCI_T1;
			break;
		default:
			assert(0);
		}

		yubikey_begin_txn(ykey);
		rv = yubikey_select(ykey);
		if (rv == 0)
			rv = yubikey_read_status(ykey);
		if (rv == 0)
			rv = yubikey_read_serial(ykey);
		yubikey_end_txn(ykey);

		if (rv == 0) {
			ykey->yk_next = yks;
			yks = ykey;
		} else {
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}
}

static uint8_t *
parse_hex(const char *str, uint *outlen)
{
	const int len = strlen(str);
	uint8_t *data = calloc(len / 2 + 1, 1);
	int i, idx = 0, shift = 4;
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
	uint8_t *buf = calloc(limit * 3, 1);
	size_t n;

	n = fread(buf, 1, limit * 3 - 1, stdin);
	if (!feof(stdin)) {
		fprintf(stderr, "error: input too long (max %d bytes)\n",
		    limit);
		exit(1);
	}

	if (hex_in == B_TRUE) {
		uint len;
		uint8_t *pbuf = parse_hex(buf, &len);
		free(buf);
		n = len;
		buf = pbuf;
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
	struct yubikey *yk;
	for (yk = yks; yk != NULL; yk = yk->yk_next) {
		if (parseable == B_TRUE) {
			printf("%d.%d.%d:%u:%s:",
			    yk->yk_version[0], yk->yk_version[1],
			    yk->yk_version[2], yk->yk_serial, yk->yk_rdrname);
			if (yk->yk_touchlvl & CONFIG1_VALID)
				printf("true:");
			else
				printf("false:");
			if (yk->yk_touchlvl & CONFIG2_VALID)
				printf("true\n");
			else
				printf("false\n");
		} else {
			printf("Yubikey v%d.%d.%d (%u) in '%s'",
			    yk->yk_version[0], yk->yk_version[1],
			    yk->yk_version[2], yk->yk_serial, yk->yk_rdrname);
			if (yk->yk_touchlvl & CONFIG1_VALID)
				printf(" +slot1");
			if (yk->yk_touchlvl & CONFIG2_VALID)
				printf(" +slot2");
			printf("\n");
		}
	}
}

static void
cmd_hmac(SCARDCONTEXT ctx, int slot)
{
	uint len;
	uint8_t *inp;
	struct apdu *apdu;
	enum yk_cmd cmd;
	int rv;

	switch (slot) {
	case 1:
		cmd = CMD_HMAC_1;
		break;
	case 2:
		cmd = CMD_HMAC_2;
		break;
	default:
		assert(0);
	}

	inp = read_stdin(64, &len);

	apdu = make_apdu(CLA_ISO, INS_API_REQ, cmd, 0);
	apdu->a_data = inp;
	apdu->a_datalen = len;

	yubikey_begin_txn(selyk);
	rv = yubikey_select(selyk);
	if (rv != 0) {
		fprintf(stderr, "yubikey_select(%s) failed: %d\n",
		    selyk->yk_rdrname, rv);
		free_apdu(apdu);
		exit(1);
	}
	rv = transceive_apdu(selyk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    selyk->yk_rdrname, rv);
		free_apdu(apdu);
		exit(1);
	}
	yubikey_end_txn(selyk);

	if (apdu->a_sw == SW_NO_ERROR && apdu->a_replylen > 0) {
		if (hex_out == B_TRUE) {
			dump_hex(stdout, apdu->a_reply, apdu->a_replylen);
		} else {
			fwrite(apdu->a_reply, 1, apdu->a_replylen, stdout);
		}
	} else if (apdu->a_sw == SW_NO_ERROR) {
		fprintf(stderr, "error: Yubikey slot is not configured for "
		    "HMAC\n");
		exit(2);
	} else {
		fprintf(stderr, "error: Yubikey returned error: %04x\n",
		    apdu->a_sw);
		exit(1);
	}
}

static void
cmd_otp(SCARDCONTEXT ctx, int slot)
{
	struct apdu *apdu;
	enum yk_cmd cmd;
	int rv;

	apdu = make_apdu(CLA_ISO, INS_OTP, slot - 1, 0);

	yubikey_begin_txn(selyk);
	rv = yubikey_select(selyk);
	if (rv != 0) {
		fprintf(stderr, "yubikey_select(%s) failed: %d\n",
		    selyk->yk_rdrname, rv);
		free_apdu(apdu);
		exit(1);
	}
	rv = transceive_apdu(selyk, apdu);
	if (rv != 0) {
		fprintf(stderr, "transceive_apdu(%s) failed: %d\n",
		    selyk->yk_rdrname, rv);
		free_apdu(apdu);
		exit(1);
	}
	yubikey_end_txn(selyk);

	if (apdu->a_sw == SW_NO_ERROR && apdu->a_replylen > 0) {
		fwrite(apdu->a_reply, 1, apdu->a_replylen, stdout);
		fprintf(stdout, "\n");
	} else if (apdu->a_sw == SW_NO_ERROR) {
		fprintf(stderr, "error: Yubikey slot is not configured for "
		    "OTP generation\n");
		exit(2);
	} else if (apdu->a_sw == SW_CONDITIONS_NOT_SATISFIED) {
		fprintf(stderr, "error: Yubikey does not allow OTP to be "
		    "extracted in this mode (e.g. connected over USB)\n");
		exit(1);
	} else {
		fprintf(stderr, "error: Yubikey returned error: %04x\n",
		    apdu->a_sw);
		exit(1);
	}
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: yktool [options] <operation>\n"
	    "Available operations:\n"
	    "  list               Lists Yubikeys present\n"
	    "  hmac <slot #>      Computes an HMAC over data on stdin\n"
	    "  otp <slot #>       Gets a one-time password\n"
	    "\n"
	    "Options:\n"
	    "  --hex-out|-x       Outputs on stdout are in hex\n"
	    "  --hex-in|-X        Inputs on stdin are in hex\n"
	    "  --serial|-s <#>    Select a specific Yubikey by serial #\n"
	    "  --debug|-d         Spit out lots of debug info to stderr\n"
	    "                     (incl. APDU trace)\n"
	    "  --parseable|-p     Generate parseable output from 'list'\n");
	exit(3);
}

const char *optstring = "x(hex-out)X(hex-in)s:(serial)c:(acc-code)"
    "C:(set-acc-code)d(debug)p(parseable)";

int
main(int argc, char *argv[])
{
	LONG rv;
	SCARDCONTEXT ctx;
	extern char *optarg;
	extern int optind, optopt, opterr;
	int c;
	uint len;
	int64_t serial = -1;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			debug = B_TRUE;
			break;
		case 'x':
			hex_out = B_TRUE;
			break;
		case 'X':
			hex_in = B_TRUE;
			break;
		case 's':
			serial = strtoll(optarg, NULL, 10);
			break;
		case 'c':
			acc_code = parse_hex(optarg, &len);
			if (len != 6) {
				fprintf(stderr, "error: acc code must be "
				    "6 bytes in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'p':
			parseable = B_TRUE;
			break;
		case 'C':
			new_acc_code = parse_hex(optarg, &len);
			if (len != 6) {
				fprintf(stderr, "error: new acc code must be "
				    "6 bytes in length (you gave %d)\n", len);
				exit(3);
			}
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

	find_all_yubikeys(ctx);

	if (serial == -1) {
		selyk = yks;
		if (selyk == NULL) {
			fprintf(stderr, "error: no Yubikeys found on the "
			    "system\n");
			exit(2);
		}
	} else {
		struct yubikey *yk;
		for (yk = yks; yk != NULL; yk = yk->yk_next) {
			if (yk->yk_serial == serial) {
				selyk = yk;
				break;
			}
		}
		if (selyk == NULL) {
			fprintf(stderr, "error: failed to find Yubikey with "
			    "given serial number (%llu)\n", serial);
			exit(2);
		}
	}

	if (strcmp(op, "list") == 0) {
		if (optind < argc)
			usage();
		cmd_list(ctx);

	} else if (strcmp(op, "hmac") == 0) {
		int slot;
		if (optind >= argc)
			usage();
		slot = strtol(argv[optind++], NULL, 10);
		if (optind < argc)
			usage();
		if (slot != 1 && slot != 2) {
			fprintf(stderr, "error: invalid slot # (%d)\n", slot);
			exit(3);
		}
		cmd_hmac(ctx, slot);

	} else if (strcmp(op, "otp") == 0) {
		int slot;
		if (optind >= argc)
			usage();
		slot = strtol(argv[optind++], NULL, 10);
		if (optind < argc)
			usage();
		if (slot != 1 && slot != 2) {
			fprintf(stderr, "error: invalid slot # (%d)\n", slot);
			exit(3);
		}
		cmd_otp(ctx, slot);

	} else {
		usage();
	}

	return (0);
}

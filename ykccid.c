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

#include "ykccid.h"

const uint8_t AID_YUBIOTP[] = {
	0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

const uint8_t PGM_SEQ_INVALID = 0x00;

const uint16_t CONFIG1_VALID = 0x01;
const uint16_t CONFIG1_TOUCH = 0x04;
const uint16_t CONFIG2_VALID = 0x02;
const uint16_t CONFIG2_TOUCH = 0x08;

const uint32_t MAX_APDU_SIZE = 16384;

static uint16_t
yubikey_crc16(const uint8_t *buf, int buf_size)
{
	uint16_t m_crc = 0xffff;

	while (buf_size--) {
		int i, j;
		m_crc ^= (uint8_t) * buf++ & 0xFF;
		for (i = 0; i < 8; i++) {
			j = m_crc & 1;
			m_crc >>= 1;
			if (j)
				m_crc ^= 0x8408;
		}
	}

	return (m_crc);
}

static void
set_config_crc(struct slot_config *c)
{
	uint16_t crc;

	crc = yubikey_crc16((const uint8_t *)c,
	    offsetof(struct slot_config, sc_crc));
	c->sc_crc[0] = (crc & 0xff00) >> 8;
	c->sc_crc[1] = crc & 0xff;
}

struct slot_config *
ykc_config_make_hmac(const uint8_t *hmacKey, int len)
{
	struct slot_config *c = calloc(1, sizeof (struct slot_config));
	int j;
	assert(len == 20);
	assert(c != NULL);

	j = 0;
	bcopy(hmacKey, c->sc_key, sizeof (c->sc_key));
	j += sizeof (c->sc_key);
	len -= sizeof (c->sc_key);
	assert(len <= sizeof (c->sc_uid));
	bcopy(hmacKey + j, c->sc_uid, len);

	c->sc_cfg_flags = CFGFLAG_CHAL_HMAC | CFGFLAG_HMAC_LT64;
	c->sc_tkt_flags = TKTFLAG_CHAL_RESP;
	c->sc_ext_flags = EXTFLAG_SERIAL_API_VISIBLE |
	    EXTFLAG_SERIAL_USB_VISIBLE | EXTFLAG_ALLOW_UPDATE;

	return (c);
}

static uint8_t *
apdu_to_buffer(struct apdu *apdu, uint *outlen)
{
	uint8_t *buf = calloc(1, 5 + apdu->a_datalen);
	assert(buf != NULL);
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

struct apdu *
ykc_apdu_make(enum iso_class cls, enum iso_ins ins, uint8_t p1, uint8_t p2)
{
	struct apdu *a = calloc(1, sizeof (struct apdu));
	assert(a != NULL);
	a->a_cls = cls;
	a->a_ins = ins;
	a->a_p1 = p1;
	a->a_p2 = p2;
	return (a);
}

void
ykc_apdu_free(struct apdu *a)
{
	if (a->a_reply != NULL)
		free(a->a_reply);
	free(a);
}

void
ykc_txn_begin(struct yubikey *ykey)
{
	assert(ykey->yk_intxn == B_FALSE);
	LONG rv;
	rv = SCardBeginTransaction(ykey->yk_cardhdl);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardBeginTransaction(%s) failed: %s\n",
		    ykey->yk_rdrname, pcsc_stringify_error(rv));
		abort();
	}
	ykey->yk_intxn = B_TRUE;
}

void
ykc_txn_end(struct yubikey *ykey)
{
	LONG rv;
	(void) SCardEndTransaction(ykey->yk_cardhdl, SCARD_LEAVE_CARD);
	ykey->yk_intxn = B_FALSE;
}

int
ykc_apdu_transceive(struct yubikey *ykey, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;
	DWORD recvLength;
	assert(ykey->yk_intxn == B_TRUE);
	uint8_t *recvBuffer = calloc(1, MAX_APDU_SIZE);
	assert(recvBuffer != NULL);
	uint8_t *cmd = apdu_to_buffer(apdu, &cmdLen);
	if (cmd == NULL || cmdLen < 5)
		return (ENOMEM);

	recvLength = MAX_APDU_SIZE;
	rv = SCardTransmit(ykey->yk_cardhdl, &ykey->yk_sendpci, cmd,
	    cmdLen, NULL, recvBuffer, &recvLength);

	if (rv != SCARD_S_SUCCESS) {
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

int
ykc_select(struct yubikey *ykey)
{
	int rv;
	struct apdu *apdu;

	assert(ykey->yk_intxn == B_TRUE);

	apdu = ykc_apdu_make(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);
	apdu->a_data = (uint8_t *)AID_YUBIOTP;
	apdu->a_datalen = sizeof (AID_YUBIOTP);

	rv = ykc_apdu_transceive(ykey, apdu);
	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
	} else {
		rv = EINVAL;
	}

	ykc_apdu_free(apdu);

	return (rv);
}

int
ykc_read_serial(struct yubikey *ykey)
{
	int rv;
	struct apdu *apdu;

	apdu = ykc_apdu_make(CLA_ISO, INS_API_REQ, CMD_GET_SERIAL, 0);
	rv = ykc_apdu_transceive(ykey, apdu);

	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		if (apdu->a_replylen != 4) {
			ykc_apdu_free(apdu);
			return (EIO);
		}
		const uint8_t *reply = apdu->a_reply;
		ykey->yk_serial = reply[3] | (reply[2] << 8) |
		    (reply[1] << 16) | (reply[0] << 24);
		ykc_apdu_free(apdu);
		return (0);

	} else {
		ykc_apdu_free(apdu);
		return (EIO);
	}
}

int
ykc_read_status(struct yubikey *ykey)
{
	int rv;
	struct apdu *apdu;

	apdu = ykc_apdu_make(CLA_ISO, INS_STATUS, 0, 0);
	rv = ykc_apdu_transceive(ykey, apdu);

	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		if (apdu->a_replylen != 6) {
			ykc_apdu_free(apdu);
			return (EIO);
		}
		const uint8_t *reply = apdu->a_reply;
		ykey->yk_version[0] = reply[0];
		ykey->yk_version[1] = reply[1];
		ykey->yk_version[2] = reply[2];

		ykey->yk_pgmseq = reply[3];

		ykey->yk_touchlvl = reply[4] | (reply[5] << 8);

		ykc_apdu_free(apdu);
		return (0);
	} else {
		ykc_apdu_free(apdu);
		return (EIO);
	}
}

void
ykc_release(struct yubikey *yk)
{
	struct yubikey *next;
	while (yk != NULL) {
		assert(yk->yk_intxn == B_FALSE);
		(void) SCardDisconnect(yk->yk_cardhdl, SCARD_LEAVE_CARD);
		next = yk->yk_next;
		free(yk);
		yk = next;
	}
}

struct yubikey *
ykc_find(SCARDCONTEXT ctx)
{
	DWORD rv, readersLen;
	LPTSTR readers, thisrdr;
	struct yubikey *list = NULL;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		return (NULL);
	}
	readers = calloc(1, readersLen);
	assert(readers != NULL);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		return (NULL);
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		struct yubikey *ykey;
		DWORD activeProtocol;

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			continue;
		}

		ykey = calloc(1, sizeof (struct yubikey));
		assert(ykey != NULL);
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

		ykc_txn_begin(ykey);
		rv = ykc_select(ykey);
		if (rv == 0)
			rv = ykc_read_status(ykey);
		if (rv == 0)
			rv = ykc_read_serial(ykey);
		ykc_txn_end(ykey);

		if (rv == 0) {
			ykey->yk_next = list;
			list = ykey;
		} else {
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}

	return (list);
}

int
ykc_hmac(struct yubikey *yk, int slot, const char *input, size_t inputLen,
    char *output, size_t *outputLen)
{
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
		return (EINVAL);
	}

	apdu = ykc_apdu_make(CLA_ISO, INS_API_REQ, cmd, 0);
	apdu->a_data = (char *)input;
	apdu->a_datalen = inputLen;

	rv = ykc_select(yk);
	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}
	rv = ykc_apdu_transceive(yk, apdu);
	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}

	if (apdu->a_sw == SW_NO_ERROR && apdu->a_replylen > 0) {
		size_t len = *outputLen;
		if (apdu->a_replylen < len)
			len = apdu->a_replylen;
		bcopy(apdu->a_reply, output, len);
		*outputLen = len;
		rv = 0;
	} else if (apdu->a_sw == SW_NO_ERROR) {
		rv = ENOENT;
	} else {
		rv = EIO;
	}

	ykc_apdu_free(apdu);
	return (rv);
}

int
ykc_program(struct yubikey *yk, int slot, struct slot_config *config)
{
	struct apdu *apdu;
	enum yk_cmd cmd;
	int rv;

	switch (slot) {
	case 1:
		cmd = CMD_SET_CONF_1;
		break;
	case 2:
		cmd = CMD_SET_CONF_2;
		break;
	default:
		return (EINVAL);
	}

	set_config_crc(config);

	apdu = ykc_apdu_make(CLA_ISO, INS_API_REQ, cmd, 0);
	apdu->a_data = (uint8_t *)config;
	apdu->a_datalen = sizeof (struct slot_config);

	rv = ykc_select(yk);
	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}
	rv = ykc_apdu_transceive(yk, apdu);
	if (rv != 0) {
		ykc_apdu_free(apdu);
		return (rv);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		const uint8_t *reply = apdu->a_reply;
		uint16_t mask = 0;

		assert(yk->yk_version[0] == reply[0]);
		assert(yk->yk_version[1] == reply[1]);
		assert(yk->yk_version[2] == reply[2]);

		yk->yk_touchlvl = reply[4] | (reply[5] << 8);

		if (slot == 1)
			mask = (yk->yk_touchlvl & CONFIG1_VALID);
		else if (slot == 2)
			mask = (yk->yk_touchlvl & CONFIG2_VALID);

		const uint8_t pgmSeq = reply[3];

		if (pgmSeq <= yk->yk_pgmseq || mask == 0) {
			rv = EINVAL;
		} else {
			rv = 0;
		}
		yk->yk_pgmseq = pgmSeq;
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EACCES;
	} else {
		rv = EIO;
	}

	ykc_apdu_free(apdu);
	return (rv);
}

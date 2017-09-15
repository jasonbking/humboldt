/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_YKCCID_H)
#define _YKCCID_H

#include <stdint.h>

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

extern const uint8_t PGM_SEQ_INVALID;

extern const uint16_t CONFIG1_VALID;
extern const uint16_t CONFIG1_TOUCH;
extern const uint16_t CONFIG2_VALID;
extern const uint16_t CONFIG2_TOUCH;

extern const uint32_t MAX_APDU_SIZE;

extern const uint8_t AID_YUBIOTP[];

enum iso_sw {
	SW_NO_ERROR = 0x9000,
	SW_CONDITIONS_NOT_SATISFIED = 0x6985,
	SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982
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

enum tkt_flag {
	TKTFLAG_OATH_HOTP = 0x40,
	TKTFLAG_CHAL_RESP = 0x40
};

enum cfg_flag {
	CFGFLAG_CHAL_HMAC = 0x22,
	CFGFLAG_HMAC_LT64 = 0x04,
	CFGFLAG_CHAL_BTN_TRIG = 0x08
};

enum ext_flag {
	EXTFLAG_SERIAL_USB_VISIBLE = 0x02,
	EXTFLAG_SERIAL_API_VISIBLE = 0x04,
	EXTFLAG_ALLOW_UPDATE = 0x20
};

struct slot_config {
	uint8_t sc_fixed[16];
	uint8_t sc_uid[6];
	uint8_t sc_key[16];
	uint8_t sc_nacc_code[6];
	uint8_t sc_fixed_size;
	uint8_t sc_ext_flags;
	uint8_t sc_tkt_flags;
	uint8_t sc_cfg_flags;
	uint8_t sc_pad[2];
	uint8_t sc_crc[2];
	uint8_t sc_acc_code[6];
};

/*
 * Find all yubikeys on the system, return the first one (you can then follow
 * yk_next to find the rest).
 */
struct yubikey *ykc_find(SCARDCONTEXT ctx);
/* Release handles and free the given set of yubikeys. */
void ykc_release(struct yubikey *yk);

/* Make slot configurations for use with ykc_program() */
struct slot_config *ykc_config_make_hmac(const uint8_t *hmacKey, int len);

/* Low-level APDU access */
struct apdu *ykc_apdu_make(enum iso_class cls, enum iso_ins ins, uint8_t p1,
    uint8_t p2);
void ykc_apdu_free(struct apdu *pdu);
int ykc_apdu_transceive(struct yubikey *yk, struct apdu *pdu);

/* Transactions */
void ykc_txn_begin(struct yubikey *yk);
void ykc_txn_end(struct yubikey *yk);

/* All of these assume that a txn is open (ykc_txn_begin was called) */
int ykc_select(struct yubikey *yk);
int ykc_read_serial(struct yubikey *yk);
int ykc_read_status(struct yubikey *yk);
int ykc_hmac(struct yubikey *yk, int slot, const char *input, size_t inputLen,
    char *output, size_t *outputLen);
int ykc_program(struct yubikey *yk, int slot, struct slot_config *config);

#endif

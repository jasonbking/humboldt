/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_SOFTTOKEN_H)
#define _SOFTTOKEN_H

#include <zone.h>
#include <libnvpair.h>
#include "sshkey.h"

#define	TOKEN_CHROOT_DIR	"/var/run/softtokend"
#define	TOKEN_SOCKET_DIR	"/var/zonecontrol/%s"
#define	TOKEN_SOCKET_PATH	TOKEN_SOCKET_DIR "/token.sock"
#define	TOKEN_KEYS_DIR		"/zones/%s/keys"

enum slot_type {
	SLOT_ASYM_AUTH = 0x01,
	SLOT_ASYM_CERT_SIGN = 0x02,
	SLOT_SYM_HSM = 0x03,

	SLOT_MAX
};

enum slot_algo {
	ALGO_ED_25519 = 0x01,
	ALGO_RSA_2048 = 0x02,
	ALGO_CHACHA20 = 0x03,

	ALGO_MAX
};

enum ctl_cmd_type {
	CMD_STATUS = 0xa0,
	CMD_UNLOCK_KEY,
	CMD_LOCK_KEY,
	CMD_SHUTDOWN
};

enum ctl_cmd_status {
	STATUS_OK = 0xc0,
	STATUS_ERROR = 0xc1,
};

struct ctl_cmd {
	uint8_t cc_cookie;
	uint8_t cc_type;
	uint8_t cc_p1;
};

struct token_slot {
	uint8_t ts_id;
	enum slot_type ts_type;
	enum slot_algo ts_algo;
	const char *ts_name;
	struct token_slot *ts_next;
	struct token_slot_data *ts_data;
	size_t ts_datasize;
	struct sshkey *ts_public;
	nvlist_t *ts_nvl;
	struct agent_slot *ts_agent;
};

struct token_slot_data {
	volatile uint32_t tsd_len;
	volatile char tsd_data[1];
};

extern size_t slot_n;
extern struct token_slot *token_slots;

void supervisor_main(zoneid_t zid, int ctlfd);
void agent_main(zoneid_t zid, int listensock, int ctlfd);

void read_cmd(int fd, struct ctl_cmd *cmd);
void write_cmd(int fd, const struct ctl_cmd *cmd);

#endif

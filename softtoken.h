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

struct ctl_cmd {
	uint8_t cc_cookie;
	uint8_t cc_type;
	uint8_t cc_p1;
};

struct token_slot {
	enum slot_type ts_type;
	enum slot_algo ts_algo;
	const char *ts_name;
	struct token_slot *ts_next;
	struct token_slot_data *ts_data;
	size_t ts_datasize;
	nvlist_t *ts_nvl;
};

struct token_slot_data {
	uint32_t tsd_len;
	char tsd_data[1];
};

extern struct token_slot *token_slots;

void supervisor_main(zoneid_t zid, int ctlfd);
void agent_main(zoneid_t zid, int listensock, int ctlfd);

#endif

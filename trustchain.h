/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_TRUSTCHAIN_H)
#define _TRUSTCHAIN_H

#include <stdint.h>
#include <assert.h>

#include <sys/types.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

enum tc_block_type {
	TCBLK_ROOT = 0x01,
	TCBLK_ADD_NODE = 0x02,
	TCBLK_RM_NODE = 0x03,
	TCBLK_SET_BACKUP = 0x04,
	TCBLK_ADD_CHAIN = 0x05,
	TCBLK_RM_CHAIN = 0x06
};

enum tc_block_version {
	TCBLK_V1 = 0x01
};

struct tc_chain {
	/* Filled out by tc_from_binary() */
	struct tc_block *tc_root;

	/* Filled out by tc_verify() */
	boolean_t tc_verified;
	struct sshkey *tc_rootkey;

	/*
	 * Caches of latest sets of nodes, peer chains and backup settings, for
	 * easy access after verify() completes.
	 */
	struct tc_node *tc_nodes;
	struct tc_set_backup_block *tc_backups;
	struct tc_peer_chain *tc_chains;
};

struct tc_backup_key {
	struct tc_backup_key *tbk_next;
	uint8_t tbk_index;
	const char *tbk_name;
	struct sshkey *tbk_pubkey;
};

struct tc_node {
	struct tc_node *tcn_next;
	uint8_t tcn_guid[16];
	struct sshkey *tcn_pubkey;
	X509 *tcn_x509;
};

struct tc_peer_chain {
	struct tc_peer *tpc_next;
	struct sshkey *tpc_rootkey;
	const char *tpc_dcname;
};

/* Actual deserialised chain structures. */
struct tc_block {
	struct tc_block *tb_next;
	enum tc_block_version tb_version;
	enum tc_block_type tb_type;
	uint64_t tb_time;
	uint8_t tb_prevhash[32];
	union {
		struct tc_root_block ti_root;
		struct tc_add_node_block ti_add_node;
		struct tc_rm_node_block ti_rm_node;
		struct tc_set_backup_block ti_set_backup;
		struct tc_add_chain_block ti_add_chain;
		struct tc_rm_chain_block ti_rm_chain;
	} tb_inner;
	struct tc_block_sig *tb_sigs;
};

struct tc_block_sig {
	struct tc_block_sig *tbs_next;
	uint8_t tbs_guid[16];
	size_t tbs_len;
	uint8_t *tbs_sig;
};

struct tc_root_block {
	struct sshkey *trb_pubkey;
	uint64_t trb_serial;
	const char *trb_dcname;
	const char *trb_contact;
	struct tc_node *trb_nodes;
};

struct tc_add_node_block {
	uint8_t tan_guid[16];
	struct sshkey *tan_pubkey;
	X509 *tan_x509;
};

struct tc_rm_node_block {
	uint8_t trn_guid[16];
	struct sshkey *trn_pubkey;
};

struct tc_set_backup_block {
	uint8_t tsb_n;
	uint8_t tsb_k;
	struct tc_backup_key *tsb_keys;
};

struct tc_add_chain_block {
	struct sshkey *tac_rootkey;
	const char *tac_dcname;
};

struct tc_rm_chain_block {
	struct sshkey *trc_rootkey;
	const char *trc_dcname;
};

int tc_from_binary(const uint8_t *input, size_t len, struct tc_chain **chain);
int tc_to_binary(struct tc_chain *chain, uint8_t **output, size_t *len);
int tc_block_to_binary(struct tc_block *block, uint8_t **output, size_t *len);
void tc_free(struct tc_chain *chain);
int tc_verify(struct tc_chain *chain, struct sshkey *rootkey);

#endif

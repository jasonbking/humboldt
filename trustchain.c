/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <sys/debug.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"
#include "libssh/cipher.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "trustchain.h"

int
tc_from_binary(const uint8_t *input, size_t len, struct tc_chain **chain)
{
}

static int
tc_block_to_buf(struct tc_block *blk, struct sshbuf *buf)
{
	struct sshbuf *kbuf;
	struct tc_node *node;
	size_t cdlen;
	uint8_t *cdata;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	VERIFY3S(blk->tb_version, ==, TCBLK_V1);
	VERIFY0(sshbuf_put_u8(buf, blk->tb_version));

	VERIFY0(sshbuf_put_string(buf, blk->tb_prevhash,
	    sizeof (blk->tb_prevhash)));

	VERIFY0(sshbuf_put_u8(buf, blk->tb_type));

	switch (blk->tb_type) {
	case TCBLK_ROOT:
		struct tc_root_block *root = &(blk->tb_inner.ti_root);

		VERIFY0(sshkey_putb(root->trb_pubkey, kbuf));
		VERIFY0(sshbuf_put_stringb(buf, kbuf));
		VERIFY0(sshbuf_put_u64(buf, root->trb_serial));
		VERIFY0(sshbuf_put_cstring(buf, root->trb_dcname));
		VERIFY0(sshbuf_put_cstring(buf, root->trb_contact));

		node = root->trb_nodes;
		for (; node != NULL; node = node->tcn_next) {
			VERIFY0(sshbuf_put_string(buf, node->tcn_guid,
			    sizeof (node->tcn_guid)));

			sshbuf_reset(kbuf);
			VERIFY0(sshkey_putb(node->tcn_pubkey, kbuf));
			VERIFY0(sshbuf_put_stringb(buf, kbuf));

			cdlen = i2d_X509(node->tcn_x509, &cdata);
			VERIFY(cdata != NULL);
			VERIFY3U(cdlen, >, 0);
			VERIFY0(sshbuf_put_string(buf, cdata, cdlen));

			OPENSSL_free(cdata);
		}
		break;
	case TCBLK_ADD_NODE:
		struct tc_add_node_block *addn =
		    &(blk->tb_inner.ti_add_node);

		VERIFY0(sshbuf_put_string(buf, addn->tan_guid,
		    sizeof (addn->tan_guid)));

		VERIFY0(sshkey_putb(addn->tan_pubkey, kbuf));
		VERIFY0(sshbuf_put_stringb(buf, kbuf));

		cdlen = i2d_X509(addn->tan_x509, &cdata);
		VERIFY(cdata != NULL);
		VERIFY3U(cdlen, >, 0);
		VERIFY0(sshbuf_put_string(buf, cdata, cdlen));

		OPENSSL_free(cdata);
		break;
	case TCBLK_RM_NODE:
		struct tc_rm_node_block *rmn =
		    &(blk->tb_inner.ti_rm_node);

		VERIFY0(sshbuf_put_string(buf, rmn->trn_guid,
		    sizeof (rmn->trn_guid)));

		VERIFY0(sshkey_putb(rmn->trn_pubkey, kbuf));
		VERIFY0(sshbuf_put_stringb(buf, kbuf));
		break;
	case TCBLK_SET_BACKUP:
		struct tc_set_backup_block *sbb =
		    &(blk->tb_inner.ti_set_backup);
		struct tc_backup_key *bk;

		VERIFY0(sshkey_put_u8(buf, sbb->tsb_n));
		VERIFY0(sshkey_put_u8(buf, sbb->tsb_k));

		bk = sbb->tsb_keys;
		for (; bk != NULL; bk = bk->tbk_next) {
			VERIFY0(sshkey_put_u8(buf, bk->tbk_index));
			VERIFY0(sshkey_put_cstring(buf, bk->tbk_name));

			sshbuf_reset(kbuf);
			VERIFY0(sshkey_putb(bk->tbk_pubkey, kbuf));
			VERIFY0(sshbuf_put_stringb(buf, kbuf));
		}
		break;
	case TCBLK_ADD_CHAIN:
		struct tc_add_chain_block *addc =
		    &(blk->tb_inner.ti_add_chain);
		break;
	case TCBLK_RM_CHAIN:
		struct tc_rm_chain_block *rmc =
		    &(blk->tb_inner.ti_rm_chain);
		break;
	}

	sshbuf_free(kbuf);
}

int
tc_to_binary(struct tc_chain *chain, uint8_t **output, size_t *len)
{
	struct sshbuf *buf, *bbuf, *sbuf;
	struct tc_block *blk;
	struct tc_block_sig *sig;
	int rc;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	bbuf = sshbuf_new();
	VERIFY(buf != NULL);

	for (blk = chain->tc_root; blk != NULL; blk = blk->tb_next) {
		sshbuf_reset(bbuf);

		if ((rc = tc_block_to_buf(blk, bbuf)) != 0)
			goto out;
		VERIFY0(sshbuf_put_stringb(buf, bbuf));

		sshbuf_reset(bbuf);

		for (sig = blk->tb_sigs; sig != NULL; sig = sig->tbs_next) {
			VERIFY0(sshbuf_put_string(bbuf, sig->tbs_guid,
			    sizeof (sig->tbs_guid)));
			VERIFY0(sshbuf_put_string(bbuf, sig->tbs_sig,
			    sig->tbs_len));
		}
		VERIFY0(sshbuf_put_stringb(buf, bbuf));
	}

	*len = sshbuf_len(buf);
	*output = calloc(1, *len);
	VERIFY(*output != NULL);
	bcopy(sshbuf_ptr(buf), *output, *len);
	rc = 0;

out:
	sshbuf_free(buf);
	sshbuf_free(bbuf);

	return (rc);
}

int
tc_block_to_binary(struct tc_block *blk, uint8_t **output, size_t *len)
{
	struct sshbuf *buf;
	int rc;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	if ((rc = tc_block_to_buf(blk, buf)) != 0) {
		sshbuf_free(buf);
		return (rc);
	}

	*len = sshbuf_len(buf);
	*output = calloc(1, *len);
	VERIFY(*output != NULL);
	bcopy(sshbuf_ptr(buf), *output, *len);
	return (0);
}

void
tc_free(struct tc_chain *chain)
{
}

int
tc_verify(struct tc_chain *chain, struct sshkey *rootkey)
{
}

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
#include "sshbuf.h"
#include "digest.h"
#include "cipher.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tlv.h"
#include "piv.h"
#include "bunyan.h"

const uint8_t AID_PIV[] = {
	0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

static int
piv_read_chuid(struct piv_token *pk)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;

	assert(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, PIV_TAG_CHUID);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_read_chuid.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GET_DATA(CHUID) response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			piv_apdu_free(apdu);
			return (ENOTSUP);
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
				assert(tlv_read(tlv, pk->pt_guid, 0,
				    sizeof (pk->pt_guid)) ==
				    sizeof (pk->pt_guid));
				tlv_end(tlv);
				break;
			default:
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (ENOTSUP);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		rv = ENOENT;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_DATA for "
		    "PIV CHUID file",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

struct piv_token *
piv_enumerate(SCARDCONTEXT ctx)
{
	DWORD rv, readersLen;
	LPTSTR readers, thisrdr;
	struct piv_token *ks = NULL;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardListReaders failed",
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		return (NULL);
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardListReaders failed",
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		return (NULL);
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		struct piv_token *key;
		DWORD activeProtocol;

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			bunyan_log(DEBUG, "SCardConnect failed",
			    "reader", BNY_STRING, thisrdr,
			    "err", BNY_STRING, pcsc_stringify_error(rv),
			    NULL);
			continue;
		}

		key = calloc(1, sizeof (struct piv_token));
		key->pt_cardhdl = card;
		key->pt_rdrname = thisrdr;
		key->pt_proto = activeProtocol;

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			key->pt_sendpci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			key->pt_sendpci = *SCARD_PCI_T1;
			break;
		default:
			assert(0);
		}

		piv_txn_begin(key);
		rv = piv_select(key);
		if (rv == 0)
			rv = piv_read_chuid(key);
		piv_txn_end(key);

		if (rv == 0) {
			key->pt_next = ks;
			ks = key;
		} else {
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}

	return (ks);
}

void
piv_release(struct piv_token *pk)
{
	struct piv_token *next;
	struct piv_slot *ps, *psnext;

	while (pk != NULL) {
		assert(pk->pt_intxn == B_FALSE);
		(void) SCardDisconnect(pk->pt_cardhdl, SCARD_LEAVE_CARD);

		ps = pk->pt_slots;
		while (ps != NULL) {
			OPENSSL_free(ps->ps_subj);
			X509_free(ps->ps_x509);
			sshkey_free(ps->ps_pubkey);
			psnext = ps->ps_next;
			free(ps);
			ps = psnext;
		}

		next = pk->pt_next;
		free(pk);
		pk = next;
	}
}

struct piv_slot *
piv_get_slot(struct piv_token *tk, enum piv_slotid slotid)
{
	struct piv_slot *s;
	for (s = tk->pt_slots; s != NULL; s = s->ps_next) {
		if (s->ps_slot == slotid)
			break;
	}
	return (s);
}

struct apdu *
piv_apdu_make(enum iso_class cls, enum iso_ins ins, uint8_t p1, uint8_t p2)
{
	struct apdu *a = calloc(1, sizeof (struct apdu));
	a->a_cls = cls;
	a->a_ins = ins;
	a->a_p1 = p1;
	a->a_p2 = p2;
	return (a);
}

void
piv_apdu_free(struct apdu *a)
{
	if (a->a_reply.b_data != NULL) {
		explicit_bzero(a->a_reply.b_data, MAX_APDU_SIZE);
		free(a->a_reply.b_data);
	}
	free(a);
}

static uint8_t *
apdu_to_buffer(struct apdu *apdu, uint *outlen)
{
	struct apdubuf *d = &(apdu->a_cmd);
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
		/* TODO: maybe look at handling ext APDUs? */
		assert(d->b_len < 256 && d->b_len > 0);
		buf[4] = d->b_len;
		bcopy(d->b_data + d->b_offset, buf + 5, d->b_len);
		*outlen = d->b_len + 5;
		return (buf);
	}
}

int
piv_apdu_transceive(struct piv_token *key, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;

	boolean_t freedata = B_FALSE;
	DWORD recvLength;
	uint8_t *cmd;
	struct apdubuf *r = &(apdu->a_reply);

	assert(key->pt_intxn == B_TRUE);

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

	bunyan_log(TRACE, "sending APDU",
	    "apdu", BNY_BIN_HEX, cmd, cmdLen,
	    NULL);

	rv = SCardTransmit(key->pt_cardhdl, &key->pt_sendpci, cmd,
	    cmdLen, NULL, r->b_data + r->b_offset, &recvLength);
	explicit_bzero(cmd, cmdLen);
	free(cmd);

	bunyan_log(TRACE, "received APDU",
	    "apdu", BNY_BIN_HEX, r->b_data + r->b_offset, (size_t)recvLength,
	    NULL);

	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(DEBUG, "SCardTransmit failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		if (freedata) {
			free(r->b_data);
			bzero(r, sizeof (struct apdubuf));
		}
		return (rv);
	}
	recvLength -= 2;

	r->b_len = recvLength;
	apdu->a_sw = (r->b_data[r->b_offset + recvLength] << 8) |
	    r->b_data[r->b_offset + recvLength + 1];

	return (0);
}

int
piv_apdu_transceive_chain(struct piv_token *pk, struct apdu *apdu)
{
	int rv;
	size_t offset;
	size_t rem;

	assert(pk->pt_intxn == B_TRUE);

	/* First, send the command. */
	rem = apdu->a_cmd.b_len;
	while (rem > 0) {
		/* Is there another block needed in the chain? */
		if (rem > 0xFF) {
			apdu->a_cls |= CLA_CHAIN;
			apdu->a_cmd.b_len = 0xFF;
		} else {
			apdu->a_cls &= ~CLA_CHAIN;
			apdu->a_cmd.b_len = rem;
		}
		rv = piv_apdu_transceive(pk, apdu);
		if (rv != 0)
			return (rv);
		if ((apdu->a_sw & 0xFF00) == SW_NO_ERROR ||
		    (apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00 ||
		    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
		    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
			apdu->a_cmd.b_offset += apdu->a_cmd.b_len;
			rem -= apdu->a_cmd.b_len;
		} else {
			/*
			 * Return any other error straight away -- we can
			 * only get response chaining on BYTES_REMAINING
			 */
			return (0);
		}
	}

	/*
	 * We keep the original reply offset so we can calculate how much
	 * data we actually received later.
	 */
	offset = apdu->a_reply.b_offset;

	while ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00) {
		apdu->a_cls = CLA_ISO;
		apdu->a_ins = INS_CONTINUE;
		apdu->a_p1 = 0;
		apdu->a_p2 = 0;
		apdu->a_cmd.b_data = NULL;
		apdu->a_reply.b_offset += apdu->a_reply.b_len;
		assert(apdu->a_reply.b_offset < apdu->a_reply.b_size);

		rv = piv_apdu_transceive(pk, apdu);
		if (rv != 0)
			return (rv);
	}

	/* Work out the total length of all the segments we recieved. */
	apdu->a_reply.b_len += apdu->a_reply.b_offset - offset;
	apdu->a_reply.b_offset = offset;

	return (0);
}

int
piv_txn_begin(struct piv_token *key)
{
	assert(key->pt_intxn == B_FALSE);
	LONG rv;
	rv = SCardBeginTransaction(key->pt_cardhdl);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardBeginTransaction failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		return (EIO);
	}
	key->pt_intxn = B_TRUE;
	return (0);
}

void
piv_txn_end(struct piv_token *key)
{
	assert(key->pt_intxn == B_TRUE);
	LONG rv;
	rv = SCardEndTransaction(key->pt_cardhdl,
	    key->pt_reset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardEndTransaction failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
	}
	key->pt_intxn = B_FALSE;
	key->pt_reset = B_FALSE;
}

int
piv_select(struct piv_token *tk)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;

	assert(tk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);
	apdu->a_cmd.b_data = (uint8_t *)AID_PIV;
	apdu->a_cmd.b_len = sizeof (AID_PIV);

	rv = piv_apdu_transceive(tk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_select.transceive_apdu failed",
		    "reader", BNY_STRING, tk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		piv_apdu_free(apdu);
		return (EIO);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != PIV_TAG_APT) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_SELECT response payload",
			    "reader", BNY_STRING, tk->pt_rdrname,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			switch (tag) {
			case PIV_TAG_AID:
			case PIV_TAG_AUTHORITY:
			case PIV_TAG_APP_LABEL:
			case PIV_TAG_URI:
				/* TODO: validate/store these maybe? */
				tlv_skip(tlv);
				break;
			case PIV_TAG_ALGS:
				if (tk->pt_alg_count > 0) {
					tlv_skip(tlv);
					break;
				}
				while (!tlv_at_end(tlv)) {
					tag = tlv_read_tag(tlv);
					if (tag == 0x80) {
						idx = tk->pt_alg_count++;
						tk->pt_algs[idx] =
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
				bunyan_log(DEBUG, "card returned unknown tag "
				    "in PIV INS_SELECT response payload",
				    "reader", BNY_STRING, tk->pt_rdrname,
				    "tag", BNY_UINT, tag,
				    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
				    apdu->a_reply.b_offset, apdu->a_reply.b_len,
				    NULL);
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (ENOTSUP);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;
	} else {
		bunyan_log(DEBUG, "card did not accept INS_SELECT for PIV",
		    "reader", BNY_STRING, tk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = ENOENT;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_auth_admin(struct piv_token *pt, const uint8_t *key, size_t keylen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *chal = NULL, *resp = NULL, *iv = NULL;
	size_t challen, ivlen, resplen;
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;

	assert(pt->pt_intxn == B_TRUE);

	cipher = cipher_by_name("3des-cbc");
	assert(cipher != NULL);

	assert(cipher_keylen(cipher) == keylen);
	assert(cipher_authlen(cipher) == 0);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_CHALLENGE);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, PIV_ALG_3DES,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive(pt, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_auth_admin.transceive_chain failed",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw != SW_NO_ERROR) {
		bunyan_log(DEBUG, "card did not return challenge to "
		    "INS_GEN_AUTH",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		piv_apdu_free(apdu);
		return (EINVAL);
	}

	tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
	    apdu->a_reply.b_len);
	tag = tlv_read_tag(tlv);
	if (tag != 0x7C) {
		bunyan_log(DEBUG, "card returned invalid tag in PIV "
		    "INS_GEN_AUTH response payload",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "slotid", BNY_UINT, (uint)0x9B,
		    "tag", BNY_UINT, tag,
		    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
		    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
		tlv_skip(tlv);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (ENOTSUP);
	}

	while (!tlv_at_end(tlv)) {
		tag = tlv_read_tag(tlv);
		if (tag == GA_TAG_CHALLENGE) {
			challen = tlv_rem(tlv);
			chal = calloc(1, challen);
			challen = tlv_read(tlv, chal, 0, challen);
			tlv_end(tlv);
			continue;
		}
		tlv_skip(tlv);
	}
	tlv_end(tlv);

	assert(chal != NULL);
	tlv_free(tlv);
	piv_apdu_free(apdu);

	resplen = challen;
	resp = calloc(1, resplen);
	assert(resp != NULL);

	assert(cipher_blocksize(cipher) == challen);

	ivlen = cipher_ivlen(cipher);
	iv = calloc(1, ivlen);
	assert(iv != NULL);
	explicit_bzero(iv, ivlen);

	rv = cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1);
	assert(rv == 0);
	rv = cipher_crypt(cctx, 0, resp, chal, challen, 0, 0);
	assert(rv == 0);
	cipher_free(cctx);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_write(tlv, resp, 0, resplen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	pt->pt_reset = B_TRUE;

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, PIV_ALG_3DES,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	free(chal);
	explicit_bzero(resp, resplen);
	free(resp);

	rv = piv_apdu_transceive(pt, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_auth_admin.transceive_chain failed",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
	} else if (apdu->a_sw == SW_INCORRECT_P1P2) {
		rv = ENOENT;
	} else if (apdu->a_sw == SW_WRONG_DATA) {
		rv = EACCES;
	} else {
		rv = EINVAL;
	}

	piv_apdu_free(apdu);
	return (rv);
}

int
piv_read_cert(struct piv_token *pk, enum piv_slotid slotid)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;
	uint8_t *ptr;
	size_t len;
	X509 *cert;
	struct piv_slot *pc;
	EVP_PKEY *pkey;
	uint8_t certinfo = 0;

	assert(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	switch (slotid) {
	case PIV_SLOT_9A:
		tlv_write_uint(tlv, PIV_TAG_CERT_9A);
		break;
	case PIV_SLOT_9C:
		tlv_write_uint(tlv, PIV_TAG_CERT_9C);
		break;
	case PIV_SLOT_9D:
		tlv_write_uint(tlv, PIV_TAG_CERT_9D);
		break;
	case PIV_SLOT_9E:
		tlv_write_uint(tlv, PIV_TAG_CERT_9E);
		break;
	default:
		assert(0);
	}
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_read_cert.transceive_chain failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GET_DATA response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
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

		/* See the NIST PIV spec. This bit should always be zero. */
		if ((certinfo & PIV_CI_X509) != 0) {
			bunyan_log(DEBUG, "card returned cert with PIV_CI_X509 "
			    "flag set, assuming invalid",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}

		/* TODO: gzip support */
		if ((certinfo & PIV_CI_COMPTYPE) != PIV_COMP_NONE) {
			bunyan_log(WARN, "card returned compressed cert",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}

		cert = d2i_X509(NULL, &ptr, len);
		if (cert == NULL) {
			/* Getting error codes out of OpenSSL is weird. */
			char errbuf[128];
			unsigned long err = ERR_peek_last_error();
			ERR_load_crypto_strings();
			ERR_error_string(err, errbuf);
			bunyan_log(WARN, "card returned invalid cert",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid,
			    "openssl_err", BNY_STRING, errbuf,
			    "data", BNY_BIN_HEX, ptr, len, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (EINVAL);
		}

		tlv_free(tlv);

		for (pc = pk->pt_slots; pc != NULL; pc = pc->ps_next) {
			if (pc->ps_slot == slotid)
				break;
		}
		if (pc == NULL) {
			pc = calloc(1, sizeof (struct piv_slot));
			assert(pc != NULL);
			pc->ps_next = pk->pt_slots;
			pk->pt_slots = pc;
		} else {
			OPENSSL_free(pc->ps_subj);
			X509_free(pc->ps_x509);
			sshkey_free(pc->ps_pubkey);
		}
		pc->ps_slot = slotid;
		pc->ps_x509 = cert;
		pc->ps_subj = X509_NAME_oneline(
		    X509_get_subject_name(cert), NULL, 0);
		pkey = X509_get_pubkey(cert);
		assert(pkey != NULL);
		assert(sshkey_from_evp_pkey(pkey, KEY_UNSPEC,
		    &pc->ps_pubkey) == 0);

		switch (pc->ps_pubkey->type) {
		case KEY_ECDSA:
			switch (sshkey_size(pc->ps_pubkey)) {
			case 256:
				pc->ps_alg = PIV_ALG_ECCP256;
				break;
			case 384:
				pc->ps_alg = PIV_ALG_ECCP384;
				break;
			default:
				assert(0);
			}
			break;
		case KEY_RSA:
			switch (sshkey_size(pc->ps_pubkey)) {
			case 1024:
				pc->ps_alg = PIV_ALG_RSA1024;
				break;
			case 2048:
				pc->ps_alg = PIV_ALG_RSA2048;
				break;
			default:
				assert(0);
			}
			break;
		default:
			assert(0);
		}

		rv = 0;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		rv = ENOENT;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_DATA for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_read_all_certs(struct piv_token *tk)
{
	int rv;

	assert(tk->pt_intxn == B_TRUE);

	rv = piv_read_cert(tk, PIV_SLOT_9E);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP)
		return (rv);
	rv = piv_read_cert(tk, PIV_SLOT_9A);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP)
		return (rv);
	rv = piv_read_cert(tk, PIV_SLOT_9C);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP)
		return (rv);
	rv = piv_read_cert(tk, PIV_SLOT_9D);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP)
		return (rv);

	return (rv);
}

int
piv_verify_pin(struct piv_token *pk, const char *pin, uint *retries)
{
	int rv;
	struct apdu *apdu;
	char pinbuf[8];
	size_t i;

	assert(pk->pt_intxn == B_TRUE);

	memset(pinbuf, 0xFF, sizeof (pinbuf));
	for (i = 0; i < 8, pin[i] != 0; ++i)
		pinbuf[i] = pin[i];
	assert(pin[i] == 0);

	apdu = piv_apdu_make(CLA_ISO, INS_VERIFY, 0x00, 0x80);
	apdu->a_cmd.b_data = pinbuf;
	apdu->a_cmd.b_len = 8;

	rv = piv_apdu_transceive(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_verify_pin.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		piv_apdu_free(apdu);
		return (EIO);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
		pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		*retries = (apdu->a_sw & 0x000F);
		rv = EACCES;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_VERIFY for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_sign(struct piv_token *tk, struct piv_slot *slot, const uint8_t *data,
    size_t datalen, enum sshdigest_types *hashalgo, uint8_t **signature,
    size_t *siglen)
{
	int rv, i;
	struct ssh_digest_ctx *hctx;
	uint8_t *buf;
	size_t nread, dglen, inplen;
	boolean_t cardhash = B_FALSE;
	enum piv_alg oldalg;

	assert(tk->pt_intxn == B_TRUE);

	switch (slot->ps_alg) {
	case PIV_ALG_RSA1024:
		inplen = 128;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		break;
	case PIV_ALG_RSA2048:
		inplen = 256;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		break;
	case PIV_ALG_ECCP256:
		inplen = 32;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		for (i = 0; i < tk->pt_alg_count; ++i) {
			if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA1 &&
			    *hashalgo == SSH_DIGEST_SHA1) {
				cardhash = B_TRUE;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA1;
			} else if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA256 &&
			    *hashalgo == SSH_DIGEST_SHA256) {
				cardhash = B_TRUE;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA256;
			}
		}
		break;
	case PIV_ALG_ECCP384:
		*hashalgo = SSH_DIGEST_SHA384;
		inplen = (dglen = 48);
		break;
	default:
		assert(0);
	}

	if (!cardhash) {
		buf = calloc(1, dglen);
		assert(buf != NULL);

		hctx = ssh_digest_start(*hashalgo);
		assert(hctx != NULL);
		assert(ssh_digest_update(hctx, data, datalen) == 0);
		assert(ssh_digest_final(hctx, buf, dglen) == 0);
		ssh_digest_free(hctx);
	} else {
		bunyan_log(TRACE, "doing hash on card", NULL);
		buf = data;
		inplen = datalen;
	}

	/*
	 * If it's an RSA signature, we have to generate the PKCS#1 style
	 * padded signing blob around the hash.
	 *
	 * ECDSA is so much nicer than this. Why can't we just use it? Oh,
	 * because Java ruined everything. Right.
	 */
	if (slot->ps_alg == PIV_ALG_RSA1024 ||
	    slot->ps_alg == PIV_ALG_RSA2048) {
		int nid;
		/*
		 * Roll up your sleeves, folks, we're going in (to the dank
		 * and musty corners of OpenSSL where few dare tread)
		 */
		X509_SIG digestInfo;
		X509_ALGOR algor;
		ASN1_TYPE parameter;
		ASN1_OCTET_STRING digest;
		uint8_t *tmp, *out;

		tmp = calloc(1, inplen);
		assert(tmp != NULL);
		out = NULL;

		/*
		 * XXX: I thought this should be sha256WithRSAEncryption?
		 *      but that doesn't work lol
		 */
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

		/*
		 * There is another undocumented openssl function that does
		 * this padding bit, but eh.
		 */
		memset(buf, 0xFF, inplen);
		buf[0] = 0x00;
		/* The second byte is the block type -- 0x01 here means 0xFF */
		buf[1] = 0x01;
		buf[inplen - nread - 1] = 0x00;
		bcopy(out, buf + (inplen - nread), nread);

		free(tmp);
		OPENSSL_free(out);
	}

	rv = piv_sign_prehash(tk, slot, buf, inplen, signature, siglen);

	if (!cardhash)
		free(buf);

	if (cardhash)
		slot->ps_alg = oldalg;

	return (rv);
}

int
piv_sign_prehash(struct piv_token *pk, struct piv_slot *pc,
    const uint8_t *hash, size_t hashlen, uint8_t **signature, size_t *siglen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *buf;

	assert(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x7C, hashlen + 16);
	/* Push an empty RESPONSE tag to say that's what we're asking for. */
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	/* And now push the data we're providing (the CHALLENGE). */
	tlv_pushl(tlv, GA_TAG_CHALLENGE, hashlen);
	tlv_write(tlv, hash, 0, hashlen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, pc->ps_alg, pc->ps_slot);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_sign_prehash.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GEN_AUTH response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)pc->ps_slot,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
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

	} else if (apdu->a_sw = SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_AUTH for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_ecdh(struct piv_token *pk, struct piv_slot *slot, struct sshkey *pubkey,
    uint8_t **secret, size_t *seclen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	struct piv_slot *pc;
	uint8_t *buf;
	struct sshbuf *sbuf;
	size_t len;

	assert(pk->pt_intxn == B_TRUE);

	sbuf = sshbuf_new();
	assert(sbuf != NULL);
	assert(pubkey->type == KEY_ECDSA);
	rv = sshbuf_put_eckey(sbuf, pubkey->ecdsa);
	assert(rv == 0);
	/* The buffer has the 32-bit length prefixed */
	len = sshbuf_len(sbuf) - 4;
	buf = sshbuf_ptr(sbuf) + 4;
	assert(*buf == 0x04);

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x7C, len + 16);
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	tlv_pushl(tlv, GA_TAG_EXP, len);
	tlv_write(tlv, buf, 0, len);
	sshbuf_free(sbuf);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, slot->ps_alg,
	    slot->ps_slot);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_ecdh.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GEN_AUTH response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)pc->ps_slot,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}

		*seclen = tlv_rem(tlv);
		buf = calloc(1, *seclen);
		assert(buf != NULL);
		*seclen = tlv_read(tlv, buf, 0, *seclen);
		*secret = buf;

		tlv_end(tlv);
		tlv_end(tlv);
		tlv_free(tlv);

		rv = 0;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_AUTH for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

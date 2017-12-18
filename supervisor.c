/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <synch.h>
#include <thread.h>
#include <string.h>
#include <strings.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/fork.h>
#include <sys/wait.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <dirent.h>
#include <port.h>
#include <dlfcn.h>
#include <link.h>

#include <wintypes.h>
#include <winscard.h>

#include <librename.h>
#include <libnvpair.h>

#include <openssl/err.h>

#include "softtoken.h"
#include "bunyan.h"
#include "piv.h"
#include "json.h"

#include "libssh/sshkey.h"
#include "libssh/cipher.h"
#include "libssh/sshbuf.h"
#include "libssh/ssherr.h"
#include "libssh/ssh2.h"
#include "libssh/authfd.h"
#include "ed25519/crypto_api.h"

/*
 * The "supervisor" process is a child of the soft-token manager. There is one
 * supervisor process per soft-token instance (so, per zone generally). The
 * supervisor is a privileged process that retains access to the HW token for
 * the duration of its operation. Its responsibility is to mediate access to
 * to the key material for its child, the agent, which processes the actual
 * connections from clients.
 *
 * The supervisor maps a set of shared pages that are inherited by the agent
 * child, of sufficient size to hold the key material. Upon a request from the
 * agent, the supervisor "unlocks" the key by decrypting it and writing the
 * plain-text key material out into the shared memory pages.
 *
 * This request for unlock comes to the supervisor via a pipe that it creates
 * before forking the agent child.
 */

struct token_slot *token_slots = NULL;
size_t slot_n = 0;

static pid_t agent_pid;
static uint8_t id_seed;

extern mutex_t *bunyan_wrmutex;

static SCARDCONTEXT sup_ctx;
static struct piv_token *sup_tks, *sup_systk;

#define	MAX_ZINF_LEN	(32*1024)

static void
encrypt_and_write_key(struct sshkey *skey, struct piv_token *tk,
    const char *dir, struct token_slot *info)
{
	int rv, i;
	uint8_t *boxd, *key, *iv, *encdata;
	char *packdata;
	u_char *pubblob;
	size_t boxdlen, keylen, ivlen, authlen, blocksz, enclen;
	size_t packlen, publen;
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;
	nvlist_t *nv;
	const char *ciphername = "chacha20-poly1305";
	struct sshbuf *buf;
	librename_atomic_t *rast;
	FILE *f;
	struct sshkey *pubkey;
	struct piv_slot *slot;
	struct piv_ecdh_box *box;

	VERIFY0(sshkey_demote(skey, &pubkey));
	VERIFY0(sshkey_to_blob(pubkey, &pubblob, &publen));
	sshkey_free(pubkey);

	buf = sshbuf_new();
	VERIFY3P(buf, !=, NULL);

	/* Get some cipher metadata so we know what sizes things should be */
	cipher = cipher_by_name(ciphername);
	VERIFY3P(cipher, !=, NULL);

	/* Generate the random key to encrypt the actual data */
	keylen = cipher_keylen(cipher);
	key = calloc(1, keylen);
	VERIFY3P(key, !=, NULL);
	arc4random_buf(key, keylen);

	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);

	/* Generate an IV for the cipher to use later */
	ivlen = cipher_ivlen(cipher);
	iv = calloc(1, ivlen);
	VERIFY3P(iv, !=, NULL);
	arc4random_buf(iv, ivlen);

	slot = piv_get_slot(tk, PIV_SLOT_KEY_MGMT);
	if (slot == NULL) {
		VERIFY0(piv_txn_begin(tk));
		VERIFY0(piv_select(tk));
		rv = piv_read_cert(tk, PIV_SLOT_KEY_MGMT);
		piv_txn_end(tk);
		VERIFY3U(rv, ==, 0);
		slot = piv_get_slot(tk, PIV_SLOT_KEY_MGMT);
	}
	VERIFY3P(slot, !=, NULL);

	bunyan_log(TRACE, "boxing key for PIV slot",
	    "keyname", BNY_STRING, info->ts_name,
	    "algo", BNY_UINT, (uint)info->ts_algo,
	    "guid", BNY_BIN_HEX, tk->pt_guid, sizeof (tk->pt_guid),
	    "slotid", BNY_UINT, (uint)slot->ps_slot, NULL);

	box = piv_box_new();
	VERIFY3P(box, !=, NULL);
	VERIFY0(piv_box_set_data(box, key, keylen));
	VERIFY0(piv_box_seal(tk, slot, box));
	VERIFY0(piv_box_to_binary(box, &boxd, &boxdlen));
	piv_box_free(box);

	rv = sshkey_private_serialize(skey, buf);
	VERIFY0(rv);
	/* Add PKCS#5 style padding to the end of the serialized private key */
	i = 0;
	while (sshbuf_len(buf) % blocksz) {
		rv = sshbuf_put_u8(buf, ++i & 0xff);
		VERIFY0(rv);
	}

	rv = cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1);
	VERIFY0(rv);
	enclen = sshbuf_len(buf) + authlen;
	encdata = calloc(1, enclen);
	rv = cipher_crypt(cctx, 0, encdata, sshbuf_ptr(buf), sshbuf_len(buf),
	    0, authlen);
	VERIFY0(rv);
	sshbuf_reset(buf);
	cipher_free(cctx);

	/*
	 * Now we've got the encdata blob, time to build the nvlist up that
	 * we'll pack and write out on disk.
	 */
	VERIFY0(nvlist_alloc(&nv, NV_UNIQUE_NAME, 0));

	VERIFY0(nvlist_add_uint8(nv, "version", 1));
	VERIFY0(nvlist_add_uint8(nv, "algo", info->ts_algo));
	VERIFY0(nvlist_add_uint8(nv, "type", info->ts_type));

	VERIFY0(nvlist_add_byte_array(nv, "local-box", boxd, boxdlen));

	VERIFY0(nvlist_add_string(nv, "encalgo", ciphername));
	VERIFY0(nvlist_add_byte_array(nv, "encdata", encdata, enclen));
	VERIFY0(nvlist_add_byte_array(nv, "iv", iv, ivlen));

	VERIFY0(nvlist_add_byte_array(nv, "pubkey", pubblob, publen));

	packdata = NULL;
	packlen = 0;
	VERIFY0(nvlist_pack(nv, &packdata, &packlen, NV_ENCODE_XDR, 0));
	VERIFY3P(packdata, !=, NULL);
	VERIFY3U(packlen, >, 0);

	/*
	 * Use atomic rename to write out the key file, so we never end up with
	 * a "half-written" key.
	 */
	rv = librename_atomic_init(dir, info->ts_name, NULL, 0600, 0, &rast);
	VERIFY0(rv);
	f = fdopen(librename_atomic_fd(rast), "w");
	VERIFY3S(fwrite(packdata, packlen, 1, f), ==, 1);
	VERIFY0(fflush(f));
	rv = librename_atomic_commit(rast);
	VERIFY0(rv);
	librename_atomic_fini(rast);

	/* Make sure to explicit_bzero any buffers that held sensitive data. */
	explicit_bzero(key, keylen);
	free(key);
	explicit_bzero(iv, ivlen);
	free(iv);
	explicit_bzero(encdata, enclen);
	free(encdata);
	free(pubblob);
	explicit_bzero(boxd, boxdlen);
	free(boxd);
	sshbuf_free(buf);
}

struct certsign_ctx {
	int csc_authfd;
	struct sshkey *csc_pubkey;
	struct piv_token *csc_tk;
	struct piv_slot *csc_slot;
};

static int
piv_ssh_cert_signer(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg, u_int compat,
    void *vctx)
{
	struct certsign_ctx *ctx;
	enum sshdigest_types hashalg;
	size_t siglen;
	uint8_t *sig = NULL;
	struct sshbuf *buf;
	int rv;

	VERIFY(vctx != NULL);
	ctx = (struct certsign_ctx *)vctx;
	VERIFY(ctx->csc_tk != NULL);
	VERIFY(ctx->csc_slot != NULL);

	hashalg = SSH_DIGEST_SHA256;

	rv = piv_sign(ctx->csc_tk, ctx->csc_slot, data, datalen, &hashalg, 
	    &sig, &siglen);
	if (rv != 0) {
		bunyan_log(ERROR, "piv_sign failed",
		    "rv", BNY_INT, rv, NULL);
		return (SSH_ERR_SYSTEM_ERROR);
	}
	if (hashalg != SSH_DIGEST_SHA256) {
		explicit_bzero(sig, siglen);
		free(sig);
		return (SSH_ERR_KEY_TYPE_MISMATCH);
	}

	buf = sshbuf_new();
	VERIFY(buf != NULL);
	VERIFY0(sshkey_sig_from_asn1(ctx->csc_slot->ps_pubkey->type,
	    SSH_DIGEST_SHA256, sig, siglen, buf));
	explicit_bzero(sig, siglen);
	free(sig);

	*sigp = calloc(1, sshbuf_len(buf));
	*lenp = sshbuf_len(buf);
	VERIFY0(sshbuf_get(buf, *sigp, *lenp));
	sshbuf_free(buf);

	return (0);
}

static int
new_cert_global_x509(struct token_slot *slot)
{
	struct piv_token *tk;
	struct piv_slot *sl;
	EVP_PKEY *pkey;
	RSA *rsacp;
	int nid;
	enum sshdigest_types hashalg, wantalg;
	BIGNUM *serial;
	ASN1_INTEGER *serial_asn1;
	X509 *cert;
	X509_NAME *subj, *issu;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	ASN1_TYPE *null_parameter;
	uint8_t *tbs, *sig, *cdata;
	size_t tbslen, siglen, cdlen;
	struct sshkey *pub;
	int rv;
	u_int i;
	const char *uuid, *hostname;

	VERIFY3U(slot->ts_type, ==, SLOT_ASYM_CERT_SIGN);
	VERIFY3U(slot->ts_algo, ==, ALGO_RSA_2048);
	VERIFY3U(slot->ts_public->type, ==, KEY_RSA);

	tk = sup_systk;

	VERIFY0(piv_txn_begin(tk));
	VERIFY0(piv_select(tk));
	sl = piv_get_slot(tk, PIV_SLOT_SIGNATURE);
	if (sl == NULL) {
		rv = piv_read_cert(tk, PIV_SLOT_SIGNATURE);
		sl = piv_get_slot(tk, PIV_SLOT_SIGNATURE);
	}
	VERIFY(sl != NULL);

	pub = sl->ps_pubkey;

	pkey = EVP_PKEY_new();
	VERIFY(pkey != NULL);

	rsacp = RSA_new();
	VERIFY(rsacp != NULL);
	rsacp->e = BN_dup(slot->ts_public->rsa->e);
	VERIFY(rsacp->e != NULL);
	rsacp->n = BN_dup(slot->ts_public->rsa->n);
	VERIFY(rsacp->n != NULL);
	/*
	 * NOTE: this takes ownership of the RSA. Freeing it and its BNs is
	 * no longer our problem
	 */
	rv = EVP_PKEY_assign_RSA(pkey, rsacp);
	VERIFY3S(rv, ==, 1);
	rsacp = NULL;

	if (pub->type == KEY_RSA) {
		nid = NID_sha256WithRSAEncryption;
		wantalg = SSH_DIGEST_SHA256;
	} else if (pub->type == KEY_ECDSA) {
		boolean_t haveSha256 = B_FALSE;
		boolean_t haveSha1 = B_FALSE;
		for (i = 0; i < tk->pt_alg_count; ++i) {
			if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA256) {
				haveSha256 = B_TRUE;
			} else if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA1) {
				haveSha1 = B_TRUE;
			}
		}
		if (haveSha1 && !haveSha256) {
			nid = NID_ecdsa_with_SHA1;
			wantalg = SSH_DIGEST_SHA1;
		} else {
			nid = NID_ecdsa_with_SHA256;
			wantalg = SSH_DIGEST_SHA256;
		}
	}

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	VERIFY(serial != NULL);
	VERIFY3S(BN_pseudo_rand(serial, 64, 0, 0), ==, 1);
	VERIFY(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);
	BN_free(serial);

	cert = X509_new();
	VERIFY(cert != NULL);
	VERIFY3S(X509_set_version(cert, 2), ==, 1);
	VERIFY3S(X509_set_serialNumber(cert, serial_asn1), ==, 1);
	ASN1_INTEGER_free(serial_asn1);
	VERIFY(X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL);
	VERIFY(X509_gmtime_adj(X509_get_notAfter(cert), 300) != NULL);

	uuid = getenv("SYSTEM_UUID");
	VERIFY(uuid != NULL);
	VERIFY3U(strlen(uuid), >, 0);

	hostname = getenv("SYSTEM_HOSTNAME");
	VERIFY(hostname != NULL);

	subj = X509_NAME_new();
	VERIFY(subj != NULL);
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "title", MBSTRING_ASC,
	    (unsigned char *)slot->ts_name, -1, -1, 0), ==, 1);
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
	    (unsigned char *)hostname, -1, -1, 0), ==, 1);
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "UID", MBSTRING_ASC,
	    (unsigned char *)uuid, -1, -1, 0), ==, 1);
	if (strlen(getenv("SYSTEM_DC")) > 0) {
		VERIFY3S(X509_NAME_add_entry_by_txt(subj, "DC", MBSTRING_ASC,
		    (unsigned char *)getenv("SYSTEM_DC"), -1, -1, 0), ==, 1);
	}
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "OU", MBSTRING_ASC,
	    (unsigned char *)"nodes", -1, -1, 0), ==, 1);
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
	    (unsigned char *)"triton", -1, -1, 0), ==, 1);
	VERIFY3S(X509_set_subject_name(cert, subj), ==, 1);
	X509_NAME_free(subj);

	issu = X509_get_subject_name(sl->ps_x509);
	VERIFY(issu != NULL);
	VERIFY3S(X509_set_issuer_name(cert, issu), ==, 1);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
	    "critical,CA:TRUE");
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage,
	    "critical,keyCertSign,cRLSign");
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	VERIFY3S(X509_set_pubkey(cert, pkey), ==, 1);
	EVP_PKEY_free(pkey);

	cert->sig_alg->algorithm = OBJ_dup(OBJ_nid2obj(nid));
	cert->cert_info->signature->algorithm = OBJ_dup(OBJ_nid2obj(nid));

	if (pub->type == KEY_RSA) {
		null_parameter = ASN1_TYPE_new();
		bzero(null_parameter, sizeof (*null_parameter));
		null_parameter->type = V_ASN1_NULL;
		null_parameter->value.ptr = NULL;
		cert->sig_alg->parameter = null_parameter;

		null_parameter = ASN1_TYPE_new();
		bzero(null_parameter, sizeof (*null_parameter));
		null_parameter->type = V_ASN1_NULL;
		null_parameter->value.ptr = NULL;
		cert->cert_info->signature->parameter = null_parameter;
	}

	cert->cert_info->enc.modified = 1;
	tbs = NULL;
	tbslen = i2d_X509_CINF(cert->cert_info, &tbs);
	VERIFY(tbs != NULL);
	VERIFY3U(tbslen, >, 0);

	VERIFY0(piv_system_token_auth(tk));
	hashalg = wantalg;
	VERIFY0(piv_sign(tk, sl, tbs, tbslen, &hashalg, &sig, &siglen));
	VERIFY3U(hashalg, ==, wantalg);

	piv_txn_end(tk);
	OPENSSL_free(tbs);

	M_ASN1_BIT_STRING_set(cert->signature, sig, siglen);
	cert->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;

	cdata = NULL;
	cdlen = i2d_X509(cert, &cdata);
	VERIFY(cdata != NULL);
	VERIFY3U(cdlen, >, 0);
	VERIFY3U(cdlen, <, MAX_CERT_LEN);

	X509_free(cert);
	explicit_bzero(sig, siglen);
	free(sig);

	slot->ts_certdata->tsd_len = 0;
	bcopy(cdata, (void *)slot->ts_certdata->tsd_data, cdlen);
	slot->ts_certdata->tsd_len = cdlen;

	OPENSSL_free(cdata);

	return (0);
}

static int
new_cert_global_ssh(struct token_slot *slot)
{
	struct sshkey *certk;
	struct sshkey_cert *cert;
	struct sshbuf *b;
	const char *uuid;
	time_t now;
	int rv;
	struct piv_token *tk;
	struct piv_slot *sl;
	struct certsign_ctx csc;
	uint8_t *blob;
	size_t bloblen;

	bzero(&csc, sizeof (csc));

	VERIFY3U(slot->ts_type, ==, SLOT_ASYM_AUTH);
	VERIFY3U(slot->ts_algo, ==, ALGO_ED_25519);
	VERIFY3U(slot->ts_public->type, ==, KEY_ED25519);

	VERIFY0(sshkey_demote(slot->ts_public, &certk));
	VERIFY(certk != NULL);
	VERIFY0(sshkey_to_certified(certk));

	cert = certk->cert;
	VERIFY(cert != NULL);

	cert->type = SSH2_CERT_TYPE_HOST;
	arc4random_buf(&cert->serial, sizeof (cert->serial));
	cert->key_id = strdup(slot->ts_name);
	VERIFY(cert->key_id != NULL);
	cert->nprincipals = 1;
	cert->principals = (char **)calloc(1, sizeof (char *));
	VERIFY(cert->principals != NULL);

	uuid = getenv("SYSTEM_UUID");
	VERIFY(uuid != NULL);
	VERIFY3U(strlen(uuid), >, 0);
	cert->principals[0] = strdup(uuid);

	now = time(NULL);
	cert->valid_after = now;
	cert->valid_before = now + 300;

	VERIFY(cert->extensions != NULL);

	b = sshbuf_new();
	VERIFY(b != NULL);

	VERIFY0(sshbuf_put_cstring(cert->extensions, "hostname"));
	VERIFY0(sshbuf_put_cstring(b, getenv("SYSTEM_HOSTNAME")));
	VERIFY0(sshbuf_put_stringb(cert->extensions, b));
	sshbuf_reset(b);

	VERIFY0(sshbuf_put_cstring(cert->extensions, "datacenter"));
	VERIFY0(sshbuf_put_cstring(b, getenv("SYSTEM_DC")));
	VERIFY0(sshbuf_put_stringb(cert->extensions, b));
	sshbuf_reset(b);

	sshbuf_free(b);

	tk = sup_systk;

	VERIFY0(piv_txn_begin(tk));
	VERIFY0(piv_select(tk));
	sl = piv_get_slot(tk, PIV_SLOT_SIGNATURE);
	if (sl == NULL) {
		rv = piv_read_cert(tk, PIV_SLOT_SIGNATURE);
		sl = piv_get_slot(tk, PIV_SLOT_SIGNATURE);
	}
	VERIFY(sl != NULL);

	csc.csc_tk = tk;
	csc.csc_slot = sl;
	VERIFY0(piv_system_token_auth(tk));
	VERIFY0(sshkey_certify_custom(certk, sl->ps_pubkey, NULL,
	    piv_ssh_cert_signer, &csc));

	piv_txn_end(tk);

	VERIFY0(sshkey_to_blob(certk, &blob, &bloblen));
	VERIFY3U(bloblen, >, 0);
	VERIFY3U(bloblen, <, MAX_CERT_LEN);
	slot->ts_certdata->tsd_len = 0;
	bcopy(blob, (void *)slot->ts_certdata->tsd_data, bloblen);
	slot->ts_certdata->tsd_len = bloblen;

	sshkey_free(certk);
	free(blob);

	return (0);
}

static int
new_cert_global(struct token_slot *slot)
{
	if (slot->ts_type == SLOT_ASYM_AUTH) {
		return (new_cert_global_ssh(slot));
	} else if (slot->ts_type == SLOT_ASYM_CERT_SIGN) {
		return (new_cert_global_x509(slot));
	}
	VERIFY(0);
	return (EIO);
}

static int
agent_ssh_cert_signer(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg, u_int compat,
    void *vctx)
{
	struct certsign_ctx *ctx;

	VERIFY(vctx != NULL);
	ctx = (struct certsign_ctx *)vctx;
	VERIFY(ctx->csc_authfd > 0);
	VERIFY(ctx->csc_pubkey != NULL);

	VERIFY(ctx->csc_pubkey == key);

	return (ssh_agent_sign(ctx->csc_authfd, key, sigp, lenp, data,
	    datalen, alg, compat));
}

static int
new_cert_zone_ssh(zoneid_t zid, nvlist_t *zinfo, struct certsign_ctx *csc,
    struct ssh_identitylist *idl, struct token_slot *slot)
{
	struct sshkey *certk;
	struct sshkey_cert *cert;
	struct sshbuf *b;
	char *uuid, *tmp;
	time_t now;
	int rv;
	size_t i;
	uint8_t *blob;
	size_t bloblen;
	struct sshkey *pcert = NULL;
	nvlist_t *ztags;

	VERIFY3U(slot->ts_type, ==, SLOT_ASYM_AUTH);
	VERIFY3U(slot->ts_algo, ==, ALGO_ED_25519);
	VERIFY3U(slot->ts_public->type, ==, KEY_ED25519);

	for (i = 0; i < idl->nkeys; ++i) {
		VERIFY(idl->keys[i] != NULL);
		if (idl->keys[i]->type == KEY_ED25519 &&
		    strcmp(idl->comments[i], "auth.key") == 0) {
			csc->csc_pubkey = idl->keys[i];
		} else if (idl->keys[i]->type == KEY_ED25519_CERT &&
		    strcmp(idl->comments[i], "auth.key-cert") == 0) {
			pcert = idl->keys[i];
		}
	}
	VERIFY(csc->csc_pubkey != NULL);

	VERIFY0(sshkey_demote(slot->ts_public, &certk));
	VERIFY(certk != NULL);
	VERIFY0(sshkey_to_certified(certk));

	cert = certk->cert;
	VERIFY(cert != NULL);

	cert->type = SSH2_CERT_TYPE_HOST;
	arc4random_buf(&cert->serial, sizeof (cert->serial));
	cert->key_id = strdup(slot->ts_name);
	VERIFY(cert->key_id != NULL);
	cert->nprincipals = 1;
	cert->principals = (char **)calloc(1, sizeof (char *));
	VERIFY(cert->principals != NULL);

	VERIFY0(nvlist_lookup_string(zinfo, "uuid", &uuid));
	cert->principals[0] = strdup(uuid);

	now = time(NULL);
	cert->valid_after = now;
	cert->valid_before = now + 300;

	VERIFY(cert->extensions != NULL);

	b = sshbuf_new();
	VERIFY(b != NULL);

	if (nvlist_lookup_string(zinfo, "alias", &tmp) == 0) {
		VERIFY0(sshbuf_put_cstring(cert->extensions, "alias"));
		VERIFY0(sshbuf_put_cstring(b, tmp));
		VERIFY0(sshbuf_put_stringb(cert->extensions, b));
		sshbuf_reset(b);
	}

	if (nvlist_lookup_string(zinfo, "owner_uuid", &tmp) == 0) {
		VERIFY0(sshbuf_put_cstring(cert->extensions, "owner"));
		VERIFY0(sshbuf_put_cstring(b, tmp));
		VERIFY0(sshbuf_put_stringb(cert->extensions, b));
		sshbuf_reset(b);
	}

	if (nvlist_lookup_string(zinfo, "datacenter_name", &tmp) == 0) {
		VERIFY0(sshbuf_put_cstring(cert->extensions, "datacenter"));
		VERIFY0(sshbuf_put_cstring(b, tmp));
		VERIFY0(sshbuf_put_stringb(cert->extensions, b));
		sshbuf_reset(b);
	}

	VERIFY0(nvlist_lookup_nvlist(zinfo, "tags", &ztags));
	tmp = NULL;
	rv = nvlist_lookup_string(ztags, "smartdc_role", &tmp);
	if (rv != 0)
		rv = nvlist_lookup_string(ztags, "manta_role", &tmp);
	if (rv != 0)
		rv = nvlist_lookup_string(ztags, "role", &tmp);

	if (rv == 0) {
		VERIFY(tmp != NULL);
		VERIFY0(sshbuf_put_cstring(cert->extensions, "role"));
		VERIFY0(sshbuf_put_cstring(b, tmp));
		VERIFY0(sshbuf_put_stringb(cert->extensions, b));
		sshbuf_reset(b);
	}

	sshbuf_free(b);

	VERIFY0(sshkey_certify_custom(certk, csc->csc_pubkey, NULL,
	    agent_ssh_cert_signer, csc));

	VERIFY0(sshkey_to_blob(certk, &blob, &bloblen));
	VERIFY3U(bloblen, >, 0);
	VERIFY3U(bloblen, <, MAX_CERT_LEN);
	slot->ts_certdata->tsd_len = 0;
	bcopy(blob, (void *)slot->ts_certdata->tsd_data, bloblen);
	slot->ts_certdata->tsd_len = bloblen;

	free(blob);
	sshkey_free(certk);

	if (pcert != NULL) {
		VERIFY0(sshkey_to_blob(pcert, &blob, &bloblen));
		VERIFY3U(bloblen, >, 0);
		VERIFY3U(bloblen, <, MAX_CERT_LEN);
		slot->ts_chaindata->tsd_len = 0;
		bcopy(blob, (void *)slot->ts_chaindata->tsd_data, bloblen);
		slot->ts_chaindata->tsd_len = bloblen;

		free(blob);
	}

	return (0);
}

static int
new_cert_zone_x509(zoneid_t zid, nvlist_t *zinfo, struct certsign_ctx *csc,
    struct ssh_identitylist *idl, struct token_slot *slot)
{
	EVP_PKEY *pkey;
	RSA *rsacp;
	int nid;
	BIGNUM *serial;
	ASN1_INTEGER *serial_asn1;
	X509 *cert, *pcert = NULL;
	X509_NAME *subj, *issu;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	ASN1_TYPE *null_parameter;
	uint8_t *tbs, *sig, *sigdata, *cdata, *ptr;
	size_t tbslen, siglen, sigdlen, cdlen;
	int rv;
	u_int i;
	struct sshkey *pubk;
	char *uuid, *tmp;
	struct ssh_x509chain *chain = NULL;
	struct sshbuf *sigbuf;

	VERIFY3U(slot->ts_type, ==, SLOT_ASYM_CERT_SIGN);
	VERIFY3U(slot->ts_algo, ==, ALGO_RSA_2048);
	VERIFY3U(slot->ts_public->type, ==, KEY_RSA);

	for (i = 0; i < idl->nkeys; ++i) {
		VERIFY(idl->keys[i] != NULL);
		if (idl->keys[i]->type == KEY_RSA &&
		    strcmp(idl->comments[i], "cert.key") == 0) {
			csc->csc_pubkey = (pubk = idl->keys[i]);
			break;
		}
	}
	VERIFY(pubk != NULL);

	VERIFY0(ssh_agent_get_x509(csc->csc_authfd, pubk, &chain));

	if (chain->ncerts == 0) {
		bunyan_log(WARN, "gz token does not contain any certs; cannot "
		    "renew zone cert (no issuer known)", NULL);
		return (ENOENT);
	}
	VERIFY3U(chain->ncerts, >=, 1);

	ptr = chain->certs[0];
	if (d2i_X509(&pcert, (const uint8_t **)&ptr,
	    chain->certlen[0]) == NULL) {
		char errbuf[128];
		unsigned long err = ERR_peek_last_error();
		ERR_load_crypto_strings();
		ERR_error_string(err, errbuf);

		bunyan_log(WARN, "d2i_X509 on response from gz agent failed",
		    "openssl_err", BNY_STRING, errbuf,
		    NULL);
		return (EINVAL);
	}
	VERIFY(pcert != NULL);

	pkey = EVP_PKEY_new();
	VERIFY(pkey != NULL);

	rsacp = RSA_new();
	VERIFY(rsacp != NULL);
	rsacp->e = BN_dup(slot->ts_public->rsa->e);
	VERIFY(rsacp->e != NULL);
	rsacp->n = BN_dup(slot->ts_public->rsa->n);
	VERIFY(rsacp->n != NULL);
	/*
	 * NOTE: this takes ownership of the RSA. Freeing it and its BNs is
	 * no longer our problem
	 */
	rv = EVP_PKEY_assign_RSA(pkey, rsacp);
	VERIFY3S(rv, ==, 1);
	rsacp = NULL;

	nid = NID_sha256WithRSAEncryption;

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	VERIFY(serial != NULL);
	VERIFY3S(BN_pseudo_rand(serial, 64, 0, 0), ==, 1);
	VERIFY(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);
	BN_free(serial);

	cert = X509_new();
	VERIFY(cert != NULL);
	VERIFY3S(X509_set_version(cert, 2), ==, 1);
	VERIFY3S(X509_set_serialNumber(cert, serial_asn1), ==, 1);
	ASN1_INTEGER_free(serial_asn1);
	VERIFY(X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL);
	VERIFY(X509_gmtime_adj(X509_get_notAfter(cert), 300) != NULL);

	subj = X509_NAME_new();
	VERIFY(subj != NULL);

	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "title", MBSTRING_ASC,
	    (unsigned char *)slot->ts_name, -1, -1, 0), ==, 1);

	VERIFY0(nvlist_lookup_string(zinfo, "uuid", &uuid));
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
	    (unsigned char *)uuid, -1, -1, 0), ==, 1);

	if (nvlist_lookup_string(zinfo, "alias", &tmp) == 0) {
		VERIFY3S(X509_NAME_add_entry_by_txt(subj, "GN", MBSTRING_ASC,
		    (unsigned char *)tmp, -1, -1, 0), ==, 1);
	}

	if (nvlist_lookup_string(zinfo, "owner_uuid", &tmp) == 0) {
		VERIFY3S(X509_NAME_add_entry_by_txt(subj, "UID", MBSTRING_ASC,
		    (unsigned char *)tmp, -1, -1, 0), ==, 1);
	}

	if (nvlist_lookup_string(zinfo, "datacenter_name", &tmp) == 0) {
		VERIFY3S(X509_NAME_add_entry_by_txt(subj, "DC", MBSTRING_ASC,
		    (unsigned char *)tmp, -1, -1, 0), ==, 1);
	}

	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "OU", MBSTRING_ASC,
	    (unsigned char *)"instances", -1, -1, 0), ==, 1);
	VERIFY3S(X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
	    (unsigned char *)"triton", -1, -1, 0), ==, 1);

	VERIFY3S(X509_set_subject_name(cert, subj), ==, 1);
	X509_NAME_free(subj);

	issu = X509_get_subject_name(pcert);
	VERIFY3S(X509_set_issuer_name(cert, issu), ==, 1);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
	    "critical,CA:TRUE");
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage,
	    "critical,keyCertSign,cRLSign");
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	VERIFY3S(X509_set_pubkey(cert, pkey), ==, 1);
	EVP_PKEY_free(pkey);

	cert->sig_alg->algorithm = OBJ_dup(OBJ_nid2obj(nid));
	cert->cert_info->signature->algorithm = OBJ_dup(OBJ_nid2obj(nid));

	null_parameter = ASN1_TYPE_new();
	bzero(null_parameter, sizeof (*null_parameter));
	null_parameter->type = V_ASN1_NULL;
	null_parameter->value.ptr = NULL;
	cert->sig_alg->parameter = null_parameter;

	null_parameter = ASN1_TYPE_new();
	bzero(null_parameter, sizeof (*null_parameter));
	null_parameter->type = V_ASN1_NULL;
	null_parameter->value.ptr = NULL;
	cert->cert_info->signature->parameter = null_parameter;

	cert->cert_info->enc.modified = 1;
	tbs = NULL;
	tbslen = i2d_X509_CINF(cert->cert_info, &tbs);
	VERIFY(tbs != NULL);
	VERIFY3U(tbslen, >, 0);

	rv = ssh_agent_sign(csc->csc_authfd, pubk, &sig, &siglen, tbs, tbslen,
	    "rsa-sha2-256", 0);
	VERIFY0(rv);

	OPENSSL_free(tbs);

	sigbuf = sshbuf_from(sig, siglen);
	VERIFY(sigbuf != NULL);
	VERIFY0(sshbuf_get_cstring(sigbuf, &tmp, NULL));
	VERIFY(tmp != NULL);
	VERIFY3S(strcmp(tmp, "rsa-sha2-256"), ==, 0);
	free(tmp);
	VERIFY0(sshbuf_get_string(sigbuf, &sigdata, &sigdlen));

	M_ASN1_BIT_STRING_set(cert->signature, sigdata, sigdlen);
	cert->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;

	cdata = NULL;
	cdlen = i2d_X509(cert, &cdata);
	VERIFY(cdata != NULL);
	VERIFY3U(cdlen, >, 0);
	VERIFY3U(cdlen, <, MAX_CERT_LEN);

	X509_free(cert);
	sshbuf_free(sigbuf);
	explicit_bzero(sig, siglen);
	free(sig);
	explicit_bzero(sigdata, sigdlen);
	free(sigdata);

	slot->ts_certdata->tsd_len = 0;
	bcopy(cdata, (void *)slot->ts_certdata->tsd_data, cdlen);
	slot->ts_certdata->tsd_len = cdlen;

	slot->ts_chaindata->tsd_len = 0;
	VERIFY3U(chain->certlen[0], <, MAX_CERT_LEN);
	bcopy(chain->certs[0], (void *)slot->ts_chaindata->tsd_data,
	    chain->certlen[0]);
	slot->ts_chaindata->tsd_len = chain->certlen[0];

	OPENSSL_free(cdata);
	ssh_free_x509chain(chain);
	X509_free(pcert);

	return (0);
}

static int
new_cert_zone(zoneid_t zid, nvlist_t *zinfo, struct token_slot *slot)
{
	struct certsign_ctx csc;
	struct sockaddr_un sunaddr;
	struct ssh_identitylist *idl;
	int rv;

	bzero(&csc, sizeof (csc));
	bzero(&sunaddr, sizeof (sunaddr));
	sunaddr.sun_family = AF_UNIX;
	(void) snprintf(sunaddr.sun_path, sizeof (sunaddr.sun_path),
	    TOKEN_SOCKET_PATH, "global");

	csc.csc_authfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (csc.csc_authfd < 0) {
		bunyan_log(ERROR, "socket() failed",
		    "errno", BNY_INT, errno,
		    "err", BNY_STRING, strerror(errno));
		return (errno);
	}

	if (connect(csc.csc_authfd, (struct sockaddr *)&sunaddr,
	    sizeof (sunaddr)) < 0) {
		bunyan_log(ERROR, "connect() failed",
		    "errno", BNY_INT, errno,
		    "err", BNY_STRING, strerror(errno));
		VERIFY0(close(csc.csc_authfd));
		return (errno);
	}

	rv = ssh_fetch_identitylist(csc.csc_authfd, &idl);
	if (rv != 0) {
		VERIFY0(close(csc.csc_authfd));
		return (rv);
	}

	if (idl->nkeys < 1 || idl->keys == NULL) {
		ssh_free_identitylist(idl);
		VERIFY0(close(csc.csc_authfd));
		return (ENOENT);
	}

	if (slot->ts_type == SLOT_ASYM_AUTH) {
		rv = new_cert_zone_ssh(zid, zinfo, &csc, idl, slot);
	} else if (slot->ts_type == SLOT_ASYM_CERT_SIGN) {
		rv = new_cert_zone_x509(zid, zinfo, &csc, idl, slot);
	} else {
		VERIFY(0);
	}

	ssh_free_identitylist(idl);
	VERIFY0(close(csc.csc_authfd));
	return (rv);
}

/*
 * "Locks" a key, by zeroing out the shared memory segment our child gets the
 * key data from.
 */
static int
lock_key(struct token_slot *slot)
{
	explicit_bzero(slot->ts_data, slot->ts_datasize +
	    sizeof (struct token_slot_data));
	bunyan_log(DEBUG, "locked key",
	    "keyname", BNY_STRING, slot->ts_name, NULL);
	return (0);
}

/*
 * Unlocks a key by decrypting it and writing it into the shared memory segment
 * so our child process (running agent_main()) can use it.
 */
static int
unlock_key(struct token_slot *slot)
{
	struct piv_token *tk, *tks, *systk = NULL;
	struct piv_slot *sl;
	struct piv_ecdh_box *box;
	nvlist_t *nv = slot->ts_nvl;
	int rv;

	uchar_t *boxd, *key, *iv, *encdata;
	uint_t boxdlen, ivlen, authlen, blocksz, enclen;
	size_t keylen;
	const struct sshcipher *cipher;
	struct sshbuf *buf;
	struct sshkey *pkey;
	struct sshcipher_ctx *cctx;
	char *ciphername;
	struct bunyan_timers *tms;
	uint attempts;
	const char *pin;

	tms = bny_timers_new();
	VERIFY3P(tms, !=, NULL);
	VERIFY0(bny_timer_begin(tms));

	tks = sup_systk;

	VERIFY0(nvlist_lookup_byte_array(nv, "local-box", &boxd, &boxdlen));
	VERIFY0(piv_box_from_binary(boxd, boxdlen, &box));

	VERIFY0(piv_box_find_token(tks, box, &tk, &sl));

	rv = piv_system_token_find(tks, &systk);
	if (rv != 0) {
		bunyan_log(WARN, "failed to get a system PIV token", NULL);
	}
	if (tk != systk && systk != NULL) {
		bunyan_log(WARN, "attempting to decrypt key using a PIV "
		    "token that is not the system token",
		    "box_guid", BNY_BIN_HEX,
		    tk->pt_guid, sizeof (tk->pt_guid),
		    "system_guid", BNY_BIN_HEX,
		    systk->pt_guid, sizeof (systk->pt_guid),
		    NULL);
	}

	VERIFY0(bny_timer_next(tms, "select_yubikey"));

	attempts = 1;

	VERIFY0(piv_txn_begin(tk));
	VERIFY0(piv_select(tk));
	if (tk == systk) {
		VERIFY0(piv_system_token_auth(tk));
	} else {
		pin = getenv("PIV_LOCAL_PIN");
		if (pin == NULL)
			pin = "123456";
		VERIFY0(piv_verify_pin(tk, pin, &attempts));
	}
	VERIFY0(piv_box_open(tk, sl, box));
	piv_txn_end(tk);

	VERIFY0(piv_box_take_data(box, &key, &keylen));
	piv_box_free(box);

	VERIFY0(bny_timer_next(tms, "ecdh_kd"));

	VERIFY0(nvlist_lookup_string(nv, "encalgo", &ciphername));
	VERIFY0(nvlist_lookup_byte_array(nv, "iv", &iv, &ivlen));

	cipher = cipher_by_name(ciphername);
	VERIFY3P(cipher, !=, NULL);

	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	VERIFY3S(ivlen, ==, cipher_ivlen(cipher));
	VERIFY3U(keylen, ==, cipher_keylen(cipher));

	VERIFY0(nvlist_lookup_byte_array(nv, "encdata", &encdata, &enclen));

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));

	slot->ts_data->tsd_len = enclen - authlen;
	VERIFY0(cipher_crypt(cctx, 0, (u_char *)slot->ts_data->tsd_data,
	    encdata, enclen - authlen, 0, authlen));

	cipher_free(cctx);
	explicit_bzero(key, keylen);
	free(key);

	VERIFY0(bny_timer_next(tms, "decrypt"));

	buf = sshbuf_from((const void *)slot->ts_data->tsd_data,
	    slot->ts_data->tsd_len);
	VERIFY3P(buf, !=, NULL);
	VERIFY0(sshkey_private_deserialize(buf, &pkey));
	VERIFY3S(sshkey_equal_public(pkey, slot->ts_public), ==, 1);
	sshkey_free(pkey);
	sshbuf_free(buf);

	VERIFY0(bny_timer_next(tms, "verify"));

	bunyan_log(DEBUG, "unlocked key",
	    "keyname", BNY_STRING, slot->ts_name,
	    "timers", BNY_TIMERS, tms, NULL);
	bny_timers_free(tms);

	return (0);
}

static void
generate_keys(const char *zonename, const char *keydir)
{
	struct sshkey *authkey;
	struct sshkey *certkey;
	struct piv_token *tk = NULL;
	int rv;
	struct token_slot tpl;
	bzero(&tpl, sizeof (tpl));

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &sup_ctx);
	VERIFY3S(rv, ==, SCARD_S_SUCCESS);

	sup_tks = piv_enumerate(sup_ctx);
	VERIFY(sup_tks != NULL);
	VERIFY0(piv_system_token_find(sup_tks, &sup_systk));

	tk = sup_systk;
	VERIFY3P(tk, !=, NULL);

	rv = sshkey_generate(KEY_ED25519, 256, &authkey);
	VERIFY0(rv);
	tpl.ts_type = SLOT_ASYM_AUTH;
	tpl.ts_algo = ALGO_ED_25519;
	tpl.ts_name = "auth.key";
	encrypt_and_write_key(authkey, tk, keydir, &tpl);
	sshkey_free(authkey);

	rv = sshkey_generate(KEY_RSA, 2048, &certkey);
	VERIFY0(rv);
	tpl.ts_type = SLOT_ASYM_CERT_SIGN;
	tpl.ts_algo = ALGO_RSA_2048;
	tpl.ts_name = "cert.key";
	encrypt_and_write_key(certkey, tk, keydir, &tpl);
	sshkey_free(certkey);
}

static void
read_key_file(const char *nm, const char *fn)
{
	uchar_t *pubkey;
	uint_t publen;
	nvlist_t *nvl;
	char *shm;
	FILE *f;
	long sz;
	struct token_slot *ts;
	char *buf, *name;
	uint8_t val;
	int rv;
	size_t pgs;
	const size_t pgsz = getpagesize();

	bunyan_log(TRACE, "unpacking key file",
	    "filename", BNY_STRING, nm, NULL);

	f = fopen(fn, "r");
	if (f == NULL) {
		bunyan_log(ERROR, "error opening key file",
		    "filename", BNY_STRING, nm,
		    "errno", BNY_INT, errno,
		    "strerror", BNY_STRING, strerror(errno),
		    NULL);
		return;
	}

	VERIFY0(fseek(f, 0L, SEEK_END));
	sz = ftell(f);
	VERIFY0(fseek(f, 0L, SEEK_SET));

	if (sz > 1*1024*1024 || sz < 0) {
		bunyan_log(ERROR, "bad length of key file",
		    "filename", BNY_STRING, nm, NULL);
		return;
	}

	buf = calloc(1, sz);
	VERIFY(buf != NULL);

	VERIFY3S(fread(buf, sz, 1, f), ==, 1);
	fclose(f);

	if ((rv = nvlist_unpack(buf, sz, &nvl, 0)) != 0) {
		bunyan_log(ERROR, "key file is not an nvlist",
		    "filename", BNY_STRING, nm,
		    "code", BNY_INT, rv, NULL);
		return;
	}

	free(buf);

	VERIFY0(nvlist_lookup_uint8(nvl, "version", &val));
	if (val != 1) {
		bunyan_log(ERROR, "key file is wrong version",
		    "filename", BNY_STRING, nm,
		    "version", BNY_INT, (int)val, NULL);
		return;
	}

	/*
	 * The decrypted key data is always smaller than the nvlist was, so
	 * we'll just allocate that much shared memory for it.
	 *
	 * We add two pages (one at the beginning and end of the mapping) and
	 * set them to PROT_NONE with mprotect, to try to catch various kinds
	 * of overflow bugs that might otherwise reach into the key data.
	 */
	pgs = (sz + sizeof (struct token_slot_data)) / pgsz;
	pgs += 3;	/* 2 extra + round-up from division */
	shm = mmap(0, pgs * pgsz, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	VERIFY(shm != NULL);
	explicit_bzero(shm, pgs * pgsz);
	VERIFY0(mlock(shm + pgsz, (pgs - 2) * pgsz));
	VERIFY0(mprotect(shm, pgsz, PROT_NONE));
	VERIFY0(mprotect(shm + (pgs - 1) * pgsz, pgsz, PROT_NONE));

	ts = calloc(1, sizeof (struct token_slot));
	VERIFY(ts != NULL);
	name = calloc(1, strlen(nm) + 1);
	VERIFY(name != NULL);
	strcpy(name, nm);
	ts->ts_name = name;
	ts->ts_nvl = nvl;
	ts->ts_data = (struct token_slot_data *)(shm + pgsz);
	ts->ts_datasize = sz;

	shm = mmap(0, MAX_CERT_LEN, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	VERIFY(shm != NULL);
	explicit_bzero(shm, sizeof (struct token_slot_data));
	ts->ts_certdata = (struct token_slot_data *)shm;

	shm = mmap(0, MAX_CHAIN_LEN, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	VERIFY(shm != NULL);
	explicit_bzero(shm, sizeof (struct token_slot_data));
	ts->ts_chaindata = (struct token_slot_data *)shm;

	VERIFY0(nvlist_lookup_uint8(nvl, "type", &val));
	VERIFY3U(val, >, 0);
	VERIFY3U(val, <, SLOT_MAX);
	ts->ts_type = val;
	VERIFY0(nvlist_lookup_uint8(nvl, "algo", &val));
	VERIFY3U(val, >, 0);
	VERIFY3U(val, <, ALGO_MAX);
	ts->ts_algo = val;

	VERIFY0(nvlist_lookup_byte_array(nvl, "pubkey", &pubkey, &publen));
	VERIFY0(sshkey_from_blob(pubkey, publen, &ts->ts_public));

	bunyan_log(TRACE, "unpack ok",
	    "filename", BNY_STRING, nm, NULL);

	ts->ts_next = token_slots;
	token_slots = ts;
	ts->ts_id = (++slot_n) ^ id_seed;
}

static void
make_slots(const char *zonename)
{
	char keydir[PATH_MAX];
	char fn[PATH_MAX];
	DIR *dirp;
	struct dirent *dp;
	pid_t kid, w;
	int stat;

	/*
	 * Walk through the zone keys directory and interpret each file as a
	 * key data file. These are formatted as a packed nvlist.
	 */
	snprintf(keydir, sizeof (keydir), TOKEN_KEYS_DIR, zonename);

again:
	if ((dirp = opendir(keydir)) != NULL) {
		do {
			if ((dp = readdir(dirp)) != NULL) {
				if (dp->d_name[0] == '.') {
					continue;
				}
				snprintf(fn, sizeof (fn), "%s/%s", keydir,
				    dp->d_name);

				read_key_file(dp->d_name, fn);
			}
		} while (dp != NULL);

		closedir(dirp);
	}

	if (token_slots == NULL) {
		bunyan_log(INFO, "generating keys for zone", NULL);

		kid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
		assert(kid != -1);
		if (kid == 0) {
			(void) mkdir(keydir, 0700);
			generate_keys(zonename, keydir);
			exit(0);
		}

		do {
			w = waitpid(kid, &stat, 0);
		} while (w == -1 && errno == EINTR);
		assert(WIFEXITED(stat));
		assert(WEXITSTATUS(stat) == 0);
		goto again;
	}
}

static void
supervisor_panic(void)
{
	struct token_slot *ts;
	pid_t w;
	int rv;

	bunyan_log(ERROR, "panic!", NULL);

	for (ts = token_slots; ts != NULL; ts = ts->ts_next) {
		(void) lock_key(ts);
	}
	(void) kill(agent_pid, SIGABRT);
	do {
		w = waitpid(agent_pid, &rv, 0);
	} while (w == -1 && errno == EINTR);

	bunyan_log(INFO, "agent child stopped",
	    "exit_status", BNY_INT, WEXITSTATUS(rv),
	    NULL);
	assert(WIFEXITED(rv));

	abort();
}

static void
supervisor_loop(zoneid_t zid, nvlist_t *zinfo, int ctlfd, int kidfd, int logfd,
    int listensock)
{
	int portfd;
	port_event_t ev;
	timespec_t to;
	int rv;
	struct ctl_cmd cmd, rcmd;
	enum ctl_cmd_type cmdtype;
	struct token_slot *ts;
	pid_t w;
	FILE *logf;
	char *logline;

	bzero(&to, sizeof (to));

	portfd = port_create();
	assert(portfd > 0);

	logf = fdopen(logfd, "r");
	VERIFY(logf != NULL);

	logline = calloc(1, MAX_LOG_LINE);
	VERIFY(logline != NULL);

	VERIFY0(port_associate(portfd,
	    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));
	VERIFY0(port_associate(portfd,
	    PORT_SOURCE_FD, kidfd, POLLIN, NULL));
	VERIFY0(port_associate(portfd,
	    PORT_SOURCE_FD, logfd, POLLIN, NULL));

	while (1) {
		rv = port_get(portfd, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			VERIFY0(rv);
		}
		if (ev.portev_object == ctlfd) {
			VERIFY0(read_cmd(ctlfd, &cmd));
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_SHUTDOWN:
				bzero(&rcmd, sizeof (rcmd));
				rcmd.cc_cookie = cmd.cc_cookie;
				rcmd.cc_type = CMD_SHUTDOWN;
				VERIFY0(write_cmd(kidfd, &rcmd));
				do {
					w = waitpid(agent_pid, &rv, 0);
				} while (w == -1 && errno == EINTR);
				for (ts = token_slots; ts != NULL;
				    ts = ts->ts_next) {
					(void) lock_key(ts);
				}
				bunyan_log(INFO, "agent child stopped",
				    "exit_status", BNY_INT, WEXITSTATUS(rv),
				    NULL);
				assert(WIFEXITED(rv));
				assert(WEXITSTATUS(rv) == 0);
				exit(0);
				break;
			default:
				bunyan_log(ERROR,
				    "parent sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				continue;
			}
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, ctlfd, POLLIN, NULL));

		} else if (ev.portev_object == kidfd) {
			if (read_cmd(kidfd, &cmd) != 0) {
				supervisor_panic();
			}
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_UNLOCK_KEY:
			case CMD_LOCK_KEY:
				for (ts = token_slots; ts != NULL;
				    ts = ts->ts_next) {
					if (ts->ts_id == cmd.cc_p1)
						break;
				}
				if (ts == NULL) {
					bunyan_log(ERROR,
					    "child sent cmd for invalid key",
					    "key_id", BNY_INT, cmd.cc_p1,
					    NULL);
					supervisor_panic();
				}

				if (cmdtype == CMD_UNLOCK_KEY)
					rv = unlock_key(ts);
				else
					rv = lock_key(ts);
				if (rv == 0) {
					bzero(&rcmd, sizeof (rcmd));
					rcmd.cc_cookie = cmd.cc_cookie;
					rcmd.cc_type = CMD_STATUS;
					rcmd.cc_p1 = STATUS_OK;
					VERIFY0(write_cmd(kidfd,
					    &rcmd));
					break;
				}
				break;
			case CMD_RENEW_CERT:
				for (ts = token_slots; ts != NULL;
				    ts = ts->ts_next) {
					if (ts->ts_id == cmd.cc_p1)
						break;
				}
				if (ts == NULL) {
					bunyan_log(ERROR,
					    "child sent cmd for invalid key",
					    "key_id", BNY_INT, cmd.cc_p1,
					    NULL);
					supervisor_panic();
				}
				if (zid == GLOBAL_ZONEID) {
					rv = new_cert_global(ts);
				} else {
					rv = new_cert_zone(zid, zinfo, ts);
				}
				if (rv == 0) {
					bzero(&rcmd, sizeof (rcmd));
					rcmd.cc_cookie = cmd.cc_cookie;
					rcmd.cc_type = CMD_STATUS;
					rcmd.cc_p1 = STATUS_OK;
					VERIFY0(write_cmd(kidfd,
					    &rcmd));
					break;
				}
				bzero(&rcmd, sizeof (rcmd));
				rcmd.cc_cookie = cmd.cc_cookie;
				rcmd.cc_type = CMD_STATUS;
				rcmd.cc_p1 = STATUS_ERROR;
				VERIFY0(write_cmd(kidfd, &rcmd));
				break;
			default:
				bunyan_log(ERROR,
				    "child sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				supervisor_panic();
			}
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, kidfd, POLLIN, NULL));

		} else if (ev.portev_object == logfd) {
			fgets(logline, MAX_LOG_LINE, logf);
			mutex_enter(bunyan_wrmutex);
			fputs(logline, stderr);
			mutex_exit(bunyan_wrmutex);
			VERIFY0(port_associate(portfd,
			    PORT_SOURCE_FD, logfd, POLLIN, NULL));

		} else {
			assert(0);
		}
	}
}

/*
 * Since we've forked off a single parent process, we currently share text
 * pages both with it and with all other children who have forked off the same
 * way. This is dangerous, as cache timing side-channel attacks will be able to
 * easily observe the execution of one zone's soft-token from a different zone
 * (many of these attacks are only possible, or at least are vastly easier,
 * with shared text/code pages).
 *
 * So, our solution here is to walk around all of the mapped pages in
 * RTLD_SELF (this will include text as well as bss and static data) and
 * "unshare" them (make ourselves a private copy). We do this by briefly
 * changing their permissions to RWX, writing a byte in each page, and then
 * changing them back to R-X.
 *
 * We should really add this as a feature to the linker, but for now, le hack.
 */
void
unshare_code(void)
{
	Dl_mapinfo_t mi;
	uint cnt;
	volatile char *ptr, *base, *limit;
	size_t sz;
	char tmp;
	intptr_t pgsz = sysconf(_SC_PAGE_SIZE);
	intptr_t pgmask = ~(pgsz - 1);

	bzero(&mi, sizeof (mi));
	VERIFY0(dlinfo(RTLD_SELF, RTLD_DI_MMAPCNT, &mi.dlm_acnt));
	mi.dlm_maps = calloc(mi.dlm_acnt, sizeof (mmapobj_result_t));
	VERIFY(mi.dlm_maps != NULL);
	VERIFY0(dlinfo(RTLD_SELF, RTLD_DI_MMAPS, &mi));

	for (cnt = 0; cnt < mi.dlm_rcnt; ++cnt) {
		if ((mi.dlm_maps[cnt].mr_prot & PROT_EXEC) == PROT_EXEC) {
			ptr = mi.dlm_maps[cnt].mr_addr;
			sz = mi.dlm_maps[cnt].mr_msize;
			limit = ptr + sz;
			base = (volatile char *)((intptr_t)ptr & pgmask);

			VERIFY0(mprotect((caddr_t)base, sz,
			    PROT_READ | PROT_WRITE | PROT_EXEC));

			for (; ptr < limit; ptr += pgsz) {
				tmp = *ptr;
				*ptr = tmp;
			}

			VERIFY0(mprotect((caddr_t)base, sz,
			    mi.dlm_maps[cnt].mr_prot));
		}
	}

	free(mi.dlm_maps);
}

void
supervisor_main(zoneid_t zid, int ctlfd)
{
	char zonename[ZONENAME_MAX];
	char sockdir[PATH_MAX];
	struct sockaddr_un addr;
	int listensock;
	ssize_t len;
	pid_t kid, w;
	int kidpipe[2], logpipe[2], vmpipe[2];
	priv_set_t *pset;
	int rv, stat;
	int32_t v;
	nvlist_t *zinfo = NULL;
	char *zinfbuf;
	size_t zinflen;
	FILE *vmpipef;
	nvlist_parse_json_error_t jsonerr;
	const char *uuid;

	bunyan_set_name("supervisor");

	unshare_code();

	len = getzonenamebyid(zid, zonename, sizeof (zonename));
	VERIFY3U(len, >, 0);
	zonename[len] = '\0';

	VERIFY0(pipe(vmpipe));

	if (zid != GLOBAL_ZONEID) {
		/* Go fetch info about the zone from vmadm. */
		kid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
		VERIFY(kid != -1);
		if (kid == 0) {
			VERIFY0(close(vmpipe[0]));

			VERIFY3S(dup2(vmpipe[1], 1), ==, 1);
			VERIFY3S(dup2(vmpipe[1], 2), ==, 2);

			VERIFY0(execlp("/usr/sbin/vmadm", "vmadm",
			    "get", zonename, (char *)0));
		}
		VERIFY0(close(vmpipe[1]));

		do {
			w = waitpid(kid, &stat, 0);
		} while (w == -1 && errno == EINTR);
		assert(WIFEXITED(stat));
		assert(WEXITSTATUS(stat) == 0);

		vmpipef = fdopen(vmpipe[0], "r");
		VERIFY(vmpipef != NULL);
		zinfbuf = calloc(1, MAX_ZINF_LEN);
		VERIFY(zinfbuf != NULL);
		zinflen = fread(zinfbuf, 1, MAX_ZINF_LEN, vmpipef);
		VERIFY3U(zinflen, >, 0);
		VERIFY3U(zinflen, <, MAX_ZINF_LEN);
		VERIFY(feof(vmpipef));
		VERIFY0(fclose(vmpipef));

		zinfbuf[zinflen] = '\0';

		if (nvlist_parse_json(zinfbuf, zinflen, &zinfo,
		    NVJSON_FORCE_INTEGER, &jsonerr) != 0) {
			bunyan_log(ERROR, "vmadm json parse failure",
			    "errno", BNY_INT, jsonerr.nje_errno,
			    "pos", BNY_INT, jsonerr.nje_pos,
			    "err", BNY_STRING, jsonerr.nje_message,
			    "json", BNY_STRING, zinfbuf,
			    NULL);
			VERIFY(0);
		}
		VERIFY(zinfo != NULL);

		VERIFY0(nvlist_lookup_int32(zinfo, "v", &v));
		VERIFY3S(v, ==, 1);
		VERIFY0(nvlist_lookup_string(zinfo, "uuid", (char **)&uuid));
		VERIFY0(strcmp(uuid, zonename));
	}

	id_seed = arc4random_uniform(255);

	/*
	 * Early drop of privs before we fork our child or do any work.
	 * We have to keep quite a bit of stuff here, but we can let go of
	 * some of it later after we've forked.
	 */
	pset = priv_allocset();
	assert(pset != NULL);

	priv_basicset(pset);

	VERIFY0(priv_delset(pset, PRIV_PROC_EXEC));
	VERIFY0(priv_delset(pset, PRIV_PROC_INFO));
	VERIFY0(priv_delset(pset, PRIV_PROC_SESSION));
	VERIFY0(priv_delset(pset, PRIV_FILE_LINK_ANY));
	/* We need these for dealing with the socket and key files. */
	VERIFY0(priv_addset(pset, PRIV_FILE_DAC_READ));
	VERIFY0(priv_addset(pset, PRIV_FILE_DAC_WRITE));
	VERIFY0(priv_addset(pset, PRIV_FILE_DAC_SEARCH));
	VERIFY0(priv_addset(pset, PRIV_IPC_DAC_READ));
	VERIFY0(priv_addset(pset, PRIV_IPC_DAC_WRITE));
	/* Our child will need these to do mlockall() and drop privs. */
	VERIFY0(priv_addset(pset, PRIV_PROC_LOCK_MEMORY));
	VERIFY0(priv_addset(pset, PRIV_PROC_CHROOT));
	VERIFY0(priv_addset(pset, PRIV_PROC_SETID));

	VERIFY0(setppriv(PRIV_SET, PRIV_PERMITTED, pset));
	VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, pset));

	bunyan_log(DEBUG, "starting supervisor for zone",
	    "zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	/*
	 * Lock all our memory into RAM so it can't be swapped out. We're
	 * going to be doing crypto operations and dealing with key material,
	 * so we don't want anything to be swappable.
	 */
	VERIFY0(mlockall(MCL_CURRENT | MCL_FUTURE));

	/* Open the socket directory and make our listen socket. */
	snprintf(sockdir, sizeof (sockdir), TOKEN_SOCKET_DIR, zonename);
	(void) mkdir(sockdir, 0700);

	listensock = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(listensock > 0);
	bzero(&addr, sizeof (addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof (addr.sun_path) - 1,
	    TOKEN_SOCKET_PATH, zonename);
	(void) unlink(addr.sun_path);
	VERIFY0(bind(listensock, (struct sockaddr *)&addr, sizeof (addr)));

	bunyan_set("zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	bunyan_log(DEBUG, "zonecontrol socket created",
	    "sockpath", BNY_STRING, addr.sun_path, NULL);

	/* Now open up our key files and establish the shared pages. */
	make_slots(zonename);

	VERIFY0(pipe(kidpipe));
	VERIFY0(pipe(logpipe));

	/* And create the actual agent process. */
	agent_pid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
	assert(agent_pid != -1);
	if (agent_pid == 0) {
		VERIFY0(close(kidpipe[0]));
		VERIFY0(close(ctlfd));
		VERIFY0(close(logpipe[0]));

		VERIFY3S(dup2(logpipe[1], 1), ==, 1);
		VERIFY3S(dup2(logpipe[1], 2), ==, 2);
		bunyan_unshare();

		agent_main(zid, zinfo, listensock, kidpipe[1]);
		bunyan_log(ERROR, "agent_main returned", NULL);
		exit(1);
	}
	VERIFY0(close(kidpipe[1]));
	VERIFY0(close(logpipe[1]));

	/*
	 * Now that we've finished forking we can give up the privs we only
	 * kept to give to our child.
	 */
	VERIFY0(priv_delset(pset, PRIV_PROC_FORK));
	/* we still need this for piv shm code */
	/*VERIFY0(priv_delset(pset, PRIV_PROC_LOCK_MEMORY));*/
	VERIFY0(priv_delset(pset, PRIV_PROC_CHROOT));
	VERIFY0(priv_delset(pset, PRIV_PROC_SETID));
	/* We still need this for PCSCd */
	/*VERIFY0(priv_delset(pset, PRIV_NET_ACCESS));*/

	VERIFY0(setppriv(PRIV_SET, PRIV_PERMITTED, pset));
	VERIFY0(setppriv(PRIV_SET, PRIV_EFFECTIVE, pset));
	priv_freeset(pset);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &sup_ctx);
	VERIFY3S(rv, ==, SCARD_S_SUCCESS);

	sup_tks = piv_enumerate(sup_ctx);
	VERIFY(sup_tks != NULL);
	VERIFY0(piv_system_token_find(sup_tks, &sup_systk));

	supervisor_loop(zid, zinfo, ctlfd, kidpipe[0], logpipe[0], listensock);
}

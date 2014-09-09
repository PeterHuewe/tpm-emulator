/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: tpm_transport.c 367 2010-02-13 15:52:18Z mast $
 */

/* 
 * Thanks go to Edison Su (<sudison@gmail.com>) for providing
 * the initial Transport Session patch.
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"
#include "tpm_data.h"
#include "crypto/rsa.h"
#include "crypto/sha1.h"

/*
 * Transport Sessions ([TPM_Part3], Section 24)
 */

static void debug_buf(const char *str, uint8_t *buf, size_t buf_len)
{
  static char map[] = "0123456789abcdef";
  char hex[buf_len * 3];
  size_t i;
  for (i = 0; i < buf_len; i++) {
    hex[i*3 + 0] = map[buf[i] >> 4];
    hex[i*3 + 1] = map[buf[i] & 0x0f];
    hex[i*3 + 2] = ' ';
  }
  hex[sizeof(hex) - 1] = 0;
  debug("%s%s", str, hex);
}

static int decrypt_transport_auth(TPM_KEY_DATA *key, BYTE *enc, UINT32 enc_size,
                                  TPM_TRANSPORT_AUTH *trans_auth) 
{
  BYTE *buf;
  size_t buf_size;
  int scheme;
  switch (key->encScheme) {
    case TPM_ES_RSAESOAEP_SHA1_MGF1: scheme = RSA_ES_OAEP_SHA1; break;
    case TPM_ES_RSAESPKCSv15: scheme = RSA_ES_PKCSV15; break;
    default: return -1;
  }
  buf = tpm_malloc(key->key.size);
  if (buf == NULL
      || tpm_rsa_decrypt(&key->key, scheme, enc, enc_size, buf, &buf_size)
      || buf_size != sizeof_TPM_TRANSPORT_AUTH(x)
      || (((UINT16)buf[0] << 8) | buf[1]) != TPM_TAG_TRANSPORT_AUTH) {
    tpm_free(buf);
    return -1;
  }
  trans_auth->tag = TPM_TAG_TRANSPORT_AUTH;
  memcpy(trans_auth->authData, &buf[2], sizeof(TPM_AUTHDATA));
  tpm_free(buf);
  return 0;
}

static void transport_log_in(BYTE *params, BYTE *pubKeyHash,
                             TPM_DIGEST *transDigest)
{
  BYTE *ptr, buf[sizeof_TPM_TRANSPORT_LOG_IN(x)];
  UINT32 len;
  tpm_sha1_ctx_t sha1;

  ptr = buf; len = sizeof(buf);
  tpm_marshal_TPM_TAG(&ptr, &len, TPM_TAG_TRANSPORT_LOG_IN);
  tpm_marshal_BLOB(&ptr, &len, params, SHA1_DIGEST_LENGTH);
  tpm_marshal_BLOB(&ptr, &len, pubKeyHash, SHA1_DIGEST_LENGTH);
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, transDigest->digest, sizeof(transDigest->digest));
  tpm_sha1_update(&sha1, buf, sizeof(buf));
  tpm_sha1_final(&sha1, transDigest->digest);
  debug_buf("LogIn: transDigest: ", transDigest->digest, sizeof(transDigest->digest));
}

static void transport_log_out(BYTE *params, TPM_DIGEST *transDigest)
{
  BYTE *ptr, buf[sizeof_TPM_TRANSPORT_LOG_OUT(x)];
  UINT32 len;
  tpm_sha1_ctx_t sha1;

  ptr = buf; len = sizeof(buf);
  tpm_marshal_TPM_TAG(&ptr, &len, TPM_TAG_TRANSPORT_LOG_OUT);
  tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, &tpmData.stany.data.currentTicks);
  tpm_marshal_BLOB(&ptr, &len, params, SHA1_DIGEST_LENGTH);
  tpm_marshal_TPM_MODIFIER_INDICATOR(&ptr, &len, tpmData.stany.flags.localityModifier);
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, transDigest->digest, sizeof(transDigest->digest));
  tpm_sha1_update(&sha1, buf, sizeof(buf));
  tpm_sha1_final(&sha1, transDigest->digest);
  debug_buf("LogOut: transDigest: ", transDigest->digest, sizeof(transDigest->digest));
}

TPM_RESULT TPM_EstablishTransport(TPM_KEY_HANDLE encHandle,
                                  TPM_TRANSPORT_PUBLIC *transPublic,
                                  UINT32 secretSize, BYTE *secret,
                                  TPM_AUTH *auth1,
                                  TPM_TRANSHANDLE *transHandle,
                                  TPM_MODIFIER_INDICATOR *locality,
                                  TPM_CURRENT_TICKS *currentTicks,
                                  TPM_NONCE *transNonceEven)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_TRANSPORT_AUTH trans_auth;
  TPM_SESSION_DATA *session;

  info("TPM_EstablishTransport()");
  /* setup authorization data */
  if (encHandle == TPM_KH_TRANSPORT) {
    if (auth1->authHandle != TPM_INVALID_HANDLE) return TPM_BADTAG;
    if (transPublic->transAttributes & TPM_TRANSPORT_ENCRYPT) return TPM_BAD_SCHEME;
    if (secretSize != 20) return TPM_BAD_PARAM_SIZE;
    memcpy(trans_auth.authData, secret, 20);
  } else {
    /* get key and verify its usage */
    key = tpm_get_key(encHandle);
    if (key == NULL) return TPM_INVALID_KEYHANDLE;
    if (key->keyUsage != TPM_KEY_STORAGE && key->keyUsage != TPM_KEY_LEGACY)
        return TPM_INVALID_KEYUSAGE;
    /* verify authorization */ 
    if (key->authDataUsage != TPM_AUTH_NEVER) {
      res = tpm_verify_auth(auth1, key->usageAuth, encHandle);
      if (res != TPM_SUCCESS) return res;
      if (decrypt_transport_auth(key, secret, secretSize, &trans_auth))
        return TPM_DECRYPT_ERROR;
    }
  }
  /* check whether the transport has to be encrypted */
  if (transPublic->transAttributes & TPM_TRANSPORT_ENCRYPT) {
    if (tpmData.permanent.flags.FIPS
        && transPublic->algID == TPM_ALG_MGF1) return TPM_INAPPROPRIATE_ENC;
    /* until now, only MGF1 is supported */
    if (transPublic->algID != TPM_ALG_MGF1) return TPM_BAD_KEY_PROPERTY;
  }
  /* initialize transport session */
  tpm_get_random_bytes(transNonceEven->nonce, sizeof(transNonceEven->nonce));
  *transHandle = tpm_get_free_session(TPM_ST_TRANSPORT);
  session = tpm_get_transport(*transHandle);
  if (session == NULL) return TPM_RESOURCES;
  session->transInternal.transHandle = *transHandle;
  memset(&session->transInternal.transDigest, 0, sizeof(TPM_DIGEST));
  memcpy(&session->transInternal.transPublic, transPublic,
    sizeof_TPM_TRANSPORT_PUBLIC((*transPublic)));
  memcpy(&session->transInternal.transNonceEven, transNonceEven, sizeof(TPM_NONCE));
  memcpy(&session->nonceEven, transNonceEven, sizeof(TPM_NONCE));
  memcpy(&session->transInternal.authData, trans_auth.authData, sizeof(TPM_AUTHDATA));
  *locality = tpmData.stany.flags.localityModifier;
  memcpy(currentTicks, &tpmData.stany.data.currentTicks, sizeof(TPM_CURRENT_TICKS));
  /* perform transport logging */
  if (transPublic->transAttributes & TPM_TRANSPORT_LOG) {
    tpm_sha1_ctx_t sha1;
    BYTE *ptr, buf[4 + 4 + 4 + sizeof_TPM_CURRENT_TICKS(x) + 20];
    UINT32 len;
    /* log input */
    memset(buf, 0, sizeof(buf));
    transport_log_in(auth1->digest, buf, &session->transInternal.transDigest);
    /* compute digest of output parameters and log output */
    ptr = buf; len = sizeof(buf);
    tpm_marshal_UINT32(&ptr, &len, TPM_SUCCESS);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &len, TPM_ORD_EstablishTransport);
    tpm_marshal_TPM_MODIFIER_INDICATOR(&ptr, &len, *locality);
    tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, currentTicks);
    tpm_marshal_TPM_NONCE(&ptr, &len, transNonceEven);
    tpm_sha1_init(&sha1);
    tpm_sha1_update(&sha1, buf, sizeof(buf));
    tpm_sha1_final(&sha1, buf);
    transport_log_out(buf, &session->transInternal.transDigest);
  }
  /* check whether this is a exclusive transport session */
  if (transPublic->transAttributes & TPM_TRANSPORT_EXCLUSIVE) {
    tpmData.stany.flags.transportExclusive = TRUE;
    tpmData.stany.data.transExclusive = *transHandle;
  }
  auth1->continueAuthSession = FALSE;
  return TPM_SUCCESS;
}

extern UINT32 tpm_get_in_param_offset(TPM_COMMAND_CODE ordinal);
extern UINT32 tpm_get_out_param_offset(TPM_COMMAND_CODE ordinal);
extern void tpm_compute_in_param_digest(TPM_REQUEST *req);
extern void tpm_execute_command(TPM_REQUEST *req, TPM_RESPONSE *rsp);
extern void tpm_compute_out_param_digest(TPM_COMMAND_CODE ordinal, TPM_RESPONSE *rsp);

static void decrypt_wrapped_command(BYTE *buf, UINT32 buf_len, TPM_AUTH *auth,
                                    TPM_SESSION_DATA *session)

{
  UINT32 i, j;
  BYTE mask[SHA1_DIGEST_LENGTH];
  tpm_sha1_ctx_t sha1;
  for (i = 0; buf_len > 0; i++) {
    tpm_sha1_init(&sha1);
    tpm_sha1_update(&sha1, session->nonceEven.nonce, sizeof(session->nonceEven.nonce));
    tpm_sha1_update(&sha1, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
    tpm_sha1_update(&sha1, (uint8_t*)"in", 2);
    tpm_sha1_update(&sha1, session->transInternal.authData, sizeof(TPM_SECRET));
    tpm_sha1_update_be32(&sha1, i);
    tpm_sha1_final(&sha1, mask);
    for (j = 0; j < sizeof(mask) && buf_len > 0; j++) { 
      *buf++ ^= mask[j];
      buf_len--;
    }
  }
}

static void encrypt_wrapped_command(BYTE *buf, UINT32 buf_len, TPM_AUTH *auth,
                                    TPM_SESSION_DATA *session)
{
  UINT32 i, j;
  BYTE mask[SHA1_DIGEST_LENGTH];
  tpm_sha1_ctx_t sha1;
  for (i = 0; buf_len > 0; i++) {
    tpm_sha1_init(&sha1);
    tpm_sha1_update(&sha1, session->nonceEven.nonce, sizeof(session->nonceEven.nonce));
    tpm_sha1_update(&sha1, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
    tpm_sha1_update(&sha1, (uint8_t*)"out", 3);
    tpm_sha1_update(&sha1, session->transInternal.authData, sizeof(TPM_SECRET));
    tpm_sha1_update_be32(&sha1, i);
    tpm_sha1_final(&sha1, mask);
    for (j = 0; j < sizeof(mask) && buf_len > 0; j++) { 
      *buf++ ^= mask[j];
      buf_len--;
    }
  }
}

static void compute_key_digest(TPM_REQUEST *req, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t ctx;
  TPM_HANDLE h1, h2;
  TPM_KEY_DATA *k1, *k2;
  BYTE *ptr;
  UINT32 len, offset = tpm_get_in_param_offset(req->ordinal);
  /* handle some exceptions */
  if (req->ordinal == TPM_ORD_FlushSpecific) offset = 0;
  else if (req->ordinal == TPM_ORD_OwnerReadInternalPub) offset = 4;
  /* compute public key digests */
  if (offset == 0) {
    debug("no handles");
    memset(digest, 0, sizeof(TPM_DIGEST));
  } else if (offset == 4) {
    debug("one handle");
    ptr = req->param; len = 4;
    tpm_unmarshal_TPM_HANDLE(&ptr, &len, &h1);
    k1 = tpm_get_key(h1);
    if (k1 != NULL && tpm_compute_key_data_digest(k1, digest) == 0) {
      debug("key found");
      /* compute outer hash */
      tpm_sha1_init(&ctx);
      tpm_sha1_update(&ctx, digest->digest, sizeof(digest->digest));
      tpm_sha1_final(&ctx, digest->digest);
    } else {
      memset(digest, 0, sizeof(TPM_DIGEST));
    }
  } else if (offset == 8) {
    TPM_DIGEST digest2;
    debug("two handles");
    ptr = req->param; len = 8;
    tpm_unmarshal_TPM_HANDLE(&ptr, &len, &h1);
    tpm_unmarshal_TPM_HANDLE(&ptr, &len, &h2);
    k1 = tpm_get_key(h1);
    k2 = tpm_get_key(h2);
    if (k1 != NULL && tpm_compute_key_data_digest(k1, digest) == 0
        && k2 != NULL && tpm_compute_key_data_digest(k2, &digest2) == 0) {
      debug("two keys found");
      /* compute outer hash */
      tpm_sha1_init(&ctx);
      tpm_sha1_update(&ctx, digest->digest, sizeof(digest->digest));
      tpm_sha1_update(&ctx, digest2.digest, sizeof(digest2.digest));
      tpm_sha1_final(&ctx, digest->digest);
    } else {
      memset(digest, 0, sizeof(TPM_DIGEST));
    }
  } else {
    memset(digest, 0, sizeof(TPM_DIGEST));
  }
}

TPM_RESULT TPM_ExecuteTransport(UINT32 inWrappedCmdSize, BYTE *inWrappedCmd,
                                TPM_AUTH *auth1, UINT64 *currentTicks,
                                TPM_MODIFIER_INDICATOR *locality,
                                UINT32 *outWrappedCmdSize, BYTE **outWrappedCmd)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_REQUEST req;
  TPM_RESPONSE rsp;
  BYTE *ptr, buf[4 * 4 + 8 + 20];
  UINT32 len, offset;
  tpm_sha1_ctx_t sha1;
  info("TPM_ExecuteTransport()");
  /* get transport session */
  session = tpm_get_transport(auth1->authHandle);
  if (session == NULL) return TPM_BAD_PARAMETER;
  /* unmarshal wrapped command */
  len = inWrappedCmdSize;
  ptr = inWrappedCmd;
  if (tpm_unmarshal_TPM_REQUEST(&ptr, &len, &req)) return TPM_FAIL;
  /* decrypt wrapped command if needed */
  ptr = tpm_malloc(req.paramSize);
  if (ptr == NULL) return TPM_FAIL;
  memcpy(ptr, req.param, req.paramSize);
  if (session->transInternal.transPublic.transAttributes & TPM_TRANSPORT_ENCRYPT) {
    if (req.ordinal == TPM_ORD_OIAP || req.ordinal == TPM_ORD_OSAP) {
      offset = req.paramSize;
    } else if (req.ordinal == TPM_ORD_DSAP) {
      offset = 30;
    } else {
      offset = tpm_get_in_param_offset(req.ordinal);
    }
    debug("decrypting %d bytes, starting at pos %d", req.paramSize - offset, offset);
    decrypt_wrapped_command(ptr + offset, req.paramSize - offset, auth1, session);
  }
  req.param = ptr;
  /* verify authorization */
  tpm_compute_in_param_digest(&req);
  tpm_sha1_init(&sha1);
  tpm_sha1_update_be32(&sha1, TPM_ORD_ExecuteTransport);
  tpm_sha1_update_be32(&sha1, inWrappedCmdSize);
  tpm_sha1_update(&sha1, req.auth1.digest, sizeof(req.auth1.digest));
  tpm_sha1_final(&sha1, auth1->digest);
  res = tpm_verify_auth(auth1, session->transInternal.authData, TPM_INVALID_HANDLE);
  if (res != TPM_SUCCESS) {
    tpm_free(req.param);
    return res;
  }
  /* nested transport sessions are not allowed */
  if (req.ordinal == TPM_ORD_EstablishTransport
      || req.ordinal == TPM_ORD_ExecuteTransport
      || req.ordinal == TPM_ORD_ReleaseTransportSigned) {
    tpm_free(req.param);
    return TPM_NO_WRAP_TRANSPORT;
  }
  /* log input parameters */
  if (session->transInternal.transPublic.transAttributes & TPM_TRANSPORT_LOG) {
    TPM_DIGEST keyDigest;
    compute_key_digest(&req, &keyDigest);
    transport_log_in(req.auth1.digest, keyDigest.digest,
                     &session->transInternal.transDigest);
  }
  /* execute and audit command*/
  tpm_audit_request(req.ordinal, &req);
  tpm_execute_command(&req, &rsp);
  tpm_audit_response(req.ordinal, &rsp);
  tpm_free(req.param);
  /* get locality and ticks */
  *locality = tpmData.stany.flags.localityModifier;
  *currentTicks = tpmData.stany.data.currentTicks.currentTicks;
  /* if required, compute digest of internal output parameters */
  debug("result = %d", rsp.result);
  if (rsp.result == TPM_SUCCESS) {
    if (rsp.tag == TPM_TAG_RSP_COMMAND) {
      rsp.auth1 = &req.auth1;
      tpm_compute_out_param_digest(req.ordinal, &rsp);
    }
    /* encrypt parameters */
    if (session->transInternal.transPublic.transAttributes & TPM_TRANSPORT_ENCRYPT) {
      if (req.ordinal == TPM_ORD_OIAP || req.ordinal == TPM_ORD_OSAP) {
        offset = rsp.paramSize;
      } else if (req.ordinal == TPM_ORD_DSAP) {
        offset = rsp.paramSize;
      } else {
        offset = tpm_get_out_param_offset(req.ordinal);
      }
      debug("encrypting %d bytes, starting at pos %d", rsp.paramSize - offset, offset);
      encrypt_wrapped_command(rsp.param + offset, rsp.paramSize - offset, auth1, session);
    }
  } else {
    rsp.auth1 = &req.auth1;
    memset(rsp.auth1->digest, 0, sizeof(*rsp.auth1->digest));
  }
  /* marshal response */
  *outWrappedCmdSize = len = rsp.size;
  *outWrappedCmd = ptr = tpm_malloc(len);
  if (ptr == NULL) {
    tpm_free(rsp.param);
    return TPM_FAIL;
  }
  tpm_marshal_TPM_RESPONSE(&ptr, &len, &rsp);
  debug("marshalling done.");
  /* log output parameters */
  if (session->transInternal.transPublic.transAttributes & TPM_TRANSPORT_LOG) {
    transport_log_out(rsp.auth1->digest, &session->transInternal.transDigest);
  }
  tpm_free(rsp.param);
  /* compute digest of output parameters */
  ptr = buf; len = sizeof(buf);
  tpm_marshal_UINT32(&ptr, &len, TPM_SUCCESS);
  tpm_marshal_TPM_COMMAND_CODE(&ptr, &len, TPM_ORD_ExecuteTransport);
  tpm_marshal_UINT64(&ptr, &len, *currentTicks);
  tpm_marshal_TPM_MODIFIER_INDICATOR(&ptr, &len, *locality);
  tpm_marshal_UINT32(&ptr, &len, *outWrappedCmdSize);
  memcpy(ptr, rsp.auth1->digest, sizeof(rsp.auth1->digest));
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof(buf));
  tpm_sha1_final(&sha1, auth1->digest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ReleaseTransportSigned(TPM_KEY_HANDLE keyHandle,
                                      TPM_NONCE *antiReplay,
                                      TPM_AUTH *auth1, TPM_AUTH *auth2,
                                      TPM_MODIFIER_INDICATOR *locality,
                                      TPM_CURRENT_TICKS *currentTicks,
                                      UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  BYTE buf[30 + 20];
  info("TPM_ReleaseTransportSigned()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */ 
  if (auth2->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
    session = tpm_get_transport(auth2->authHandle);
    if (session == NULL) return TPM_INVALID_AUTHHANDLE;
    res = tpm_verify_auth(auth2, session->transInternal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
  } else {
    session = tpm_get_transport(auth1->authHandle);
    if (session == NULL) return TPM_INVALID_AUTHHANDLE;
    res = tpm_verify_auth(auth1, session->transInternal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return res;
  }
  /* invalidate transport session */
  auth1->continueAuthSession = FALSE;
  /* logging must be enabled */
  if (!(session->transInternal.transPublic.transAttributes & TPM_TRANSPORT_LOG))
    return TPM_BAD_MODE;
  *locality = tpmData.stany.flags.localityModifier;
  memcpy(currentTicks, &tpmData.stany.data.currentTicks, sizeof(TPM_CURRENT_TICKS));
  transport_log_out(auth1->digest, &session->transInternal.transDigest);
  /* setup a TPM_SIGN_INFO structure */
  memcpy(&buf[0], (uint8_t*)"\x00\x05TRAN", 6);
  memcpy(&buf[6], antiReplay->nonce, 20);
  memcpy(&buf[26], (uint8_t*)"\x00\x00\x00\x14", 4);
  memcpy(&buf[30], session->transInternal.transDigest.digest, 20);
  /* sign info structure */ 
  if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_SHA1) {
    tpm_sha1_ctx_t ctx;
    debug("TPM_SS_RSASSAPKCS1v15_SHA1");
    tpm_sha1_init(&ctx);
    tpm_sha1_update(&ctx, buf, sizeof(buf));
    tpm_sha1_final(&ctx, buf);
    res = tpm_sign(key, auth1, FALSE, buf, SHA1_DIGEST_LENGTH, sig, sigSize);
  } else if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_INFO) {
    debug("TPM_SS_RSASSAPKCS1v15_INFO");
    res = tpm_sign(key, auth1, TRUE, buf, sizeof(buf), sig, sigSize);
  } else {
    debug("unsupported signature scheme: %02x", key->sigScheme);
    res = TPM_INVALID_KEYUSAGE;
  }
  return res;
}

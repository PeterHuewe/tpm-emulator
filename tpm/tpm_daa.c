/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *               2005-2008 Heiko Stamer <stamer@gaos.org> 
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
 * $Id: tpm_daa.c 452 2010-07-19 19:05:05Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"
#include "crypto/sha1.h"
#include "crypto/rsa.h"
#include "crypto/rc4.h"
#include "crypto/hmac.h"

#define DAA_LABEL_00 ((uint8_t*)"\x00")
#define DAA_LABEL_01 ((uint8_t*)"\x01")
#define DAA_LABEL_r0 ((uint8_t*)"r0")
#define DAA_LABEL_r1 ((uint8_t*)"r1")
#define DAA_LABEL_r2 ((uint8_t*)"r2")

UINT32 tpm_get_free_daa_session(void)
{
  UINT32 i;
  
  for (i = 0; i < TPM_MAX_SESSIONS_DAA; i++) {
    if (tpmData.stany.data.sessionsDAA[i].type == TPM_ST_INVALID) {
      tpmData.stany.data.sessionsDAA[i].type = TPM_ST_DAA;
      tpmData.stany.data.sessionsDAA[i].handle = INDEX_TO_DAA_HANDLE(i);
      return INDEX_TO_DAA_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}

/* Verify that DAA_session->DAA_digestContext == 
 * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error on mismatch */
static TPM_RESULT tpm_daa_verify_digestContext(TPM_DAA_SESSION_DATA *session, 
                                               tpm_sha1_ctx_t *sha1)
{
  TPM_DIGEST dgt;
  UINT32 size, len;
  BYTE *buf, *ptr;
  
  tpm_sha1_init(sha1);
  
  size = len = sizeof(TPM_DAA_TPM);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return -1;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_TPM(&ptr, &len, &session->DAA_tpmSpecific)) {
    tpm_free(buf);
    return -1;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  size = len = sizeof(TPM_DAA_JOINDATA);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return -1;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_JOINDATA(&ptr, &len, &session->DAA_joinSession)) {
    tpm_free(buf);
    return -1;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  tpm_sha1_final(sha1, dgt.digest);
  
  return memcmp(dgt.digest, session->DAA_session.DAA_digestContext.digest, 
    sizeof(TPM_DIGEST));
}

/* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
 * DAA_joinSession) */
static void tpm_daa_update_digestContext(TPM_DAA_SESSION_DATA *session,
                                         tpm_sha1_ctx_t *sha1)
{
  UINT32 size, len;
  BYTE *buf, *ptr;
  
  tpm_sha1_init(sha1);
  
  /* DAA_tpmSpecific */
  size = len = sizeof(TPM_DAA_TPM);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_TPM(&ptr, &len, &session->DAA_tpmSpecific)) {
    tpm_free(buf);
    return;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  /* DAA_joinSession */
  size = len = sizeof(TPM_DAA_JOINDATA);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_JOINDATA(&ptr, &len, &session->DAA_joinSession)) {
    tpm_free(buf);
    return;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  tpm_sha1_final(sha1, session->DAA_session.DAA_digestContext.digest);
}

/* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) and 
 * return error on mismatch */
static TPM_RESULT tpm_daa_verify_digestContext_sign(TPM_DAA_SESSION_DATA *session,
                                                    tpm_sha1_ctx_t *sha1)
{
  TPM_DIGEST dgt;
  UINT32 size, len;
  BYTE *buf, *ptr;
  
  tpm_sha1_init(sha1);
  
  size = len = sizeof(TPM_DAA_TPM);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return -1;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_TPM(&ptr, &len, &session->DAA_tpmSpecific)) {
    tpm_free(buf);
    return -1;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  tpm_sha1_final(sha1, dgt.digest);
  
  return memcmp(dgt.digest, session->DAA_session.DAA_digestContext.digest, 
    sizeof(TPM_DIGEST));
}

/* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific) */
static void tpm_daa_update_digestContext_sign(TPM_DAA_SESSION_DATA *session,
                                              tpm_sha1_ctx_t *sha1)
{
  UINT32 size, len;
  BYTE *buf, *ptr;
  
  tpm_sha1_init(sha1);
  
  size = len = sizeof(TPM_DAA_TPM);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_TPM(&ptr, &len, &session->DAA_tpmSpecific)) {
    tpm_free(buf);
    return;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  tpm_sha1_final(sha1, session->DAA_session.DAA_digestContext.digest);
}

/* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
 * SHA-1(DAA_issuerSettings) and return error on mismatch */
static TPM_RESULT tpm_daa_verify_digestIssuer(TPM_DAA_SESSION_DATA *session,
                                              tpm_sha1_ctx_t *sha1)
{
  TPM_DIGEST dgt;
  UINT32 size, len;
  BYTE *buf, *ptr;
  
  tpm_sha1_init(sha1);
  
  size = len = sizeof(TPM_DAA_ISSUER);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return -1;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_ISSUER(&ptr, &len, &session->DAA_issuerSettings)) {
    tpm_free(buf);
    return -1;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  tpm_sha1_final(sha1, dgt.digest);
  
  return memcmp(dgt.digest, session->DAA_tpmSpecific.DAA_digestIssuer.digest, 
    sizeof(TPM_DIGEST));
}

/* Set DAA_tpmSpecific->DAA_digestIssuer == SHA-1(DAA_issuerSettings) */
static void tpm_daa_update_digestIssuer(TPM_DAA_SESSION_DATA *session,
                                        tpm_sha1_ctx_t *sha1)
{
  UINT32 size, len;
  BYTE *buf, *ptr;
  
  tpm_sha1_init(sha1);
  
  size = len = sizeof(TPM_DAA_ISSUER);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL)
    return;
  memset(buf, 0, size);
  if (tpm_marshal_TPM_DAA_ISSUER(&ptr, &len, &session->DAA_issuerSettings)) {
    tpm_free(buf);
    return;
  }
  tpm_sha1_update(sha1, buf, size);
  tpm_free(buf);
  
  tpm_sha1_final(sha1, session->DAA_tpmSpecific.DAA_digestIssuer.digest);
}

/* Verify that SHA-1(input) == digest and return error !TPM_SUCCESS 
 * on mismatch */
static TPM_RESULT tpm_daa_verify_generic(TPM_DIGEST digest, BYTE *input, 
                                         UINT32 inputSize, tpm_sha1_ctx_t *sha1)
{
  TPM_DIGEST dgt;
  
  tpm_sha1_init(sha1);
  tpm_sha1_update(sha1, input, inputSize);
  tpm_sha1_final(sha1, dgt.digest);
  return memcmp(dgt.digest, digest.digest, sizeof(TPM_DIGEST));
}

/* Encryption and decryption of the TPM_DAA_SENSITIVE structure */
static int encrypt_daa(BYTE *iv, UINT32 iv_size, TPM_DAA_SENSITIVE *sensitive, 
                       BYTE **enc, UINT32 *enc_size)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  
  /* marshal sensitive */
  *enc_size = len = sizeof_TPM_DAA_SENSITIVE((*sensitive));
  *enc = ptr = tpm_malloc(len);
  if (*enc == NULL)
    return -1;
  if (tpm_marshal_TPM_DAA_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*enc);
    return -1;
  }
  
  /* encrypt sensitive */
  memcpy(key, tpmData.permanent.data.daaKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, *enc, *enc, *enc_size);
  
  return 0;
}

static int decrypt_daa(BYTE *iv, UINT32 iv_size, BYTE *enc, UINT32 enc_size, 
                       TPM_DAA_SENSITIVE *sensitive, BYTE **buf)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  
  /* decrypt sensitive */
  len = enc_size, *buf = ptr = tpm_malloc(len);
  if (ptr == NULL)
    return -1;
  memcpy(key, tpmData.permanent.data.daaKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, enc, ptr, enc_size);
  
  /* unmarshal sensitive */
  if (tpm_unmarshal_TPM_DAA_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*buf);
    return -1;
  }
  
  return 0;
}

/* Computation of the HMAC which protects the integrity of the TPM_DAA_BLOB */
static int compute_daa_digest(TPM_DAA_BLOB *daaBlob, TPM_DIGEST *digest)
{
  BYTE *buf, *ptr;
  UINT32 len;
  tpm_hmac_ctx_t hmac_ctx;
  
  len = sizeof_TPM_DAA_BLOB((*daaBlob));
  buf = ptr = tpm_malloc(len);
  if (buf == NULL)
    return -1;
  if (tpm_marshal_TPM_DAA_BLOB(&ptr, &len, daaBlob)) {
    tpm_free(buf);
    return -1;
  }
  memset(&buf[22], 0, sizeof(TPM_DIGEST));
  tpm_hmac_init(&hmac_ctx, tpmData.permanent.data.daaProof.nonce,
    sizeof(tpmData.permanent.data.daaProof.nonce));
  tpm_hmac_update(&hmac_ctx, buf, sizeof_TPM_DAA_BLOB((*daaBlob)));
  tpm_hmac_final(&hmac_ctx, digest->digest);
  tpm_free(buf);
  return 0;
}

/*
 * DAA commands ([TPM_Part3], Section 26)
 * Operations that are necessary to setup a TPM for DAA, execute the 
 * JOIN process, and execute the SIGN process.
 */

#define SCRATCH_SIZE 256

TPM_RESULT TPM_DAA_Join(TPM_HANDLE handle, BYTE stage, UINT32 inputSize0,
                        BYTE *inputData0, UINT32 inputSize1,
                        BYTE *inputData1, TPM_AUTH *auth1,
                        TPM_COMMAND_CODE *ordinal, UINT32 *outputSize,
                        BYTE **outputData)
{
  BYTE scratch[SCRATCH_SIZE];
  TPM_DAA_SESSION_DATA *session = NULL;
  
  TPM_RESULT res;
  UINT32 cnt, len;
  tpm_sha1_ctx_t sha1;
  tpm_rsa_public_key_t key;
  BYTE *signedData = NULL, *signatureValue = NULL, *DAA_generic_gamma = NULL,
    *DAA_generic_R0 = NULL, *DAA_generic_R1 = NULL, *DAA_generic_n = NULL,
    *DAA_generic_S0 = NULL, *DAA_generic_S1 = NULL, *ptr;
  tpm_bn_t X, Y, Z, n, f, q, f0, f1, w1, w, gamma, r0, r1, r2, r3, r, s0, s1, 
    s12, s2, s3, E, E1, u2, u3, v0, v10, v1, tmp;
  size_t size;
  BYTE mgf1_seed[2 + sizeof(TPM_DIGEST)];
  TPM_DAA_BLOB blob;
  TPM_DAA_SENSITIVE sensitive;
  
  info("TPM_DAA_Join()");
  debug("handle = %.8x, stage = %d", handle, stage);
  debug("stany.data.currentDAA = %.8x", tpmData.stany.data.currentDAA);
  
  /* Initalize internal scratch pad */
  memset(scratch, 0, SCRATCH_SIZE);
  
  /* Verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  
  /* Verify and initalize the session, for all stages greater than zero. */
  if (stage > 0) {
    if ((HANDLE_TO_INDEX(handle) >= TPM_MAX_SESSIONS_DAA) ||
      (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].type != 
        TPM_ST_DAA) ||
      (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].handle != 
      handle)) {
        /* Probe, whether the handle from stany.data.currentDAA is valid. */
        handle = tpmData.stany.data.currentDAA;
        if ((HANDLE_TO_INDEX(handle) >= TPM_MAX_SESSIONS_DAA) ||
          (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].type != 
            TPM_ST_DAA) ||
          (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].handle != 
            handle))
              return TPM_BAD_HANDLE;
    }
    session = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)];
  }
  
  /* TPM_DAA_JOIN [TPM_Part3], Section 26.1, Rev. 85 */
  switch (stage) {
    case 0:
    {
      /* Determine that sufficient resources are available to perform a
       * DAA_Join. Assign session handle for this DAA_Join. */
      handle = tpm_get_free_daa_session();
      if (handle == TPM_INVALID_HANDLE)
        return TPM_RESOURCES;
      session = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)];
      /* Set all fields in DAA_issuerSettings = NULL */
      memset(&session->DAA_issuerSettings, 0, sizeof(TPM_DAA_ISSUER));
      session->DAA_issuerSettings.tag = TPM_TAG_DAA_ISSUER;
      /* Set all fields in DAA_tpmSpecific = NULL */
      memset(&session->DAA_tpmSpecific, 0, sizeof(TPM_DAA_TPM));
      session->DAA_tpmSpecific.tag = TPM_TAG_DAA_TPM;
      /* Set all fields in DAA_session = NULL */
      memset(&session->DAA_session, 0, sizeof(TPM_DAA_CONTEXT));
      session->DAA_session.tag = TPM_TAG_DAA_CONTEXT;
      /* Set all fields in DAA_joinSession = NULL */
      memset(&session->DAA_joinSession, 0, sizeof(TPM_DAA_JOINDATA));
      /* Verify that sizeOf(inputData0) == sizeOf(DAA_tpmSpecific->DAA_count)
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(session->DAA_tpmSpecific.DAA_count)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Verify that inputData0 > 0, and return TPM_DAA_INPUT_DATA0 on
       * mismatch */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_UINT32(&ptr, &len, &cnt) || (len != 0)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if (cnt <= 0) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_tpmSpecific->DAA_count = inputData0 */
      debug("TPM_DAA_Join() -- set DAA_count := %d", cnt);
      session->DAA_tpmSpecific.DAA_count = cnt;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific ||
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session, &sha1);
      /* Set DAA_session->DAA_stage = 1 */
      session->DAA_session.DAA_stage = 1;
      /* Assign session handle for DAA_Join */
      tpmData.stany.data.currentDAA = handle;
      debug("TPM_DAA_Join() -- set handle := %.8x", handle);
      /* Set outputData = new session handle */
      *outputSize = sizeof(TPM_HANDLE);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL) {
        ptr = *outputData, len = *outputSize;
        if (tpm_marshal_TPM_HANDLE(&ptr, &len, handle)) {
          debug("TPM_DAA_Join(): tpm_marshal_TPM_HANDLE() failed.");
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_FAIL;
        }
      } else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 1:
    {
      /* Verify that DAA_session->DAA_stage == 1. Return TPM_DAA_STAGE
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 1) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify that sizeOf(inputData0) == DAA_SIZE_issuerModulus and
       * return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != DAA_SIZE_issuerModulus) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* If DAA_session->DAA_scratch == NULL: */
      if (!memcmp(scratch, session->DAA_session.DAA_scratch, 
        sizeof(session->DAA_session.DAA_scratch))) {
          /* Set DAA_session->DAA_scratch = inputData0 */
          memset(session->DAA_session.DAA_scratch, 0, 
            sizeof(session->DAA_session.DAA_scratch));
          memcpy(session->DAA_session.DAA_scratch, inputData0, inputSize0);
          /* Set DAA_joinSession->DAA_digest_n0 = 
           * SHA-1(DAA_session->DAA_scratch) */
          tpm_sha1_init(&sha1);
          tpm_sha1_update(&sha1, session->DAA_session.DAA_scratch, 
            sizeof(session->DAA_session.DAA_scratch));
          tpm_sha1_final(&sha1, (BYTE*) &session->DAA_joinSession.DAA_digest_n0);
          /* Set DAA_tpmSpecific->DAA_rekey = SHA-1(TPM_DAA_TPM_SEED || 
           * DAA_joinSession->DAA_digest_n0) */
          tpm_sha1_init(&sha1);
          tpm_sha1_update(&sha1, (BYTE*) &tpmData.permanent.data.tpmDAASeed, 
            sizeof(tpmData.permanent.data.tpmDAASeed));
          tpm_sha1_update(&sha1, (BYTE*) &session->DAA_joinSession.DAA_digest_n0, 
            sizeof(session->DAA_joinSession.DAA_digest_n0));
          tpm_sha1_final(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey);
      /* Else (If DAA_session->DAA_scratch != NULL): */
      } else {
        /* Set signedData = inputData0 */
        signedData = inputData0;
        /* Verify that sizeOf(inputData1) == DAA_SIZE_issuerModulus and 
         * return error TPM_DAA_INPUT_DATA1 on mismatch */
        if (inputSize1 != DAA_SIZE_issuerModulus) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
        }
        /* Set signatureValue = inputData1 */
        signatureValue = inputData1;
        /* Use the RSA key == [DAA_session->DAA_scratch] to verify that 
         * signatureValue is a signature on signedData, and return error 
         * TPM_DAA_ISSUER_VALIDITY on mismatch */
        if (tpm_rsa_import_public_key(&key, RSA_MSB_FIRST, 
          session->DAA_session.DAA_scratch, DAA_SIZE_issuerModulus, NULL, 0)) {
            memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
            return TPM_DAA_ISSUER_VALIDITY;
        }
        if (tpm_rsa_verify(&key, RSA_SSA_PKCS1_SHA1, signedData, inputSize0, 
          signatureValue)) {
            memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
            return TPM_DAA_ISSUER_VALIDITY;
        }
        tpm_rsa_release_public_key(&key);
        /* Set DAA_session->DAA_scratch = signedData */
        memset(session->DAA_session.DAA_scratch, 0, 
          sizeof(session->DAA_session.DAA_scratch));
        memcpy(session->DAA_session.DAA_scratch, inputData0, inputSize0);
      }
      /* Decrement DAA_tpmSpecific->DAA_count by 1 (unity) */
      session->DAA_tpmSpecific.DAA_count--;
      /* If DAA_tpmSpecific->DAA_count == 0: */
      if (session->DAA_tpmSpecific.DAA_count == 0) {
        /* Increment DAA_Session->DAA_stage by 1 */
        session->DAA_session.DAA_stage++;
      }
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session, &sha1);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 2:
    {
      /* Verify that DAA_session->DAA_stage == 2. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 2) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify that sizeOf(inputData0) == sizeOf(TPM_DAA_ISSUER) and 
       * return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(TPM_DAA_ISSUER)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_issuerSettings = inputData0. Verify that all fields in 
       * DAA_issuerSettings are present and return error
       * TPM_DAA_INPUT_DATA0 if not. */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_TPM_DAA_ISSUER(&ptr, &len, 
        &session->DAA_issuerSettings) || (len != 0) || 
        !(session->DAA_issuerSettings.tag == TPM_TAG_DAA_ISSUER)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Verify that sizeOf(inputData1) == DAA_SIZE_issuerModulus and 
       * return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (inputSize1 != DAA_SIZE_issuerModulus) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA1;
      }
      /* Set signatureValue = inputData1 */
      signatureValue = inputData1;
      /* Set signedData = (DAA_joinSession->DAA_digest_n0 || 
       * DAA_issuerSettings) */
      memcpy(scratch, &session->DAA_joinSession.DAA_digest_n0, 
        sizeof(TPM_DIGEST));
      memcpy(scratch + sizeof(TPM_DIGEST), inputData0, inputSize0);
      signedData = scratch;
      /* Use the RSA key [DAA_session->DAA_scratch] to verify that 
       * signatureValue is a signature on signedData, and return error 
       * TPM_DAA_ISSUER_VALIDITY on mismatch */
      if (tpm_rsa_import_public_key(&key, RSA_MSB_FIRST, 
        session->DAA_session.DAA_scratch, DAA_SIZE_issuerModulus, NULL, 0)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_ISSUER_VALIDITY;
      }
      if (tpm_rsa_verify(&key, RSA_SSA_PKCS1_SHA1, signedData, 
        sizeof(TPM_DIGEST) + inputSize0, signatureValue)) {
          tpm_rsa_release_public_key(&key);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_ISSUER_VALIDITY;
      }
      tpm_rsa_release_public_key(&key);
      /* Set DAA_tpmSpecific->DAA_digestIssuer == SHA-1(DAA_issuerSettings) */
      tpm_daa_update_digestIssuer(session, &sha1);
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session, &sha1);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = NULL */
      *outputSize = 0;
      *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 3:
    {
      /* Verify that DAA_session->DAA_stage == 3. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 3) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify that sizeOf(inputData0) == sizeOf(DAA_tpmSpecific->DAA_count)
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(session->DAA_tpmSpecific.DAA_count)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_tpmSpecific->DAA_count = inputData0 */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_UINT32(&ptr, &len, 
        &session->DAA_tpmSpecific.DAA_count) || (len != 0)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Obtain random data from the RNG and store it as 
       * DAA_joinSession->DAA_join_u0 */
      tpm_get_random_bytes(session->DAA_joinSession.DAA_join_u0, 
        sizeof(session->DAA_joinSession.DAA_join_u0));
      /* Obtain random data from the RNG and store it as 
       * DAA_joinSession->DAA_join_u1 */
      tpm_get_random_bytes(session->DAA_joinSession.DAA_join_u1, 
        sizeof(session->DAA_joinSession.DAA_join_u1));
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session, &sha1);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 4:
    {
      /* Verify that DAA_session->DAA_stage == 4. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 4) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_R0 = inputData0 */
      DAA_generic_R0 = inputData0;
      /* Verify that SHA-1(DAA_generic_R0) == 
       * DAA_issuerSettings->DAA_digest_R0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R0, 
        DAA_generic_R0, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Set X = DAA_generic_R0 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_R0);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Set f0  = f mod 2^DAA_power0 (erase all but the lowest DAA_power0 
       * bits of f) */
      tpm_bn_init(f0), tpm_bn_init(tmp);
      tpm_bn_ui_pow_ui(tmp, 2, DAA_power0);
      tpm_bn_mod(f0, f, tmp);
      /* Set DAA_session->DAA_scratch = (X^f0) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_powm(tmp, X, f0, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(f0), tpm_bn_clear(tmp);
      tpm_bn_clear(X), tpm_bn_clear(n);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 5:
    {
      /* Verify that DAA_session->DAA_stage == 5. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 5) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_R1 = inputData0 */
      DAA_generic_R1 = inputData0;
      /* Verify that SHA-1(DAA_generic_R1) == 
       * DAA_issuerSettings->DAA_digest_R1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R1, 
        DAA_generic_R1, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Set X = DAA_generic_R1 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_R1);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Shift f right by DAA_power0 bits (discard the lowest DAA_power0 
       * bits) and label the result f1 */
      tpm_bn_init(f1);
      tpm_bn_fdiv_q_2exp(f1, f, DAA_power0);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^f1) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, f1, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(f1), tpm_bn_clear(tmp);
      tpm_bn_clear(X), tpm_bn_clear(n), tpm_bn_clear(Z);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 6:
    {
      /* Verify that DAA_session->DAA_stage == 6. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 6) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_S0 = inputData0 */
      DAA_generic_S0 = inputData0;
      /* Verify that SHA-1(DAA_generic_S0) == 
       * DAA_issuerSettings->DAA_digest_S0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S0, 
        DAA_generic_S0, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Set X = DAA_generic_S0 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_S0);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set Y = DAA_joinSession->DAA_join_u0 */
      tpm_bn_init(Y);
      tpm_bn_import(Y, sizeof(session->DAA_joinSession.DAA_join_u0), 1, 
        session->DAA_joinSession.DAA_join_u0);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 7:
    {
      /* Verify that DAA_session->DAA_stage == 7. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 7) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_S1 = inputData0 */
      DAA_generic_S1 = inputData0;
      /* Verify that SHA-1(DAA_generic_S1) == 
       * DAA_issuerSettings->DAA_digest_S1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S1, 
        DAA_generic_S1, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Set X = DAA_generic_S1 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_S1);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Y = DAA_joinSession->DAA_join_u1 */
      tpm_bn_init(Y);
      tpm_bn_import(Y, sizeof(session->DAA_joinSession.DAA_join_u1), 1, 
        session->DAA_joinSession.DAA_join_u1);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, &size, 1, tmp);
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch + 
        (sizeof(session->DAA_session.DAA_scratch) - size),
        &size, 1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set DAA_session->DAA_digest to the SHA-1(DAA_session->DAA_scratch || 
       * DAA_tpmSpecific->DAA_count || DAA_joinSession->DAA_digest_n0) */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, session->DAA_session.DAA_scratch, 
        sizeof(session->DAA_session.DAA_scratch));
      ptr = scratch, len = sizeof(scratch);
      if (tpm_marshal_UINT32(&ptr, &len, session->DAA_tpmSpecific.DAA_count)) {
        debug("TPM_DAA_Join(): tpm_marshal_UINT32() failed.");
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_FAIL;
      }
      tpm_sha1_update(&sha1, scratch, sizeof(UINT32));
      tpm_sha1_update(&sha1, session->DAA_joinSession.DAA_digest_n0.digest, 
        sizeof(session->DAA_joinSession.DAA_digest_n0.digest));
      tpm_sha1_final(&sha1, session->DAA_session.DAA_digest.digest);
      /* Set outputData = DAA_session->DAA_scratch */
      *outputSize = sizeof(session->DAA_session.DAA_scratch);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL) {
        memcpy(*outputData, session->DAA_session.DAA_scratch, *outputSize);
      } else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 8:
    {
      /* Verify that DAA_session->DAA_stage == 8. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 8) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify inputSize0 == DAA_SIZE_NE and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != DAA_SIZE_NE) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set NE = decrypt(inputData0, privEK) */
      memset(scratch, 0, sizeof(scratch));
      if (tpm_rsa_decrypt(&tpmData.permanent.data.endorsementKey, 
        RSA_ES_OAEP_SHA1, inputData0, inputSize0, scratch, &size)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DECRYPT_ERROR;
      }
      /* Set outputData = SHA-1(DAA_session->DAA_digest || NE) */
      *outputSize = SHA1_DIGEST_LENGTH;
      if ((*outputData = tpm_malloc(*outputSize)) == NULL) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, session->DAA_session.DAA_digest.digest, 
        sizeof(session->DAA_session.DAA_digest.digest));
      tpm_sha1_update(&sha1, scratch, size);
      tpm_sha1_final(&sha1, *outputData);
      /* Set DAA_session->DAA_digest = NULL */
      memset(&session->DAA_session.DAA_digest, 0, 
        sizeof(session->DAA_session.DAA_digest));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 9:
    {
      /* Verify that DAA_session->DAA_stage == 9. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 9) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_R0 = inputData0 */
      DAA_generic_R0 = inputData0;
      /* Verify that SHA-1(DAA_generic_R0) == 
       * DAA_issuerSettings->DAA_digest_R0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R0, 
        DAA_generic_R0, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain random data from the RNG and store it as 
       * DAA_session->DAA_contextSeed */
      tpm_get_random_bytes(session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r0, 1, scratch);
      /* Set X = DAA_generic_R0 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_R0);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set DAA_session->DAA_scratch = (X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 10:
    {
      /* Verify that DAA_session->DAA_stage == 10. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 10) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_R1 = inputData0 */
      DAA_generic_R1 = inputData0;
      /* Verify that SHA-1(DAA_generic_R1) == 
       * DAA_issuerSettings->DAA_digest_R1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R1, 
        DAA_generic_R1, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r1, 1, scratch);
      /* Set X = DAA_generic_R1 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_R1);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 11:
    {
      /* Verify that DAA_session->DAA_stage == 11. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 11) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_S0 = inputData0 */
      DAA_generic_S0 = inputData0;
      /* Verify that SHA-1(DAA_generic_S0) == 
       * DAA_issuerSettings->DAA_digest_S0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S0, 
        DAA_generic_S0, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r2, 1, scratch);
      /* Set X = DAA_generic_S0 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_S0);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 12:
    {
      /* Verify that DAA_session->DAA_stage == 12. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 12) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_S1 = inputData0 */
      DAA_generic_S1 = inputData0;
      /* Verify that SHA-1(DAA_generic_S1) == 
       * DAA_issuerSettings->DAA_digest_S1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S1, 
        DAA_generic_S1, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r3 bits from MGF1("r3", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r3", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r3);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r3, 1, scratch);
      /* Set X = DAA_generic_S1 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_S1);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, &size, 1, tmp);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = DAA_session->DAA_scratch */
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, session->DAA_session.DAA_scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 13:
    {
      /* Verify that DAA_session->DAA_stage == 13. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 13) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Verify that inputSize1 == DAA_SIZE_w and return error 
       * TPM_DAA_INPUT_DATA1 on mismatch */
      if (inputSize1 != DAA_SIZE_w) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA1;
      }
      /* Set w = inputData1 */
      tpm_bn_init(w);
      tpm_bn_import(w, inputSize1, 1, inputData1);
      /* Set w1 = w^(DAA_issuerSettings->DAA_generic_q) mod 
       * (DAA_generic_gamma) */
      tpm_bn_init(gamma);
      tpm_bn_import(gamma, inputSize0, 1, DAA_generic_gamma);
      tpm_bn_init(q);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_init(w1);
      tpm_bn_powm(w1, w, q, gamma);
      /* If w1 != 1 (unity), return error TPM_DAA_WRONG_W */
      if (tpm_bn_cmp_ui(w1, 1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_WRONG_W;
      }
      /* Set DAA_session->DAA_scratch = w */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, w);
      tpm_bn_clear(w), tpm_bn_clear(gamma), tpm_bn_clear(w1), tpm_bn_clear(q);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 14:
    {
      /* Verify that DAA_session->DAA_stage == 14. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 14) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set f = SHA-1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0) || SHA-1(DAA_tpmSpecific->DAA_rekey 
       * || DAA_tpmSpecific->DAA_count || 1) mod 
       * DAA_issuerSettings->DAA_generic_q. */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Set E = ((DAA_session->DAA_scratch)^f) mod (DAA_generic_gamma).*/
      tpm_bn_init(gamma);
      tpm_bn_import(gamma, inputSize0, 1, DAA_generic_gamma);
      tpm_bn_init(w);
      tpm_bn_import(w, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      tpm_bn_init(E);
      tpm_bn_powm(E, w, f, gamma);
      /* Set outputData = E */
      tpm_bn_export(scratch, &size, 1, E);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(gamma), tpm_bn_clear(w), tpm_bn_clear(E);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 15:
    {
      /* Verify that DAA_session->DAA_stage == 15. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 15) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them r0 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      tpm_bn_init(r0);
      tpm_bn_import(r0, DAA_SIZE_r0, 1, scratch);
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them r1 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      tpm_bn_init(r1);
      tpm_bn_import(r1, DAA_SIZE_r1, 1, scratch);
      /* Set r = r0 + 2^DAA_power0 * r1 mod 
       * (DAA_issuerSettings->DAA_generic_q). */
      tpm_bn_init(q);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_init(r);
      tpm_bn_ui_pow_ui(r, 2, DAA_power0);
      tpm_bn_mul(r, r, r1);
      tpm_bn_mod(r, r, q);
      tpm_bn_add(r, r, r0);
      tpm_bn_mod(r, r, q);
      /* Set E1 = ((DAA_session->DAA_scratch)^r) mod (DAA_generic_gamma). */
      tpm_bn_init(gamma);
      tpm_bn_import(gamma, inputSize0, 1, DAA_generic_gamma);
      tpm_bn_init(w);
      tpm_bn_import(w, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      tpm_bn_init(E1);
      tpm_bn_powm(E1, w, r, gamma);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = E1 */
      tpm_bn_export(scratch, &size, 1, E1);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r0), tpm_bn_clear(r1), tpm_bn_clear(q), tpm_bn_clear(r);
      tpm_bn_clear(gamma), tpm_bn_clear(w), tpm_bn_clear(E1);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 16:
    {
      BYTE *NT = NULL;
      
      /* Verify that DAA_session->DAA_stage == 16. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 16) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify that inputSize0 == sizeOf(TPM_DIGEST) and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(TPM_DIGEST)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_session->DAA_digest = inputData0 */
      memcpy(session->DAA_session.DAA_digest.digest, inputData0, inputSize0);
      /* Obtain DAA_SIZE_NT bits from the RNG and label them NT */
      if ((NT = tpm_malloc(DAA_SIZE_NT)) == NULL) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      tpm_get_random_bytes(NT, DAA_SIZE_NT);
      /* Set DAA_session->DAA_digest to the SHA-1(DAA_session->DAA_digest || 
       * NT)*/
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) session->DAA_session.DAA_digest.digest, 
          sizeof(session->DAA_session.DAA_digest.digest));
      tpm_sha1_update(&sha1, NT, DAA_SIZE_NT);
      tpm_sha1_final(&sha1, session->DAA_session.DAA_digest.digest);
      /* Set outputData = NT */
      *outputSize = DAA_SIZE_NT;
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, NT, *outputSize);
      else {
        tpm_free(NT);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      tpm_free(NT);
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 17:
    {
      /* Verify that DAA_session->DAA_stage == 17. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 17) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them r0 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      tpm_bn_init(r0);
      tpm_bn_import(r0, DAA_SIZE_r0, 1, scratch);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Set f0 = f mod 2^DAA_power0 (erase all but the lowest DAA_power0 
       * bits of f) */
      tpm_bn_init(f0);
      tpm_bn_init(tmp);
      tpm_bn_ui_pow_ui(tmp, 2, DAA_power0);
      tpm_bn_mod(f0, f, tmp);
      /* Set s0 = r0 + (DAA_session->DAA_digest) * f0 in Z */
      tpm_bn_init(s0);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s0, tmp, f0);
      tpm_bn_add(s0, r0, s0);
      /* Set outputData = s0 */
      tpm_bn_export(scratch, &size, 1, s0);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r0), tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(f0);
      tpm_bn_clear(s0), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 18:
    {
      /* Verify that DAA_session->DAA_stage == 18. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 18) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them r1 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      tpm_bn_init(r1);
      tpm_bn_import(r1, DAA_SIZE_r1, 1, scratch);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Shift f right by DAA_power0 bits (discard the lowest DAA_power0 
       * bits) and label the result f1 */
      tpm_bn_init(f1);
      tpm_bn_fdiv_q_2exp(f1, f, DAA_power0);
      /* Set s1 = r1 + (DAA_session->DAA_digest) * f1 in Z */
      tpm_bn_init(s1);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s1, tmp, f1);
      tpm_bn_add(s1, r1, s1);
      /* Set outputData = s1 */
      tpm_bn_export(scratch, &size, 1, s1);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r1), tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(f1);
      tpm_bn_clear(s1), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 19:
    {
      /* Verify that DAA_session->DAA_stage == 19. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 19) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them r2 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      tpm_bn_init(r2);
      tpm_bn_import(r2, DAA_SIZE_r2, 1, scratch);
      /* Set s2 = r2 + (DAA_session->DAA_digest) * 
       * (DAA_joinSession->DAA_join_u0) mod 2^DAA_power1 
       * (Erase all but the lowest DAA_power1 bits of s2) */
      tpm_bn_init(s2);
      tpm_bn_import(s2, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, session->DAA_joinSession.DAA_join_u0);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s2, tmp, s2);
      tpm_bn_add(s2, r2, s2);
      tpm_bn_ui_pow_ui(tmp, 2, DAA_power1);
      tpm_bn_mod(s2, s2, tmp);
      /* Set DAA_session->DAA_scratch = s2 */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, s2);
      /* Set outputData = s2 */
      tpm_bn_export(scratch, &size, 1, s2);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r2), tpm_bn_clear(s2), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 20:
    {
      /* Verify that DAA_session->DAA_stage == 20. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 20) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them r2 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      tpm_bn_init(r2);
      tpm_bn_import(r2, DAA_SIZE_r2, 1, scratch);
      /* Set s12 = r2 + (DAA_session->DAA_digest) * 
       * (DAA_joinSession->DAA_join_u0) */
      tpm_bn_init(s12);
      tpm_bn_import(s12, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, session->DAA_joinSession.DAA_join_u0);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s12, tmp, s12);
      tpm_bn_add(s12, r2, s12);
      /* Shift s12 right by DAA_power1 bit (discard the lowest DAA_power1 
       * bits). */
      tpm_bn_fdiv_q_2exp(s12, s12, DAA_power1);
      /* Set DAA_session->DAA_scratch = s12 */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, s12);
      tpm_bn_clear(r2), tpm_bn_clear(s12), tpm_bn_clear(tmp);
      /* Set outputData = DAA_session->DAA_digest */
      *outputSize = sizeof(session->DAA_session.DAA_digest.digest);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, session->DAA_session.DAA_digest.digest, 
          *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 21:
    {
      /* Verify that DAA_session->DAA_stage == 21. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 21) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r3 bits from MGF1("r3", 
       * DAA_session->DAA_contextSeed), and label them r3 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r3", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r3);
      tpm_bn_init(r3);
      tpm_bn_import(r3, DAA_SIZE_r3, 1, scratch);
      /* Set s3 = r3 + (DAA_session->DAA_digest) * 
       * (DAA_joinSession->DAA_join_u1) + (DAA_session->DAA_scratch). */
      tpm_bn_init(s3);
      tpm_bn_import(s3, sizeof(session->DAA_joinSession.DAA_join_u1), 
        1, session->DAA_joinSession.DAA_join_u1);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s3, tmp, s3);
      tpm_bn_add(s3, r3, s3);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_scratch), 
        -1, session->DAA_session.DAA_scratch);
      tpm_bn_add(s3, s3, tmp);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = s3 */
      tpm_bn_export(scratch, &size, 1, s3);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r3), tpm_bn_clear(s3), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 22:
    {
      /* Verify that DAA_session->DAA_stage == 22. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 22) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify inputSize0 == DAA_SIZE_v0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != DAA_SIZE_v0) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set u2 = inputData0 */
      tpm_bn_init(u2);
      tpm_bn_import(u2, DAA_SIZE_v0, 1, inputData0);
      /* Set v0 = u2 + (DAA_joinSession->DAA_join_u0) mod 2^DAA_power1 
       * (Erase all but the lowest DAA_power1 bits of v0). */
      tpm_bn_init(v0);
      tpm_bn_import(v0, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, session->DAA_joinSession.DAA_join_u0);
      tpm_bn_add(v0, u2, v0);
      tpm_bn_init(tmp);
      tpm_bn_ui_pow_ui(tmp, 2, DAA_power1);
      tpm_bn_mod(v0, v0, tmp);
      /* Set DAA_tpmSpecific->DAA_digest_v0 = SHA-1(v0) */
      tpm_bn_export(scratch, &size, 1, v0);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) scratch, size);
      tpm_sha1_final(&sha1, session->DAA_tpmSpecific.DAA_digest_v0.digest);
      /* Set v10 = u2 + (DAA_joinSession->DAA_join_u0) in Z */
      tpm_bn_init(v10);
      tpm_bn_import(v10, sizeof(session->DAA_joinSession.DAA_join_u0), 
        1, session->DAA_joinSession.DAA_join_u0);
      tpm_bn_add(v10, u2, v10);
      /* Shift v10 right by DAA_power1 bits (erase the lowest DAA_power1 
       * bits). */
      tpm_bn_fdiv_q_2exp(v10, v10, DAA_power1);
      /* Set DAA_session->DAA_scratch = v10 */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, v10);
      tpm_bn_clear(u2), tpm_bn_clear(v0), tpm_bn_clear(tmp), tpm_bn_clear(v10);
      /* Set outputData */
        memset(&blob, 0, sizeof(blob));
        /* Fill in TPM_DAA_BLOB with a type of TPM_RT_DAA_V0 and encrypt 
         * the v0 parameters */
        blob.tag = TPM_TAG_DAA_BLOB;
        blob.resourceType = TPM_RT_DAA_V0;
        memset(blob.label, 0, sizeof(blob.label));
        memset(&blob.blobIntegrity, 0, sizeof(TPM_DIGEST));
        blob.additionalSize = TPM_SYM_KEY_SIZE;
        blob.additionalData = tpm_malloc(blob.additionalSize);
        if (blob.additionalData == NULL) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_NOSPACE;
        }
        tpm_get_random_bytes(blob.additionalData, blob.additionalSize);
        sensitive.tag = TPM_TAG_DAA_SENSITIVE;
        sensitive.internalSize = size;
        sensitive.internalData = scratch;
        if (encrypt_daa(blob.additionalData, blob.additionalSize,
          &sensitive, &blob.sensitiveData, &blob.sensitiveSize)) {
            tpm_free(blob.additionalData);
            memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
            return TPM_ENCRYPT_ERROR;
        }
        if (compute_daa_digest(&blob, &blob.blobIntegrity)) {
          debug("TPM_DAA_Join(): compute_daa_digest() failed.");
          tpm_free(blob.sensitiveData);
          tpm_free(blob.additionalData);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_FAIL;
        }
        /* Set outputData to the encrypted TPM_DAA_BLOB */
        *outputSize = sizeof_TPM_DAA_BLOB(blob);
        if ((*outputData = tpm_malloc(*outputSize)) == NULL) {
          tpm_free(blob.sensitiveData);
          tpm_free(blob.additionalData);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_NOSPACE;
        }
        len = *outputSize;
        ptr = *outputData;
        if (tpm_marshal_TPM_DAA_BLOB(&ptr, &len, &blob)) {
          debug("TPM_DAA_Join(): tpm_marshal_TPM_DAA_BLOB() failed.");
          tpm_free(blob.sensitiveData);
          tpm_free(blob.additionalData);
          tpm_free(*outputData);
          *outputSize = 0;
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_FAIL;
        }
        tpm_free(blob.sensitiveData);
        tpm_free(blob.additionalData);
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session, &sha1);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 23:
    {
      /* Verify that DAA_session->DAA_stage == 23. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 23) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify inputSize0 == DAA_SIZE_v1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != DAA_SIZE_v1) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set u3 = inputData0 */
      tpm_bn_init(u3);
      tpm_bn_import(u3, DAA_SIZE_v1, 1, inputData0);
      /* Set v1 = u3 + DAA_joinSession->DAA_join_u1 + 
       * DAA_session->DAA_scratch */
      tpm_bn_init(v1);
      tpm_bn_import(v1, sizeof(session->DAA_joinSession.DAA_join_u1), 
        1, session->DAA_joinSession.DAA_join_u1);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_scratch), 
        -1, session->DAA_session.DAA_scratch);
      tpm_bn_add(v1, v1, tmp);
      tpm_bn_add(v1, u3, v1);
      /* Set DAA_tpmSpecific->DAA_digest_v1 = SHA-1(v1) */
      tpm_bn_export(scratch, &size, 1, v1);
      tpm_bn_clear(u3), tpm_bn_clear(v1), tpm_bn_clear(tmp);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) scratch, size);
      tpm_sha1_final(&sha1, session->DAA_tpmSpecific.DAA_digest_v1.digest);
      /* Set outputData */
        memset(&blob, 0, sizeof(blob));
        /* Fill in TPM_DAA_BLOB with a type of TPM_RT_DAA_V1 and encrypt 
         * the v1 parameters */
        blob.tag = TPM_TAG_DAA_BLOB;
        blob.resourceType = TPM_RT_DAA_V1;
        memset(blob.label, 0, sizeof(blob.label));
        memset(&blob.blobIntegrity, 0, sizeof(TPM_DIGEST));
        blob.additionalSize = TPM_SYM_KEY_SIZE;
        blob.additionalData = tpm_malloc(blob.additionalSize);
        if (blob.additionalData == NULL) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_NOSPACE;
        }
        tpm_get_random_bytes(blob.additionalData, blob.additionalSize);
        sensitive.tag = TPM_TAG_DAA_SENSITIVE;
        sensitive.internalSize = size;
        sensitive.internalData = scratch;
        if (encrypt_daa(blob.additionalData, blob.additionalSize,
          &sensitive, &blob.sensitiveData, &blob.sensitiveSize)) {
            tpm_free(blob.additionalData);
            memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
            return TPM_ENCRYPT_ERROR;
        }
        if (compute_daa_digest(&blob, &blob.blobIntegrity)) {
          debug("TPM_DAA_Join(): compute_daa_digest() failed.");
          tpm_free(blob.sensitiveData);
          tpm_free(blob.additionalData);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_FAIL;
        }
        /* Set outputData to the encrypted TPM_DAA_BLOB */
        *outputSize = sizeof_TPM_DAA_BLOB(blob);
        if ((*outputData = tpm_malloc(*outputSize)) == NULL) {
          tpm_free(blob.sensitiveData);
          tpm_free(blob.additionalData);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_NOSPACE;
        }
        len = *outputSize;
        ptr = *outputData;
        if (tpm_marshal_TPM_DAA_BLOB(&ptr, &len, &blob)) {
          debug("TPM_DAA_Join(): tpm_marshal_TPM_DAA_BLOB() failed.");
          tpm_free(blob.sensitiveData);
          tpm_free(blob.additionalData);
          tpm_free(*outputData);
          *outputSize = 0;
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_FAIL;
        }
        tpm_free(blob.sensitiveData);
        tpm_free(blob.additionalData);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific || 
       * DAA_joinSession) */
      tpm_daa_update_digestContext(session, &sha1);
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 24:
    {
      /* Verify that DAA_session->DAA_stage == 24. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 24) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == 
       * SHA-1(DAA_tpmSpecific || DAA_joinSession) and return error 
       * TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set outputData = enc(DAA_tpmSpecific) */
      memset(&blob, 0, sizeof(blob));
      blob.tag = TPM_TAG_DAA_BLOB;
      blob.resourceType = TPM_RT_DAA_TPM;
      memcpy(blob.label, "DAA_tpmSpecific", 15);
      memset(&blob.blobIntegrity, 0, sizeof(TPM_DIGEST));
      blob.additionalSize = TPM_SYM_KEY_SIZE;
      blob.additionalData = tpm_malloc(blob.additionalSize);
      if (blob.additionalData == NULL) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      tpm_get_random_bytes(blob.additionalData, blob.additionalSize);
      sensitive.tag = TPM_TAG_DAA_SENSITIVE;
      sensitive.internalSize = len = sizeof(TPM_DAA_TPM);
      sensitive.internalData = ptr = tpm_malloc(sensitive.internalSize);
      if (sensitive.internalData == NULL) {
        tpm_free(blob.additionalData);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      if (tpm_marshal_TPM_DAA_TPM(&ptr, &len, &session->DAA_tpmSpecific)) {
        debug("TPM_DAA_Join(): tpm_marshal_TPM_DAA_TPM() failed.");
        tpm_free(blob.additionalData);
        tpm_free(sensitive.internalData);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_FAIL;
      }
      if (encrypt_daa(blob.additionalData, blob.additionalSize,
        &sensitive, &blob.sensitiveData, &blob.sensitiveSize)) {
          tpm_free(blob.additionalData);
          tpm_free(sensitive.internalData);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_ENCRYPT_ERROR;
      }
      if (compute_daa_digest(&blob, &blob.blobIntegrity)) {
        debug("TPM_DAA_Join(): compute_daa_digest() failed.");
        tpm_free(blob.sensitiveData);
        tpm_free(sensitive.internalData);
        tpm_free(blob.additionalData);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_FAIL;
      }
      *outputSize = sizeof_TPM_DAA_BLOB(blob);
      if ((*outputData = tpm_malloc(*outputSize)) == NULL) {
        tpm_free(blob.sensitiveData);
        tpm_free(sensitive.internalData);
        tpm_free(blob.additionalData);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      len = *outputSize;
      ptr = *outputData;
      if (tpm_marshal_TPM_DAA_BLOB(&ptr, &len, &blob)) {
        debug("TPM_DAA_Join(): tpm_marshal_TPM_DAA_BLOB() failed.");
        tpm_free(blob.sensitiveData);
        tpm_free(sensitive.internalData);
        tpm_free(blob.additionalData);
        tpm_free(*outputData);
        *outputSize = 0;
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_FAIL;
      }
      tpm_free(blob.sensitiveData);
      tpm_free(sensitive.internalData);
      tpm_free(blob.additionalData);
      /* Terminate the DAA session and all resources assoociated with the
       * DAA sign session handle. */
      memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    default:
      return TPM_DAA_STAGE;
  }
}

TPM_RESULT TPM_DAA_Sign(TPM_HANDLE handle, BYTE stage, UINT32 inputSize0,
                        BYTE *inputData0, UINT32 inputSize1,
                        BYTE *inputData1, TPM_AUTH *auth1,
                        TPM_COMMAND_CODE *ordinal, UINT32 *outputSize,
                        BYTE **outputData)
{
  BYTE scratch[SCRATCH_SIZE];
  TPM_DAA_SESSION_DATA *session = NULL;
  
  TPM_RESULT res;
  tpm_sha1_ctx_t sha1;
  BYTE *ptr, *buf;
  UINT32 len;
  TPM_DAA_BLOB blob;
  TPM_DAA_SENSITIVE sensitive;
  TPM_DIGEST digest;
  BYTE *DAA_generic_R0 = NULL, *DAA_generic_R1 = NULL, *DAA_generic_n = NULL, 
    *DAA_generic_S0 = NULL, *DAA_generic_S1 = NULL, *DAA_generic_gamma = NULL;
  BYTE mgf1_seed[2 + sizeof(TPM_DIGEST)];
  tpm_bn_t X, Y, Z, n, w1, w, gamma, q, f, E, r0, r1, r, E1, f0, s0, f1, s1, 
    r2, s2, s12, r4, s3, tmp;
  BYTE selector;
  size_t size;
  TPM_KEY_DATA *aikData;
  TPM_KEY_HANDLE aikHandle;
  
  info("TPM_DAA_Sign()");
  debug("handle = %.8x, stage = %d", handle, stage);
  debug("stany.data.currentDAA = %.8x", tpmData.stany.data.currentDAA);
  
  /* Initalize internal scratch pad */
  memset(scratch, 0, SCRATCH_SIZE);
  
  /* Verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  
  /* Verify and initalize the session, for all stages greater than zero. */
  if (stage > 0) {
    if ((HANDLE_TO_INDEX(handle) >= TPM_MAX_SESSIONS_DAA) ||
      (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].type != 
        TPM_ST_DAA) ||
      (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].handle != 
      handle)) {
        /* Probe, whether the handle from stany.data.currentDAA is valid. */
        handle = tpmData.stany.data.currentDAA;
        if ((HANDLE_TO_INDEX(handle) >= TPM_MAX_SESSIONS_DAA) ||
          (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].type != 
            TPM_ST_DAA) ||
          (tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)].handle != 
            handle))
              return TPM_BAD_HANDLE;
    }
    session = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)];
  }
  
  /* TPM_DAA_SIGN [TPM_Part3], Section 26.2, Rev. 85 */
  switch (stage) {
    case 0:
    {
      /* Determine that sufficient resources are available to perform a 
       * DAA_Sign. Assign session handle for this DAA_Sign. */
      handle = tpm_get_free_daa_session();
      if (handle == TPM_INVALID_HANDLE)
        return TPM_RESOURCES;
      session = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(handle)];
      /* Verify that sizeOf(inputData0) == sizeOf(TPM_DAA_ISSUER)
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(TPM_DAA_ISSUER)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_issuerSettings = inputData0. */
      /* Verify that all fields in DAA_issuerSettings are present and 
       * return error TPM_DAA_INPUT_DATA0 if not. */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_TPM_DAA_ISSUER(&ptr, &len, 
        &session->DAA_issuerSettings) || (len != 0) || 
        (session->DAA_issuerSettings.tag != TPM_TAG_DAA_ISSUER)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set all fields in DAA_session = NULL */
      memset(&session->DAA_session, 0, sizeof(TPM_DAA_CONTEXT));
      /* Assign new handle for session */
      tpmData.stany.data.currentDAA = handle;
      debug("TPM_DAA_Sign() -- set handle := %.8x", handle);
      /* Set outputData to new handle */
      *outputSize = sizeof(TPM_HANDLE);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL) {
        ptr = *outputData, len = *outputSize;
        if (tpm_marshal_TPM_HANDLE(&ptr, &len, handle)) {
          debug("TPM_DAA_Sign(): tpm_marshal_TPM_HANDLE() failed.");
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_FAIL;
        }
      } else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Set DAA_session->DAA_stage = 1 */
      session->DAA_session.DAA_stage = 1;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 1:
    {
      /* Verify that DAA_session->DAA_stage == 1. Return TPM_DAA_STAGE and 
       * flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 1) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Set DAA_tpmSpecific = unwrap(inputData0) */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_TPM_DAA_BLOB(&ptr, &len, &blob) || (len != 0)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      sensitive.internalData = scratch;
      if (decrypt_daa(blob.additionalData, blob.additionalSize, 
        blob.sensitiveData, blob.sensitiveSize, &sensitive, &buf)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DECRYPT_ERROR;
      }
      if (compute_daa_digest(&blob, &digest) || 
        memcmp(&digest, &blob.blobIntegrity, sizeof(TPM_DIGEST))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((blob.resourceType != TPM_RT_DAA_TPM) || 
        (sensitive.tag != TPM_TAG_DAA_SENSITIVE || 
        (sensitive.internalSize != sizeof(TPM_DAA_TPM)))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if (tpm_unmarshal_TPM_DAA_TPM(&sensitive.internalData,
        &sensitive.internalSize, &session->DAA_tpmSpecific)) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      tpm_free(buf);
      
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Set DAA_session->DAA_digestContext = SHA-1(DAA_tpmSpecific) */
      tpm_daa_update_digestContext_sign(session, &sha1);
      /* Obtain random data from the RNG and store it as 
       * DAA_session->DAA_contextSeed */
      tpm_get_random_bytes(session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Set DAA_session->DAA_stage = 2 */
      session->DAA_session.DAA_stage = 2;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 2:
    {
      /* Verify that DAA_session->DAA_stage == 2. Return TPM_DAA_STAGE and 
       * flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 2) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_R0 = inputData0 */
      DAA_generic_R0 = inputData0;
      /* Verify that SHA-1(DAA_generic_R0) == 
       * DAA_issuerSettings->DAA_digest_R0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R0, 
        DAA_generic_R0, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r0, 1, scratch);
      /* Set X = DAA_generic_R0 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_R0);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set DAA_session->DAA_scratch = (X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 3:
    {
      /* Verify that DAA_session->DAA_stage == 3. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 3) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_R1 = inputData0 */
      DAA_generic_R1 = inputData0;
      /* Verify that SHA-1(DAA_generic_R1) == 
       * DAA_issuerSettings->DAA_digest_R1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_R1, 
        DAA_generic_R1, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r1, 1, scratch);
      /* Set X = DAA_generic_R1 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_R1);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 4:
    {
      /* Verify that DAA_session->DAA_stage == 4. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 4) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_S0 = inputData0 */
      DAA_generic_S0 = inputData0;
      /* Verify that SHA-1(DAA_generic_S0) == 
       * DAA_issuerSettings->DAA_digest_S0 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S0, 
        DAA_generic_S0, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r2, 1, scratch);
      /* Set X = DAA_generic_S0 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_S0);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, tmp);
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 5:
    {
      /* Verify that DAA_session->DAA_stage == 5. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 5) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_S1 = inputData0 */
      DAA_generic_S1 = inputData0;
      /* Verify that SHA-1(DAA_generic_S1) == 
       * DAA_issuerSettings->DAA_digest_S1 and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_S1, 
        DAA_generic_S1, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_generic_n = inputData1 */
      DAA_generic_n = inputData1;
      /* Verify that SHA-1(DAA_generic_n) == DAA_issuerSettings->DAA_digest_n 
       * and return error TPM_DAA_INPUT_DATA1 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_n, 
        DAA_generic_n, inputSize1, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
      }
      /* Obtain DAA_SIZE_r4 bits from MGF1("r4", 
       * DAA_session->DAA_contextSeed), and label them Y */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r4", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r4);
      tpm_bn_init(Y);
      tpm_bn_import(Y, DAA_SIZE_r4, 1, scratch);
      /* Set X = DAA_generic_S1 */
      tpm_bn_init(X);
      tpm_bn_import(X, inputSize0, 1, DAA_generic_S1);
      /* Set n = DAA_generic_n */
      tpm_bn_init(n);
      tpm_bn_import(n, inputSize1, 1, DAA_generic_n);
      /* Set Z = DAA_session->DAA_scratch */
      tpm_bn_init(Z);
      tpm_bn_import(Z, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      /* Set DAA_session->DAA_scratch = Z*(X^Y) mod n */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_init(tmp);
      tpm_bn_powm(tmp, X, Y, n);
      tpm_bn_mul(tmp, tmp, Z);
      tpm_bn_mod(tmp, tmp, n);
      tpm_bn_export(session->DAA_session.DAA_scratch, &size, 1, tmp);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(X), tpm_bn_clear(Y), tpm_bn_clear(Z), tpm_bn_clear(n), tpm_bn_clear(tmp);
      /* Set outputData = DAA_session->DAA_scratch */
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, session->DAA_session.DAA_scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 6:
    {
      /* Verify that DAA_session->DAA_stage == 6. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 6) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Verify that inputSize1 == DAA_SIZE_w and return error 
       * TPM_DAA_INPUT_DATA1 on mismatch */
      if (inputSize1 != DAA_SIZE_w) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA1;
      }
      /* Set w = inputData1 */
      tpm_bn_init(w);
      tpm_bn_import(w, inputSize1, 1, inputData1);
      /* Set w1 = w^(DAA_issuerSettings->DAA_generic_q) mod 
       * (DAA_generic_gamma) */
      tpm_bn_init(gamma);
      tpm_bn_import(gamma, inputSize0, 1, DAA_generic_gamma);
      tpm_bn_init(q);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_init(w1);
      tpm_bn_powm(w1, w, q, gamma);
      /* If w1 != 1 (unity), return error TPM_DAA_WRONG_W */
      if (tpm_bn_cmp_ui(w1, 1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_WRONG_W;
      }
      /* Set DAA_session->DAA_scratch = w */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, w);
      tpm_bn_clear(w), tpm_bn_clear(gamma), tpm_bn_clear(w1), tpm_bn_clear(q);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 7:
    {
      /* Verify that DAA_session->DAA_stage == 7. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 7) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Set f = SHA-1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0) || SHA-1(DAA_tpmSpecific->DAA_rekey 
       * || DAA_tpmSpecific->DAA_count || 1) mod 
       * DAA_issuerSettings->DAA_generic_q. */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Set E = ((DAA_session->DAA_scratch)^f) mod (DAA_generic_gamma).*/
      tpm_bn_init(gamma);
      tpm_bn_import(gamma, inputSize0, 1, DAA_generic_gamma);
      tpm_bn_init(w);
      tpm_bn_import(w, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      tpm_bn_init(E);
      tpm_bn_powm(E, w, f, gamma);
      /* Set outputData = E */
      tpm_bn_export(scratch, &size, 1, E);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(gamma), tpm_bn_clear(w), tpm_bn_clear(E);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 8:
    {
      /* Verify that DAA_session->DAA_stage == 8. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 8) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_generic_gamma = inputData0 */
      DAA_generic_gamma = inputData0;
      /* Verify that SHA-1(DAA_generic_gamma) == 
       * DAA_issuerSettings->DAA_digest_gamma and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (tpm_daa_verify_generic(session->DAA_issuerSettings.DAA_digest_gamma, 
        DAA_generic_gamma, inputSize0, &sha1)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them r0 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      tpm_bn_init(r0);
      tpm_bn_import(r0, DAA_SIZE_r0, 1, scratch);
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them r1 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      tpm_bn_init(r1);
      tpm_bn_import(r1, DAA_SIZE_r1, 1, scratch);
      /* Set r = r0 + 2^DAA_power0 * r1 mod 
       * (DAA_issuerSettings->DAA_generic_q). */
      tpm_bn_init(q);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_init(r);
      tpm_bn_ui_pow_ui(r, 2, DAA_power0);
      tpm_bn_mul(r, r, r1);
      tpm_bn_mod(r, r, q);
      tpm_bn_add(r, r, r0);
      tpm_bn_mod(r, r, q);
      /* Set E1 = ((DAA_session->DAA_scratch)^r) mod (DAA_generic_gamma). */
      tpm_bn_init(gamma);
      tpm_bn_import(gamma, inputSize0, 1, DAA_generic_gamma);
      tpm_bn_init(w);
      tpm_bn_import(w, sizeof(session->DAA_session.DAA_scratch), -1, 
        session->DAA_session.DAA_scratch);
      tpm_bn_init(E1);
      tpm_bn_powm(E1, w, r, gamma);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = E1 */
      tpm_bn_export(scratch, &size, 1, E1);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r0), tpm_bn_clear(r1), tpm_bn_clear(q), tpm_bn_clear(r);
      tpm_bn_clear(gamma), tpm_bn_clear(w), tpm_bn_clear(E1);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 9:
    {
      BYTE *NT = NULL;
      
      /* Verify that DAA_session->DAA_stage == 9. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 9) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Verify that inputSize0 == sizeOf(TPM_DIGEST) and return error 
       * TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(TPM_DIGEST)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* Set DAA_session->DAA_digest = inputData0 */
      memcpy(&session->DAA_session.DAA_digest, inputData0, inputSize0);
      /* Obtain DAA_SIZE_NT bytes from the RNG and label them NT */
      if ((NT = tpm_malloc(DAA_SIZE_NT)) == NULL) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      tpm_get_random_bytes(NT, DAA_SIZE_NT);
      /* Set DAA_session->DAA_digest to the SHA-1(DAA_session->DAA_digest || 
       * NT)*/
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_session.DAA_digest, 
          sizeof(session->DAA_session.DAA_digest));
      tpm_sha1_update(&sha1, NT, DAA_SIZE_NT);
      tpm_sha1_final(&sha1, session->DAA_session.DAA_digest.digest);
      /* Set outputData = NT */
      *outputSize = DAA_SIZE_NT;
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, NT, *outputSize);
      else {
        tpm_free(NT);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      tpm_free(NT);
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 10:
    {
      /* Verify that DAA_session->DAA_stage == 10. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 10) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set selector = inputData0, verify that selector == 0 or 1, and 
       * return error TPM_DAA_INPUT_DATA0 on mismatch */
      if (inputSize0 != sizeof(selector)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      memcpy(&selector, inputData0, sizeof(selector));
      if ((selector != '\x00') && (selector != '\x01')) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      /* If selector == 1, verify that inputSize1 == sizeOf(TPM_DIGEST), and */
      if (selector == '\x01') {
        debug("DAA_Sign(): selector == 1");
        if (inputSize1 != sizeof(TPM_DIGEST)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
        }
        /* Set DAA_session->DAA_digest to SHA-1(DAA_session->DAA_digest || 
         * 1 || inputData1) */
        tpm_sha1_init(&sha1);
        tpm_sha1_update(&sha1, (BYTE*) &session->DAA_session.DAA_digest, 
          sizeof(session->DAA_session.DAA_digest));
        tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
        tpm_sha1_update(&sha1, inputData1, inputSize1);
        tpm_sha1_final(&sha1, (BYTE*) &session->DAA_session.DAA_digest);
      }
      /* If selector == 0, verify that inputData1 is a handle to a TPM 
       * identity key (AIK), and */
      if (selector == '\x00') {
        debug("DAA_Sign(): selector == 0");
        if (tpm_unmarshal_TPM_KEY_HANDLE(&inputData1, &inputSize1, 
          &aikHandle) || (inputSize1 != 0))
        {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
        }
        debug("DAA_Sign(): aikHandle == %.8x", aikHandle);
        aikData = tpm_get_key(aikHandle);
        if (aikData == NULL) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
        }
        if (aikData->keyUsage != TPM_KEY_IDENTITY) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA1;
        }
        /* Set DAA_session->DAA_digest to SHA-1(DAA_session->DAA_digest || 
         * 0 || n2) where n2 is the modulus of the AIK */
        tpm_sha1_init(&sha1);
        tpm_sha1_update(&sha1, (BYTE*) &session->DAA_session.DAA_digest, 
          sizeof(session->DAA_session.DAA_digest));
        tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
        tpm_rsa_export_modulus(&aikData->key, scratch, &size);
        tpm_sha1_update(&sha1, scratch, size);
        tpm_sha1_final(&sha1, (BYTE*) &session->DAA_session.DAA_digest);
      }
      /* Set outputData = DAA_session->DAA_digest */
      *outputSize = sizeof(session->DAA_session.DAA_digest);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, &session->DAA_session.DAA_digest, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 11:
    {
      /* Verify that DAA_session->DAA_stage == 11. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 11) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r0 bits from MGF1("r0", 
       * DAA_session->DAA_contextSeed), and label them r0 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r0", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r0);
      tpm_bn_init(r0);
      tpm_bn_import(r0, DAA_SIZE_r0, 1, scratch);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Set f0 = f mod 2^DAA_power0 (erase all but the lowest DAA_power0 
       * bits of f) */
      tpm_bn_init(f0);
      tpm_bn_init(tmp);
      tpm_bn_ui_pow_ui(tmp, 2, DAA_power0);
      tpm_bn_mod(f0, f, tmp);
      /* Set s0 = r0 + (DAA_session->DAA_digest) * (f0) */
      tpm_bn_init(s0);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s0, tmp, f0);
      tpm_bn_add(s0, r0, s0);
      /* Set outputData = s0 */
      tpm_bn_export(scratch, &size, 1, s0);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r0), tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(f0);
      tpm_bn_clear(s0), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 12:
    {
      /* Verify that DAA_session->DAA_stage == 12. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 12) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Obtain DAA_SIZE_r1 bits from MGF1("r1", 
       * DAA_session->DAA_contextSeed), and label them r1 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r1", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r1);
      tpm_bn_init(r1);
      tpm_bn_import(r1, DAA_SIZE_r1, 1, scratch);
      /* Set f = SHA1(DAA_tpmSpecific->DAA_rekey || 
       * DAA_tpmSpecific->DAA_count || 0 ) || 
       * SHA1(DAA_tpmSpecific->DAA_rekey || DAA_tpmSpecific->DAA_count || 
       * 1 ) mod DAA_issuerSettings->DAA_generic_q */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_00, 1);
      tpm_sha1_final(&sha1, scratch);
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_rekey, 
          sizeof(session->DAA_tpmSpecific.DAA_rekey));
      tpm_sha1_update(&sha1, (BYTE*) &session->DAA_tpmSpecific.DAA_count, 
          sizeof(session->DAA_tpmSpecific.DAA_count));
      tpm_sha1_update(&sha1, DAA_LABEL_01, 1);
      tpm_sha1_final(&sha1, scratch + SHA1_DIGEST_LENGTH);
      tpm_bn_init(f), tpm_bn_init(q);
      tpm_bn_import(f, 2 * SHA1_DIGEST_LENGTH, 1, scratch);
      tpm_bn_import(q, sizeof(session->DAA_issuerSettings.DAA_generic_q), 
        1, session->DAA_issuerSettings.DAA_generic_q);
      tpm_bn_mod(f, f, q);
      /* Shift f right by DAA_power0 bits (discard the lowest DAA_power0 
       * bits) and label the result f1 */
      tpm_bn_init(f1);
      tpm_bn_fdiv_q_2exp(f1, f, DAA_power0);
      /* Set s1 = r1 + (DAA_session->DAA_digest) * (f1) */
      tpm_bn_init(s1);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s1, tmp, f1);
      tpm_bn_add(s1, r1, s1);
      /* Set outputData = s1 */
      tpm_bn_export(scratch, &size, 1, s1);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r1), tpm_bn_clear(f), tpm_bn_clear(q), tpm_bn_clear(f1);
      tpm_bn_clear(s1), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 13:
    {
      BYTE *DAA_private_v0 = NULL;
      
      /* Verify that DAA_session->DAA_stage == 13. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 13) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_private_v0 = unwrap(inputData0) */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_TPM_DAA_BLOB(&ptr, &len, &blob) || (len != 0)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      sensitive.internalData = scratch;
      if (decrypt_daa(blob.additionalData, blob.additionalSize, 
        blob.sensitiveData, blob.sensitiveSize, &sensitive, &buf)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DECRYPT_ERROR;
      }
      if (compute_daa_digest(&blob, &digest) || 
        memcmp(&digest, &blob.blobIntegrity, sizeof(TPM_DIGEST))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((blob.resourceType != TPM_RT_DAA_V0) || 
        (sensitive.tag != TPM_TAG_DAA_SENSITIVE || 
        (sensitive.internalSize == 0) || 
        (sensitive.internalSize > DAA_SIZE_v0))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((DAA_private_v0 = tpm_malloc(DAA_SIZE_v0)) == NULL) {
        tpm_free(buf);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      memcpy(DAA_private_v0, sensitive.internalData, sensitive.internalSize);
      tpm_free(buf);
      /* Verify that SHA-1(DAA_private_v0) == DAA_tpmSpecific->DAA_digest_v0 
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, DAA_private_v0, sensitive.internalSize);
      tpm_sha1_final(&sha1, (BYTE*) &digest);
      if (memcmp(&digest, &session->DAA_tpmSpecific.DAA_digest_v0, 
        sizeof(TPM_DIGEST))) {
          tpm_free(DAA_private_v0);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them r2 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      tpm_bn_init(r2);
      tpm_bn_import(r2, DAA_SIZE_r2, 1, scratch);
      /* Set s2 = r2 + (DAA_session->DAA_digest) * 
       * (DAA_private_v0) mod 2^DAA_power1 
       * (Erase all but the lowest DAA_power1 bits of s2) */
      tpm_bn_init(s2);
      tpm_bn_import(s2, sensitive.internalSize, 1, DAA_private_v0);
      tpm_free(DAA_private_v0);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s2, tmp, s2);
      tpm_bn_add(s2, r2, s2);
      tpm_bn_ui_pow_ui(tmp, 2, DAA_power1);
      tpm_bn_mod(s2, s2, tmp);
      /* Set DAA_session->DAA_scratch = s2 */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, s2);
      /* Set outputData = s2 */
      tpm_bn_export(scratch, &size, 1, s2);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r2), tpm_bn_clear(s2), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 14:
    {
      BYTE *DAA_private_v0 = NULL;
      
      /* Verify that DAA_session->DAA_stage == 14. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 14) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_private_v0 = unwrap(inputData0) */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_TPM_DAA_BLOB(&ptr, &len, &blob) || (len != 0)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      sensitive.internalData = scratch;
      if (decrypt_daa(blob.additionalData, blob.additionalSize, 
        blob.sensitiveData, blob.sensitiveSize, &sensitive, &buf)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DECRYPT_ERROR;
      }
      if (compute_daa_digest(&blob, &digest) || 
        memcmp(&digest, &blob.blobIntegrity, sizeof(TPM_DIGEST))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((blob.resourceType != TPM_RT_DAA_V0) || 
        (sensitive.tag != TPM_TAG_DAA_SENSITIVE || 
        (sensitive.internalSize == 0) || 
        (sensitive.internalSize > DAA_SIZE_v0))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((DAA_private_v0 = tpm_malloc(DAA_SIZE_v0)) == NULL) {
        tpm_free(buf);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      memcpy(DAA_private_v0, sensitive.internalData, sensitive.internalSize);
      tpm_free(buf);
      /* Verify that SHA-1(DAA_private_v0) == DAA_tpmSpecific->DAA_digest_v0 
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, DAA_private_v0, sensitive.internalSize);
      tpm_sha1_final(&sha1, (BYTE*) &digest);
      if (memcmp(&digest, &session->DAA_tpmSpecific.DAA_digest_v0, 
        sizeof(TPM_DIGEST))) {
          tpm_free(DAA_private_v0);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Obtain DAA_SIZE_r2 bits from MGF1("r2", 
       * DAA_session->DAA_contextSeed), and label them r2 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r2", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r2);
      tpm_bn_init(r2);
      tpm_bn_import(r2, DAA_SIZE_r2, 1, scratch);
      /* Set s12 = r2 + (DAA_session->DAA_digest) * (DAA_private_v0). */
      tpm_bn_init(s12);
      tpm_bn_import(s12, sensitive.internalSize, 1, DAA_private_v0);
      tpm_free(DAA_private_v0);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s12, tmp, s12);
      tpm_bn_add(s12, r2, s12);
      /* Shift s12 right by DAA_power1 bits (erase the lowest DAA_power1 
       * bits). */
      tpm_bn_fdiv_q_2exp(s12, s12, DAA_power1);
      /* Set DAA_session->DAA_scratch = s12 */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      tpm_bn_export(session->DAA_session.DAA_scratch, NULL, -1, s12);
      tpm_bn_clear(r2), tpm_bn_clear(s12), tpm_bn_clear(tmp);
      /* Set outputData = NULL */
      *outputSize = 0, *outputData = NULL;
      /* Increment DAA_session->DAA_stage by 1 */
      session->DAA_session.DAA_stage++;
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    case 15:
    {
      BYTE *DAA_private_v1 = NULL;
      
      /* Verify that DAA_session->DAA_stage == 15. Return TPM_DAA_STAGE 
       * and flush handle on mismatch */
      if (session->DAA_session.DAA_stage != 15) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_STAGE;
      }
      /* Verify that DAA_tpmSpecific->DAA_digestIssuer == 
       * SHA-1(DAA_issuerSettings) and return error TPM_DAA_ISSUER_SETTINGS 
       * on mismatch */
      if (tpm_daa_verify_digestIssuer(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_ISSUER_SETTINGS;
      }
      /* Verify that DAA_session->DAA_digestContext == SHA-1(DAA_tpmSpecific) 
       * and return error TPM_DAA_TPM_SETTINGS on mismatch */
      if (tpm_daa_verify_digestContext_sign(session, &sha1)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_TPM_SETTINGS;
      }
      /* Set DAA_private_v1 = unwrap(inputData0) */
      ptr = inputData0, len = inputSize0;
      if (tpm_unmarshal_TPM_DAA_BLOB(&ptr, &len, &blob) || (len != 0)) {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_DAA_INPUT_DATA0;
      }
      sensitive.internalData = scratch;
      if (decrypt_daa(blob.additionalData, blob.additionalSize, 
        blob.sensitiveData, blob.sensitiveSize, &sensitive, &buf)) {
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DECRYPT_ERROR;
      }
      if (compute_daa_digest(&blob, &digest) || 
        memcmp(&digest, &blob.blobIntegrity, sizeof(TPM_DIGEST))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((blob.resourceType != TPM_RT_DAA_V1) || 
        (sensitive.tag != TPM_TAG_DAA_SENSITIVE || 
        (sensitive.internalSize == 0) || 
        (sensitive.internalSize > DAA_SIZE_v1))) {
          tpm_free(buf);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      if ((DAA_private_v1 = tpm_malloc(DAA_SIZE_v1)) == NULL) {
        tpm_free(buf);
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      memcpy(DAA_private_v1, sensitive.internalData, sensitive.internalSize);
      tpm_free(buf);
      /* Verify that SHA-1(DAA_private_v1) == DAA_tpmSpecific->DAA_digest_v1 
       * and return error TPM_DAA_INPUT_DATA0 on mismatch */
      tpm_sha1_init(&sha1);
      tpm_sha1_update(&sha1, DAA_private_v1, sensitive.internalSize);
      tpm_sha1_final(&sha1, (BYTE*) &digest);
      if (memcmp(&digest, &session->DAA_tpmSpecific.DAA_digest_v1, 
        sizeof(TPM_DIGEST))) {
          tpm_free(DAA_private_v1);
          memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
          return TPM_DAA_INPUT_DATA0;
      }
      /* Obtain DAA_SIZE_r4 bits from MGF1("r4", 
       * DAA_session->DAA_contextSeed), and label them r4 */
      memset(scratch, 0, sizeof(scratch));
      memcpy(mgf1_seed, "r4", 2);
      memcpy(mgf1_seed + 2, session->DAA_session.DAA_contextSeed.nonce, 
        sizeof(TPM_NONCE));
      tpm_rsa_mask_generation(mgf1_seed, sizeof(mgf1_seed), scratch, DAA_SIZE_r4);
      tpm_bn_init(r4);
      tpm_bn_import(r4, DAA_SIZE_r4, 1, scratch);
      /* Set s3 = r4 + (DAA_session->DAA_digest) * (DAA_private_v1) + 
       * (DAA_session->DAA_scratch). */
      tpm_bn_init(s3);
      tpm_bn_import(s3, sensitive.internalSize, 1, DAA_private_v1);
      tpm_free(DAA_private_v1);
      tpm_bn_init(tmp);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_digest.digest), 
        1, session->DAA_session.DAA_digest.digest);
      tpm_bn_mul(s3, tmp, s3);
      tpm_bn_add(s3, r4, s3);
      tpm_bn_import(tmp, sizeof(session->DAA_session.DAA_scratch), 
        -1, session->DAA_session.DAA_scratch);
      tpm_bn_add(s3, s3, tmp);
      /* Set DAA_session->DAA_scratch = NULL */
      memset(session->DAA_session.DAA_scratch, 0, 
        sizeof(session->DAA_session.DAA_scratch));
      /* Set outputData = s3 */
      tpm_bn_export(scratch, &size, 1, s3);
      *outputSize = (uint32_t)size;
      tpm_bn_clear(r4), tpm_bn_clear(s3), tpm_bn_clear(tmp);
      if ((*outputData = tpm_malloc(*outputSize)) != NULL)
        memcpy(*outputData, scratch, *outputSize);
      else {
        memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
        return TPM_NOSPACE;
      }
      /* Terminate the DAA session and all resources assoociated with the
       * DAA sign session handle. */
      memset(session, 0, sizeof(TPM_DAA_SESSION_DATA));
      /* Return TPM_SUCCESS */
      return TPM_SUCCESS;
    }
    default:
      return TPM_DAA_STAGE;
  }
}

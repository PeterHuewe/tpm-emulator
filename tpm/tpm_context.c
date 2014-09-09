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
 * $Id: tpm_context.c 452 2010-07-19 19:05:05Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"
#include <crypto/rc4.h>
#include <crypto/hmac.h>

/*
 * Session Management ([TPM_Part3], Section 21)
 */

UINT32 tpm_get_free_session(BYTE type)
{
  UINT32 i;
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    if (tpmData.stany.data.sessions[i].type == TPM_ST_INVALID) {
      tpmData.stany.data.sessions[i].type = type;
      if (type == TPM_ST_TRANSPORT) return INDEX_TO_TRANS_HANDLE(i);
      else return INDEX_TO_AUTH_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}

void tpm_invalidate_sessions(TPM_HANDLE handle)
{
  TPM_SESSION_DATA *session;
  int i;

  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    session = &tpmData.stany.data.sessions[i];
    if ((session->type == TPM_ST_OSAP && session->handle == handle)
        || (session->type == TPM_ST_DSAP && session->handle == handle)
        || (session->type == TPM_ST_TRANSPORT && session->handle == handle))
      memset(session, 0, sizeof(*session));
  }
}

TPM_RESULT TPM_KeyControlOwner(TPM_KEY_HANDLE keyHandle, TPM_PUBKEY pubKey,
                               UINT32 bitName, BOOL bitValue, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_PUBKEY pubKey2;
  TPM_DIGEST keyDigest, keyDigest2;
  info("TPM_KeyControlOwner()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* verify public key */
  if (tpm_compute_pubkey_digest(&pubKey, &keyDigest)) {
    debug("tpm_compute_pubkey_digest() failed");
    return TPM_FAIL;
  }
  if (tpm_extract_pubkey(key, &pubKey2)) {
    debug("tpm_extraxt_pubkey() failed.");
    return TPM_FAIL;
  }
  if (tpm_compute_pubkey_digest(&pubKey2, &keyDigest2)) {
    debug("tpm_compute_pubkey_digest() failed");
    free_TPM_PUBKEY(pubKey2);
    return TPM_FAIL;
  }
  free_TPM_PUBKEY(pubKey2);
  if (memcmp(&keyDigest, &keyDigest2, sizeof(TPM_DIGEST)) != 0)
    return TPM_BAD_PARAMETER;
  /* get bit name */
  debug("bitName = %d", bitName);
  if (bitName & TPM_KEY_CONTROL_OWNER_EVICT) {
    if (bitValue) {
      int i, num = 0;
      for (i = 0; i < TPM_MAX_KEYS; i++) {
        if (!tpmData.permanent.data.keys[i].payload ||
            !(tpmData.permanent.data.keys[i].keyControl
              & TPM_KEY_CONTROL_OWNER_EVICT)) num++;
      }
      if (num < 2) return TPM_NOSPACE;
      if (key->parentPCRStatus || (key->keyFlags & TPM_KEY_FLAG_VOLATILE))
        return TPM_BAD_PARAMETER;
      key->keyControl |= TPM_KEY_CONTROL_OWNER_EVICT;
    } else {
      key->keyControl &= ~TPM_KEY_CONTROL_OWNER_EVICT;
    }
  } else {
    return TPM_BAD_MODE;
  }
  return TPM_SUCCESS;
}

static int encrypt_context(BYTE *iv, UINT32 iv_size, TPM_CONTEXT_SENSITIVE *context, 
                           BYTE **enc, UINT32 *enc_size)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  /* marshal context */
  *enc_size = len = sizeof_TPM_CONTEXT_SENSITIVE((*context));
  *enc = ptr = tpm_malloc(len);
  if (*enc == NULL) return -1;
  if (tpm_marshal_TPM_CONTEXT_SENSITIVE(&ptr, &len, context)) {
    tpm_free(*enc);
    return -1;
  }
  /* encrypt context */
  memcpy(key, tpmData.permanent.data.contextKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, *enc, *enc, *enc_size);
  return 0;
}

static int decrypt_context(BYTE *iv, UINT32 iv_size, BYTE *enc, UINT32 enc_size, 
                           TPM_CONTEXT_SENSITIVE *context, BYTE **buf) 
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  len = enc_size;
  *buf = ptr = tpm_malloc(len);
  if (*buf == NULL) return -1;
  /* decrypt context */
  memcpy(key, tpmData.permanent.data.contextKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));  
  tpm_rc4_crypt(&rc4_ctx, enc, *buf, enc_size);
  /* unmarshal context */
  if (tpm_unmarshal_TPM_CONTEXT_SENSITIVE(&ptr, &len, context)) {
    tpm_free(*buf);
    return -1;
  }
  return 0;
}

static int compute_context_digest(TPM_CONTEXT_BLOB *contextBlob, TPM_DIGEST *digest)
{
  BYTE *buf, *ptr;
  UINT32 len;
  tpm_hmac_ctx_t hmac_ctx;
  len = sizeof_TPM_CONTEXT_BLOB((*contextBlob));
  buf = ptr = tpm_malloc(len);
  if (buf == NULL) return -1;
  if (tpm_marshal_TPM_CONTEXT_BLOB(&ptr, &len, contextBlob)) {
    tpm_free(buf);
    return -1;
  }
  memset(&buf[30], 0, 20);
  tpm_hmac_init(&hmac_ctx, tpmData.permanent.data.tpmProof.nonce, 
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  tpm_hmac_update(&hmac_ctx, buf, sizeof_TPM_CONTEXT_BLOB((*contextBlob)));
  tpm_hmac_final(&hmac_ctx, digest->digest);
  tpm_free(buf);
  return 0;
}

TPM_RESULT TPM_SaveContext(TPM_HANDLE handle, TPM_RESOURCE_TYPE resourceType,
                           const BYTE label[16], UINT32 *contextSize,
                           TPM_CONTEXT_BLOB *contextBlob)
{
  TPM_CONTEXT_SENSITIVE context;
  TPM_SESSION_DATA *session = NULL;
  TPM_DAA_SESSION_DATA *sessionDAA = NULL;
  TPM_KEY_DATA *key = NULL;
  int i = 0;
  info("TPM_SaveContext() resourceType = %08x", resourceType);
  /* setup context data */
  context.tag = TPM_TAG_CONTEXT_SENSITIVE;
  context.resourceType = resourceType;
  if (resourceType == TPM_RT_AUTH || resourceType == TPM_RT_TRANS) {
    session = (resourceType == TPM_RT_AUTH) ? tpm_get_auth(handle) : 
               tpm_get_transport(handle);
    if (session == NULL) return TPM_INVALID_RESOURCE;
    /* store session data */
    memcpy(&context.internalData.session, session, sizeof(TPM_SESSION_DATA));
    context.internalSize = sizeof_TPM_SESSION_DATA((*session));
    /* set context nonce */
    memcpy(&context.contextNonce, &tpmData.stany.data.contextNonceSession, 
           sizeof(TPM_NONCE));
  } else if (resourceType == TPM_RT_KEY) {
    key = tpm_get_key(handle);
    debug("resourceType = TPM_RT_KEY, handle = %08x, key = %p", handle, key);
    if (key == NULL) return TPM_INVALID_RESOURCE;
    if (key->keyControl & TPM_KEY_CONTROL_OWNER_EVICT) return TPM_OWNER_CONTROL;
    /* store key data (shallow copy is ok) */
    memcpy(&context.internalData.key, key, sizeof(TPM_KEY_DATA));
    context.internalSize = sizeof_TPM_KEY_DATA((*key));
    /* set context nonce */
    memcpy(&context.contextNonce, &tpmData.stclear.data.contextNonceKey, 
           sizeof(TPM_NONCE));
  } else if (resourceType == TPM_RT_DAA_TPM) {
    sessionDAA = tpm_get_daa(handle);
    if (sessionDAA == NULL) return TPM_INVALID_RESOURCE;
    /* store sessionDAA data */
    memcpy(&context.internalData.sessionDAA, sessionDAA,
           sizeof(TPM_DAA_SESSION_DATA));
    context.internalSize = sizeof(TPM_DAA_SESSION_DATA);
    /* set context nonce */
    memcpy(&context.contextNonce, &tpmData.stany.data.contextNonceSession, 
           sizeof(TPM_NONCE));
  } else {
    return TPM_INVALID_RESOURCE;
  }
  /* setup context blob */
  contextBlob->tag = TPM_TAG_CONTEXTBLOB;
  contextBlob->resourceType = resourceType;
  contextBlob->handle = handle;
  memset(&contextBlob->integrityDigest, 0, sizeof(TPM_DIGEST));
  memcpy(contextBlob->label, label, sizeof(contextBlob->label));
  contextBlob->additionalSize = TPM_SYM_KEY_SIZE;
  contextBlob->additionalData = tpm_malloc(contextBlob->additionalSize);
  if (contextBlob->additionalData == NULL) return TPM_FAIL;
  tpm_get_random_bytes(contextBlob->additionalData, 
                       contextBlob->additionalSize);
  /* increment context counter */
  if (resourceType == TPM_RT_KEY) {
    contextBlob->contextCount = 0;
  } else {
    if (tpmData.stany.data.contextCount >= 0xfffffffc) {
      tpm_free(contextBlob->additionalData);
      return TPM_TOOMANYCONTEXTS;
    }
    contextBlob->contextCount = ++tpmData.stany.data.contextCount;
    for (i = 0; i < TPM_MAX_SESSION_LIST; i++) {
      if (tpmData.stany.data.contextList[i] == 0) break;
    }
    if (i >= TPM_MAX_SESSION_LIST) {
      tpm_free(contextBlob->additionalData);
      return TPM_NOCONTEXTSPACE;
    }
    tpmData.stany.data.contextCount++;
    tpmData.stany.data.contextList[i] = tpmData.stany.data.contextCount;
    contextBlob->contextCount = tpmData.stany.data.contextCount;
  }
  debug("context counter = %d", tpmData.stany.data.contextCount);
  /* encrypt sensitive data */
  if (encrypt_context(contextBlob->additionalData, contextBlob->additionalSize,
      &context, &contextBlob->sensitiveData, &contextBlob->sensitiveSize)) {
        tpm_free(contextBlob->additionalData);
        return TPM_ENCRYPT_ERROR;
  }
  /* compute context digest */
  if (compute_context_digest(contextBlob, &contextBlob->integrityDigest)) {
    tpm_free(contextBlob->additionalData);
    return TPM_FAIL;
  }
  *contextSize = sizeof_TPM_CONTEXT_BLOB((*contextBlob));
  if (resourceType != TPM_RT_KEY) {
    /* The TPM MUST invalidate all information regarding the resource 
     * except for information needed for reloading. */
    if (resourceType != TPM_RT_DAA_TPM)
      session->type = TPM_ST_INVALID;
    else {
      memset(sessionDAA, 0, sizeof(TPM_DAA_SESSION_DATA));
      sessionDAA->type = TPM_ST_INVALID;
      tpmData.stany.data.currentDAA = 0;
    }
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadContext(TPM_HANDLE entityHandle, BOOL keepHandle,
                           UINT32 contextSize, TPM_CONTEXT_BLOB *contextBlob,
                           TPM_HANDLE *handle)
{
  TPM_CONTEXT_SENSITIVE context;
  BYTE *context_buf;
  TPM_SESSION_DATA *session;
  TPM_DAA_SESSION_DATA *sessionDAA;
  TPM_KEY_DATA *key;
  TPM_DIGEST digest;
  int i = 0;
  info("TPM_LoadContext()");
  if (decrypt_context(contextBlob->additionalData, contextBlob->additionalSize,
      contextBlob->sensitiveData, contextBlob->sensitiveSize, 
      &context, &context_buf)) return TPM_DECRYPT_ERROR;
  /* validate structure */
  if (compute_context_digest(contextBlob, &digest)
      || memcmp(&digest, &contextBlob->integrityDigest, sizeof(TPM_DIGEST))) {
    tpm_free(context_buf);
    return TPM_BADCONTEXT;
  }
  if (contextBlob->resourceType == TPM_RT_KEY) {
   /* check contextNonce */
    if (context.internalData.key.parentPCRStatus 
        || (context.internalData.key.keyFlags & TPM_KEY_FLAG_VOLATILE)) {
      if (memcmp(&context.contextNonce, &tpmData.stclear.data.contextNonceKey,
          sizeof(TPM_NONCE)) != 0) {
        tpm_free(context_buf);
        return TPM_BADCONTEXT;
      }
    }
    /* check handle */
    key = tpm_get_key_slot(entityHandle);
    if (key == NULL || !key->payload) {
      if (keepHandle) {
        tpm_free(context_buf);
        return TPM_BAD_HANDLE;
      }    
      *handle = tpm_get_free_key();
      if (*handle == TPM_INVALID_HANDLE) {
        tpm_free(context_buf);
        return TPM_RESOURCES;
      }
      key = &tpmData.permanent.data.keys[HANDLE_TO_INDEX(*handle)];
    } else {
      *handle = entityHandle;
    }
    /* reload resource */
    memcpy(key, &context.internalData.key, sizeof(TPM_KEY_DATA));
    tpm_rsa_copy_key(&key->key, &context.internalData.key.key);
  } else if (contextBlob->resourceType == TPM_RT_DAA_TPM) {
    /* check contextNonce */
    if (memcmp(&context.contextNonce, &tpmData.stany.data.contextNonceSession, 
        sizeof(TPM_NONCE)) != 0) {
      tpm_free(context_buf);
      return TPM_BADCONTEXT;
    }
    /* check context list */
    for (i = 0; i < TPM_MAX_SESSION_LIST; i++)
      if (tpmData.stany.data.contextList[i] == contextBlob->contextCount) break;
    if (i >= TPM_MAX_SESSION_LIST) {
      tpm_free(context_buf);
      return TPM_BADCONTEXT;
    }
    tpmData.stany.data.contextList[i] = 0;
    /* check handle */
    info("entityHandle = %08x, keepHandle = %d", entityHandle, keepHandle);
    sessionDAA = tpm_get_daa_slot(entityHandle);
    if (sessionDAA == NULL) {
      if (keepHandle) {
        tpm_free(context_buf);
        return TPM_BAD_HANDLE;
      }
      *handle = tpm_get_free_daa_session();
      if (*handle == TPM_INVALID_HANDLE) {
        tpm_free(context_buf);
        return TPM_RESOURCES;
      }
      sessionDAA = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(*handle)];
    } else if (sessionDAA->type != TPM_ST_INVALID) {
      if (keepHandle) {
        tpm_free(context_buf);
        return TPM_BAD_HANDLE;
      }
      *handle = tpm_get_free_daa_session();
      if (*handle == TPM_INVALID_HANDLE) {
        tpm_free(context_buf);
        return TPM_RESOURCES;
      }
      sessionDAA = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(*handle)];
    } else {
      if (HANDLE_TO_RT(entityHandle) != TPM_RT_DAA_TPM) {
        if (keepHandle) {
          tpm_free(context_buf);
          return TPM_BAD_HANDLE;
        }
        *handle = tpm_get_free_daa_session();
        if (*handle == TPM_INVALID_HANDLE) {
          tpm_free(context_buf);
          return TPM_RESOURCES;
        }
        sessionDAA = &tpmData.stany.data.sessionsDAA[HANDLE_TO_INDEX(*handle)];
      } else
        *handle = entityHandle;
    }
    /* reload resource */
    tpmData.stany.data.currentDAA = *handle;
    info("stany.data.currentDAA := %.8x", *handle);
    memset(sessionDAA, 0, sizeof(TPM_DAA_SESSION_DATA));
    memcpy(sessionDAA, &context.internalData.sessionDAA, context.internalSize);
  } else {
    /* check contextNonce */
    if (memcmp(&context.contextNonce, &tpmData.stany.data.contextNonceSession, 
        sizeof(TPM_NONCE)) != 0) {
      tpm_free(context_buf);
      return TPM_BADCONTEXT;
    }
    if (context.internalData.session.type == TPM_ST_OSAP
        && tpm_get_key(context.internalData.session.handle) == NULL) {
      tpm_free(context_buf);
      return TPM_RESOURCEMISSING;
    }
    /* check context list */
    for (i = 0; i < TPM_MAX_SESSION_LIST; i++)
      if (tpmData.stany.data.contextList[i] == contextBlob->contextCount) break;
    if (i >= TPM_MAX_SESSION_LIST) {
      tpm_free(context_buf);
      return TPM_BADCONTEXT;
    }
    tpmData.stany.data.contextList[i] = 0;
    /* check handle */
    session = tpm_get_session_slot(entityHandle);
    if (session == NULL || session->type != TPM_ST_INVALID) {
      if (keepHandle) {
        tpm_free(context_buf);
        return TPM_BAD_HANDLE;
      }
      *handle = tpm_get_free_session(context.internalData.session.type);
      if (*handle == TPM_INVALID_HANDLE) {
        tpm_free(context_buf);
        return TPM_RESOURCES;
      }
      session = &tpmData.stany.data.sessions[HANDLE_TO_INDEX(*handle)];
    } else {
      *handle = entityHandle;
    }
    /* reload resource */
    memcpy(session, &context.internalData.session, sizeof(TPM_SESSION_DATA));
  }
  tpm_free(context_buf);
  return TPM_SUCCESS;
}

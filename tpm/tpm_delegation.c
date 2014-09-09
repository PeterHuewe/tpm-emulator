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
 * $Id: tpm_delegation.c 367 2010-02-13 15:52:18Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_marshalling.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "crypto/hmac.h"
#include "crypto/rc4.h"

/*
 * Delegation Commands ([TPM_Part3], Section 19)
 */

TPM_FAMILY_TABLE_ENTRY *tpm_get_family_row(TPM_FAMILY_ID id)
{
  UINT32 i;
  for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    if (tpmData.permanent.data.familyTable.famRow[i].valid
        && tpmData.permanent.data.familyTable.famRow[i].familyID == id)
      return &tpmData.permanent.data.familyTable.famRow[i];
  }
  return NULL;
}

TPM_DELEGATE_TABLE_ROW *tpm_get_delegate_row(UINT32 row)
{
  if (row < TPM_NUM_DELEGATE_TABLE_ENTRY
      && tpmData.permanent.data.delegateTable.delRow[row].valid)
    return &tpmData.permanent.data.delegateTable.delRow[row];
  return NULL;
}

void tpm_compute_owner_blob_digest(TPM_DELEGATE_OWNER_BLOB *blob,
                                   TPM_DIGEST *digest)
{
  tpm_hmac_ctx_t ctx;
  BYTE buf[sizeof_TPM_DELEGATE_OWNER_BLOB((*blob))];
  BYTE *ptr = buf;
  UINT32 length = sizeof(buf);
  tpm_marshal_TPM_DELEGATE_OWNER_BLOB(&ptr, &length, blob);
  memset(&buf[2 + sizeof_TPM_DELEGATE_PUBLIC(blob->pub)], 0, 20);
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce,
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  tpm_hmac_update(&ctx, buf, sizeof(buf) - length);
  tpm_hmac_final(&ctx, digest->digest);
}

void tpm_compute_key_blob_digest(TPM_DELEGATE_KEY_BLOB *blob,
                                 TPM_DIGEST *digest)
{
  tpm_hmac_ctx_t ctx;
  BYTE buf[sizeof_TPM_DELEGATE_KEY_BLOB((*blob))];
  BYTE *ptr = buf;
  UINT32 length = sizeof(buf);
  tpm_marshal_TPM_DELEGATE_KEY_BLOB(&ptr, &length, blob);
  memset(&buf[2 + sizeof_TPM_DELEGATE_PUBLIC(blob->pub)], 0, 20);
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce,
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  tpm_hmac_update(&ctx, buf, sizeof(buf) - length);
  tpm_hmac_final(&ctx, digest->digest);
}

int tpm_encrypt_sensitive(BYTE *iv, UINT32 iv_size,
                          TPM_DELEGATE_SENSITIVE *sensitive,
                          BYTE **enc, UINT32 *enc_size)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  /* marshal context */
  *enc_size = len = sizeof_TPM_DELEGATE_SENSITIVE((*sensitive));
  *enc = ptr = tpm_malloc(len);
  if (*enc == NULL) return -1;
  if (tpm_marshal_TPM_DELEGATE_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*enc);
    return -1;
  }
  /* encrypt context */
  memcpy(key, tpmData.permanent.data.delegateKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, *enc, *enc, *enc_size);
  return 0;
}

int tpm_decrypt_sensitive(BYTE *iv, UINT32 iv_size, BYTE *enc, UINT32 enc_size,
                          TPM_DELEGATE_SENSITIVE *sensitive, BYTE **buf)
{
  UINT32 len;
  BYTE *ptr;
  tpm_rc4_ctx_t rc4_ctx;
  BYTE key[TPM_SYM_KEY_SIZE + iv_size];
  len = enc_size;
  *buf = ptr = tpm_malloc(len);
  if (*buf == NULL) return -1;
  /* decrypt context */
  memcpy(key, tpmData.permanent.data.delegateKey, TPM_SYM_KEY_SIZE);
  memcpy(&key[TPM_SYM_KEY_SIZE], iv, iv_size);
  tpm_rc4_init(&rc4_ctx, key, sizeof(key));
  tpm_rc4_crypt(&rc4_ctx, enc, *buf, enc_size);
  /* unmarshal context */
  if (tpm_unmarshal_TPM_DELEGATE_SENSITIVE(&ptr, &len, sensitive)) {
    tpm_free(*buf);
    return -1;
  }
  return 0;
}

static TPM_FAMILY_TABLE_ENTRY *tpm_get_free_family_row(void) {
  UINT32 i;
  for(i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    if(!tpmData.permanent.data.familyTable.famRow[i].valid) {
      tpmData.permanent.data.familyTable.famRow[i].valid = TRUE;
      return &tpmData.permanent.data.familyTable.famRow[i];
    }
  }
  return NULL;
}

TPM_RESULT TPM_Delegate_Manage(TPM_FAMILY_ID familyID,
                               TPM_FAMILY_OPERATION opFlag,
                               UINT32 opDataSize, BYTE *opData,
                               TPM_AUTH *auth1,
                               UINT32 *retDataSize, BYTE **retData)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_FAMILY_TABLE_ENTRY *fr;
  UINT32 i;

  info("[TPM_Delegate_Manage]");
  /* if no new family row is to be created, get the existing one */
  if (opFlag != TPM_FAMILY_CREATE) {
    fr = tpm_get_family_row(familyID);
    if (fr == NULL) return TPM_BADINDEX;
  } else {
    fr = NULL;
  }
  /* verify authorization */
  session = tpm_get_auth(auth1->authHandle);
  if (session == NULL) return TPM_AUTHFAIL;
  if (auth1->authHandle != TPM_INVALID_AUTHHANDLE) {
    res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
    if (res != TPM_SUCCESS) return res;
    if (session->type == TPM_ST_DSAP) {
      if (session->familyID != familyID) return TPM_DELEGATE_FAMILY;
      auth1->continueAuthSession = FALSE;
    }
  } else {
    if (tpmData.permanent.flags.owned) return TPM_AUTHFAIL;
    /* check delegate admin lock */
    if (fr != NULL && (fr->flags & TPM_DELEGATE_ADMIN_LOCK)) {
      debug("delegate admin lock is set");
      return TPM_DELEGATE_LOCK;
    }
    /* verify maximal number of writes without an owner */
    if (tpmData.permanent.data.noOwnerNVWrite >= TPM_MAX_NV_WRITE_NOOWNER)
      return TPM_MAXNVWRITES;
    tpmData.permanent.data.noOwnerNVWrite++;
  }
  /* invalidate all but this auth session */
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    TPM_SESSION_DATA *s = &tpmData.stany.data.sessions[i];
    if (s->type != TPM_ST_TRANSPORT && s != session) memset(s, 0, sizeof(*s));
  }
  tpmData.stclear.data.ownerReference = TPM_KH_OWNER;
  /* perform requested operation */
  if (opFlag == TPM_FAMILY_CREATE) {
    BYTE *ptr;
    UINT32 length;
    debug("ofFlag = TPM_FAMILY_CREATE");
    if (opDataSize != 1) return TPM_BAD_PARAM_SIZE;
    /* get a free family row */
    fr = tpm_get_free_family_row();
    if (fr == NULL)  return TPM_NOSPACE;
    /* initialize the new row */
    fr->tag = TPM_TAG_FAMILY_TABLE_ENTRY;
    fr->familyLabel.label = *opData;
    tpmData.permanent.data.lastFamilyID++;
    fr->familyID = tpmData.permanent.data.lastFamilyID;
    fr->verificationCount = 1;
    fr->flags = 0;
    /* return the familyID */
    length = *retDataSize = 4;
    ptr = *retData = tpm_malloc(*retDataSize);
    if (*retData == NULL) {
      debug("tpm_malloc() failed.");
      fr->valid = FALSE;
      return TPM_FAIL;
    }
    if (tpm_marshal_UINT32(&ptr, &length, fr->familyID) != 0) {
      debug("tpm_marshal_UINT32() failed.");
      tpm_free(*retData);
      fr->valid = FALSE;
      return TPM_FAIL;
    }
  } else if (opFlag == TPM_FAMILY_ADMIN) {
    debug("opFlag = TPM_FAMILY_ADMIN");
    if (opDataSize != 1) return TPM_BAD_PARAM_SIZE;
    if (*opData)fr->flags |= TPM_DELEGATE_ADMIN_LOCK;
    else fr->flags &= ~TPM_DELEGATE_ADMIN_LOCK;
    *retDataSize = 0;
  } else if (opFlag == TPM_FAMILY_ENABLE) {
    debug("opFlag = TPM_FAMFLAG_ENABLED");
    if (opDataSize != 1) return TPM_BAD_PARAM_SIZE;
    if (*opData)fr->flags |= TPM_FAMFLAG_ENABLED;
    else fr->flags &= ~TPM_FAMFLAG_ENABLED;
    *retDataSize = 0;
    return TPM_SUCCESS;
  } else if (opFlag == TPM_FAMILY_INVALIDATE) {
    debug("opFlag = TPM_FAMILY_INVALIDATE");
    /* invalidate all family data */
    memset(fr, 0, sizeof(*fr));
    fr->valid = FALSE;
    *retDataSize = 0;
  } else {
    debug("unknown opFlag value: %d", opFlag);
    return TPM_BAD_PARAMETER;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Delegate_CreateKeyDelegation(TPM_KEY_HANDLE keyHandle,
                                            TPM_DELEGATE_PUBLIC *publicInfo,
                                            TPM_ENCAUTH *delAuth,
                                            TPM_AUTH *auth1,
                                            TPM_DELEGATE_KEY_BLOB *blob)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_FAMILY_TABLE_ENTRY *fr;
  TPM_SECRET secret;
  TPM_KEY_DATA *key;
  TPM_PUBKEY pubKey;
  TPM_DELEGATE_SENSITIVE sensitive;
  info("TPM_Delegate_CreateKeyDelegation()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  session = tpm_get_auth(auth1->authHandle);
  if (session == NULL) return TPM_FAIL;
  if (session->type != TPM_ST_OSAP && session->type != TPM_ST_DSAP) {
    debug("session is neither of type OSAP nor DSAP");
    return TPM_INVALID_AUTHHANDLE;
  }
  res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  /* get specified family entry */
  fr = tpm_get_family_row(publicInfo->familyID);
  if (fr == NULL) return TPM_BADINDEX;
  /* check delegation type */
  if (publicInfo->permissions.delegateType != TPM_DEL_KEY_BITS) {
    debug("invalid delegation type: %d", publicInfo->permissions.delegateType);
    return TPM_BAD_PARAMETER;
  }
  blob->tag = TPM_TAG_DELEGATE_KEY_BLOB;
  /* verify permissions if the access was delegated */
  if (session->type == TPM_ST_DSAP) {
    if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
    if (session->familyID != publicInfo->familyID) return TPM_DELEGATE_FAMILY;
    if (((session->permissions.per1 | publicInfo->permissions.per1)
          != session->permissions.per1)
        || ((session->permissions.per2 | publicInfo->permissions.per2)
             != session->permissions.per2)) return TPM_AUTHFAIL;
  }
  /* decrypt delegation secret */
  tpm_decrypt_auth_secret(*delAuth, session->sharedSecret,
                          &session->lastNonceEven, secret);
  /* compute key digest */
  if (tpm_extract_pubkey(key, &pubKey)) {
    debug("tpm_extraxt_pubkey() failed.");
    return TPM_FAIL;
  }
  if (tpm_compute_pubkey_digest(&pubKey, &blob->pubKeyDigest)) {
    debug("tpm_compute_pubkey_digest() failed");
    free_TPM_PUBKEY(pubKey);
    return TPM_FAIL;
  }
  free_TPM_PUBKEY(pubKey);
  /* create a delegate sensitive structure */
  sensitive.tag = TPM_TAG_DELEGATE_SENSITIVE;
  memcpy(&sensitive.authValue, &secret, sizeof(TPM_SECRET));
  /* generate IV and encrypt sensitive area */
  blob->additionalSize = TPM_SYM_KEY_SIZE;
  blob->additionalArea = tpm_malloc(blob->additionalSize);
  if (blob->additionalArea == NULL) {
    debug("tpm_malloc() failed.");
    return TPM_NOSPACE;
  }
  tpm_get_random_bytes(blob->additionalArea, blob->additionalSize);
  if (tpm_encrypt_sensitive(blob->additionalArea, blob->additionalSize,
        &sensitive, &blob->sensitiveArea, &blob->sensitiveSize)) {
    debug("tpm_encrypt_sensitive() failed.");
    tpm_free(blob->additionalArea);
    return TPM_ENCRYPT_ERROR;
  }
  /* copy public delegation information */
  memcpy(&blob->pub, publicInfo, sizeof(TPM_DELEGATE_PUBLIC));
  blob->pub.verificationCount = fr->verificationCount;
  /* compute integrity digest */
  tpm_compute_key_blob_digest(blob, &blob->integrityDigest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Delegate_CreateOwnerDelegation(BOOL increment,
                                              TPM_DELEGATE_PUBLIC *publicInfo,
                                              TPM_ENCAUTH *delAuth,
                                              TPM_AUTH *auth1,
                                              TPM_DELEGATE_OWNER_BLOB *blob)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_FAMILY_TABLE_ENTRY *fr;
  TPM_SECRET secret;
  TPM_DELEGATE_SENSITIVE sensitive;
  info("[TPM_Delegate_CreateOwnerDelegation]");
  /* verify authorization */
  session = tpm_get_auth(auth1->authHandle);
  if (session == NULL) return TPM_FAIL;
  if (session->type != TPM_ST_OSAP && session->type != TPM_ST_DSAP) {
    debug("session is neither of type OSAP nor DSAP");
    return TPM_INVALID_AUTHHANDLE;
  }
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  /* get specified family entry */
  fr = tpm_get_family_row(publicInfo->familyID);
  if (fr == NULL) return TPM_BADINDEX;
  /* check delegation type */
  if (publicInfo->permissions.delegateType != TPM_DEL_OWNER_BITS) {
    debug("invalid delegation type: %d", publicInfo->permissions.delegateType);
    return TPM_BAD_PARAMETER;
  }
  blob->tag = TPM_TAG_DELEGATE_OWNER_BLOB;
  /* verify permissions if the access was delegated */
  if (session->type == TPM_ST_DSAP) {
  if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
  if (session->familyID != publicInfo->familyID) return TPM_DELEGATE_FAMILY;
  if (((session->permissions.per1 | publicInfo->permissions.per1)
        != session->permissions.per1)
      || ((session->permissions.per2 | publicInfo->permissions.per2)
           != session->permissions.per2)) return TPM_AUTHFAIL;
  }
  /* increment verification count if required */
  if (increment) {
    UINT32 i;
    fr->verificationCount++;
    debug("incrementing verificationCount to %d", fr->verificationCount);
    tpmData.stclear.data.ownerReference = TPM_KH_OWNER;
    /* invalidate all but this session */
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
      TPM_SESSION_DATA *s = &tpmData.stany.data.sessions[i];
      if (s->type != TPM_ST_TRANSPORT && s != session) memset(s, 0, sizeof(*s));
    }
  }
  /* decrypt delegation secret */
  tpm_decrypt_auth_secret(*delAuth, session->sharedSecret,
                          &session->lastNonceEven, secret);
  /* create a delegate sensitive structure */
  sensitive.tag = TPM_TAG_DELEGATE_SENSITIVE;
  memcpy(&sensitive.authValue, &secret, sizeof(TPM_SECRET));
  /* generate IV and encrypt sensitive area */
  blob->additionalSize = TPM_SYM_KEY_SIZE;
  blob->additionalArea = tpm_malloc(blob->additionalSize);
  if (blob->additionalArea == NULL) {
    debug("tpm_malloc() failed.");
    return TPM_NOSPACE;
  }
  tpm_get_random_bytes(blob->additionalArea, blob->additionalSize);
  if (tpm_encrypt_sensitive(blob->additionalArea, blob->additionalSize,
      &sensitive, &blob->sensitiveArea, &blob->sensitiveSize)) {
    debug("tpm_encrypt_sensitive() failed.");
    tpm_free(blob->additionalArea);
    return TPM_ENCRYPT_ERROR;
  }
  /* copy public delegation information */
  memcpy(&blob->pub, publicInfo, sizeof(TPM_DELEGATE_PUBLIC));
  blob->pub.verificationCount = fr->verificationCount;
  /* compute integrity digest */
  tpm_compute_owner_blob_digest(blob, &blob->integrityDigest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Delegate_LoadOwnerDelegation(TPM_DELEGATE_INDEX index,
                                            TPM_DELEGATE_OWNER_BLOB *blob,
                                            TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_FAMILY_TABLE_ENTRY *fr;
  TPM_DIGEST blobDigest;
  TPM_DELEGATE_SENSITIVE sensitive;
  TPM_DELEGATE_TABLE_ROW *dr;
  BYTE *sens_buf;
  UINT32 i;
  info("TPM_Delegate_LoadOwnerDelegation()");
  /* get specified family entry */
  fr = tpm_get_family_row(blob->pub.familyID);
  if (fr == NULL) return TPM_BADINDEX;
  /* verify authorization */
  session = tpm_get_auth(auth1->authHandle);
  if (session == NULL) return TPM_AUTHFAIL;
  if (auth1->authHandle != TPM_INVALID_AUTHHANDLE) {
    res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
    if (res != TPM_SUCCESS) return res;
    if (session->type == TPM_ST_DSAP) {
      if (session->familyID != blob->pub.familyID) return TPM_DELEGATE_FAMILY;
      auth1->continueAuthSession = FALSE;
    }
  } else {
    if (tpmData.permanent.flags.owned) return TPM_AUTHFAIL;
    /* check delegate admin lock */
    if (fr != NULL && (fr->flags & TPM_DELEGATE_ADMIN_LOCK)) {
      debug("delegate admin lock is set");
      return TPM_DELEGATE_LOCK;
    }
    /* verify maximal number of writes without an owner */
    if (tpmData.permanent.data.noOwnerNVWrite >= TPM_MAX_NV_WRITE_NOOWNER)
    return TPM_MAXNVWRITES;
    tpmData.permanent.data.noOwnerNVWrite++;
  }
  /* verify the integrity of the blob and decode/decrypt the sensitive data */
  if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
  if (tpmData.permanent.flags.owned) {
    tpm_compute_owner_blob_digest(blob, &blobDigest);
    if (memcmp(&blob->integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* decrypt sensitive data */
    if (tpm_decrypt_sensitive(blob->additionalArea, blob->additionalSize,
      blob->sensitiveArea, blob->sensitiveSize, &sensitive, &sens_buf)) {
      debug("tpm_decrypt_sensitive() failed");
      return TPM_DECRYPT_ERROR;
    }
  } else {
    BYTE *ptr = blob->sensitiveArea;
    UINT32 length = blob->sensitiveSize;
    if (tpm_unmarshal_TPM_DELEGATE_SENSITIVE(&ptr, &length, &sensitive) != 0) {
      debug("tpm_unmarshal_TPM_DELEGATE_SENSITIVE()");
      return TPM_FAIL;
    }
    sens_buf = NULL;
  }
  if (sensitive.tag != TPM_TAG_DELEGATE_SENSITIVE) {
    tpm_free(sens_buf);
    return TPM_INVALID_STRUCTURE;
  }
  /* check that index is valid and copy data */
  debug("index = %d", index);
  if (index >= TPM_NUM_DELEGATE_TABLE_ENTRY) {
    tpm_free(sens_buf);
    return TPM_BADINDEX;
  }
  dr = &tpmData.permanent.data.delegateTable.delRow[index];
  dr->valid = TRUE;
  dr->tag = TPM_TAG_DELEGATE_TABLE_ROW;
  memcpy(&dr->authValue, &sensitive.authValue, sizeof(TPM_SECRET));
  memcpy(&dr->pub, &blob->pub, sizeof(TPM_DELEGATE_PUBLIC));
  tpm_free(sens_buf);
  /* invalidate all but this session */
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    TPM_SESSION_DATA *s = &tpmData.stany.data.sessions[i];
     if (s->type != TPM_ST_TRANSPORT && s != session) memset(s, 0, sizeof(*s));
  }
  tpmData.stclear.data.ownerReference = TPM_KH_OWNER;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Delegate_ReadTable(UINT32 *familyTableSize, BYTE **familyTable,
                                  UINT32 *delegateTableSize,
                                  BYTE **delegateTable)
{
  UINT32 i, length;
  BYTE *ptr;
  info("TPM_Delegate_ReadTable");
  /* compute the size of the family table */
  *familyTableSize = 0;
  *familyTable = NULL;
  for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    if (tpmData.permanent.data.familyTable.famRow[i].valid) {
      *familyTableSize += sizeof_TPM_FAMILY_TABLE_ENTRY(
        tpmData.permanent.data.familyTable.famRow[i]);
    }
  }
  debug("family table size: %d", *familyTableSize);
  /* allocate the table buffer and copy the family table */
  if (*familyTableSize > 0) {
    length = *familyTableSize;
    ptr = *familyTable = tpm_malloc(*familyTableSize);
    if (*familyTable == NULL) return TPM_RESOURCES;
    for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
      if (tpmData.permanent.data.familyTable.famRow[i].valid) {
        debug("writing table row %d", i);
        if (tpm_marshal_TPM_FAMILY_TABLE_ENTRY(&ptr, &length,
            &tpmData.permanent.data.familyTable.famRow[i])) {
          debug("tpm_marshal_TPM_FAMILY_TABLE_ENTRY() failed.");
          tpm_free(*familyTable);
          return TPM_FAIL;
        }
      }
    }
  }
  /* computing the size of the delegation table */
  *delegateTableSize = 0;
  *delegateTable = NULL;
  for (i = 0; i < TPM_NUM_DELEGATE_TABLE_ENTRY; i++) {
    if (tpmData.permanent.data.delegateTable.delRow[i].valid) {
      *delegateTableSize += sizeof_TPM_DELEGATE_PUBLIC(
        tpmData.permanent.data.delegateTable.delRow[i].pub) + 4;
    }
  }
  debug("delegation table size: %d", *delegateTableSize);
  /* allocate the table buffer and copy the delegation table */
  if (*delegateTableSize > 0) {
    length = *delegateTableSize;
    ptr = *delegateTable = tpm_malloc(*delegateTableSize);
    if (*delegateTable == NULL) {
      tpm_free(*familyTable);
      return TPM_RESOURCES;
    }
    for (i = 0; i < TPM_NUM_DELEGATE_TABLE_ENTRY; i++) {
      if (tpmData.permanent.data.delegateTable.delRow[i].valid) {
        debug("writing delegate row %d", i);
        if (tpm_marshal_TPM_DELEGATE_INDEX(&ptr, &length, i)
            || tpm_marshal_TPM_DELEGATE_PUBLIC(&ptr, &length,
                 &tpmData.permanent.data.delegateTable.delRow[i].pub)) {
          debug("tpm_marshal_UINT32 or -TPM_DELEGATE_PUBLIC failed.");
          tpm_free(*familyTable);
          tpm_free(*delegateTable);
          return TPM_FAIL;
        }
      }
    }
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Delegate_UpdateVerification(UINT32 inputSize, BYTE *inputData,
                                           TPM_AUTH *auth1, UINT32 *outputSize,
                                           BYTE **outputData)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  info("TPM_Delegate_UpdateVerification()");
  /* verify authorization */
  session = tpm_get_auth(auth1->authHandle);
  if (session == NULL) return TPM_AUTHFAIL;
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* determine the type of the input data */
  if (inputSize == 4) {
    TPM_DELEGATE_INDEX index;
    TPM_DELEGATE_TABLE_ROW *dr;
    TPM_FAMILY_TABLE_ENTRY *fr;
    debug("TPM_DELEGATE_TABLE_ROW");
    /* unmarshal delegate index */
    if (tpm_unmarshal_TPM_DELEGATE_INDEX(&inputData, &inputSize, &index)) {
      debug("tpm_unmarshal_TPM_DELEGATE_INDEX() failed.");
      return TPM_FAIL;
    }
    /* get delegate and family row */
    dr = tpm_get_delegate_row(index);
    if (dr == NULL) return TPM_BADINDEX;
    fr = tpm_get_family_row(dr->pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    /* verify permissions if the access was delegated */
    if (session->type == TPM_ST_DSAP) {
      if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
      if (session->familyID != fr->familyID) return TPM_DELEGATE_FAMILY;
    }
    /* update verification count */
    dr->pub.verificationCount = fr->verificationCount;
    *outputSize = 0;
    *outputData = NULL;
  } else if (inputData[0] == (TPM_TAG_DELEGATE_OWNER_BLOB >> 8)
             && inputData[1] == (TPM_TAG_DELEGATE_OWNER_BLOB & 0xff)) {
    TPM_DELEGATE_OWNER_BLOB blob;
    TPM_DIGEST blobDigest;
    TPM_FAMILY_TABLE_ENTRY *fr;
    UINT32 length;
    BYTE *ptr;
    debug("TPM_DELEGATE_OWNER_BLOB");
    /* unmarshal the blob */
    if (tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB(&inputData, &inputSize, &blob)) {
      debug("tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB() failed.");
      return TPM_FAIL;
    }
    /* validate the integrity of the blob */
    tpm_compute_owner_blob_digest(&blob, &blobDigest);
    if (memcmp(&blob.integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* get family row */
    fr = tpm_get_family_row(blob.pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    /* verify permissions if the access was delegated */
    if (session->type == TPM_ST_DSAP) {
      if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
      if (session->familyID != fr->familyID) return TPM_DELEGATE_FAMILY;
    }
    /* update verification count */
    blob.pub.verificationCount = fr->verificationCount;
    /* update the blob digest */
    tpm_compute_owner_blob_digest(&blob, &blobDigest);
    /* marshal the blob */
    length = *outputSize = sizeof_TPM_DELEGATE_OWNER_BLOB(blob);
    ptr = *outputData = tpm_malloc(*outputSize);
    if (ptr == NULL) {
      debug("tpm_malloc() failed.");
      return TPM_NOSPACE;
    }
    if (tpm_marshal_TPM_DELEGATE_OWNER_BLOB(&ptr, &length, &blob) != 0) {
      debug("tpm_marshal_TPM_DELEGATE_OWNER_BLOB() failed.");
      tpm_free(*outputData);
      return TPM_FAIL;
    }
  } else if (inputData[0] == (TPM_TAG_DELEGATE_KEY_BLOB >> 8)
               && inputData[1] == (TPM_TAG_DELEGATE_KEY_BLOB & 0xff)) {
    TPM_DELEGATE_KEY_BLOB blob;
    TPM_DIGEST blobDigest;
    TPM_FAMILY_TABLE_ENTRY *fr;
    UINT32 length;
    BYTE *ptr;
    debug("TPM_DELEGATE_KEY_BLOB");
    /* unmarshal the blob */
    if (tpm_unmarshal_TPM_DELEGATE_KEY_BLOB(&inputData, &inputSize, &blob)) {
      debug("tpm_unmarshal_TPM_DELEGATE_KEY_BLOB() failed.");
      return TPM_FAIL;
    }
    /* validate the integrity of the blob */
    tpm_compute_key_blob_digest(&blob, &blobDigest);
    if (memcmp(&blob.integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* get family row */
    fr = tpm_get_family_row(blob.pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    /* verify permissions if the access was delegated */
    if (session->type == TPM_ST_DSAP) {
      if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
      if (session->familyID != fr->familyID) return TPM_DELEGATE_FAMILY;
    }
    /* update verification count */
    blob.pub.verificationCount = fr->verificationCount;
    /* update the blob digest */
    tpm_compute_key_blob_digest(&blob, &blobDigest);
    /* marshal the blob */
    length = *outputSize = sizeof_TPM_DELEGATE_KEY_BLOB(blob);
    ptr = *outputData = tpm_malloc(*outputSize);
    if (ptr == NULL) {
      debug("tpm_malloc() failed.");
      return TPM_NOSPACE;
    }
    if (tpm_marshal_TPM_DELEGATE_KEY_BLOB(&ptr, &length, &blob) != 0) {
      debug("tpm_marshal_TPM_DELEGATE_KEY_BLOB() failed.");
      tpm_free(*outputData);
      return TPM_FAIL;
    }
  } else {
    debug("unsupported input structure: %02x%02x", inputData[0], inputData[1]);
    return TPM_BAD_PARAMETER;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Delegate_VerifyDelegation(UINT32 delegateSize, BYTE *delegation)
{
  info("TPM_Delegate_VerifyDelegation()");
  if (delegation[0] == (TPM_TAG_DELEGATE_OWNER_BLOB >> 8)
      && delegation[1] == (TPM_TAG_DELEGATE_OWNER_BLOB & 0xff)) {
    TPM_DELEGATE_OWNER_BLOB blob;
    TPM_DIGEST blobDigest;
    TPM_FAMILY_TABLE_ENTRY *fr;
    TPM_DELEGATE_SENSITIVE sensitive;
    BYTE *sens_buf;
    debug("TPM_DELEGATE_OWNER_BLOB");
    /* unmarshal the blob */
    if (tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB(&delegation, &delegateSize, &blob)) {
      debug("tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB() failed.");
      return TPM_FAIL;
    }
    /* validate the integrity of the blob */
    tpm_compute_owner_blob_digest(&blob, &blobDigest);
    if (memcmp(&blob.integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* get family row */
    fr = tpm_get_family_row(blob.pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
    /* verify verification count */
    if (blob.pub.verificationCount != fr->verificationCount)
      return TPM_FAMILYCOUNT;
    /* decrypt and verify sensitive area */
    if (tpm_decrypt_sensitive(blob.additionalArea, blob.additionalSize,
        blob.sensitiveArea, blob.sensitiveSize, &sensitive, &sens_buf)) {
      debug("tpm_decrypt_sensitive() failed");
      return TPM_DECRYPT_ERROR;
    }
    tpm_free(sens_buf);
    if (sensitive.tag != TPM_TAG_DELEGATE_SENSITIVE) return TPM_BAD_PARAMETER;
  } else if (delegation[0] == (TPM_TAG_DELEGATE_KEY_BLOB >> 8)
          && delegation[1] == (TPM_TAG_DELEGATE_KEY_BLOB & 0xff)) {
    TPM_DELEGATE_KEY_BLOB blob;
    TPM_DIGEST blobDigest;
    TPM_FAMILY_TABLE_ENTRY *fr;
    TPM_DELEGATE_SENSITIVE sensitive;
    BYTE *sens_buf;
    debug("TPM_DELEGATE_KEY_BLOB");
    /* unmarshal the blob */
    if (tpm_unmarshal_TPM_DELEGATE_KEY_BLOB(&delegation, &delegateSize, &blob)) {
      debug("tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB() failed.");
      return TPM_FAIL;
    }
    /* validate the integrity of the blob */
    tpm_compute_key_blob_digest(&blob, &blobDigest);
    if (memcmp(&blob.integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* get family row */
    fr = tpm_get_family_row(blob.pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
    /* verify verification count */
    if (blob.pub.verificationCount != fr->verificationCount)
      return TPM_FAMILYCOUNT;
    /* decrypt and verify sensitive area */
    if (tpm_decrypt_sensitive(blob.additionalArea, blob.additionalSize,
        blob.sensitiveArea, blob.sensitiveSize, &sensitive, &sens_buf)) {
      debug("tpm_decrypt_sensitive() failed");
      return TPM_DECRYPT_ERROR;
    }
    tpm_free(sens_buf);
    if (sensitive.tag != TPM_TAG_DELEGATE_SENSITIVE) return TPM_BAD_PARAMETER;
  } else {
    debug("unsupported input structure: %02x%02x", delegation[0], delegation[1]);
    return TPM_BAD_PARAMETER;
  }
  return TPM_SUCCESS;
}


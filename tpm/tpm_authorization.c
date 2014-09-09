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
 * $Id: tpm_authorization.c 467 2011-07-19 17:36:12Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_data.h"
#include "tpm_marshalling.h"
#include "crypto/hmac.h"
#include "crypto/sha1.h"

/*
 * Authorization Changing ([TPM_Part3], Section 17)
 */

TPM_RESULT TPM_ChangeAuth(TPM_KEY_HANDLE parentHandle,
                          TPM_PROTOCOL_ID protocolID, TPM_ENCAUTH *newAuth,
                          TPM_ENTITY_TYPE entityType, UINT32 encDataSize,
                          BYTE *encData, TPM_AUTH *auth1, TPM_AUTH *auth2,
                          UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_SESSION_DATA *session;
  TPM_SECRET plainAuth;
  info("TPM_ChangeAuth()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify entity authorization */ 
  auth2->continueAuthSession = FALSE;
  session = tpm_get_auth(auth2->authHandle);
  if (session->type != TPM_ST_OIAP) return TPM_BAD_MODE; 
  /* verify parent authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_BAD_MODE;  
  /* decrypt auth */
  tpm_decrypt_auth_secret(*newAuth, session->sharedSecret,
                          &session->lastNonceEven, plainAuth);
  /* decrypt the entity, replace authData, and encrypt it again */
  if (entityType == TPM_ET_DATA) {
    TPM_SEALED_DATA seal;
    BYTE *seal_buf;
    /* decrypt entity */
    if (tpm_decrypt_sealed_data(parent, encData, encDataSize,
        &seal, &seal_buf)) return TPM_DECRYPT_ERROR;
    /* verify auth2 */
    res = tpm_verify_auth(auth2, seal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
    /* change authData and use it also for auth2 */
    memcpy(seal.authData, plainAuth, sizeof(TPM_SECRET));    
    /* encrypt entity */
    *outDataSize = parent->key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (tpm_encrypt_sealed_data(parent, &seal, *outData, outDataSize)) {
      tpm_free(encData);
      tpm_free(seal_buf);      
      return TPM_ENCRYPT_ERROR;
    }                    
    tpm_free(seal_buf); 
  } else if (entityType == TPM_ET_KEY) {
    TPM_STORE_ASYMKEY store;
    BYTE *store_buf;
    /* decrypt entity */
    if (tpm_decrypt_private_key(parent, encData, encDataSize,
        &store, &store_buf, NULL)) return TPM_DECRYPT_ERROR;
    /* verify auth2 */
    res = tpm_verify_auth(auth2, store.usageAuth, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
    /* change usageAuth and use it also for auth2 */
    memcpy(store.usageAuth, plainAuth, sizeof(TPM_SECRET));  
    /* encrypt entity */
    *outDataSize = parent->key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (tpm_encrypt_private_key(parent, &store, *outData, outDataSize)) {
      tpm_free(encData);
      tpm_free(store_buf);      
      return TPM_ENCRYPT_ERROR;
    }                    
    tpm_free(store_buf); 
  } else {
    return TPM_WRONG_ENTITYTYPE;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ChangeAuthOwner(TPM_PROTOCOL_ID protocolID, 
                               TPM_ENCAUTH *newAuth, 
                               TPM_ENTITY_TYPE entityType, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *session;
  TPM_SECRET plainAuth;
  int i;
  info("TPM_ChangeAuthOwner()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* decrypt auth */
  tpm_decrypt_auth_secret(*newAuth, session->sharedSecret,
                          &session->lastNonceEven, plainAuth);
  /* change authorization data */
  if (entityType == TPM_ET_OWNER) {
    memcpy(tpmData.permanent.data.ownerAuth, plainAuth, sizeof(TPM_SECRET));
    /* invalidate all associated sessions but the current one */
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
      if (tpmData.stany.data.sessions[i].handle == TPM_KH_OWNER
          && &tpmData.stany.data.sessions[i] != session) {
          memset(&tpmData.stany.data.sessions[i], 0, sizeof(TPM_SESSION_DATA));
      }
    }
  } else if (entityType == TPM_ET_SRK) {
    memcpy(tpmData.permanent.data.srk.usageAuth, plainAuth, sizeof(TPM_SECRET));
/* probably not correct; spec. v1.2 rev94 says nothing about authDataUsage
    tpmData.permanent.data.srk.authDataUsage = TPM_AUTH_ALWAYS;
*/
    /* invalidate all associated sessions but the current one */
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
      if (tpmData.stany.data.sessions[i].handle == TPM_KH_SRK
          && &tpmData.stany.data.sessions[i] != session) {
          memset(&tpmData.stany.data.sessions[i], 0, sizeof(TPM_SESSION_DATA));
      }
    }
  } else {
    return TPM_WRONG_ENTITYTYPE;
  }
  return TPM_SUCCESS;
}

/*
 * Authorization Sessions ([TPM_Part3], Section 18)
 */

TPM_RESULT TPM_OIAP(TPM_AUTHHANDLE *authHandle, TPM_NONCE *nonceEven)
{
  TPM_SESSION_DATA *session;
  info("TPM_OIAP()");
  /* get a free session if any is left */
  *authHandle = tpm_get_free_session(TPM_ST_OIAP);
  session = tpm_get_auth(*authHandle);
  if (session == NULL) return TPM_RESOURCES;
  /* setup session */
  tpm_get_random_bytes(nonceEven->nonce, sizeof(nonceEven->nonce));
  memcpy(&session->nonceEven, nonceEven, sizeof(TPM_NONCE));
  debug("handle = %08x", *authHandle);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_OSAP(TPM_ENTITY_TYPE entityType, UINT32 entityValue, 
                    TPM_NONCE *nonceOddOSAP, TPM_AUTHHANDLE *authHandle,
                    TPM_NONCE *nonceEven, TPM_NONCE *nonceEvenOSAP)
{
  tpm_hmac_ctx_t ctx;
  TPM_SESSION_DATA *session;
  TPM_SECRET *secret = NULL;
  info("TPM_OSAP()");
  /* get a free session if any is left */
  *authHandle = tpm_get_free_session(TPM_ST_OSAP);
  session = tpm_get_auth(*authHandle);
  if (session == NULL) return TPM_RESOURCES;
  debug("entityType = %04x, entityValue = %04x", entityType, entityValue);
  /* check whether ADIP encryption scheme is supported */
  switch (entityType & 0xFF00) {
    case TPM_ET_XOR:
      break;
    default:
      return TPM_INAPPROPRIATE_ENC;
  }
  /* get resource handle and the respective secret */
  switch (entityType & 0x00FF) {
    case TPM_ET_KEYHANDLE:
      session->handle = entityValue;
      if (session->handle == TPM_KH_OPERATOR) return TPM_BAD_HANDLE;
      if (tpm_get_key(session->handle) != NULL)
        secret = &tpm_get_key(session->handle)->usageAuth;
      else
        debug("TPM_OSAP failed(): tpm_get_key(handle) == NULL");
      break;
    case TPM_ET_OWNER:
    case TPM_ET_VERIFICATION_AUTH:
      session->handle = TPM_KH_OWNER;
      if (tpmData.permanent.flags.owned)
        secret = &tpmData.permanent.data.ownerAuth;
      break;
    case TPM_ET_SRK:
      session->handle = TPM_KH_SRK;
      if (tpmData.permanent.data.srk.payload)
        secret = &tpmData.permanent.data.srk.usageAuth;
      break;
    case TPM_ET_COUNTER:
      session->handle = entityValue;
      if (tpm_get_counter(session->handle) != NULL)
        secret = &tpm_get_counter(session->handle)->usageAuth;
      break;
    case TPM_ET_NV:
      session->handle = entityValue;
      if (tpm_get_nvs(session->handle) != NULL)
        secret = &tpm_get_nvs(session->handle)->authValue;
      break;
    default:
      return TPM_BAD_PARAMETER;
  }
  if (secret == NULL) {
    debug("TPM_OSAP failed(): secret == NULL");
    memset(session, 0, sizeof(*session));
    return TPM_BAD_PARAMETER;
  }
  /* save entity type */
  session->entityType = entityType;
  /* generate nonces */
  tpm_get_random_bytes(nonceEven->nonce, sizeof(nonceEven->nonce));
  memcpy(&session->nonceEven, nonceEven, sizeof(TPM_NONCE));
  tpm_get_random_bytes(nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
  /* compute shared secret */
  tpm_hmac_init(&ctx, *secret, sizeof(*secret));
  tpm_hmac_update(&ctx, nonceEvenOSAP->nonce, sizeof(nonceEvenOSAP->nonce));
  tpm_hmac_update(&ctx, nonceOddOSAP->nonce, sizeof(nonceOddOSAP->nonce));
  tpm_hmac_final(&ctx, session->sharedSecret);
  debug("handle = %08x", *authHandle);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_DSAP(TPM_ENTITY_TYPE entityType, TPM_KEY_HANDLE keyHandle,
                    TPM_NONCE *nonceOddDSAP, UINT32 entityValueSize,
                    BYTE *entityValue, TPM_AUTHHANDLE *authHandle,
                    TPM_NONCE *nonceEven, TPM_NONCE *nonceEvenDSAP)
{
  tpm_hmac_ctx_t ctx;
  TPM_SESSION_DATA *session;
  TPM_SECRET secret;
  TPM_FAMILY_TABLE_ENTRY *fr;
  info("TPM_DSAP()");
  /* get a free session if any is left */
  *authHandle = tpm_get_free_session(TPM_ST_DSAP);
  session = tpm_get_auth(*authHandle);
  if (session == NULL) return TPM_RESOURCES;
  debug("entityType = %04x, entityValueSize = %04x", entityType, entityValueSize);
  /* decode entity value and get respective secret */
  if (entityType == TPM_ET_DEL_OWNER_BLOB) {
    TPM_DELEGATE_OWNER_BLOB blob;
    TPM_DELEGATE_SENSITIVE sens;
    BYTE *sens_buf;
    TPM_DIGEST blobDigest;
    /* unmarshal the entity value */
    if (tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB(&entityValue,
                                              &entityValueSize, &blob)
        || blob.tag != TPM_TAG_DELEGATE_OWNER_BLOB) return TPM_WRONG_ENTITYTYPE;
    /* validate the integrity of the blob */
    tpm_compute_owner_blob_digest(&blob, &blobDigest);
    if (memcmp(&blob.integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* get family table row */
    debug("family id = %d", blob.pub.familyID);
    fr = tpm_get_family_row(blob.pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
    if (fr->verificationCount != blob.pub.verificationCount) return TPM_FAIL;
    /* decrypt sensitive data */
    if (tpm_decrypt_sensitive(blob.additionalArea, blob.additionalSize,
          blob.sensitiveArea, blob.sensitiveSize, &sens, &sens_buf)) {
      debug("tpm_decrypt_sensitive() failed");
      return TPM_DECRYPT_ERROR;
    }
    if (sens.tag != TPM_TAG_DELEGATE_SENSITIVE) {
      tpm_free(sens_buf);
      return TPM_BAD_DELEGATE;
    }
    memcpy(&secret, &sens.authValue, sizeof(TPM_SECRET));
    memcpy(&session->permissions, &blob.pub.permissions, sizeof(TPM_DELEGATIONS));
    session->handle = TPM_KH_OWNER;
    session->familyID = blob.pub.familyID;
    tpm_free(sens_buf);
  } else if (entityType == TPM_ET_DEL_ROW) {
    UINT32 row;
    TPM_DELEGATE_TABLE_ROW *dr;
    if (tpm_unmarshal_UINT32(&entityValue, &entityValueSize, &row))
      return TPM_WRONG_ENTITYTYPE;
    debug("row number = %d", row);
    dr = tpm_get_delegate_row(row);
    if (dr == NULL) return TPM_BADINDEX;
    fr = tpm_get_family_row(dr->pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
    if (fr->verificationCount != dr->pub.verificationCount) return TPM_FAIL;
    memcpy(&secret, dr->authValue, sizeof(TPM_SECRET));
    memcpy(&session->permissions, &dr->pub.permissions, sizeof(TPM_DELEGATIONS));
    session->handle = keyHandle;
    session->familyID = dr->pub.familyID;
  } else if (entityType == TPM_ET_DEL_KEY_BLOB) {
    TPM_DELEGATE_KEY_BLOB blob;
    TPM_DELEGATE_SENSITIVE sens;
    BYTE *sens_buf;
    TPM_DIGEST blobDigest;
    TPM_KEY_DATA *key;
    TPM_PUBKEY pubKey;
    /* unmarshal the entity value */
    if (tpm_unmarshal_TPM_DELEGATE_KEY_BLOB(&entityValue,
                                            &entityValueSize, &blob)
        || blob.tag != TPM_TAG_DELEGATE_KEY_BLOB) return TPM_WRONG_ENTITYTYPE;
    /* validate the integrity of the blob */
    tpm_compute_key_blob_digest(&blob, &blobDigest);
    if (memcmp(&blob.integrityDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_AUTHFAIL;
    /* validate key digest */
    key = tpm_get_key(keyHandle);
    if (key == NULL) return TPM_KEYNOTFOUND;
    if (tpm_extract_pubkey(key, &pubKey) != 0) {
      debug("tpm_extract_pubkey() failed.");
      return TPM_FAIL;
    }
    if (tpm_compute_pubkey_digest(&pubKey, &blobDigest) != 0) {
      debug("tpm_compute_pubkey_digest() failed.");
      free_TPM_PUBKEY(pubKey);
      return TPM_FAIL;
    }
    free_TPM_PUBKEY(pubKey);
    if (memcmp(&blob.pubKeyDigest, &blobDigest, sizeof(TPM_DIGEST)) != 0)
      return TPM_KEYNOTFOUND;
    /* get family table row */
    debug("family id = %d", blob.pub.familyID);
    fr = tpm_get_family_row(blob.pub.familyID);
    if (fr == NULL) return TPM_BADINDEX;
    if (!(fr->flags & TPM_FAMFLAG_ENABLED)) return TPM_DISABLED_CMD;
    if (fr->verificationCount != blob.pub.verificationCount) return TPM_FAIL;
    /* decrypt sensitive data */
    if (tpm_decrypt_sensitive(blob.additionalArea, blob.additionalSize,
          blob.sensitiveArea, blob.sensitiveSize, &sens, &sens_buf)) {
      debug("tpm_decrypt_sensitive() failed");
      return TPM_DECRYPT_ERROR;
   }
   if (sens.tag != TPM_TAG_DELEGATE_SENSITIVE) {
     tpm_free(sens_buf);
     return TPM_BAD_DELEGATE;
   }
   memcpy(&secret, &sens.authValue, sizeof(TPM_SECRET));
   memcpy(&session->permissions, &blob.pub.permissions, sizeof(TPM_DELEGATIONS));
   session->handle = keyHandle;
   session->familyID = blob.pub.familyID;
   tpm_free(sens_buf);
  } else {
    return TPM_BAD_PARAMETER;
  }
  /* save entity type */
  session->entityType = entityType;
  /* generate nonces */
  tpm_get_random_bytes(nonceEven->nonce, sizeof(nonceEven->nonce));
  memcpy(&session->nonceEven, nonceEven, sizeof(TPM_NONCE));
  tpm_get_random_bytes(nonceEvenDSAP->nonce, sizeof(nonceEvenDSAP->nonce));
  /* compute shared secret */
  tpm_hmac_init(&ctx, secret, sizeof(secret));
  tpm_hmac_update(&ctx, nonceEvenDSAP->nonce, sizeof(nonceEvenDSAP->nonce));
  tpm_hmac_update(&ctx, nonceOddDSAP->nonce, sizeof(nonceOddDSAP->nonce));
  tpm_hmac_final(&ctx, session->sharedSecret);
  debug("handle = %08x", *authHandle);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SetOwnerPointer(TPM_ENTITY_TYPE entityType, UINT32 entityValue)
{
  info("TPM_SetOwnerPointer() is not supported");
  return TPM_DISABLED_CMD;
}

#define IS_SET(val, mask) (((val) & (mask)) == (mask))

static BOOL is_owner_delegation_permitted(TPM_COMMAND_CODE ordinal,
                                          UINT32 per1, UINT32 per2)
{
  switch (ordinal) {
    case TPM_ORD_SetOrdinalAuditStatus:
      return IS_SET(per1, TPM_DELEGATE_SetOrdinalAuditStatus);
    case TPM_ORD_DirWriteAuth:
      return IS_SET(per1, TPM_DELEGATE_DirWriteAuth);
    case TPM_ORD_CMK_ApproveMA:
      return IS_SET(per1, TPM_DELEGATE_CMK_ApproveMA);
    case TPM_ORD_NV_WriteValue:
      return IS_SET(per1, TPM_DELEGATE_NV_WriteValue);
    case TPM_ORD_CMK_CreateTicket:
      return IS_SET(per1, TPM_DELEGATE_CMK_CreateTicket);
    case TPM_ORD_NV_ReadValue:
      return IS_SET(per1, TPM_DELEGATE_NV_ReadValue);
    case TPM_ORD_Delegate_LoadOwnerDelegation:
      return IS_SET(per1, TPM_DELEGATE_Delegate_LoadOwnerDelegation);
    case TPM_ORD_DAA_Join:
      return IS_SET(per1, TPM_DELEGATE_DAA_Join);
    case TPM_ORD_AuthorizeMigrationKey:
      return IS_SET(per1, TPM_DELEGATE_AuthorizeMigrationKey);
    case TPM_ORD_CreateMaintenanceArchive:
      return IS_SET(per1, TPM_DELEGATE_CreateMaintenanceArchive);
    case TPM_ORD_LoadMaintenanceArchive:
      return IS_SET(per1, TPM_DELEGATE_LoadMaintenanceArchive);
    case TPM_ORD_KillMaintenanceFeature:
      return IS_SET(per1, TPM_DELEGATE_KillMaintenanceFeature);
    case TPM_ORD_OwnerReadInternalPub:
      return IS_SET(per1, TPM_DELEGATE_OwnerReadInternalPub);
    case TPM_ORD_ResetLockValue:
      return IS_SET(per1, TPM_DELEGATE_ResetLockValue);
    case TPM_ORD_OwnerClear:
      return IS_SET(per1, TPM_DELEGATE_OwnerClear);
    case TPM_ORD_DisableOwnerClear:
      return IS_SET(per1, TPM_DELEGATE_DisableOwnerClear);
    case TPM_ORD_NV_DefineSpace:
      return IS_SET(per1, TPM_DELEGATE_NV_DefineSpace);
    case TPM_ORD_OwnerSetDisable:
      return IS_SET(per1, TPM_DELEGATE_OwnerSetDisable);
    case TPM_ORD_SetCapability:
      return IS_SET(per1, TPM_DELEGATE_SetCapability);
    case TPM_ORD_MakeIdentity:
      return IS_SET(per1, TPM_DELEGATE_MakeIdentity);
    case TPM_ORD_ActivateIdentity:
      return IS_SET(per1, TPM_DELEGATE_ActivateIdentity);
    case TPM_ORD_OwnerReadPubek:
      return IS_SET(per1, TPM_DELEGATE_OwnerReadPubek);
    case TPM_ORD_DisablePubekRead:
      return IS_SET(per1, TPM_DELEGATE_DisablePubekRead);
    case TPM_ORD_SetRedirection:
      return IS_SET(per1, TPM_DELEGATE_SetRedirection);
    case TPM_ORD_FieldUpgrade:
      return IS_SET(per1, TPM_DELEGATE_FieldUpgrade);
    case TPM_ORD_Delegate_UpdateVerification:
      return IS_SET(per1, TPM_DELEGATE_Delegate_UpdateVerification);
    case TPM_ORD_CreateCounter:
      return IS_SET(per1, TPM_DELEGATE_CreateCounter);
    case TPM_ORD_ReleaseCounterOwner:
      return IS_SET(per1, TPM_DELEGATE_ReleaseCounterOwner);
    case TPM_ORD_Delegate_Manage:
      return IS_SET(per1, TPM_DELEGATE_Delegate_Manage);
    case TPM_ORD_Delegate_CreateOwnerDelegation:
      return IS_SET(per1, TPM_DELEGATE_Delegate_CreateOwnerDelegation);
    case TPM_ORD_DAA_Sign:
      return IS_SET(per1, TPM_DELEGATE_DAA_Sign);
  }
  return FALSE;
}

static BOOL is_key_delegation_permitted(TPM_COMMAND_CODE ordinal,
                                        UINT32 per1, UINT32 per2)
{
  switch (ordinal) {
    case TPM_ORD_CMK_ConvertMigration:
      return IS_SET(per1, TPM_KEY_DELEGATE_CMK_ConvertMigration);
    case TPM_ORD_TickStampBlob:
      return IS_SET(per1, TPM_KEY_DELEGATE_TickStampBlob);
    case TPM_ORD_ChangeAuthAsymStart:
      return IS_SET(per1, TPM_KEY_DELEGATE_ChangeAuthAsymStart);
    case TPM_ORD_ChangeAuthAsymFinish:
      return IS_SET(per1, TPM_KEY_DELEGATE_ChangeAuthAsymFinish);
    case TPM_ORD_CMK_CreateKey:
      return IS_SET(per1, TPM_KEY_DELEGATE_CMK_CreateKey);
    case TPM_ORD_MigrateKey:
      return IS_SET(per1, TPM_KEY_DELEGATE_MigrateKey);
    case TPM_ORD_LoadKey2:
      return IS_SET(per1, TPM_KEY_DELEGATE_LoadKey2);
    case TPM_ORD_EstablishTransport:
      return IS_SET(per1, TPM_KEY_DELEGATE_EstablishTransport);
    case TPM_ORD_ReleaseTransportSigned:
      return IS_SET(per1, TPM_KEY_DELEGATE_ReleaseTransportSigned);
    case TPM_ORD_Quote2:
      return IS_SET(per1, TPM_KEY_DELEGATE_Quote2);
    case TPM_ORD_Sealx:
      return IS_SET(per1, TPM_KEY_DELEGATE_Sealx);
    case TPM_ORD_MakeIdentity:
      return IS_SET(per1, TPM_KEY_DELEGATE_MakeIdentity);
    case TPM_ORD_ActivateIdentity:
      return IS_SET(per1, TPM_KEY_DELEGATE_ActivateIdentity);
    case TPM_ORD_GetAuditDigestSigned:
      return IS_SET(per1, TPM_KEY_DELEGATE_GetAuditDigestSigned);
    case TPM_ORD_Sign:
      return IS_SET(per1, TPM_KEY_DELEGATE_Sign);
    case TPM_ORD_CertifyKey2:
      return IS_SET(per1, TPM_KEY_DELEGATE_CertifyKey2);
    case TPM_ORD_CertifyKey:
      return IS_SET(per1, TPM_KEY_DELEGATE_CertifyKey);
    case TPM_ORD_CreateWrapKey:
      return IS_SET(per1, TPM_KEY_DELEGATE_CreateWrapKey);
    case TPM_ORD_CMK_CreateBlob:
      return IS_SET(per1, TPM_KEY_DELEGATE_CMK_CreateBlob);
    case TPM_ORD_CreateMigrationBlob:
      return IS_SET(per1, TPM_KEY_DELEGATE_CreateMigrationBlob);
    case TPM_ORD_ConvertMigrationBlob:
      return IS_SET(per1, TPM_KEY_DELEGATE_ConvertMigrationBlob);
    case TPM_ORD_Delegate_CreateKeyDelegation:
      return IS_SET(per1, TPM_KEY_DELEGATE_Delegate_CreateKeyDelegation);
    case TPM_ORD_ChangeAuth:
      return IS_SET(per1, TPM_KEY_DELEGATE_ChangeAuth);
    case TPM_ORD_GetPubKey:
      return IS_SET(per1, TPM_KEY_DELEGATE_GetPubKey);
    case TPM_ORD_Quote:
      return IS_SET(per1, TPM_KEY_DELEGATE_Quote);
    case TPM_ORD_Unseal:
      return IS_SET(per1, TPM_KEY_DELEGATE_Unseal);
    case TPM_ORD_Seal:
      return IS_SET(per1, TPM_KEY_DELEGATE_Seal);
    case TPM_ORD_LoadKey:
      return IS_SET(per1, TPM_KEY_DELEGATE_LoadKey);
  }
  return FALSE;
}

TPM_RESULT tpm_verify_auth(TPM_AUTH *auth, TPM_SECRET secret,
                           TPM_HANDLE handle)
{
  tpm_hmac_ctx_t ctx;
  TPM_SESSION_DATA *session;
  BYTE digest[SHA1_DIGEST_LENGTH];

  info("tpm_verify_auth()");
  debug("handle = %08x", auth->authHandle);
  /* get dedicated authorization or transport session */
  session = tpm_get_auth(auth->authHandle);
  if (session == NULL) session = tpm_get_transport(auth->authHandle);
  if (session == NULL) return TPM_INVALID_AUTHHANDLE;
  /* setup authorization */
  if (session->type == TPM_ST_OIAP) {
    debug("[TPM_ST_OIAP]");
    /* We copy the secret because it might be deleted or invalidated
       afterwards, but we need it again for authorizing the response. */
    memcpy(session->sharedSecret, secret, sizeof(TPM_SECRET));
  } else if (session->type == TPM_ST_OSAP) {
    debug("[TPM_ST_OSAP]");
    if (session->handle != handle) return TPM_AUTHFAIL;
  } else if (session->type == TPM_ST_DSAP) {
    debug("[TPM_ST_DSAP]");
    if (session->handle != handle) return TPM_AUTHFAIL;
    /* check permissions */
    debug("delegation type = %d", session->permissions.delegateType);
    if (session->permissions.delegateType == TPM_DEL_OWNER_BITS) {
      if (!is_owner_delegation_permitted(auth->ordinal,
             session->permissions.per1, session->permissions.per2))
        return TPM_DISABLED_CMD;
    } else if (session->permissions.delegateType == TPM_DEL_KEY_BITS) {
      if (!is_key_delegation_permitted(auth->ordinal,
             session->permissions.per1, session->permissions.per2))
        return TPM_DISABLED_CMD;
    } else {
      return TPM_AUTHFAIL;
    }
  } else if (session->type == TPM_ST_TRANSPORT) {
    debug("[TPM_ST_TRANSPORT]");
    memcpy(session->sharedSecret, session->transInternal.authData,
           sizeof(TPM_SECRET));
  } else {
    return TPM_INVALID_AUTHHANDLE;
  }
  memcpy(auth->secret, session->sharedSecret, sizeof(TPM_SECRET));
  /* verify authorization */
  tpm_hmac_init(&ctx, auth->secret, sizeof(auth->secret));
  tpm_hmac_update(&ctx, auth->digest, sizeof(auth->digest));
  tpm_hmac_update(&ctx, session->nonceEven.nonce, sizeof(session->nonceEven.nonce));
  tpm_hmac_update(&ctx, auth->nonceOdd.nonce, sizeof(auth->nonceOdd.nonce));
  tpm_hmac_update(&ctx, &auth->continueAuthSession, 1);
  tpm_hmac_final(&ctx, digest);
  if (memcmp(digest, auth->auth, sizeof(auth->auth))) return TPM_AUTHFAIL;
  /* generate new nonceEven */
  memcpy(&session->lastNonceEven, &session->nonceEven, sizeof(TPM_NONCE));
  tpm_get_random_bytes(auth->nonceEven.nonce, sizeof(auth->nonceEven.nonce));
  memcpy(&session->nonceEven, &auth->nonceEven, sizeof(TPM_NONCE));
  return TPM_SUCCESS;
}

void tpm_decrypt_auth_secret(TPM_ENCAUTH encAuth, TPM_SECRET secret,
                             TPM_NONCE *nonce, TPM_SECRET plainAuth)
{
  unsigned int i;
  tpm_sha1_ctx_t ctx;
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, secret, sizeof(TPM_SECRET));
  tpm_sha1_update(&ctx, nonce->nonce, sizeof(nonce->nonce));
  tpm_sha1_final(&ctx, plainAuth);
  for (i = 0; i < sizeof(TPM_SECRET); i++)
    plainAuth[i] ^= encAuth[i];
}

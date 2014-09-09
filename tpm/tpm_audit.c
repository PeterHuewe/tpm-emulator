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
 * $Id: tpm_audit.c 385 2010-02-17 15:41:28Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_marshalling.h"
#include "tpm_handles.h"
#include <crypto/sha1.h>

/*
 * Auditing ([TPM_Part3], Section 8)
 * The TPM generates an audit event in response to the TPM executing a 
 * function that has the audit flag set to TRUE for that function. The 
 * TPM maintains an extended value for all audited operations. 
 */
 
#define AUDIT_STATUS tpmData.permanent.data.ordinalAuditStatus

void tpm_audit_request(TPM_COMMAND_CODE ordinal, TPM_REQUEST *req)
{
  tpm_sha1_ctx_t sha1_ctx;
  BYTE buf[sizeof_TPM_AUDIT_EVENT_IN(x)], *ptr;
  UINT32 len;
  TPM_COMMAND_CODE ord = ordinal & TPM_ORD_INDEX_MASK;
  if (ord < TPM_ORD_MAX
      && (AUDIT_STATUS[ord / 8] & (1 << (ord & 0x07)))) {
    info("tpm_audit_request()");
    /* is there already an audit session running? */
    if (!tpmData.stany.data.auditSession) {       
      tpmData.stany.data.auditSession = TRUE;
      tpmData.permanent.data.auditMonotonicCounter++;
    }
    /* update audit digest */
    ptr = buf; len = sizeof(buf);
    tpm_marshal_TPM_TAG(&ptr, &len, TPM_TAG_AUDIT_EVENT_IN);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &len, ordinal);
    tpm_sha1_init(&sha1_ctx);
    tpm_sha1_update(&sha1_ctx, req->param, req->paramSize);
    tpm_sha1_final(&sha1_ctx, ptr);
    ptr += 20; len -= 20;
    tpm_marshal_TPM_TAG(&ptr, &len, TPM_TAG_COUNTER_VALUE);
    tpm_marshal_UINT32(&ptr, &len, 0);
    tpm_marshal_UINT32(&ptr, &len, tpmData.permanent.data.auditMonotonicCounter);
    tpm_sha1_init(&sha1_ctx);
    tpm_sha1_update(&sha1_ctx, tpmData.stany.data.auditDigest.digest, sizeof(TPM_DIGEST));
    tpm_sha1_update(&sha1_ctx, buf, sizeof(buf));
    tpm_sha1_final(&sha1_ctx, tpmData.stany.data.auditDigest.digest);
  }
}

void tpm_audit_response(TPM_COMMAND_CODE ordinal, TPM_RESPONSE *rsp)
{
  tpm_sha1_ctx_t sha1_ctx;
  BYTE buf[sizeof_TPM_AUDIT_EVENT_OUT(x)], *ptr;
  UINT32 len;
  TPM_COMMAND_CODE ord = ordinal & TPM_ORD_INDEX_MASK;
  if (ord < TPM_ORD_MAX
      && (AUDIT_STATUS[ord / 8] & (1 << (ord & 0x07)))) {
    info("tpm_audit_response()");
    /* update audit digest */
    ptr = buf; len = sizeof(buf);
    tpm_marshal_TPM_TAG(&ptr, &len, TPM_TAG_AUDIT_EVENT_OUT);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &len, ordinal);
    tpm_sha1_init(&sha1_ctx);
    tpm_sha1_update(&sha1_ctx, rsp->param, rsp->paramSize);
    tpm_sha1_final(&sha1_ctx, ptr);
    ptr += 20; len -= 20;
    tpm_marshal_TPM_TAG(&ptr, &len, TPM_TAG_COUNTER_VALUE);
    tpm_marshal_UINT32(&ptr, &len, 0);
    tpm_marshal_UINT32(&ptr, &len, tpmData.permanent.data.auditMonotonicCounter);
    tpm_marshal_TPM_RESULT(&ptr, &len, rsp->result);
    tpm_sha1_init(&sha1_ctx);
    tpm_sha1_update(&sha1_ctx, tpmData.stany.data.auditDigest.digest, sizeof(TPM_DIGEST));
    tpm_sha1_update(&sha1_ctx, buf, sizeof(buf));
    tpm_sha1_final(&sha1_ctx, tpmData.stany.data.auditDigest.digest);
  }
}

/* number of bits to represent 0, 1, 2, 3 ... */
static uint8_t bits[] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 }; 

TPM_RESULT TPM_GetAuditDigest(UINT32 startOrdinal, 
                              TPM_COUNTER_VALUE *counterValue, 
                              TPM_DIGEST *auditDigest, BOOL *more,
                              UINT32 *ordSize, UINT32 **ordList)
{
  UINT32 i, j, len, *ptr;
  info("TPM_GetAuditDigest()");
  /* compute (maximal) size of the ordinal list */
  for (len = 0, i = startOrdinal/8; i < TPM_ORD_MAX/8; i++) {
    len += bits[AUDIT_STATUS[i] & 0x0f];
    len += bits[(AUDIT_STATUS[i] >> 4) & 0x0f];  
  }
  /* setup ordinal list */
  ptr = *ordList = tpm_malloc(len);
  if (ptr == NULL) return TPM_FAIL;
  for (*ordSize = 0, i = startOrdinal/8; i < TPM_ORD_MAX/8; i++) {
    if (AUDIT_STATUS[i]) for (j = 0; j < 8; j++) {
      if ((AUDIT_STATUS[i] & (1 << j)) && i * 8 + j > startOrdinal) {
        *ptr++ = i * 8 + j;
        *ordSize += 4;
      }      
    } 
  }
  counterValue->tag = TPM_TAG_COUNTER_VALUE;
  memset(counterValue->label, 0, sizeof(counterValue->label));
  counterValue->counter = tpmData.permanent.data.auditMonotonicCounter;
  memcpy(auditDigest, &tpmData.stany.data.auditDigest, sizeof(TPM_DIGEST));
  if (more != NULL) *more = FALSE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_GetAuditDigestSigned(TPM_KEY_HANDLE keyHandle, 
                                    BOOL closeAudit, TPM_NONCE *antiReplay,
                                    TPM_AUTH *auth1,
                                    TPM_COUNTER_VALUE *counterValue,
                                    TPM_DIGEST *auditDigest,
                                    TPM_DIGEST *ordinalDigest,
                                    UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  UINT32 ordSize;
  UINT32 *ordList;
  BYTE buf[TPM_ORD_MAX * 4];
  BYTE *ptr;
  UINT32 len;
  tpm_sha1_ctx_t ctx;
  info("TPM_GetAuditDigestSigned()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  if (key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_IDENTITY
      && key->keyUsage != TPM_KEY_LEGACY) return TPM_INVALID_KEYUSAGE;
  /* verify authorization */ 
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  /* get audit digest */    
  res = TPM_GetAuditDigest(0, counterValue, auditDigest, NULL,
                           &ordSize, &ordList);
  if (res != TPM_SUCCESS) return res;
  /* allocate buffer memory */
  len = sizeof(buf);
  ptr = buf;
  if (tpm_marshal_UINT32_ARRAY(&ptr, &len, ordList, ordSize/4) != 0) {
    debug("tpm_marshal_UINT32_ARRAY() failed.");
    tpm_free(ordList);
    return TPM_FAIL;
  }
  tpm_free(ordList);
  /* compute ordinal digest */
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, buf, ordSize);
  tpm_sha1_final(&ctx, ordinalDigest->digest);
  /* setup a TPM_SIGN_INFO structure */
  memset(buf, 0, sizeof(buf));
  memcpy(&buf[0], "\x00\x05", 2);
  memcpy(&buf[2], "ADIG", 4);
  memcpy(&buf[6], antiReplay->nonce, 20);
  len = sizeof(buf) - 26;
  ptr = &buf[26];
  if (tpm_marshal_UINT32(&ptr, &len,
        20 + sizeof_TPM_COUNTER_VALUE((*counterValue)) + 20) != 0) {
    debug("tpm_marshal_UINT32() failed.");
    return TPM_FAIL;
  }
  memcpy(ptr, auditDigest->digest, 20);
  len -= 20;
  ptr += 20;
  if (tpm_marshal_TPM_COUNTER_VALUE(&ptr, &len, counterValue) != 0) {
    debug("tpm_marshal_TPM_COUNTER_VALUE() failed.");
    return TPM_FAIL;
  }
  memcpy(ptr, ordinalDigest->digest, 20);
  /* check key usage */
  if (closeAudit) {
    if (key->keyUsage == TPM_KEY_IDENTITY) {
      memset(&tpmData.stany.data.auditDigest, 0, sizeof(TPM_DIGEST));
    } else {
      return TPM_INVALID_KEYUSAGE;
    }
  }
  /* sign data */
  if (key->sigScheme == TPM_SS_RSASSAPKCS1v15_SHA1) {
    debug("TPM_SS_RSASSAPKCS1v15_SHA1");
    len = 30 + 20 + sizeof_TPM_COUNTER_VALUE((*counterValue)) + 20;
    tpm_sha1_init(&ctx);
    tpm_sha1_update(&ctx, buf, len);
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

TPM_RESULT TPM_SetOrdinalAuditStatus(TPM_COMMAND_CODE ordinalToAudit,
                                     BOOL auditState, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_SetOrdinalAuditStatus()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* set ordinal's audit status */
  if (ordinalToAudit > TPM_ORD_MAX) return TPM_BADINDEX;
  ordinalToAudit &= TPM_ORD_INDEX_MASK;
  if (auditState) {
    AUDIT_STATUS[ordinalToAudit / 8] |= (1 << (ordinalToAudit & 0x07));
  } else {
    AUDIT_STATUS[ordinalToAudit / 8] &= ~(1 << (ordinalToAudit & 0x07)); 
  }
  return TPM_SUCCESS;
}


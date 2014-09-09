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
 * $Id: tpm_cmd_handler.c 467 2011-07-19 17:36:12Z mast $
 */

#include "tpm_marshalling.h"
#include "tpm_commands.h"
#include "crypto/sha1.h"
#include "crypto/hmac.h"
#include "tpm_data.h"
#include "tpm_handles.h"

#ifdef MTM_EMULATOR
#include "mtm/mtm_commands.h"
#endif

UINT32 tpm_get_in_param_offset(TPM_COMMAND_CODE ordinal)
{
  switch (ordinal) {
    case TPM_ORD_ActivateIdentity:
    case TPM_ORD_ChangeAuth:
    case TPM_ORD_ChangeAuthAsymStart:
    case TPM_ORD_CMK_ConvertMigration:
    case TPM_ORD_CMK_CreateBlob:
    case TPM_ORD_CMK_CreateKey:
    case TPM_ORD_ConvertMigrationBlob:
    case TPM_ORD_CreateMigrationBlob:
    case TPM_ORD_CreateWrapKey:
    case TPM_ORD_Delegate_CreateKeyDelegation:
    case TPM_ORD_DSAP:
    case TPM_ORD_EstablishTransport:
    case TPM_ORD_EvictKey:
    case TPM_ORD_FlushSpecific:
    case TPM_ORD_GetAuditDigestSigned:
    case TPM_ORD_GetPubKey:
    case TPM_ORD_KeyControlOwner:
    case TPM_ORD_LoadKey:
    case TPM_ORD_LoadKey2:
    case TPM_ORD_MigrateKey:
    case TPM_ORD_Quote:
    case TPM_ORD_Quote2:
    case TPM_ORD_ReleaseTransportSigned:
    case TPM_ORD_SaveKeyContext:
    case TPM_ORD_Seal:
    case TPM_ORD_Sealx:
    case TPM_ORD_SetRedirection:
    case TPM_ORD_Sign:
    case TPM_ORD_TickStampBlob:
    case TPM_ORD_UnBind:
    case TPM_ORD_Unseal:
    case TPM_ORD_DAA_Join:
    case TPM_ORD_DAA_Sign:
      return 4;

    case TPM_ORD_CertifyKey:
    case TPM_ORD_CertifyKey2:
    case TPM_ORD_ChangeAuthAsymFinish:
      return 8;

    case TPM_ORD_OSAP:
      return 26;

    default:
      return 0;
  }
}

UINT32 tpm_get_out_param_offset(TPM_COMMAND_CODE ordinal)
{
  switch (ordinal) {

    case TPM_ORD_EstablishTransport:
    case TPM_ORD_LoadKey2:
      return 4;

    case TPM_ORD_OIAP:
      return 24;

    case TPM_ORD_OSAP:
      return 44;

    default:
      return 0;
  }
}
  
void tpm_compute_in_param_digest(TPM_REQUEST *req)
{
  tpm_sha1_ctx_t sha1;
  UINT32 offset = tpm_get_in_param_offset(req->ordinal);

  /* compute SHA1 hash */
  if (offset <= req->paramSize) {
    tpm_sha1_init(&sha1);
    tpm_sha1_update_be32(&sha1, req->ordinal);
    /* skip all handles at the beginning */
    tpm_sha1_update(&sha1, req->param + offset, req->paramSize - offset);
    tpm_sha1_final(&sha1, req->auth1.digest);
    memcpy(req->auth2.digest, req->auth1.digest, sizeof(req->auth1.digest));
  }
}

void tpm_compute_out_param_digest(TPM_COMMAND_CODE ordinal, TPM_RESPONSE *rsp)
{
  tpm_sha1_ctx_t sha1;
  UINT32 offset = tpm_get_out_param_offset(ordinal);

  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update_be32(&sha1, rsp->result);
  tpm_sha1_update_be32(&sha1, ordinal);
  tpm_sha1_update(&sha1, rsp->param + offset, rsp->paramSize - offset);
  tpm_sha1_final(&sha1, rsp->auth1->digest);
  if (rsp->auth2 != NULL) memcpy(rsp->auth2->digest, 
    rsp->auth1->digest, sizeof(rsp->auth1->digest));
}

static TPM_RESULT execute_TPM_Startup(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_STARTUP_TYPE startupType;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_STARTUP_TYPE(&ptr, &len, &startupType)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_Startup(startupType);
}

static TPM_RESULT execute_TPM_SaveState(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_SaveState();
}

static TPM_RESULT execute_TPM_SelfTestFull(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_SelfTestFull();
}

static TPM_RESULT execute_TPM_ContinueSelfTest(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_ContinueSelfTest();
}

static TPM_RESULT execute_TPM_GetTestResult(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* execute command */
  res = TPM_GetTestResult(&outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_SetOwnerInstall(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  BOOL state;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_BOOL(&ptr, &len, &state)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SetOwnerInstall(state);
}

static TPM_RESULT execute_TPM_OwnerSetDisable(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  BOOL disableState;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_BOOL(&ptr, &len, &disableState)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_OwnerSetDisable(disableState, &req->auth1);
}

static TPM_RESULT execute_TPM_PhysicalEnable(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_PhysicalEnable();
}

static TPM_RESULT execute_TPM_PhysicalDisable(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_PhysicalDisable();
}

static TPM_RESULT execute_TPM_PhysicalSetDeactivated(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  BOOL state;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_BOOL(&ptr, &len, &state)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_PhysicalSetDeactivated(state);
}

static TPM_RESULT execute_TPM_SetTempDeactivated(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  return TPM_SetTempDeactivated(&req->auth1);
}

static TPM_RESULT execute_TPM_SetOperatorAuth(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_SECRET operatorAuth;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_SECRET(&ptr, &len, &operatorAuth)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SetOperatorAuth(&operatorAuth);
}

static TPM_RESULT execute_TPM_TakeOwnership(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PROTOCOL_ID protocolID;
  UINT32 encOwnerAuthSize;
  BYTE *encOwnerAuth;
  UINT32 encSrkAuthSize;
  BYTE *encSrkAuth;
  TPM_KEY srkParams;
  TPM_KEY srkPub;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PROTOCOL_ID(&ptr, &len, &protocolID)
      || tpm_unmarshal_UINT32(&ptr, &len, &encOwnerAuthSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encOwnerAuth, encOwnerAuthSize)
      || tpm_unmarshal_UINT32(&ptr, &len, &encSrkAuthSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encSrkAuth, encSrkAuthSize)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &srkParams)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_TakeOwnership(protocolID, encOwnerAuthSize, encOwnerAuth, 
    encSrkAuthSize, encSrkAuth, &srkParams, &req->auth1, &srkPub);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_KEY(srkPub);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, &srkPub)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_KEY(srkPub);
  return res;
}

static TPM_RESULT execute_TPM_OwnerClear(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  return TPM_OwnerClear(&req->auth1);
}

static TPM_RESULT execute_TPM_ForceClear(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_ForceClear();
}

static TPM_RESULT execute_TPM_DisableOwnerClear(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  return TPM_DisableOwnerClear(&req->auth1);
}

static TPM_RESULT execute_TPM_DisableForceClear(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_DisableForceClear();
}

static TPM_RESULT execute_TSC_PhysicalPresence(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PHYSICAL_PRESENCE physicalPresence;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PHYSICAL_PRESENCE(&ptr, &len, &physicalPresence)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TSC_PhysicalPresence(physicalPresence);
}

static TPM_RESULT execute_TSC_ResetEstablishmentBit(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TSC_ResetEstablishmentBit();
}

static TPM_RESULT execute_TPM_GetCapability(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_CAPABILITY_AREA capArea;
  UINT32 subCapSize;
  BYTE *subCap;
  UINT32 respSize;
  BYTE *resp = NULL;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_CAPABILITY_AREA(&ptr, &len, &capArea)
      || tpm_unmarshal_UINT32(&ptr, &len, &subCapSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &subCap, subCapSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
#ifdef MTM_EMULATOR
  res = MTM_GetCapability(capArea, subCapSize, subCap, &respSize, &resp);
#else
  res = TPM_GetCapability(capArea, subCapSize, subCap, &respSize, &resp);
#endif
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + respSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, respSize)
      || tpm_marshal_BLOB(&ptr, &len, resp, respSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(resp);
  return res;
}

static TPM_RESULT execute_TPM_SetCapability(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_CAPABILITY_AREA capArea;
  UINT32 subCapSize, setValueSize;
  BYTE *subCap, *setValue;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_CAPABILITY_AREA(&ptr, &len, &capArea)
      || tpm_unmarshal_UINT32(&ptr, &len, &subCapSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &subCap, subCapSize)
      || tpm_unmarshal_UINT32(&ptr, &len, &setValueSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &setValue, setValueSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SetCapability(capArea, subCapSize, subCap, setValueSize, setValue, &req->auth1);
}

static TPM_RESULT execute_TPM_GetCapabilityOwner(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 non_volatile_flags, volatile_flags;
  TPM_VERSION version;
  BYTE *resp = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  res = TPM_GetCapabilityOwner(&req->auth1, &version, &non_volatile_flags, &volatile_flags);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 12;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_VERSION(&ptr, &len, &version)
      || tpm_marshal_UINT32(&ptr, &len, non_volatile_flags)
      || tpm_marshal_UINT32(&ptr, &len, volatile_flags)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(resp);
  return res;
}

static TPM_RESULT execute_TPM_GetAuditDigest(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 startOrdinal;
  TPM_COUNTER_VALUE counterValue;
  TPM_DIGEST auditDigest;
  BOOL more;
  UINT32 ordSize;
  UINT32 *ordList = NULL;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &startOrdinal)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_GetAuditDigest(startOrdinal, &counterValue, &auditDigest, &more, &ordSize, &ordList);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 10 + 20 + 1 + 4 + ordSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_COUNTER_VALUE(&ptr, &len, &counterValue)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &auditDigest)
      || tpm_marshal_BOOL(&ptr, &len, more)
      || tpm_marshal_UINT32(&ptr, &len, ordSize)
      || tpm_marshal_UINT32_ARRAY(&ptr, &len, ordList, ordSize/4)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(ordList);
  return res;
}

static TPM_RESULT execute_TPM_GetAuditDigestSigned(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  BOOL closeAudit;
  TPM_NONCE antiReplay;
  TPM_COUNTER_VALUE counterValue;
  TPM_DIGEST auditDigest;
  TPM_DIGEST ordinalDigest;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_BOOL(&ptr, &len, &closeAudit)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_GetAuditDigestSigned(keyHandle, closeAudit, &antiReplay, &req->auth1,
    &counterValue, &auditDigest, &ordinalDigest, &sigSize, &sig);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 10 + 20 + 20 + 4 + sigSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_COUNTER_VALUE(&ptr, &len, &counterValue)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &auditDigest)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &ordinalDigest)
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(sig);
  return res;
}

static TPM_RESULT execute_TPM_SetOrdinalAuditStatus(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_COMMAND_CODE ordinalToAudit;
  BOOL auditState;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_COMMAND_CODE(&ptr, &len, &ordinalToAudit)
      || tpm_unmarshal_BOOL(&ptr, &len, &auditState)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SetOrdinalAuditStatus(ordinalToAudit, auditState, &req->auth1);
}

static TPM_RESULT execute_TPM_FieldUpgrade(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_FieldUpgrade();
}

static TPM_RESULT execute_TPM_SetRedirection(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_REDIR_COMMAND redirCmd;
  UINT32 inputDataSize;
  BYTE *inputData;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_REDIR_COMMAND(&ptr, &len, &redirCmd)
      || tpm_unmarshal_UINT32(&ptr, &len, &inputDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inputData, inputDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SetRedirection(keyHandle, redirCmd, inputDataSize, inputData, &req->auth1);
}

static TPM_RESULT execute_TPM_ResetLockValue(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  return TPM_ResetLockValue(&req->auth1);
}

static TPM_RESULT execute_TPM_Seal(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_ENCAUTH encAuth;
  UINT32 pcrInfoSize;
  TPM_PCR_INFO pcrInfo;
  UINT32 inDataSize;
  BYTE *inData;
  TPM_STORED_DATA sealedData;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &encAuth)
      || tpm_unmarshal_UINT32(&ptr, &len, &pcrInfoSize)
      || (pcrInfoSize > 0
          && tpm_unmarshal_TPM_PCR_INFO(&ptr, &len, &pcrInfo))
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Seal(keyHandle, &encAuth, pcrInfoSize, &pcrInfo, inDataSize, inData, 
    &req->auth1, &sealedData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_STORED_DATA(sealedData);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_STORED_DATA(&ptr, &len, &sealedData)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_STORED_DATA(sealedData);
  return res;
}

static TPM_RESULT execute_TPM_Unseal(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_STORED_DATA inData;
  UINT32 sealedDataSize;
  BYTE *secret = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_STORED_DATA(&ptr, &len, &inData)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Unseal(parentHandle, &inData, &req->auth1, &req->auth2, &sealedDataSize, &secret);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + sealedDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, sealedDataSize)
      || tpm_marshal_BLOB(&ptr, &len, secret, sealedDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(secret);
  return res;
}

static TPM_RESULT execute_TPM_UnBind(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  UINT32 inDataSize;
  BYTE *inData;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_UnBind(keyHandle, inDataSize, inData, &req->auth1, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_CreateWrapKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_ENCAUTH dataUsageAuth;
  TPM_ENCAUTH dataMigrationAuth;
  TPM_KEY keyInfo;
  TPM_KEY wrappedKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &dataUsageAuth)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &dataMigrationAuth)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &keyInfo)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateWrapKey(parentHandle, &dataUsageAuth, &dataMigrationAuth, 
    &keyInfo, &req->auth1, &wrappedKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_KEY(wrappedKey);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, &wrappedKey)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_KEY(wrappedKey);
  return res;
}

static TPM_RESULT execute_TPM_LoadKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_KEY inKey;
  TPM_KEY_HANDLE inkeyHandle;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &inKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadKey(parentHandle, &inKey, &req->auth1, &inkeyHandle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, inkeyHandle)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_LoadKey2(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_KEY inKey;
  TPM_KEY_HANDLE inkeyHandle;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &inKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadKey2(parentHandle, &inKey, &req->auth1, &inkeyHandle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, inkeyHandle)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_GetPubKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_PUBKEY pubKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_GetPubKey(keyHandle, &req->auth1, &pubKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(pubKey);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &pubKey)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(pubKey);
  return res;
}

static TPM_RESULT execute_TPM_Sealx(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_ENCAUTH encAuth;
  UINT32 pcrInfoSize;
  TPM_PCR_INFO pcrInfo;
  UINT32 inDataSize;
  BYTE *inData;
  TPM_STORED_DATA sealedData;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &encAuth)
      || tpm_unmarshal_UINT32(&ptr, &len, &pcrInfoSize)
      || (pcrInfoSize > 0
          && tpm_unmarshal_TPM_PCR_INFO(&ptr, &len, &pcrInfo))
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Sealx(keyHandle, &encAuth, pcrInfoSize, &pcrInfo, inDataSize, inData, 
    &req->auth1, &sealedData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_STORED_DATA(sealedData);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_STORED_DATA(&ptr, &len, &sealedData)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_STORED_DATA(sealedData);
  return res;
}

static TPM_RESULT execute_TPM_CreateMigrationBlob(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_MIGRATE_SCHEME migrationType;
  TPM_MIGRATIONKEYAUTH migrationKeyAuth;
  UINT32 encDataSize;
  BYTE *encData;
  UINT32 randomSize;
  BYTE *random = NULL;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_MIGRATE_SCHEME(&ptr, &len, &migrationType)
      || tpm_unmarshal_TPM_MIGRATIONKEYAUTH(&ptr, &len, &migrationKeyAuth)
      || tpm_unmarshal_UINT32(&ptr, &len, &encDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encData, encDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateMigrationBlob(parentHandle, migrationType, &migrationKeyAuth, encDataSize, 
    encData, &req->auth1, &req->auth2, &randomSize, &random, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + randomSize + 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, randomSize)
      || tpm_marshal_BLOB(&ptr, &len, random, randomSize)
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(random);
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_ConvertMigrationBlob(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  UINT32 inDataSize;
  BYTE *inData;
  UINT32 randomSize;
  BYTE *random;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, inDataSize)
      || tpm_unmarshal_UINT32(&ptr, &len, &randomSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &random, randomSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ConvertMigrationBlob(parentHandle, inDataSize, inData, randomSize, 
    random, &req->auth1, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_AuthorizeMigrationKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_MIGRATE_SCHEME migrateScheme;
  TPM_PUBKEY migrationKey;
  TPM_MIGRATIONKEYAUTH outData;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_MIGRATE_SCHEME(&ptr, &len, &migrateScheme)
      || tpm_unmarshal_TPM_PUBKEY(&ptr, &len, &migrationKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_AuthorizeMigrationKey(migrateScheme, &migrationKey, &req->auth1, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_MIGRATIONKEYAUTH(outData);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_MIGRATIONKEYAUTH(&ptr, &len, &outData)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_MIGRATIONKEYAUTH(outData);
  return res;
}

static TPM_RESULT execute_TPM_MigrateKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE maKeyHandle;
  TPM_PUBKEY pubKey;
  UINT32 inDataSize;
  BYTE *inData;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &maKeyHandle)
      || tpm_unmarshal_TPM_PUBKEY(&ptr, &len, &pubKey)
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_MigrateKey(maKeyHandle, &pubKey, inDataSize, inData, 
    &req->auth1, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_CMK_SetRestrictions(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_CMK_DELEGATE restriction;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_CMK_DELEGATE(&ptr, &len, &restriction)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_CMK_SetRestrictions(restriction, &req->auth1);
}

static TPM_RESULT execute_TPM_CMK_ApproveMA(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_DIGEST migrationAuthorityDigest;
  TPM_HMAC outData;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_DIGEST(&ptr, &len, &migrationAuthorityDigest)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CMK_ApproveMA(&migrationAuthorityDigest, &req->auth1, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_HMAC(&ptr, &len, &outData)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_CMK_CreateKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_ENCAUTH dataUsageAuth;
  TPM_KEY keyInfo;
  TPM_HMAC migrationAuthorityApproval;
  TPM_DIGEST migrationAuthorityDigest;
  TPM_KEY wrappedKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &dataUsageAuth)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &keyInfo)
      || tpm_unmarshal_TPM_HMAC(&ptr, &len, &migrationAuthorityApproval)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &migrationAuthorityDigest)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CMK_CreateKey(parentHandle, &dataUsageAuth, &keyInfo, &migrationAuthorityApproval,
    &migrationAuthorityDigest, &req->auth1, &req->auth2, &wrappedKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_KEY(wrappedKey);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, &wrappedKey)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_KEY(wrappedKey);
  return res;
}

static TPM_RESULT execute_TPM_CMK_CreateTicket(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PUBKEY verificationKey;
  TPM_DIGEST signedData;
  UINT32 signatureValueSize;
  BYTE *signatureValue;
  TPM_DIGEST sigTicket;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PUBKEY(&ptr, &len, &verificationKey)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &signedData)
      || tpm_unmarshal_UINT32(&ptr, &len, &signatureValueSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &signatureValue, signatureValueSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CMK_CreateTicket(&verificationKey, &signedData, signatureValueSize, 
    signatureValue, &req->auth1, &sigTicket);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &sigTicket)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_CMK_CreateBlob(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_MIGRATE_SCHEME migrationType;
  TPM_MIGRATIONKEYAUTH migrationKeyAuth;
  TPM_DIGEST pubSourceKeyDigest;
  UINT32 msaListSize;
  TPM_MSA_COMPOSITE msaList;
  UINT32 restrictTicketSize;
  TPM_CMK_AUTH restrictTicket;
  UINT32 sigTicketSize;
  TPM_HMAC sigTicket;
  UINT32 encDataSize;
  BYTE *encData;
  UINT32 randomSize;
  BYTE *random = NULL;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_MIGRATE_SCHEME(&ptr, &len, &migrationType)
      || tpm_unmarshal_TPM_MIGRATIONKEYAUTH(&ptr, &len, &migrationKeyAuth)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &pubSourceKeyDigest)
      || tpm_unmarshal_UINT32(&ptr, &len, &msaListSize)
      || tpm_unmarshal_TPM_MSA_COMPOSITE(&ptr, &len, &msaList)
      || tpm_unmarshal_UINT32(&ptr, &len, &restrictTicketSize)
      || (restrictTicketSize > 0
          && tpm_unmarshal_TPM_CMK_AUTH(&ptr, &len, &restrictTicket))
      || tpm_unmarshal_UINT32(&ptr, &len, &sigTicketSize)
      || (sigTicketSize > 0
          && tpm_unmarshal_TPM_HMAC(&ptr, &len, &sigTicket))
      || tpm_unmarshal_UINT32(&ptr, &len, &encDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encData, encDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CMK_CreateBlob(parentHandle, migrationType, &migrationKeyAuth,
    &pubSourceKeyDigest, &msaList,
    restrictTicketSize > 0 ? &restrictTicket : NULL,
    sigTicketSize > 0 ? &sigTicket : NULL,
    encDataSize, encData, &req->auth1, &randomSize, &random, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + randomSize + 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, randomSize)
      || tpm_marshal_BLOB(&ptr, &len, random, randomSize)
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(random);
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_CMK_ConvertMigration(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_CMK_AUTH restrictTicket;
  TPM_HMAC sigTicket;
  TPM_KEY migratedKey;
  UINT32 msaListSize;
  TPM_MSA_COMPOSITE msaList;
  UINT32 randomSize;
  BYTE *random;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_CMK_AUTH(&ptr, &len, &restrictTicket)
      || tpm_unmarshal_TPM_HMAC(&ptr, &len, &sigTicket)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &migratedKey)
      || tpm_unmarshal_UINT32(&ptr, &len, &msaListSize)
      || tpm_unmarshal_TPM_MSA_COMPOSITE(&ptr, &len, &msaList)
      || tpm_unmarshal_UINT32(&ptr, &len, &randomSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &random, randomSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CMK_ConvertMigration(parentHandle, &restrictTicket, &sigTicket, 
    &migratedKey, &msaList, randomSize, random, &req->auth1, &outDataSize,
    &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_CreateMaintenanceArchive(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  BOOL generateRandom;
  UINT32 randomSize;
  BYTE *random = NULL;
  UINT32 archiveSize;
  BYTE *archive = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_BOOL(&ptr, &len, &generateRandom)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateMaintenanceArchive(generateRandom, &req->auth1, &randomSize, 
    &random, &archiveSize, &archive);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + randomSize + 4 + archiveSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, randomSize)
      || tpm_marshal_BLOB(&ptr, &len, random, randomSize)
      || tpm_marshal_UINT32(&ptr, &len, archiveSize)
      || tpm_marshal_BLOB(&ptr, &len, archive, archiveSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(random);
  tpm_free(archive);
  return res;
}

static TPM_RESULT execute_TPM_LoadMaintenanceArchive(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 archiveSize;
  BYTE *archive;
  UINT32 sigSize;
  BYTE *sig;
  UINT32 randomSize;
  BYTE *random;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &archiveSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &archive, archiveSize)
      || tpm_unmarshal_UINT32(&ptr, &len, &sigSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &sig, sigSize)
      || tpm_unmarshal_UINT32(&ptr, &len, &randomSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &random, randomSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_LoadMaintenanceArchive(archiveSize, archive, sigSize, sig,
   randomSize, random, &req->auth1);
}

static TPM_RESULT execute_TPM_KillMaintenanceFeature(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  return TPM_KillMaintenanceFeature(&req->auth1);
}

static TPM_RESULT execute_TPM_LoadManuMaintPub(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NONCE antiReplay;
  TPM_PUBKEY pubKey;
  TPM_DIGEST checksum;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || tpm_unmarshal_TPM_PUBKEY(&ptr, &len, &pubKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadManuMaintPub(&antiReplay, &pubKey, &checksum);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &checksum)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_ReadManuMaintPub(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NONCE antiReplay;
  TPM_DIGEST checksum;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ReadManuMaintPub(&antiReplay, &checksum);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &checksum)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_SHA1Start(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 maxNumBytes;
  TPM_RESULT res;
  /* execute command */
  res = TPM_SHA1Start(&maxNumBytes);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, maxNumBytes)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_SHA1Update(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 numBytes;
  BYTE *hashData;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &numBytes)
      || tpm_unmarshal_BLOB(&ptr, &len, &hashData, numBytes)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SHA1Update(numBytes, hashData);
}

static TPM_RESULT execute_TPM_SHA1Complete(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 hashDataSize;
  BYTE *hashData;
  TPM_DIGEST hashValue;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &hashDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &hashData, hashDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_SHA1Complete(hashDataSize, hashData, &hashValue);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &hashValue)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_SHA1CompleteExtend(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCRINDEX pcrNum;
  UINT32 hashDataSize;
  BYTE *hashData;
  TPM_DIGEST hashValue;
  TPM_PCRVALUE outDigest;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCRINDEX(&ptr, &len, &pcrNum)
      || tpm_unmarshal_UINT32(&ptr, &len, &hashDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &hashData, hashDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_SHA1CompleteExtend(pcrNum, hashDataSize, hashData, &hashValue, &outDigest);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &hashValue)
      || tpm_marshal_TPM_PCRVALUE(&ptr, &len, &outDigest)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_Sign(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  UINT32 areaToSignSize;
  BYTE *areaToSign;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_UINT32(&ptr, &len, &areaToSignSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &areaToSign, areaToSignSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Sign(keyHandle, areaToSignSize, areaToSign, &req->auth1, &sigSize, &sig);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + sigSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(sig);
  return res;
}

static TPM_RESULT execute_TPM_GetRandom(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 bytesRequested;
  UINT32 randomBytesSize;
  BYTE *randomBytes = NULL;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &bytesRequested)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_GetRandom(bytesRequested, &randomBytesSize, &randomBytes);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + randomBytesSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, randomBytesSize)
      || tpm_marshal_BLOB(&ptr, &len, randomBytes, randomBytesSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(randomBytes);
  return res;
}

static TPM_RESULT execute_TPM_StirRandom(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 dataSize;
  BYTE *inData;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &dataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inData, dataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_StirRandom(dataSize, inData);
}

static TPM_RESULT execute_TPM_CertifyKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE certHandle;
  TPM_KEY_HANDLE keyHandle;
  TPM_NONCE antiReplay;
  TPM_CERTIFY_INFO certifyInfo;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &certHandle)
      || tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CertifyKey(certHandle, keyHandle, &antiReplay, &req->auth1, 
    &req->auth2, &certifyInfo, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_CERTIFY_INFO(certifyInfo) + 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CERTIFY_INFO(&ptr, &len, &certifyInfo)
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_CERTIFY_INFO(certifyInfo);
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_CertifyKey2(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_KEY_HANDLE certHandle;
  TPM_DIGEST migrationPubDigest;
  TPM_NONCE antiReplay;
  TPM_CERTIFY_INFO certifyInfo;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &certHandle)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &migrationPubDigest)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CertifyKey2(keyHandle, certHandle, &migrationPubDigest, &antiReplay, 
    &req->auth1, &req->auth2, &certifyInfo, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_CERTIFY_INFO(certifyInfo) + 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CERTIFY_INFO(&ptr, &len, &certifyInfo)
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_CERTIFY_INFO(certifyInfo);
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_CreateEndorsementKeyPair(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NONCE antiReplay;
  TPM_KEY_PARMS keyInfo;
  TPM_PUBKEY pubEndorsementKey;
  TPM_DIGEST Checksum;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || tpm_unmarshal_TPM_KEY_PARMS(&ptr, &len, &keyInfo)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateEndorsementKeyPair(&antiReplay, &keyInfo, &pubEndorsementKey, &Checksum);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(pubEndorsementKey) + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &pubEndorsementKey)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &Checksum)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(pubEndorsementKey);
  return res;
}

static TPM_RESULT execute_TPM_CreateRevocableEK(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NONCE antiReplay;
  TPM_KEY_PARMS keyInfo;
  BOOL generateReset;
  TPM_NONCE inputEKreset;
  TPM_PUBKEY pubEndorsementKey;
  TPM_DIGEST Checksum;
  TPM_NONCE outputEKreset;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || tpm_unmarshal_TPM_KEY_PARMS(&ptr, &len, &keyInfo)
      || tpm_unmarshal_BOOL(&ptr, &len, &generateReset)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &inputEKreset)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateRevocableEK(&antiReplay, &keyInfo, generateReset, 
    &inputEKreset, &pubEndorsementKey, &Checksum, &outputEKreset);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(pubEndorsementKey) + 20 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &pubEndorsementKey)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &Checksum)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &outputEKreset)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(pubEndorsementKey);
  return res;
}

static TPM_RESULT execute_TPM_RevokeTrust(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NONCE EKReset;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NONCE(&ptr, &len, &EKReset)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_RevokeTrust(&EKReset);
}

static TPM_RESULT execute_TPM_ReadPubek(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NONCE antiReplay;
  TPM_PUBKEY pubEndorsementKey;
  TPM_DIGEST checksum;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ReadPubek(&antiReplay, &pubEndorsementKey, &checksum);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(pubEndorsementKey) + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &pubEndorsementKey)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &checksum)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(pubEndorsementKey);
  return res;
}

static TPM_RESULT execute_TPM_DisablePubekRead(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  return TPM_DisablePubekRead(&req->auth1);
}

static TPM_RESULT execute_TPM_OwnerReadInternalPub(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_PUBKEY publicPortion;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_OwnerReadInternalPub(keyHandle, &req->auth1, &publicPortion);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(publicPortion);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &publicPortion)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(publicPortion);
  return res;
}

static TPM_RESULT execute_TPM_MakeIdentity(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_ENCAUTH identityAuth;
  TPM_CHOSENID_HASH labelPrivCADigest;
  TPM_KEY idKeyParams;
  TPM_KEY idKey;
  UINT32 identityBindingSize;
  BYTE *identityBinding = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &identityAuth)
      || tpm_unmarshal_TPM_CHOSENID_HASH(&ptr, &len, &labelPrivCADigest)
      || tpm_unmarshal_TPM_KEY(&ptr, &len, &idKeyParams)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_MakeIdentity(&identityAuth, &labelPrivCADigest, &idKeyParams, 
    &req->auth1, &req->auth2, &idKey, &identityBindingSize, &identityBinding);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_KEY(idKey) + 4 + identityBindingSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, &idKey)
      || tpm_marshal_UINT32(&ptr, &len, identityBindingSize)
      || tpm_marshal_BLOB(&ptr, &len, identityBinding, identityBindingSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_KEY(idKey);
  tpm_free(identityBinding);
  return res;
}

static TPM_RESULT execute_TPM_ActivateIdentity(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE idKeyHandle;
  UINT32 blobSize;
  BYTE *blob;
  TPM_SYMMETRIC_KEY symmetricKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &idKeyHandle)
      || tpm_unmarshal_UINT32(&ptr, &len, &blobSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &blob, blobSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* allocate memory for the symmetricKey data */
  symmetricKey.size = blobSize;
  symmetricKey.data = tpm_malloc(blobSize);
  if (symmetricKey.data == NULL)
    return TPM_NOSPACE;
  /* execute command */
  res = TPM_ActivateIdentity(idKeyHandle, blobSize, blob, &req->auth1, 
    &req->auth2, &symmetricKey);
  if (res != TPM_SUCCESS) {
    free_TPM_SYMMETRIC_KEY(symmetricKey);
    return res;
  }
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_SYMMETRIC_KEY(symmetricKey);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL)
    res = TPM_NOSPACE;
  else if (tpm_marshal_TPM_SYMMETRIC_KEY(&ptr, &len, &symmetricKey)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_SYMMETRIC_KEY(symmetricKey);
  return res;
}

static TPM_RESULT execute_TPM_Extend(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCRINDEX pcrNum;
  TPM_DIGEST inDigest;
  TPM_PCRVALUE outDigest;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCRINDEX(&ptr, &len, &pcrNum)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &inDigest)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
#ifdef MTM_EMULATOR
  res = MTM_Extend(pcrNum, &inDigest, &outDigest);
#else
  res = TPM_Extend(pcrNum, &inDigest, &outDigest);
#endif
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PCRVALUE(&ptr, &len, &outDigest)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_PCRRead(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCRINDEX pcrIndex;
  TPM_PCRVALUE outDigest;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCRINDEX(&ptr, &len, &pcrIndex)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_PCRRead(pcrIndex, &outDigest);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PCRVALUE(&ptr, &len, &outDigest)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_Quote(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_NONCE extrnalData;
  TPM_PCR_SELECTION targetPCR;
  TPM_PCR_COMPOSITE pcrData;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &extrnalData)
      || tpm_unmarshal_TPM_PCR_SELECTION(&ptr, &len, &targetPCR)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Quote(keyHandle, &extrnalData, &targetPCR, &req->auth1, &pcrData, &sigSize, &sig);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PCR_COMPOSITE(pcrData) + 4 + sigSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PCR_COMPOSITE(&ptr, &len, &pcrData)
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(sig);
  return res;
}

static TPM_RESULT execute_TPM_PCR_Reset(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCR_SELECTION pcrSelection;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCR_SELECTION(&ptr, &len, &pcrSelection)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
#ifdef MTM_EMULATOR
  return MTM_PCR_Reset(&pcrSelection);
#else
  return TPM_PCR_Reset(&pcrSelection);
#endif
}

static TPM_RESULT execute_TPM_Quote2(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_NONCE externalData;
  TPM_PCR_SELECTION targetPCR;
  BOOL addVersion;
  TPM_PCR_INFO_SHORT pcrData;
  UINT32 versionInfoSize;
  TPM_CAP_VERSION_INFO versionInfo;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &externalData)
      || tpm_unmarshal_TPM_PCR_SELECTION(&ptr, &len, &targetPCR)
      || tpm_unmarshal_BOOL(&ptr, &len, &addVersion)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Quote2(keyHandle, &externalData, &targetPCR, addVersion, 
    &req->auth1, &pcrData, &versionInfoSize, &versionInfo, &sigSize, &sig);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PCR_INFO_SHORT(pcrData) + 4 
    + versionInfoSize + 4 + sigSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PCR_INFO_SHORT(&ptr, &len, &pcrData)
      || tpm_marshal_UINT32(&ptr, &len, versionInfoSize)
      || ((addVersion == TRUE)
          && tpm_marshal_TPM_CAP_VERSION_INFO(&ptr, &len, &versionInfo))
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(sig);
  return res;
}

static TPM_RESULT execute_TPM_ChangeAuth(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_PROTOCOL_ID protocolID;
  TPM_ENCAUTH newAuth;
  TPM_ENTITY_TYPE entityType;
  UINT32 encDataSize;
  BYTE *encData;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_PROTOCOL_ID(&ptr, &len, &protocolID)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &newAuth)
      || tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
      || tpm_unmarshal_UINT32(&ptr, &len, &encDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encData, encDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ChangeAuth(parentHandle, protocolID, &newAuth, entityType, encDataSize, 
    encData, &req->auth1, &req->auth2, &outDataSize, &outData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_ChangeAuthOwner(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PROTOCOL_ID protocolID;
  TPM_ENCAUTH newAuth;
  TPM_ENTITY_TYPE entityType;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PROTOCOL_ID(&ptr, &len, &protocolID)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &newAuth)
      || tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_ChangeAuthOwner(protocolID, &newAuth, entityType, &req->auth1);
}

static TPM_RESULT execute_TPM_OIAP(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
  TPM_RESULT res;
  /* execute command */
  res = TPM_OIAP(&authHandle, &nonceEven);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_AUTHHANDLE(&ptr, &len, authHandle)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEven)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_OSAP(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_ENTITY_TYPE entityType;
  UINT32 entityValue;
  TPM_NONCE nonceOddOSAP;
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
  TPM_NONCE nonceEvenOSAP;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
      || tpm_unmarshal_UINT32(&ptr, &len, &entityValue)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &nonceOddOSAP)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_OSAP(entityType, entityValue, &nonceOddOSAP, &authHandle, 
    &nonceEven, &nonceEvenOSAP);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + 20 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_AUTHHANDLE(&ptr, &len, authHandle)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEven)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEvenOSAP)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_DSAP(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_ENTITY_TYPE entityType;
  TPM_KEY_HANDLE keyHandle;
  UINT32 entityValueSize;
  BYTE *entityValue;
  TPM_NONCE nonceOddDSAP;
  TPM_AUTHHANDLE authHandle;
  TPM_NONCE nonceEven;
  TPM_NONCE nonceEvenDSAP;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
      || tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &nonceOddDSAP)
      || tpm_unmarshal_UINT32(&ptr, &len, &entityValueSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &entityValue, entityValueSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_DSAP(entityType, keyHandle, &nonceOddDSAP, entityValueSize,
    entityValue, &authHandle, &nonceEven, &nonceEvenDSAP);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + 20 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_AUTHHANDLE(&ptr, &len, authHandle)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEven)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &nonceEvenDSAP)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_SetOwnerPointer(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_ENTITY_TYPE entityType;
  UINT32 entityValue;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
      || tpm_unmarshal_UINT32(&ptr, &len, &entityValue)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_SetOwnerPointer(entityType, entityValue);
}

static TPM_RESULT execute_TPM_Delegate_Manage(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_FAMILY_ID familyID;
  TPM_FAMILY_OPERATION opFlag;
  UINT32 opDataSize;
  BYTE *opData;
  UINT32 retDataSize;
  BYTE *retData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_FAMILY_ID(&ptr, &len, &familyID)
      || tpm_unmarshal_TPM_FAMILY_OPERATION(&ptr, &len, &opFlag)
      || tpm_unmarshal_UINT32(&ptr, &len, &opDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &opData, opDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Delegate_Manage(familyID, opFlag, opDataSize, opData, 
    &req->auth1, &retDataSize, &retData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + retDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, retDataSize)
      || tpm_marshal_BLOB(&ptr, &len, retData, retDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(retData);
  return res;
}

static TPM_RESULT execute_TPM_Delegate_CreateKeyDelegation(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_DELEGATE_PUBLIC publicInfo;
  TPM_ENCAUTH delAuth;
  UINT32 blobSize;
  TPM_DELEGATE_KEY_BLOB blob;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_DELEGATE_PUBLIC(&ptr, &len, &publicInfo)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &delAuth)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Delegate_CreateKeyDelegation(keyHandle, &publicInfo, &delAuth, 
    &req->auth1, &blob);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  blobSize = sizeof_TPM_DELEGATE_KEY_BLOB(blob);
  rsp->paramSize = len = 4 + blobSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, blobSize)
      || tpm_marshal_TPM_DELEGATE_KEY_BLOB(&ptr, &len, &blob)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_DELEGATE_KEY_BLOB(blob);
  return res;
}

static TPM_RESULT execute_TPM_Delegate_CreateOwnerDelegation(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  BOOL increment;
  TPM_DELEGATE_PUBLIC publicInfo;
  TPM_ENCAUTH delAuth;
  UINT32 blobSize;
  TPM_DELEGATE_OWNER_BLOB blob;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_BOOL(&ptr, &len, &increment)
      || tpm_unmarshal_TPM_DELEGATE_PUBLIC(&ptr, &len, &publicInfo)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &delAuth)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Delegate_CreateOwnerDelegation(increment, &publicInfo, &delAuth, 
    &req->auth1, &blob);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  blobSize = sizeof_TPM_DELEGATE_OWNER_BLOB(blob);
  rsp->paramSize = len = 4 + blobSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, blobSize)
      || tpm_marshal_TPM_DELEGATE_OWNER_BLOB(&ptr, &len, &blob)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_DELEGATE_OWNER_BLOB(blob);
  return res;
}

static TPM_RESULT execute_TPM_Delegate_LoadOwnerDelegation(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_DELEGATE_INDEX index;
  UINT32 blobSize;
  TPM_DELEGATE_OWNER_BLOB blob;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_DELEGATE_INDEX(&ptr, &len, &index)
      || tpm_unmarshal_UINT32(&ptr, &len, &blobSize)
      || tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB(&ptr, &len, &blob)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_Delegate_LoadOwnerDelegation(index, &blob, &req->auth1);
}

static TPM_RESULT execute_TPM_Delegate_ReadTable(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 familyTableSize;
  BYTE *familyTable = NULL;
  UINT32 delegateTableSize;
  BYTE *delegateTable = NULL;
  TPM_RESULT res;
  /* execute command */
  res = TPM_Delegate_ReadTable(&familyTableSize, &familyTable, &delegateTableSize, &delegateTable);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + familyTableSize + 4 + delegateTableSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, familyTableSize)
      || tpm_marshal_BLOB(&ptr, &len, familyTable, familyTableSize)
      || tpm_marshal_UINT32(&ptr, &len, delegateTableSize)
      || tpm_marshal_BLOB(&ptr, &len, delegateTable, delegateTableSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(familyTable);
  tpm_free(delegateTable);
  return res;
}

static TPM_RESULT execute_TPM_Delegate_UpdateVerification(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 inputSize;
  BYTE *inputData;
  UINT32 outputSize;
  BYTE *outputData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &inputSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inputData, inputSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_Delegate_UpdateVerification(inputSize, inputData, 
    &req->auth1, &outputSize, &outputData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outputSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outputSize)
      || tpm_marshal_BLOB(&ptr, &len, outputData, outputSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outputData);
  return res;
}

static TPM_RESULT execute_TPM_Delegate_VerifyDelegation(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 delegateSize;
  BYTE *delegation;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &delegateSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &delegation, delegateSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_Delegate_VerifyDelegation(delegateSize, delegation);
}

static TPM_RESULT execute_TPM_NV_DefineSpace(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NV_DATA_PUBLIC pubInfo;
  TPM_ENCAUTH encAuth;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NV_DATA_PUBLIC(&ptr, &len, &pubInfo)
      || tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &encAuth)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_NV_DefineSpace(&pubInfo, &encAuth, &req->auth1);
}

static TPM_RESULT execute_TPM_NV_WriteValue(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 dataSize;
  BYTE *data;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NV_INDEX(&ptr, &len, &nvIndex)
      || tpm_unmarshal_UINT32(&ptr, &len, &offset)
      || tpm_unmarshal_UINT32(&ptr, &len, &dataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &data, dataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_NV_WriteValue(nvIndex, offset, dataSize, data, &req->auth1);
}

static TPM_RESULT execute_TPM_NV_WriteValueAuth(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 dataSize;
  BYTE *data;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NV_INDEX(&ptr, &len, &nvIndex)
      || tpm_unmarshal_UINT32(&ptr, &len, &offset)
      || tpm_unmarshal_UINT32(&ptr, &len, &dataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &data, dataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_NV_WriteValueAuth(nvIndex, offset, dataSize, data, &req->auth1);
}

static TPM_RESULT execute_TPM_NV_ReadValue(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 inDataSize;
  UINT32 outDataSize;
  BYTE *data = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NV_INDEX(&ptr, &len, &nvIndex)
      || tpm_unmarshal_UINT32(&ptr, &len, &offset)
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_NV_ReadValue(nvIndex, offset, inDataSize, &req->auth1, &outDataSize, &data);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, data, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(data);
  return res;
}

static TPM_RESULT execute_TPM_NV_ReadValueAuth(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_NV_INDEX nvIndex;
  UINT32 offset;
  UINT32 inDataSize;
  UINT32 outDataSize;
  BYTE *data = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_NV_INDEX(&ptr, &len, &nvIndex)
      || tpm_unmarshal_UINT32(&ptr, &len, &offset)
      || tpm_unmarshal_UINT32(&ptr, &len, &inDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_NV_ReadValueAuth(nvIndex, offset, inDataSize, &req->auth1, &outDataSize, &data);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, data, outDataSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(data);
  return res;
}

static TPM_RESULT execute_TPM_KeyControlOwner(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_PUBKEY pubKey;
  UINT32 bitName;
  BOOL bitValue;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_PUBKEY(&ptr, &len, &pubKey)
      || tpm_unmarshal_UINT32(&ptr, &len, &bitName)
      || tpm_unmarshal_BOOL(&ptr, &len, &bitValue)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_KeyControlOwner(keyHandle, pubKey, bitName, bitValue, &req->auth1);
}

static TPM_RESULT execute_TPM_SaveContext(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_HANDLE handle;
  TPM_RESOURCE_TYPE resourceType;
  BYTE label[16];
  UINT32 contextSize;
  TPM_CONTEXT_BLOB contextBlob;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_HANDLE(&ptr, &len, &handle)
      || tpm_unmarshal_TPM_RESOURCE_TYPE(&ptr, &len, &resourceType)
      || tpm_unmarshal_BYTE_ARRAY(&ptr, &len, label, 16)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_SaveContext(handle, resourceType, label, &contextSize, &contextBlob);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + contextSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, contextSize)
      || tpm_marshal_TPM_CONTEXT_BLOB(&ptr, &len, &contextBlob)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_CONTEXT_BLOB(contextBlob);
  return res;
}

static TPM_RESULT execute_TPM_LoadContext(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_HANDLE entityHandle;
  BOOL keepHandle;
  UINT32 contextSize;
  TPM_CONTEXT_BLOB contextBlob;
  TPM_HANDLE handle;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_HANDLE(&ptr, &len, &entityHandle)
      || tpm_unmarshal_BOOL(&ptr, &len, &keepHandle)
      || tpm_unmarshal_UINT32(&ptr, &len, &contextSize)
      || tpm_unmarshal_TPM_CONTEXT_BLOB(&ptr, &len, &contextBlob)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadContext(entityHandle, keepHandle, contextSize, &contextBlob, &handle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_HANDLE(&ptr, &len, handle)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_FlushSpecific(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_HANDLE handle;
  TPM_RESOURCE_TYPE resourceType;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_HANDLE(&ptr, &len, &handle)
      || tpm_unmarshal_TPM_RESOURCE_TYPE(&ptr, &len, &resourceType)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
#ifdef MTM_EMULATOR
  return MTM_FlushSpecific(handle, resourceType);
#else
  return TPM_FlushSpecific(handle, resourceType);
#endif
}

static TPM_RESULT execute_TPM_GetTicks(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_CURRENT_TICKS currentTime;
  TPM_RESULT res;
  /* execute command */
  res = TPM_GetTicks(&currentTime);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 32;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, &currentTime)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_TickStampBlob(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  TPM_NONCE antiReplay;
  TPM_DIGEST digestToStamp;
  TPM_CURRENT_TICKS currentTicks;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || tpm_unmarshal_TPM_DIGEST(&ptr, &len, &digestToStamp)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_TickStampBlob(keyHandle, &antiReplay, &digestToStamp, &req->auth1, 
    &currentTicks, &sigSize, &sig);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 32 + 4 + sigSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, &currentTicks)
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(sig);
  return res;
}

static TPM_RESULT execute_TPM_EstablishTransport(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE encHandle;
  TPM_TRANSPORT_PUBLIC transPublic;
  UINT32 secretSize;
  BYTE *secret;
  TPM_TRANSHANDLE transHandle;
  TPM_MODIFIER_INDICATOR locality;
  TPM_CURRENT_TICKS currentTicks;
  TPM_NONCE transNonce;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &encHandle)
      || tpm_unmarshal_TPM_TRANSPORT_PUBLIC(&ptr, &len, &transPublic)
      || tpm_unmarshal_UINT32(&ptr, &len, &secretSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &secret, secretSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_EstablishTransport(encHandle, &transPublic, secretSize, secret, 
    &req->auth1, &transHandle, &locality, &currentTicks, &transNonce);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + 4 + 32 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_TRANSHANDLE(&ptr, &len, transHandle)
      || tpm_marshal_TPM_MODIFIER_INDICATOR(&ptr, &len,  locality)
      || tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, &currentTicks)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &transNonce)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_ExecuteTransport(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 inWrappedCmdSize;
  BYTE *inWrappedCmd;
  UINT64 currentTicks;
  TPM_MODIFIER_INDICATOR locality;
  UINT32 outWrappedCmdSize;
  BYTE *outWrappedCmd = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &inWrappedCmdSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &inWrappedCmd, inWrappedCmdSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ExecuteTransport(inWrappedCmdSize, inWrappedCmd, &req->auth1, 
    &currentTicks, &locality, &outWrappedCmdSize, &outWrappedCmd);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 8 + 4 + 4 + outWrappedCmdSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT64(&ptr, &len, currentTicks)
      || tpm_marshal_TPM_MODIFIER_INDICATOR(&ptr, &len, locality)
      || tpm_marshal_UINT32(&ptr, &len, outWrappedCmdSize)
      || tpm_marshal_BLOB(&ptr, &len, outWrappedCmd, outWrappedCmdSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outWrappedCmd);
  return res;
}

static TPM_RESULT execute_TPM_ReleaseTransportSigned(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE key;
  TPM_NONCE antiReplay;
  TPM_MODIFIER_INDICATOR locality;
  TPM_CURRENT_TICKS currentTicks;
  UINT32 signSize;
  BYTE *signature = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &key)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ReleaseTransportSigned(key, &antiReplay, &req->auth1, &req->auth2, 
    &locality, &currentTicks, &signSize, &signature);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + 32 + 4 + signSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_MODIFIER_INDICATOR(&ptr, &len, locality)
      || tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, &currentTicks)
      || tpm_marshal_UINT32(&ptr, &len, signSize)
      || tpm_marshal_BLOB(&ptr, &len, signature, signSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(signature);
  return res;
}

static TPM_RESULT execute_TPM_CreateCounter(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_ENCAUTH authData;
  BYTE label[4];
  TPM_COUNT_ID countID;
  TPM_COUNTER_VALUE counterValue;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_ENCAUTH(&ptr, &len, &authData)
      || tpm_unmarshal_BYTE_ARRAY(&ptr, &len, label, 4)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_CreateCounter(&authData, label, &req->auth1, &countID, &counterValue);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + sizeof_TPM_COUNTER_VALUE(counterValue);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_COUNT_ID(&ptr, &len, countID)
      || tpm_marshal_TPM_COUNTER_VALUE(&ptr, &len, &counterValue)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_IncrementCounter(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_COUNT_ID countID;
  TPM_COUNTER_VALUE count;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_COUNT_ID(&ptr, &len, &countID)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_IncrementCounter(countID, &req->auth1, &count);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 10;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_COUNTER_VALUE(&ptr, &len, &count)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_ReadCounter(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_COUNT_ID countID;
  TPM_COUNTER_VALUE count;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_COUNT_ID(&ptr, &len, &countID)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ReadCounter(countID, &count);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 10;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_COUNTER_VALUE(&ptr, &len, &count)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_ReleaseCounter(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_COUNT_ID countID;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_COUNT_ID(&ptr, &len, &countID)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
#ifdef MTM_EMULATOR
  return MTM_ReleaseCounter(countID, &req->auth1);
#else
  return TPM_ReleaseCounter(countID, &req->auth1);
#endif
}

static TPM_RESULT execute_TPM_ReleaseCounterOwner(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_COUNT_ID countID;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_COUNT_ID(&ptr, &len, &countID)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
#ifdef MTM_EMULATOR
  return MTM_ReleaseCounterOwner(countID, &req->auth1);
#else
  return TPM_ReleaseCounterOwner(countID, &req->auth1);
#endif
}

static TPM_RESULT execute_TPM_DAA_Join(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_HANDLE handle;
  BYTE stage;
  UINT32 inputSize0;
  BYTE *inputData0;
  UINT32 inputSize1;
  BYTE *inputData1;
  TPM_COMMAND_CODE ordinal;
  UINT32 outputSize;
  BYTE *outputData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_HANDLE(&ptr, &len, &handle)
      || tpm_unmarshal_BYTE(&ptr, &len, &stage)
      || tpm_unmarshal_UINT32(&ptr, &len, &inputSize0)
      || tpm_unmarshal_BLOB(&ptr, &len, &inputData0, inputSize0)
      || tpm_unmarshal_UINT32(&ptr, &len, &inputSize1)
      || tpm_unmarshal_BLOB(&ptr, &len, &inputData1, inputSize1)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_DAA_Join(handle, stage, inputSize0, inputData0, inputSize1, 
    inputData1, &req->auth1, &ordinal, &outputSize, &outputData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outputSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outputSize)
      || tpm_marshal_BLOB(&ptr, &len, outputData, outputSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outputData);
  return res;
}

static TPM_RESULT execute_TPM_DAA_Sign(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_HANDLE handle;
  BYTE stage;
  UINT32 inputSize0;
  BYTE *inputData0;
  UINT32 inputSize1;
  BYTE *inputData1;
  TPM_COMMAND_CODE ordinal;
  UINT32 outputSize;
  BYTE *outputData = NULL;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_HANDLE(&ptr, &len, &handle)
      || tpm_unmarshal_BYTE(&ptr, &len, &stage)
      || tpm_unmarshal_UINT32(&ptr, &len, &inputSize0)
      || tpm_unmarshal_BLOB(&ptr, &len, &inputData0, inputSize0)
      || tpm_unmarshal_UINT32(&ptr, &len, &inputSize1)
      || tpm_unmarshal_BLOB(&ptr, &len, &inputData1, inputSize1)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_DAA_Sign(handle, stage, inputSize0, inputData0, inputSize1, 
    inputData1, &req->auth1, &ordinal, &outputSize, &outputData);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outputSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outputSize)
      || tpm_marshal_BLOB(&ptr, &len, outputData, outputSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outputData);
  return res;
}

static TPM_RESULT execute_TPM_EvictKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE evictHandle;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &evictHandle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_EvictKey(evictHandle);
}

static TPM_RESULT execute_TPM_Terminate_Handle(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_AUTHHANDLE handle;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &len, &handle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_Terminate_Handle(handle);
}

static TPM_RESULT execute_TPM_SaveKeyContext(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE keyHandle;
  UINT32 keyContextSize;
  BYTE *keyContextBlob = NULL;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &keyHandle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_SaveKeyContext(keyHandle, &keyContextSize, &keyContextBlob);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + keyContextSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, keyContextSize)
      || tpm_marshal_BLOB(&ptr, &len, keyContextBlob, keyContextSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(keyContextBlob);
  return res;
}

static TPM_RESULT execute_TPM_LoadKeyContext(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 keyContextSize;
  BYTE *keyContextBlob;
  TPM_KEY_HANDLE keyHandle;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &keyContextSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &keyContextBlob, keyContextSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadKeyContext(keyContextSize, keyContextBlob, &keyHandle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, keyHandle)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_SaveAuthContext(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_AUTHHANDLE authandle;
  UINT32 authContextSize;
  BYTE *authContextBlob = NULL;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &len, &authandle)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_SaveAuthContext(authandle, &authContextSize, &authContextBlob);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + authContextSize;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, authContextSize)
      || tpm_marshal_BLOB(&ptr, &len, authContextBlob, authContextSize)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(authContextBlob);
  return res;
}

static TPM_RESULT execute_TPM_LoadAuthContext(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 authContextSize;
  BYTE *authContextBlob;
  TPM_KEY_HANDLE authHandle;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &authContextSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &authContextBlob, authContextSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_LoadAuthContext(authContextSize, authContextBlob, &authHandle);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, authHandle)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_DirWriteAuth(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_DIRINDEX dirIndex;
  TPM_DIRVALUE newContents;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_DIRINDEX(&ptr, &len, &dirIndex)
      || tpm_unmarshal_TPM_DIRVALUE(&ptr, &len, &newContents)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  return TPM_DirWriteAuth(dirIndex, &newContents, &req->auth1);
}

static TPM_RESULT execute_TPM_DirRead(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_DIRINDEX dirIndex;
  TPM_DIRVALUE dirContents;
  TPM_RESULT res;
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_DIRINDEX(&ptr, &len, &dirIndex)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_DirRead(dirIndex, &dirContents);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_DIRVALUE(&ptr, &len, &dirContents)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_TPM_ChangeAuthAsymStart(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE idHandle;
  TPM_NONCE antiReplay;
  TPM_KEY_PARMS inTempKey;
  TPM_CERTIFY_INFO certifyInfo;
  UINT32 sigSize;
  BYTE *sig = NULL;
  TPM_KEY_HANDLE ephHandle;
  TPM_KEY outTempKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &idHandle)
      || tpm_unmarshal_TPM_NONCE(&ptr, &len, &antiReplay)
      || tpm_unmarshal_TPM_KEY_PARMS(&ptr, &len, &inTempKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ChangeAuthAsymStart(idHandle, &antiReplay, &inTempKey, &req->auth1, 
    &certifyInfo, &sigSize, &sig, &ephHandle, &outTempKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 95 + 4 + sigSize + 4 + sizeof_TPM_KEY(outTempKey);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_CERTIFY_INFO(&ptr, &len, &certifyInfo)
      || tpm_marshal_UINT32(&ptr, &len, sigSize)
      || tpm_marshal_BLOB(&ptr, &len, sig, sigSize)
      || tpm_marshal_TPM_KEY_HANDLE(&ptr, &len, ephHandle)
      || tpm_marshal_TPM_KEY(&ptr, &len, &outTempKey)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(sig);
  free_TPM_KEY(outTempKey);
  return res;
}

static TPM_RESULT execute_TPM_ChangeAuthAsymFinish(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_KEY_HANDLE parentHandle;
  TPM_KEY_HANDLE ephHandle;
  TPM_ENTITY_TYPE entityType;
  TPM_HMAC newAuthLink;
  UINT32 newAuthSize;
  BYTE *encNewAuth;
  UINT32 encDataSize;
  BYTE *encData;
  UINT32 outDataSize;
  BYTE *outData = NULL;
  TPM_NONCE saltNonce;
  TPM_DIGEST changeProof;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &parentHandle)
      || tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &len, &ephHandle)
      || tpm_unmarshal_TPM_ENTITY_TYPE(&ptr, &len, &entityType)
      || tpm_unmarshal_TPM_HMAC(&ptr, &len, &newAuthLink)
      || tpm_unmarshal_UINT32(&ptr, &len, &newAuthSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encNewAuth, newAuthSize)
      || tpm_unmarshal_UINT32(&ptr, &len, &encDataSize)
      || tpm_unmarshal_BLOB(&ptr, &len, &encData, encDataSize)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = TPM_ChangeAuthAsymFinish(parentHandle, ephHandle, entityType, 
    &newAuthLink, newAuthSize, encNewAuth, encDataSize, encData, &req->auth1, 
    &outDataSize, &outData, &saltNonce, &changeProof);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + outDataSize + 20 + 20;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, outDataSize)
      || tpm_marshal_BLOB(&ptr, &len, outData, outDataSize)
      || tpm_marshal_TPM_NONCE(&ptr, &len, &saltNonce)
      || tpm_marshal_TPM_DIGEST(&ptr, &len, &changeProof)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  tpm_free(outData);
  return res;
}

static TPM_RESULT execute_TPM_Reset(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  /* execute command */
  return TPM_Reset();
}

static TPM_RESULT execute_TPM_OwnerReadPubek(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PUBKEY pubEndorsementKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  res = TPM_OwnerReadPubek(&req->auth1, &pubEndorsementKey);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = sizeof_TPM_PUBKEY(pubEndorsementKey);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, &pubEndorsementKey)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_PUBKEY(pubEndorsementKey);
  return res;
}

static void tpm_setup_rsp_auth(TPM_COMMAND_CODE ordinal, TPM_RESPONSE *rsp) 
{
  tpm_hmac_ctx_t hmac;

  /* compute parameter digest */
  if (ordinal != TPM_ORD_ExecuteTransport)
    tpm_compute_out_param_digest(ordinal, rsp);
  /* compute authorization values */
  switch (rsp->tag) {
    case TPM_TAG_RSP_AUTH2_COMMAND:
      tpm_hmac_init(&hmac, rsp->auth2->secret, sizeof(rsp->auth2->secret));
      tpm_hmac_update(&hmac, rsp->auth2->digest, sizeof(rsp->auth2->digest));
      tpm_hmac_update(&hmac, rsp->auth2->nonceEven.nonce, 
                  sizeof(rsp->auth2->nonceEven.nonce));
      tpm_hmac_update(&hmac, rsp->auth2->nonceOdd.nonce, 
                  sizeof(rsp->auth2->nonceOdd.nonce));
      tpm_hmac_update(&hmac, (BYTE*)&rsp->auth2->continueAuthSession, 1);
      tpm_hmac_final(&hmac, rsp->auth2->auth);
    case TPM_TAG_RSP_AUTH1_COMMAND:
      tpm_hmac_init(&hmac, rsp->auth1->secret, sizeof(rsp->auth1->secret));
      tpm_hmac_update(&hmac, rsp->auth1->digest, sizeof(rsp->auth1->digest));
      tpm_hmac_update(&hmac, rsp->auth1->nonceEven.nonce, 
        sizeof(rsp->auth1->nonceEven.nonce));
      tpm_hmac_update(&hmac, rsp->auth1->nonceOdd.nonce, 
        sizeof(rsp->auth1->nonceOdd.nonce));
      tpm_hmac_update(&hmac, (BYTE*)&rsp->auth1->continueAuthSession, 1);
      tpm_hmac_final(&hmac, rsp->auth1->auth);
      break;
  }
}

static void tpm_setup_error_response(TPM_RESULT res, TPM_RESPONSE *rsp)
{
  rsp->tag = TPM_TAG_RSP_COMMAND;
  rsp->size = 10;
  rsp->result = res;
  rsp->param = NULL;
  rsp->paramSize = 0;
}

static TPM_RESULT tpm_check_status_and_mode(TPM_REQUEST *req)
{
  /* verify that self-test succeeded */
  if (!tpmData.permanent.flags.selfTestSucceeded) return TPM_FAILEDSELFTEST;
  /* initialisation must be finished before we execute any command */
  if (tpmData.stany.flags.postInitialise) return TPM_INVALID_POSTINIT;
  /* if the TPM is deactivated only a subset of all commands can be performed */
  if ((tpmData.permanent.flags.deactivated || tpmData.stclear.flags.deactivated)
      && req->ordinal != TPM_ORD_Reset
      && req->ordinal != TPM_ORD_Init
      && req->ordinal != TPM_ORD_Startup
      && req->ordinal != TPM_ORD_SaveState
      && req->ordinal != TPM_ORD_SHA1Start
      && req->ordinal != TPM_ORD_SHA1Update
      && req->ordinal != TPM_ORD_SHA1Complete
      && req->ordinal != TPM_ORD_SHA1CompleteExtend
      && req->ordinal != TPM_ORD_OIAP
      && req->ordinal != TPM_ORD_OSAP
      && req->ordinal != TPM_ORD_DSAP
      && req->ordinal != TPM_ORD_GetCapability
      && req->ordinal != TPM_ORD_SetCapability
      && req->ordinal != TPM_ORD_TakeOwnership
      && req->ordinal != TPM_ORD_OwnerSetDisable
      && req->ordinal != TPM_ORD_PhysicalDisable
      && req->ordinal != TPM_ORD_PhysicalEnable
      && req->ordinal != TPM_ORD_PhysicalSetDeactivated
      && req->ordinal != TPM_ORD_ContinueSelfTest
      && req->ordinal != TPM_ORD_SelfTestFull
      && req->ordinal != TPM_ORD_GetTestResult
      && req->ordinal != TPM_ORD_FlushSpecific
      && req->ordinal != TPM_ORD_Terminate_Handle
      && req->ordinal != TPM_ORD_Extend
      && req->ordinal != TPM_ORD_PCR_Reset
      && req->ordinal != TPM_ORD_NV_DefineSpace
      && req->ordinal != TPM_ORD_NV_ReadValue
      && req->ordinal != TPM_ORD_NV_WriteValue
      && req->ordinal != TSC_ORD_PhysicalPresence
      && req->ordinal != TSC_ORD_ResetEstablishmentBit
      ) return TPM_DEACTIVATED;
  /* if the TPM is disabled only a subset of all commands can be performed */
  if (tpmData.permanent.flags.disable
      && req->ordinal != TPM_ORD_Reset
      && req->ordinal != TPM_ORD_Init
      && req->ordinal != TPM_ORD_Startup
      && req->ordinal != TPM_ORD_SaveState
      && req->ordinal != TPM_ORD_SHA1Start
      && req->ordinal != TPM_ORD_SHA1Update
      && req->ordinal != TPM_ORD_SHA1Complete
      && req->ordinal != TPM_ORD_SHA1CompleteExtend
      && req->ordinal != TPM_ORD_OIAP
      && req->ordinal != TPM_ORD_OSAP
      && req->ordinal != TPM_ORD_DSAP
      && req->ordinal != TPM_ORD_GetCapability
      && req->ordinal != TPM_ORD_SetCapability
      && req->ordinal != TPM_ORD_OwnerSetDisable
      && req->ordinal != TPM_ORD_PhysicalEnable
      && req->ordinal != TPM_ORD_ContinueSelfTest
      && req->ordinal != TPM_ORD_SelfTestFull
      && req->ordinal != TPM_ORD_GetTestResult
      && req->ordinal != TPM_ORD_FlushSpecific
      && req->ordinal != TPM_ORD_Terminate_Handle
      && req->ordinal != TPM_ORD_Extend
      && req->ordinal != TPM_ORD_PCR_Reset
      && req->ordinal != TPM_ORD_NV_DefineSpace
      && req->ordinal != TPM_ORD_NV_ReadValue
      && req->ordinal != TPM_ORD_NV_WriteValue
      && req->ordinal != TSC_ORD_PhysicalPresence
      && req->ordinal != TSC_ORD_ResetEstablishmentBit
      ) return TPM_DISABLED;
  return TPM_SUCCESS; 
}

void tpm_execute_command(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  TPM_RESULT res;
  
  /* setup authorisation as well as response tag and size */
  memset(rsp, 0, sizeof(*rsp));
  switch (req->tag) {
    case TPM_TAG_RQU_AUTH2_COMMAND:
      debug("[TPM_TAG_RQU_AUTH2_COMMAND]");
      rsp->tag = TPM_TAG_RSP_AUTH2_COMMAND;
      rsp->size = 10 + 2 * 41;
      rsp->auth1 = &req->auth1;
      rsp->auth2 = &req->auth2;
      break;

    case TPM_TAG_RQU_AUTH1_COMMAND:
      debug("[TPM_TAG_RQU_AUTH1_COMMAND]");
      rsp->tag = TPM_TAG_RSP_AUTH1_COMMAND;
      rsp->size = 10 + 41;
      rsp->auth1 = &req->auth1;
      break;

    case TPM_TAG_RQU_COMMAND:
      debug("[TPM_TAG_RQU_COMMAND]");
      rsp->tag = TPM_TAG_RSP_COMMAND;
      rsp->size = 10;
      break;

    default:
      info("The tag value sent to for a command (0x%02x) is invalid", req->tag);
      tpm_setup_error_response(TPM_BADTAG, rsp);
      return;
  }

  /* check whether the command is allowed in the current mode of the TPM */
  res = tpm_check_status_and_mode(req);
  if (res != TPM_SUCCESS) {
    info("tpm_check_status_and_mode(0x%02x) failed: (0x%02x) %s", 
         req->ordinal, res, tpm_error_to_string(res));
    tpm_setup_error_response(res, rsp);
    return;
  }

  /* handle command ordinal */
  switch (req->ordinal) {
    case TPM_ORD_Startup:
      debug("[TPM_ORD_Startup]");
      res = execute_TPM_Startup(req, rsp);
    break;

    case TPM_ORD_SaveState:
      debug("[TPM_ORD_SaveState]");
      res = execute_TPM_SaveState(req, rsp);
    break;

    case TPM_ORD_SelfTestFull:
      debug("[TPM_ORD_SelfTestFull]");
      res = execute_TPM_SelfTestFull(req, rsp);
    break;

    case TPM_ORD_ContinueSelfTest:
      debug("[TPM_ORD_ContinueSelfTest]");
      res = execute_TPM_ContinueSelfTest(req, rsp);
    break;

    case TPM_ORD_GetTestResult:
      debug("[TPM_ORD_GetTestResult]");
      res = execute_TPM_GetTestResult(req, rsp);
    break;

    case TPM_ORD_SetOwnerInstall:
      debug("[TPM_ORD_SetOwnerInstall]");
      res = execute_TPM_SetOwnerInstall(req, rsp);
    break;

    case TPM_ORD_OwnerSetDisable:
      debug("[TPM_ORD_OwnerSetDisable]");
      res = execute_TPM_OwnerSetDisable(req, rsp);
    break;

    case TPM_ORD_PhysicalEnable:
      debug("[TPM_ORD_PhysicalEnable]");
      res = execute_TPM_PhysicalEnable(req, rsp);
    break;

    case TPM_ORD_PhysicalDisable:
      debug("[TPM_ORD_PhysicalDisable]");
      res = execute_TPM_PhysicalDisable(req, rsp);
    break;

    case TPM_ORD_PhysicalSetDeactivated:
      debug("[TPM_ORD_PhysicalSetDeactivated]");
      res = execute_TPM_PhysicalSetDeactivated(req, rsp);
    break;

    case TPM_ORD_SetTempDeactivated:
      debug("[TPM_ORD_SetTempDeactivated]");
      res = execute_TPM_SetTempDeactivated(req, rsp);
    break;

    case TPM_ORD_SetOperatorAuth:
      debug("[TPM_ORD_SetOperatorAuth]");
      res = execute_TPM_SetOperatorAuth(req, rsp);
    break;

    case TPM_ORD_TakeOwnership:
      debug("[TPM_ORD_TakeOwnership]");
      res = execute_TPM_TakeOwnership(req, rsp);
    break;

    case TPM_ORD_OwnerClear:
      debug("[TPM_ORD_OwnerClear]");
      res = execute_TPM_OwnerClear(req, rsp);
    break;

    case TPM_ORD_ForceClear:
      debug("[TPM_ORD_ForceClear]");
      res = execute_TPM_ForceClear(req, rsp);
    break;

    case TPM_ORD_DisableOwnerClear:
      debug("[TPM_ORD_DisableOwnerClear]");
      res = execute_TPM_DisableOwnerClear(req, rsp);
    break;

    case TPM_ORD_DisableForceClear:
      debug("[TPM_ORD_DisableForceClear]");
      res = execute_TPM_DisableForceClear(req, rsp);
    break;

    case TSC_ORD_PhysicalPresence:
      res = execute_TSC_PhysicalPresence(req, rsp);
    break;

    case TSC_ORD_ResetEstablishmentBit:
      res = execute_TSC_ResetEstablishmentBit(req, rsp);
    break;

    case TPM_ORD_GetCapability:
      debug("[TPM_ORD_GetCapability]");
      res = execute_TPM_GetCapability(req, rsp);
    break;

    case TPM_ORD_SetCapability:
      debug("[TPM_ORD_SetCapability]");
      res = execute_TPM_SetCapability(req, rsp);
    break;

    case TPM_ORD_GetCapabilityOwner:
      debug("[TPM_ORD_GetCapabilityOwner]");
      res = execute_TPM_GetCapabilityOwner(req, rsp);
    break;

    case TPM_ORD_GetAuditDigest:
      debug("[TPM_ORD_GetAuditDigest]");
      res = execute_TPM_GetAuditDigest(req, rsp);
    break;

    case TPM_ORD_GetAuditDigestSigned:
      debug("[TPM_ORD_GetAuditDigestSigned]");
      res = execute_TPM_GetAuditDigestSigned(req, rsp);
    break;

    case TPM_ORD_SetOrdinalAuditStatus:
      debug("[TPM_ORD_SetOrdinalAuditStatus]");
      res = execute_TPM_SetOrdinalAuditStatus(req, rsp);
    break;

    case TPM_ORD_FieldUpgrade:
      debug("[TPM_ORD_FieldUpgrade]");
      res = execute_TPM_FieldUpgrade(req, rsp);
    break;

    case TPM_ORD_SetRedirection:
      debug("[TPM_ORD_SetRedirection]");
      res = execute_TPM_SetRedirection(req, rsp);
    break;

    case TPM_ORD_ResetLockValue:
      debug("[TPM_ORD_ResetLockValue]");
      res = execute_TPM_ResetLockValue(req, rsp);
    break;

    case TPM_ORD_Seal:
      debug("[TPM_ORD_Seal]");
      res = execute_TPM_Seal(req, rsp);
    break;

    case TPM_ORD_Unseal:
      debug("[TPM_ORD_Unseal]");
      res = execute_TPM_Unseal(req, rsp);
    break;

    case TPM_ORD_UnBind:
      debug("[TPM_ORD_UnBind]");
      res = execute_TPM_UnBind(req, rsp);
    break;

    case TPM_ORD_CreateWrapKey:
      debug("[TPM_ORD_CreateWrapKey]");
      res = execute_TPM_CreateWrapKey(req, rsp);
    break;

    case TPM_ORD_LoadKey:
      debug("[TPM_ORD_LoadKey]");
      res = execute_TPM_LoadKey(req, rsp);
    break;

    case TPM_ORD_LoadKey2:
      debug("[TPM_ORD_LoadKey2]");
      res = execute_TPM_LoadKey2(req, rsp);
    break;

    case TPM_ORD_GetPubKey:
      debug("[TPM_ORD_GetPubKey]");
      res = execute_TPM_GetPubKey(req, rsp);
    break;

    case TPM_ORD_Sealx:
      debug("[TPM_ORD_Sealx]");
      res = execute_TPM_Sealx(req, rsp);
    break;

    case TPM_ORD_CreateMigrationBlob:
      debug("[TPM_ORD_CreateMigrationBlob]");
      res = execute_TPM_CreateMigrationBlob(req, rsp);
    break;

    case TPM_ORD_ConvertMigrationBlob:
      debug("[TPM_ORD_ConvertMigrationBlob]");
      res = execute_TPM_ConvertMigrationBlob(req, rsp);
    break;

    case TPM_ORD_AuthorizeMigrationKey:
      debug("[TPM_ORD_AuthorizeMigrationKey]");
      res = execute_TPM_AuthorizeMigrationKey(req, rsp);
    break;

    case TPM_ORD_MigrateKey:
      debug("[TPM_ORD_MigrateKey]");
      res = execute_TPM_MigrateKey(req, rsp);
    break;

    case TPM_ORD_CMK_SetRestrictions:
      debug("[TPM_ORD_CMK_SetRestrictions]");
      res = execute_TPM_CMK_SetRestrictions(req, rsp);
    break;

    case TPM_ORD_CMK_ApproveMA:
      debug("[TPM_ORD_CMK_ApproveMA]");
      res = execute_TPM_CMK_ApproveMA(req, rsp);
    break;

    case TPM_ORD_CMK_CreateKey:
      debug("[TPM_ORD_CMK_CreateKey]");
      res = execute_TPM_CMK_CreateKey(req, rsp);
    break;

    case TPM_ORD_CMK_CreateTicket:
      debug("[TPM_ORD_CMK_CreateTicket]");
      res = execute_TPM_CMK_CreateTicket(req, rsp);
    break;

    case TPM_ORD_CMK_CreateBlob:
      debug("[TPM_ORD_CMK_CreateBlob]");
      res = execute_TPM_CMK_CreateBlob(req, rsp);
    break;

    case TPM_ORD_CMK_ConvertMigration:
      debug("[TPM_ORD_CMK_ConvertMigration]");
      res = execute_TPM_CMK_ConvertMigration(req, rsp);
    break;

    case TPM_ORD_CreateMaintenanceArchive:
      debug("[TPM_ORD_CreateMaintenanceArchive]");
      res = execute_TPM_CreateMaintenanceArchive(req, rsp);
    break;

    case TPM_ORD_LoadMaintenanceArchive:
      debug("[TPM_ORD_LoadMaintenanceArchive]");
      res = execute_TPM_LoadMaintenanceArchive(req, rsp);
    break;

    case TPM_ORD_KillMaintenanceFeature:
      debug("[TPM_ORD_KillMaintenanceFeature]");
      res = execute_TPM_KillMaintenanceFeature(req, rsp);
    break;

    case TPM_ORD_LoadManuMaintPub:
      debug("[TPM_ORD_LoadManuMaintPub]");
      res = execute_TPM_LoadManuMaintPub(req, rsp);
    break;

    case TPM_ORD_ReadManuMaintPub:
      debug("[TPM_ORD_ReadManuMaintPub]");
      res = execute_TPM_ReadManuMaintPub(req, rsp);
    break;

    case TPM_ORD_SHA1Start:
      debug("[TPM_ORD_SHA1Start]");
      res = execute_TPM_SHA1Start(req, rsp);
    break;

    case TPM_ORD_SHA1Update:
      debug("[TPM_ORD_SHA1Update]");
      res = execute_TPM_SHA1Update(req, rsp);
    break;

    case TPM_ORD_SHA1Complete:
      debug("[TPM_ORD_SHA1Complete]");
      res = execute_TPM_SHA1Complete(req, rsp);
    break;

    case TPM_ORD_SHA1CompleteExtend:
      debug("[TPM_ORD_SHA1CompleteExtend]");
      res = execute_TPM_SHA1CompleteExtend(req, rsp);
    break;

    case TPM_ORD_Sign:
      debug("[TPM_ORD_Sign]");
      res = execute_TPM_Sign(req, rsp);
    break;

    case TPM_ORD_GetRandom:
      debug("[TPM_ORD_GetRandom]");
      res = execute_TPM_GetRandom(req, rsp);
    break;

    case TPM_ORD_StirRandom:
      debug("[TPM_ORD_StirRandom]");
      res = execute_TPM_StirRandom(req, rsp);
    break;

    case TPM_ORD_CertifyKey:
      debug("[TPM_ORD_CertifyKey]");
      res = execute_TPM_CertifyKey(req, rsp);
    break;

    case TPM_ORD_CertifyKey2:
      debug("[TPM_ORD_CertifyKey2]");
      res = execute_TPM_CertifyKey2(req, rsp);
    break;

    case TPM_ORD_CreateEndorsementKeyPair:
      debug("[TPM_ORD_CreateEndorsementKeyPair]");
      res = execute_TPM_CreateEndorsementKeyPair(req, rsp);
    break;

    case TPM_ORD_CreateRevocableEK:
      debug("[TPM_ORD_CreateRevocableEK]");
      res = execute_TPM_CreateRevocableEK(req, rsp);
    break;

    case TPM_ORD_RevokeTrust:
      debug("[TPM_ORD_RevokeTrust]");
      res = execute_TPM_RevokeTrust(req, rsp);
    break;

    case TPM_ORD_ReadPubek:
      debug("[TPM_ORD_ReadPubek]");
      res = execute_TPM_ReadPubek(req, rsp);
    break;

    case TPM_ORD_DisablePubekRead:
      debug("[TPM_ORD_DisablePubekRead]");
      res = execute_TPM_DisablePubekRead(req, rsp);
    break;

    case TPM_ORD_OwnerReadInternalPub:
      debug("[TPM_ORD_OwnerReadInternalPub]");
      res = execute_TPM_OwnerReadInternalPub(req, rsp);
    break;

    case TPM_ORD_MakeIdentity:
      debug("[TPM_ORD_MakeIdentity]");
      res = execute_TPM_MakeIdentity(req, rsp);
    break;

    case TPM_ORD_ActivateIdentity:
      debug("[TPM_ORD_ActivateIdentity]");
      res = execute_TPM_ActivateIdentity(req, rsp);
    break;

    case TPM_ORD_Extend:
      debug("[TPM_ORD_Extend]");
      res = execute_TPM_Extend(req, rsp);
    break;

    case TPM_ORD_PCRRead:
      debug("[TPM_ORD_PCRRead]");
      res = execute_TPM_PCRRead(req, rsp);
    break;

    case TPM_ORD_Quote:
      debug("[TPM_ORD_Quote]");
      res = execute_TPM_Quote(req, rsp);
    break;

    case TPM_ORD_PCR_Reset:
      debug("[TPM_ORD_PCR_Reset]");
      res = execute_TPM_PCR_Reset(req, rsp);
    break;

    case TPM_ORD_Quote2:
      debug("[TPM_ORD_Quote2]");
      res = execute_TPM_Quote2(req, rsp);
    break;

    case TPM_ORD_ChangeAuth:
      debug("[TPM_ORD_ChangeAuth]");
      res = execute_TPM_ChangeAuth(req, rsp);
    break;

    case TPM_ORD_ChangeAuthOwner:
      debug("[TPM_ORD_ChangeAuthOwner]");
      res = execute_TPM_ChangeAuthOwner(req, rsp);
    break;

    case TPM_ORD_OIAP:
      debug("[TPM_ORD_OIAP]");
      res = execute_TPM_OIAP(req, rsp);
    break;

    case TPM_ORD_OSAP:
      debug("[TPM_ORD_OSAP]");
      res = execute_TPM_OSAP(req, rsp);
    break;

    case TPM_ORD_DSAP:
      debug("[TPM_ORD_DSAP]");
      res = execute_TPM_DSAP(req, rsp);
    break;

    case TPM_ORD_SetOwnerPointer:
      debug("[TPM_ORD_SetOwnerPointer]");
      res = execute_TPM_SetOwnerPointer(req, rsp);
    break;

    case TPM_ORD_Delegate_Manage:
      debug("[TPM_ORD_Delegate_Manage]");
      res = execute_TPM_Delegate_Manage(req, rsp);
    break;

    case TPM_ORD_Delegate_CreateKeyDelegation:
      debug("[TPM_ORD_Delegate_CreateKeyDelegation]");
      res = execute_TPM_Delegate_CreateKeyDelegation(req, rsp);
    break;

    case TPM_ORD_Delegate_CreateOwnerDelegation:
      debug("[TPM_ORD_Delegate_CreateOwnerDelegation]");
      res = execute_TPM_Delegate_CreateOwnerDelegation(req, rsp);
    break;

    case TPM_ORD_Delegate_LoadOwnerDelegation:
      debug("[TPM_ORD_Delegate_LoadOwnerDelegation]");
      res = execute_TPM_Delegate_LoadOwnerDelegation(req, rsp);
    break;

    case TPM_ORD_Delegate_ReadTable:
      debug("[TPM_ORD_Delegate_ReadTable]");
      res = execute_TPM_Delegate_ReadTable(req, rsp);
    break;

    case TPM_ORD_Delegate_UpdateVerification:
      debug("[TPM_ORD_Delegate_UpdateVerification]");
      res = execute_TPM_Delegate_UpdateVerification(req, rsp);
    break;

    case TPM_ORD_Delegate_VerifyDelegation:
      debug("[TPM_ORD_Delegate_VerifyDelegation]");
      res = execute_TPM_Delegate_VerifyDelegation(req, rsp);
    break;

    case TPM_ORD_NV_DefineSpace:
      debug("[TPM_ORD_NV_DefineSpace]");
      res = execute_TPM_NV_DefineSpace(req, rsp);
    break;

    case TPM_ORD_NV_WriteValue:
      debug("[TPM_ORD_NV_WriteValue]");
      res = execute_TPM_NV_WriteValue(req, rsp);
    break;

    case TPM_ORD_NV_WriteValueAuth:
      debug("[TPM_ORD_NV_WriteValueAuth]");
      res = execute_TPM_NV_WriteValueAuth(req, rsp);
    break;

    case TPM_ORD_NV_ReadValue:
      debug("[TPM_ORD_NV_ReadValue]");
      res = execute_TPM_NV_ReadValue(req, rsp);
    break;

    case TPM_ORD_NV_ReadValueAuth:
      debug("[TPM_ORD_NV_ReadValueAuth]");
      res = execute_TPM_NV_ReadValueAuth(req, rsp);
    break;

    case TPM_ORD_KeyControlOwner:
      debug("[TPM_ORD_KeyControlOwner]");
      res = execute_TPM_KeyControlOwner(req, rsp);
    break;

    case TPM_ORD_SaveContext:
      debug("[TPM_ORD_SaveContext]");
      res = execute_TPM_SaveContext(req, rsp);
    break;

    case TPM_ORD_LoadContext:
      debug("[TPM_ORD_LoadContext]");
      res = execute_TPM_LoadContext(req, rsp);
    break;

    case TPM_ORD_FlushSpecific:
      debug("[TPM_ORD_FlushSpecific]");
      res = execute_TPM_FlushSpecific(req, rsp);
    break;

    case TPM_ORD_GetTicks:
      debug("[TPM_ORD_GetTicks]");
      res = execute_TPM_GetTicks(req, rsp);
    break;

    case TPM_ORD_TickStampBlob:
      debug("[TPM_ORD_TickStampBlob]");
      res = execute_TPM_TickStampBlob(req, rsp);
    break;

    case TPM_ORD_EstablishTransport:
      debug("[TPM_ORD_EstablishTransport]");
      res = execute_TPM_EstablishTransport(req, rsp);
    break;

    case TPM_ORD_ExecuteTransport:
      debug("[TPM_ORD_ExecuteTransport]");
      res = execute_TPM_ExecuteTransport(req, rsp);
    break;

    case TPM_ORD_ReleaseTransportSigned:
      debug("[TPM_ORD_ReleaseTransportSigned]");
      res = execute_TPM_ReleaseTransportSigned(req, rsp);
    break;

    case TPM_ORD_CreateCounter:
      debug("[TPM_ORD_CreateCounter]");
      res = execute_TPM_CreateCounter(req, rsp);
    break;

    case TPM_ORD_IncrementCounter:
      debug("[TPM_ORD_IncrementCounter]");
      res = execute_TPM_IncrementCounter(req, rsp);
    break;

    case TPM_ORD_ReadCounter:
      debug("[TPM_ORD_ReadCounter]");
      res = execute_TPM_ReadCounter(req, rsp);
    break;

    case TPM_ORD_ReleaseCounter:
      debug("[TPM_ORD_ReleaseCounter]");
      res = execute_TPM_ReleaseCounter(req, rsp);
    break;

    case TPM_ORD_ReleaseCounterOwner:
      debug("[TPM_ORD_ReleaseCounterOwner]");
      res = execute_TPM_ReleaseCounterOwner(req, rsp);
    break;

    case TPM_ORD_DAA_Join:
      debug("[TPM_ORD_DAA_Join]");
      res = execute_TPM_DAA_Join(req, rsp);
    break;

    case TPM_ORD_DAA_Sign:
      debug("[TPM_ORD_DAA_Sign]");
      res = execute_TPM_DAA_Sign(req, rsp);
    break;

    case TPM_ORD_EvictKey:
      debug("[TPM_ORD_EvictKey]");
      res = execute_TPM_EvictKey(req, rsp);
    break;

    case TPM_ORD_Terminate_Handle:
      debug("[TPM_ORD_Terminate_Handle]");
      res = execute_TPM_Terminate_Handle(req, rsp);
    break;

    case TPM_ORD_SaveKeyContext:
      debug("[TPM_ORD_SaveKeyContext]");
      res = execute_TPM_SaveKeyContext(req, rsp);
    break;

    case TPM_ORD_LoadKeyContext:
      debug("[TPM_ORD_LoadKeyContext]");
      res = execute_TPM_LoadKeyContext(req, rsp);
    break;

    case TPM_ORD_SaveAuthContext:
      debug("[TPM_ORD_SaveAuthContext]");
      res = execute_TPM_SaveAuthContext(req, rsp);
    break;

    case TPM_ORD_LoadAuthContext:
      debug("[TPM_ORD_LoadAuthContext]");
      res = execute_TPM_LoadAuthContext(req, rsp);
    break;

    case TPM_ORD_DirWriteAuth:
      debug("[TPM_ORD_DirWriteAuth]");
      res = execute_TPM_DirWriteAuth(req, rsp);
    break;

    case TPM_ORD_DirRead:
      debug("[TPM_ORD_DirRead]");
      res = execute_TPM_DirRead(req, rsp);
    break;

    case TPM_ORD_ChangeAuthAsymStart:
      debug("[TPM_ORD_ChangeAuthAsymStart]");
      res = execute_TPM_ChangeAuthAsymStart(req, rsp);
    break;

    case TPM_ORD_ChangeAuthAsymFinish:
      debug("[TPM_ORD_ChangeAuthAsymFinish]");
      res = execute_TPM_ChangeAuthAsymFinish(req, rsp);
    break;

    case TPM_ORD_Reset:
      debug("[TPM_ORD_Reset]");
      res = execute_TPM_Reset(req, rsp);
    break;

    case TPM_ORD_OwnerReadPubek:
      debug("[TPM_ORD_OwnerReadPubek]");
      res = execute_TPM_OwnerReadPubek(req, rsp);
    break;

    default:
#ifdef MTM_EMULATOR
      res = mtm_execute_command(req, rsp);
      if (res != TPM_BAD_ORDINAL) break;
#endif
      info("The ordinal (0x%02x) was unknown or inconsistent", req->ordinal);
      tpm_setup_error_response(TPM_BAD_ORDINAL, rsp);
      return;
  }

  /* setup response */
  if (res != TPM_SUCCESS) {
    info("TPM command failed: (0x%02x) %s", res, tpm_error_to_string(res));
    tpm_setup_error_response(res, rsp);
    if (!(res & TPM_NON_FATAL)) {
      if (rsp->auth1 != NULL) rsp->auth1->continueAuthSession = FALSE;
      if (rsp->auth2 != NULL) rsp->auth2->continueAuthSession = FALSE;
    }
  } else {
    info("TPM command succeeded");
    rsp->size += rsp->paramSize;
    if (rsp->tag != TPM_TAG_RSP_COMMAND) tpm_setup_rsp_auth(req->ordinal, rsp);
    if (tpmConf & TPM_CONF_STRONG_PERSISTENCE) {
      if (tpm_store_permanent_data() != 0) {
        error("tpm_store_permanent_data() failed");
      }
    }
  }
  /* terminate authorization sessions if necessary */
  if (rsp->auth1 != NULL && !rsp->auth1->continueAuthSession) 
    TPM_FlushSpecific(rsp->auth1->authHandle, HANDLE_TO_RT(rsp->auth1->authHandle));
  if (rsp->auth2 != NULL && !rsp->auth2->continueAuthSession) 
    TPM_FlushSpecific(rsp->auth2->authHandle, TPM_RT_AUTH);
  /* if transportExclusive is set, only the execution of TPM_ExecuteTransport
     and TPM_ReleaseTransportSigned is allowed */
  if (tpmData.stany.flags.transportExclusive
      && req->ordinal != TPM_ORD_ExecuteTransport
      && req->ordinal != TPM_ORD_ReleaseTransportSigned) {
    TPM_FlushSpecific(tpmData.stany.data.transExclusive, TPM_RT_TRANS);
    tpmData.stany.flags.transportExclusive = FALSE;
  }
}

int tpm_emulator_init(uint32_t startup, uint32_t conf)
{
  /* initialize external functions and data */
  if (tpm_extern_init() != 0) return -1;
  /* initialize the emulator */
  debug("tpm_emulator_init(%d, 0x%08x)", startup, conf);
  tpmConf = conf;
#ifdef MTM_EMULATOR
  info("MTM support enabled");
#endif
  /* try to restore data, if it fails use default values */
  if (tpm_restore_permanent_data() != 0) tpm_init_data();
  TPM_Init(startup);
  return 0;
}

void tpm_emulator_shutdown()
{
  debug("tpm_emulator_shutdown()");
  if (TPM_SaveState() != TPM_SUCCESS) {
    error("TPM_SaveState() failed");
  }
  tpm_release_data();
  /* release external functions and data */
  tpm_extern_release();
}

int tpm_handle_command(const uint8_t *in, uint32_t in_size, uint8_t **out, uint32_t *out_size)
{
  TPM_REQUEST req;
  TPM_RESPONSE rsp;
  BYTE *ptr;
  UINT32 len;
  BOOL free_out;

  debug("tpm_handle_command()");

  /* we need the whole packet at once, otherwise unmarshalling will fail */
  if (tpm_unmarshal_TPM_REQUEST((uint8_t**)&in, &in_size, &req) != 0) {
    error("tpm_unmarshal_TPM_REQUEST() failed");
    return -1;
  }
  
  /* update timing ticks */
  tpm_update_ticks();
  
  /* audit request */
  tpm_audit_request(req.ordinal, &req);

  /* execute command */
  tpm_execute_command(&req, &rsp);

  /* audit response */
  tpm_audit_response(req.ordinal, &rsp);

  /* init output and marshal response */
  if (*out != NULL) {
    if (*out_size < rsp.size) {
      error("output buffer to small (%d/%d)", *out_size, rsp.size);
      tpm_free(rsp.param);
      return -1;
    }
    *out_size = len = rsp.size;
    ptr = *out;
    free_out = FALSE;
  } else {
    *out_size = len = rsp.size;
    *out = ptr = tpm_malloc(len);
    if (ptr == NULL) {
      error("tpm_malloc() failed");
      tpm_free(rsp.param);
      return -1;
    }
    free_out = TRUE;
  }
  if (tpm_marshal_TPM_RESPONSE(&ptr, &len, &rsp) != 0) {
    error("tpm_marshal_TPM_RESPONSE() failed");
    if (free_out) tpm_free(*out);
    tpm_free(rsp.param);
    return -1;
  }
  tpm_free(rsp.param);
  return 0;
}


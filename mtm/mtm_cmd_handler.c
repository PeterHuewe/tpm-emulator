/* Software-based Mobile Trusted Module (MTM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2007 Jan-Erik Ekberg <jan-erik.ekberg@nokia.com>,
 *                    Nokia Corporation and/or its subsidiary(-ies)
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
 * $Id$
 */

#include "mtm_commands.h"
#include "mtm_marshalling.h"

extern void tpm_compute_in_param_digest(TPM_REQUEST *req);

static TPM_RESULT execute_MTM_InstallRIM(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 rimCertSize;
  TPM_RIM_CERTIFICATE rimCertIn;
  TPM_RIM_CERTIFICATE rimCertOut;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &rimCertSize)
      || tpm_unmarshal_TPM_RIM_CERTIFICATE(&ptr, &len, &rimCertIn)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = MTM_InstallRIM(&rimCertIn, &req->auth1, &rimCertOut);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + sizeof_TPM_RIM_CERTIFICATE(rimCertOut);
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_UINT32(&ptr, &len, sizeof_TPM_RIM_CERTIFICATE(rimCertOut))
      || tpm_marshal_TPM_RIM_CERTIFICATE(&ptr, &len, &rimCertOut)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  free_TPM_RIM_CERTIFICATE(rimCertOut);
  return res;
}

static TPM_RESULT execute_MTM_LoadVerificationKey(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_VERIFICATION_KEY_HANDLE parentKey;
  UINT32 verificationKeySize;
  TPM_VERIFICATION_KEY verificationKey;
  TPM_VERIFICATION_KEY_HANDLE verificationKeyHandle;
  BYTE loadMethod;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_VERIFICATION_KEY_HANDLE(&ptr, &len, &parentKey)
      || tpm_unmarshal_UINT32(&ptr, &len, &verificationKeySize)
      || tpm_unmarshal_TPM_VERIFICATION_KEY(&ptr, &len, &verificationKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command  */
  res = MTM_LoadVerificationKey(parentKey, &verificationKey, &req->auth1,
    &verificationKeyHandle, &loadMethod);
  if (res != TPM_SUCCESS) return res;
  /* marshal output */
  rsp->paramSize = len = 4 + 1;
  rsp->param = ptr = tpm_malloc(len);
  if (ptr == NULL
      || tpm_marshal_TPM_VERIFICATION_KEY_HANDLE(&ptr, &len, verificationKeyHandle)
      || tpm_marshal_BYTE(&ptr, &len, loadMethod)) {
    tpm_free(rsp->param);
    res = TPM_FAIL;
  }
  return res;
}

static TPM_RESULT execute_MTM_LoadVerificationRootKeyDisable(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* execute command */
  res = MTM_LoadVerificationRootKeyDisable();
  /* marshal output */
  rsp->paramSize = 0;
  rsp->param = NULL;
  return res;
}

static TPM_RESULT execute_MTM_VerifyRIMCert(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 rimCertSize;
  TPM_RIM_CERTIFICATE rimCert;
  TPM_VERIFICATION_KEY_HANDLE rimKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &rimCertSize)
      || tpm_unmarshal_TPM_RIM_CERTIFICATE(&ptr, &len, &rimCert)
      || tpm_unmarshal_TPM_VERIFICATION_KEY_HANDLE(&ptr, &len, &rimKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = MTM_VerifyRIMCert(&rimCert, rimKey);
  /* marshal output */
  rsp->paramSize = len = 0;
  rsp->param = ptr = NULL;
  return res;
}

static TPM_RESULT execute_MTM_VerifyRIMCertAndExtend(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 rimCertSize;
  TPM_RIM_CERTIFICATE rimCert;
  TPM_VERIFICATION_KEY_HANDLE rimKey;
  TPM_PCRVALUE outDigest;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &rimCertSize)
      || tpm_unmarshal_TPM_RIM_CERTIFICATE(&ptr, &len, &rimCert)
      || tpm_unmarshal_TPM_VERIFICATION_KEY_HANDLE(&ptr, &len, &rimKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = MTM_VerifyRIMCertAndExtend(&rimCert, rimKey, &outDigest);
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

static TPM_RESULT execute_MTM_IncrementBootstrapCounter(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  UINT32 rimCertSize;
  TPM_RIM_CERTIFICATE rimCert;
  TPM_VERIFICATION_KEY_HANDLE rimKey;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_UINT32(&ptr, &len, &rimCertSize)
      || tpm_unmarshal_TPM_RIM_CERTIFICATE(&ptr, &len, &rimCert)
      || tpm_unmarshal_TPM_VERIFICATION_KEY_HANDLE(&ptr, &len, &rimKey)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = MTM_IncrementBootstrapCounter(&rimCert, rimKey);
  /* marshal output */
  rsp->paramSize = len = 0;
  rsp->param = ptr = NULL;
  return res;
}

static TPM_RESULT execute_MTM_SetVerifiedPCRSelection(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  BYTE *ptr;
  UINT32 len;
  TPM_PCR_SELECTION verifiedSelection;
  TPM_RESULT res;
  /* compute parameter digest */
  tpm_compute_in_param_digest(req);
  /* unmarshal input */
  ptr = req->param;
  len = req->paramSize;
  if (tpm_unmarshal_TPM_PCR_SELECTION(&ptr, &len, &verifiedSelection)
      || len != 0) return TPM_BAD_PARAMETER;
  /* execute command */
  res = MTM_SetVerifiedPCRSelection(&verifiedSelection, &req->auth1);
  /* marshal output */
  rsp->paramSize = len = 0;
  rsp->param = ptr = NULL;
  return res;
}


TPM_RESULT mtm_execute_command(TPM_REQUEST *req, TPM_RESPONSE *rsp)
{
  TPM_RESULT res;

  /* handle command ordinal */
  switch (req->ordinal) {
    case MTM_ORD_InstallRIM:
      debug("[MTM_ORD_InstallRIM]");
      res = execute_MTM_InstallRIM(req, rsp);
      break;

    case MTM_ORD_LoadVerificationKey:
      debug("[MTM_ORD_LoadVerificationKey]");
      res = execute_MTM_LoadVerificationKey(req, rsp);
      break;

    case MTM_ORD_LoadVerificationRootKeyDisable:
      debug("[MTM_ORD_LoadVerificationRootKeyDisable]");
      res = execute_MTM_LoadVerificationRootKeyDisable(req, rsp);
      break;

    case MTM_ORD_VerifyRIMCert:
      debug("[MTM_ORD_VerifyRIMCert]");
      res = execute_MTM_VerifyRIMCert(req, rsp);
      break;

    case MTM_ORD_VerifyRIMCertAndExtend:
      debug("[MTM_ORD_VerifyRIMCertAndExtend]");
      res = execute_MTM_VerifyRIMCertAndExtend(req, rsp);
      break;

    case MTM_ORD_IncrementBootstrapCounter:
      debug("[MTM_ORD_IncrementBootstrapCounter]");
      res = execute_MTM_IncrementBootstrapCounter(req, rsp);
      break;

    case MTM_ORD_SetVerifiedPCRSelection:
      debug("[MTM_ORD_SetVerifiedPCRSelection]");
      res = execute_MTM_SetVerifiedPCRSelection(req, rsp);
      break;

    default:
      res = TPM_BAD_ORDINAL;
      break;
  }
  return res;
}

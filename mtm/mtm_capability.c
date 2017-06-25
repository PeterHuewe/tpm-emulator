/* Software-based Mobile Trusted Module (MTM) Emulator
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
 * $Id$
 */

#include "mtm_structures.h"
#include "mtm_marshalling.h"
#include "mtm_data.h"
#include "tpm/tpm_data.h"
#include "tpm/tpm_commands.h"

static inline TPM_RESULT return_UINT32(UINT32 *respSize, BYTE **resp, UINT32 value)
{
  UINT32 len = *respSize = 4;
  BYTE *ptr = *resp = tpm_malloc(*respSize);
  if (ptr == NULL || tpm_marshal_UINT32(&ptr, &len, value)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

static inline TPM_RESULT return_BOOL(UINT32 *respSize, BYTE **resp, BOOL value)
{
  UINT32 len = *respSize = 1;
  BYTE *ptr = *resp = tpm_malloc(*respSize);
  if (ptr == NULL || tpm_marshal_BOOL(&ptr, &len, value)) {
    tpm_free(*resp);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

#define return_BYTE return_BOOL

static TPM_RESULT cap_ord(UINT32 subCapSize, BYTE *subCap,
                          UINT32 *respSize, BYTE **resp)
{
  TPM_COMMAND_CODE ord;
  if (tpm_unmarshal_TPM_COMMAND_CODE(&subCap, &subCapSize, &ord))
    return TPM_BAD_MODE;
  switch (ord) {
    case MTM_ORD_InstallRIM:
    case MTM_ORD_LoadVerificationKey:
    case MTM_ORD_LoadVerificationRootKeyDisable:
    case MTM_ORD_VerifyRIMCert:
    case MTM_ORD_VerifyRIMCertAndExtend:
    case MTM_ORD_IncrementBootstrapCounter:
    case MTM_ORD_SetVerifiedPCRSelection:
      return return_BOOL(respSize, resp, TRUE);
    default:
      return return_BOOL(respSize, resp, FALSE);
  }
}

static TPM_RESULT cap_mtm_permanent_data(UINT32 subCapSize, BYTE *subCap,
                                         UINT32 *respSize, BYTE **resp)
{
  UINT32 subCapVal, len;
  BYTE* ptr;

/* unmarshal subCap */
  if (tpm_unmarshal_UINT32(&subCap, &subCapSize, &subCapVal) != 0)
    return TPM_BAD_PARAMETER;
  switch (subCapVal) {

    case 1:
      return TPM_FAIL;
      break;

    case 2:
      *respSize = len = sizeof_TPM_PCR_SELECTION(mtmData.permanent.data.verifiedPCRs);
      *resp = ptr = tpm_malloc(*respSize);
      if (*resp == NULL 
          || tpm_marshal_TPM_PCR_SELECTION(&ptr, &len, &mtmData.permanent.data.verifiedPCRs)) {
        tpm_free(*resp);
        return TPM_FAIL;
      }
      error("[TPM_CAP_MTM_PERMANENT_DATA] SubCap 2 not Implemented");
      return TPM_FAIL; // TODO not implemented.

    case 3:
      return return_UINT32(respSize, resp,
        tpmData.permanent.data.counters[MTM_COUNTER_SELECT_BOOTSTRAP].counter);

    case 4:
      return return_UINT32(respSize, resp, mtmData.permanent.data.counterRimProtectId);

    case 5:
      return return_UINT32(respSize, resp, mtmData.permanent.data.counterStorageProtectId);

    case 6:
      return return_BYTE(respSize, resp, mtmData.permanent.data.specMajor);

    case 7:
      return return_BYTE(respSize, resp, mtmData.permanent.data.specMinor);

    case 8:
      return return_BYTE(respSize, resp, mtmData.permanent.data.loadVerificationKeyMethods);

    default:
      return TPM_BAD_PARAMETER;

  }
  return TPM_SUCCESS;
}

TPM_RESULT MTM_GetCapability(TPM_CAPABILITY_AREA capArea, UINT32 subCapSize,
                             BYTE *subCap, UINT32 *respSize, BYTE **resp)
{
  info("MTM_GetCapability()");
  switch (capArea) {

    case TPM_CAP_ORD:
      debug("[MTM_CAP_ORD]");
      TPM_RESULT res = cap_ord(subCapSize, subCap, respSize, resp);
      if (res == TPM_SUCCESS && resp[0] == FALSE) {
        res = TPM_GetCapability(capArea, subCapSize, subCap, respSize, resp);
      }
      return res;

    case TPM_CAP_MTM_PERMANENT_DATA:
      debug("[TPM_CAP_MTM_PERMANENT_DATA]");
      return cap_mtm_permanent_data(subCapSize, subCap, respSize, resp);

    default:
      return TPM_GetCapability(capArea, subCapSize, subCap, respSize, resp);

  }
}


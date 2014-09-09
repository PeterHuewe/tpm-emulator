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
 * $Id: tpm_nv_storage.c 465 2011-07-19 17:20:32Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"

/*
 * Non-volatile Storage ([TPM_Part3], Section 20)
 * This section handles the allocation and use of the TPM non-volatile storage.
 */

TPM_NV_DATA_SENSITIVE *tpm_get_nvs(TPM_NV_INDEX index)
{
  int i;
  for (i = 0; i < TPM_MAX_NVS; i++) {
    if (tpmData.permanent.data.nvStorage[i].valid
        && tpmData.permanent.data.nvStorage[i].pubInfo.nvIndex == index) {
      return &tpmData.permanent.data.nvStorage[i];
    }
  }
  return NULL;
}

static TPM_NV_DATA_SENSITIVE *tpm_get_free_nvs(void)
{
  int i;
  for (i = 0; i < TPM_MAX_NVS; i++) {
    if (!tpmData.permanent.data.nvStorage[i].valid) {
      return &tpmData.permanent.data.nvStorage[i];
    }
  }
  return NULL;
}

void tpm_nv_remove_data(TPM_NV_DATA_SENSITIVE *nv)
{
  UINT32 i;
  /* remove data */
  memcpy(tpmData.permanent.data.nvData + nv->dataIndex,
    tpmData.permanent.data.nvData + nv->dataIndex + nv->pubInfo.dataSize,
    nv->pubInfo.dataSize);
  /* adapt indices */
  for (i = 0; i < TPM_MAX_NVS; i++) {
    if (tpmData.permanent.data.nvStorage[i].valid
        && tpmData.permanent.data.nvStorage[i].dataIndex > nv->dataIndex)
      tpmData.permanent.data.nvStorage[i].dataIndex -= nv->pubInfo.dataSize;
  }
  tpmData.permanent.data.nvDataSize -= nv->pubInfo.dataSize;
  /* invalidate meta data */
  memset(tpmData.permanent.data.nvData + tpmData.permanent.data.nvDataSize,
    0xff, nv->pubInfo.dataSize);
  memset(nv, 0x00, sizeof(TPM_NV_DATA_SENSITIVE));
}

TPM_RESULT TPM_NV_DefineSpace(TPM_NV_DATA_PUBLIC *pubInfo,
                              TPM_ENCAUTH *encAuth, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_SECRET plainAuth;
  TPM_NV_DATA_SENSITIVE *nv;
  TPM_SESSION_DATA *session = NULL;
  UINT32 i;

  info("TPM_NV_DefineSpace()");
  /* lock NV storage */
  if (auth1->authHandle == TPM_INVALID_HANDLE
      && pubInfo->nvIndex == TPM_NV_INDEX_LOCK) {
    debug("nvIndex = TPM_NV_INDEX_LOCK");
    tpmData.permanent.flags.nvLocked = TRUE;
    return TPM_SUCCESS;
  }
  debug("nvIndex = %08x", pubInfo->nvIndex);
  /* verify maximal number of writes without an owner */
  if (!tpmData.permanent.flags.owned
      && ++tpmData.permanent.data.noOwnerNVWrite > TPM_MAX_NV_WRITE_NOOWNER)
    return TPM_MAXNVWRITES;
  /* if NV storage is not locked omit authorization verifications */
  if (tpmData.permanent.flags.nvLocked) {
    if (auth1->authHandle == TPM_INVALID_HANDLE) {
      /* no authorization available */
      if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
      if (tpmData.permanent.flags.owned) return TPM_OWNER_SET;
      if (pubInfo->dataSize == 0) return TPM_BAD_DATASIZE;
      memcpy(plainAuth, *encAuth, sizeof(TPM_SECRET));
    } else {
      /* verify authorization */
      res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
      if (res != TPM_SUCCESS) return res;
      session = tpm_get_auth(auth1->authHandle);
      if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
      auth1->continueAuthSession = FALSE;
      /* decrypt auth */
      tpm_decrypt_auth_secret(*encAuth, session->sharedSecret,
                              &session->lastNonceEven, plainAuth);
    }
    if (pubInfo->nvIndex & TPM_NV_INDEX_D) return TPM_BADINDEX;
  }
  /* check whether nvIndex is reserved */
  if (pubInfo->nvIndex == TPM_NV_INDEX0
      || pubInfo->nvIndex == TPM_NV_INDEX_DIR) return TPM_BADINDEX;
  /* check whether nvIndex points to a valid NV storage area */
  nv = tpm_get_nvs(pubInfo->nvIndex);
  if (nv != NULL) {
    if (tpmData.permanent.flags.nvLocked) {
      if ((nv->pubInfo.permission.attributes & TPM_NV_PER_GLOBALLOCK)
          && tpmData.stclear.flags.bGlobalLock) return TPM_AREA_LOCKED;
      if ((nv->pubInfo.permission.attributes & TPM_NV_PER_WRITE_STCLEAR)
          && nv->pubInfo.bWriteSTClear) return TPM_AREA_LOCKED;
    }
    debug("deleting NV storage area for index %08x", pubInfo->nvIndex);
    /* invalidate all associated sessions but the current one */
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
      if (tpmData.stany.data.sessions[i].handle == pubInfo->nvIndex
          && &tpmData.stany.data.sessions[i] != session) {
          memset(&tpmData.stany.data.sessions[i], 0, sizeof(TPM_SESSION_DATA));
      }
    }
    /* delete the NV storage area */
    tpm_nv_remove_data(nv);
    if (pubInfo->dataSize == 0) return TPM_SUCCESS;
  }
  /* verify pcrInfoRead and pcrInfoWrite */
  if (pubInfo->pcrInfoRead.pcrSelection.sizeOfSelect > TPM_NUM_PCR/8
      || (pubInfo->pcrInfoRead.localityAtRelease & 0x1f) == 0
      || (pubInfo->pcrInfoRead.localityAtRelease & 0xe0) != 0
      || pubInfo->pcrInfoWrite.pcrSelection.sizeOfSelect > TPM_NUM_PCR/8
      || (pubInfo->pcrInfoWrite.localityAtRelease & 0x1f) == 0
      || (pubInfo->pcrInfoWrite.localityAtRelease & 0xe0) != 0)
    return TPM_INVALID_STRUCTURE;
  /* verify that attributes are consistent */
  if ((pubInfo->permission.attributes & TPM_NV_PER_OWNERWRITE)
      && (pubInfo->permission.attributes & TPM_NV_PER_AUTHWRITE))
    return TPM_AUTH_CONFLICT;
  if ((pubInfo->permission.attributes & TPM_NV_PER_OWNERREAD)
      && (pubInfo->permission.attributes & TPM_NV_PER_AUTHREAD))
    return TPM_AUTH_CONFLICT;
  if (!(pubInfo->permission.attributes & (TPM_NV_PER_OWNERWRITE 
        | TPM_NV_PER_AUTHWRITE | TPM_NV_PER_WRITEDEFINE | TPM_NV_PER_PPWRITE))
      && pubInfo->pcrInfoWrite.localityAtRelease == 0x1f) return TPM_PER_NOWRITE;
  if (pubInfo->dataSize == 0) return TPM_BAD_PARAM_SIZE;
  /* check whether there is enough space for the new NV storage area */
  nv = tpm_get_free_nvs();
  if (pubInfo->dataSize > (TPM_MAX_NV_SIZE - tpmData.permanent.data.nvDataSize)
      || nv == NULL) return TPM_NOSPACE;
  /* return success if this was just a test */
  if (pubInfo->nvIndex == TPM_NV_INDEX_TRIAL) return TPM_SUCCESS;
  /* allocate and initialize a new NV storage area */
  nv->tag = TPM_TAG_NV_DATA_SENSITIVE;
  memcpy(&nv->pubInfo, pubInfo, sizeof(TPM_NV_DATA_PUBLIC));
  nv->pubInfo.bReadSTClear = FALSE;
  nv->pubInfo.bWriteSTClear = FALSE;
  nv->pubInfo.bWriteDefine = FALSE;
  memcpy(nv->authValue, plainAuth, sizeof(TPM_SECRET));
  nv->dataIndex = tpmData.permanent.data.nvDataSize;
  tpmData.permanent.data.nvDataSize += pubInfo->dataSize;
  nv->valid = TRUE;
  memset(tpmData.permanent.data.nvData + nv->dataIndex, 
         0xff, pubInfo->dataSize);
  return TPM_SUCCESS;
}

static TPM_RESULT nv_write(TPM_NV_DATA_SENSITIVE *nv, UINT32 offset,
                           UINT32 dataSize, BYTE *data, BOOL verify)
{
  TPM_RESULT res;
  TPM_DIGEST digest;

  if (verify) {
    /* test for physical presence if required */
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_PPWRITE)
        && !tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
    /* verify that area is not locked */
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_WRITEDEFINE)
        && nv->pubInfo.bWriteDefine) return TPM_AREA_LOCKED;
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_GLOBALLOCK)
        && tpmData.stclear.flags.bGlobalLock) return TPM_AREA_LOCKED;
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_WRITE_STCLEAR)
        && nv->pubInfo.bWriteSTClear) return TPM_AREA_LOCKED;
    /* verify locality and PCRs */
    if (!(nv->pubInfo.pcrInfoWrite.localityAtRelease
          & (1 << tpmData.stany.flags.localityModifier)))
      return TPM_BAD_LOCALITY;
    res = tpm_compute_pcr_digest(&nv->pubInfo.pcrInfoWrite.pcrSelection,
                                 &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &nv->pubInfo.pcrInfoWrite.digestAtRelease,
               sizeof(TPM_DIGEST))) return TPM_WRONGPCRVAL;
  }
  /* write data */
  if (dataSize == 0) {
    nv->pubInfo.bWriteSTClear = TRUE;
    nv->pubInfo.bWriteDefine = TRUE;
  } else {
    if (offset + dataSize > nv->pubInfo.dataSize) return TPM_NOSPACE;
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_WRITEALL)
        && dataSize != nv->pubInfo.dataSize) return TPM_NOT_FULLWRITE;
    memcpy(tpmData.permanent.data.nvData + nv->dataIndex + offset,
           data, dataSize);
  }
  nv->pubInfo.bReadSTClear = FALSE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_NV_WriteValue(TPM_NV_INDEX nvIndex, UINT32 offset,
                             UINT32 dataSize, BYTE *data, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_NV_DATA_SENSITIVE *nv;

  info("TPM_NV_WriteValue()");
  /* set global lock */
  if (nvIndex == TPM_NV_INDEX0) {
    debug("nvIndex = TPM_NV_INDEX0");
    tpmData.stclear.flags.bGlobalLock = TRUE;
    return TPM_SUCCESS;
  }
  debug("nvIndex = %08x, offset = %d, dataSize = %d",
        nvIndex, offset, dataSize);
  /* get NV storage area that nvIndex points to */
  nv = tpm_get_nvs(nvIndex);
  if (nv == NULL) return TPM_BADINDEX;
  if (nv->pubInfo.permission.attributes & TPM_NV_PER_AUTHWRITE)
    return TPM_AUTH_CONFLICT;
  /* if NV storage is not locked omit authorization verifications */
  if (tpmData.permanent.flags.nvLocked) {
    if (auth1->authHandle == TPM_INVALID_HANDLE) {
      /* no authorization available */
      if (nv->pubInfo.permission.attributes & TPM_NV_PER_OWNERWRITE)
        return TPM_AUTH_CONFLICT;
      if (++tpmData.permanent.data.noOwnerNVWrite > TPM_MAX_NV_WRITE_NOOWNER)
        return TPM_MAXNVWRITES;
    } else {
      /* verify authorization */
      if (!(nv->pubInfo.permission.attributes & TPM_NV_PER_OWNERWRITE))
        return TPM_AUTH_CONFLICT;
      res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
      if (res != TPM_SUCCESS) return res;
    }
  }
  /* write data */
  return nv_write(nv, offset, dataSize, data,
                  tpmData.permanent.flags.nvLocked);
}

TPM_RESULT TPM_NV_WriteValueAuth(TPM_NV_INDEX nvIndex, UINT32 offset,
                                 UINT32 dataSize, BYTE *data, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_NV_DATA_SENSITIVE *nv;

  info("TPM_NV_WriteValueAuth()");
  debug("nvIndex = %08x, offset = %d, dataSize = %d",
        nvIndex, offset, dataSize);
  /* get NV storage area that nvIndex points to */
  nv = tpm_get_nvs(nvIndex);
  if (nv == NULL) return TPM_BADINDEX;
  if (!(nv->pubInfo.permission.attributes & TPM_NV_PER_AUTHWRITE))
    return TPM_AUTH_CONFLICT;
  /* verify authorization */
  res = tpm_verify_auth(auth1, nv->authValue, nvIndex);
  if (res != TPM_SUCCESS) return res;
  /* write data */
  return nv_write(nv, offset, dataSize, data, TRUE);
}

TPM_RESULT nv_read(TPM_NV_DATA_SENSITIVE *nv,  UINT32 offset,
                   UINT32 inDataSize, UINT32 *outDataSize, 
                   BYTE **data, BOOL verify)
{
  TPM_RESULT res;
  TPM_DIGEST digest;

  if (verify) {
    /* test for physical presence if required */
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_PPREAD)
        && !tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
    /* verify that area is not locked */
    if ((nv->pubInfo.permission.attributes & TPM_NV_PER_READ_STCLEAR)
        && nv->pubInfo.bReadSTClear) return TPM_DISABLED_CMD;
    /* verify locality and PCRs */
    if (!(nv->pubInfo.pcrInfoRead.localityAtRelease
          & (1 << tpmData.stany.flags.localityModifier)))
      return TPM_BAD_LOCALITY;
    res = tpm_compute_pcr_digest(&nv->pubInfo.pcrInfoRead.pcrSelection,
                                 &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &nv->pubInfo.pcrInfoRead.digestAtRelease,
               sizeof(TPM_DIGEST))) return TPM_WRONGPCRVAL;
  }
  /* read data */
  if (inDataSize == 0) {
    nv->pubInfo.bReadSTClear = TRUE;
    *outDataSize = 0;
    *data = NULL; 
  } else {
    if (offset + inDataSize > nv->pubInfo.dataSize) return TPM_NOSPACE;
    *outDataSize = inDataSize;
    *data = tpm_malloc(*outDataSize);
    if (*data == NULL) return TPM_FAIL;
    memcpy(*data, tpmData.permanent.data.nvData + nv->dataIndex + offset,
           inDataSize);
  }
  return TPM_SUCCESS;

}

TPM_RESULT TPM_NV_ReadValue(TPM_NV_INDEX nvIndex,  UINT32 offset,
                            UINT32 inDataSize, TPM_AUTH *auth1,  
                            UINT32 *outDataSize, BYTE **data)
{
  TPM_RESULT res;
  TPM_NV_DATA_SENSITIVE *nv;

  info("TPM_NV_ReadValue()");
  debug("nvIndex = %08x, offset = %d, inDataSize = %d",
        nvIndex, offset, inDataSize);
  /* get NV storage area that nvIndex points to */
  nv = tpm_get_nvs(nvIndex);
  if (nv == NULL) return TPM_BADINDEX;
  if (nv->pubInfo.permission.attributes & TPM_NV_PER_AUTHREAD)
    return TPM_AUTH_CONFLICT;
  /* if NV storage is not locked omit authorization verifications */
  if (tpmData.permanent.flags.nvLocked) {
    if (auth1->authHandle == TPM_INVALID_HANDLE) {
      /* no authorization available */
      if (nv->pubInfo.permission.attributes & TPM_NV_PER_OWNERREAD)
        return TPM_AUTH_CONFLICT;
    } else {
      /* verify authorization */
      if (!(nv->pubInfo.permission.attributes & TPM_NV_PER_OWNERREAD))
        return TPM_AUTH_CONFLICT;
      res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
      if (res != TPM_SUCCESS) return res;
    }
  }
  /* read data */
  return nv_read(nv, offset, inDataSize, outDataSize, data, TRUE);
}

TPM_RESULT TPM_NV_ReadValueAuth(TPM_NV_INDEX nvIndex,  UINT32 offset,
                                UINT32 inDataSize, TPM_AUTH *auth1,  
                                UINT32 *outDataSize, BYTE **data)
{
  TPM_RESULT res;
  TPM_NV_DATA_SENSITIVE *nv;

  info("TPM_NV_ReadValueAuth()");
  debug("nvIndex = %08x, offset = %d, inDataSize = %d",
        nvIndex, offset, inDataSize);
  /* get NV storage area that nvIndex points to */
  nv = tpm_get_nvs(nvIndex);
  if (nv == NULL) return TPM_BADINDEX;
  if (!(nv->pubInfo.permission.attributes & TPM_NV_PER_AUTHREAD))
    return TPM_AUTH_CONFLICT;
  /* verify authorization */
  res = tpm_verify_auth(auth1, nv->authValue, nvIndex);
  if (res != TPM_SUCCESS) return res;
  /* read data */
  return nv_read(nv, offset, inDataSize, outDataSize, data, TRUE);
}


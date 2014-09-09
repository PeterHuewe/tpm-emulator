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
 * $Id: tpm_owner.c 470 2011-10-25 12:02:49Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "crypto/rsa.h"

/*
 * Admin Opt-in ([TPM_Part3], Section 5)
 * [tpm_owner.c]
 */

TPM_RESULT TPM_SetOwnerInstall(BOOL state)
{
  info("TPM_SetOwnerInstall()");
  if (tpmData.permanent.flags.owned) return TPM_SUCCESS;
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  tpmData.permanent.flags.ownership = state;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_OwnerSetDisable(BOOL disableState, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_OwnerSetDisable()");
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  tpmData.permanent.flags.disable = disableState;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PhysicalEnable()
{
  info("TPM_PhysicalEnable()");
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  tpmData.permanent.flags.disable = FALSE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PhysicalDisable()
{
  info("TPM_PhysicalDisable()");
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  tpmData.permanent.flags.disable = TRUE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PhysicalSetDeactivated(BOOL state)
{
  info("TPM_PhysicalSetDeactivated()");
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  tpmData.permanent.flags.deactivated = state;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SetTempDeactivated(TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_SetTempDeactivated()");
  if (auth1->authHandle == TPM_INVALID_HANDLE) {
    if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  } else {
    if (!tpmData.permanent.flags.operator) return TPM_NOOPERATOR;
    res = tpm_verify_auth(auth1, tpmData.permanent.data.operatorAuth, TPM_KH_OPERATOR);
    if (res != TPM_SUCCESS) return res;
  }
  tpmData.stclear.flags.deactivated = TRUE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SetOperatorAuth(TPM_SECRET *operatorAuth)
{
  info("TPM_SetOperatorAuth()");
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  memcpy(&tpmData.permanent.data.operatorAuth,
    operatorAuth, sizeof(TPM_SECRET));
  tpmData.permanent.flags.operator = TRUE;
  return TPM_SUCCESS;
}

/*
 * Admin Ownership ([TPM_Part3], Section 6)
 */

TPM_RESULT TPM_TakeOwnership(TPM_PROTOCOL_ID protocolID,
                             UINT32 encOwnerAuthSize, BYTE *encOwnerAuth,
                             UINT32 encSrkAuthSize, BYTE *encSrkAuth,
                             TPM_KEY *srkParams, TPM_AUTH *auth1,
                             TPM_KEY *srkPub)
{
  TPM_RESULT res;
  tpm_rsa_private_key_t *ek = &tpmData.permanent.data.endorsementKey;
  TPM_KEY_DATA *srk = &tpmData.permanent.data.srk;
  size_t buf_size = ek->size >> 3;
  BYTE buf[buf_size];

  info("TPM_TakeOwnership()");
  if (!ek->size) return TPM_NO_ENDORSEMENT;
  if (protocolID != TPM_PID_OWNER) return TPM_BAD_PARAMETER;
  if (tpmData.permanent.flags.owned) return TPM_OWNER_SET;
  if (!tpmData.permanent.flags.ownership) return TPM_INSTALL_DISABLED;
  /* decrypt ownerAuth */
  if (tpm_rsa_decrypt(ek, RSA_ES_OAEP_SHA1, encOwnerAuth, encOwnerAuthSize,
      buf, &buf_size) != 0) return TPM_DECRYPT_ERROR;
  if (buf_size != sizeof(TPM_SECRET)) return TPM_BAD_KEY_PROPERTY;
  memcpy(tpmData.permanent.data.ownerAuth, buf, buf_size);
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  if (tpm_get_auth(auth1->authHandle)->type != TPM_ST_OIAP)
    return TPM_AUTHFAIL;
  /* reset srk and decrypt srkAuth */
  memset(srk, 0, sizeof(*srk));
  if (tpm_rsa_decrypt(ek, RSA_ES_OAEP_SHA1, encSrkAuth, encSrkAuthSize,
      buf, &buf_size) != 0) return TPM_DECRYPT_ERROR;
  if (buf_size != sizeof(TPM_SECRET)) return TPM_BAD_KEY_PROPERTY;
  memcpy(srk->usageAuth, buf, buf_size);
  /* validate SRK parameters */
  if (srkParams->keyFlags & TPM_KEY_FLAG_MIGRATABLE
      || srkParams->keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  if (srkParams->algorithmParms.algorithmID != TPM_ALG_RSA
      || srkParams->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || srkParams->algorithmParms.sigScheme != TPM_SS_NONE
      || srkParams->algorithmParms.parmSize == 0
      || srkParams->algorithmParms.parms.rsa.keyLength != 2048
      || srkParams->algorithmParms.parms.rsa.numPrimes != 2
      || srkParams->algorithmParms.parms.rsa.exponentSize != 0
      || srkParams->PCRInfoSize != 0) return TPM_BAD_KEY_PROPERTY;
  /* setup and generate SRK */
  srk->keyFlags = srkParams->keyFlags;
  srk->keyFlags |= TPM_KEY_FLAG_PCR_IGNORE;
  srk->keyFlags &= ~TPM_KEY_FLAG_HAS_PCR;
  srk->keyUsage = srkParams->keyUsage;
  srk->encScheme = srkParams->algorithmParms.encScheme;
  srk->sigScheme = srkParams->algorithmParms.sigScheme;
  srk->authDataUsage = srkParams->authDataUsage;
  debug("srk->authDataUsage = %02x", srk->authDataUsage);
  srk->parentPCRStatus = FALSE;
  srkParams->algorithmParms.parms.rsa.keyLength = 2048;
  if (tpm_rsa_generate_key(&srk->key,
      srkParams->algorithmParms.parms.rsa.keyLength)) return TPM_FAIL;
  srk->payload = TPM_PT_ASYM;
  /* generate context, delegate, and DAA key */
  tpm_get_random_bytes(tpmData.permanent.data.contextKey,
    sizeof(tpmData.permanent.data.contextKey));
  tpm_get_random_bytes(tpmData.permanent.data.delegateKey,
      sizeof(tpmData.permanent.data.delegateKey));
  tpm_get_random_bytes(tpmData.permanent.data.daaKey,
      sizeof(tpmData.permanent.data.daaKey));
  /* export SRK */
  memcpy(srkPub, srkParams, sizeof(TPM_KEY));
  srkPub->pubKey.keyLength = srk->key.size >> 3;
  srkPub->pubKey.key = tpm_malloc(srkPub->pubKey.keyLength);
  if (srkPub->pubKey.key == NULL) {
    tpm_rsa_release_private_key(&srk->key);
    srk->payload = TPM_PT_NONE;
    return TPM_FAIL;
  }
  tpm_rsa_export_modulus(&srk->key, srkPub->pubKey.key, NULL);
  /* setup tpmProof/daaProof and set state to owned */
  tpm_get_random_bytes(tpmData.permanent.data.tpmProof.nonce,
    sizeof(tpmData.permanent.data.tpmProof.nonce));
  tpm_get_random_bytes(tpmData.permanent.data.daaProof.nonce,
    sizeof(tpmData.permanent.data.daaProof.nonce));
  tpmData.permanent.flags.readPubek = FALSE;
  tpmData.permanent.flags.owned = TRUE;
  return TPM_SUCCESS;
}

void tpm_owner_clear()
{
  int i;
  /* unload all keys */
  for (i = 0; i < TPM_MAX_KEYS; i++) {
    if (tpmData.permanent.data.keys[i].payload)
      TPM_FlushSpecific(INDEX_TO_KEY_HANDLE(i), TPM_RT_KEY);
  }
  /* invalidate stany and stclear data */
  memset(&tpmData.stany.data, 0 , sizeof(tpmData.stany.data));
  memset(&tpmData.stclear.data, 0 , sizeof(tpmData.stclear.data));
  /* release SRK */
  tpm_rsa_release_private_key(&tpmData.permanent.data.srk.key);
  /* invalidate permanent data */
  memset(&tpmData.permanent.data.ownerAuth, 0,
    sizeof(tpmData.permanent.data.ownerAuth));
  memset(&tpmData.permanent.data.srk, 0,
    sizeof(tpmData.permanent.data.srk));
  memset(&tpmData.permanent.data.tpmProof, 0,
    sizeof(tpmData.permanent.data.tpmProof));
  memset(&tpmData.permanent.data.operatorAuth, 0,
    sizeof(tpmData.permanent.data.operatorAuth));
  /* invalidate delegate, context, and DAA key */
  memset(&tpmData.permanent.data.contextKey, 0,
    sizeof(tpmData.permanent.data.contextKey));
  memset(&tpmData.permanent.data.delegateKey, 0,
    sizeof(tpmData.permanent.data.delegateKey));
  /* set permanent data */
  tpmData.permanent.data.noOwnerNVWrite = 0;
  tpmData.permanent.data.restrictDelegate = 0;
  memset (tpmData.permanent.data.ordinalAuditStatus, 0,
          sizeof(tpmData.permanent.data.ordinalAuditStatus));
  /* set permanent flags */
  tpmData.permanent.flags.owned = FALSE;
  tpmData.permanent.flags.operator = FALSE;
  tpmData.permanent.flags.disableOwnerClear = FALSE;
  tpmData.permanent.flags.ownership = TRUE;
  tpmData.permanent.flags.disable = FALSE;
  tpmData.permanent.flags.deactivated = FALSE;
  tpmData.permanent.flags.maintenanceDone = FALSE;
  tpmData.permanent.flags.allowMaintenance = TRUE;
  tpmData.permanent.flags.disableFullDALogicInfo = FALSE;
  tpmData.permanent.flags.readPubek = TRUE;
  /* release all counters */
  for (i = 0; i < TPM_MAX_COUNTERS; i++)
    memset(&tpmData.permanent.data.counters[i], 0, sizeof(TPM_COUNTER_VALUE));
  /* invalidate family and delegates table */
  for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    memset(&tpmData.permanent.data.familyTable.famRow[i], 0,
           sizeof(TPM_FAMILY_TABLE_ENTRY));
  }
  for (i = 0; i < TPM_NUM_DELEGATE_TABLE_ENTRY; i++) {
    memset(&tpmData.permanent.data.delegateTable.delRow[i], 0,
           sizeof(TPM_DELEGATE_TABLE_ROW));
  }
  /* release NV storage */
  for (i = 0; i < TPM_MAX_NVS; i++) {
    if (tpmData.permanent.data.nvStorage[i].valid
        && (tpmData.permanent.data.nvStorage[i].pubInfo.permission.attributes
            & (TPM_NV_PER_OWNERWRITE | TPM_NV_PER_OWNERREAD))) {
      tpm_nv_remove_data(&tpmData.permanent.data.nvStorage[i]);
    }
  }
}

TPM_RESULT TPM_OwnerClear(TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_OwnerClear()");
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  if (tpmData.permanent.flags.disableOwnerClear) return TPM_CLEAR_DISABLED;
  tpm_owner_clear();
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ForceClear()
{
  info("TPM_ForceClear()");
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  if (tpmData.stclear.flags.disableForceClear) return TPM_CLEAR_DISABLED;
  tpm_owner_clear();
  return TPM_SUCCESS;
}

TPM_RESULT TPM_DisableOwnerClear(TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_DisableOwnerClear()");
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  tpmData.permanent.flags.disableOwnerClear = TRUE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_DisableForceClear()
{
  info("TPM_DisableForceClear()");
  tpmData.stclear.flags.disableForceClear = TRUE;
  return TPM_SUCCESS;
}

TPM_RESULT TSC_PhysicalPresence(TPM_PHYSICAL_PRESENCE physicalPresence)
{
  info("TSC_PhysicalPresence()");
  if (!tpmData.permanent.flags.physicalPresenceLifetimeLock) {
    /* enable physicalPresenceHW or physicalPresenceCMD */
    if (physicalPresence & TPM_PHYSICAL_PRESENCE_HW_ENABLE)
      tpmData.permanent.flags.physicalPresenceHWEnable = TRUE;
    if (physicalPresence & TPM_PHYSICAL_PRESENCE_CMD_ENABLE)
      tpmData.permanent.flags.physicalPresenceCMDEnable = TRUE;
  } else if (physicalPresence & TPM_PHYSICAL_PRESENCE_LIFETIME_LOCK) {
    /* set physicalPresenceLifetimeLock */
    tpmData.permanent.flags.physicalPresenceLifetimeLock = TRUE;
  } else if (tpmData.permanent.flags.physicalPresenceCMDEnable &&
             !tpmData.stclear.flags.physicalPresenceLock) {
    /* set physicalPresence or physicalPresenceLock */
    if (physicalPresence & TPM_PHYSICAL_PRESENCE_PRESENT)
      tpmData.stclear.flags.physicalPresence = TRUE;
    if (physicalPresence & TPM_PHYSICAL_PRESENCE_NOTPRESENT)
      tpmData.stclear.flags.physicalPresence = FALSE;
    if (physicalPresence & TPM_PHYSICAL_PRESENCE_LOCK)
      tpmData.stclear.flags.physicalPresenceLock = TRUE;
  } else {
    return TPM_BAD_PARAMETER;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TSC_ResetEstablishmentBit()
{
  info("TSC_ResetEstablishmentBit()");
  /* locality must be three or four */
  if (tpmData.stany.flags.localityModifier != 3
      && tpmData.stany.flags.localityModifier != 4) return TPM_BAD_LOCALITY;
  /* as we do not have such a bit we do nothing and just return true */
  return TPM_SUCCESS;
}

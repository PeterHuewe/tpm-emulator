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
 * $Id: tpm_startup.c 367 2010-02-13 15:52:18Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"

/*
 * Admin Startup and State ([TPM_Part3], Section 3)
 * This section describes the commands that start a TPM.
 */

void TPM_Init(TPM_STARTUP_TYPE startupType)
{
  info("TPM_Init()");
  /* startup the TPM */
  tpmData.stany.flags.postInitialise = TRUE;
  TPM_SelfTestFull();
  TPM_Startup(startupType);
}

#define SET_TO_ZERO(a) memset(a, 0x00, sizeof(*a))
#define SET_TO_0xFF(a) memset(a, 0xff, sizeof(*a)) 
#define SET_TO_RAND(a) tpm_get_random_bytes(a, sizeof(*a))

TPM_RESULT TPM_Startup(TPM_STARTUP_TYPE startupType)
{
  int i;
  info("TPM_Startup(%d)", startupType);
  if (tpmData.stany.flags.postInitialise == FALSE) return TPM_INVALID_POSTINIT;
  /* reset STANY_FLAGS */
  SET_TO_ZERO(&tpmData.stany.flags);
  tpmData.stany.flags.tag = TPM_TAG_STANY_FLAGS;
  /* set data and flags according to the given startup type */
  if (startupType == TPM_ST_CLEAR) {
    /* reset STANY_DATA (invalidates ALL sessions) */
    SET_TO_ZERO(&tpmData.stany.data);
    tpmData.stany.data.tag = TPM_TAG_STANY_DATA;
    /* init session-context nonce */
    SET_TO_RAND(&tpmData.stany.data.contextNonceSession);
    /* reset PCR values */
    for (i = 0; i < TPM_NUM_PCR; i++) {
      if (tpmData.permanent.data.pcrAttrib[i].pcrReset)
        SET_TO_0xFF(&tpmData.permanent.data.pcrValue[i].digest);
      else
        SET_TO_ZERO(&tpmData.permanent.data.pcrValue[i].digest);
    }
    /* reset STCLEAR_FLAGS */
    SET_TO_ZERO(&tpmData.stclear.flags);
    tpmData.stclear.flags.tag = TPM_TAG_STCLEAR_FLAGS;
    tpmData.stclear.flags.deactivated = tpmData.permanent.flags.deactivated;
    /* reset STCLEAR_DATA */
    SET_TO_ZERO(&tpmData.stclear.data);
    tpmData.stclear.data.tag = TPM_TAG_STCLEAR_DATA;
    /* flush volatiles and PCR dependent keys */
    for (i = 0; i < TPM_MAX_KEYS; i++) {
      if (tpmData.permanent.data.keys[i].payload
          && ((tpmData.permanent.data.keys[i].keyFlags & TPM_KEY_FLAG_VOLATILE)
              || tpmData.permanent.data.keys[i].parentPCRStatus))
        TPM_FlushSpecific(INDEX_TO_KEY_HANDLE(i), TPM_RT_KEY);
    }
    /* init key-context nonce */
    SET_TO_RAND(&tpmData.stclear.data.contextNonceKey);
    /* invalidate counter handle */
    tpmData.stclear.data.countID = TPM_INVALID_HANDLE;
    /* reset NV read and write flags */
    for (i = 0; i < TPM_MAX_NVS; i++) {
        tpmData.permanent.data.nvStorage[i].pubInfo.bReadSTClear = FALSE;
        tpmData.permanent.data.nvStorage[i].pubInfo.bWriteSTClear = FALSE;
    }
  } else if (startupType == TPM_ST_STATE) {
    if (!tpmData.permanent.flags.dataRestored) {
      error("restoring permanent data failed");
      tpmData.permanent.data.testResult = "tpm_restore_permanent_data() failed";
      tpmData.permanent.flags.selfTestSucceeded = FALSE;
      return TPM_FAIL;
    }
  } else if (startupType == TPM_ST_DEACTIVATED) {
    tpmData.stclear.flags.deactivated = TRUE;
    /* invalidate any saved state */
    tpm_erase_permanent_data();
  } else {
    return TPM_BAD_PARAMETER;
  }
  tpmData.stany.flags.postInitialise = FALSE;
  tpmData.stany.flags.TOSPresent = FALSE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SaveState()
{
  info("TPM_SaveState()");
  if (tpmData.permanent.flags.selfTestSucceeded && !tpmData.stclear.flags.deactivated) { 
    return (tpm_store_permanent_data()) ? TPM_FAIL : TPM_SUCCESS;
  } else {
    debug("TPM is deactivated or in fail-stop mode, thus the permanent data is not stored");
    return TPM_SUCCESS;
  }
}

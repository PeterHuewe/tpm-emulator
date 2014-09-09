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
 * $Id: tpm_management.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"

/*
 * Administrative Functions ([TPM_Part3], Section 9)
 */

TPM_RESULT TPM_FieldUpgrade()
{
  info("TPM_FieldUpgrade()");
  /* nothing to do so far */
  return TPM_SUCCESS;
}

TPM_RESULT TPM_SetRedirection(TPM_KEY_HANDLE keyHandle,
                              TPM_REDIR_COMMAND redirCmd, UINT32 inputDataSize,
                              BYTE *inputData, TPM_AUTH *auth1)
{
  info("TPM_SetRedirection()");
  /* this command is not supported by the TPM emulator */ 
  return TPM_DISABLED_CMD;
}

TPM_RESULT TPM_ResetLockValue(TPM_AUTH *auth1)
{
  TPM_RESULT res;
  
  info("TPM_ResetLockValue");
  if (tpmData.stclear.data.disableResetLock) return TPM_AUTHFAIL;
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) {
    tpmData.stclear.data.disableResetLock = TRUE;
    return res;
  }
  /* reset dictionary attack mitigation mechanism */
  return TPM_SUCCESS;
}

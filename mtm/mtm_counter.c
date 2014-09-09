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

#include "mtm_commands.h"
#include "tpm/tpm_handles.h"
#include "tpm/tpm_commands.h"

TPM_RESULT MTM_ReleaseCounter(TPM_COUNT_ID countID, TPM_AUTH *auth1)
{
  int i = HANDLE_TO_INDEX(countID);
  info("MTM_ReleaseCounter()");
  if (i == MTM_COUNTER_SELECT_BOOTSTRAP
      || i == MTM_COUNTER_SELECT_RIMPROTECT
      || i == MTM_COUNTER_SELECT_STORAGEPROTECT) {
    debug("MTM counters cannot be released");
    return TPM_FAIL;
  }
  return TPM_ReleaseCounter(countID, auth1);
}

TPM_RESULT MTM_ReleaseCounterOwner(TPM_COUNT_ID countID, TPM_AUTH *auth1)
{
  int i = HANDLE_TO_INDEX(countID);
  info("MTM_ReleaseCounterOwner()");
  if (i == MTM_COUNTER_SELECT_BOOTSTRAP
      || i == MTM_COUNTER_SELECT_RIMPROTECT
      || i == MTM_COUNTER_SELECT_STORAGEPROTECT) {
    debug("MTM counters cannot be released");
    return TPM_FAIL;
  }
  return TPM_ReleaseCounterOwner(countID, auth1);
}



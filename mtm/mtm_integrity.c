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
#include "mtm_data.h"
#include "tpm/tpm_commands.h"

TPM_RESULT MTM_Extend(TPM_PCRINDEX pcrNum, TPM_DIGEST *inDigest, 
                      TPM_PCRVALUE *outDigest)
{
  info("MTM_Extend()");
  if (mtmData.permanent.data.verifiedPCRs.pcrSelect[pcrNum >> 3] & (1 << (pcrNum & 7))) {
    return TPM_BAD_LOCALITY;
  }
  return TPM_Extend(pcrNum, inDigest, outDigest);
}

TPM_RESULT MTM_PCR_Reset(TPM_PCR_SELECTION *pcrSelection)
{
  int i;
  info("MTM_PCR_Reset()");
  for (i = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    if ((pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7)))
        && (mtmData.permanent.data.verifiedPCRs.pcrSelect[i >> 3] & (1 << (i & 7)))) {
      return TPM_FAIL;
    }
  }
  return TPM_PCR_Reset(pcrSelection);
}


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

#include "mtm_data.h"
#include "tpm/tpm_data.h"

MTM_DATA mtmData;

static void set_counter(unsigned int num, const char *label)
{
  TPM_COUNTER_VALUE *counter = &tpmData.permanent.data.counters[num];
  counter->valid = TRUE;
  counter->tag = TPM_TAG_COUNTER_VALUE;
  memcpy(counter->label, label, sizeof(counter->label));
  counter->counter = 1;
  memset(counter->usageAuth, 0, sizeof(TPM_SECRET));
}

void mtm_init_data(void)
{
  int i;
  info("initializing MTM data to default values");
  /* reset all data to NULL, FALSE or 0 */
  memset(&mtmData, 0, sizeof(mtmData));
  mtmData.permanent.data.tag = MTM_TAG_PERMANENT_DATA;
  /* set specification version */
  mtmData.permanent.data.specMajor = 0x01;
  mtmData.permanent.data.specMinor = 0x00;
  /* define verified PCRs */
  mtmData.permanent.data.verifiedPCRs.sizeOfSelect = TPM_NUM_PCR / 8;
  for (i = 0; i < TPM_NUM_PCR / 8; i++) {
    mtmData.permanent.data.verifiedPCRs.pcrSelect[i] = 0x00;
  }
  /* map MTM counters to TPM counters */
  set_counter(MTM_COUNTER_SELECT_BOOTSTRAP, "MTM1");
  set_counter(MTM_COUNTER_SELECT_RIMPROTECT, "MTM2");
  set_counter(MTM_COUNTER_SELECT_STORAGEPROTECT, "MTM3");
  /* the field integrityCheckRootData is filled when the first verification key is loaded */
  memset(mtmData.permanent.data.integrityCheckRootData, 0xff,
         sizeof(mtmData.permanent.data.integrityCheckRootData));
  /* set internal verification key */
  memcpy(mtmData.permanent.data.internalVerificationKey,
         "\x77\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x00\x00\x00\x77", sizeof(TPM_SECRET));
  /* init flags */
  mtmData.stany.flags.tag = MTM_TAG_STANY_FLAGS;
  mtmData.stany.flags.loadVerificationRootKeyEnabled = TRUE;
}


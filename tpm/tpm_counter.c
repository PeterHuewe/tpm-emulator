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
 * $Id: tpm_counter.c 472 2011-11-12 09:00:22Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_data.h"

/*
 * Monotonic Counter ([TPM_Part3], Section 25)
 */

static TPM_ACTUAL_COUNT get_max_counter_value(void)
{
  UINT32 i;
  TPM_ACTUAL_COUNT max = 0;
  for (i = 0; i < TPM_MAX_COUNTERS; i++) {
    if (tpmData.permanent.data.counters[i].valid
        && tpmData.permanent.data.counters[i].counter > max)
      max = tpmData.permanent.data.counters[i].counter;
  }
  return max;
}

static TPM_COUNT_ID get_free_counter(void)
{
  UINT32 i;
  for (i = 0; i < TPM_MAX_COUNTERS; i++) {
    if (!tpmData.permanent.data.counters[i].valid) {
      tpmData.permanent.data.counters[i].valid = TRUE;
      return INDEX_TO_COUNTER_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}

TPM_RESULT TPM_CreateCounter(TPM_ENCAUTH *authData, BYTE label[4],
                             TPM_AUTH *auth1, TPM_COUNT_ID *countID, 
                             TPM_COUNTER_VALUE *counterValue)
{
  TPM_RESULT res;
  TPM_COUNTER_VALUE *counter;
  TPM_SESSION_DATA *session;
  info("TPM_CreateCounter()");
  /* get a free counter if any is left */
  *countID = get_free_counter();
  counter = tpm_get_counter(*countID);
  if (counter == NULL) return TPM_SIZE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if ((session->type != TPM_ST_OSAP) && (session->type != TPM_ST_DSAP))
    return TPM_AUTHFAIL;
  /* decrypt authorization secret */
  tpm_decrypt_auth_secret(*authData, session->sharedSecret, 
    &session->lastNonceEven, counter->usageAuth);
  /* setup counter */
  counter->tag = TPM_TAG_COUNTER_VALUE;
  memcpy(counter->label, label, 4);
  counter->counter = get_max_counter_value() + 1;
  memcpy(counterValue, counter, sizeof(TPM_COUNTER_VALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_IncrementCounter(TPM_COUNT_ID countID, TPM_AUTH *auth1,
                                TPM_COUNTER_VALUE *count)
{
  TPM_RESULT res;
  TPM_COUNTER_VALUE *counter;
  info("TPM_IncrementCounter()");
  /* get counter */
  counter = tpm_get_counter(countID);
  if (counter == NULL) return TPM_BAD_COUNTER;
  /* verify authorization */
  res = tpm_verify_auth(auth1, counter->usageAuth, countID);
  if (res != TPM_SUCCESS) return res;
  /* verify counter selection and increment counter */
  if (tpm_get_counter(tpmData.stclear.data.countID) != NULL
      && tpmData.stclear.data.countID != countID) return TPM_BAD_COUNTER;
  tpmData.stclear.data.countID = countID;
  counter->counter++;
  memcpy(count, counter, sizeof(TPM_COUNTER_VALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ReadCounter(TPM_COUNT_ID countID, TPM_COUNTER_VALUE *count)
{
  TPM_COUNTER_VALUE *counter;
  info("TPM_ReadCounter()");
  /* get counter */
  counter = tpm_get_counter(countID);
  if (counter == NULL) return TPM_BAD_COUNTER;
  memcpy(count, counter, sizeof(TPM_COUNTER_VALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ReleaseCounter(TPM_COUNT_ID countID, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_COUNTER_VALUE *counter;
  info("TPM_ReleaseCounter()");
  /* get counter */
  counter = tpm_get_counter(countID);
  if (counter == NULL) return TPM_BAD_COUNTER;
  /* verify authorization */
  res = tpm_verify_auth(auth1, counter->usageAuth, countID);
  if (res != TPM_SUCCESS) return res;
  /* release counter */
  if (tpmData.stclear.data.countID == countID)
    tpmData.stclear.data.countID = TPM_INVALID_HANDLE;
  memset(counter, 0, sizeof(TPM_COUNTER_VALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ReleaseCounterOwner(TPM_COUNT_ID countID, TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_COUNTER_VALUE *counter;
  info("TPM_ReleaseCounterOwner()");
  /* get counter */
  counter = tpm_get_counter(countID);
  if (counter == NULL) return TPM_BAD_COUNTER;
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* release counter */
  if (tpmData.stclear.data.countID == countID)
    tpmData.stclear.data.countID = TPM_INVALID_HANDLE;
  memset(counter, 0, sizeof(TPM_COUNTER_VALUE));
  return TPM_SUCCESS;
}


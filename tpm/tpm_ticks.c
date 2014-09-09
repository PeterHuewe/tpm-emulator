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
 * $Id: tpm_ticks.c 453 2010-09-11 11:00:58Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"

/*
 * Timing Ticks ([TPM_Part3], Section 23)
 * The TPM timing ticks are always available for use. The association of 
 * timing ticks to actual time is a protocol that occurs outside of the TPM. 
 * See the design document for details. 
 */

TPM_RESULT TPM_GetTicks(TPM_CURRENT_TICKS *currentTime)
{
  info("TPM_GetTicks()");
  memcpy(currentTime, &tpmData.stany.data.currentTicks, 
    sizeof(TPM_CURRENT_TICKS));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_TickStampBlob(TPM_KEY_HANDLE keyHandle, TPM_NONCE *antiReplay,
                             TPM_DIGEST *digestToStamp, TPM_AUTH *auth1,  
                             TPM_CURRENT_TICKS *currentTicks, 
                             UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  BYTE *info_buffer, *ptr;
  UINT32 info_length, len;
  info("TPM_TickStampBlob()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  if (key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_LEGACY
      && key->keyUsage != TPM_KEY_IDENTITY) return TPM_INVALID_KEYUSAGE;
  if (key->sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1)
    return TPM_INAPPROPRIATE_SIG;
  /* get current ticks */
  TPM_GetTicks(currentTicks);
  /* sign data using signature scheme PKCS1_SHA1 and TPM_SIGN_INFO container */
  *sigSize = key->key.size >> 3;
  *sig = tpm_malloc(*sigSize);
  if (*sig == NULL) return TPM_FAIL; 
  /* setup TPM_SIGN_INFO structure */
  info_length = 30 + sizeof(TPM_DIGEST) + sizeof_TPM_CURRENT_TICKS(currentTicks);
  info_buffer = tpm_malloc(info_length);
  if (info_buffer == NULL) {
    tpm_free(*sig);
    return TPM_FAIL;
  }
  memcpy(&info_buffer[0], "\x00\x05TSTP", 6);
  memcpy(&info_buffer[6], antiReplay->nonce, 20);
  ptr = &info_buffer[26]; len = info_length - 26;
  tpm_marshal_UINT32(&ptr, &len, info_length - 30);
  memcpy(ptr, digestToStamp->digest, sizeof(TPM_DIGEST));
  ptr += sizeof(TPM_DIGEST); len -= sizeof(TPM_DIGEST);
  if (tpm_marshal_TPM_CURRENT_TICKS(&ptr, &len, currentTicks)
      || tpm_rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1,
                      info_buffer, info_length, *sig)) {
    tpm_free(*sig);
    tpm_free(info_buffer);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

void tpm_update_ticks(void)
{
  if (tpmData.stany.data.currentTicks.tag == 0) {
    tpmData.stany.data.currentTicks.tag = TPM_TAG_CURRENT_TICKS;
    tpmData.stany.data.currentTicks.currentTicks += tpm_get_ticks();
    tpm_get_random_bytes(tpmData.stany.data.currentTicks.tickNonce.nonce, 
      sizeof(TPM_NONCE));
    tpmData.stany.data.currentTicks.tickRate = 1;
  } else {
    tpmData.stany.data.currentTicks.currentTicks += tpm_get_ticks();
  }
}


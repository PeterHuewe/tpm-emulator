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
 * $Id: tpm_credentials.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_marshalling.h"
#include "tpm_data.h"
#include "crypto/sha1.h"

/*
 * Credential Handling ([TPM_Part3], Section 14)
 * There are two create EK commands. The first matches the 1.1 functionality. 
 * The second provides the mechanism to enable revokeEK and provides 
 * FIPS 140-2 compatibility. 
 */

TPM_RESULT tpm_get_pubek(TPM_PUBKEY *pubEndorsementKey)
{
  UINT32 key_length;
  if (!tpmData.permanent.data.endorsementKey.size) return TPM_NO_ENDORSEMENT;
  /* setup TPM_PUBKEY structure */
  key_length = tpmData.permanent.data.endorsementKey.size;
  pubEndorsementKey->pubKey.keyLength = key_length >> 3;
  pubEndorsementKey->pubKey.key = tpm_malloc(pubEndorsementKey->pubKey.keyLength);
  if (pubEndorsementKey->pubKey.key == NULL) return TPM_FAIL;
  tpm_rsa_export_modulus(&tpmData.permanent.data.endorsementKey,
                     pubEndorsementKey->pubKey.key, NULL);
  pubEndorsementKey->algorithmParms.algorithmID = TPM_ALG_RSA;
  pubEndorsementKey->algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
  pubEndorsementKey->algorithmParms.sigScheme = TPM_SS_NONE;
  pubEndorsementKey->algorithmParms.parms.rsa.keyLength = key_length;
  pubEndorsementKey->algorithmParms.parms.rsa.numPrimes = 2;
  pubEndorsementKey->algorithmParms.parms.rsa.exponentSize = 0;
  pubEndorsementKey->algorithmParms.parms.rsa.exponent = NULL;
  pubEndorsementKey->algorithmParms.parmSize = 12;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CreateEndorsementKeyPair(TPM_NONCE *antiReplay,
                                        TPM_KEY_PARMS *keyInfo, 
                                        TPM_PUBKEY *pubEndorsementKey, 
                                        TPM_DIGEST *checksum)
{
  info("TPM_CreateEndorsementKeyPair()");
  return TPM_DISABLED_CMD;
}

TPM_RESULT TPM_CreateRevocableEK(TPM_NONCE *antiReplay, TPM_KEY_PARMS *keyInfo,
                                 BOOL generateReset, TPM_NONCE *inputEKreset,  
                                 TPM_PUBKEY *pubEndorsementKey, 
                                 TPM_DIGEST *checksum, 
                                 TPM_NONCE *outputEKreset)
{
  TPM_RESULT res;
  info("TPM_CreateRevocableEK()");
  /* verify key parameters */
  if (tpmData.permanent.data.endorsementKey.size > 0) return TPM_DISABLED_CMD;
  if (keyInfo->algorithmID != TPM_ALG_RSA
      || keyInfo->encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || keyInfo->sigScheme != TPM_SS_NONE
      || keyInfo->parmSize == 0
      || keyInfo->parms.rsa.keyLength != 2048
      || keyInfo->parms.rsa.numPrimes != 2
      || keyInfo->parms.rsa.exponentSize != 0) return TPM_BAD_KEY_PROPERTY;
  /* create endorsement key */
  if (tpm_rsa_generate_key(&tpmData.permanent.data.endorsementKey, 
      keyInfo->parms.rsa.keyLength)) return TPM_FAIL;
  /* return PUBEK */
  res = tpm_get_pubek(pubEndorsementKey);
  if (res != TPM_SUCCESS) {
    tpm_rsa_release_private_key(&tpmData.permanent.data.endorsementKey);
    tpmData.permanent.data.endorsementKey.size = 0;
    return res;
  }
  /* compute checksum */
  if (tpm_compute_pubkey_checksum(antiReplay, pubEndorsementKey, checksum)) {
    tpm_free(pubEndorsementKey->pubKey.key);
    tpm_rsa_release_private_key(&tpmData.permanent.data.endorsementKey);
    tpmData.permanent.data.endorsementKey.size = 0;
    return TPM_FAIL;
  }
  tpmData.permanent.flags.enableRevokeEK = TRUE;
  tpmData.permanent.flags.CEKPUsed = TRUE;
  if (generateReset) {
    tpm_get_random_bytes(tpmData.permanent.data.ekReset.nonce, 
      sizeof(tpmData.permanent.data.ekReset.nonce));
  } else {
    memcpy(&tpmData.permanent.data.ekReset, inputEKreset, sizeof(TPM_NONCE));
  }
  memcpy(outputEKreset, &tpmData.permanent.data.ekReset, sizeof(TPM_NONCE));
  /* Create TPM_PERMANENT_DATA->TPM_DAA_TPM_SEED from the TPM RNG */
  tpm_get_random_bytes(tpmData.permanent.data.tpmDAASeed.nonce, 
    sizeof(tpmData.permanent.data.tpmDAASeed.nonce));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_RevokeTrust(TPM_NONCE *ekReset)
{
  info("TPM_RevokeTrust()");
  if (!tpmData.permanent.flags.enableRevokeEK) return TPM_FAIL;
  if (!tpm_get_physical_presence()) return TPM_BAD_PRESENCE;
  if (memcmp(ekReset, &tpmData.permanent.data.ekReset, 
             sizeof(TPM_NONCE))) return TPM_AUTHFAIL;
  tpm_owner_clear();
  tpm_rsa_release_private_key(&tpmData.permanent.data.endorsementKey);
  tpmData.permanent.data.endorsementKey.size = 0;
  /* Invalidate TPM_PERMANENT_DATA->tpmDAASeed */
  memset(tpmData.permanent.data.tpmDAASeed.nonce, 0, 
    sizeof(tpmData.permanent.data.tpmDAASeed.nonce));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ReadPubek(TPM_NONCE *antiReplay, TPM_PUBKEY *pubEndorsementKey, 
                         TPM_DIGEST *checksum)
{
  TPM_RESULT res;
  info("TPM_ReadPubek()");
  if (!tpmData.permanent.flags.readPubek) return TPM_DISABLED_CMD;
  /* get PUBEK */
  res = tpm_get_pubek(pubEndorsementKey);
  if (res != TPM_SUCCESS) return res; 
  /* compute checksum */
  if (tpm_compute_pubkey_checksum(antiReplay, pubEndorsementKey, checksum)) {
    tpm_free(pubEndorsementKey->pubKey.key);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_DisablePubekRead(TPM_AUTH *auth1)
{
  TPM_RESULT res;
  info("TPM_DisablePubekRead()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  tpmData.permanent.flags.readPubek = FALSE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_OwnerReadInternalPub(TPM_KEY_HANDLE keyHandle, TPM_AUTH *auth1,  
                                    TPM_PUBKEY *publicPortion)
{
  TPM_RESULT res;
  TPM_KEY_DATA *srk = &tpmData.permanent.data.srk;
  info("TPM_OwnerReadInternalPub()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  if (keyHandle == TPM_KH_EK) {
    return tpm_get_pubek(publicPortion);
  } else if (keyHandle == TPM_KH_SRK) {
    publicPortion->pubKey.keyLength = srk->key.size >> 3;
    publicPortion->pubKey.key = tpm_malloc(publicPortion->pubKey.keyLength);
    if (publicPortion->pubKey.key == NULL) return TPM_FAIL;
    tpm_rsa_export_modulus(&srk->key, publicPortion->pubKey.key, NULL);
    publicPortion->algorithmParms.algorithmID = TPM_ALG_RSA;
    publicPortion->algorithmParms.encScheme = srk->encScheme;
    publicPortion->algorithmParms.sigScheme = srk->sigScheme;
    publicPortion->algorithmParms.parms.rsa.keyLength = srk->key.size;
    publicPortion->algorithmParms.parms.rsa.numPrimes = 2;
    publicPortion->algorithmParms.parms.rsa.exponentSize = 0;
    publicPortion->algorithmParms.parms.rsa.exponent = NULL;
    publicPortion->algorithmParms.parmSize = 12;
    return TPM_SUCCESS;
  } else {
    return TPM_BAD_PARAMETER;
  }
}

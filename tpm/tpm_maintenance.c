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
 * $Id: tpm_maintenance.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_marshalling.h"
#include "tpm_data.h"
#include "crypto/sha1.h"

/*
 * Maintenance Functions ([TPM_Part3], Section 12)
 */

static int tpm_setup_privkey(TPM_KEY_DATA *key, TPM_KEY *privkey)
{
  size_t key_length;
  
  privkey->tag = TPM_TAG_KEY12;
  privkey->fill = 0;
  privkey->keyUsage = key->keyUsage;
  privkey->keyFlags = key->keyFlags;
  privkey->authDataUsage = key->authDataUsage;
  if (tpm_setup_key_parms(key, &privkey->algorithmParms) != 0) return -1;
  memcpy(&privkey->PCRInfo, &key->pcrInfo, sizeof(TPM_PCR_INFO)); 
  privkey->PCRInfoSize = sizeof_TPM_PCR_INFO(privkey->PCRInfo);
  privkey->encDataSize = 0;
  privkey->encData = NULL;
  key_length = key->key.size >> 3;
  privkey->pubKey.key = tpm_malloc(key_length);
  if (privkey->pubKey.key == NULL) {
    free_TPM_KEY((*privkey));
    return -1;
  }
  tpm_rsa_export_modulus(&key->key, privkey->pubKey.key, &key_length);
  privkey->pubKey.keyLength = key_length;
  return 0;
}

TPM_RESULT TPM_CreateMaintenanceArchive(BOOL generateRandom, TPM_AUTH *auth1,
                                        UINT32 *randomSize, BYTE **random,
                                        UINT32 *archiveSize, BYTE **archive)
{
  TPM_RESULT res;
  TPM_KEY key;
  TPM_DIGEST key_digest;
  BYTE *buf, *ptr;
  UINT32 len;
  size_t buf_len, p_len;
  
  info("TPM_CreateMaintenanceArchive()");
  if (!tpmData.permanent.flags.allowMaintenance) return TPM_DISABLED_CMD;
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  if (!tpmData.permanent.data.manuMaintPub.valid) return TPM_KEYNOTFOUND;
  /* set up a TPM_KEY structure for the SRK */
  if (tpm_setup_privkey(&tpmData.permanent.data.srk, &key) != 0) {
    debug("tpm_setup_privkey(SRK) failed");
    return TPM_FAIL;
  }
  if (tpm_compute_key_digest(&key, &key_digest) != 0) {
    debug("tpm_compute_key_digest() failed");
    free_TPM_KEY(key);
    return TPM_FAIL;
  }
  /* generate an OAEP encoding of the TPM_MIGRATE_ASYMKEY structure for
     the SRK: 0x00|seed|0x00-pad|0x01|TPM_MIGRATE_ASYMKEY */
  debug("generating OAEP encoding");
  buf_len = tpmData.permanent.data.manuMaintPub.key.size >> 3;
  buf = tpm_malloc(buf_len);
  if (buf == NULL) {
    free_TPM_KEY(key);
    return TPM_NOSPACE;
  }
  buf[0] = 0x00;
  tpm_rsa_export_prime1(&tpmData.permanent.data.srk.key, &buf[5], &p_len);
  ptr = &buf[1]; len = 4;
  tpm_marshal_UINT32(&ptr, &len, p_len);
  memmove(&buf[buf_len - (1 + 45 + p_len - 16)], &buf[5 + 16], p_len - 16);
  memset(&buf[5 + 16], 0, buf_len - 1 - 20 - 1 - 45 - p_len + 16);
  len = 1 + 45 + p_len - 16;
  ptr = &buf[buf_len - len];
  tpm_marshal_BYTE(&ptr, &len, 0x01);  
  tpm_marshal_TPM_PAYLOAD_TYPE(&ptr, &len, TPM_PT_MAINT);
  tpm_marshal_TPM_NONCE(&ptr, &len, &tpmData.permanent.data.tpmProof);
  tpm_marshal_TPM_DIGEST(&ptr, &len, &key_digest);
  tpm_marshal_UINT32(&ptr, &len, p_len - 16); 
  tpm_rsa_mask_generation(&buf[1], SHA1_DIGEST_LENGTH, 
    &buf[1 + SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH - 1);
  tpm_rsa_mask_generation(&buf[1 + SHA1_DIGEST_LENGTH], 
    buf_len - SHA1_DIGEST_LENGTH - 1, &buf[1], SHA1_DIGEST_LENGTH);
  /* XOR encrypt OAEP encoding */
  debug("generateRandom = %d", generateRandom);
  if (generateRandom) {
    *randomSize = buf_len;
    *random = tpm_malloc(*randomSize);
    if (*random == NULL) {
      free_TPM_KEY(key);
      tpm_free(buf);
      return TPM_NOSPACE;
    }
    tpm_get_random_bytes(*random, *randomSize);
    for (len = 0; len < buf_len; len++) buf[len] ^= (*random)[len];
  } else {
    *randomSize = 0;
    *random = NULL;
    tpm_rsa_mask_generation(tpmData.permanent.data.ownerAuth,
                            SHA1_DIGEST_LENGTH, buf, buf_len);
  }
  /* RSA encrypt OAEP encoding */
  if (tpm_rsa_encrypt(&tpmData.permanent.data.manuMaintPub.key, RSA_ES_PLAIN,
                      buf, buf_len, buf, &buf_len) != 0) {
    debug("tpm_rsa_encrypt() failed");
    free_TPM_KEY(key);
    tpm_free(buf);
    return TPM_FAIL;
  }
  key.encData = buf;
  key.encDataSize = buf_len;
  /* marshal response */
  len = *archiveSize = sizeof_TPM_KEY(key);
  ptr = *archive = tpm_malloc(len);
  debug("archiveSize = %d, archive = %p", *archiveSize, *archive);
  if (ptr == NULL || tpm_marshal_TPM_KEY(&ptr, &len, &key)) {
    tpm_free(ptr);
    tpm_free(*random);
    free_TPM_KEY(key);
    return TPM_NOSPACE;
  }
  free_TPM_KEY(key);
  *archiveSize -= len;
  tpmData.permanent.flags.maintenanceDone = TRUE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadMaintenanceArchive(UINT32 archiveSize, BYTE *archive,
                                      UINT32 sigSize, BYTE *sig,
                                      UINT32 randomSize, BYTE *random,
                                      TPM_AUTH *auth1)
{
  TPM_RESULT res;
  TPM_KEY newsrk;
  TPM_DIGEST digest;
  tpm_sha1_ctx_t sha1;
  BYTE *buf, *ptr;
  UINT32 len;
  size_t buf_len;
    
  info("TPM_LoadMaintenanceArchive()");
  /* verify authorization */
  if (!tpmData.permanent.data.manuMaintPub.valid) return TPM_KEYNOTFOUND;
  if (!tpmData.permanent.flags.allowMaintenance) return TPM_DISABLED_CMD;
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
   /* verify signature */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, archive, archiveSize);
  tpm_sha1_final(&sha1, digest.digest);
  if (sigSize != tpmData.permanent.data.manuMaintPub.key.size >> 3
      || tpm_rsa_verify(&tpmData.permanent.data.manuMaintPub.key,
                        RSA_SSA_PKCS1_SHA1, digest.digest,
                        sizeof(digest.digest), sig) != 0)
    return TPM_BAD_SIGNATURE;
  /* unmarshal archive */
  ptr = archive; len = archiveSize;
  if (tpm_unmarshal_TPM_KEY(&ptr, &len, &newsrk) != 0 || len != 0)
    return TPM_BAD_PARAMETER;
  /* decrypt private key */
  buf_len = newsrk.encDataSize;
  buf = tpm_malloc(buf_len);
  if (buf == NULL) return TPM_NOSPACE;
  if (tpm_rsa_decrypt(&tpmData.permanent.data.srk.key, RSA_ES_PLAIN,
                      newsrk.encData, newsrk.encDataSize, buf, &buf_len)
      || buf[0] != 0x00) {
    debug("tpm_rsa_decrypt() failed");
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  if (randomSize > 0) {
    for (len = 0; len < buf_len; len++) buf[len] ^= random[len];
  } else {
    tpm_rsa_mask_generation(tpmData.permanent.data.ownerAuth,
                            SHA1_DIGEST_LENGTH, buf, buf_len);
  }
  tpm_rsa_mask_generation(&buf[1 + SHA1_DIGEST_LENGTH],
    buf_len - SHA1_DIGEST_LENGTH - 1, &buf[1], SHA1_DIGEST_LENGTH);
  tpm_rsa_mask_generation(&buf[1], SHA1_DIGEST_LENGTH,
    &buf[1 + SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH - 1);
  /* validate new SRK */
  if (newsrk.keyFlags & TPM_KEY_FLAG_MIGRATABLE
      || newsrk.keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  if (newsrk.algorithmParms.algorithmID != TPM_ALG_RSA
      || newsrk.algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || newsrk.algorithmParms.sigScheme != TPM_SS_NONE
      || newsrk.algorithmParms.parmSize == 0
      || newsrk.algorithmParms.parms.rsa.keyLength != 2048
      || newsrk.algorithmParms.parms.rsa.numPrimes != 2
      || newsrk.algorithmParms.parms.rsa.exponentSize != 0
      || newsrk.PCRInfoSize != 0) return TPM_BAD_KEY_PROPERTY;
  /* clear owner but keep ownerAuth */
  memcpy(digest.digest, tpmData.permanent.data.ownerAuth, sizeof(TPM_SECRET));
  tpm_owner_clear();
  memcpy(tpmData.permanent.data.ownerAuth, digest.digest, sizeof(TPM_SECRET));
  /* update tpmProof */
  for (ptr = &buf[21]; *ptr == 0x00; ptr++);
  memcpy(&tpmData.permanent.data.tpmProof, &ptr[2], sizeof(TPM_NONCE));
  ptr += 1 + 25;
  memmove(&buf[21], ptr, &buf[buf_len] - ptr); 
  /* update SRK */
  tpmData.permanent.data.srk.keyFlags = newsrk.keyFlags;
  tpmData.permanent.data.srk.keyFlags |= TPM_KEY_FLAG_PCR_IGNORE;
  tpmData.permanent.data.srk.keyFlags &= ~TPM_KEY_FLAG_HAS_PCR;
  tpmData.permanent.data.srk.keyUsage = newsrk.keyUsage;
  tpmData.permanent.data.srk.keyControl = TPM_KEY_CONTROL_OWNER_EVICT;
  tpmData.permanent.data.srk.encScheme = newsrk.algorithmParms.encScheme;
  tpmData.permanent.data.srk.sigScheme = newsrk.algorithmParms.sigScheme;
  tpmData.permanent.data.srk.authDataUsage = newsrk.authDataUsage;
  tpmData.permanent.data.srk.parentPCRStatus = FALSE;
  if (tpm_rsa_import_key(&tpmData.permanent.data.srk.key, RSA_MSB_FIRST,
    newsrk.pubKey.key, newsrk.pubKey.keyLength,
    newsrk.algorithmParms.parms.rsa.exponent,
    newsrk.algorithmParms.parms.rsa.exponentSize, &buf[5], NULL) != 0) {
    tpm_free(buf);
    debug("tpm_rsa_import_key() failed");
    return TPM_FAIL;
  }
  /* enable SRK and mark TPM as owned */
  tpmData.permanent.data.srk.payload = TPM_PT_ASYM;
  tpmData.permanent.flags.owned = TRUE;
  tpmData.permanent.flags.maintenanceDone = TRUE;
  tpm_free(buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_KillMaintenanceFeature(TPM_AUTH *auth1)
{
  TPM_RESULT res;

  info("TPM_KillMaintenanceFeature()");
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  tpmData.permanent.flags.allowMaintenance = FALSE;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadManuMaintPub(TPM_NONCE *antiReplay, TPM_PUBKEY *pubKey,
                                TPM_DIGEST *checksum)
{
  TPM_PUBKEY_DATA *key = &tpmData.permanent.data.manuMaintPub;

  info("TPM_LoadManuMaintPub()");
  if (key->valid) return TPM_DISABLED_CMD;
  if (pubKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || pubKey->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || pubKey->algorithmParms.sigScheme != TPM_SS_NONE
      || pubKey->algorithmParms.parms.rsa.keyLength < 2048) 
    return TPM_BAD_KEY_PROPERTY;
  key->encScheme = pubKey->algorithmParms.encScheme;
  key->sigScheme = pubKey->algorithmParms.sigScheme;
  if (tpm_rsa_import_public_key(&key->key, RSA_MSB_FIRST, 
        pubKey->pubKey.key, pubKey->pubKey.keyLength,
        pubKey->algorithmParms.parms.rsa.exponent,
        pubKey->algorithmParms.parms.rsa.exponentSize) != 0) return TPM_FAIL;
  if (tpm_compute_pubkey_checksum(antiReplay, pubKey, checksum) != 0)
    return TPM_FAIL;
  tpmData.permanent.data.manuMaintPub.valid = 1;
  return TPM_SUCCESS;
}

static int tpm_setup_pubkey(TPM_PUBKEY_DATA *key, TPM_PUBKEY *pubkey)
{
  size_t key_length;
 
  key_length = key->key.size >> 3;
  pubkey->pubKey.key = tpm_malloc(key_length);
  if (pubkey->pubKey.key == NULL) return -1;
  tpm_rsa_export_public_modulus(&key->key, pubkey->pubKey.key, &key_length);
  pubkey->pubKey.keyLength = key_length;
  key_length = key->key.size >> 3;
  pubkey->algorithmParms.parms.rsa.exponent = tpm_malloc(key_length);
  if (pubkey->algorithmParms.parms.rsa.exponent == NULL) {
    tpm_free(pubkey->pubKey.key);
    return -1;
  }
  tpm_rsa_export_public_exponent(&key->key, 
    pubkey->algorithmParms.parms.rsa.exponent, &key_length);
  pubkey->algorithmParms.parms.rsa.exponentSize = key_length;
  pubkey->algorithmParms.algorithmID = TPM_ALG_RSA;
  pubkey->algorithmParms.encScheme = key->encScheme;
  pubkey->algorithmParms.sigScheme = key->sigScheme;
  pubkey->algorithmParms.parms.rsa.keyLength = key->key.size;
  pubkey->algorithmParms.parms.rsa.numPrimes = 2;
  pubkey->algorithmParms.parmSize = 
    sizeof_TPM_RSA_KEY_PARMS(pubkey->algorithmParms.parms.rsa);
  return 0;
}

TPM_RESULT TPM_ReadManuMaintPub(TPM_NONCE *antiReplay, TPM_DIGEST *checksum)
{
  TPM_PUBKEY key;
  int res;
  
  info("TPM_ReadManuMaintPub()");
  if (!tpmData.permanent.data.manuMaintPub.valid) return TPM_KEYNOTFOUND;
  if (tpm_setup_pubkey(&tpmData.permanent.data.manuMaintPub, &key) != 0)
    return TPM_FAIL;
  res = tpm_compute_pubkey_checksum(antiReplay, &key, checksum);
  free_TPM_PUBKEY(key);
  return (res == 0) ? TPM_SUCCESS : TPM_FAIL;
}


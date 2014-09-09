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
 * $Id: tpm_migration.c 462 2011-06-04 14:14:33Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_data.h"
#include "tpm_marshalling.h"
#include "crypto/sha1.h"
#include "crypto/hmac.h"

/*
 * Migration ([TPM_Part3], Section 11)
 */

static int tpm_compute_migration_digest(TPM_PUBKEY *migrationKey,
                                        TPM_MIGRATE_SCHEME migrationScheme,
                                        TPM_NONCE *tpmProof, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_PUBKEY((*migrationKey));
  BYTE *buf, *ptr, buf2[2];
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, migrationKey)) {
    tpm_free(buf);
    return -1;
  }
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_PUBKEY((*migrationKey)));
  ptr = buf2; len = 2;
  tpm_marshal_UINT16(&ptr, &len, migrationScheme);
  tpm_sha1_update(&sha1, buf2, 2);
  tpm_sha1_update(&sha1, tpmProof->nonce, sizeof(TPM_NONCE));
  tpm_sha1_final(&sha1, digest->digest);
  tpm_free(buf);
  return 0;
}

static int tpm_verify_migration_digest(TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
                                       TPM_NONCE *tpmProof)
{
  TPM_DIGEST digest;
  if (tpm_compute_migration_digest(&migrationKeyAuth->migrationKey,
      migrationKeyAuth->migrationScheme, tpmProof, &digest)) return -1;
  return memcmp(digest.digest, migrationKeyAuth->digest.digest, sizeof(TPM_DIGEST));
}

TPM_RESULT TPM_CreateMigrationBlob(TPM_KEY_HANDLE parentHandle,
                                   TPM_MIGRATE_SCHEME migrationType,
                                   TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
                                   UINT32 encDataSize, BYTE *encData,
                                   TPM_AUTH *auth1, TPM_AUTH *auth2,
                                   UINT32 *randomSize, BYTE **random,
                                   UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_SESSION_DATA *session;
  BYTE *key_buf;
  UINT32 key_buf_size;
  TPM_STORE_ASYMKEY store;
  TPM_PUBKEY_DATA key;

  info("TPM_CreateMigrationBlob()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify parent authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  session = tpm_get_auth(auth2->authHandle);
  if (session == NULL || session->type != TPM_ST_OIAP) return TPM_AUTHFAIL;
  /* verify key properties */
  if (parent->keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  if (tpm_decrypt_private_key(parent, encData, encDataSize,
                              &store, &key_buf, &key_buf_size) != 0) {
    return TPM_DECRYPT_ERROR;
  }
  if (store.payload != TPM_PT_ASYM) {
    tpm_free(key_buf);
    return TPM_DECRYPT_ERROR;
  }
  debug("key size: %d / %d", store.privKey.keyLength, key_buf_size);
  /* verify migration authorization */
  res = tpm_verify_auth(auth2, store.migrationAuth, TPM_INVALID_HANDLE);
  if (res != TPM_SUCCESS) {
    tpm_free(key_buf);
    return TPM_MIGRATEFAIL;
  }
  if (tpm_verify_migration_digest(migrationKeyAuth,
      &tpmData.permanent.data.tpmProof)) {
    debug("tpm_verify_migration_digest() failed");
    tpm_free(key_buf);
    return TPM_MIGRATEFAIL;
  }
  debug("migration authorization is valid.");
  /* set public key */
  if (tpm_setup_pubkey_data(&migrationKeyAuth->migrationKey, &key) != 0) {
      debug("tpm_setup_pubkey() failed");
      tpm_free(key_buf);
      return TPM_FAIL;
  }
  /* perform migration */
  if (migrationType == TPM_MS_REWRAP) {
    /* re-encrypt raw key data */
    debug("migrationType = TPM_MS_REWRAP");
    *random = NULL;
    *randomSize = 0;
    *outDataSize = key.key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (*outData == NULL) {
      free_TPM_PUBKEY_DATA(key);
      tpm_free(*outData);
      tpm_free(key_buf);
      return TPM_FAIL;
    }
    if (tpm_encrypt_public(&key, key_buf, key_buf_size,
                           *outData, outDataSize) != 0) {
        free_TPM_PUBKEY_DATA(key);
        tpm_free(*outData);
        tpm_free(key_buf);
        return TPM_ENCRYPT_ERROR;
    }
  } else if (migrationType == TPM_MS_MIGRATE) {
    BYTE *ptr, *buf;
    UINT32 len;
    size_t buf_len;
    /* generate an OAEP encoding of the TPM_MIGRATE_ASYMKEY structure:
       K1|seed|0x00-pad|0x01|TPM_MIGRATE_ASYMKEY */
    debug("migrationType = TPM_MS_MIGRATE");
    len = buf_len = 198;
    ptr = buf = tpm_malloc(buf_len);
    *randomSize = buf_len;
    *random = tpm_malloc(*randomSize);
    *outDataSize = key.key.size >> 3;
    *outData = tpm_malloc(*outDataSize);
    if (buf == NULL || *random == NULL || *outData == NULL) {
      free_TPM_PUBKEY_DATA(key);
      tpm_free(buf);
      tpm_free(*random);
      tpm_free(*outData);
      tpm_free(key_buf);
      return TPM_NOSPACE;
    }
    memset(buf, 0, buf_len);
    tpm_marshal_UINT32(&ptr, &len, store.privKey.keyLength);
    memcpy(ptr, store.privKey.key, 16);
    ptr += 16;
    memcpy(ptr, store.migrationAuth, sizeof(TPM_SECRET));
    len = 46 + store.privKey.keyLength - 16;
    ptr = &buf[buf_len - len];
    tpm_marshal_BYTE(&ptr, &len, 0x01);
    tpm_marshal_TPM_PAYLOAD_TYPE(&ptr, &len, TPM_PT_MIGRATE);
    tpm_marshal_TPM_SECRET(&ptr, &len, &store.usageAuth);
    tpm_marshal_TPM_DIGEST(&ptr, &len, &store.pubDataDigest);
    tpm_marshal_UINT32(&ptr, &len, store.privKey.keyLength - 16);
    memcpy(ptr, &store.privKey.key[16], store.privKey.keyLength - 16);
    tpm_rsa_mask_generation(buf, SHA1_DIGEST_LENGTH,
      &buf[SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH);
    tpm_rsa_mask_generation(&buf[SHA1_DIGEST_LENGTH],
      buf_len - SHA1_DIGEST_LENGTH, buf, SHA1_DIGEST_LENGTH);
    /* XOR encrypt OAEP encoding */
    tpm_get_random_bytes(*random, *randomSize);
    for (len = 0; len < buf_len; len++) buf[len] ^= (*random)[len];
    /* RSA encrypt OAEP encoding */
    if (tpm_rsa_encrypt(&key.key, RSA_ES_OAEP_SHA1, buf, buf_len,
                        *outData, &buf_len)) {
      debug("tpm_rsa_encrypt() failed");
      free_TPM_PUBKEY_DATA(key);
      tpm_free(buf);
      tpm_free(*random);
      tpm_free(*outData);
      tpm_free(key_buf);
      return TPM_ENCRYPT_ERROR;
    }
    *outDataSize = buf_len;
    tpm_free(buf);
  } else {
    debug("invalid migration type: %d", migrationType);
    free_TPM_PUBKEY_DATA(key);
    tpm_free(key_buf);
    return TPM_BAD_PARAMETER;
  }
  free_TPM_PUBKEY_DATA(key);
  tpm_free(key_buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ConvertMigrationBlob(TPM_KEY_HANDLE parentHandle,
                                    UINT32 inDataSize, BYTE *inData,
                                    UINT32 randomSize, BYTE *random,
                                    TPM_AUTH *auth1,
                                    UINT32 *outDataSize,BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  BYTE *ptr, *buf;
  UINT32 len;
  size_t buf_len;
  TPM_STORE_ASYMKEY store;

  info("TPM_ConvertMigrationBlob()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify parent authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || parent->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
    if (res != TPM_SUCCESS) return res;
  }
  /* verify key properties */
  if (parent->keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  buf_len = parent->key.size >> 3;
  buf = tpm_malloc(buf_len);
  if (buf == NULL) return TPM_NOSPACE;
  /* RSA decrypt OAEP encoding */
  if (tpm_rsa_decrypt(&parent->key, RSA_ES_OAEP_SHA1,
                      inData, inDataSize, buf, &buf_len)
      || buf_len != randomSize || buf_len != 198) {
    debug("tpm_rsa_decrypt() failed");
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  /* XOR decrypt OAEP encoding */
  for (len = 0; len < buf_len; len++) buf[len] ^= random[len];
  /* unmask OAEP encoding */
  tpm_rsa_mask_generation(&buf[SHA1_DIGEST_LENGTH],
    buf_len - SHA1_DIGEST_LENGTH, buf, SHA1_DIGEST_LENGTH);
  tpm_rsa_mask_generation(buf, SHA1_DIGEST_LENGTH,
    &buf[SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH);
  /* create a TPM_STORE_ASYMKEY structure */
  memcpy(store.migrationAuth, &buf[20], sizeof(TPM_SECRET));
  for (ptr = &buf[20 + sizeof(TPM_SECRET)]; *ptr == 0x00; ptr++);
  if (ptr[0] != 0x01 || ptr[1] != TPM_PT_MIGRATE) {
      debug("OAEP encoding is invalid");
      tpm_free(buf);
      return TPM_DECRYPT_ERROR;
  }
  ptr += 2;
  len = buf_len - (ptr - buf);
  store.payload = TPM_PT_ASYM;
  tpm_unmarshal_TPM_SECRET(&ptr, &len, &store.usageAuth);
  tpm_unmarshal_TPM_DIGEST(&ptr, &len, &store.pubDataDigest);
  tpm_unmarshal_UINT32(&ptr, &len, &store.privKey.keyLength);
  store.privKey.keyLength += 16;
  if (store.privKey.keyLength != len + 16) {
    error("invalid key length %d; expected %d",
          store.privKey.keyLength, len + 16);
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  memmove(&buf[20], ptr, len);
  store.privKey.key = &buf[4];
  /* encrypt private key */
  *outDataSize = parent->key.size >> 3;
  *outData = tpm_malloc(*outDataSize);
  if (*outData == NULL) {
    tpm_free(buf);
    return TPM_NOSPACE;
  }
  if (tpm_encrypt_private_key(parent, &store, *outData, outDataSize)) {
    debug("tpm_encrypt_private_key() failed");
    tpm_free(*outData);
    tpm_free(buf);
    return TPM_ENCRYPT_ERROR;
  }
  tpm_free(buf);
  return TPM_SUCCESS;
}

static int tpm_copy_pubkey(TPM_PUBKEY *in, TPM_PUBKEY *out)
{
  memcpy(out, in, sizeof(TPM_PUBKEY));
  out->pubKey.key = tpm_malloc(out->pubKey.keyLength);
  if (out->pubKey.key == NULL) return -1;
  memcpy(out->pubKey.key, in->pubKey.key, out->pubKey.keyLength);
  out->algorithmParms.parms.rsa.exponent =
    tpm_malloc(out->algorithmParms.parms.rsa.exponentSize);
  if (out->algorithmParms.parms.rsa.exponent == NULL) {
    tpm_free(out->pubKey.key);
    return -1;
  }
  memcpy(out->algorithmParms.parms.rsa.exponent,
    in->algorithmParms.parms.rsa.exponent,
    out->algorithmParms.parms.rsa.exponentSize);
  return 0;
}

TPM_RESULT TPM_AuthorizeMigrationKey(TPM_MIGRATE_SCHEME migrateScheme,
                                     TPM_PUBKEY *migrationKey, TPM_AUTH *auth1,
                                     TPM_MIGRATIONKEYAUTH *outData)
{
  TPM_RESULT res;

  info("TPM_AuthorizeMigrationKey()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* verify the key size and encryption scheme */
  if (migrationKey->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
      || migrationKey->algorithmParms.algorithmID != TPM_ALG_RSA)
    return TPM_INAPPROPRIATE_ENC;
  if (migrationKey->algorithmParms.parms.rsa.keyLength  < 2048)
    return TPM_BAD_KEY_PROPERTY;
  /* create migration key authorization */
  if (tpm_compute_migration_digest(migrationKey, migrateScheme,
      &tpmData.permanent.data.tpmProof, &outData->digest) != 0) {
      debug("tpm_compute_migration_digest() failed");
      return TPM_FAIL;
  }
  outData->migrationScheme = migrateScheme;
  if (tpm_copy_pubkey(migrationKey, &outData->migrationKey) != 0) {
      debug("tpm_copy_pubkey() failed");
      return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_MigrateKey(TPM_KEY_HANDLE maKeyHandle, TPM_PUBKEY *pubKey,
                          UINT32 inDataSize, BYTE *inData, TPM_AUTH *auth1,
                          UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_PUBKEY_DATA key2;
  UINT32 size;
  BYTE *buf;
  UINT32 buf_len;

  info("TPM_MigrateKey()");
  key = tpm_get_key(maKeyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify key authorization */
  res = tpm_verify_auth(auth1, key->usageAuth, maKeyHandle);
  if (res != TPM_SUCCESS) return res;
  /* verify key usage */
  if (key->keyUsage != TPM_KEY_MIGRATE) return TPM_BAD_KEY_PROPERTY;
  if (key->encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1) return TPM_INAPPROPRIATE_ENC;
  /* verify public key  */
  if (pubKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || pubKey->algorithmParms.parms.rsa.keyLength < (inDataSize << 3))
    return TPM_BAD_KEY_PROPERTY;
  if (tpm_setup_pubkey_data(pubKey, &key2) != 0) return TPM_FAIL;
  /* decrypt inData and re-encrypt it with the public key */
  *outDataSize = size = pubKey->algorithmParms.parms.rsa.keyLength >> 3;
  *outData = tpm_malloc(*outDataSize);
  buf_len = inDataSize;
  buf = tpm_malloc(buf_len);
  if (*outData == NULL || buf == NULL) {
    free_TPM_PUBKEY_DATA(key2);
    tpm_free(*outData);
    tpm_free(buf);
    return TPM_NOSPACE;
  }
  if (tpm_decrypt(key, inData, inDataSize, buf, &buf_len) != 0) {
    free_TPM_PUBKEY_DATA(key2);
    tpm_free(*outData);
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  if (tpm_encrypt_public(&key2, buf, buf_len, *outData, outDataSize) != 0) {
    free_TPM_PUBKEY_DATA(key2);
    tpm_free(*outData);
    tpm_free(buf);
    return TPM_ENCRYPT_ERROR;
  }
  free_TPM_PUBKEY_DATA(key2);
  tpm_free(buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_SetRestrictions(TPM_CMK_DELEGATE restriction,
                                   TPM_AUTH *auth1)
{
  TPM_RESULT res;

  info("TPM_CMK_SetRestrictions()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* update delegation restriction */
  tpmData.permanent.data.restrictDelegate = restriction;
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_ApproveMA(TPM_DIGEST *migrationAuthorityDigest,
                             TPM_AUTH *auth1, TPM_HMAC *outData)
{
  TPM_RESULT res;
  BYTE buf[2];
  tpm_hmac_ctx_t ctx;

  info("TPM_CMK_ApproveMA()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  if (res != TPM_SUCCESS) return res;
  /* create hmac of a TPM_CMK_MA_APPROVAL structure */
  buf[0] = (TPM_TAG_CMK_MA_APPROVAL >> 8) & 0xff;
  buf[1] = TPM_TAG_CMK_MA_APPROVAL & 0xff;
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce, sizeof(TPM_NONCE));
  tpm_hmac_update(&ctx, buf, 2);
  tpm_hmac_update(&ctx, migrationAuthorityDigest->digest, sizeof(TPM_DIGEST));
  tpm_hmac_final(&ctx, outData->digest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_CreateKey(TPM_KEY_HANDLE parentHandle,
                             TPM_ENCAUTH *dataUsageAuth,
                             TPM_KEY *keyInfo,
                             TPM_HMAC *migrationAuthorityApproval,
                             TPM_DIGEST *migrationAuthorityDigest,
                             TPM_AUTH *auth1, TPM_AUTH *auth2,
                             TPM_KEY *wrappedKey)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_SESSION_DATA *session;
  tpm_hmac_ctx_t ctx;
  BYTE buf[SHA1_DIGEST_LENGTH];
  TPM_STORE_ASYMKEY store;
  tpm_rsa_private_key_t rsa;
  UINT32 key_length;
  TPM_PUBKEY pubKey;
  TPM_DIGEST keyDigest;

  info("TPM_CMK_CreateKey()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* must be TPM_KEY12 */
  if (keyInfo->tag != TPM_TAG_KEY12) return TPM_INVALID_STRUCTURE;
  /* verify key parameters */
  if (parent->keyUsage != TPM_KEY_STORAGE
      || parent->encScheme == TPM_ES_NONE
      || parent->keyFlags & TPM_KEY_FLAG_MIGRATABLE
      || !(keyInfo->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
      || !(keyInfo->keyFlags & TPM_KEY_FLAG_AUTHORITY)
      || keyInfo->keyUsage == TPM_KEY_IDENTITY
      || keyInfo->keyUsage == TPM_KEY_AUTHCHANGE) return TPM_INVALID_KEYUSAGE;
  if (keyInfo->algorithmParms.algorithmID != TPM_ALG_RSA
      || keyInfo->algorithmParms.parmSize == 0
      || keyInfo->algorithmParms.parms.rsa.keyLength < 512
      || keyInfo->algorithmParms.parms.rsa.numPrimes != 2
      || keyInfo->algorithmParms.parms.rsa.exponentSize != 0)
    return TPM_BAD_KEY_PROPERTY;
  if (tpmData.permanent.flags.FIPS
      && (keyInfo->algorithmParms.parms.rsa.keyLength < 1024
          || keyInfo->authDataUsage == TPM_AUTH_NEVER
          || keyInfo->keyUsage == TPM_KEY_LEGACY)) return TPM_NOTFIPS;
  if ((keyInfo->keyUsage == TPM_KEY_STORAGE
       || keyInfo->keyUsage == TPM_KEY_MIGRATE)
      && (keyInfo->algorithmParms.algorithmID != TPM_ALG_RSA
          || keyInfo->algorithmParms.parms.rsa.keyLength != 2048
          || keyInfo->algorithmParms.sigScheme != TPM_SS_NONE
          || keyInfo->algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1))
    return TPM_BAD_KEY_PROPERTY;
  /* verify migration authority */
  buf[0] = (TPM_TAG_CMK_MA_APPROVAL >> 8) & 0xff;
  buf[1] = TPM_TAG_CMK_MA_APPROVAL & 0xff;
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce, sizeof(TPM_NONCE));
  tpm_hmac_update(&ctx, buf, 2);
  tpm_hmac_update(&ctx, migrationAuthorityDigest->digest, sizeof(TPM_DIGEST));
  tpm_hmac_final(&ctx, buf);
  if (memcmp(migrationAuthorityApproval->digest, buf, sizeof(TPM_HMAC)) != 0)
    return TPM_MA_AUTHORITY;
  /* setup the wrapped key */
  memcpy(wrappedKey, keyInfo, sizeof(TPM_KEY));
  /* setup key store */
  store.payload = TPM_PT_MIGRATE_RESTRICTED;
  tpm_decrypt_auth_secret(*dataUsageAuth, session->sharedSecret,
    &session->lastNonceEven, store.usageAuth);
  /* compute PCR digest */
  if (keyInfo->PCRInfoSize > 0) {
    tpm_compute_pcr_digest(&keyInfo->PCRInfo.creationPCRSelection,
      &keyInfo->PCRInfo.digestAtCreation, NULL);
    keyInfo->PCRInfo.localityAtCreation =
      tpmData.stany.flags.localityModifier;
  }
  /* generate key and store it */
  key_length = keyInfo->algorithmParms.parms.rsa.keyLength;
  if (tpm_rsa_generate_key(&rsa, key_length)) {
    debug("TPM_CreateWrapKey(): tpm_rsa_generate_key() failed.");
    return TPM_FAIL;
  }
  wrappedKey->pubKey.keyLength = key_length >> 3;
  wrappedKey->pubKey.key = tpm_malloc(wrappedKey->pubKey.keyLength);
  store.privKey.keyLength = key_length >> 4;
  store.privKey.key = tpm_malloc(store.privKey.keyLength);
  wrappedKey->encDataSize = parent->key.size >> 3;
  wrappedKey->encData = tpm_malloc(wrappedKey->encDataSize);
  if (wrappedKey->pubKey.key == NULL || store.privKey.key == NULL
      || wrappedKey->encData == NULL) {
    tpm_rsa_release_private_key(&rsa);
    tpm_free(wrappedKey->pubKey.key);
    tpm_free(store.privKey.key);
    tpm_free(wrappedKey->encData);
    return TPM_NOSPACE;
  }
  tpm_rsa_export_modulus(&rsa, wrappedKey->pubKey.key, NULL);
  tpm_rsa_export_prime1(&rsa, store.privKey.key, NULL);
  tpm_rsa_release_private_key(&rsa);
  /* create hmac of TPM_CMK_MIGAUTH  */
  buf[0] = (TPM_TAG_CMK_MIGAUTH >> 8) & 0xff;
  buf[1] = TPM_TAG_CMK_MIGAUTH & 0xff;
  memcpy(&pubKey.algorithmParms, &wrappedKey->algorithmParms,
         sizeof(TPM_KEY_PARMS));
  memcpy(&pubKey.pubKey, &wrappedKey->pubKey, sizeof(TPM_STORE_PUBKEY));
  if (tpm_compute_pubkey_digest(&pubKey, &keyDigest) !=0 ) {
    debug("tpm_compute_pubkey_digest() failed");
    return TPM_FAIL;
  }
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce, sizeof(TPM_NONCE));
  tpm_hmac_update(&ctx, buf, 2);
  tpm_hmac_update(&ctx, migrationAuthorityDigest->digest, sizeof(TPM_DIGEST));
  tpm_hmac_update(&ctx, keyDigest.digest, sizeof(TPM_DIGEST));
  tpm_hmac_final(&ctx, store.migrationAuth);
  /* compute the digest of the wrapped key (without encData) */
  if (tpm_compute_key_digest(wrappedKey, &store.pubDataDigest)) {
    debug("TPM_CreateWrapKey(): tpm_compute_key_digest() failed.");
    return TPM_FAIL;
  }
  /* encrypt private key data */
  if (tpm_encrypt_private_key(parent, &store, wrappedKey->encData,
      &wrappedKey->encDataSize)) {
    tpm_free(wrappedKey->pubKey.key);
    tpm_free(store.privKey.key);
    tpm_free(wrappedKey->encData);
    return TPM_ENCRYPT_ERROR;
  }
  tpm_free(store.privKey.key);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_CreateTicket(TPM_PUBKEY *verificationKey,
                                TPM_DIGEST *signedData,
                                UINT32 signatureValueSize,
                                BYTE *signatureValue, TPM_AUTH *auth1,
                                TPM_DIGEST *sigTicket)
{
  TPM_RESULT res;
  TPM_PUBKEY_DATA key;
  BYTE buf[2];
  TPM_DIGEST keyDigest;
  tpm_hmac_ctx_t ctx;

  info("TPM_CMK_CreateTicket()");
  /* verify authorization */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  /* verify key type and algorithm */
  if (verificationKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || verificationKey->algorithmParms.encScheme != TPM_ES_NONE)
    return TPM_BAD_KEY_PROPERTY;
  if (verificationKey->algorithmParms.sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1
      && verificationKey->algorithmParms.sigScheme != TPM_SS_RSASSAPKCS1v15_INFO)
    return TPM_BAD_KEY_PROPERTY;
  /* verify signature */
  if (tpm_setup_pubkey_data(verificationKey, &key) != 0) return TPM_FAIL;
  res = tpm_verify(&key, auth1, FALSE, signedData->digest, sizeof(TPM_DIGEST),
                   signatureValue, signatureValueSize);
  free_TPM_PUBKEY_DATA(key);
  if (res != TPM_SUCCESS) return res;
  /* create hmac on TPM_CMK_SIGTICKET */
  buf[0] = (TPM_TAG_CMK_SIGTICKET >> 8) & 0xff;
  buf[1] = TPM_TAG_CMK_SIGTICKET & 0xff;
  if (tpm_compute_pubkey_digest(verificationKey, &keyDigest) !=0 ) {
    debug("tpm_compute_pubkey_digest() failed");
    return TPM_FAIL;
  }
  tpm_hmac_init(&ctx, tpmData.permanent.data.tpmProof.nonce, sizeof(TPM_NONCE));
  tpm_hmac_update(&ctx, buf, 2);
  tpm_hmac_update(&ctx, keyDigest.digest, sizeof(TPM_DIGEST));
  tpm_hmac_update(&ctx, signedData->digest, sizeof(TPM_DIGEST));
  tpm_hmac_final(&ctx, sigTicket->digest);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_CreateBlob(TPM_KEY_HANDLE parentHandle,
                              TPM_MIGRATE_SCHEME migrationType,
                              TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
                              TPM_DIGEST *pubSourceKeyDigest,
                              TPM_MSA_COMPOSITE *msaList,
                              TPM_CMK_AUTH *restrictTicket,
                              TPM_HMAC *sigTicket,
                              UINT32 encDataSize, BYTE *encData,
                              TPM_AUTH *auth1,
                              UINT32 *randomSize, BYTE **random,
                              UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_STORE_ASYMKEY store;
  BYTE *key_buf;
  UINT32 key_buf_size;
  tpm_hmac_ctx_t hmac_ctx;
  tpm_sha1_ctx_t sha1_ctx;
  BYTE tag[2], hmac[SHA1_DIGEST_LENGTH];
  BYTE *ptr, *buf;
  UINT32 i, len;
  size_t buf_len;
  TPM_DIGEST migKeyDigest;
  TPM_DIGEST msaListDigest;
  TPM_DIGEST ticketDigest;
  TPM_PUBKEY_DATA key;

  info("TPM_CMK_CreateBlob()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  /* migrationType must match */
  if (migrationType != migrationKeyAuth->migrationScheme) return TPM_BAD_MODE;
  if (parent->keyFlags & TPM_KEY_FLAG_MIGRATABLE) return TPM_BAD_KEY_PROPERTY;
  /* decrypt private key */
  if (tpm_decrypt_private_key(parent, encData, encDataSize,
                              &store, &key_buf, &key_buf_size) != 0) {
    return TPM_DECRYPT_ERROR;
  }
  if (store.payload != TPM_PT_MIGRATE_RESTRICTED
      && store.payload != TPM_PT_MIGRATE_EXTERNAL) {
    tpm_free(key_buf);
    return TPM_DECRYPT_ERROR;
  }
  if (tpm_verify_migration_digest(migrationKeyAuth,
      &tpmData.permanent.data.tpmProof)) {
    debug("tpm_verify_migration_digest() failed");
    tpm_free(key_buf);
    return TPM_MIGRATEFAIL;
  }
  /* verify the migration authority list */
  len = sizeof_TPM_MSA_COMPOSITE((*msaList));
  ptr = buf = tpm_malloc(len);
  if (buf == NULL || tpm_marshal_TPM_MSA_COMPOSITE(&ptr, &len, msaList)) {
    debug("tpm_marshal_TPM_MSA_COMPOSITE() failed");
    tpm_free(buf);
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf, sizeof_TPM_MSA_COMPOSITE((*msaList)));
  tpm_sha1_final(&sha1_ctx, msaListDigest.digest);
  tpm_free(buf);
  tag[0] = (TPM_TAG_CMK_MIGAUTH >> 8) & 0xff;
  tag[1] = TPM_TAG_CMK_MIGAUTH & 0xff;
  tpm_hmac_init(&hmac_ctx, tpmData.permanent.data.tpmProof.nonce, sizeof(TPM_NONCE));
  tpm_hmac_update(&hmac_ctx, tag, 2);
  tpm_hmac_update(&hmac_ctx, msaListDigest.digest, sizeof(TPM_DIGEST));
  tpm_hmac_update(&hmac_ctx, pubSourceKeyDigest->digest, sizeof(TPM_DIGEST));
  tpm_hmac_final(&hmac_ctx, hmac);
  if (memcmp(hmac, store.migrationAuth, sizeof(TPM_SECRET)) != 0) {
    tpm_free(key_buf);
    return TPM_MA_AUTHORITY;
  }
  if (tpm_compute_pubkey_digest(&migrationKeyAuth->migrationKey, &migKeyDigest) !=0 ) {
    debug("tpm_compute_pubkey_digest() failed");
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  len = sizeof_TPM_CMK_AUTH((*restrictTicket));
  ptr = buf = tpm_malloc(len);
  if (buf == NULL || tpm_marshal_TPM_CMK_AUTH(&ptr, &len, restrictTicket)) {
    debug("tpm_marshal_TPM_CMK_AUTH() failed");
    tpm_free(buf);
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf, sizeof_TPM_CMK_AUTH((*restrictTicket)));
  tpm_sha1_final(&sha1_ctx, ticketDigest.digest);
  tpm_free(buf);
  /* verify the migration destination */
  if (migrationKeyAuth->migrationScheme == TPM_MS_RESTRICT_MIGRATE) {
    for (i = 0; i < msaList->MSAlist; i++) {
        if (memcmp(msaList->migAuthDigest[i].digest, migKeyDigest.digest,
                   sizeof(TPM_DIGEST)) == 0) break;
    }
    if (i >= msaList->MSAlist) {
      tpm_free(key_buf);
      return TPM_MA_AUTHORITY;
    }
    /* verify the key type and algorithm */
    if (migrationKeyAuth->migrationKey.algorithmParms.algorithmID != TPM_ALG_RSA
        || migrationKeyAuth->migrationKey.algorithmParms.encScheme != TPM_ES_RSAESOAEP_SHA1_MGF1
        || migrationKeyAuth->migrationKey.algorithmParms.sigScheme != TPM_SS_NONE) {
      tpm_free(key_buf);
      return TPM_BAD_KEY_PROPERTY;
    }
  } else if (migrationKeyAuth->migrationScheme == TPM_MS_RESTRICT_APPROVE) {
    if (restrictTicket == NULL || sigTicket == NULL) {
      tpm_free(key_buf);
      return TPM_BAD_PARAMETER;
    }
    for (i = 0; i < msaList->MSAlist; i++) {
      /* create hmac of TPM_CMK_SIGTICKET */
      tag[0] = (TPM_TAG_CMK_SIGTICKET >> 8) & 0xff;
      tag[1] = TPM_TAG_CMK_SIGTICKET & 0xff;
      tpm_hmac_init(&hmac_ctx, tpmData.permanent.data.tpmProof.nonce,
                    sizeof(TPM_NONCE));
      tpm_hmac_update(&hmac_ctx, tag, 2);
      tpm_hmac_update(&hmac_ctx, msaList->migAuthDigest[i].digest,
                      sizeof(TPM_DIGEST));
      tpm_hmac_update(&hmac_ctx, ticketDigest.digest, sizeof(TPM_DIGEST));
      tpm_hmac_final(&hmac_ctx, hmac);
      if (memcmp(hmac, sigTicket->digest, sizeof(TPM_DIGEST)) == 0) break;
    }
    if (i >= msaList->MSAlist) {
      tpm_free(key_buf);
      return TPM_MA_AUTHORITY;
    }
    if (memcmp(&restrictTicket->destinationKeyDigest, &migKeyDigest,
               sizeof(TPM_DIGEST)) != 0) {
      tpm_free(key_buf);
      return TPM_MA_DESTINATION;
    }
    if (memcmp(&restrictTicket->sourceKeyDigest, pubSourceKeyDigest,
               sizeof(TPM_DIGEST)) != 0) {
      tpm_free(key_buf);
      return TPM_MA_SOURCE;
    }
  } else {
    tpm_free(key_buf);
    return TPM_BAD_PARAMETER;
  }
  /* set public key */
  if (tpm_setup_pubkey_data(&migrationKeyAuth->migrationKey, &key) != 0) {
    debug("tpm_setup_pubkey() failed");
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  /* generate an OAEP encoding of the TPM_MIGRATE_ASYMKEY structure:
     0x00|seed|K1|0x00-pad|0x01|TPM_MIGRATE_ASYMKEY */
  len = buf_len = 198;
  ptr = buf = tpm_malloc(buf_len);
  *randomSize = buf_len;
  *random = tpm_malloc(*randomSize);
  *outDataSize = key.key.size >> 3;
  *outData = tpm_malloc(*outDataSize);
  if (buf == NULL || *random == NULL || *outData == NULL) {
    free_TPM_PUBKEY_DATA(key);
    tpm_free(buf);
    tpm_free(*random);
    tpm_free(*outData);
    tpm_free(key_buf);
    return TPM_NOSPACE;
  }
  memset(buf, 0, buf_len);
  tpm_marshal_UINT32(&ptr, &len, store.privKey.keyLength);
  memcpy(ptr, store.privKey.key, 16);
  ptr += 16;
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, msaListDigest.digest, sizeof(TPM_DIGEST));
  tpm_sha1_update(&sha1_ctx, pubSourceKeyDigest->digest, sizeof(TPM_DIGEST));
  tpm_sha1_final(&sha1_ctx, ptr);
  len = 46 + store.privKey.keyLength - 16;
  ptr = &buf[buf_len - len];
  tpm_marshal_BYTE(&ptr, &len, 0x01);
  tpm_marshal_TPM_PAYLOAD_TYPE(&ptr, &len, TPM_PT_CMK_MIGRATE);
  tpm_marshal_TPM_SECRET(&ptr, &len, &store.usageAuth);
  tpm_marshal_TPM_DIGEST(&ptr, &len, &store.pubDataDigest);
  tpm_marshal_UINT32(&ptr, &len, store.privKey.keyLength - 16);
  memcpy(ptr, &store.privKey.key[16], store.privKey.keyLength - 16);
  tpm_rsa_mask_generation(buf, SHA1_DIGEST_LENGTH,
    &buf[SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH);
  tpm_rsa_mask_generation(&buf[SHA1_DIGEST_LENGTH],
    buf_len - SHA1_DIGEST_LENGTH, buf, SHA1_DIGEST_LENGTH);
  /* XOR encrypt OAEP encoding */
  tpm_get_random_bytes(*random, *randomSize);
  for (len = 0; len < buf_len; len++) buf[len] ^= (*random)[len];
  /* RSA encrypt OAEP encoding */
  if (tpm_rsa_encrypt(&key.key, RSA_ES_OAEP_SHA1, buf, buf_len,
                      *outData, &buf_len)) {
    debug("tpm_rsa_encrypt() failed");
    free_TPM_PUBKEY_DATA(key);
    tpm_free(buf);
    tpm_free(*random);
    tpm_free(*outData);
    tpm_free(key_buf);
    return TPM_ENCRYPT_ERROR;
  }
  *outDataSize = buf_len;
  free_TPM_PUBKEY_DATA(key);
  tpm_free(key_buf);
  tpm_free(buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CMK_ConvertMigration(TPM_KEY_HANDLE parentHandle,
                                    TPM_CMK_AUTH *restrictTicket,
                                    TPM_HMAC *sigTicket, TPM_KEY *migratedKey,
                                    TPM_MSA_COMPOSITE *msaList,
                                    UINT32 randomSize, BYTE *random,
                                    TPM_AUTH *auth1,
                                    UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  BYTE *ptr, *buf, *buf2;
  UINT32 i, len;
  size_t buf_len;
  BYTE tag[2], hmac[SHA1_DIGEST_LENGTH];
  TPM_STORE_ASYMKEY store;
  tpm_sha1_ctx_t sha1_ctx;
  tpm_hmac_ctx_t hmac_ctx;
  TPM_PUBKEY migratedPubKey;
  TPM_PUBKEY parentPubKey;
  TPM_DIGEST migKeyDigest;
  TPM_DIGEST msaListDigest;
  TPM_DIGEST ticketDigest;
  TPM_DIGEST parentDigest;

  info("TPM_CMK_ConvertMigration()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || parent->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
    if (res != TPM_SUCCESS) return res;
  }
  /* verify key properties */
  if (parent->keyUsage != TPM_KEY_STORAGE
      || parent->keyFlags & TPM_KEY_FLAG_MIGRATABLE) return TPM_INVALID_KEYUSAGE;
  if (!(migratedKey->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
      && (!(migratedKey->keyFlags & TPM_KEY_FLAG_AUTHORITY))) return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  buf_len = parent->key.size >> 3;
  buf = tpm_malloc(buf_len);
  if (buf == NULL) return TPM_NOSPACE;
  /* RSA decrypt OAEP encoding */
  if (tpm_rsa_decrypt(&parent->key, RSA_ES_OAEP_SHA1, migratedKey->encData,
                      migratedKey->encDataSize, buf, &buf_len)
      || buf_len != randomSize || buf_len != 198) {
    debug("tpm_rsa_decrypt() failed");
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  /* XOR decrypt OAEP encoding */
  for (len = 0; len < buf_len; len++) buf[len] ^= random[len];
  /* unmask OAEP encoding */
  tpm_rsa_mask_generation(&buf[SHA1_DIGEST_LENGTH],
    buf_len - SHA1_DIGEST_LENGTH , buf, SHA1_DIGEST_LENGTH);
  tpm_rsa_mask_generation(buf, SHA1_DIGEST_LENGTH,
    &buf[SHA1_DIGEST_LENGTH], buf_len - SHA1_DIGEST_LENGTH);
  /* compute digest of migrated public key */
  memcpy(&migratedPubKey.algorithmParms, &migratedKey->algorithmParms,
         sizeof(TPM_KEY_PARMS));
  memcpy(&migratedPubKey.pubKey, &migratedKey->pubKey, sizeof(TPM_STORE_PUBKEY));
  if (tpm_compute_pubkey_digest(&migratedPubKey, &migKeyDigest) != 0) {
    debug("tpm_compute_pubkey_digest() failed");
    tpm_free(buf);
    return TPM_FAIL;
  }
  /* compute digest of parent key */
  parentPubKey.pubKey.keyLength = parent->key.size >> 3;
  parentPubKey.pubKey.key = tpm_malloc(parentPubKey.pubKey.keyLength);
  if (parentPubKey.pubKey.key == NULL) {
    tpm_free(buf);
    return TPM_NOSPACE;
  }
  tpm_rsa_export_modulus(&parent->key, parentPubKey.pubKey.key, NULL);
  if (tpm_setup_key_parms(parent, &parentPubKey.algorithmParms) != 0) {
    debug("tpm_setup_key_parms() failed.");
    tpm_free(parentPubKey.pubKey.key);
    tpm_free(buf);
    return TPM_FAIL;
  }
  if (tpm_compute_pubkey_digest(&parentPubKey, &parentDigest) != 0) {
    debug("tpm_compute_pubkey_digest() failed.");
    free_TPM_PUBKEY(parentPubKey);
    tpm_free(buf);
    return TPM_FAIL;
  }
  free_TPM_PUBKEY(parentPubKey);
  /* compute digest of msaList */
  len = sizeof_TPM_MSA_COMPOSITE((*msaList));
  ptr = buf2 = tpm_malloc(len);
  if (buf2 == NULL || tpm_marshal_TPM_MSA_COMPOSITE(&ptr, &len, msaList)) {
    debug("tpm_marshal_TPM_MSA_COMPOSITE() failed");
    tpm_free(buf2);
    tpm_free(buf);
    return TPM_FAIL;
  }
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf2, sizeof_TPM_MSA_COMPOSITE((*msaList)));
  tpm_sha1_final(&sha1_ctx, msaListDigest.digest);
  tpm_free(buf2);
  /* compute digest of restrictedTicket */
  len = sizeof_TPM_CMK_AUTH((*restrictTicket));
  ptr = buf2 = tpm_malloc(len);
  if (buf2 == NULL || tpm_marshal_TPM_CMK_AUTH(&ptr, &len, restrictTicket)) {
    debug("tpm_marshal_TPM_CMK_AUTH() failed");
    tpm_free(buf2);
    tpm_free(buf);
    return TPM_FAIL;
  }
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf2, sizeof_TPM_CMK_AUTH((*restrictTicket)));
  tpm_sha1_final(&sha1_ctx, ticketDigest.digest);
  tpm_free(buf2);
  /* verify decoded data */
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, msaListDigest.digest, sizeof(TPM_DIGEST));
  tpm_sha1_update(&sha1_ctx, migKeyDigest.digest, sizeof(TPM_DIGEST));
  tpm_sha1_final(&sha1_ctx, hmac);
  if (memcmp(&buf[20], hmac, sizeof(TPM_DIGEST)) != 0) {
    tpm_free(buf);
    return TPM_INVALID_STRUCTURE;
  }
  /* create a TPM_STORE_ASYMKEY structure */
  for (ptr = &buf[40]; *ptr == 0x00; ptr++);
  if (ptr[0] != 0x01 || ptr[1] != TPM_PT_CMK_MIGRATE) {
    debug("OAEP encoding is invalid");
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  ptr += 2;
  len = buf_len - (ptr - buf);
  store.payload = TPM_PT_MIGRATE_EXTERNAL;
  tpm_unmarshal_TPM_SECRET(&ptr, &len, &store.usageAuth);
  tpm_unmarshal_TPM_DIGEST(&ptr, &len, &store.pubDataDigest);
  tpm_unmarshal_UINT32(&ptr, &len, &store.privKey.keyLength);
  store.privKey.keyLength += 16;
  if (store.privKey.keyLength != len + 16) {
    error("invalid key length %d; expected %d",
          store.privKey.keyLength, len + 16);
    tpm_free(buf);
    return TPM_DECRYPT_ERROR;
  }
  memmove(&buf[20], ptr, len);
  store.privKey.key = &buf[4];  
  tag[0] = (TPM_TAG_CMK_MIGAUTH >> 8) & 0xff;
  tag[1] = TPM_TAG_CMK_MIGAUTH & 0xff;
  tpm_hmac_init(&hmac_ctx, tpmData.permanent.data.tpmProof.nonce, sizeof(TPM_NONCE));
  tpm_hmac_update(&hmac_ctx, tag, 2);
  tpm_hmac_update(&hmac_ctx, msaListDigest.digest, sizeof(TPM_DIGEST));
  tpm_hmac_update(&hmac_ctx, migKeyDigest.digest, sizeof(TPM_DIGEST));
  tpm_hmac_final(&hmac_ctx, store.migrationAuth);
  /* verify the migration destination */
  for (i = 0; i < msaList->MSAlist; i++) {
    /* create hmac of TPM_CMK_SIGTICKET */
    tag[0] = (TPM_TAG_CMK_SIGTICKET >> 8) & 0xff;
    tag[1] = TPM_TAG_CMK_SIGTICKET & 0xff;
    tpm_hmac_init(&hmac_ctx, tpmData.permanent.data.tpmProof.nonce,
                  sizeof(TPM_NONCE));
    tpm_hmac_update(&hmac_ctx, tag, 2);
    tpm_hmac_update(&hmac_ctx, msaList->migAuthDigest[i].digest,
                    sizeof(TPM_DIGEST));
    tpm_hmac_update(&hmac_ctx, ticketDigest.digest, sizeof(TPM_DIGEST));
    tpm_hmac_final(&hmac_ctx, hmac);
    if (memcmp(hmac, sigTicket->digest, sizeof(TPM_DIGEST)) == 0) break;
  }
  if (i >= msaList->MSAlist) {
    tpm_free(buf);
    return TPM_MA_AUTHORITY;
  }
  if (memcmp(&restrictTicket->destinationKeyDigest, &parentDigest,
             sizeof(TPM_DIGEST)) != 0) {
    tpm_free(buf);
    return TPM_MA_DESTINATION;
  }
  if (memcmp(&restrictTicket->sourceKeyDigest, &migKeyDigest,
             sizeof(TPM_DIGEST)) != 0) {
    tpm_free(buf);
    return TPM_MA_SOURCE;
  }
  /* encrypt private key */
  *outDataSize = parent->key.size >> 3;
  *outData = tpm_malloc(*outDataSize);
  if (*outData == NULL) {
    tpm_free(buf);
    return TPM_NOSPACE;
  }
  if (tpm_encrypt_private_key(parent, &store, *outData, outDataSize)) {
    debug("tpm_encrypt_private_key() failed");
    tpm_free(*outData);
    tpm_free(buf);
    return TPM_ENCRYPT_ERROR;
  }
  tpm_free(buf);
  return TPM_SUCCESS;
}

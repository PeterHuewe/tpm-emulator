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
 * $Id: tpm_storage.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "tpm_handles.h"
#include "crypto/sha1.h"
#include "crypto/rsa.h"
#include "tpm_marshalling.h"

/*
 * Storage functions ([TPM_Part3], Section 10)
 */

TPM_KEY_HANDLE tpm_get_free_key(void)
{
  int i;
  for (i = 0; i < TPM_MAX_KEYS; i++) {
    if (!tpmData.permanent.data.keys[i].payload) {
      tpmData.permanent.data.keys[i].payload = TPM_PT_ASYM;
      return INDEX_TO_KEY_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}

int tpm_encrypt_public(TPM_PUBKEY_DATA *key, BYTE *in, UINT32 in_size,
                       BYTE *enc, UINT32 *enc_size)
{
  size_t size = *enc_size;
  int scheme;
  switch (key->encScheme) {
    case TPM_ES_RSAESOAEP_SHA1_MGF1: scheme = RSA_ES_OAEP_SHA1; break;
    case TPM_ES_RSAESPKCSv15: scheme = RSA_ES_PKCSV15; break;
    default:
      debug("unsupported encryption scheme: %d", key->encScheme);
      return -1;
  }
  if (tpm_rsa_encrypt(&key->key, scheme, in, in_size, enc, &size) != 0) {
    debug("tpm_rsa_encrypt() failed");
    return -1;
  }
  *enc_size = size;
  return 0;
}

int tpm_encrypt_private(TPM_KEY_DATA *key, BYTE *in, UINT32 in_size,
                        BYTE *enc, UINT32 *enc_size)
{
  int res;
  TPM_PUBKEY_DATA pubKey;
  pubKey.encScheme = key->encScheme;
  TPM_RSA_EXTRACT_PUBLIC_KEY(key->key, pubKey.key);
  res = tpm_encrypt_public(&pubKey, in, in_size, enc, enc_size);
  free_TPM_PUBKEY_DATA(pubKey);
  return res;
}

int tpm_decrypt(TPM_KEY_DATA *key, BYTE *enc, UINT32 enc_size,
                BYTE *out, UINT32 *out_size)
{
  size_t size = *out_size;
  int scheme;
  switch (key->encScheme) {
    case TPM_ES_RSAESOAEP_SHA1_MGF1: scheme = RSA_ES_OAEP_SHA1; break;
    case TPM_ES_RSAESPKCSv15: scheme = RSA_ES_PKCSV15; break;
    default:
      debug("unsupported encryption scheme: %d", key->encScheme);
      return -1;
  }
  if (tpm_rsa_decrypt(&key->key, scheme, enc, enc_size, out, &size) != 0) {
    debug("tpm_rsa_decrypt() failed");
    return -1;
  }
  *out_size = size;
  return 0;
}

int tpm_encrypt_sealed_data(TPM_KEY_DATA *key, TPM_SEALED_DATA *seal,
                            BYTE *enc, UINT32 *enc_size)
{
  UINT32 len = sizeof_TPM_SEALED_DATA((*seal));
  BYTE *buf, *ptr;
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_SEALED_DATA(&ptr, &len, seal)
      || tpm_encrypt_private(key, buf, sizeof_TPM_SEALED_DATA((*seal)),
                             enc, enc_size)) {
    tpm_free(buf);
    return -1;
  }
  tpm_free(buf);
  return 0;
}

int tpm_decrypt_sealed_data(TPM_KEY_DATA *key, BYTE *enc, UINT32 enc_size,
                            TPM_SEALED_DATA *seal, BYTE **buf)
{
  BYTE *ptr;
  *buf = ptr = tpm_malloc(enc_size);
  if (*buf == NULL
      || tpm_decrypt(key, enc, enc_size, *buf, &enc_size)
      || tpm_unmarshal_TPM_SEALED_DATA(&ptr, &enc_size, seal)) {
    tpm_free(*buf);
    return -1;
  }
  return 0;
}

int tpm_encrypt_private_key(TPM_KEY_DATA *key, TPM_STORE_ASYMKEY *store,
                            BYTE *enc, UINT32 *enc_size)
{
  UINT32 len = sizeof_TPM_STORE_ASYMKEY((*store));
  BYTE *buf, *ptr;
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_STORE_ASYMKEY(&ptr, &len, store)
      || tpm_encrypt_private(key, buf, sizeof_TPM_STORE_ASYMKEY((*store)),
                             enc, enc_size)) {
    tpm_free(buf);
    return -1;
  }
  tpm_free(buf);
  return 0;
}

int tpm_decrypt_private_key(TPM_KEY_DATA *key, BYTE *enc, UINT32 enc_size,
                            TPM_STORE_ASYMKEY *store,
                            BYTE **buf, UINT32 *buf_size)
{
  BYTE *ptr;
  *buf = ptr = tpm_malloc(enc_size);
  if (*buf == NULL || tpm_decrypt(key, enc, enc_size, *buf, &enc_size)) {
    tpm_free(*buf);
    return -1;
  }
  if (buf_size != NULL) *buf_size = enc_size;
  if (tpm_unmarshal_TPM_STORE_ASYMKEY(&ptr, &enc_size, store) != 0) {
    tpm_free(*buf);
    return -1;
  }
  if (buf_size != NULL) *buf_size -= enc_size;
  return 0;
}

static void tpm_xor_encrypt(TPM_SESSION_DATA *session, TPM_NONCE *nonceOdd,
                            BYTE *data, UINT32 data_size)
{
  BYTE seed[2 * sizeof(TPM_NONCE) + 3 + sizeof(TPM_SECRET)];
  BYTE *ptr = seed;

  /* set up seed */
  memcpy(ptr, session->lastNonceEven.nonce, sizeof(TPM_NONCE));
  ptr += sizeof(TPM_NONCE);
  memcpy(ptr, nonceOdd->nonce, sizeof(TPM_NONCE));
  ptr += sizeof(TPM_NONCE);
  memcpy(ptr, (const BYTE*)"XOR", 3);
  ptr += 3;
  memcpy(ptr, session->sharedSecret, sizeof(TPM_SECRET));
  /* decrypt data */
  tpm_rsa_mask_generation(seed, sizeof(seed), data, data_size);
}

int tpm_compute_key_digest(TPM_KEY *key, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_KEY((*key));
  BYTE *buf, *ptr;
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_KEY(&ptr, &len, key)) {
    tpm_free(buf);
    return -1;
  }
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_KEY((*key)) - key->encDataSize - 4);
  tpm_sha1_final(&sha1, digest->digest);
  tpm_free(buf);
  return 0;
}

int tpm_compute_key_data_digest(TPM_KEY_DATA *key, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 key_len = key->key.size >> 3;
  BYTE *buf = tpm_malloc(4 + key_len);
  if (buf == NULL) {
    debug("tpm_malloc() failed.");
    return -1;
  }
  /* extract modulus  */
  buf[0] = (key_len >> 24) & 0xff;
  buf[1] = (key_len >> 16) & 0xff;
  buf[2] = (key_len >>  8) & 0xff;
  buf[3] = (key_len >>  0) & 0xff;
  tpm_rsa_export_modulus(&key->key, &buf[4], NULL);
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, 4 + key_len);
  tpm_sha1_final(&sha1, digest->digest);
  tpm_free(buf);
  return 0;
}

static int tpm_verify_key_digest(TPM_KEY *key, TPM_DIGEST *digest)
{
  TPM_DIGEST key_digest;
  if (tpm_compute_key_digest(key, &key_digest)) return -1;
  return memcmp(key_digest.digest, digest->digest, sizeof(key_digest.digest));
}

int tpm_compute_pubkey_checksum(TPM_NONCE *antiReplay, TPM_PUBKEY *pubKey,
                                TPM_DIGEST *checksum)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_PUBKEY((*pubKey));
  BYTE buf[len], *ptr = buf;

  if (tpm_marshal_TPM_PUBKEY(&ptr, &len, pubKey)) return -1;
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_PUBKEY((*pubKey)));
  tpm_sha1_update(&sha1, antiReplay->nonce, sizeof(antiReplay->nonce));
  tpm_sha1_final(&sha1, checksum->digest);
  return 0;
}

int tpm_compute_pubkey_digest(TPM_PUBKEY *key, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_PUBKEY((*key));
  BYTE *buf, *ptr;
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_PUBKEY(&ptr, &len, key)) {
    tpm_free(buf);
    return -1;
  }
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_PUBKEY((*key)));
  tpm_sha1_final(&sha1, digest->digest);
  tpm_free(buf);
  return 0;
}

int tpm_setup_key_parms(TPM_KEY_DATA *key, TPM_KEY_PARMS *parms)
{
  size_t exp_len;
  parms->algorithmID = TPM_ALG_RSA;
  parms->encScheme = key->encScheme;
  parms->sigScheme = key->sigScheme;
  parms->parms.rsa.keyLength = key->key.size;
  parms->parms.rsa.numPrimes = 2;
  if (tpm_bn_cmp_ui(key->key.e, 65537) == 0) {
    parms->parms.rsa.exponentSize = 0;
    parms->parms.rsa.exponent = NULL;
  } else {
    parms->parms.rsa.exponentSize = tpm_rsa_exponent_length(&key->key);
    parms->parms.rsa.exponent = tpm_malloc(parms->parms.rsa.exponentSize);
    if (parms->parms.rsa.exponent == NULL) return -1;
    tpm_rsa_export_exponent(&key->key, parms->parms.rsa.exponent, &exp_len);
    parms->parms.rsa.exponentSize = exp_len;
  }
  parms->parmSize = 12 + parms->parms.rsa.exponentSize;
  return 0;
}

int tpm_setup_pubkey_data(TPM_PUBKEY *in, TPM_PUBKEY_DATA *out)
{
  out->valid = TRUE;
  out->encScheme = in->algorithmParms.encScheme;
  out->sigScheme = in->algorithmParms.sigScheme;
  out->key.size = in->algorithmParms.parms.rsa.keyLength;
  if (tpm_rsa_import_public_key(&out->key, RSA_MSB_FIRST,
      in->pubKey.key, in->pubKey.keyLength,
      in->algorithmParms.parms.rsa.exponent,
      in->algorithmParms.parms.rsa.exponentSize) != 0) return -1;
  return 0;
}

int tpm_extract_pubkey(TPM_KEY_DATA *key, TPM_PUBKEY *pubKey)
{
  pubKey->pubKey.keyLength = key->key.size >> 3;
  pubKey->pubKey.key = tpm_malloc(pubKey->pubKey.keyLength);
  if (pubKey->pubKey.key == NULL) {
    debug("tpm_malloc() failed.");
    return -1;
  }
  tpm_rsa_export_modulus(&key->key, pubKey->pubKey.key, NULL);
  if (tpm_setup_key_parms(key, &pubKey->algorithmParms) != 0) {
    debug("tpm_setup_key_parms() failed.");
    tpm_free(pubKey->pubKey.key);
    return -1;
  }
  return 0;
}

int tpm_extract_store_pubkey(TPM_KEY_DATA *key, TPM_STORE_PUBKEY *pubKey)
{
  pubKey->keyLength = key->key.size >> 3;
  pubKey->key = tpm_malloc(pubKey->keyLength);
  if (pubKey->key == NULL) {
    debug("tpm_malloc() failed.");
    return -1;
  }
  tpm_rsa_export_modulus(&key->key, pubKey->key, NULL);
  return 0;
}

static int compute_store_digest(TPM_STORED_DATA *store, TPM_DIGEST *digest)
{
  tpm_sha1_ctx_t sha1;
  UINT32 len = sizeof_TPM_STORED_DATA((*store));
  BYTE *buf, *ptr;
  buf = ptr = tpm_malloc(len);
  if (buf == NULL
      || tpm_marshal_TPM_STORED_DATA(&ptr, &len, store)) {
    tpm_free(buf);
    return -1;
  }
  /* compute SHA1 hash */
  tpm_sha1_init(&sha1);
  tpm_sha1_update(&sha1, buf, sizeof_TPM_STORED_DATA((*store)));
  tpm_sha1_final(&sha1, digest->digest);
  tpm_free(buf);
  return 0;
}

static int verify_store_digest(TPM_STORED_DATA *store, TPM_DIGEST *digest)
{
  TPM_DIGEST store_digest;
  if (compute_store_digest(store, &store_digest)) return -1;
  return memcmp(store_digest.digest, digest->digest,
    sizeof(store_digest.digest));
}

TPM_RESULT TPM_Seal(TPM_KEY_HANDLE keyHandle, TPM_ENCAUTH *encAuth,
                    UINT32 pcrInfoSize, TPM_PCR_INFO *pcrInfo,
                    UINT32 inDataSize, BYTE *inData,
                    TPM_AUTH *auth1, TPM_STORED_DATA *sealedData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  TPM_SEALED_DATA seal;
  info("TPM_Seal()");
  if (inDataSize == 0) return TPM_BAD_PARAMETER;
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_STORAGE
      || key->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
    return TPM_INVALID_KEYUSAGE;
  /* setup store */
  if (pcrInfo->tag == TPM_TAG_PCR_INFO_LONG) {
    sealedData->tag = TPM_TAG_STORED_DATA12;
    sealedData->et = 0x0000;
  } else {
    sealedData->tag = 0x0101;
    sealedData->et = 0x0000;
  }   
  sealedData->encDataSize = 0;
  sealedData->encData = NULL;
  sealedData->sealInfoSize = pcrInfoSize;
  if (pcrInfoSize > 0) {
    sealedData->sealInfoSize = pcrInfoSize;
    memcpy(&sealedData->sealInfo, pcrInfo, sizeof(TPM_PCR_INFO));
    res = tpm_compute_pcr_digest(&pcrInfo->creationPCRSelection, 
      &sealedData->sealInfo.digestAtCreation, NULL);
    if (res != TPM_SUCCESS) return res;
    sealedData->sealInfo.localityAtCreation = 
      tpmData.stany.flags.localityModifier;
  }
  /* setup seal */
  seal.payload = TPM_PT_SEAL;
  memcpy(&seal.tpmProof, &tpmData.permanent.data.tpmProof, 
    sizeof(TPM_NONCE));
  if (compute_store_digest(sealedData, &seal.storedDigest)) {
    debug("TPM_Seal(): compute_store_digest() failed.");
    return TPM_FAIL;
  }
  if ((session->entityType & 0xff00) !=  TPM_ET_XOR)
    return TPM_INAPPROPRIATE_ENC;
  tpm_decrypt_auth_secret(*encAuth, session->sharedSecret,
    &session->lastNonceEven, seal.authData);
  seal.dataSize = inDataSize; 
  seal.data = inData;
  /* encrypt sealed data */
  sealedData->encDataSize = key->key.size >> 3;
  sealedData->encData = tpm_malloc(sealedData->encDataSize);
  if (sealedData->encData == NULL) return TPM_NOSPACE;
  if (tpm_encrypt_sealed_data(key, &seal, sealedData->encData, 
                              &sealedData->encDataSize)) {
    tpm_free(sealedData->encData);
    return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Sealx(TPM_KEY_HANDLE keyHandle, TPM_ENCAUTH *encAuth,
                    UINT32 pcrInfoSize, TPM_PCR_INFO *pcrInfo,
                    UINT32 inDataSize, BYTE *inData,
                    TPM_AUTH *auth1, TPM_STORED_DATA *sealedData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  TPM_SEALED_DATA seal;

  info("TPM_Sealx()");
  if (inDataSize == 0) return TPM_BAD_PARAMETER;
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP) return TPM_AUTHFAIL;
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_STORAGE
      || key->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
    return TPM_INVALID_KEYUSAGE;
  /* setup store */
  if (pcrInfo->tag != TPM_TAG_PCR_INFO_LONG)
    return TPM_BAD_PARAMETER;
  if ((session->entityType & 0xff00) !=  TPM_ET_XOR)
    return TPM_INAPPROPRIATE_ENC;
  sealedData->tag = TPM_TAG_STORED_DATA12;
  sealedData->et = TPM_ET_XOR | TPM_ET_KEY;
  sealedData->encDataSize = 0;
  sealedData->encData = NULL;
  sealedData->sealInfoSize = pcrInfoSize;
  if (pcrInfoSize > 0) {
    sealedData->sealInfoSize = pcrInfoSize;
    memcpy(&sealedData->sealInfo, pcrInfo, sizeof(TPM_PCR_INFO));
    res = tpm_compute_pcr_digest(&pcrInfo->creationPCRSelection,
      &sealedData->sealInfo.digestAtCreation, NULL);
    if (res != TPM_SUCCESS) return res;
    sealedData->sealInfo.localityAtCreation =
      tpmData.stany.flags.localityModifier;
  }  
  /* setup seal */
  seal.payload = TPM_PT_SEAL;
  memcpy(&seal.tpmProof, &tpmData.permanent.data.tpmProof,
    sizeof(TPM_NONCE));
  if (compute_store_digest(sealedData, &seal.storedDigest)) {
    debug("TPM_Sealx(): compute_store_digest() failed.");
    return TPM_FAIL;
  }
  tpm_decrypt_auth_secret(*encAuth, session->sharedSecret,
    &session->lastNonceEven, seal.authData);
  tpm_xor_encrypt(session, &auth1->nonceOdd, inData, inDataSize);
  seal.dataSize = inDataSize;
  seal.data = inData;
  /* encrypt sealed data */
  sealedData->encDataSize = key->key.size >> 3;
  sealedData->encData = tpm_malloc(sealedData->encDataSize);
  if (sealedData->encData == NULL) return TPM_NOSPACE;
  if (tpm_encrypt_sealed_data(key, &seal, sealedData->encData,
                              &sealedData->encDataSize)) {
    tpm_free(sealedData->encData);
    return TPM_ENCRYPT_ERROR;
  }
  return TPM_SUCCESS;

}

TPM_RESULT TPM_Unseal(TPM_KEY_HANDLE parentHandle, TPM_STORED_DATA *inData,
                      TPM_AUTH *auth1, TPM_AUTH *auth2,  UINT32 *sealedDataSize, 
                      BYTE **secret)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_SESSION_DATA *session;
  TPM_SEALED_DATA seal;
  BYTE *seal_buf;
  TPM_DIGEST digest;
  info("TPM_Unseal()");
  /* get key */
  key = tpm_get_key(parentHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization, if only auth1 is present we use it for the data */
  if (auth2->authHandle != TPM_INVALID_HANDLE 
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, parentHandle);
    if (res != TPM_SUCCESS) return res;
    auth1->continueAuthSession = FALSE;
    session = tpm_get_auth(auth1->authHandle);
  } else {
    session = NULL;
  }
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_STORAGE
      || key->keyFlags & TPM_KEY_FLAG_MIGRATABLE) return TPM_INVALID_KEYUSAGE;
  /* verify PCR info */
  if (inData->sealInfoSize > 0) {
    res = tpm_compute_pcr_digest(&inData->sealInfo.releasePCRSelection,
      &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &inData->sealInfo.digestAtRelease, sizeof(TPM_DIGEST)))
      return TPM_WRONGPCRVAL;
    if (inData->sealInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(inData->sealInfo.localityAtRelease 
             & (1 << tpmData.stany.flags.localityModifier)))
       return TPM_BAD_LOCALITY;
  }
  /* decrypt sealed data */
  if (tpm_decrypt_sealed_data(key, inData->encData, inData->encDataSize,
                              &seal, &seal_buf)) return TPM_DECRYPT_ERROR;
  inData->encDataSize = 0;
  if (seal.payload != TPM_PT_SEAL
      || memcmp(&tpmData.permanent.data.tpmProof, &seal.tpmProof, 
             sizeof(TPM_NONCE))
      || verify_store_digest(inData, &seal.storedDigest)) {
    tpm_free(seal_buf);
    return TPM_NOTSEALED_BLOB;
  }
  /* verify data auth */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
    res = tpm_verify_auth(auth2, seal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return (res == TPM_AUTHFAIL) ? TPM_AUTH2FAIL : res;
  } else {
    res = tpm_verify_auth(auth1, seal.authData, TPM_INVALID_HANDLE);
    if (res != TPM_SUCCESS) return res;
  }
  /* encrypt data if required */
  debug("entity type = %04x", inData->et & 0xff00);
  if (inData->et != 0) {
     if (auth2->authHandle == TPM_INVALID_HANDLE) return TPM_AUTHFAIL;
     if (session->type != TPM_ST_OSAP) return TPM_BAD_MODE;
     if ((inData->et & 0xff00) == TPM_ET_XOR) {
        tpm_xor_encrypt(session, &auth1->nonceOdd, seal.data, seal.dataSize);
     } else return TPM_INAPPROPRIATE_ENC;
  }
  /* return secret */
  *sealedDataSize = seal.dataSize;
  *secret = tpm_malloc(*sealedDataSize);
  if (*secret == NULL) {
    tpm_free(seal_buf);
    return TPM_NOSPACE;
  }
  memcpy(*secret, seal.data, seal.dataSize);
  tpm_free(seal_buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_UnBind(TPM_KEY_HANDLE keyHandle, UINT32 inDataSize,
                      BYTE *inData, TPM_AUTH *auth1, 
                      UINT32 *outDataSize, BYTE **outData)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  size_t out_len;
  int scheme;
  
  info("TPM_UnBind()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify auth */
  if (auth1->authHandle != TPM_INVALID_HANDLE 
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  /* verify key properties */
  if (key->keyUsage != TPM_KEY_BIND 
      && key->keyUsage != TPM_KEY_LEGACY) return TPM_INVALID_KEYUSAGE;
  /* the size of the input data muss be greater than zero */
  if (inDataSize == 0) return TPM_BAD_PARAMETER;
  /* decrypt data */
  *outDataSize = inDataSize;
  *outData = tpm_malloc(*outDataSize);
  if (*outData == NULL) return TPM_NOSPACE;
  switch (key->encScheme) {
    case TPM_ES_RSAESOAEP_SHA1_MGF1: scheme = RSA_ES_OAEP_SHA1; break;
    case TPM_ES_RSAESPKCSv15: scheme = RSA_ES_PKCSV15; break;
    default: tpm_free(*outData); return TPM_DECRYPT_ERROR;
  }
  if (tpm_rsa_decrypt(&key->key, scheme, inData, inDataSize, *outData, &out_len)) {
    tpm_free(*outData);
    return TPM_DECRYPT_ERROR;
  }
  *outDataSize = out_len;
  /* verify data if it is of type TPM_BOUND_DATA */
  if (key->encScheme == TPM_ES_RSAESOAEP_SHA1_MGF1 
      || key->keyUsage != TPM_KEY_LEGACY) {
    if (*outDataSize < 5 || memcmp(*outData, "\x01\x01\00\x00\x02", 5) != 0) {
      tpm_free(*outData);
      return TPM_DECRYPT_ERROR;
    }
    *outDataSize -= 5;
    memmove(*outData, &(*outData)[5], *outDataSize);
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_CreateWrapKey(TPM_KEY_HANDLE parentHandle, 
                             TPM_ENCAUTH *dataUsageAuth,
                             TPM_ENCAUTH *dataMigrationAuth,
                             TPM_KEY *keyInfo, TPM_AUTH *auth1,  
                             TPM_KEY *wrappedKey)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent;
  TPM_SESSION_DATA *session;
  TPM_STORE_ASYMKEY store;
  tpm_rsa_private_key_t rsa;
  UINT32 key_length;

  info("TPM_CreateWrapKey()");
  /* get parent key */
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
  if (res != TPM_SUCCESS) return res;
  auth1->continueAuthSession = FALSE;
  session = tpm_get_auth(auth1->authHandle);
  if (session->type != TPM_ST_OSAP && session->type != TPM_ST_DSAP)
    return TPM_AUTHFAIL;
  /* verify key parameters */
  if (parent->keyUsage != TPM_KEY_STORAGE
      || parent->encScheme == TPM_ES_NONE
      || ((parent->keyFlags & TPM_KEY_FLAG_MIGRATABLE)
          && !(keyInfo->keyFlags & TPM_KEY_FLAG_MIGRATABLE))
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
  /* setup the wrapped key */
  memcpy(wrappedKey, keyInfo, sizeof(TPM_KEY));
  /* setup key store */
  store.payload = TPM_PT_ASYM;
  tpm_decrypt_auth_secret(*dataUsageAuth, session->sharedSecret, 
    &session->lastNonceEven, store.usageAuth);
  if (keyInfo->keyFlags & TPM_KEY_FLAG_MIGRATABLE) {
    tpm_decrypt_auth_secret(*dataMigrationAuth, session->sharedSecret, 
      &auth1->nonceOdd, store.migrationAuth);
    /* clear PCR digest */
    if (keyInfo->PCRInfoSize > 0) {
      memset(keyInfo->PCRInfo.digestAtCreation.digest, 0,
          sizeof(keyInfo->PCRInfo.digestAtCreation.digest));
      keyInfo->PCRInfo.localityAtCreation = 0;
    }
  } else {
    memcpy(store.migrationAuth, tpmData.permanent.data.tpmProof.nonce, 
      sizeof(TPM_SECRET));
    /* compute PCR digest */
    if (keyInfo->PCRInfoSize > 0) {
      tpm_compute_pcr_digest(&keyInfo->PCRInfo.creationPCRSelection, 
        &keyInfo->PCRInfo.digestAtCreation, NULL);
      keyInfo->PCRInfo.localityAtCreation = 
        tpmData.stany.flags.localityModifier;
    }
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

TPM_RESULT TPM_LoadKey(TPM_KEY_HANDLE parentHandle, TPM_KEY *inKey,
                       TPM_AUTH *auth1, TPM_KEY_HANDLE *inkeyHandle)
{
  TPM_RESULT res;
  TPM_KEY_DATA *parent, *key;
  BYTE *key_buf;
  TPM_STORE_ASYMKEY store;
  info("TPM_LoadKey()");
  /* get parent key */
  debug("parentHandle = %08x", parentHandle);
  parent = tpm_get_key(parentHandle);
  if (parent == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE) {
    debug("authDataUsage = %02x", parent->authDataUsage);
    res = tpm_verify_auth(auth1, parent->usageAuth, parentHandle);
    if (res != TPM_SUCCESS) return res;
  } else if (parent->authDataUsage != TPM_AUTH_NEVER) {
    debug("TPM_LoadKey(): parent key requires authorization.");
    return TPM_AUTHFAIL;
  }
  if (parent->keyUsage != TPM_KEY_STORAGE) return TPM_INVALID_KEYUSAGE;
  /* verify key properties */
  if (inKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || inKey->algorithmParms.parmSize == 0
      || inKey->algorithmParms.parms.rsa.keyLength > 2048
      || inKey->algorithmParms.parms.rsa.numPrimes != 2)
    return TPM_BAD_KEY_PROPERTY;
  if (inKey->keyUsage == TPM_KEY_AUTHCHANGE) return TPM_INVALID_KEYUSAGE;
  if (inKey->keyUsage == TPM_KEY_STORAGE
       && (inKey->algorithmParms.algorithmID != TPM_ALG_RSA
           || inKey->algorithmParms.parms.rsa.keyLength != 2048
           || inKey->algorithmParms.sigScheme != TPM_SS_NONE)) 
    return TPM_INVALID_KEYUSAGE;
  if (inKey->keyUsage == TPM_KEY_IDENTITY
      && (inKey->keyFlags & TPM_KEY_FLAG_MIGRATABLE
          || inKey->algorithmParms.algorithmID != TPM_ALG_RSA
          || inKey->algorithmParms.parms.rsa.keyLength != 2048
          || inKey->algorithmParms.encScheme != TPM_ES_NONE)) 
    return TPM_INVALID_KEYUSAGE;
  /* decrypt private key */
  if (tpm_decrypt_private_key(parent, inKey->encData, inKey->encDataSize,
                              &store, &key_buf, NULL)) return TPM_DECRYPT_ERROR;
  /* get a free key-slot, if any free slot is left */
  *inkeyHandle = tpm_get_free_key();
  key = tpm_get_key(*inkeyHandle);
  if (key == NULL) {
    tpm_free(key_buf);
    return TPM_NOSPACE;
  }
  /* import key */
  if (tpm_verify_key_digest(inKey, &store.pubDataDigest) != 0) {
    debug("tpm_verify_key_digest() failed.");
    memset(key, 0, sizeof(TPM_KEY_DATA));
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  if (inKey->pubKey.keyLength != (store.privKey.keyLength * 2)) {
    debug("size of the public modulus does not match the secret prime");
    memset(key, 0, sizeof(TPM_KEY_DATA));
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  if (tpm_rsa_import_key(&key->key, RSA_MSB_FIRST,
                         inKey->pubKey.key, inKey->pubKey.keyLength,
                         inKey->algorithmParms.parms.rsa.exponent,
                         inKey->algorithmParms.parms.rsa.exponentSize,
                         store.privKey.key, NULL)) {
    debug("tpm_rsa_import_key() failed.");
    memset(key, 0, sizeof(TPM_KEY_DATA));
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  /* verify tpmProof */
  if (!(inKey->keyFlags & TPM_KEY_FLAG_MIGRATABLE)) {
    if (memcmp(tpmData.permanent.data.tpmProof.nonce,
               store.migrationAuth, sizeof(TPM_NONCE))) {
      debug("TPM_LoadKey(): tpmProof verification failed.");
      memset(key, 0, sizeof(TPM_KEY_DATA));
      tpm_free(key_buf);
      return TPM_FAIL;
    }
  }
  if (store.payload) key->payload = store.payload;
  key->keyUsage = inKey->keyUsage;
  key->keyFlags = inKey->keyFlags;
  key->authDataUsage = inKey->authDataUsage;
  key->encScheme = inKey->algorithmParms.encScheme;
  key->sigScheme = inKey->algorithmParms.sigScheme;
  memcpy(key->usageAuth, store.usageAuth, sizeof(TPM_SECRET));
  memcpy(key->migrationAuth, store.migrationAuth, sizeof(TPM_SECRET));
  /* setup PCR info */
  if (inKey->PCRInfoSize > 0) {
    memcpy(&key->pcrInfo, &inKey->PCRInfo, sizeof(TPM_PCR_INFO));
    key->keyFlags |= TPM_KEY_FLAG_HAS_PCR;
  } else {
    key->keyFlags |= TPM_KEY_FLAG_PCR_IGNORE;
    key->keyFlags &= ~TPM_KEY_FLAG_HAS_PCR;
  }
  key->parentPCRStatus = parent->parentPCRStatus;
  tpm_free(key_buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_LoadKey2(TPM_KEY_HANDLE parentHandle, TPM_KEY *inKey,
                        TPM_AUTH *auth1, TPM_KEY_HANDLE *inkeyHandle)
{
  info("TPM_LoadKey2()");
  return TPM_LoadKey(parentHandle, inKey, auth1, inkeyHandle);
}

TPM_RESULT internal_TPM_LoadKey(TPM_KEY *inKey, TPM_KEY_HANDLE *inkeyHandle)
{
  TPM_KEY_DATA *parent, *key;
  BYTE *key_buf;
  TPM_STORE_ASYMKEY store;
  info("internal_TPM_LoadKey()");
  /* get SRK */
  parent = tpm_get_key(TPM_KH_SRK);
  if (parent == NULL) return TPM_FAIL;
  /* verify key properties */
  if (inKey->algorithmParms.algorithmID != TPM_ALG_RSA
      || inKey->algorithmParms.parmSize == 0
      || inKey->algorithmParms.parms.rsa.keyLength > 2048
      || inKey->algorithmParms.parms.rsa.numPrimes != 2)
    return TPM_BAD_KEY_PROPERTY;
  /* decrypt private key */
  if (tpm_decrypt_private_key(parent, inKey->encData, inKey->encDataSize,
                              &store, &key_buf, NULL)) return TPM_DECRYPT_ERROR;
  /* get a free key-slot, if any free slot is left */
  *inkeyHandle = tpm_get_free_key();
  key = tpm_get_key(*inkeyHandle);
  if (key == NULL) {
    tpm_free(key_buf);
    return TPM_NOSPACE;
  }
  /* import key */
  if (tpm_verify_key_digest(inKey, &store.pubDataDigest)
      || inKey->pubKey.keyLength != (store.privKey.keyLength * 2)
      || tpm_rsa_import_key(&key->key, RSA_MSB_FIRST,
                        inKey->pubKey.key, inKey->pubKey.keyLength,
                        inKey->algorithmParms.parms.rsa.exponent,
                        inKey->algorithmParms.parms.rsa.exponentSize,
                        store.privKey.key, NULL)) {
    debug("internal_LoadKey(): tpm_verify_key_digest() or tpm_rsa_import_key() failed.");
    memset(key, 0, sizeof(TPM_KEY_DATA));
    tpm_free(key_buf);
    return TPM_FAIL;
  }
  key->keyUsage = inKey->keyUsage;
  key->keyFlags = inKey->keyFlags;
  key->authDataUsage = inKey->authDataUsage;
  key->encScheme = inKey->algorithmParms.encScheme;
  key->sigScheme = inKey->algorithmParms.sigScheme;
  memcpy(key->usageAuth, store.usageAuth, sizeof(TPM_SECRET));
  /* setup PCR info */
  if (inKey->PCRInfoSize > 0) {
    memcpy(&key->pcrInfo, &inKey->PCRInfo, sizeof(TPM_PCR_INFO));
    key->keyFlags |= TPM_KEY_FLAG_HAS_PCR;
  } else {
    key->keyFlags |= TPM_KEY_FLAG_PCR_IGNORE;
    key->keyFlags &= ~TPM_KEY_FLAG_HAS_PCR;
  }
  key->parentPCRStatus = parent->parentPCRStatus;
  tpm_free(key_buf);
  return TPM_SUCCESS;
}

TPM_RESULT TPM_GetPubKey(TPM_KEY_HANDLE keyHandle, TPM_AUTH *auth1,
                         TPM_PUBKEY *pubKey)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_DIGEST digest;
  info("TPM_GetPubKey()");
  /* get key */
  if (keyHandle == TPM_KH_SRK
      && !tpmData.permanent.flags.readSRKPub) return TPM_INVALID_KEYHANDLE;
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || (key->authDataUsage != TPM_AUTH_NEVER
          && key->authDataUsage != TPM_AUTH_PRIV_USE_ONLY)) {
              res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
              if (res != TPM_SUCCESS) return res;
  }
  if (!(key->keyFlags & TPM_KEY_FLAG_PCR_IGNORE)) {
    res = tpm_compute_pcr_digest(&key->pcrInfo.releasePCRSelection,
      &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &key->pcrInfo.digestAtRelease, sizeof(TPM_DIGEST)))
      return TPM_WRONGPCRVAL;
    if (key->pcrInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(key->pcrInfo.localityAtRelease
             & (1 << tpmData.stany.flags.localityModifier)))
       return TPM_BAD_LOCALITY;
  }
  /* extract pubKey */
  if (tpm_extract_pubkey(key, pubKey) != 0) return TPM_FAIL;
  return TPM_SUCCESS;
}

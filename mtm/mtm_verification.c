/* Software-based Mobile Trusted Module (MTM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2007 Jan-Erik Ekberg <jan-erik.ekberg@nokia.com>,
 *                    Nokia Corporation and/or its subsidiary(-ies)
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
#include "mtm_commands.h"
#include "tpm/tpm_commands.h"
#include "mtm_data.h"
#include "tpm/tpm_data.h"
#include "mtm_handles.h"
#include "mtm_marshalling.h"
#include "crypto/hmac.h"
#include "crypto/rsa.h"
#include "crypto/sha1.h"

static int copy_TPM_RIM_CERTIFICATE(TPM_RIM_CERTIFICATE* src, TPM_RIM_CERTIFICATE* dst)
{
  memcpy(dst, src, sizeof(TPM_RIM_CERTIFICATE));
  if (dst->extensionDigestSize > 0) {
    dst->extensionDigestData = tpm_malloc(dst->extensionDigestSize);
    if (dst->extensionDigestData == NULL) return -1;
    memcpy(dst->extensionDigestData, src->extensionDigestData,
           dst->extensionDigestSize);
  } else {
    dst->extensionDigestData = NULL;
  }
  if (dst->integrityCheckSize > 0) {
    dst->integrityCheckData = tpm_malloc(dst->integrityCheckSize);
    if (dst->integrityCheckData == NULL) {
      tpm_free(dst->extensionDigestData);
      return -1;
    }
    memcpy(dst->integrityCheckData, src->integrityCheckData,
           dst->integrityCheckSize);
  } else {
    dst->integrityCheckData = NULL;
  }
  return 0;
}

static int compute_rim_certificate_digest(TPM_RIM_CERTIFICATE* rimCert, BYTE *digest)
{
  tpm_sha1_ctx_t sha1_ctx;
  BYTE *buf, *ptr;
  UINT32 buf_len, len;
  UINT32 integrityCheckSize;

  /* marshal certificate */
  integrityCheckSize = rimCert->integrityCheckSize;
  rimCert->integrityCheckSize = 0;
  buf_len = len = sizeof_TPM_RIM_CERTIFICATE((*rimCert));
  buf = ptr = tpm_malloc(buf_len);
  if (buf == NULL || tpm_marshal_TPM_RIM_CERTIFICATE(&ptr, &len, rimCert)) {
    rimCert->integrityCheckSize = integrityCheckSize;
    tpm_free(buf);
    return -1;
  }
  rimCert->integrityCheckSize = integrityCheckSize;
  /* compute hmac */
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf, buf_len);
  tpm_sha1_final(&sha1_ctx, digest);
  tpm_free(buf);
  return 0;
}

static int compute_rim_certificate_hmac(TPM_RIM_CERTIFICATE* rimCert, BYTE *digest)
{
  tpm_hmac_ctx_t hmac_ctx;
  BYTE *buf, *ptr;
  UINT32 buf_len, len;
  UINT32 integrityCheckSize;

  /* marshal certificate */
  integrityCheckSize = rimCert->integrityCheckSize;
  rimCert->integrityCheckSize = 0;
  buf_len = len = sizeof_TPM_RIM_CERTIFICATE((*rimCert));
  buf = ptr = tpm_malloc(buf_len);
  if (buf == NULL || tpm_marshal_TPM_RIM_CERTIFICATE(&ptr, &len, rimCert)) {
    rimCert->integrityCheckSize = integrityCheckSize;
    tpm_free(buf);
    return -1;
  }
  rimCert->integrityCheckSize = integrityCheckSize;
  /* compute hmac */
  tpm_hmac_init(&hmac_ctx, mtmData.permanent.data.internalVerificationKey,
                sizeof(TPM_SECRET));
  tpm_hmac_update(&hmac_ctx, buf, buf_len);
  tpm_hmac_final(&hmac_ctx, digest);
  tpm_free(buf);
  return 0;
}

static TPM_RESULT verify_rim_certificate(TPM_RIM_CERTIFICATE *rimCert)
{
  /* check parrentID */
  debug("parentId = %08x", rimCert->parentId);
  if (rimCert->parentId == TPM_VERIFICATION_KEY_ID_NONE) return TPM_KEYNOTFOUND;
  /* verify certificate with appropiate key */
  if (rimCert->parentId == TPM_VERIFICATION_KEY_ID_INTERNAL) {
    BYTE digest[SHA1_DIGEST_LENGTH];
    debug("internal verification");
    if (compute_rim_certificate_hmac(rimCert, digest) != 0) {
      debug("compute_rim_certificate_hmac() failed");
      return TPM_FAIL;
    }
    /* check hmac */
    if (memcmp(digest, rimCert->integrityCheckData, SHA1_DIGEST_LENGTH) != 0) {
      debug("verification failed");
      return TPM_AUTHFAIL;
    } else {
      debug("verification succeeded");
      return TPM_SUCCESS;
    }
  } else {
    BYTE digest[SHA1_DIGEST_LENGTH];
    /* get verification key */
    MTM_KEY_DATA *key = mtm_get_key_by_id(rimCert->parentId);
    if (key == NULL) {
      return TPM_KEYNOTFOUND;
    }
    /* compute digest */
    if (compute_rim_certificate_digest(rimCert, digest) != 0) {
      debug("compute_rim_certificate_digest() failed");
      return TPM_FAIL;
    }
    /* check key properties */
    if (key->keyAlgorithm != TPM_ALG_RSA 
        || key->keyScheme != TPM_SS_RSASSAPKCS1v15_SHA1) {
      debug("invalid signature scheme");
      return TPM_BAD_SCHEME;
    }
    /* verify signature */
    if (tpm_rsa_verify(&key->key, RSA_SSA_PKCS1_SHA1_RAW, digest, sizeof(digest),
                       rimCert->integrityCheckData) != 0) {
      debug("verification failed");
      return TPM_AUTHFAIL;
    } else {
      debug("verification succeeded");
      return TPM_SUCCESS;
    }
  }
}

static int compute_verification_key_digest(TPM_VERIFICATION_KEY *key, BYTE *digest)
{
  tpm_sha1_ctx_t sha1_ctx;
  BYTE *buf, *ptr;
  UINT32 buf_len, len;
  UINT32 integrityCheckSize;

  /* marshal certificate */
  integrityCheckSize = key->integrityCheckSize;
  key->integrityCheckSize = 0;
  buf_len = len = sizeof_TPM_VERIFICATION_KEY((*key));
  buf = ptr = tpm_malloc(buf_len);
  if (buf == NULL || tpm_marshal_TPM_VERIFICATION_KEY(&ptr, &len, key)) {
    key->integrityCheckSize = integrityCheckSize;
    tpm_free(buf);
    return -1;
  }
  key->integrityCheckSize = integrityCheckSize;
  /* compute sha1 */
  tpm_sha1_init(&sha1_ctx);
  tpm_sha1_update(&sha1_ctx, buf, buf_len);
  tpm_sha1_final(&sha1_ctx, digest);
  tpm_free(buf);
  return 0;

}

static TPM_RESULT verify_verification_key(TPM_VERIFICATION_KEY *key, MTM_KEY_DATA *parentKey)
{
  BYTE digest[SHA1_DIGEST_LENGTH];

  /* compute digest */
  if (compute_verification_key_digest(key, digest) != 0) {
    debug("compute_verification_key_digest() failed");
    return TPM_FAIL;
  }
  /* check key properties */
  if (parentKey->keyAlgorithm != TPM_ALG_RSA
      || parentKey->keyScheme != TPM_SS_RSASSAPKCS1v15_SHA1) {
    debug("invalid signature scheme");
    return TPM_BAD_SCHEME;
  }
  /* verify signature */
  if (tpm_rsa_verify(&parentKey->key, RSA_SSA_PKCS1_SHA1_RAW, digest, sizeof(digest),
                     key->integrityCheckData) != 0) {
    debug("verification failed");
    return TPM_AUTHFAIL;
  } else {
    debug("verification succeeded");
    return TPM_SUCCESS;
  }
}

static int store_verification_key(TPM_VERIFICATION_KEY *inKey, MTM_KEY_DATA *outKey)
{
  outKey->usageFlags = inKey->usageFlags;
  outKey->parentId = inKey->parentId;
  outKey->myId = inKey->myId;
  outKey->keyAlgorithm = inKey->keyAlgorithm;
  outKey->keyScheme = inKey->keyScheme;
  BYTE *ptr = inKey->keyData;
  UINT32 len = inKey->keySize;
  if (tpm_unmarshal_RSAPub(&ptr, &len, &outKey->key) != 0) return -1;
  return 0;
}

TPM_RESULT MTM_InstallRIM(TPM_RIM_CERTIFICATE *rimCertIn, TPM_AUTH *auth1,
                          TPM_RIM_CERTIFICATE *rimCertOut)
{
  TPM_RESULT res;
  TPM_ACTUAL_COUNT cntProtect;

  info("MTM_InstallRIM()");
  /* 1 */
  if (rimCertIn == NULL || rimCertIn->tag != TPM_TAG_RIM_CERTIFICATE)
    return TPM_BAD_PARAMETER;
  /* 2 */
  res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, auth1->authHandle);
  if (res != TPM_SUCCESS) return res;
  /* 3 */
  cntProtect = tpmData.permanent.data.counters[MTM_COUNTER_SELECT_RIMPROTECT].counter;
  /* 5 */
  rimCertIn->integrityCheckSize = SHA1_DIGEST_LENGTH;
  if (copy_TPM_RIM_CERTIFICATE(rimCertIn, rimCertOut) != 0) {
    debug("copy_TPM_RIM_CERTIFICATE() failed");
    return TPM_FAIL;
  }
  /* 6, 7 */
  if (rimCertIn->referenceCounter.counterSelection != MTM_COUNTER_SELECT_NONE) {
    rimCertOut->referenceCounter.counterValue = cntProtect + 1;
    rimCertOut->referenceCounter.counterSelection = MTM_COUNTER_SELECT_RIMPROTECT;
  } else {
    rimCertOut->referenceCounter.counterValue = 0;
  }
  /* 8 */
  rimCertOut->parentId = TPM_VERIFICATION_KEY_ID_INTERNAL;
  /* 10, 11, 12 */
  if (compute_rim_certificate_hmac(rimCertOut, rimCertOut->integrityCheckData) != 0) {
    debug("compute_rim_certificate_hmac() failed");
    free_TPM_RIM_CERTIFICATE((*rimCertOut));
    return TPM_FAIL;
  }
  /* 13 */
  return TPM_SUCCESS;
}

static TPM_VERIFICATION_KEY_HANDLE mtm_get_free_key(void)
{
  int i;
  for (i = 0; i < TPM_MAX_KEYS; i++) {
    if (!mtmData.permanent.data.keys[i].valid) {
      mtmData.permanent.data.keys[i].valid = TRUE;
      return INDEX_TO_KEY_HANDLE(i);
    }
  }
  return TPM_INVALID_HANDLE;
}


TPM_RESULT MTM_LoadVerificationKey(TPM_VERIFICATION_KEY_HANDLE parentKeyHandle,
                                   TPM_VERIFICATION_KEY *verificationKey, TPM_AUTH *auth1,
                                   TPM_VERIFICATION_KEY_HANDLE *verificationKeyHandle,
                             	     BYTE *loadMethod)
{
  TPM_RESULT res;
  MTM_KEY_DATA *key;

  /* 1 */
  if (verificationKey == NULL || verificationKey->tag != TPM_TAG_VERIFICATION_KEY)
    return TPM_BAD_PARAMETER;
  /* 2 */
  *verificationKeyHandle = mtm_get_free_key();
  key = mtm_get_key(*verificationKeyHandle);
  if (key == NULL) {
    debug("no free key slot available");
    return TPM_NOSPACE;
  }
  *loadMethod = 0;
  /* 3 */
  if (mtmData.stany.flags.loadVerificationRootKeyEnabled) {
    debug("TPM_VERIFICATION_KEY_ROOT_LOAD");
    /* set integrityCheckRootData */
    if (!mtmData.permanent.data.integrityCheckRootValid) {
      if (compute_verification_key_digest(verificationKey,
            mtmData.permanent.data.integrityCheckRootData) != 0) {
        debug("compute_verification_key_digest() failed");
        memset(key, 0, sizeof(*key));
        return TPM_FAIL;
      }
      mtmData.permanent.data.integrityCheckRootValid = TRUE;
    }
    *loadMethod = TPM_VERIFICATION_KEY_ROOT_LOAD;
  }
  /* 4 */
  if (*loadMethod == 0
      && mtmData.permanent.data.integrityCheckRootValid) {
    BYTE digest[SHA1_DIGEST_LENGTH];
    if (compute_verification_key_digest(verificationKey, digest) != 0) {
      debug("compute_verification_key_digest() failed");
      memset(key, 0, sizeof(*key));
      return TPM_FAIL;
    }
    if (memcmp(mtmData.permanent.data.integrityCheckRootData,
               digest, SHA1_DIGEST_LENGTH) == 0) {
      debug("TPM_VERIFICATION_KEY_INTEGRITY_CHECK_ROOT_DATA_LOAD");
      *loadMethod = TPM_VERIFICATION_KEY_INTEGRITY_CHECK_ROOT_DATA_LOAD;
    }
  }
  /* 5 */
  if (*loadMethod == 0
      && tpmData.permanent.flags.owned && auth1->authHandle != TPM_INVALID_HANDLE) {
    TPM_RESULT res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
    if (res != TPM_SUCCESS) {
      memset(key, 0, sizeof(*key));
      return res;
    }
    debug("TPM_VERIFICATION_KEY_OWNER_AUTHORIZED_LOAD");
    *loadMethod = TPM_VERIFICATION_KEY_OWNER_AUTHORIZED_LOAD;
  }
  /* 6 */
  if (*loadMethod == 0) {
    MTM_KEY_DATA *parentKey = mtm_get_key(parentKeyHandle);
    if (parentKey == NULL) {
      debug("invalid parent key handle %08x", parentKeyHandle);
      memset(key, 0, sizeof(*key));
      return TPM_KEYNOTFOUND;
    }
    /* 7a-c */
    if (!(parentKey->usageFlags & TPM_VERIFICATION_KEY_USAGE_SIGN_RIMAUTH)) {
      memset(key, 0, sizeof(*key));
      return TPM_INVALID_KEYUSAGE;
    }
    if ((verificationKey->usageFlags & TPM_VERIFICATION_KEY_USAGE_INCREMENT_BOOTSTRAP)
        && !(parentKey->usageFlags & TPM_VERIFICATION_KEY_USAGE_INCREMENT_BOOTSTRAP)) {
      memset(key, 0, sizeof(*key));
      return TPM_INVALID_KEYUSAGE;
    }
    if (key->parentId != parentKey->myId) {
      debug("id mismatch: parentId = %08x keyId = %08x", key->parentId, parentKey->myId);
      memset(key, 0, sizeof(*key));  
      return TPM_AUTHFAIL;  
    }
    /* 7d */
    res = verify_verification_key(verificationKey, parentKey);
    if (res != TPM_SUCCESS) {
      memset(key, 0, sizeof(*key));
      return res;
    }
    /* 7e-g */
    if (verificationKey->referenceCounter.counterSelection > MTM_COUNTER_SELECT_MAX)
      return TPM_BAD_COUNTER;
    if (verificationKey->referenceCounter.counterSelection == MTM_COUNTER_SELECT_BOOTSTRAP) {
      if (verificationKey->referenceCounter.counterValue
          < tpmData.permanent.data.counters[MTM_COUNTER_SELECT_BOOTSTRAP].counter)
        return TPM_BAD_COUNTER;
    }
    if (verificationKey->referenceCounter.counterSelection == MTM_COUNTER_SELECT_RIMPROTECT) {
      if (verificationKey->referenceCounter.counterValue
          < tpmData.permanent.data.counters[MTM_COUNTER_SELECT_RIMPROTECT].counter)
        return TPM_BAD_COUNTER;
    }
    /* 7j */
    debug("TPM_VERIFICATION_KEY_CHAIN_AUTHORIZED_LOAD");
    *loadMethod = TPM_VERIFICATION_KEY_CHAIN_AUTHORIZED_LOAD;
  }
  /* store verification key */
  if (store_verification_key(verificationKey, key) != 0) {
    debug("store_verification_key() failed");
    memset(key, 0, sizeof(*key));
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

TPM_RESULT MTM_LoadVerificationRootKeyDisable()
{
  info("MTM_LoadVerificationRootKeyDisable()");
  mtmData.stany.flags.loadVerificationRootKeyEnabled = FALSE;
  mtmData.permanent.data.loadVerificationKeyMethods |= TPM_VERIFICATION_KEY_ROOT_LOAD;
  return TPM_SUCCESS;
}

TPM_RESULT MTM_VerifyRIMCert(TPM_RIM_CERTIFICATE* rimCert,
                             TPM_VERIFICATION_KEY_HANDLE rimKeyHandle)
{
  TPM_RESULT res;
  
  info("MTM_VerifyRIMCert()");
  debug("key handle = %08x", rimKeyHandle);
  /* 1 */
  if (rimCert ==  NULL || rimCert->tag != TPM_TAG_RIM_CERTIFICATE)
    return TPM_BAD_PARAMETER;
  /* 2 */
  if (rimCert->parentId == TPM_VERIFICATION_KEY_ID_NONE)
    return TPM_AUTHFAIL;
  /* 3 */
  if (rimCert->parentId == TPM_VERIFICATION_KEY_ID_INTERNAL) {
    return verify_rim_certificate(rimCert);
  } else {
    /* 4 */
    MTM_KEY_DATA *rimKey = mtm_get_key(rimKeyHandle);
    if (rimKey == NULL) return TPM_KEYNOTFOUND;
    if ((rimKey->usageFlags & TPM_VERIFICATION_KEY_USAGE_SIGN_RIMCERT) == 0)
      return TPM_INVALID_KEYUSAGE;
    if (rimCert->parentId != rimKey->myId) {
      debug("id mismatch: parentId = %08x keyId = %08x", rimCert->parentId, rimKey->myId);
      return TPM_AUTHFAIL;
    }
    res = verify_rim_certificate(rimCert);
    if (res != TPM_SUCCESS) return res;
  }
  /* 5 */
  if (rimCert->referenceCounter.counterSelection > MTM_COUNTER_SELECT_MAX)
    return TPM_BAD_COUNTER;
  /* 6 */
  if (rimCert->referenceCounter.counterSelection == MTM_COUNTER_SELECT_BOOTSTRAP) {
    if (rimCert->referenceCounter.counterValue
        < tpmData.permanent.data.counters[MTM_COUNTER_SELECT_BOOTSTRAP].counter)
      return TPM_BAD_COUNTER;
  }
  /* 7 */
  if (rimCert->referenceCounter.counterSelection == MTM_COUNTER_SELECT_RIMPROTECT) {
    if (rimCert->referenceCounter.counterValue
        < tpmData.permanent.data.counters[MTM_COUNTER_SELECT_RIMPROTECT].counter)
      return TPM_BAD_COUNTER;
  }
  return TPM_SUCCESS;
}

TPM_RESULT MTM_VerifyRIMCertAndExtend(TPM_RIM_CERTIFICATE *rimCert,
                                      TPM_VERIFICATION_KEY_HANDLE rimKey,
                                      TPM_PCRVALUE *outDigest)
{
  int i;
  TPM_RESULT res;

  info("MTM_VerifyRIMCertAndExtend()");
  /* 1-7 */
  res = MTM_VerifyRIMCert(rimCert, rimKey);
  if (res != TPM_SUCCESS) return res;
  /* 8 */
  for (i = 0; i < TPM_NUM_PCR / 8; i++) {
    if (rimCert->state.pcrSelection.pcrSelect[i] != 0) break;
  }
  if (i < TPM_NUM_PCR / 8) {
    TPM_COMPOSITE_HASH digest;
    if (tpm_compute_pcr_digest(&rimCert->state.pcrSelection, &digest, NULL) != TPM_SUCCESS) {
      debug("tpm_compute_pcr_digest() failed");
      return TPM_FAIL;
    }
    if (memcmp(&digest, &rimCert->state.digestAtRelease, sizeof(TPM_COMPOSITE_HASH)) != 0)
      return TPM_WRONGPCRVAL;
  }
  /* 9, 10 */
  return TPM_Extend(rimCert->measurementPcrIndex, &rimCert->measurementValue, outDigest);
}

TPM_RESULT MTM_IncrementBootstrapCounter(TPM_RIM_CERTIFICATE *rimCert,
                                         TPM_VERIFICATION_KEY_HANDLE rimKeyHandle)
{
  TPM_RESULT res;
  MTM_KEY_DATA* rimKey;
 
  info("MTM_IncrementBootstrapCounter()");
  /* 1 */
  if (rimCert == NULL || rimCert->tag != TPM_TAG_RIM_CERTIFICATE)
    return TPM_BAD_PARAMETER;
  /* 2 */
  debug("rimKeyHandle = %08x", rimKeyHandle);
  rimKey = mtm_get_key(rimKeyHandle);
  if (rimKey == NULL) return TPM_KEYNOTFOUND;
  /* 3 */
  if ((rimKey->usageFlags & TPM_VERIFICATION_KEY_USAGE_SIGN_RIMCERT) == 0
      ||(rimKey->usageFlags & TPM_VERIFICATION_KEY_USAGE_INCREMENT_BOOTSTRAP) == 0)
    return TPM_INVALID_KEYUSAGE;
  /* 4 */
  if (rimCert->parentId != rimKey->myId) return TPM_AUTHFAIL;
  /* 5 */
  res = verify_rim_certificate(rimCert);
  if (res != TPM_SUCCESS) return res;
  /* 6 */
  if (rimCert->referenceCounter.counterSelection > MTM_COUNTER_SELECT_MAX)
    return TPM_BAD_COUNTER;
  /* 7 */
  if (rimCert->referenceCounter.counterSelection == MTM_COUNTER_SELECT_BOOTSTRAP) {
    if (rimCert->referenceCounter.counterValue
        < tpmData.permanent.data.counters[MTM_COUNTER_SELECT_BOOTSTRAP].counter)
      return TPM_BAD_COUNTER;
    tpmData.permanent.data.counters[MTM_COUNTER_SELECT_BOOTSTRAP].counter
      = rimCert->referenceCounter.counterValue;
  }
  return TPM_SUCCESS;
}

TPM_RESULT MTM_SetVerifiedPCRSelection(TPM_PCR_SELECTION *verifiedSelection,
                                       TPM_AUTH *auth1)
{
  int i;
  TPM_RESULT res;

  info("MTM_SetVerifiedPCRSelection()");
  /* verify permission */
  if (tpmData.permanent.flags.owned) {
    res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, TPM_KH_OWNER);
  } else {
    res = FALSE;
  }
  if (!res && !mtmData.stany.flags.loadVerificationRootKeyEnabled) {
    return TPM_FAIL;
  }
  /* echeck if a localityModifier is set */
  for (i = 0; i < TPM_NUM_PCR; i++) {
    if (verifiedSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
	    if (tpmData.permanent.data.pcrAttrib[i].pcrResetLocal) return TPM_FAIL;
	  }
  }
  /* copy selection */
  memcpy(&mtmData.permanent.data.verifiedPCRs,
         verifiedSelection, sizeof(TPM_PCR_SELECTION));
  return TPM_SUCCESS;
}


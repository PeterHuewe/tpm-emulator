/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *               2005-2008 Heiko Stamer <stamer@gaos.org>
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
 * $Id: tpm_identity.c 468 2011-09-09 07:58:42Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "crypto/sha1.h"
#include "crypto/rsa.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"

#define LOCALITY tpmData.stany.flags.localityModifier

/*
 * Identity Creation and Activation ([TPM_Part3], Section 15)
 */

TPM_RESULT TPM_MakeIdentity(
  TPM_ENCAUTH *identityAuth,
  TPM_CHOSENID_HASH *labelPrivCADigest,
  TPM_KEY *idKeyParams,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_KEY *idKey,
  UINT32 *identityBindingSize,
  BYTE **identityBinding
)
{
  TPM_RESULT res;
  TPM_SESSION_DATA *ownerAuth_sessionData;
  TPM_SECRET A1;
  tpm_rsa_private_key_t tpm_signature_key;
  UINT32 key_length;
  TPM_STORE_ASYMKEY store;
  TPM_IDENTITY_CONTENTS idContents;
  UINT32 len;
  BYTE *buf, *ptr;
  
  info("TPM_MakeIdentity()");
  /* 1. Validate the idKeyParams parameters for the key description */
    if (idKeyParams->algorithmParms.encScheme != TPM_ES_NONE
      || idKeyParams->algorithmParms.sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1)
        return TPM_BAD_KEY_PROPERTY;
    /* a. If the algorithm type is RSA the key length MUST be a minimum of 2048.
     * For interoperability the key length SHOULD be 2048 */
    /* b. If the algorithm type is other than RSA the strength provided by the 
     * key MUST be comparable to RSA 2048 */
    /* c. If the TPM is not designed to create a key of the requested type, 
     * return the error code TPM_BAD_KEY_PROPERTY */
    switch (idKeyParams->algorithmParms.algorithmID) {
      case TPM_ALG_RSA:
        if (idKeyParams->algorithmParms.parmSize == 0
          || idKeyParams->algorithmParms.parms.rsa.keyLength != 2048
          || idKeyParams->algorithmParms.parms.rsa.numPrimes != 2
          || idKeyParams->algorithmParms.parms.rsa.exponentSize != 0)
            return TPM_BAD_KEY_PROPERTY;
        break;
      default:
        return TPM_BAD_KEY_PROPERTY;
    }
    /* d. If TPM_PERMANENT_FLAGS->FIPS is TRUE then */
    if (tpmData.permanent.flags.FIPS == TRUE) {
      /* i. If authDataUsage specifies TPM_AUTH_NEVER return TPM_NOTFIPS */
      if (idKeyParams->authDataUsage == TPM_AUTH_NEVER)
        return TPM_NOTFIPS;
    }
  /* 2. Use authHandle to verify that the Owner authorized all TPM_MakeIdentity 
   * input parameters. */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
    res = tpm_verify_auth(auth2, tpmData.permanent.data.ownerAuth, 
      TPM_KH_OWNER);
    if (res != TPM_SUCCESS) return res;
    ownerAuth_sessionData = tpm_get_auth(auth2->authHandle);
  } else {
    res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, 
      TPM_KH_OWNER);
    if (res != TPM_SUCCESS) return res;
    ownerAuth_sessionData = tpm_get_auth(auth1->authHandle);
  }
  /* 3. Use srkAuthHandle to verify that the SRK owner authorized all 
   * TPM_MakeIdentity input parameters. */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
    res = tpm_verify_auth(auth1, tpmData.permanent.data.srk.usageAuth, 
      TPM_KH_SRK);
    if (res != TPM_SUCCESS) return res;
  }
  /* 4. Verify that idKeyParams->keyUsage is TPM_KEY_IDENTITY. If it is not, 
   * return TPM_INVALID_KEYUSAGE */
  if (idKeyParams->keyUsage != TPM_KEY_IDENTITY)
    return TPM_INVALID_KEYUSAGE;
  /* 5. Verify that idKeyParams->keyFlags->migratable is FALSE. If it is not,
   * return TPM_INVALID_KEYUSAGE */
  if ((idKeyParams->keyFlags & TPM_KEY_FLAG_MIGRATABLE) == 
    TPM_KEY_FLAG_MIGRATABLE)
      return TPM_INVALID_KEYUSAGE;
  /* 6. If ownerAuth indicates XOR encryption for the AuthData secrets */
  if (ownerAuth_sessionData == NULL) return TPM_INVALID_AUTHHANDLE;
  if ((ownerAuth_sessionData->entityType & 0xFF00) == TPM_ET_XOR) {
    /* a. Create X1 the SHA-1 of the concatenation of (ownerAuth->sharedSecret 
     * || authLastNonceEven) */
    /* b. Create A1 by XOR X1 and identityAuth */
    tpm_decrypt_auth_secret(*identityAuth, ownerAuth_sessionData->sharedSecret, 
      &ownerAuth_sessionData->lastNonceEven, A1);
  } else {
  /* 7. Else */
    /* a. Create A1 by decrypting identityAuth using the algorithm indicated 
     * in the OSAP session */
    /* b. Key is from ownerAuth->sharedSecret */
    /* c. IV is SHA-1 of (authLastNonceEven || nonceOdd) */
    debug("TPM_MakeIdentity() does not support entityType=%.8x yet.", 
      ownerAuth_sessionData->entityType);
    return TPM_FAIL;
  }
  /* 8. Set continueAuthSession and continueSRKSession to FALSE. */
  auth2->continueAuthSession = FALSE, auth1->continueAuthSession = FALSE;
  /* 9. Determine the structure version */
    /* a. If idKeyParms->tag is TPM_TAG_KEY12 */
    if (idKeyParams->tag == TPM_TAG_KEY12) {
      /* i. Set V1 to 2 */
      /* ii. Create idKey a TPM_KEY12 structure using idKeyParams as the 
       * default values for the structure */
      idKey->tag = TPM_TAG_KEY12;
      idKey->fill = 0x0000;
      idKey->keyUsage = TPM_KEY_IDENTITY;
      idKey->keyFlags = idKeyParams->keyFlags;
      idKey->authDataUsage = idKeyParams->authDataUsage;
      idKey->algorithmParms.algorithmID = 
        idKeyParams->algorithmParms.algorithmID;
      idKey->algorithmParms.encScheme = idKeyParams->algorithmParms.encScheme;
      idKey->algorithmParms.sigScheme = idKeyParams->algorithmParms.sigScheme;
      idKey->algorithmParms.parmSize = idKeyParams->algorithmParms.parmSize;
      switch (idKeyParams->algorithmParms.algorithmID) {
        case TPM_ALG_RSA:
          idKey->algorithmParms.parms.rsa.keyLength =
            idKeyParams->algorithmParms.parms.rsa.keyLength;
          idKey->algorithmParms.parms.rsa.numPrimes =
            idKeyParams->algorithmParms.parms.rsa.numPrimes;
          idKey->algorithmParms.parms.rsa.exponentSize =
            idKeyParams->algorithmParms.parms.rsa.exponentSize;
          break;
        default:
          return TPM_BAD_KEY_PROPERTY;
      }
      idKey->PCRInfoSize = idKeyParams->PCRInfoSize;
      idKey->PCRInfo.tag = TPM_TAG_PCR_INFO_LONG;
      idKey->PCRInfo.localityAtCreation = 
        idKeyParams->PCRInfo.localityAtCreation;
      idKey->PCRInfo.localityAtRelease = 
        idKeyParams->PCRInfo.localityAtRelease;
      idKey->PCRInfo.creationPCRSelection = 
        idKeyParams->PCRInfo.creationPCRSelection;
      idKey->PCRInfo.releasePCRSelection = 
        idKeyParams->PCRInfo.releasePCRSelection;
      idKey->PCRInfo.digestAtCreation = 
        idKeyParams->PCRInfo.digestAtCreation;
      idKey->PCRInfo.digestAtRelease = 
        idKeyParams->PCRInfo.digestAtRelease;
    } else if (idKeyParams->tag == 0x0101) {
    /* b. If idKeyParms->ver is 1.1 */
      /* i. Set V1 to 1 */
      /* ii. Create idKey a TPM_KEY structure using idKeyParams as the 
       * default values for the structure */
      idKey->tag = 0x0101;
      idKey->fill = 0x0000;
      idKey->keyUsage = TPM_KEY_IDENTITY;
      idKey->keyFlags = idKeyParams->keyFlags;
      idKey->authDataUsage = idKeyParams->authDataUsage;
      idKey->algorithmParms.algorithmID = 
        idKeyParams->algorithmParms.algorithmID;
      idKey->algorithmParms.encScheme = idKeyParams->algorithmParms.encScheme;
      idKey->algorithmParms.sigScheme = idKeyParams->algorithmParms.sigScheme;
      idKey->algorithmParms.parmSize = idKeyParams->algorithmParms.parmSize;
      switch (idKeyParams->algorithmParms.algorithmID) {
        case TPM_ALG_RSA:
          idKey->algorithmParms.parms.rsa.keyLength =
            idKeyParams->algorithmParms.parms.rsa.keyLength;
          idKey->algorithmParms.parms.rsa.numPrimes =
            idKeyParams->algorithmParms.parms.rsa.numPrimes;
          idKey->algorithmParms.parms.rsa.exponentSize =
            idKeyParams->algorithmParms.parms.rsa.exponentSize;
          break;
        default:
          return TPM_BAD_KEY_PROPERTY;
      }
      idKey->PCRInfoSize = idKeyParams->PCRInfoSize;
      idKey->PCRInfo.tag = 0x0000;
      idKey->PCRInfo.creationPCRSelection = 
        idKeyParams->PCRInfo.creationPCRSelection;
      idKey->PCRInfo.digestAtRelease = 
        idKeyParams->PCRInfo.digestAtRelease;
      idKey->PCRInfo.digestAtCreation = 
        idKeyParams->PCRInfo.digestAtCreation;
    } else {
      debug("TPM_MakeIdentity(): unsupport this TPM_KEY structure.");
      return TPM_FAIL;
    }
  /* 10. Set the digestAtCreation values for pcrInfo */
  if (idKey->PCRInfoSize > 0) {
    res = tpm_compute_pcr_digest(&idKey->PCRInfo.creationPCRSelection,
      &idKey->PCRInfo.digestAtCreation, NULL);
    if (res != TPM_SUCCESS) return res;
      /* a. For PCR_INFO_LONG include the locality of the current command */
      if (idKey->PCRInfo.tag == TPM_TAG_PCR_INFO_LONG)
        idKey->PCRInfo.localityAtCreation = (1 << LOCALITY);
  }
  /* 11. Create an asymmetric key pair (identityPubKey and tpm_signature_key) 
   * using a TPM-protected capability, in accordance with the algorithm 
   * specified in idKeyParams */
  key_length = idKeyParams->algorithmParms.parms.rsa.keyLength;
  if (tpm_rsa_generate_key(&tpm_signature_key, key_length)) {
    debug("TPM_MakeIdentity(): tpm_rsa_generate_key() failed.");
    return TPM_FAIL;
  }
  /* 12. Ensure that the AuthData information in A1 is properly stored in the 
   * idKey as usageAuth. */
  memcpy(store.usageAuth, A1, sizeof(TPM_SECRET));
  /* 13. Attach identityPubKey and tpm_signature_key to idKey */
  idKey->pubKey.keyLength = key_length >> 3;
  idKey->pubKey.key = tpm_malloc(idKey->pubKey.keyLength);
  if (idKey->pubKey.key == NULL) {
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  store.privKey.keyLength = key_length >> 4;
  store.privKey.key = tpm_malloc(store.privKey.keyLength);
  if (store.privKey.key == NULL) {
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  idKey->encDataSize = tpmData.permanent.data.srk.key.size >> 3;
  idKey->encData = tpm_malloc(idKey->encDataSize);
  if (idKey->encData == NULL) {
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  tpm_rsa_export_modulus(&tpm_signature_key, idKey->pubKey.key, NULL);
  tpm_rsa_export_prime1(&tpm_signature_key, store.privKey.key, NULL);
  /* 14. Set idKey->migrationAuth to TPM_PERMANENT_DATA->tpmProof */
  memcpy(store.migrationAuth, tpmData.permanent.data.tpmProof.nonce, 
    sizeof(TPM_SECRET));
  /* 15. Ensure that all TPM_PAYLOAD_TYPE structures identify this key as 
   * TPM_PT_ASYM */
  store.payload = TPM_PT_ASYM;
  /* compute the digest on all public data of this key */
  if (tpm_compute_key_digest(idKey, &store.pubDataDigest)) {
    debug("TPM_MakeIdentity(): tpm_compute_key_digest() failed.");
    tpm_free(idKey->encData);
    tpm_free(store.privKey.key);
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_FAIL;
  }
  /* 16. Encrypt the private portion of idKey using the SRK as the parent key */
  if (tpm_encrypt_private_key(&tpmData.permanent.data.srk, &store, idKey->encData, 
    &idKey->encDataSize)) {
      tpm_free(idKey->encData);
      tpm_free(store.privKey.key);
      tpm_free(idKey->pubKey.key);
      tpm_rsa_release_private_key(&tpm_signature_key);
      return TPM_ENCRYPT_ERROR;
  }
  tpm_free(store.privKey.key);
  /* 17. Create a TPM_IDENTITY_CONTENTS structure named idContents using 
   * labelPrivCADigest and the information from idKey */
  idContents.ver.major = 1, idContents.ver.minor = 1; /* MUST BE 1.1, (Spec) */
  idContents.ver.revMajor = 0, idContents.ver.revMinor = 0;
  idContents.ordinal = TPM_ORD_MakeIdentity;
  memcpy(&idContents.labelPrivCADigest, labelPrivCADigest, 
    sizeof(TPM_CHOSENID_HASH));
  idContents.identityPubKey.algorithmParms.algorithmID = 
    idKey->algorithmParms.algorithmID;
  idContents.identityPubKey.algorithmParms.encScheme = 
    idKey->algorithmParms.encScheme;
  idContents.identityPubKey.algorithmParms.sigScheme = 
    idKey->algorithmParms.sigScheme;
  idContents.identityPubKey.algorithmParms.parmSize = 
    idKey->algorithmParms.parmSize;
  switch (idKey->algorithmParms.algorithmID) {
    case TPM_ALG_RSA:
      idContents.identityPubKey.algorithmParms.parms.rsa.keyLength =
        idKey->algorithmParms.parms.rsa.keyLength;
      idContents.identityPubKey.algorithmParms.parms.rsa.numPrimes =
        idKey->algorithmParms.parms.rsa.numPrimes;
      idContents.identityPubKey.algorithmParms.parms.rsa.exponentSize =
        idKey->algorithmParms.parms.rsa.exponentSize;
      break;
    default:
      tpm_free(idKey->encData);
      tpm_free(idKey->pubKey.key);
      tpm_rsa_release_private_key(&tpm_signature_key);
      return TPM_BAD_KEY_PROPERTY;
  }
  idContents.identityPubKey.pubKey.keyLength = key_length >> 3;
  idContents.identityPubKey.pubKey.key = 
    tpm_malloc(idContents.identityPubKey.pubKey.keyLength);
  if (idContents.identityPubKey.pubKey.key == NULL) {
    tpm_free(idKey->encData);
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  tpm_rsa_export_modulus(&tpm_signature_key, idContents.identityPubKey.pubKey.key, NULL);
  len = sizeof_TPM_IDENTITY_CONTENTS((idContents));
  buf = ptr = tpm_malloc(len);
  if (buf == NULL) {
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  if (tpm_marshal_TPM_IDENTITY_CONTENTS(&ptr, &len, &idContents)) {
    debug("TPM_MakeIdentity(): tpm_marshal_TPM_IDENTITY_CONTENTS() failed.");
    tpm_free(buf);
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_FAIL;
  }
  /* 18. Sign idContents using tpm_signature_key and 
   * TPM_SS_RSASSAPKCS1v15_SHA1. Store the result in identityBinding. */
  *identityBindingSize = tpm_signature_key.size >> 3;
  *identityBinding = tpm_malloc(*identityBindingSize);
  if (*identityBinding == NULL) {
    tpm_free(buf);
    tpm_free(idContents.identityPubKey.pubKey.key);
    tpm_free(idKey->encData);
    tpm_free(idKey->pubKey.key);
    tpm_rsa_release_private_key(&tpm_signature_key);
    return TPM_NOSPACE;
  }
  if (tpm_rsa_sign(&tpm_signature_key, RSA_SSA_PKCS1_SHA1, buf, 
    sizeof_TPM_IDENTITY_CONTENTS((idContents)), *identityBinding)) {
      debug("TPM_MakeIdentity(): tpm_rsa_sign() failed.");
      tpm_free(*identityBinding);
      tpm_free(buf);
      tpm_free(idContents.identityPubKey.pubKey.key);
      tpm_free(idKey->encData);
      tpm_free(idKey->pubKey.key);
      tpm_rsa_release_private_key(&tpm_signature_key);
      return TPM_FAIL;
  }
  tpm_free(buf);
  tpm_free(idContents.identityPubKey.pubKey.key);
  tpm_rsa_release_private_key(&tpm_signature_key);
  
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ActivateIdentity(
  TPM_KEY_HANDLE idKeyHandle,
  UINT32 blobSize,
  BYTE *blob,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_SYMMETRIC_KEY *symmetricKey
)
{
  TPM_RESULT res;
  TPM_KEY_DATA *idKey = NULL;
  TPM_PUBKEY pubKey;
  TPM_DIGEST H1;
  BYTE *B1 = NULL;
  size_t sizeB1 = 0;
  UINT32 len;
  BYTE *ptr;
  BYTE B1__what = 0x00;
  TPM_EK_BLOB B1__ekBlob;
  TPM_ASYM_CA_CONTENTS B1__asymCaContents;
  TPM_SYMMETRIC_KEY *K1 = NULL;
  TPM_EK_BLOB_ACTIVATE A1;
  TPM_COMPOSITE_HASH C1;
  
  info("TPM_ActivateIdentity()");
  
  /* 1. Using the authHandle field, validate the owner's AuthData to execute 
   * the command and all of the incoming parameters. */
  if (auth2->authHandle != TPM_INVALID_HANDLE) {
    res = tpm_verify_auth(auth2, tpmData.permanent.data.ownerAuth, 
      TPM_KH_OWNER);
    if (res != TPM_SUCCESS) return res;
  } else {
    res = tpm_verify_auth(auth1, tpmData.permanent.data.ownerAuth, 
      TPM_KH_OWNER);
    if (res != TPM_SUCCESS) return res;
  }
  
  /* 2. Using the idKeyAuthHandle, validate the AuthData to execute command 
   * and all of the incoming parameters */
  idKey = tpm_get_key(idKeyHandle);
  if (idKey == NULL)
    return TPM_INVALID_KEYHANDLE;
  if (auth2->authHandle != TPM_INVALID_HANDLE) { 
    if (idKey->authDataUsage != TPM_AUTH_NEVER) {
      res = tpm_verify_auth(auth1, idKey->usageAuth, idKeyHandle);
      if (res != TPM_SUCCESS) return res;
    }
  }
  
  /* 3. Validate that the idKey is the public key of a valid TPM identity by 
   * checking that idKeyHandle->keyUsage is TPM_KEY_IDENTITY. 
   * Return TPM_BAD_PARAMETER on mismatch */
  if (idKey->keyUsage != TPM_KEY_IDENTITY)
    return TPM_BAD_PARAMETER;
  
  /* 4. Create H1 the digest of a TPM_PUBKEY derived from idKey */
  pubKey.pubKey.keyLength = idKey->key.size >> 3;
  pubKey.pubKey.key = tpm_malloc(pubKey.pubKey.keyLength);
  if (pubKey.pubKey.key == NULL)
    return TPM_NOSPACE;
  tpm_rsa_export_modulus(&idKey->key, pubKey.pubKey.key, NULL);
  if (tpm_setup_key_parms(idKey, &pubKey.algorithmParms) != 0) {
    debug("TPM_ActivateIdentity(): tpm_setup_key_parms() failed.");
    tpm_free(pubKey.pubKey.key);
    return TPM_FAIL;
  }
  tpm_free(pubKey.algorithmParms.parms.rsa.exponent);
  pubKey.algorithmParms.parms.rsa.exponentSize = 0;
  pubKey.algorithmParms.parmSize = 12;
  if (tpm_compute_pubkey_digest(&pubKey, &H1)) {
    debug("TPM_ActivateIdentity(): tpm_compute_pubkey_digest() failed.");
    tpm_free(pubKey.pubKey.key);
    return TPM_FAIL;
  }
  
  /* 5. Decrypt blob creating B1 using PRIVEK as the decryption key */
  B1 = tpm_malloc(blobSize);
  if (B1 == NULL) {
    tpm_free(pubKey.pubKey.key);
    return TPM_NOSPACE;
  }
  if (tpm_rsa_decrypt(&tpmData.permanent.data.endorsementKey, RSA_ES_OAEP_SHA1, 
    blob, blobSize, B1, &sizeB1)) {
      tpm_free(pubKey.pubKey.key);
      tpm_free(B1);
      return TPM_DECRYPT_ERROR;
  }
  
  /* 6. Determine the type and version of B1 */
  if ((((UINT16)B1[0] << 8) | B1[1]) == TPM_TAG_EK_BLOB) {
    /* a. If B1->tag is TPM_TAG_EK_BLOB then */
      /* i. B1 is a TPM_EK_BLOB */
    ptr = B1;
    len = sizeB1;
    if (tpm_unmarshal_TPM_EK_BLOB(&ptr, &len, &B1__ekBlob)) {
        debug("TPM_ActivateIdentity(): tpm_unmarshal_TPM_EK_BLOB() failed.");
        tpm_free(pubKey.pubKey.key);
        tpm_free(B1);
        return TPM_FAIL;
    }
    B1__what = 0x02;
  } else {
    /* b. Else */
      /* i. B1 is a TPM_ASYM_CA_CONTENTS. As there is no tag for this 
       * structure it is possible for the TPM to make a mistake here but 
       * other sections of the structure undergo validation */
    ptr = B1;
    len = sizeB1;
    if (tpm_unmarshal_TPM_ASYM_CA_CONTENTS(&ptr, &len, &B1__asymCaContents)) {
        debug("TPM_ActivateIdentity(): tpm_unmarshal_TPM_ASYM_CA_CONTENTS() failed.");
        tpm_free(pubKey.pubKey.key);
        tpm_free(B1);
        return TPM_FAIL;
    }
    B1__what = 0x01;
  }
  
  /* 7. If B1 is a version 1.1 TPM_ASYM_CA_CONTENTS then */
  if (B1__what == 0x01) {
    /* a. Compare H1 to B1->idDigest on mismatch return TPM_BAD_PARAMETER */
    if (memcmp(H1.digest, B1__asymCaContents.idDigest.digest, 
      sizeof(H1.digest))) {
        tpm_free(pubKey.pubKey.key);
        tpm_free(B1);
        return TPM_BAD_PARAMETER;
    }
    /* b. Set K1 to B1->sessionKey */
    K1 = &B1__asymCaContents.sessionKey;
  }
  
  /* 8. If B1 is a TPM_EK_BLOB then */
  if (B1__what == 0x02) {
    /* a. Validate that B1->ekType is TPM_EK_TYPE_ACTIVATE, 
     * return TPM_BAD_TYPE if not. */
    if (B1__ekBlob.ekType != TPM_EK_TYPE_ACTIVATE) {
      tpm_free(pubKey.pubKey.key);
      tpm_free(B1);
      return TPM_BAD_TYPE;
    }
    /* b. Assign A1 as a TPM_EK_BLOB_ACTIVATE structure from B1->blob */
    ptr = B1__ekBlob.blob;
    len = B1__ekBlob.blobSize;
    if (tpm_unmarshal_TPM_EK_BLOB_ACTIVATE(&ptr, &len, &A1)) {
        debug("TPM_ActivateIdentity(): tpm_unmarshal_TPM_EK_BLOB_ACTIVATE() failed.");
        tpm_free(pubKey.pubKey.key);
        tpm_free(B1);
        return TPM_FAIL;
    }
    /* c. Compare H1 to A1->idDigest on mismatch return TPM_BAD_PARAMETER */
    if (memcmp(H1.digest, A1.idDigest.digest, sizeof(H1.digest))) {
      tpm_free(pubKey.pubKey.key);
      tpm_free(B1);
      return TPM_BAD_PARAMETER;
    }
    /* d. If A1->pcrSelection is not NULL */
    if (A1.pcrInfo.pcrSelection.sizeOfSelect > 0) {
      /* i. Compute a composite hash C1 using the PCR selection 
       * A1->pcrSelection */
      if (tpm_compute_pcr_digest(&A1.pcrInfo.pcrSelection, &C1, NULL) !=
        TPM_SUCCESS) {
          debug("TPM_ActivateIdentity(): tpm_compute_pcr_digest() failed.");
          tpm_free(pubKey.pubKey.key);
          tpm_free(B1);
          return TPM_FAIL;
      }
      /* ii. Compare C1 to A1->pcrInfo->digestAtRelease and return 
       * TPM_WRONGPCRVAL on a mismatch */
      if (memcmp(&C1, &A1.pcrInfo.digestAtRelease, 
        sizeof(TPM_COMPOSITE_HASH))) {
          tpm_free(pubKey.pubKey.key);
          tpm_free(B1);
          return TPM_WRONGPCRVAL;
      }
      /* iii. If A1->pcrInfo specifies a locality ensure that the 
       * appropriate locality has been asserted, return TPM_BAD_LOCALITY 
       * on error */
      if (!(A1.pcrInfo.localityAtRelease & (1 << LOCALITY))) {
        tpm_free(pubKey.pubKey.key);
        tpm_free(B1);
        return TPM_BAD_LOCALITY;
      }
    }
    /* e. Set K1 to A1->sessionKey */
    K1 = &A1.sessionKey;
  }
  
  /* 9. Return K1 */
  if (K1 != NULL) {
    symmetricKey->algId = K1->algId;
    symmetricKey->encScheme = K1->encScheme;
    symmetricKey->size = K1->size;
    memcpy(symmetricKey->data, K1->data, K1->size);
  }
  tpm_free(pubKey.pubKey.key);
  tpm_free(B1);
  return TPM_SUCCESS;
}

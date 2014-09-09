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
 * $Id: tpm_integrity.c 474 2011-12-20 10:27:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "crypto/sha1.h"
#include "crypto/rsa.h"
#include "tpm_handles.h"
#include "tpm_marshalling.h"

/*
 * Integrity Collection and Reporting ([TPM_Part3], Section 16)
 * This section deals with what commands have direct access to the PCR.
 */

#define PCR_ATTRIB     tpmData.permanent.data.pcrAttrib
#define PCR_VALUE      tpmData.permanent.data.pcrValue
#define LOCALITY       tpmData.stany.flags.localityModifier

TPM_RESULT TPM_Extend(TPM_PCRINDEX pcrNum, TPM_DIGEST *inDigest, 
                      TPM_PCRVALUE *outDigest)
{
  tpm_sha1_ctx_t ctx;

  info("TPM_Extend()");
  if (pcrNum >= TPM_NUM_PCR) return TPM_BADINDEX;
  if (!(PCR_ATTRIB[pcrNum].pcrExtendLocal & (1 << LOCALITY))) return TPM_BAD_LOCALITY;
  /* compute new PCR value as SHA-1(old PCR value || inDigest) */
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, PCR_VALUE[pcrNum].digest, sizeof(PCR_VALUE[pcrNum].digest));
  tpm_sha1_update(&ctx, inDigest->digest, sizeof(inDigest->digest));
  tpm_sha1_final(&ctx, PCR_VALUE[pcrNum].digest);  
  /* set output digest */
  if (tpmData.permanent.flags.disable) {
    memset(outDigest->digest, 0, sizeof(*outDigest->digest));
  } else {
    memcpy(outDigest, &PCR_VALUE[pcrNum], sizeof(TPM_PCRVALUE));
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PCRRead(TPM_PCRINDEX pcrIndex, TPM_PCRVALUE *outDigest)
{
  info("TPM_PCRRead()");
  if (pcrIndex >= TPM_NUM_PCR) return TPM_BADINDEX;
  memcpy(outDigest, &PCR_VALUE[pcrIndex], sizeof(TPM_PCRVALUE));
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Quote(TPM_KEY_HANDLE keyHandle, TPM_NONCE *extrnalData, 
                     TPM_PCR_SELECTION *targetPCR, TPM_AUTH *auth1, 
                     TPM_PCR_COMPOSITE *pcrData, 
                     UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_COMPOSITE_HASH hash;
  BYTE buf[48];
  info("TPM_Quote()");
  /* get key */
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* verify authorization */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  if (key->sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1)
    return TPM_INAPPROPRIATE_SIG;
  if (key->keyUsage != TPM_KEY_SIGNING && key->keyUsage != TPM_KEY_LEGACY
      && key->keyUsage != TPM_KEY_IDENTITY)
    return TPM_INVALID_KEYUSAGE;
  /* compute composite hash */
  res = tpm_compute_pcr_digest(targetPCR, &hash, pcrData);
  if (res != TPM_SUCCESS) return res;
  /* setup quote info and sign it */
  memcpy(&buf[ 0], "\x01\x01\x00\x00QUOT", 8);
  memcpy(&buf[ 8], hash.digest, 20);
  memcpy(&buf[28], extrnalData->nonce, 20);
  *sigSize = key->key.size >> 3;
  *sig = tpm_malloc(*sigSize);
  if (*sig == NULL) return TPM_FAIL;
  if (tpm_rsa_sign(&key->key, RSA_SSA_PKCS1_SHA1, buf, 48, *sig)) {
    tpm_free(*sig);
    return TPM_FAIL;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_PCR_Reset(TPM_PCR_SELECTION *pcrSelection)
{
  int i;
  info("TPM_PCR_Reset()");
  if ((pcrSelection->sizeOfSelect * 8) > TPM_NUM_PCR)
    return TPM_INVALID_PCR_INFO;
  /* this command must be atomic, thus we first verify that all
     registers are resetable ... */ 
  for (i = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      if (!PCR_ATTRIB[i].pcrReset) return TPM_NOTRESETABLE;
      if (!(PCR_ATTRIB[i].pcrResetLocal & (1 << LOCALITY))) return TPM_NOTLOCAL;
    }
  }
  /* ... then we reset all registers at once */
  for (i = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      memset(PCR_VALUE[i].digest, 0, sizeof(PCR_VALUE[i].digest));
    }
  }
  return TPM_SUCCESS;
}

TPM_RESULT tpm_compute_pcr_digest(TPM_PCR_SELECTION *pcrSelection, 
                                  TPM_COMPOSITE_HASH *digest, 
                                  TPM_PCR_COMPOSITE *composite)
{
  int i,j;
  TPM_PCR_COMPOSITE comp;
  tpm_sha1_ctx_t ctx;
  UINT32 len;
  BYTE *buf, *ptr;
  info("tpm_compute_pcr_digest()");
  /* create PCR composite */
  if ((pcrSelection->sizeOfSelect * 8) > TPM_NUM_PCR
      || pcrSelection->sizeOfSelect == 0) return TPM_INVALID_PCR_INFO;
  for (i = 0, j = 0; i < pcrSelection->sizeOfSelect * 8; i++) {
    /* is PCR number i selected ? */
    if (pcrSelection->pcrSelect[i >> 3] & (1 << (i & 7))) {
      memcpy(&comp.pcrValue[j++], &PCR_VALUE[i], sizeof(TPM_PCRVALUE));
    }
  }
  memcpy(&comp.select, pcrSelection, sizeof(TPM_PCR_SELECTION));
  comp.valueSize = j * sizeof(TPM_PCRVALUE);
  debug("comp.valueSize = %d", comp.valueSize);
  if (comp.valueSize > 0) {
    /* marshal composite and compute hash */
    len = sizeof_TPM_PCR_COMPOSITE(comp);
    buf = ptr = tpm_malloc(len);
    if (buf == NULL
        || tpm_marshal_TPM_PCR_COMPOSITE(&ptr, &len, &comp)) {
       tpm_free(buf);
       return TPM_FAIL;
    }
    tpm_sha1_init(&ctx);
    tpm_sha1_update(&ctx, buf, sizeof_TPM_PCR_COMPOSITE(comp));
    tpm_sha1_final(&ctx, digest->digest);
    tpm_free(buf);
  } else {
    memset(digest, 0, sizeof(TPM_COMPOSITE_HASH));
  }
  /* copy composite if requested */
  if (composite != NULL)
    memcpy(composite, &comp, sizeof(TPM_PCR_COMPOSITE));
  return TPM_SUCCESS;
}

TPM_RESULT tpm_verify_pcr(TPM_KEY_DATA *key, BOOL atrelease, BOOL atcreation)
{
  TPM_RESULT res;
  TPM_COMPOSITE_HASH digest;
  info("tpm_verify_pcr()");
  if (atrelease) {
    res = tpm_compute_pcr_digest(&key->pcrInfo.releasePCRSelection, 
                                 &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &key->pcrInfo.digestAtRelease, 
        sizeof(TPM_COMPOSITE_HASH))) return TPM_WRONGPCRVAL;
    if (key->pcrInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(key->pcrInfo.localityAtRelease
             & (1 << tpmData.stany.flags.localityModifier)))
      return TPM_BAD_LOCALITY;
  }
  if (atcreation) {
    res = tpm_compute_pcr_digest(&key->pcrInfo.creationPCRSelection, 
                                 &digest, NULL);
    if (res != TPM_SUCCESS) return res;
    if (memcmp(&digest, &key->pcrInfo.digestAtCreation, 
        sizeof(TPM_COMPOSITE_HASH))) return TPM_WRONGPCRVAL;
    if (key->pcrInfo.tag == TPM_TAG_PCR_INFO_LONG
        && !(key->pcrInfo.localityAtCreation
             & (1 << tpmData.stany.flags.localityModifier)))
      return TPM_BAD_LOCALITY;
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_Quote2(TPM_KEY_HANDLE keyHandle, TPM_NONCE *externalData,
                      TPM_PCR_SELECTION *targetPCR, BOOL addVersion,
                      TPM_AUTH *auth1, TPM_PCR_INFO_SHORT *pcrData,
                      UINT32 *versionInfoSize,
                      TPM_CAP_VERSION_INFO *versionInfo,
                      UINT32 *sigSize, BYTE **sig)
{
  TPM_RESULT res;
  TPM_KEY_DATA *key;
  TPM_COMPOSITE_HASH H1;
  TPM_QUOTE_INFO2 Q1;
  tpm_sha1_ctx_t ctx;
  TPM_DIGEST digest;
  UINT32 respSize, len, size;
  BYTE *resp, *ptr, *buf;

  info("TPM_Quote2()");
  /* get key by keyHandle*/
  key = tpm_get_key(keyHandle);
  if (key == NULL) return TPM_INVALID_KEYHANDLE;
  /* 1. The TPM MUST validate the AuthData to use the key pointed
   *    to by keyhandle */
  if (auth1->authHandle != TPM_INVALID_HANDLE
      || key->authDataUsage != TPM_AUTH_NEVER) {
    res = tpm_verify_auth(auth1, key->usageAuth, keyHandle);
    if (res != TPM_SUCCESS) return res;
  }
  /* 2. Validate that keyHandle->sigScheme is TPM_SS_RSASSAPKCS1v15_SHA1 or
        TPM_SS_RSASSAPKCS1v15_INFO, if not return TPM_INAPPROPRIATE_SIG. */
  if ((key->sigScheme != TPM_SS_RSASSAPKCS1v15_SHA1) &&
       (key->sigScheme != TPM_SS_RSASSAPKCS1v15_INFO))
    return TPM_INAPPROPRIATE_SIG;
  /* 3. Validate that keyHandle->keyUsage is TPM_KEY_SIGNING, TPM_KEY_IDENTITY,
        or TPM_KEY_LEGACY, if not return TPM_INVALID_KEYUSAGE */
  if ((key->keyUsage != TPM_KEY_SIGNING) && (key->keyUsage != TPM_KEY_LEGACY)
      && (key->keyUsage != TPM_KEY_IDENTITY))
    return TPM_INVALID_KEYUSAGE;
  /* 4. Validate targetPCR is a valid TPM_PCR_SELECTION structure,
   *    on errors return TPM_INVALID_PCR_INFO */
  if (targetPCR->sizeOfSelect > sizeof(targetPCR->pcrSelect))
    return TPM_INVALID_PCR_INFO;
  /* 5. Create H1 a SHA-1 hash of a TPM_PCR_COMPOSITE using the
   *    TPM_STCLEAR_DATA->PCR[] indicated by targetPCR->pcrSelect */
  res = tpm_compute_pcr_digest(targetPCR, &H1, NULL);
  if (res != TPM_SUCCESS) return res;
  /* 6. Create S1 a TPM_PCR_INFO_SHORT */
    /* a. Set S1->pcrSelection to targetPCR */
    pcrData->pcrSelection.sizeOfSelect = targetPCR->sizeOfSelect;
    memcpy(pcrData->pcrSelection.pcrSelect, targetPCR->pcrSelect, targetPCR->sizeOfSelect);
    /* b. Set S1->localityAtRelease to TPM_STANY_DATA -> localityModifier */
    pcrData->localityAtRelease = 1 << tpmData.stany.flags.localityModifier;
    /* c. Set S1->digestAtRelease to H1 */
    memcpy(&pcrData->digestAtRelease, &H1, sizeof(TPM_COMPOSITE_HASH));
  /* 7. Create Q1 a TPM_QUOTE_INFO2 structure */
  Q1.tag = TPM_TAG_QUOTE_INFO2;
    /* a. Set Q1->fixed to "QUT2" */
    Q1.fixed[0] = 'Q', Q1.fixed[1] = 'U', Q1.fixed[2] = 'T', Q1.fixed[3] = '2';
    /* b. Set Q1->infoShort to S1 */
    Q1.infoShort.pcrSelection.sizeOfSelect = pcrData->pcrSelection.sizeOfSelect;
    memcpy(Q1.infoShort.pcrSelection.pcrSelect,
      pcrData->pcrSelection.pcrSelect, pcrData->pcrSelection.sizeOfSelect);
    Q1.infoShort.localityAtRelease = pcrData->localityAtRelease;
    memcpy(Q1.infoShort.digestAtRelease.digest,
      pcrData->digestAtRelease.digest, sizeof(TPM_COMPOSITE_HASH));
    /* c. Set Q1->externalData to externalData */
    memcpy(&Q1.externalData, externalData, sizeof(TPM_NONCE));
  size = len = sizeof_TPM_QUOTE_INFO2(Q1);
  buf = ptr = tpm_malloc(size);
  if (buf == NULL) return TPM_NOSPACE;
  if (tpm_marshal_TPM_QUOTE_INFO2(&ptr, &len, &Q1) || (len != 0)) {
    debug("TPM_Quote2(): tpm_marshal_TPM_QUOTE_INFO2() failed.");
    tpm_free(buf);
    return TPM_FAIL;
  }
  /* 8. If addVersion is TRUE */
  if (addVersion == TRUE) {
    debug("TPM_Quote2(): addVersion == TRUE");
    /* a. Concatenate to Q1 a TPM_CAP_VERSION_INFO structure */
    res = TPM_GetCapability(TPM_CAP_VERSION_VAL, 0, NULL, &respSize, &resp);
    if (res != TPM_SUCCESS) {
      debug("TPM_Quote2(): cap_version_val() failed.");
      tpm_free(buf);
      return TPM_FAIL;
    }
    /* b. Set the output parameters for versionInfo */
    ptr = resp;
    len = respSize;
    if (tpm_unmarshal_TPM_CAP_VERSION_INFO(&ptr, &len, versionInfo) ||
      (len != 0)) {
        debug("TPM_Quote2(): tpm_unmarshal_TPM_CAP_VERSION_INFO() failed.");
        tpm_free(buf);
        return TPM_FAIL;
    }
    *versionInfoSize = respSize;
   } else { /* 9. Else */
    debug("TPM_Quote2(): addVersion == FALSE");
    /* a. Set versionInfoSize to 0 */
    *versionInfoSize = 0;
    /* b. Return no bytes in versionInfo */
  }
  /* 10. Sign a SHA-1 hash of Q1 using keyHandle as the signature key */
  tpm_sha1_init(&ctx);
  tpm_sha1_update(&ctx, buf, size);
  tpm_free(buf);
  if (addVersion == TRUE) {
    tpm_sha1_update(&ctx, resp, respSize);
    tpm_free(resp);
  }
  tpm_sha1_final(&ctx, digest.digest);
  /* 11. Return the signature in sig */
  return tpm_sign(key, auth1, FALSE, digest.digest, sizeof(TPM_DIGEST), sig, sigSize);
}

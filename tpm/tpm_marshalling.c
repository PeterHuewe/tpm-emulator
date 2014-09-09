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
 * $Id: tpm_marshalling.c 372 2010-02-15 12:52:00Z mast $
 */

#include "tpm_marshalling.h"
#include "tpm_handles.h"
#include "crypto/rsa.h"

int tpm_marshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length,
                             UINT32 *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tpm_marshal_UINT32(ptr, length, v[i])) return -1;
  }
  return 0;
}

int tpm_unmarshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length,
                               UINT32 *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tpm_unmarshal_UINT32(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tpm_marshal_TPM_STRUCT_VER(BYTE **ptr, UINT32 *length, TPM_STRUCT_VER *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->major)
      || tpm_marshal_BYTE(ptr, length, v->minor)
      || tpm_marshal_BYTE(ptr, length, v->revMajor)
      || tpm_marshal_BYTE(ptr, length, v->revMinor)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STRUCT_VER(BYTE **ptr, UINT32 *length, TPM_STRUCT_VER *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->major)
      || tpm_unmarshal_BYTE(ptr, length, &v->minor)
      || tpm_unmarshal_BYTE(ptr, length, &v->revMajor)
      || tpm_unmarshal_BYTE(ptr, length, &v->revMinor)) return -1;
  return 0;
}

int tpm_marshal_TPM_VERSION(BYTE **ptr, UINT32 *length, TPM_VERSION *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->major)
      || tpm_marshal_BYTE(ptr, length, v->minor)
      || tpm_marshal_BYTE(ptr, length, v->revMajor)
      || tpm_marshal_BYTE(ptr, length, v->revMinor)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_VERSION(BYTE **ptr, UINT32 *length, TPM_VERSION *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->major)
      || tpm_unmarshal_BYTE(ptr, length, &v->minor)
      || tpm_unmarshal_BYTE(ptr, length, &v->revMajor)
      || tpm_unmarshal_BYTE(ptr, length, &v->revMinor)) return -1;
  return 0;
}

int tpm_marshal_TPM_DIGEST(BYTE **ptr, UINT32 *length, TPM_DIGEST *v)
{
  if (tpm_marshal_BYTE_ARRAY(ptr, length, v->digest, sizeof(v->digest))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DIGEST(BYTE **ptr, UINT32 *length, TPM_DIGEST *v)
{
  if (tpm_unmarshal_BYTE_ARRAY(ptr, length, v->digest, sizeof(v->digest))) return -1;
  return 0;
}

int tpm_marshal_TPM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length,
                                   TPM_PCRVALUE *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tpm_marshal_TPM_PCRVALUE(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length,
                                     TPM_PCRVALUE *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tpm_unmarshal_TPM_PCRVALUE(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tpm_marshal_TPM_NONCE(BYTE **ptr, UINT32 *length, TPM_NONCE *v)
{
  if (tpm_marshal_BYTE_ARRAY(ptr, length, v->nonce, sizeof(v->nonce))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_NONCE(BYTE **ptr, UINT32 *length, TPM_NONCE *v)
{
  if (tpm_unmarshal_BYTE_ARRAY(ptr, length, v->nonce, sizeof(v->nonce))) return -1;
  return 0;
}

int tpm_marshal_TPM_AUTHDATA(BYTE **ptr, UINT32 *length, TPM_AUTHDATA *v)
{
  if (*length < sizeof(TPM_AUTHDATA)) return -1;
  memcpy(*ptr, v, sizeof(TPM_AUTHDATA));
  *ptr += sizeof(TPM_AUTHDATA); *length -= sizeof(TPM_AUTHDATA);
  return 0;
}

int tpm_unmarshal_TPM_AUTHDATA(BYTE **ptr, UINT32 *length, TPM_AUTHDATA *v)
{
  if (*length < sizeof(TPM_AUTHDATA)) return -1;
  memcpy(v, *ptr, sizeof(TPM_AUTHDATA));
  *ptr += sizeof(TPM_AUTHDATA); *length -= sizeof(TPM_AUTHDATA);
  return 0;
}

int tpm_marshal_TPM_AUTH(BYTE **ptr, UINT32 *length, TPM_AUTH *v)
{
  if (tpm_marshal_TPM_NONCE(ptr, length, &v->nonceEven)
      || tpm_marshal_BOOL(ptr, length, v->continueAuthSession)
      || tpm_marshal_TPM_AUTHDATA(ptr, length, &v->auth)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_AUTH(BYTE **ptr, UINT32 *length, TPM_AUTH *v)
{
  if (tpm_unmarshal_TPM_AUTHHANDLE(ptr, length, &v->authHandle)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->nonceOdd)
      || tpm_unmarshal_BOOL(ptr, length, &v->continueAuthSession)
      || tpm_unmarshal_TPM_AUTHDATA(ptr, length, &v->auth)) return -1;
  return 0;
}

int tpm_marshal_TPM_KEY_HANDLE_LIST(BYTE **ptr, UINT32 *length, TPM_KEY_HANDLE_LIST *v)
{
  if (tpm_marshal_UINT16(ptr, length, v->loaded)
      || tpm_marshal_UINT32_ARRAY(ptr, length, v->handle, v->loaded)) return -1;
  return 0;
}

int tpm_marshal_TPM_CHANGEAUTH_VALIDATE(BYTE **ptr, UINT32 *length, TPM_CHANGEAUTH_VALIDATE *v)
{
  if (tpm_marshal_TPM_SECRET(ptr, length, &v->newAuthSecret)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->n1)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_CHANGEAUTH_VALIDATE(BYTE **ptr, UINT32 *length, TPM_CHANGEAUTH_VALIDATE *v)
{
  if (tpm_unmarshal_TPM_SECRET(ptr, length, &v->newAuthSecret)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->n1)) return -1;
  return 0;
}

int tpm_marshal_TPM_COUNTER_VALUE(BYTE **ptr, UINT32 *length, TPM_COUNTER_VALUE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->label, sizeof(v->label))
      || tpm_marshal_TPM_ACTUAL_COUNT(ptr, length, v->counter)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_COUNTER_VALUE(BYTE **ptr, UINT32 *length, TPM_COUNTER_VALUE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->label, sizeof(v->label))
      || tpm_unmarshal_TPM_ACTUAL_COUNT(ptr, length, &v->counter)) return -1;
  return 0;
}

int tpm_marshal_TPM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TPM_PCR_SELECTION *v)
{
  if (tpm_marshal_UINT16(ptr, length, v->sizeOfSelect)
      || v->sizeOfSelect > sizeof(v->pcrSelect) 
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->pcrSelect, v->sizeOfSelect)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TPM_PCR_SELECTION *v)
{
  if (tpm_unmarshal_UINT16(ptr, length, &v->sizeOfSelect)
      || v->sizeOfSelect > sizeof(v->pcrSelect)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->pcrSelect, v->sizeOfSelect)) return -1;
  return 0;
}

int tpm_marshal_TPM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_PCR_COMPOSITE *v)
{
  if (tpm_marshal_TPM_PCR_SELECTION(ptr, length, &v->select)
      || tpm_marshal_UINT32(ptr, length, v->valueSize)
      || v->valueSize > sizeof(v->pcrValue) 
      || tpm_marshal_TPM_PCRVALUE_ARRAY(ptr, length, v->pcrValue, 
                                        v->valueSize / sizeof(TPM_PCRVALUE))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_PCR_COMPOSITE *v)
{
  if (tpm_unmarshal_TPM_PCR_SELECTION(ptr, length, &v->select)
      || tpm_unmarshal_UINT32(ptr, length, &v->valueSize)
      || v->valueSize > sizeof(v->pcrValue)
      || tpm_unmarshal_TPM_PCRVALUE_ARRAY(ptr, length, v->pcrValue, 
                                          v->valueSize / sizeof(TPM_PCRVALUE))) return -1;
  return 0;
}

int tpm_marshal_TPM_PCR_INFO(BYTE **ptr, UINT32 *length, TPM_PCR_INFO *v)
{
  if (v->tag == TPM_TAG_PCR_INFO_LONG) {
    if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
        || tpm_marshal_TPM_LOCALITY_SELECTION(ptr, length, v->localityAtCreation)
        || tpm_marshal_TPM_LOCALITY_SELECTION(ptr, length, v->localityAtRelease)
        || tpm_marshal_TPM_PCR_SELECTION(ptr, length, &v->creationPCRSelection)
        || tpm_marshal_TPM_PCR_SELECTION(ptr, length, &v->releasePCRSelection)
        || tpm_marshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtCreation)
        || tpm_marshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)) return -1;
  } else {
    if (tpm_marshal_TPM_PCR_SELECTION(ptr, length, &v->creationPCRSelection)
      || tpm_marshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)
      || tpm_marshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtCreation)) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_PCR_INFO(BYTE **ptr, UINT32 *length, TPM_PCR_INFO *v)
{
  if ((((UINT16)(*ptr)[0] << 8) | (*ptr)[1]) == TPM_TAG_PCR_INFO_LONG) {
    if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
        || tpm_unmarshal_TPM_LOCALITY_SELECTION(ptr, length, &v->localityAtCreation)
        || tpm_unmarshal_TPM_LOCALITY_SELECTION(ptr, length, &v->localityAtRelease)
        || tpm_unmarshal_TPM_PCR_SELECTION(ptr, length, &v->creationPCRSelection)
        || tpm_unmarshal_TPM_PCR_SELECTION(ptr, length, &v->releasePCRSelection)
        || tpm_unmarshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtCreation)
        || tpm_unmarshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)) return -1;
  } else {
    if (tpm_unmarshal_TPM_PCR_SELECTION(ptr, length, &v->creationPCRSelection)
      || tpm_unmarshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)
      || tpm_unmarshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtCreation)) return -1;
    memcpy(&v->releasePCRSelection, &v->creationPCRSelection, sizeof(TPM_PCR_SELECTION));
    v->tag = 0x0000;
    v->localityAtCreation = 0;
    v->localityAtRelease = 0;
  }
  return 0;
}

int tpm_marshal_TPM_PCR_INFO_SHORT(BYTE **ptr, UINT32 *length, TPM_PCR_INFO_SHORT *v)
{
  if (tpm_marshal_TPM_PCR_SELECTION(ptr, length, &v->pcrSelection)
      || tpm_marshal_TPM_LOCALITY_SELECTION(ptr, length, v->localityAtRelease)
      || tpm_marshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PCR_INFO_SHORT(BYTE **ptr, UINT32 *length, TPM_PCR_INFO_SHORT *v)
{
  if (tpm_unmarshal_TPM_PCR_SELECTION(ptr, length, &v->pcrSelection)
      || tpm_unmarshal_TPM_LOCALITY_SELECTION(ptr, length, &v->localityAtRelease)
      || tpm_unmarshal_TPM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)) return -1;
  return 0;
}

int tpm_marshal_TPM_PCR_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_PCR_ATTRIBUTES *v)
{
  if (tpm_marshal_BOOL(ptr, length, v->pcrReset)
      || tpm_marshal_TPM_LOCALITY_SELECTION(ptr, length, v->pcrResetLocal)
      || tpm_marshal_TPM_LOCALITY_SELECTION(ptr, length, v->pcrExtendLocal)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PCR_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_PCR_ATTRIBUTES *v)
{
  if (tpm_unmarshal_BOOL(ptr, length, &v->pcrReset)
      || tpm_unmarshal_TPM_LOCALITY_SELECTION(ptr, length, &v->pcrResetLocal)
      || tpm_unmarshal_TPM_LOCALITY_SELECTION(ptr, length, &v->pcrExtendLocal)) return -1;
  return 0;
}

int tpm_marshal_TPM_STORED_DATA(BYTE **ptr, UINT32 *length, TPM_STORED_DATA *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_ENTITY_TYPE(ptr, length, v->et)
      || tpm_marshal_UINT32(ptr, length, v->sealInfoSize)
      || (v->sealInfoSize > 0
          && tpm_marshal_TPM_PCR_INFO(ptr, length, &v->sealInfo))
      || tpm_marshal_UINT32(ptr, length, v->encDataSize)
      || tpm_marshal_BLOB(ptr, length, v->encData, v->encDataSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STORED_DATA(BYTE **ptr, UINT32 *length, TPM_STORED_DATA *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_ENTITY_TYPE(ptr, length, &v->et)
      || tpm_unmarshal_UINT32(ptr, length, &v->sealInfoSize)
      || (v->sealInfoSize > 0
          && tpm_unmarshal_TPM_PCR_INFO(ptr, length, &v->sealInfo))
      || tpm_unmarshal_UINT32(ptr, length, &v->encDataSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->encData, v->encDataSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_SEALED_DATA(BYTE **ptr, UINT32 *length, TPM_SEALED_DATA *v)
{
  if (tpm_marshal_TPM_PAYLOAD_TYPE(ptr, length, v->payload)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->authData)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->tpmProof)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->storedDigest)
      || tpm_marshal_UINT32(ptr, length, v->dataSize)
      || tpm_marshal_BLOB(ptr, length, v->data, v->dataSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_SEALED_DATA(BYTE **ptr, UINT32 *length, TPM_SEALED_DATA *v)
{
  if (tpm_unmarshal_TPM_PAYLOAD_TYPE(ptr, length, &v->payload)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->authData)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->tpmProof)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->storedDigest)
      || tpm_unmarshal_UINT32(ptr, length, &v->dataSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->data, v->dataSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY *v)
{
  if (tpm_marshal_TPM_ALGORITHM_ID(ptr, length, v->algId)
      || tpm_marshal_TPM_ENC_SCHEME(ptr, length, v->encScheme)
      || tpm_marshal_UINT16(ptr, length, v->size)
      || tpm_marshal_BLOB(ptr, length, v->data, v->size)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY *v)
{
  if (tpm_unmarshal_TPM_ALGORITHM_ID(ptr, length, &v->algId)
      || tpm_unmarshal_TPM_ENC_SCHEME(ptr, length, &v->encScheme)
      || tpm_unmarshal_UINT16(ptr, length, &v->size)
      || tpm_unmarshal_BLOB(ptr, length, &v->data, v->size)) return -1;
  return 0;
}

int tpm_marshal_TPM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY_PARMS *v)
{
  if (tpm_marshal_UINT32(ptr, length, v->keyLength)
      || tpm_marshal_UINT32(ptr, length, v->blockSize)
      || tpm_marshal_UINT32(ptr, length, v->ivSize)
      || tpm_marshal_BLOB(ptr, length, v->IV, v->ivSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY_PARMS *v)
{
  if (tpm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tpm_unmarshal_UINT32(ptr, length, &v->blockSize)
      || tpm_unmarshal_UINT32(ptr, length, &v->ivSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->IV, v->ivSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_RSA_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_RSA_KEY_PARMS *v)
{
  if (tpm_marshal_UINT32(ptr, length, v->keyLength)
      || tpm_marshal_UINT32(ptr, length, v->numPrimes)
      || tpm_marshal_UINT32(ptr, length, v->exponentSize)
      || tpm_marshal_BLOB(ptr, length, v->exponent, v->exponentSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_RSA_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_RSA_KEY_PARMS *v)
{
  if (tpm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tpm_unmarshal_UINT32(ptr, length, &v->numPrimes)
      || tpm_unmarshal_UINT32(ptr, length, &v->exponentSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->exponent, v->exponentSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_KEY_PARMS *v)
{
  if (tpm_marshal_TPM_ALGORITHM_ID(ptr, length, v->algorithmID)
      || tpm_marshal_TPM_ENC_SCHEME(ptr, length, v->encScheme)
      || tpm_marshal_TPM_SIG_SCHEME(ptr, length, v->sigScheme)
      || tpm_marshal_UINT32(ptr, length, v->parmSize)) return -1;
  switch (v->algorithmID) {
    case TPM_ALG_RSA:
      if (tpm_marshal_TPM_RSA_KEY_PARMS(ptr, length, &v->parms.rsa)) return -1;
      break;
    case TPM_ALG_DES: case TPM_ALG_3DES: case TPM_ALG_AES192: case TPM_ALG_AES256:
      if (tpm_marshal_TPM_SYMMETRIC_KEY_PARMS(ptr, length, &v->parms.skp)) return -1;
      break;
    default:
      if (tpm_marshal_BLOB(ptr, length, v->parms.raw, v->parmSize)) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_KEY_PARMS *v)
{
  if (tpm_unmarshal_TPM_ALGORITHM_ID(ptr, length, &v->algorithmID)
      || tpm_unmarshal_TPM_ENC_SCHEME(ptr, length, &v->encScheme)
      || tpm_unmarshal_TPM_SIG_SCHEME(ptr, length, &v->sigScheme)
      || tpm_unmarshal_UINT32(ptr, length, &v->parmSize)) return -1;
  switch (v->algorithmID) {
    case TPM_ALG_RSA:
      if (tpm_unmarshal_TPM_RSA_KEY_PARMS(ptr, length, &v->parms.rsa)) return -1;
      break;
    case TPM_ALG_DES: case TPM_ALG_3DES: case TPM_ALG_AES192: case TPM_ALG_AES256:
      if (tpm_unmarshal_TPM_SYMMETRIC_KEY_PARMS(ptr, length, &v->parms.skp)) return -1;
      break;
    default:
      if (tpm_unmarshal_BLOB(ptr, length, &v->parms.raw, v->parmSize)) return -1;
  }
  return 0;
}

int tpm_marshal_TPM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PUBKEY *v)
{
  if (tpm_marshal_UINT32(ptr, length, v->keyLength)
      || tpm_marshal_BLOB(ptr, length, v->key, v->keyLength)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PUBKEY *v)
{
  if (tpm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tpm_unmarshal_BLOB(ptr, length, &v->key, v->keyLength)) return -1;
  return 0;
}

int tpm_marshal_TPM_KEY(BYTE **ptr, UINT32 *length, TPM_KEY *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT16(ptr, length, v->fill)
      || tpm_marshal_TPM_KEY_USAGE(ptr, length, v->keyUsage)
      || tpm_marshal_TPM_KEY_FLAGS(ptr, length, v->keyFlags)
      || tpm_marshal_TPM_AUTH_DATA_USAGE(ptr, length, v->authDataUsage)
      || tpm_marshal_TPM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tpm_marshal_UINT32(ptr, length, v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tpm_marshal_TPM_PCR_INFO(ptr, length, &v->PCRInfo))
      || tpm_marshal_TPM_STORE_PUBKEY(ptr, length, &v->pubKey)
      || tpm_marshal_UINT32(ptr, length, v->encDataSize)
      || tpm_marshal_BLOB(ptr, length, v->encData, v->encDataSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_KEY(BYTE **ptr, UINT32 *length, TPM_KEY *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT16(ptr, length, &v->fill)
      || tpm_unmarshal_TPM_KEY_USAGE(ptr, length, &v->keyUsage)
      || tpm_unmarshal_TPM_KEY_FLAGS(ptr, length, &v->keyFlags)
      || tpm_unmarshal_TPM_AUTH_DATA_USAGE(ptr, length, &v->authDataUsage)
      || tpm_unmarshal_TPM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tpm_unmarshal_UINT32(ptr, length, &v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tpm_unmarshal_TPM_PCR_INFO(ptr, length, &v->PCRInfo))
      || tpm_unmarshal_TPM_STORE_PUBKEY(ptr, length, &v->pubKey)
      || tpm_unmarshal_UINT32(ptr, length, &v->encDataSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->encData, v->encDataSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_PUBKEY(BYTE **ptr, UINT32 *length, TPM_PUBKEY *v)
{
  if (tpm_marshal_TPM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tpm_marshal_TPM_STORE_PUBKEY(ptr, length, &v->pubKey)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PUBKEY(BYTE **ptr, UINT32 *length, TPM_PUBKEY *v)
{
  if (tpm_unmarshal_TPM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tpm_unmarshal_TPM_STORE_PUBKEY(ptr, length, &v->pubKey)) return -1;
  return 0;
}

int tpm_marshal_TPM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PRIVKEY *v)
{
  if (tpm_marshal_UINT32(ptr, length, v->keyLength)
      || tpm_marshal_BLOB(ptr, length, v->key, v->keyLength)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PRIVKEY *v)
{
  if (tpm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tpm_unmarshal_BLOB(ptr, length, &v->key, v->keyLength)) return -1;
  return 0;
}

int tpm_marshal_TPM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TPM_STORE_ASYMKEY *v)
{
  if (tpm_marshal_TPM_PAYLOAD_TYPE(ptr, length, v->payload)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->usageAuth)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->migrationAuth)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->pubDataDigest)
      || tpm_marshal_TPM_STORE_PRIVKEY(ptr, length, &v->privKey)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TPM_STORE_ASYMKEY *v)
{
  if (tpm_unmarshal_TPM_PAYLOAD_TYPE(ptr, length, &v->payload)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->usageAuth)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->migrationAuth)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->pubDataDigest)
      || tpm_unmarshal_TPM_STORE_PRIVKEY(ptr, length, &v->privKey)) return -1;
  return 0;
}

int tpm_marshal_TPM_MIGRATIONKEYAUTH(BYTE **ptr, UINT32 *length, TPM_MIGRATIONKEYAUTH *v)
{
  if (tpm_marshal_TPM_PUBKEY(ptr, length, &v->migrationKey)
      || tpm_marshal_TPM_MIGRATE_SCHEME(ptr, length, v->migrationScheme)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->digest)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_MIGRATIONKEYAUTH(BYTE **ptr, UINT32 *length, TPM_MIGRATIONKEYAUTH *v)
{
  if (tpm_unmarshal_TPM_PUBKEY(ptr, length, &v->migrationKey)
      || tpm_unmarshal_TPM_MIGRATE_SCHEME(ptr, length, &v->migrationScheme)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->digest)) return -1;
  return 0;
}

int tpm_marshal_TPM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TPM_CERTIFY_INFO *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BYTE(ptr, length, v->fill)
      || tpm_marshal_TPM_PAYLOAD_TYPE(ptr, length, v->payloadType)
      || tpm_marshal_TPM_KEY_USAGE(ptr, length, v->keyUsage)
      || tpm_marshal_TPM_KEY_FLAGS(ptr, length, v->keyFlags)
      || tpm_marshal_TPM_AUTH_DATA_USAGE(ptr, length, v->authDataUsage)
      || tpm_marshal_TPM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->pubkeyDigest)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->data)
      || tpm_marshal_BOOL(ptr, length, v->parentPCRStatus)
      || tpm_marshal_UINT32(ptr, length, v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tpm_marshal_TPM_PCR_INFO(ptr, length, &v->PCRInfo))
      || (v->tag == TPM_TAG_CERTIFY_INFO2
          && tpm_marshal_UINT32(ptr, length, v->migrationAuthoritySize))
      || (v->tag == TPM_TAG_CERTIFY_INFO2 && v->migrationAuthoritySize > 0
          && tpm_marshal_BLOB(ptr, length, v->migrationAuthority,
                              v->migrationAuthoritySize))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TPM_CERTIFY_INFO *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BYTE(ptr, length, &v->fill)
      || tpm_unmarshal_TPM_PAYLOAD_TYPE(ptr, length, &v->payloadType)
      || tpm_unmarshal_TPM_KEY_USAGE(ptr, length, &v->keyUsage)
      || tpm_unmarshal_TPM_KEY_FLAGS(ptr, length, &v->keyFlags)
      || tpm_unmarshal_TPM_AUTH_DATA_USAGE(ptr, length, &v->authDataUsage)
      || tpm_unmarshal_TPM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->pubkeyDigest)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->data)
      || tpm_unmarshal_BOOL(ptr, length, &v->parentPCRStatus)
      || tpm_unmarshal_UINT32(ptr, length, &v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tpm_unmarshal_TPM_PCR_INFO(ptr, length, &v->PCRInfo))
      || (!(v->migrationAuthoritySize = 0) && v->tag == TPM_TAG_CERTIFY_INFO2
          && tpm_unmarshal_UINT32(ptr, length, &v->migrationAuthoritySize))
      || (v->tag == TPM_TAG_CERTIFY_INFO2 && v->migrationAuthoritySize > 0
          && tpm_unmarshal_BLOB(ptr, length, &v->migrationAuthority,
                                v->migrationAuthoritySize))) return -1;
  return 0;
}

int tpm_marshal_TPM_IDENTITY_CONTENTS(BYTE **ptr, UINT32 *length, TPM_IDENTITY_CONTENTS *v)
{
  if (tpm_marshal_TPM_STRUCT_VER(ptr, length, &v->ver)
      || tpm_marshal_UINT32(ptr, length, v->ordinal)
      || tpm_marshal_TPM_CHOSENID_HASH(ptr, length, &v->labelPrivCADigest)
      || tpm_marshal_TPM_PUBKEY(ptr, length, &v->identityPubKey)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_IDENTITY_CONTENTS(BYTE **ptr, UINT32 *length, TPM_IDENTITY_CONTENTS *v)
{
  if (tpm_unmarshal_TPM_STRUCT_VER(ptr, length, &v->ver)
      || tpm_unmarshal_UINT32(ptr, length, &v->ordinal)
      || tpm_unmarshal_TPM_CHOSENID_HASH(ptr, length, &v->labelPrivCADigest)
      || tpm_unmarshal_TPM_PUBKEY(ptr, length, &v->identityPubKey)) return -1;
  return 0;
}

int tpm_marshal_TPM_CURRENT_TICKS(BYTE **ptr, UINT32 *length, TPM_CURRENT_TICKS *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT64(ptr, length, v->currentTicks)
      || tpm_marshal_UINT16(ptr, length, v->tickRate)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->tickNonce)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_CURRENT_TICKS(BYTE **ptr, UINT32 *length, TPM_CURRENT_TICKS *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT64(ptr, length, &v->currentTicks)
      || tpm_unmarshal_UINT16(ptr, length, &v->tickRate)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->tickNonce)) return -1;
  return 0;
}

int tpm_marshal_TPM_TRANSPORT_PUBLIC(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_PUBLIC *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_TRANSPORT_ATTRIBUTES(ptr, length, v->transAttributes)
      || tpm_marshal_TPM_ALGORITHM_ID(ptr, length, v->algID)
      || tpm_marshal_TPM_ENC_SCHEME(ptr, length, v->encScheme)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_TRANSPORT_PUBLIC(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_PUBLIC *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_TRANSPORT_ATTRIBUTES(ptr, length, &v->transAttributes)
      || tpm_unmarshal_TPM_ALGORITHM_ID(ptr, length, &v->algID)
      || tpm_unmarshal_TPM_ENC_SCHEME(ptr, length, &v->encScheme)) return -1;
  return 0;
}

int tpm_marshal_TPM_TRANSPORT_INTERNAL(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_INTERNAL *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_AUTHDATA(ptr, length, &v->authData)
      || tpm_marshal_TPM_TRANSPORT_PUBLIC(ptr, length, &v->transPublic)
      || tpm_marshal_TPM_TRANSHANDLE(ptr, length, v->transHandle)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->transNonceEven)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->transDigest)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_TRANSPORT_INTERNAL(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_INTERNAL *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_AUTHDATA(ptr, length, &v->authData)
      || tpm_unmarshal_TPM_TRANSPORT_PUBLIC(ptr, length, &v->transPublic)
      || tpm_unmarshal_TPM_TRANSHANDLE(ptr, length, &v->transHandle)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->transNonceEven)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->transDigest)) return -1;
  return 0;
}

int tpm_marshal_TPM_CONTEXT_BLOB(BYTE **ptr, UINT32 *length, TPM_CONTEXT_BLOB *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_RESOURCE_TYPE(ptr, length, v->resourceType)
      || tpm_marshal_TPM_HANDLE(ptr, length, v->handle)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->label, sizeof(v->label))
      || tpm_marshal_UINT32(ptr, length, v->contextCount)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->integrityDigest)
      || tpm_marshal_UINT32(ptr, length, v->additionalSize)
      || tpm_marshal_BLOB(ptr, length, v->additionalData, v->additionalSize)
      || tpm_marshal_UINT32(ptr, length, v->sensitiveSize)
      || tpm_marshal_BLOB(ptr, length, v->sensitiveData, v->sensitiveSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_CONTEXT_BLOB(BYTE **ptr, UINT32 *length, TPM_CONTEXT_BLOB *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_RESOURCE_TYPE(ptr, length, &v->resourceType)
      || tpm_unmarshal_TPM_HANDLE(ptr, length, &v->handle)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->label, sizeof(v->label))
      || tpm_unmarshal_UINT32(ptr, length, &v->contextCount)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->integrityDigest)
      || tpm_unmarshal_UINT32(ptr, length, &v->additionalSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->additionalData, v->additionalSize)
      || tpm_unmarshal_UINT32(ptr, length, &v->sensitiveSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->sensitiveData, v->sensitiveSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_CONTEXT_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_CONTEXT_SENSITIVE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->contextNonce)
      || tpm_marshal_UINT32(ptr, length, v->internalSize)
      || tpm_marshal_TPM_RESOURCE_TYPE(ptr, length, v->resourceType))
        return -1;
  switch (v->resourceType) {
    case TPM_RT_KEY:
      if (tpm_marshal_TPM_KEY_DATA(ptr, length, &v->internalData.key))
        return -1;
      break;
    case TPM_RT_AUTH:
    case TPM_RT_TRANS:
      if (tpm_marshal_TPM_SESSION_DATA(ptr, length, &v->internalData.session))
        return -1;
      break;
    case TPM_RT_DAA_TPM:
      if (tpm_marshal_TPM_DAA_SESSION_DATA(ptr, length, &v->internalData.sessionDAA))
        return -1;
      break;
    default:
      return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_CONTEXT_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_CONTEXT_SENSITIVE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->contextNonce)
      || tpm_unmarshal_UINT32(ptr, length, &v->internalSize)
      || tpm_unmarshal_TPM_RESOURCE_TYPE(ptr, length, &v->resourceType))
        return -1;
  switch (v->resourceType) {
    case TPM_RT_KEY:
      if (tpm_unmarshal_TPM_KEY_DATA(ptr, length, &v->internalData.key))
        return -1;
      break;
    case TPM_RT_AUTH:
    case TPM_RT_TRANS:
      if (tpm_unmarshal_TPM_SESSION_DATA(ptr, length, &v->internalData.session))
        return -1;
      break;
    case TPM_RT_DAA_TPM:
      if (tpm_unmarshal_TPM_DAA_SESSION_DATA(ptr, length, &v->internalData.sessionDAA))
        return -1;
      break;
    default:
      return -1;
  }
  return 0;
}

int tpm_marshal_TPM_DAA_BLOB(BYTE **ptr, UINT32 *length, TPM_DAA_BLOB *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_RESOURCE_TYPE(ptr, length, v->resourceType)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->label, sizeof(v->label))
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->blobIntegrity)
      || tpm_marshal_UINT32(ptr, length, v->additionalSize)
      || tpm_marshal_BLOB(ptr, length, v->additionalData, v->additionalSize)
      || tpm_marshal_UINT32(ptr, length, v->sensitiveSize)
      || tpm_marshal_BLOB(ptr, length, v->sensitiveData, v->sensitiveSize))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_BLOB(BYTE **ptr, UINT32 *length, TPM_DAA_BLOB *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_RESOURCE_TYPE(ptr, length, &v->resourceType)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->label, sizeof(v->label))
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->blobIntegrity)
      || tpm_unmarshal_UINT32(ptr, length, &v->additionalSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->additionalData, v->additionalSize)
      || tpm_unmarshal_UINT32(ptr, length, &v->sensitiveSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->sensitiveData, v->sensitiveSize))
        return -1;
  return 0;
}

int tpm_marshal_TPM_DAA_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DAA_SENSITIVE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT32(ptr, length, v->internalSize)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->internalData, v->internalSize))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DAA_SENSITIVE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT32(ptr, length, &v->internalSize)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->internalData, v->internalSize))
        return -1;
  return 0;
}

int tpm_marshal_TPM_DAA_ISSUER(BYTE **ptr, UINT32 *length, TPM_DAA_ISSUER *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_R0)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_R1)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_S0)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_S1)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_n)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_gamma)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->DAA_generic_q, sizeof(v->DAA_generic_q)))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_ISSUER(BYTE **ptr, UINT32 *length, TPM_DAA_ISSUER *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_R0)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_R1)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_S0)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_S1)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_n)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_gamma)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->DAA_generic_q, sizeof(v->DAA_generic_q)))
        return -1;
  return 0;
}

int tpm_marshal_TPM_DAA_TPM(BYTE **ptr, UINT32 *length, TPM_DAA_TPM *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digestIssuer)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_v0)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_v1)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_rekey)
      || tpm_marshal_UINT32(ptr, length, v->DAA_count))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_TPM(BYTE **ptr, UINT32 *length, TPM_DAA_TPM *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digestIssuer)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_v0)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_v1)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_rekey)
      || tpm_unmarshal_UINT32(ptr, length, &v->DAA_count))
        return -1;
  return 0;
}

int tpm_marshal_TPM_DAA_CONTEXT(BYTE **ptr, UINT32 *length, TPM_DAA_CONTEXT *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digestContext)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->DAA_contextSeed)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->DAA_scratch, sizeof(v->DAA_scratch))
      || tpm_marshal_BYTE(ptr, length, v->DAA_stage))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_CONTEXT(BYTE **ptr, UINT32 *length, TPM_DAA_CONTEXT *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digestContext)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->DAA_contextSeed)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->DAA_scratch, sizeof(v->DAA_scratch))
      || tpm_unmarshal_BYTE(ptr, length, &v->DAA_stage))
        return -1;
  return 0;
}

int tpm_marshal_TPM_DAA_JOINDATA(BYTE **ptr, UINT32 *length, TPM_DAA_JOINDATA *v)
{
  if (tpm_marshal_BYTE_ARRAY(ptr, length, v->DAA_join_u0, sizeof(v->DAA_join_u0))
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->DAA_join_u1, sizeof(v->DAA_join_u1))
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->DAA_digest_n0))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_JOINDATA(BYTE **ptr, UINT32 *length, TPM_DAA_JOINDATA *v)
{
  if (tpm_unmarshal_BYTE_ARRAY(ptr, length, v->DAA_join_u0, sizeof(v->DAA_join_u0))
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->DAA_join_u1, sizeof(v->DAA_join_u1))
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->DAA_digest_n0))
        return -1;
  return 0;
}

int tpm_marshal_TPM_DAA_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_DAA_SESSION_DATA *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->type)
      || tpm_marshal_TPM_DAA_ISSUER(ptr, length, &v->DAA_issuerSettings)
      || tpm_marshal_TPM_DAA_TPM(ptr, length, &v->DAA_tpmSpecific)
      || tpm_marshal_TPM_DAA_CONTEXT(ptr, length, &v->DAA_session)
      || tpm_marshal_TPM_DAA_JOINDATA(ptr, length, &v->DAA_joinSession)
      || tpm_marshal_TPM_HANDLE(ptr, length, v->handle)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DAA_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_DAA_SESSION_DATA *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->type)
      || tpm_unmarshal_TPM_DAA_ISSUER(ptr, length, &v->DAA_issuerSettings)
      || tpm_unmarshal_TPM_DAA_TPM(ptr, length, &v->DAA_tpmSpecific)
      || tpm_unmarshal_TPM_DAA_CONTEXT(ptr, length, &v->DAA_session)
      || tpm_unmarshal_TPM_DAA_JOINDATA(ptr, length, &v->DAA_joinSession)
      || tpm_unmarshal_TPM_HANDLE(ptr, length, &v->handle)) return -1;
  return 0;
}

int tpm_marshal_TPM_MSA_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_MSA_COMPOSITE *v)
{
  UINT32 i;
  if (tpm_marshal_UINT32(ptr, length, v->MSAlist))
    return -1;
  for (i = 0; i < v->MSAlist; i++) {
    if (tpm_marshal_TPM_DIGEST(ptr, length, &v->migAuthDigest[i])) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_MSA_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_MSA_COMPOSITE *v)
{
  UINT32 i;
  if (tpm_unmarshal_UINT32(ptr, length, &v->MSAlist))
    return -1;
  if (v->MSAlist > MAX_MSA_COMPOSITE_ENTRIES) return -1;
  for (i = 0; i < v->MSAlist; i++) {
    if (tpm_unmarshal_TPM_DIGEST(ptr, length, &v->migAuthDigest[i])) return -1;
  }
  return 0;
}

int tpm_marshal_TPM_CMK_AUTH(BYTE **ptr, UINT32 *length, TPM_CMK_AUTH *v)
{
  if (tpm_marshal_TPM_DIGEST(ptr, length, &v->migrationAuthorityDigest)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->destinationKeyDigest)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->sourceKeyDigest))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_CMK_AUTH(BYTE **ptr, UINT32 *length, TPM_CMK_AUTH *v)
{
  if (tpm_unmarshal_TPM_DIGEST(ptr, length, &v->migrationAuthorityDigest)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->destinationKeyDigest)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->sourceKeyDigest))
        return -1;
  return 0;
}

int tpm_marshal_TPM_SELECT_SIZE(BYTE **ptr, UINT32 *length, TPM_SELECT_SIZE *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->major)
      || tpm_marshal_BYTE(ptr, length, v->minor)
      || tpm_marshal_UINT16(ptr, length, v->reqSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_SELECT_SIZE(BYTE **ptr, UINT32 *length, TPM_SELECT_SIZE *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->major)
      || tpm_unmarshal_BYTE(ptr, length, &v->minor)
      || tpm_unmarshal_UINT16(ptr, length, &v->reqSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_CAP_VERSION_INFO(BYTE **ptr, UINT32 *length, TPM_CAP_VERSION_INFO *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_VERSION(ptr, length, &v->version)
      || tpm_marshal_UINT16(ptr, length, v->specLevel)
      || tpm_marshal_BYTE(ptr, length, v->errataRev)
      || tpm_marshal_BYTE(ptr, length, v->tpmVendorID[0])
      || tpm_marshal_BYTE(ptr, length, v->tpmVendorID[1])
      || tpm_marshal_BYTE(ptr, length, v->tpmVendorID[2])
      || tpm_marshal_BYTE(ptr, length, v->tpmVendorID[3])
      || tpm_marshal_UINT16(ptr, length, v->vendorSpecificSize)
      || tpm_marshal_BLOB(ptr, length, v->vendorSpecific, v->vendorSpecificSize))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_CAP_VERSION_INFO(BYTE **ptr, UINT32 *length, TPM_CAP_VERSION_INFO *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_VERSION(ptr, length, &v->version)
      || tpm_unmarshal_UINT16(ptr, length, &v->specLevel)
      || tpm_unmarshal_BYTE(ptr, length, &v->errataRev)
      || tpm_unmarshal_BYTE(ptr, length, &v->tpmVendorID[0])
      || tpm_unmarshal_BYTE(ptr, length, &v->tpmVendorID[1])
      || tpm_unmarshal_BYTE(ptr, length, &v->tpmVendorID[2])
      || tpm_unmarshal_BYTE(ptr, length, &v->tpmVendorID[3])
      || tpm_unmarshal_UINT16(ptr, length, &v->vendorSpecificSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->vendorSpecific, v->vendorSpecificSize))
        return -1;
  return 0;
}

int tpm_marshal_TPM_ASYM_CA_CONTENTS(BYTE **ptr, UINT32 *length, TPM_ASYM_CA_CONTENTS *v)
{
  if (tpm_marshal_TPM_SYMMETRIC_KEY(ptr, length, &v->sessionKey)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->idDigest))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_ASYM_CA_CONTENTS(BYTE **ptr, UINT32 *length, TPM_ASYM_CA_CONTENTS *v)
{
  if (tpm_unmarshal_TPM_SYMMETRIC_KEY(ptr, length, &v->sessionKey)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->idDigest))
        return -1;
  return 0;
}

int tpm_marshal_TPM_QUOTE_INFO2(BYTE **ptr, UINT32 *length, TPM_QUOTE_INFO2 *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BYTE(ptr, length, v->fixed[0])
      || tpm_marshal_BYTE(ptr, length, v->fixed[1])
      || tpm_marshal_BYTE(ptr, length, v->fixed[2])
      || tpm_marshal_BYTE(ptr, length, v->fixed[3])
      || tpm_marshal_TPM_NONCE(ptr, length, &v->externalData)
      || tpm_marshal_TPM_PCR_INFO_SHORT(ptr, length, &v->infoShort))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_QUOTE_INFO2(BYTE **ptr, UINT32 *length, TPM_QUOTE_INFO2 *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BYTE(ptr, length, &v->fixed[0])
      || tpm_unmarshal_BYTE(ptr, length, &v->fixed[1])
      || tpm_unmarshal_BYTE(ptr, length, &v->fixed[2])
      || tpm_unmarshal_BYTE(ptr, length, &v->fixed[3])
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->externalData)
      || tpm_unmarshal_TPM_PCR_INFO_SHORT(ptr, length, &v->infoShort))
        return -1;
  return 0;
}

int tpm_marshal_TPM_EK_BLOB(BYTE **ptr, UINT32 *length, TPM_EK_BLOB *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_EK_TYPE(ptr, length, v->ekType)
      || tpm_marshal_UINT32(ptr, length, v->blobSize)
      || tpm_marshal_BLOB(ptr, length, v->blob, v->blobSize))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_EK_BLOB(BYTE **ptr, UINT32 *length, TPM_EK_BLOB *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_EK_TYPE(ptr, length, &v->ekType)
      || tpm_unmarshal_UINT32(ptr, length, &v->blobSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->blob, v->blobSize))
        return -1;
  return 0;
}

int tpm_marshal_TPM_EK_BLOB_ACTIVATE(BYTE **ptr, UINT32 *length, TPM_EK_BLOB_ACTIVATE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_SYMMETRIC_KEY(ptr, length, &v->sessionKey)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->idDigest)
      || tpm_marshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfo))
        return -1;
  return 0;
}

int tpm_unmarshal_TPM_EK_BLOB_ACTIVATE(BYTE **ptr, UINT32 *length, TPM_EK_BLOB_ACTIVATE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_SYMMETRIC_KEY(ptr, length, &v->sessionKey)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->idDigest)
      || tpm_unmarshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfo))
        return -1;
  return 0;
}

int tpm_marshal_TPM_NV_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_NV_ATTRIBUTES *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT32(ptr, length, v->attributes)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_NV_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_NV_ATTRIBUTES *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT32(ptr, length, &v->attributes)) return -1;
  return 0;
}

int tpm_marshal_TPM_NV_DATA_PUBLIC(BYTE **ptr, UINT32 *length, TPM_NV_DATA_PUBLIC *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_NV_INDEX(ptr, length, v->nvIndex)
      || tpm_marshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfoRead)
      || tpm_marshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfoWrite)
      || tpm_marshal_TPM_NV_ATTRIBUTES(ptr, length, &v->permission)
      || tpm_marshal_BOOL(ptr, length, v->bReadSTClear)
      || tpm_marshal_BOOL(ptr, length, v->bWriteSTClear)
      || tpm_marshal_BOOL(ptr, length, v->bWriteDefine)
      || tpm_marshal_UINT32(ptr, length, v->dataSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_NV_DATA_PUBLIC(BYTE **ptr, UINT32 *length, TPM_NV_DATA_PUBLIC *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_NV_INDEX(ptr, length, &v->nvIndex)
      || tpm_unmarshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfoRead)
      || tpm_unmarshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfoWrite)
      || tpm_unmarshal_TPM_NV_ATTRIBUTES(ptr, length, &v->permission)
      || tpm_unmarshal_BOOL(ptr, length, &v->bReadSTClear)
      || tpm_unmarshal_BOOL(ptr, length, &v->bWriteSTClear)
      || tpm_unmarshal_BOOL(ptr, length, &v->bWriteDefine)
      || tpm_unmarshal_UINT32(ptr, length, &v->dataSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_NV_DATA_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_NV_DATA_SENSITIVE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_NV_DATA_PUBLIC(ptr, length, &v->pubInfo)
      || tpm_marshal_TPM_AUTHDATA(ptr, length, &v->authValue)
      || tpm_marshal_UINT32(ptr, length, v->dataIndex)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_NV_DATA_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_NV_DATA_SENSITIVE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_NV_DATA_PUBLIC(ptr, length, &v->pubInfo)
      || tpm_unmarshal_TPM_AUTHDATA(ptr, length, &v->authValue)
      || tpm_unmarshal_UINT32(ptr, length, &v->dataIndex)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATIONS(BYTE **ptr, UINT32 *length, TPM_DELEGATIONS *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT32(ptr, length, v->delegateType)
      || tpm_marshal_UINT32(ptr, length, v->per1)
      || tpm_marshal_UINT32(ptr, length, v->per2)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATIONS(BYTE **ptr, UINT32 *length, TPM_DELEGATIONS *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT32(ptr, length, &v->delegateType)
      || tpm_unmarshal_UINT32(ptr, length, &v->per1)
      || tpm_unmarshal_UINT32(ptr, length, &v->per2)) return -1;
  return 0;
}

int tpm_marshal_TPM_FAMILY_LABEL(BYTE **ptr, UINT32 *length, TPM_FAMILY_LABEL *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->label)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_FAMILY_LABEL(BYTE **ptr, UINT32 *length, TPM_FAMILY_LABEL *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->label)) return -1;
  return 0;
}

int tpm_marshal_TPM_FAMILY_TABLE_ENTRY(BYTE **ptr, UINT32 *length, TPM_FAMILY_TABLE_ENTRY *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_FAMILY_LABEL(ptr, length, &v->familyLabel)
      || tpm_marshal_TPM_FAMILY_ID(ptr, length, v->familyID)
      || tpm_marshal_TPM_FAMILY_VERIFICATION(ptr, length, v->verificationCount)
      || tpm_marshal_TPM_FAMILY_FLAGS(ptr, length, v->flags)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_FAMILY_TABLE_ENTRY(BYTE **ptr, UINT32 *length, TPM_FAMILY_TABLE_ENTRY *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_FAMILY_LABEL(ptr, length, &v->familyLabel)
      || tpm_unmarshal_TPM_FAMILY_ID(ptr, length, &v->familyID)
      || tpm_unmarshal_TPM_FAMILY_VERIFICATION(ptr, length, &v->verificationCount)
      || tpm_unmarshal_TPM_FAMILY_FLAGS(ptr, length, &v->flags)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATE_LABEL(BYTE **ptr, UINT32 *length, TPM_DELEGATE_LABEL *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->label)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_LABEL(BYTE **ptr, UINT32 *length, TPM_DELEGATE_LABEL *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->label)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATE_PUBLIC(BYTE **ptr, UINT32 *length, TPM_DELEGATE_PUBLIC *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DELEGATE_LABEL(ptr, length, &v->rowLabel)
      || tpm_marshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfo)
      || tpm_marshal_TPM_DELEGATIONS(ptr, length, &v->permissions)
      || tpm_marshal_TPM_FAMILY_ID(ptr, length, v->familyID)
      || tpm_marshal_TPM_FAMILY_VERIFICATION(ptr, length, v->verificationCount)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_PUBLIC(BYTE **ptr, UINT32 *length, TPM_DELEGATE_PUBLIC *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DELEGATE_LABEL(ptr, length, &v->rowLabel)
      || tpm_unmarshal_TPM_PCR_INFO_SHORT(ptr, length, &v->pcrInfo)
      || tpm_unmarshal_TPM_DELEGATIONS(ptr, length, &v->permissions)
      || tpm_unmarshal_TPM_FAMILY_ID(ptr, length, &v->familyID)
      || tpm_unmarshal_TPM_FAMILY_VERIFICATION(ptr, length, &v->verificationCount)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATE_PUBLIC_ARRAY(BYTE **ptr, UINT32 *length,
                                          TPM_DELEGATE_PUBLIC *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tpm_marshal_TPM_DELEGATE_PUBLIC(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_PUBLIC_ARRAY(BYTE **ptr, UINT32 *length,
                                            TPM_DELEGATE_PUBLIC *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tpm_unmarshal_TPM_DELEGATE_PUBLIC(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tpm_marshal_TPM_DELEGATE_TABLE_ROW(BYTE **ptr, UINT32 *length, TPM_DELEGATE_TABLE_ROW *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DELEGATE_PUBLIC(ptr, length, &v->pub)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->authValue)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_TABLE_ROW(BYTE **ptr, UINT32 *length, TPM_DELEGATE_TABLE_ROW *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DELEGATE_PUBLIC(ptr, length, &v->pub)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->authValue)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATE_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DELEGATE_SENSITIVE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->authValue)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DELEGATE_SENSITIVE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
    || tpm_unmarshal_TPM_SECRET(ptr, length, &v->authValue)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATE_OWNER_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_OWNER_BLOB *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DELEGATE_PUBLIC(ptr, length, &v->pub)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->integrityDigest)
      || tpm_marshal_UINT32(ptr, length, v->additionalSize)
      || tpm_marshal_BLOB(ptr, length, v->additionalArea, v->additionalSize)
      || tpm_marshal_UINT32(ptr, length, v->sensitiveSize)
      || tpm_marshal_BLOB(ptr, length, v->sensitiveArea, v->sensitiveSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_OWNER_BLOB *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DELEGATE_PUBLIC(ptr, length, &v->pub)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->integrityDigest)
      || tpm_unmarshal_UINT32(ptr, length, &v->additionalSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->additionalArea, v->additionalSize)
      || tpm_unmarshal_UINT32(ptr, length, &v->sensitiveSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->sensitiveArea, v->sensitiveSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_DELEGATE_KEY_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_KEY_BLOB *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_DELEGATE_PUBLIC(ptr, length, &v->pub)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->integrityDigest)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->pubKeyDigest)
      || tpm_marshal_UINT32(ptr, length, v->additionalSize)
      || tpm_marshal_BLOB(ptr, length, v->additionalArea, v->additionalSize)
      || tpm_marshal_UINT32(ptr, length, v->sensitiveSize)
      || tpm_marshal_BLOB(ptr, length, v->sensitiveArea, v->sensitiveSize)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DELEGATE_KEY_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_KEY_BLOB *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_DELEGATE_PUBLIC(ptr, length, &v->pub)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->integrityDigest)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->pubKeyDigest)
      || tpm_unmarshal_UINT32(ptr, length, &v->additionalSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->additionalArea, v->additionalSize)
      || tpm_unmarshal_UINT32(ptr, length, &v->sensitiveSize)
      || tpm_unmarshal_BLOB(ptr, length, &v->sensitiveArea, v->sensitiveSize)) return -1;
  return 0;
}

int tpm_marshal_TPM_PERMANENT_FLAGS(BYTE **ptr, UINT32 *length, TPM_PERMANENT_FLAGS *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BOOL(ptr, length, v->disable)
      || tpm_marshal_BOOL(ptr, length, v->ownership)
      || tpm_marshal_BOOL(ptr, length, v->deactivated)
      || tpm_marshal_BOOL(ptr, length, v->readPubek)
      || tpm_marshal_BOOL(ptr, length, v->disableOwnerClear)
      || tpm_marshal_BOOL(ptr, length, v->allowMaintenance)
      || tpm_marshal_BOOL(ptr, length, v->physicalPresenceLifetimeLock)
      || tpm_marshal_BOOL(ptr, length, v->physicalPresenceHWEnable)
      || tpm_marshal_BOOL(ptr, length, v->physicalPresenceCMDEnable)
      || tpm_marshal_BOOL(ptr, length, v->CEKPUsed)
      || tpm_marshal_BOOL(ptr, length, v->TPMpost)
      || tpm_marshal_BOOL(ptr, length, v->TPMpostLock)
      || tpm_marshal_BOOL(ptr, length, v->FIPS)
      || tpm_marshal_BOOL(ptr, length, v->operator)
      || tpm_marshal_BOOL(ptr, length, v->enableRevokeEK)
      || tpm_marshal_BOOL(ptr, length, v->nvLocked)
      || tpm_marshal_BOOL(ptr, length, v->readSRKPub)
      || tpm_marshal_BOOL(ptr, length, v->tpmEstablished)
      || tpm_marshal_BOOL(ptr, length, v->maintenanceDone)
      || tpm_marshal_BOOL(ptr, length, v->disableFullDALogicInfo)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PERMANENT_FLAGS(BYTE **ptr, UINT32 *length, TPM_PERMANENT_FLAGS *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BOOL(ptr, length, &v->disable)
      || tpm_unmarshal_BOOL(ptr, length, &v->ownership)
      || tpm_unmarshal_BOOL(ptr, length, &v->deactivated)
      || tpm_unmarshal_BOOL(ptr, length, &v->readPubek)
      || tpm_unmarshal_BOOL(ptr, length, &v->disableOwnerClear)
      || tpm_unmarshal_BOOL(ptr, length, &v->allowMaintenance)
      || tpm_unmarshal_BOOL(ptr, length, &v->physicalPresenceLifetimeLock)
      || tpm_unmarshal_BOOL(ptr, length, &v->physicalPresenceHWEnable)
      || tpm_unmarshal_BOOL(ptr, length, &v->physicalPresenceCMDEnable)
      || tpm_unmarshal_BOOL(ptr, length, &v->CEKPUsed)
      || tpm_unmarshal_BOOL(ptr, length, &v->TPMpost)
      || tpm_unmarshal_BOOL(ptr, length, &v->TPMpostLock)
      || tpm_unmarshal_BOOL(ptr, length, &v->FIPS)
      || tpm_unmarshal_BOOL(ptr, length, &v->operator)
      || tpm_unmarshal_BOOL(ptr, length, &v->enableRevokeEK)
      || tpm_unmarshal_BOOL(ptr, length, &v->nvLocked)
      || tpm_unmarshal_BOOL(ptr, length, &v->readSRKPub)
      || tpm_unmarshal_BOOL(ptr, length, &v->tpmEstablished)
      || tpm_unmarshal_BOOL(ptr, length, &v->maintenanceDone)
      || tpm_unmarshal_BOOL(ptr, length, &v->disableFullDALogicInfo)) return -1;
  return 0;
}

int tpm_marshal_TPM_STCLEAR_FLAGS(BYTE **ptr, UINT32 *length, TPM_STCLEAR_FLAGS *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BOOL(ptr, length, v->deactivated)
      || tpm_marshal_BOOL(ptr, length, v->disableForceClear)
      || tpm_marshal_BOOL(ptr, length, v->physicalPresence)
      || tpm_marshal_BOOL(ptr, length, v->physicalPresenceLock)
      || tpm_marshal_BOOL(ptr, length, v->bGlobalLock)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STCLEAR_FLAGS(BYTE **ptr, UINT32 *length, TPM_STCLEAR_FLAGS *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BOOL(ptr, length, &v->deactivated)
      || tpm_unmarshal_BOOL(ptr, length, &v->disableForceClear)
      || tpm_unmarshal_BOOL(ptr, length, &v->physicalPresence)
      || tpm_unmarshal_BOOL(ptr, length, &v->physicalPresenceLock)
      || tpm_unmarshal_BOOL(ptr, length, &v->bGlobalLock)) return -1;
  return 0;
}

int tpm_marshal_TPM_STANY_FLAGS(BYTE **ptr, UINT32 *length, TPM_STANY_FLAGS *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BOOL(ptr, length, v->postInitialise)
      || tpm_marshal_UINT32(ptr, length, v->localityModifier)
      || tpm_marshal_BOOL(ptr, length, v->transportExclusive)
      || tpm_marshal_BOOL(ptr, length, v->TOSPresent)) return -1;
  return 0;
} 

int tpm_unmarshal_TPM_STANY_FLAGS(BYTE **ptr, UINT32 *length, TPM_STANY_FLAGS *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BOOL(ptr, length, &v->postInitialise)
      || tpm_unmarshal_UINT32(ptr, length, &v->localityModifier)
      || tpm_unmarshal_BOOL(ptr, length, &v->transportExclusive)
      || tpm_unmarshal_BOOL(ptr, length, &v->TOSPresent)) return -1;
  return 0;
}

int tpm_marshal_RSA(BYTE **ptr, UINT32 *length, tpm_rsa_private_key_t *v)
{
  size_t m_len, e_len, q_len;
  if (*length < (UINT32)sizeof_RSA((*v))) return -1;
  if (v->size > 0) {
    tpm_rsa_export_modulus(v, &(*ptr)[6], &m_len);
    tpm_rsa_export_exponent(v, &(*ptr)[6+m_len], &e_len);
    tpm_rsa_export_prime1(v, &(*ptr)[6+m_len+e_len], &q_len);
    tpm_marshal_UINT16(ptr, length, m_len);
    tpm_marshal_UINT16(ptr, length, e_len);
    tpm_marshal_UINT16(ptr, length, q_len);
    *ptr += m_len + e_len + q_len;
    *length -= m_len + e_len + q_len;
  } else {
    tpm_marshal_UINT16(ptr, length, 0);
    tpm_marshal_UINT16(ptr, length, 0);
    tpm_marshal_UINT16(ptr, length, 0);
  }
  return 0;
}

int tpm_unmarshal_RSA(BYTE **ptr, UINT32 *length, tpm_rsa_private_key_t *v)
{
  UINT16 m_len, e_len, q_len;
  if (tpm_unmarshal_UINT16(ptr, length, &m_len)
      || tpm_unmarshal_UINT16(ptr, length, &e_len)
      || tpm_unmarshal_UINT16(ptr, length, &q_len)) return -1;
  if (m_len == 0) {
    v->size = 0;
    return 0;
  }
  if (*length < (UINT32)m_len + (UINT32)e_len + (UINT32)q_len
      || q_len != m_len/2
      || tpm_rsa_import_key(v, RSA_MSB_FIRST,
                        &(*ptr)[0], m_len,
                        &(*ptr)[m_len], e_len,
                        &(*ptr)[m_len+e_len], NULL)) return -1;
  *ptr += m_len + e_len + q_len;
  *length -= m_len + e_len + q_len;
  return 0;
}

int tpm_marshal_RSAPub(BYTE **ptr, UINT32 *length, tpm_rsa_public_key_t *v)
{
  size_t m_len, e_len;
  if (*length < (UINT32)sizeof_RSAPub((*v))) return -1;
  if (v->size > 0) {
    tpm_rsa_export_public_modulus(v, &(*ptr)[4], &m_len);
    tpm_rsa_export_public_exponent(v, &(*ptr)[4+m_len], &e_len);
    tpm_marshal_UINT16(ptr, length, m_len);
    tpm_marshal_UINT16(ptr, length, e_len);
    *ptr += m_len + e_len;
    *length -= m_len + e_len;
  } else {
    tpm_marshal_UINT16(ptr, length, 0);
    tpm_marshal_UINT16(ptr, length, 0);
  }
  return 0;
}

int tpm_unmarshal_RSAPub(BYTE **ptr, UINT32 *length, tpm_rsa_public_key_t *v)
{
  UINT16 m_len, e_len;
  if (tpm_unmarshal_UINT16(ptr, length, &m_len)
      || tpm_unmarshal_UINT16(ptr, length, &e_len)) return -1;
  if (m_len == 0) {
    v->size = 0;
    return 0;
  }
  if (*length < (UINT32)m_len + (UINT32)e_len
      || tpm_rsa_import_public_key(v, RSA_MSB_FIRST, &(*ptr)[0], m_len, 
                                   &(*ptr)[m_len], e_len)) return -1;
  *ptr += m_len + e_len;
  *length -= m_len + e_len;
  return 0;
}

int tpm_marshal_TPM_KEY_DATA(BYTE **ptr, UINT32 *length, TPM_KEY_DATA *v)
{
  if (tpm_marshal_TPM_PAYLOAD_TYPE(ptr, length, v->payload)) return -1;
  if (v->payload) {
    if (tpm_marshal_TPM_KEY_USAGE(ptr, length, v->keyUsage)
        || tpm_marshal_TPM_KEY_FLAGS(ptr, length, v->keyFlags)
        || tpm_marshal_TPM_KEY_CONTROL(ptr, length, v->keyControl)
        || tpm_marshal_TPM_AUTH_DATA_USAGE(ptr, length, v->authDataUsage)
        || tpm_marshal_TPM_ENC_SCHEME(ptr, length, v->encScheme)
        || tpm_marshal_TPM_SIG_SCHEME(ptr, length, v->sigScheme)
        || tpm_marshal_TPM_SECRET(ptr, length, &v->usageAuth)
        || tpm_marshal_TPM_SECRET(ptr, length, &v->migrationAuth)
        || (v->keyFlags & TPM_KEY_FLAG_HAS_PCR
            && tpm_marshal_TPM_PCR_INFO(ptr, length, &v->pcrInfo))
        || tpm_marshal_BOOL(ptr, length, v->parentPCRStatus)
        || tpm_marshal_RSA(ptr, length, &v->key)) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_KEY_DATA(BYTE **ptr, UINT32 *length, TPM_KEY_DATA *v)
{
  if (tpm_unmarshal_TPM_PAYLOAD_TYPE(ptr, length, &v->payload)) return -1;
  if (v->payload) {
    if (tpm_unmarshal_TPM_KEY_USAGE(ptr, length, &v->keyUsage)
        || tpm_unmarshal_TPM_KEY_FLAGS(ptr, length, &v->keyFlags)
        || tpm_unmarshal_TPM_KEY_CONTROL(ptr, length, &v->keyControl)
        || tpm_unmarshal_TPM_AUTH_DATA_USAGE(ptr, length, &v->authDataUsage)
        || tpm_unmarshal_TPM_ENC_SCHEME(ptr, length, &v->encScheme)
        || tpm_unmarshal_TPM_SIG_SCHEME(ptr, length, &v->sigScheme)
        || tpm_unmarshal_TPM_SECRET(ptr, length, &v->usageAuth)
        || tpm_unmarshal_TPM_SECRET(ptr, length, &v->migrationAuth)
        || (v->keyFlags & TPM_KEY_FLAG_HAS_PCR
            && tpm_unmarshal_TPM_PCR_INFO(ptr, length, &v->pcrInfo))
        || tpm_unmarshal_BOOL(ptr, length, &v->parentPCRStatus)
        || tpm_unmarshal_RSA(ptr, length, &v->key)) return -1;
    }
  return 0;
}

int tpm_marshal_TPM_PUBKEY_DATA(BYTE **ptr, UINT32 *length, TPM_PUBKEY_DATA *v)
{
  if (tpm_marshal_BOOL(ptr, length, v->valid)) return -1;
  if (v->valid) {
    if (tpm_marshal_TPM_ENC_SCHEME(ptr, length, v->encScheme)
        || tpm_marshal_TPM_SIG_SCHEME(ptr, length, v->sigScheme)
        || tpm_marshal_RSAPub(ptr, length, &v->key)) return -1;
    }
  return 0;
}

int tpm_unmarshal_TPM_PUBKEY_DATA(BYTE **ptr, UINT32 *length, TPM_PUBKEY_DATA *v)
{
  if (tpm_unmarshal_BOOL(ptr, length, &v->valid)) return -1;
  if (v->valid) {
    if (tpm_unmarshal_TPM_ENC_SCHEME(ptr, length, &v->encScheme)
        || tpm_unmarshal_TPM_SIG_SCHEME(ptr, length, &v->sigScheme)
        || tpm_unmarshal_RSAPub(ptr, length, &v->key)) return -1;
    }
  return 0;
}

int tpm_marshal_TPM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TPM_PERMANENT_DATA *v)
{
  UINT32 i;
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_VERSION(ptr, length, &v->version)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->tpmProof)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->ekReset)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->ownerAuth)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->operatorAuth)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->tpmDAASeed)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->daaProof)
      || tpm_marshal_TPM_PUBKEY_DATA(ptr, length, &v->manuMaintPub)
      || tpm_marshal_RSA(ptr, length, &v->endorsementKey)
      || tpm_marshal_TPM_KEY_DATA(ptr, length, &v->srk)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->contextKey, sizeof(v->contextKey))
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->delegateKey, sizeof(v->contextKey))
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->daaKey, sizeof(v->contextKey))
      || tpm_marshal_TPM_ACTUAL_COUNT(ptr, length, v->auditMonotonicCounter)) return -1;
  for (i = 0; i < TPM_MAX_COUNTERS; i++) {
    if (tpm_marshal_TPM_COUNTER_VALUE(ptr, length, &v->counters[i])
        || tpm_marshal_TPM_SECRET(ptr, length, &v->counters[i].usageAuth)
        || tpm_marshal_BOOL(ptr, length, v->counters[i].valid)) return -1;
  }
  for (i = 0; i < TPM_NUM_PCR; i++) {
    if (tpm_marshal_TPM_PCR_ATTRIBUTES(ptr, length, &v->pcrAttrib[i])) return -1;
  }
  for (i = 0; i < TPM_NUM_PCR; i++) {
    if (tpm_marshal_TPM_PCRVALUE(ptr, length, &v->pcrValue[i])) return -1;
  }
  if (tpm_marshal_BYTE_ARRAY(ptr, length, v->ordinalAuditStatus, sizeof(v->ordinalAuditStatus))
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->rngState, sizeof(v->rngState))) return -1;
  for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    if (tpm_marshal_BOOL(ptr, length, v->familyTable.famRow[i].valid)) return -1;
    if (v->familyTable.famRow[i].valid) {
      if (tpm_marshal_TPM_FAMILY_TABLE_ENTRY(ptr, length, &v->familyTable.famRow[i])) return -1;
    }
  }
  for (i = 0; i < TPM_NUM_DELEGATE_TABLE_ENTRY; i++) {
    if (tpm_marshal_BOOL(ptr, length, v->delegateTable.delRow[i].valid)) return -1;
    if (v->delegateTable.delRow[i].valid) {
      if (tpm_marshal_TPM_DELEGATE_TABLE_ROW(ptr, length, &v->delegateTable.delRow[i])) return -1;
    }
  }
  if (tpm_marshal_UINT32(ptr, length, v->lastFamilyID)
      || tpm_marshal_TPM_CMK_DELEGATE(ptr, length, v->restrictDelegate)
      || tpm_marshal_UINT32(ptr, length, v->maxNVBufSize)
      || tpm_marshal_UINT32(ptr, length, v->noOwnerNVWrite)
      || tpm_marshal_UINT32(ptr, length, v->nvDataSize)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->nvData, sizeof(v->nvData))) return -1;
  for (i = 0; i < TPM_MAX_NVS; i++) {
    if (tpm_marshal_BOOL(ptr, length, v->nvStorage[i].valid)) return -1;
    if (v->nvStorage[i].valid) {
      if (tpm_marshal_TPM_NV_DATA_SENSITIVE(ptr, length, &v->nvStorage[i])) return -1;
    }
  }
  for (i = 0; i < TPM_MAX_KEYS; i++) {
    if (tpm_marshal_TPM_KEY_DATA(ptr, length, &v->keys[i])) return -1;
  }
  if (tpm_marshal_UINT32_ARRAY(ptr, length, v->tis_timeouts, TPM_NUM_TIS_TIMEOUTS)
      || tpm_marshal_UINT32_ARRAY(ptr, length, v->cmd_durations, TPM_NUM_CMD_DURATIONS)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TPM_PERMANENT_DATA *v)
{
  UINT32 i;
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_VERSION(ptr, length, &v->version)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->tpmProof)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->ekReset)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->ownerAuth)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->operatorAuth)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->tpmDAASeed)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->daaProof)
      || tpm_unmarshal_TPM_PUBKEY_DATA(ptr, length, &v->manuMaintPub)
      || tpm_unmarshal_RSA(ptr, length, &v->endorsementKey)
      || tpm_unmarshal_TPM_KEY_DATA(ptr, length, &v->srk)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->contextKey, sizeof(v->contextKey))
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->delegateKey, sizeof(v->contextKey))
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->daaKey, sizeof(v->contextKey))
      || tpm_unmarshal_TPM_ACTUAL_COUNT(ptr, length, &v->auditMonotonicCounter)) return -1;
  for (i = 0; i < TPM_MAX_COUNTERS; i++) {
    if (tpm_unmarshal_TPM_COUNTER_VALUE(ptr, length, &v->counters[i])
        || tpm_unmarshal_TPM_SECRET(ptr, length, &v->counters[i].usageAuth)
        || tpm_unmarshal_BOOL(ptr, length, &v->counters[i].valid)) return -1;
  }
  for (i = 0; i < TPM_NUM_PCR; i++) {
    if (tpm_unmarshal_TPM_PCR_ATTRIBUTES(ptr, length, &v->pcrAttrib[i])) return -1;
  }
  for (i = 0; i < TPM_NUM_PCR; i++) {
    if (tpm_unmarshal_TPM_PCRVALUE(ptr, length, &v->pcrValue[i])) return -1;
  }
  if (tpm_unmarshal_BYTE_ARRAY(ptr, length, v->ordinalAuditStatus, sizeof(v->ordinalAuditStatus))
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->rngState, sizeof(v->rngState))) return -1;
  for (i = 0; i < TPM_NUM_FAMILY_TABLE_ENTRY; i++) {
    if (tpm_unmarshal_BOOL(ptr, length, &v->familyTable.famRow[i].valid)) return -1;
    if (v->familyTable.famRow[i].valid) {
      if (tpm_unmarshal_TPM_FAMILY_TABLE_ENTRY(ptr, length, &v->familyTable.famRow[i])) return -1;
    }
  }
  for (i = 0; i < TPM_NUM_DELEGATE_TABLE_ENTRY; i++) {
    if (tpm_unmarshal_BOOL(ptr, length, &v->delegateTable.delRow[i].valid)) return -1;
    if (v->delegateTable.delRow[i].valid) {
      if (tpm_unmarshal_TPM_DELEGATE_TABLE_ROW(ptr, length, &v->delegateTable.delRow[i])) return -1;
    }
  }
  if (tpm_unmarshal_UINT32(ptr, length, &v->lastFamilyID)
      || tpm_unmarshal_TPM_CMK_DELEGATE(ptr, length, &v->restrictDelegate)
      || tpm_unmarshal_UINT32(ptr, length, &v->maxNVBufSize)
      || tpm_unmarshal_UINT32(ptr, length, &v->noOwnerNVWrite)
      || tpm_unmarshal_UINT32(ptr, length, &v->nvDataSize)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->nvData, sizeof(v->nvData))) return -1;
  for (i = 0; i < TPM_MAX_NVS; i++) {
    if (tpm_unmarshal_BOOL(ptr, length, &v->nvStorage[i].valid)) return -1;
    if (v->nvStorage[i].valid) {
      if (tpm_unmarshal_TPM_NV_DATA_SENSITIVE(ptr, length, &v->nvStorage[i])) return -1;
    }
  }
  for (i = 0; i < TPM_MAX_KEYS; i++) {
    if (tpm_unmarshal_TPM_KEY_DATA(ptr, length, &v->keys[i])) return -1;
  }
  if (tpm_unmarshal_UINT32_ARRAY(ptr, length, v->tis_timeouts, TPM_NUM_TIS_TIMEOUTS)
      || tpm_unmarshal_UINT32_ARRAY(ptr, length, v->cmd_durations, TPM_NUM_CMD_DURATIONS)) return -1;
  return 0;
}

int tpm_marshal_TPM_STCLEAR_DATA(BYTE **ptr, UINT32 *length, TPM_STCLEAR_DATA *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->contextNonceKey)
      || tpm_marshal_TPM_COUNT_ID(ptr, length, v->countID)
      || tpm_marshal_UINT32(ptr, length, v->ownerReference)
      || tpm_marshal_BOOL(ptr, length, v->disableResetLock)
      || tpm_marshal_UINT32(ptr, length, v->deferredPhysicalPresence)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STCLEAR_DATA(BYTE **ptr, UINT32 *length, TPM_STCLEAR_DATA *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->contextNonceKey)
      || tpm_unmarshal_TPM_COUNT_ID(ptr, length, &v->countID)
      || tpm_unmarshal_UINT32(ptr, length, &v->ownerReference)
      || tpm_unmarshal_BOOL(ptr, length, &v->disableResetLock)
      || tpm_unmarshal_UINT32(ptr, length, &v->deferredPhysicalPresence)) return -1;
  return 0;
}

int tpm_marshal_TPM_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_SESSION_DATA *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->type)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->nonceEven)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->lastNonceEven)
      || tpm_marshal_TPM_SECRET(ptr, length, &v->sharedSecret)
      || tpm_marshal_TPM_HANDLE(ptr, length, v->handle)
      || tpm_marshal_TPM_ENTITY_TYPE(ptr, length, v->entityType)
      || (v->type == TPM_ST_DSAP
          && (tpm_marshal_TPM_DELEGATIONS(ptr, length, &v->permissions)
              || tpm_marshal_TPM_FAMILY_ID(ptr, length, v->familyID)))
      || (v->type == TPM_ST_TRANSPORT 
          && tpm_marshal_TPM_TRANSPORT_INTERNAL(ptr, length, &v->transInternal))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_SESSION_DATA *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->type)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->nonceEven)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->lastNonceEven)
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->sharedSecret)
      || tpm_unmarshal_TPM_HANDLE(ptr, length, &v->handle)
      || tpm_unmarshal_TPM_ENTITY_TYPE(ptr, length, &v->entityType)
      || (v->type == TPM_ST_DSAP
          && (tpm_unmarshal_TPM_DELEGATIONS(ptr, length, &v->permissions)
              || tpm_unmarshal_TPM_FAMILY_ID(ptr, length, &v->familyID)))
      || (v->type == TPM_ST_TRANSPORT 
          && tpm_unmarshal_TPM_TRANSPORT_INTERNAL(ptr, length, &v->transInternal))) return -1;
  return 0;
}

int tpm_marshal_TPM_STANY_DATA(BYTE **ptr, UINT32 *length, TPM_STANY_DATA *v)
{
  UINT32 i;
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_TPM_NONCE(ptr, length, &v->contextNonceSession)
      || tpm_marshal_TPM_DIGEST(ptr, length, &v->auditDigest)
      || tpm_marshal_BOOL(ptr, length, v->auditSession)
      || tpm_marshal_TPM_CURRENT_TICKS(ptr, length, &v->currentTicks)
      || tpm_marshal_UINT32(ptr, length, v->contextCount)
      || tpm_marshal_UINT32_ARRAY(ptr, length, v->contextList, TPM_MAX_SESSION_LIST)) return -1;
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    if (tpm_marshal_TPM_SESSION_DATA(ptr, length, &v->sessions[i])) return -1;
  }
  for (i = 0; i < TPM_MAX_SESSIONS_DAA; i++) {
    if (tpm_marshal_TPM_DAA_SESSION_DATA(ptr, length, &v->sessionsDAA[i])) return -1;
  }
  if (tpm_marshal_DAAHANDLE(ptr, length, v->currentDAA)
      || tpm_marshal_TPM_TRANSHANDLE(ptr, length, v->transExclusive)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_STANY_DATA(BYTE **ptr, UINT32 *length, TPM_STANY_DATA *v)
{
  UINT32 i;
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_TPM_NONCE(ptr, length, &v->contextNonceSession)
      || tpm_unmarshal_TPM_DIGEST(ptr, length, &v->auditDigest)
      || tpm_unmarshal_BOOL(ptr, length, &v->auditSession)
      || tpm_unmarshal_TPM_CURRENT_TICKS(ptr, length, &v->currentTicks)
      || tpm_unmarshal_UINT32(ptr, length, &v->contextCount)
      || tpm_unmarshal_UINT32_ARRAY(ptr, length, v->contextList, TPM_MAX_SESSION_LIST)) return -1;
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    if (tpm_unmarshal_TPM_SESSION_DATA(ptr, length, &v->sessions[i])) return -1;
  }
  for (i = 0; i < TPM_MAX_SESSIONS_DAA; i++) {
    if (tpm_unmarshal_TPM_DAA_SESSION_DATA(ptr, length, &v->sessionsDAA[i])) return -1;
  }
  if (tpm_unmarshal_DAAHANDLE(ptr, length, &v->currentDAA)
      || tpm_unmarshal_TPM_TRANSHANDLE(ptr, length, &v->transExclusive)) return -1;
  return 0;
}

int tpm_marshal_TPM_DATA(BYTE **ptr, UINT32 *length, TPM_DATA *v)
{
  if (tpm_marshal_TPM_PERMANENT_FLAGS(ptr, length, &v->permanent.flags)
      || tpm_marshal_BOOL(ptr, length, v->permanent.flags.selfTestSucceeded)
      || tpm_marshal_BOOL(ptr, length, v->permanent.flags.owned)
      || tpm_marshal_TPM_PERMANENT_DATA(ptr, length, &v->permanent.data)
      || tpm_marshal_TPM_STCLEAR_FLAGS(ptr, length, &v->stclear.flags)
      || tpm_marshal_TPM_STCLEAR_DATA(ptr, length, &v->stclear.data)
      || tpm_marshal_TPM_STANY_DATA(ptr, length, &v->stany.data)) return -1;
  return 0;
}

int tpm_unmarshal_TPM_DATA(BYTE **ptr, UINT32 *length, TPM_DATA *v)
{
  if (tpm_unmarshal_TPM_PERMANENT_FLAGS(ptr, length, &v->permanent.flags)
      || tpm_unmarshal_BOOL(ptr, length, &v->permanent.flags.selfTestSucceeded)
      || tpm_unmarshal_BOOL(ptr, length, &v->permanent.flags.owned)
      || tpm_unmarshal_TPM_PERMANENT_DATA(ptr, length, &v->permanent.data)
      || tpm_unmarshal_TPM_STCLEAR_FLAGS(ptr, length, &v->stclear.flags)
      || tpm_unmarshal_TPM_STCLEAR_DATA(ptr, length, &v->stclear.data)
      || tpm_unmarshal_TPM_STANY_DATA(ptr, length, &v->stany.data)) return -1;
  return 0;
}

int tpm_marshal_TPM_RESPONSE(BYTE **ptr, UINT32 *length, TPM_RESPONSE *v)
{
  if (tpm_marshal_TPM_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT32(ptr, length, v->size)
      || tpm_marshal_TPM_RESULT(ptr, length, v->result)
      || tpm_marshal_BLOB(ptr, length, v->param, v->paramSize)) return -1;
  if (v->tag == TPM_TAG_RSP_AUTH2_COMMAND) {
    if (tpm_marshal_TPM_AUTH(ptr, length, v->auth1)
        || tpm_marshal_TPM_AUTH(ptr, length, v->auth2)) return -1;
  } else if (v->tag == TPM_TAG_RSP_AUTH1_COMMAND) {
    if (tpm_marshal_TPM_AUTH(ptr, length, v->auth1)) return -1;
  }
  return 0;
}

int tpm_unmarshal_TPM_REQUEST(BYTE **ptr, UINT32 *length, TPM_REQUEST *v)
{
  if (tpm_unmarshal_TPM_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT32(ptr, length, &v->size)
      || tpm_unmarshal_TPM_COMMAND_CODE(ptr, length, &v->ordinal)) return -1;
  v->param = *ptr;
  v->paramSize = *length;
  if (v->tag == TPM_TAG_RQU_AUTH2_COMMAND) {
    if (*length < 2 * 45) return -1;
    v->paramSize = *length - 2 * 45;
    if (tpm_unmarshal_BLOB(ptr, length, &v->param, v->paramSize)
        || tpm_unmarshal_TPM_AUTH(ptr, length, &v->auth1)
        || tpm_unmarshal_TPM_AUTH(ptr, length, &v->auth2)) return -1;
    v->auth1.ordinal = v->ordinal;
    v->auth2.ordinal = v->ordinal;
  } else if (v->tag == TPM_TAG_RQU_AUTH1_COMMAND) {
    if (*length < 45) return -1;
    v->paramSize = *length - 45;
    if (tpm_unmarshal_BLOB(ptr, length, &v->param, v->paramSize)
        || tpm_unmarshal_TPM_AUTH(ptr, length, &v->auth1)) return -1;
    v->auth1.ordinal = v->ordinal;
    v->auth2.authHandle = TPM_INVALID_HANDLE;
  } else {
    v->auth1.authHandle = TPM_INVALID_HANDLE;
    v->auth2.authHandle = TPM_INVALID_HANDLE;
  }
  return 0;
}

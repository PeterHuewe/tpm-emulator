/* Software-based Mobile Trusted Module (MTM) Emulator
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
 * $Id$
 */

#include "mtm_marshalling.h"

int tpm_marshal_MTM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, MTM_PERMANENT_DATA *v)
{
  int i;
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BYTE(ptr, length, v->specMajor)
      || tpm_marshal_BYTE(ptr, length, v->specMinor)
      || tpm_marshal_TPM_PCR_SELECTION(ptr, length, &v->verifiedPCRs)
      || tpm_marshal_TPM_COUNT_ID(ptr, length, v->counterRimProtectId)
      || tpm_marshal_TPM_COUNT_ID(ptr, length, v->counterStorageProtectId)
      || tpm_marshal_BYTE(ptr, length, v->loadVerificationKeyMethods)
      || tpm_marshal_BOOL(ptr, length, v->integrityCheckRootValid)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->integrityCheckRootData,
                                sizeof(v->integrityCheckRootData))
      || tpm_marshal_TPM_SECRET(ptr, length, &v->internalVerificationKey)) return -1;
  for (i = 0; i < MTM_MAX_KEYS; i++) {
    if (tpm_marshal_MTM_KEY_DATA(ptr, length, &v->keys[i])) return -1;
  }
  return 0;
}

int tpm_unmarshal_MTM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, MTM_PERMANENT_DATA *v)
{
  int i;
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BYTE(ptr, length, &v->specMajor)
      || tpm_unmarshal_BYTE(ptr, length, &v->specMinor)
      || tpm_unmarshal_TPM_PCR_SELECTION(ptr, length, &v->verifiedPCRs)
      || tpm_unmarshal_TPM_COUNT_ID(ptr, length, &v->counterRimProtectId)
      || tpm_unmarshal_TPM_COUNT_ID(ptr, length, &v->counterStorageProtectId)
      || tpm_unmarshal_BYTE(ptr, length, &v->loadVerificationKeyMethods)
      || tpm_unmarshal_BOOL(ptr, length, &v->integrityCheckRootValid)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->integrityCheckRootData,
                                  sizeof(v->integrityCheckRootData))
      || tpm_unmarshal_TPM_SECRET(ptr, length, &v->internalVerificationKey)) return -1;
  for (i = 0; i < MTM_MAX_KEYS; i++) {
    if (tpm_unmarshal_MTM_KEY_DATA(ptr, length, &v->keys[i])) return -1;
  }
  return 0;
}

int tpm_marshal_MTM_STANY_FLAGS(BYTE **ptr, UINT32 *length, MTM_STANY_FLAGS *v)
{
  if (tpm_marshal_TPM_TAG(ptr, length, v->tag)
      || tpm_marshal_BOOL(ptr, length, v->loadVerificationRootKeyEnabled)) return -1;
  return 0;
}

int tpm_unmarshal_MTM_STANY_FLAGS(BYTE **ptr, UINT32 *length, MTM_STANY_FLAGS *v)
{
  if (tpm_unmarshal_TPM_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BOOL(ptr, length, &v->loadVerificationRootKeyEnabled)) return -1;
  return 0;
}

int tpm_marshal_MTM_COUNTER_REFERENCE(BYTE **ptr, UINT32 *length, MTM_COUNTER_REFERENCE *v)
{
  if (tpm_marshal_BYTE(ptr, length, v->counterSelection)
      || tpm_marshal_TPM_ACTUAL_COUNT(ptr, length, v->counterValue)) return -1;
  return 0;
}

int tpm_unmarshal_MTM_COUNTER_REFERENCE(BYTE **ptr, UINT32 *length, MTM_COUNTER_REFERENCE *v)
{
  if (tpm_unmarshal_BYTE(ptr, length, &v->counterSelection)
      || tpm_unmarshal_TPM_ACTUAL_COUNT(ptr, length, &v->counterValue)) return -1;
  return 0;
}

int tpm_marshal_TPM_RIM_CERTIFICATE(BYTE **ptr, UINT32 *length, TPM_RIM_CERTIFICATE *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_BYTE_ARRAY(ptr, length, v->label, 8)
      || tpm_marshal_UINT32(ptr, length, v->rimVersion)
      || tpm_marshal_MTM_COUNTER_REFERENCE(ptr, length, &v->referenceCounter)
      || tpm_marshal_TPM_PCR_INFO_SHORT(ptr, length, &v->state)
      || tpm_marshal_UINT32(ptr, length, v->measurementPcrIndex)
      || tpm_marshal_TPM_PCRVALUE(ptr, length, &v->measurementValue)
      || tpm_marshal_TPM_VERIFICATION_KEY_ID(ptr, length, v->parentId)
      || tpm_marshal_BYTE(ptr, length, v->extensionDigestSize)
      || (v->extensionDigestSize > 0
          && tpm_marshal_BLOB(ptr, length, v->extensionDigestData, v->extensionDigestSize))
      || tpm_marshal_UINT32(ptr, length, v->integrityCheckSize)
      || (v->integrityCheckSize > 0
          && tpm_marshal_BLOB(ptr, length, v->integrityCheckData, v->integrityCheckSize))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_RIM_CERTIFICATE(BYTE **ptr, UINT32 *length, TPM_RIM_CERTIFICATE *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_BYTE_ARRAY(ptr, length, v->label, 8)
      || tpm_unmarshal_UINT32(ptr, length, &v->rimVersion)
      || tpm_unmarshal_MTM_COUNTER_REFERENCE(ptr, length, &v->referenceCounter)
      || tpm_unmarshal_TPM_PCR_INFO_SHORT(ptr, length, &v->state)
      || tpm_unmarshal_UINT32(ptr, length, &v->measurementPcrIndex)
      || tpm_unmarshal_TPM_PCRVALUE(ptr, length, &v->measurementValue)
      || tpm_unmarshal_TPM_VERIFICATION_KEY_ID(ptr, length, &v->parentId)
      || tpm_unmarshal_BYTE(ptr, length, &v->extensionDigestSize)
      || (v->extensionDigestSize > 0
          && tpm_unmarshal_BLOB(ptr, length, &v->extensionDigestData, v->extensionDigestSize))
      || tpm_unmarshal_UINT32(ptr, length, &v->integrityCheckSize)
      || (v->integrityCheckSize > 0
          && tpm_unmarshal_BLOB(ptr, length, &v->integrityCheckData, v->integrityCheckSize))) return -1;
  return 0;
}

int tpm_marshal_TPM_VERIFICATION_KEY(BYTE **ptr, UINT32 *length, TPM_VERIFICATION_KEY *v)
{
  if (tpm_marshal_TPM_STRUCTURE_TAG(ptr, length, v->tag)
      || tpm_marshal_UINT16(ptr, length, v->usageFlags)
      || tpm_marshal_TPM_VERIFICATION_KEY_ID(ptr, length, v->parentId)
      || tpm_marshal_TPM_VERIFICATION_KEY_ID(ptr, length, v->myId)
      || tpm_marshal_MTM_COUNTER_REFERENCE(ptr, length, &v->referenceCounter)
      || tpm_marshal_TPM_ALGORITHM_ID(ptr, length, v->keyAlgorithm)
      || tpm_marshal_TPM_SIG_SCHEME(ptr, length, v->keyScheme)
      || tpm_marshal_BYTE(ptr, length, v->extensionDigestSize)
      || (v->extensionDigestSize > 0
          && tpm_marshal_BLOB(ptr, length, v->extensionDigestData, v->extensionDigestSize))
      || tpm_marshal_UINT32(ptr, length, v->keySize)
      || (v->keySize > 0 && tpm_marshal_BLOB(ptr, length, v->keyData, v->keySize))
      || tpm_marshal_UINT32(ptr, length, v->integrityCheckSize)
      || (v->integrityCheckSize > 0
          && tpm_marshal_BLOB(ptr, length, v->integrityCheckData, v->integrityCheckSize))) return -1;
  return 0;
}

int tpm_unmarshal_TPM_VERIFICATION_KEY(BYTE **ptr, UINT32 *length, TPM_VERIFICATION_KEY *v)
{
  if (tpm_unmarshal_TPM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tpm_unmarshal_UINT16(ptr, length, &v->usageFlags)
      || tpm_unmarshal_TPM_VERIFICATION_KEY_ID(ptr, length, &v->parentId)
      || tpm_unmarshal_TPM_VERIFICATION_KEY_ID(ptr, length, &v->myId)
      || tpm_unmarshal_MTM_COUNTER_REFERENCE(ptr, length, &v->referenceCounter)
      || tpm_unmarshal_TPM_ALGORITHM_ID(ptr, length, &v->keyAlgorithm)
      || tpm_unmarshal_TPM_SIG_SCHEME(ptr, length, &v->keyScheme)
      || tpm_unmarshal_BYTE(ptr, length, &v->extensionDigestSize)
      || (v->extensionDigestSize > 0
          && tpm_unmarshal_BLOB(ptr, length, &v->extensionDigestData, v->extensionDigestSize))
      || tpm_unmarshal_UINT32(ptr, length, &v->keySize)
      || (v->keySize > 0 && tpm_unmarshal_BLOB(ptr, length, &v->keyData, v->keySize))
      || tpm_unmarshal_UINT32(ptr, length, &v->integrityCheckSize)
      || (v->integrityCheckSize > 0
          && tpm_unmarshal_BLOB(ptr, length, &v->integrityCheckData, v->integrityCheckSize))) return -1;
  return 0;
}

int tpm_marshal_MTM_KEY_DATA(BYTE **ptr, UINT32 *length, MTM_KEY_DATA *v)
{
  if (tpm_marshal_BOOL(ptr, length, v->valid)) return -1;
  if (v->valid) {
    if (tpm_marshal_UINT16(ptr, length, v->usageFlags)
        || tpm_marshal_TPM_VERIFICATION_KEY_ID(ptr, length, v->parentId)
        || tpm_marshal_TPM_VERIFICATION_KEY_ID(ptr, length, v->myId)
        || tpm_marshal_TPM_ALGORITHM_ID(ptr, length, v->keyAlgorithm)
        || tpm_marshal_TPM_SIG_SCHEME(ptr, length, v->keyScheme)
        || tpm_marshal_RSAPub(ptr, length, &v->key)) return -1;
  }
  return 0;
}

int tpm_unmarshal_MTM_KEY_DATA(BYTE **ptr, UINT32 *length, MTM_KEY_DATA *v)
{
  if (tpm_unmarshal_BOOL(ptr, length, &v->valid)) return -1;
  if (v->valid) {
    if (tpm_unmarshal_UINT16(ptr, length, &v->usageFlags)
        || tpm_unmarshal_TPM_VERIFICATION_KEY_ID(ptr, length, &v->parentId)
        || tpm_unmarshal_TPM_VERIFICATION_KEY_ID(ptr, length, &v->myId)
        || tpm_unmarshal_TPM_ALGORITHM_ID(ptr, length, &v->keyAlgorithm)
        || tpm_unmarshal_TPM_SIG_SCHEME(ptr, length, &v->keyScheme)
        || tpm_unmarshal_RSAPub(ptr, length, &v->key)) return -1;
  }
  return 0;
}

int tpm_marshal_MTM_DATA(BYTE **ptr, UINT32 *length, MTM_DATA *v)
{
  if (tpm_marshal_MTM_PERMANENT_DATA(ptr, length, &v->permanent.data)
      || tpm_marshal_MTM_STANY_FLAGS(ptr, length, &v->stany.flags)) return -1;
  return 0;
}

int tpm_unmarshal_MTM_DATA(BYTE **ptr, UINT32 *length, MTM_DATA *v)
{
  if (tpm_unmarshal_MTM_PERMANENT_DATA(ptr, length, &v->permanent.data)
      || tpm_unmarshal_MTM_STANY_FLAGS(ptr, length, &v->stany.flags)) return -1;
  return 0;
}


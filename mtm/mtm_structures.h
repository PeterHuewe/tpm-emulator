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

#ifndef _MTM_STRUCTURES_H_
#define _MTM_STRUCTURES_H_

#include "tpm/tpm_structures.h"
#include "crypto/sha1.h"

/*
 * Ordinals
 * The command ordinals provide the index value for each command.
 */
#define MTM_ORD_InstallRIM                      (66 + TPM_PROTECTED_COMMAND)
#define MTM_ORD_LoadVerificationKey             (67 + TPM_PROTECTED_COMMAND)
#define MTM_ORD_LoadVerificationRootKeyDisable  (68 + TPM_PROTECTED_COMMAND)
#define MTM_ORD_VerifyRIMCert                   (69 + TPM_PROTECTED_COMMAND)
#define MTM_ORD_VerifyRIMCertAndExtend          (72 + TPM_PROTECTED_COMMAND)
#define MTM_ORD_IncrementBootstrapCounter       (73 + TPM_PROTECTED_COMMAND)
#define MTM_ORD_SetVerifiedPCRSelection         (74 + TPM_PROTECTED_COMMAND)

/*
 * TPM_CAPABILITY_AREA Values for TPM_GetCapability
 */
#define TPM_CAP_MTM_PERMANENT_DATA        0x0000000A

/*
 * MTM_COUNTER_REFERENCE ([MTM], Section 5.1)
 * MTM counter reference structure
 */
#define MTM_COUNTER_SELECT_NONE           0
#define MTM_COUNTER_SELECT_BOOTSTRAP      1
#define MTM_COUNTER_SELECT_RIMPROTECT     2
#define MTM_COUNTER_SELECT_STORAGEPROTECT 3
#define MTM_COUNTER_SELECT_MAX            3
typedef struct MTM_COUNTER_REFERENCE_STRUCT {
  BYTE counterSelection;
  TPM_ACTUAL_COUNT counterValue;
} MTM_COUNTER_REFERENCE;
#define sizeof_MTM_COUNTER_REFERENCE(s) (1 + 4)

/*
 * TPM_VERIFICATION_KEY_ID ([MTM], Section 5.3)
 */
typedef UINT32 TPM_VERIFICATION_KEY_ID;
#define TPM_VERIFICATION_KEY_ID_NONE     0xFFFFFFFF
#define TPM_VERIFICATION_KEY_ID_INTERNAL 0xFFFFFFFE

/*
 * TPM_VERIFICATION_KEY_USAGE ([MTM], Section 5.3)
 */
#define TPM_VERIFICATION_KEY_USAGE_MTM_MASK            0x00ff
#define TPM_VERIFICATION_KEY_USAGE_AGENT_MASK          0x0f00
#define TPM_VERIFICATION_KEY_USAGE_VENDOR_MASK         0xf000
#define TPM_VERIFICATION_KEY_USAGE_SIGN_RIMCERT        0x0001
#define TPM_VERIFICATION_KEY_USAGE_SIGN_RIMAUTH        0x0002
#define TPM_VERIFICATION_KEY_USAGE_INCREMENT_BOOTSTRAP 0x0004

/*
 * TPM_VERIFICATION_KEY_HANDLE ([MTM], Section 5.3)
 * Handle used to refer to TPM_VERIFICATION_KEY structures
 */
typedef UINT32 TPM_VERIFICATION_KEY_HANDLE;

/*
 * TPM_VERIFICATION_KEY ([MTM], Section 5.3)
 * The TPM_VERIFICATION_KEY structure is used for representing keys in
 * the authorization hierarchy used to authorize RIM_Certs for a MTM.
 */
#define TPM_TAG_VERIFICATION_KEY 0x0301
typedef struct TPM_VERIFICATION_KEY_STRUCT {
  TPM_STRUCTURE_TAG tag;
  UINT16 usageFlags;
  TPM_VERIFICATION_KEY_ID parentId;
  TPM_VERIFICATION_KEY_ID myId;
  MTM_COUNTER_REFERENCE referenceCounter;
  TPM_ALGORITHM_ID keyAlgorithm;
  TPM_SIG_SCHEME keyScheme;
  BYTE extensionDigestSize;
  BYTE* extensionDigestData;
  UINT32 keySize;
  BYTE* keyData;
  UINT32 integrityCheckSize;
  BYTE* integrityCheckData;
} TPM_VERIFICATION_KEY;
#define sizeof_TPM_VERIFICATION_KEY(s) (2 + 2 + 4 + 4 \
  + sizeof_MTM_COUNTER_REFERENCE(s.referenceCounter) + 4 + 2 + 1 \
  + s.extensionDigestSize + 4 + s.keySize + 4 + s.integrityCheckSize)
#define free_TPM_VERIFICATION_KEY(s) { \
  if (s.extensionDigestSize > 0) tpm_free(s.extensionDigestData); \
  if (s.keySize > 0) tpm_free(s.keyData); \
  if (s.integrityCheckSize > 0) tpm_free(s.integrityCheckData); }

/*
 * TPM_RIM_CERTIFICATE ([MTM], Section 5.2)
 * A RIM Certificate is a structure authorizing a measurement value
 * that is extended using MTM_VerifyRIMCertAndExtend into a PCR
 * defined in the RIM Certificate.
 */
#define TPM_TAG_RIM_CERTIFICATE 0x0302
typedef struct TPM_RIM_CERTIFICATE_STRUCT {
  TPM_STRUCTURE_TAG tag;
  BYTE label[8];
  UINT32 rimVersion;
  MTM_COUNTER_REFERENCE referenceCounter;
  TPM_PCR_INFO_SHORT state;
  UINT32 measurementPcrIndex;
  TPM_PCRVALUE measurementValue;
  TPM_VERIFICATION_KEY_ID parentId;
  BYTE extensionDigestSize;
  BYTE *extensionDigestData;
  UINT32 integrityCheckSize;
  BYTE *integrityCheckData;
} TPM_RIM_CERTIFICATE;
#define sizeof_TPM_RIM_CERTIFICATE(s) (2 + 8 + 4 \
  + sizeof_MTM_COUNTER_REFERENCE(s.referenceCounter) \
  + sizeof_TPM_PCR_INFO_SHORT(s.state) \
  + 4 + 20 + 4 + 1 + s.extensionDigestSize \
  + 4 + s.integrityCheckSize)
#define free_TPM_RIM_CERTIFICATE(s) { \
  if (s.extensionDigestSize > 0) tpm_free(s.extensionDigestData); \
  if (s.integrityCheckSize > 0) tpm_free(s.integrityCheckData); }

/*
 * TPM_VERIFICATION_KEY_LOAD_METHODS ([MTM], Section 5.4)
 * Methods to load a TPM_VERIFICATION_KEY
 */
typedef BYTE TPM_VERIFICATION_KEY_LOAD_METHODS;
#define TPM_VERIFICATION_KEY_ROOT_LOAD                      0x01
#define TPM_VERIFICATION_KEY_INTEGRITY_CHECK_ROOT_DATA_LOAD 0x02
#define TPM_VERIFICATION_KEY_OWNER_AUTHORIZED_LOAD          0x04
#define TPM_VERIFICATION_KEY_CHAIN_AUTHORIZED_LOAD          0x08

/*
 * MTM_KEY_DATA
 * This structure contains the data for stored MTM verification keys.
 */
typedef struct MTM_KEY_DATA_STRUCT {
  BOOL valid;
  UINT16 usageFlags;
  TPM_VERIFICATION_KEY_ID parentId;
  TPM_VERIFICATION_KEY_ID myId;
  TPM_ALGORITHM_ID keyAlgorithm;
  TPM_SIG_SCHEME keyScheme;
  tpm_rsa_public_key_t key;
} MTM_KEY_DATA;
#define sizeof_MTM_KEY_DATA(s) ( \
  1 + 2 + 4 + 4 + 4 + 2 + sizeof_RSAPub(s.key))
#define free_MTM_KEY_DATA(s) { tpm_rsa_release_public_key(&s.key); }

/* 
 * MTM_PERMANENT_DATA ([MTM], Section 5.4)
 * The MTM_PERMANENT_DATA structure contains the permanent data associated
 * with a MTM that are used by the MTM commands. Note that there is an
 * alternative where there is only AIK but no EK defined.
 */
#define MTM_TAG_PERMANENT_DATA        0x0303
#define MTM_MAX_KEYS                  10
typedef struct MTM_PERMANENT_DATA_STRUCT {
  TPM_STRUCTURE_TAG tag;
  BYTE specMajor;
  BYTE specMinor;
  /* TPM_KEY aik; - not needed as the EK is always present */
  TPM_PCR_SELECTION verifiedPCRs;
  TPM_COUNT_ID counterRimProtectId;
  TPM_COUNT_ID counterStorageProtectId;
  TPM_VERIFICATION_KEY_LOAD_METHODS loadVerificationKeyMethods;
  BOOL integrityCheckRootValid;
  BYTE integrityCheckRootData[SHA1_DIGEST_LENGTH];
  TPM_SECRET internalVerificationKey;
  /* TPM_SECRET verificationAuth; - is a mirror of the ownerAuth */
  MTM_KEY_DATA keys[MTM_MAX_KEYS];
} MTM_PERMANENT_DATA;

static inline int sizeof_MTM_PERMANENT_DATA(MTM_PERMANENT_DATA *s)
{
  int i, size = 2 + 1 + 1 + 4 + 4 + 1 + 1 + 20;
  size += sizeof_TPM_PCR_SELECTION(s->verifiedPCRs);
  size += sizeof(s->integrityCheckRootData);
  for (i = 0; i < MTM_MAX_KEYS; i++) {
    if (s->keys[i].valid) {
      size += sizeof_MTM_KEY_DATA(s->keys[i]);
    } else {
      size += 1;
    }
  }
  return size;
}

static inline void free_MTM_PERMANENT_DATA(MTM_PERMANENT_DATA *s)
{
  int i;
  for (i = 0; i < MTM_MAX_KEYS; i++) {
    if (s->keys[i].valid) free_MTM_KEY_DATA(s->keys[i]);
  }
}

/*
 * The MTM_STANY_FLAGS structure houses additional flags that are
 * initialized by TPM_Init when the MTM boots.
 */
#define MTM_TAG_STANY_FLAGS 0x0304
typedef struct MTM_STANY_FLAGS_STRUCT {
  TPM_TAG tag;
  BOOL loadVerificationRootKeyEnabled;
} MTM_STANY_FLAGS;
#define sizeof_MTM_STANY_FLAGS(s) (2 + 1)

/*
 * MTM_DATA
 * Internal data of the MTM
 */
typedef struct tdMTM_DATA {
  struct {
    MTM_PERMANENT_DATA data;
  } permanent;
  // struct {
  // } stclear;
  struct {
    MTM_STANY_FLAGS flags;
  } stany;
} MTM_DATA;
#define sizeof_MTM_DATA(s) (sizeof_MTM_PERMANENT_DATA(&s.permanent.data) \
  + sizeof_MTM_STANY_FLAGS(s.stany.flags))
#define free_MTM_DATA(s) { free_MTM_PERMANENT_DATA(&s.permanent.data); }
 
#endif /* _MTM_STRUCTURES_H */


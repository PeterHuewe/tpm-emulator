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

#ifndef _MTM_COMMANDS_H_
#define _MTM_COMMANDS_H_

#include "mtm_structures.h"

/*
 * Modified TPM commands
 */

/**
 * MTM_Extend - adds a new measurement to a PCR
 * @pcrNum: [in] The PCR to be updated
 * @inDigest: [in] The 160 bit value representing the event to be recorded
 * @outDigest: [out] The PCR value after execution of the command
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 */
TPM_RESULT MTM_Extend(
  TPM_PCRINDEX pcrNum,
  TPM_DIGEST *inDigest,
  TPM_PCRVALUE *outDigest
);

/**
 * MTM_PCR_Reset - resets the indicated PCRs
 * @pcrSelection: [in] The PCRs to reset
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 */
TPM_RESULT MTM_PCR_Reset(
  TPM_PCR_SELECTION *pcrSelection
);

/**
 * MTM_GetCapability - provides current information regarding the TPM
 * @capArea: [in] Partition of capabilities to be interrogated
 * @subCapSize: [in] Size of subCap parameter
 * @subCap: [in] Further definition of information
 * @respSize: [out] The length of the returned capability response
 * @resp: [out] The capability response
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 */
TPM_RESULT MTM_GetCapability(
  TPM_CAPABILITY_AREA capArea,
  UINT32 subCapSize,
  BYTE *subCap,
  UINT32 *respSize,
  BYTE **resp
);

/**
 * MTM_ReleaseCounter - releases a counter
 * @countID: [in] ID value of the counter
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 */
TPM_RESULT MTM_ReleaseCounter(
  TPM_COUNT_ID countID,
  TPM_AUTH *auth1
);

/**
 * MTM_ReleaseCounterOwner - releases a counter
 * @countID: [in] ID value of the counter
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 */
TPM_RESULT MTM_ReleaseCounterOwner(
  TPM_COUNT_ID countID,
  TPM_AUTH *auth1
);

/**
 * MTM_FlushSpecific - flushes a specific handle
 * @handle: [in] Handle of the item to flush
 * @resourceType: [in] The type of resource that is being flushed
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 */
TPM_RESULT MTM_FlushSpecific(
  TPM_HANDLE handle,
  TPM_RESOURCE_TYPE resourceType
);

/*
 * Additional, MTM specific commands
 */

/**
 * MTM_InstallRIM - generates internal RIM certificates.
 * @rimCertIn: [in] Data to be used for internal RIM certificate
 * @auth1: [in, out] Authorization protocol parameters
 * @rimCertOut: [out] An internal RIM certificate
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([MTM_spec, v1.0], Section 7.2)
 */
TPM_RESULT MTM_InstallRIM(
  TPM_RIM_CERTIFICATE *rimCertIn,
  TPM_AUTH *auth1,
  TPM_RIM_CERTIFICATE *rimCertOut
);

/**
 * MTM_LoadVerificationKey - load one Verification Key into the MTM
 * @parentKey: [in] Parent key used to verify this key
 * @auth1: [in, out] Authorization protocol parameters
 * @verificationKeyHandle: [out] Handle for the key that was loaded
 * @loadMethod: [out] which method was used to load this verification key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([MTM_spec, v1.0], Section 7.3)
 */
TPM_RESULT MTM_LoadVerificationKey(
  TPM_VERIFICATION_KEY_HANDLE parentKey,
  TPM_VERIFICATION_KEY *verificationKey,
  TPM_AUTH *auth1,
  TPM_VERIFICATION_KEY_HANDLE *verificationKeyHandle,
  BYTE *loadMethod
);

/**
 * MTM_LoadVerificationRootKeyDisable - disables the functionality to load Verification Root Keys.
 * Returns: TPM_SUCCESS
 *
 * Description: ([MTM_spec, v1.0], Section 7.4)
 */
TPM_RESULT MTM_LoadVerificationRootKeyDisable();

/**
 * MTM_VerifyRIMCert - verify an internal or external RIM certificate.
 * @rimCert: [in] RIM certificate to be validated
 * @rimKey: [in] Key handle for the verification. NULL if internal verification key is used.
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([MTM_spec, v1.0], Section 7.5)
 */
TPM_RESULT MTM_VerifyRIMCert(
  TPM_RIM_CERTIFICATE* rimCert,
  TPM_VERIFICATION_KEY_HANDLE rimKey
);

/**
 * MTM_VerifyRIMCertAndExtend - verify an internal or external RIM certificate and extend PCR given in RIM certificate.
 * @rimCert: [in] RIM certificate to be validated
 * @rimKey: [in] Key handle for the verification key. NULL if internal verification key is used.
 * @outDigest: [out] The PCR value after the execution of the command
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([MTM_spec, v1.0], Section 7.6)
 */
TPM_RESULT MTM_VerifyRIMCertAndExtend(
  TPM_RIM_CERTIFICATE *rimCert,
  TPM_VERIFICATION_KEY_HANDLE rimKey,
  TPM_PCRVALUE *outDigest
);

/**
 * MTM_IncrementBootstrapCounter - increment bootstrap counter in MTM permanent data.
 * @rimCert: [in] A RIM certificate
 * @rimKey: [in] Key handle for the verification key to be used
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([MTM_spec, v1.0], Section 7.7)
 */
TPM_RESULT MTM_IncrementBootstrapCounter(
  TPM_RIM_CERTIFICATE *rimCert,
  TPM_VERIFICATION_KEY_HANDLE rimKey
);

/**
 * MTM_SetVerifiedPCRSelection - Set verifiedPCRs field in MTM_PERMANENT_DATA
 * @verifiedSelection: [in] Set of PCRs that can only be extended with this function
 * @auth1: [in, out]  Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([MTM_spec, v1.0], Section 7.8)
 */
TPM_RESULT MTM_SetVerifiedPCRSelection(
  TPM_PCR_SELECTION *verifiedSelection,
  TPM_AUTH *auth1
);

TPM_RESULT mtm_execute_command(TPM_REQUEST *req, TPM_RESPONSE *rsp);

#endif /* _MTM_COMMANDS_H_ */

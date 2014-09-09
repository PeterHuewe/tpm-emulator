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
 * $Id: tpm_commands.h 452 2010-07-19 19:05:05Z mast $
 */

#ifndef _TPM_COMMANDS_H_
#define _TPM_COMMANDS_H_

#include "tpm_structures.h"

/*
 * The following commands are specified in
 * TPM Main Part 3 Commands [TPM_Part3].
 */

/*
 * Admin Startup and State ([TPM_Part3], Section 3)
 * [tpm_startup.c]
 * This section describes the commands that start a TPM.
 */

/**
 * TPM_Init - initializes the TPM
 * @startupType: [in] Type of startup that is occurring
 * 
 * Description: ([TPM_Part3], Section 3.1)
 * TPM_Init is a "physical" method of initializing a TPM,  
 * there is no TPM_Init ordinal. 
 */
void TPM_Init(
  TPM_STARTUP_TYPE startupType
);

/**
 * TPM_Startup - starts the TPM
 * @startupType: [in] Type of startup that is occurring
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 3.2)
 * The TPM can startup in three different modes. (1) "clear" start where all 
 * variables go back to their default or non-volatile set state. (2) "save" 
 * start where the TPM recovers appropriate information and restores various 
 * values based on a prior TPM_SaveState. (3) "deactivated" start where the 
 * TPM turns itself off and requires another TPM_Init before the TPM will 
 * execute in a fully operational state.
 */
TPM_RESULT TPM_Startup(  
  TPM_STARTUP_TYPE startupType
);

/**
 * TPM_SaveState - saves the current state of the TPM 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 3.3)
 * This warns a TPM to save some state information. If the relevant shielded 
 * storage is non-volatile, this command need have no effect. If the relevant 
 * shielded storage is volatile and the TPM alone is unable to detect the loss 
 * of external power in time to move data to non-volatile memory, this command 
 * should be presented before the systems enters a low or no power state.
 */
TPM_RESULT TPM_SaveState(void);

/*
 * Admin Testing ([TPM_Part3], Section 4)
 * [tpm_testing.c]
 */

/**
 * TPM_SelfTestFull - tests all of the TPM capabilities
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 4.1)
 * Tests all of the TPM capabilities.
 */
TPM_RESULT TPM_SelfTestFull(void);

/**
 * TPM_ContinueSelfTest - continues a started self test
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 4.2)
 * Informs the TPM that it may complete the self test of all TPM functions.
 */
TPM_RESULT TPM_ContinueSelfTest(void);

/**
 * TPM_GetTestResult - provides the results of the self test
 * @outDataSize: [out] The size of the outData area 
 * @outData: [out] The outData this is manufacturer specific
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 4.3)
 * TPM_GetTestResult provides manufacturer specific information regarding the 
 * results of the self test. This command will also work when the TPM is in 
 * self test failure mode. 
 */
TPM_RESULT TPM_GetTestResult(  
  UINT32 *outDataSize,
  BYTE **outData  
);

/*
 * Admin Opt-in ([TPM_Part3], Section 5)
 * [tpm_owner.c]
 */

/**
 * TPM_SetOwnerInstall - sets the persistent owner-install flag
 * @state: [in] State to which ownership flag is to be set
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.1)
 * When enabled but without an owner this command sets the persistent flag 
 * that allows or disallows the ability to insert an owner.
 */
TPM_RESULT TPM_SetOwnerInstall(  
  BOOL state
);

/**
 * TPM_OwnerSetDisable - sets the persistent disable flag
 * @disableState: [in] Value for disable state, enable if TRUE
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.2)
 * The TPM owner sets the persistent disable flag.
 */
TPM_RESULT TPM_OwnerSetDisable(  
  BOOL disableState,
  TPM_AUTH *auth1
);

/**
 * TPM_PhysicalEnable - sets the persistent disable flag to FALSE
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.3)
 * Sets the persistent disable flag to FALSE using physical presence as 
 * authorization.
 */
TPM_RESULT TPM_PhysicalEnable(void);

/**
 * TPM_PhysicalDisable - sets the persistent disable flag to TRUE
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.4)
 * Sets the persistent disable flag to TRUE using physical presence as 
 * authorization.
 */
TPM_RESULT TPM_PhysicalDisable(void);

/**
 * TPM_PhysicalSetDeactivated - sets the deactivated flag
 * @state: [in] State to which deactivated flag is to be set
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.5)
 * Sets the deactivated flag using physical presence as authorization.
 */
TPM_RESULT TPM_PhysicalSetDeactivated(  
  BOOL state
);

/**
 * TPM_SetTempDeactivated - deactivates the TPM until the next boot
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.6)
 * This command allows the operator of the platform to deactivate the TPM until 
 * the next boot of the platform. The operator can provide the authorization by 
 * either the assertion of physical presence or presenting the operation 
 * authorization value.
 */
TPM_RESULT TPM_SetTempDeactivated(  
  TPM_AUTH *auth1
);

/**
 * TPM_SetOperatorAuth - sets the operator authorization value
 * @operatorAuth: [in] The operator authorization
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 5.7)
 * This command allows the setting of the operator authorization value. There 
 * is no confidentiality applied to the operator authorization as the value is 
 * sent under the assumption of being local to the platform. 
 */
TPM_RESULT TPM_SetOperatorAuth(  
  TPM_SECRET *operatorAuth
);

/*
 * Admin Ownership ([TPM_Part3], Section 6)
 * [tpm_owner.c]
 */

/**
 * TPM_TakeOwnership - inserts the TPM Ownership value into the TPM
 * @protocolID: [in] The ownership protocol in use
 * @encOwnerAuthSize: [in] The size of the encOwnerAuth field
 * @encOwnerAuth: [in] The owner authorization data encrypted with PUBEK
 * @encSrkAuthSize: [in] The size of the encSrkAuth field
 * @encSrkAuth: [in] The SRK authorization data encrypted with PUBEK
 * @srkParams: [in] All parameters of the new SRK
 * @auth1: [in, out] Authorization protocol parameters
 * @srkPub: [out] All parameters of the new SRK
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.1)
 * This command inserts the TPM Ownership value into the TPM.
 */
TPM_RESULT TPM_TakeOwnership(  
  TPM_PROTOCOL_ID protocolID,
  UINT32 encOwnerAuthSize,
  BYTE *encOwnerAuth,
  UINT32 encSrkAuthSize,
  BYTE *encSrkAuth,
  TPM_KEY *srkParams,
  TPM_AUTH *auth1,
  TPM_KEY *srkPub
);

/**
 * tpm_owner_clear - owner clear operation
 */
void tpm_owner_clear(void);

/**
 * TPM_OwnerClear - performs the clear operation
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.2)
 * This command performs the clear operation under Owner authorization. It 
 * is available until the Owner executes the DisableOwnerClear, at which 
 * time any further invocation of this command returns TPM_CLEAR_DISABLED.
 */
TPM_RESULT TPM_OwnerClear(  
  TPM_AUTH *auth1
);

/**
 * TPM_ForceClear - forces the clear operation
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.3)
 * This command performs the clear operation under physical access. It is
 * available until the execution of DisableForceClear, at which time any 
 * further invocation of this command returns TPM_CLEAR_DISABLED.
 */
TPM_RESULT TPM_ForceClear(void);

/**
 * TPM_DisableOwnerClear - disables the ability to execute TPM_OwnerClear
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.4)
 * This command disables the ability to execute the TPM_OwnerClear command 
 * permanently. Once invoked the only method of clearing the TPM will require 
 * physical access to the TPM. 
 */
TPM_RESULT TPM_DisableOwnerClear(  
  TPM_AUTH *auth1
);

/**
 * TPM_DisableForceClear - disables the ability to execute TPM_ForceClear
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.5)
 * The DisableForceClear command disables the execution of the ForceClear 
 * command until the next startup cycle. Once this command is executed, 
 * the TPM_ForceClear is disabled until another startup cycle is run.
 */
TPM_RESULT TPM_DisableForceClear(void);

/**
 * TSC_PhysicalPresence - sets the physical presence flag
 * @physicalPresence: [in] The state to set the TPM's Physical Presence flags
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.6)
 * This command allows a process on the platform to indicate the assertion 
 * of physical presence. 
 */
TPM_RESULT TSC_PhysicalPresence(  
  TPM_PHYSICAL_PRESENCE physicalPresence
);

/**
 * TSC_ResetEstablishmentBit - resets the establishment bit
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 6.7)
 * The PC TPM Interface Specification (TIS) specifies a bit that is set upon 
 * execution of the HASH_START sequence. This command allows for the resetting 
 * of the bit under controlled circumstances.
 */
TPM_RESULT TSC_ResetEstablishmentBit(void);

/*
 * The GetCapability Commands ([TPM_Part3], Section 7)
 * [tpm_capability.c]
 * The GetCapability command allows the TPM to report back to the requester 
 * what type of TPM it is dealing with. The request for information requires 
 * the requester to specify which piece of information that is required. 
 */

/**
 * TPM_GetCapability - provides current information regarding the TPM
 * @capArea: [in] Partition of capabilities to be interrogated
 * @subCapSize: [in] Size of subCap parameter 
 * @subCap: [in] Further definition of information
 * @respSize: [out] The length of the returned capability response 
 * @resp: [out] The capability response
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 7.1)
 * This command provides current information regarding the TPM.
 */
TPM_RESULT TPM_GetCapability(
  TPM_CAPABILITY_AREA capArea,
  UINT32 subCapSize,
  BYTE *subCap,
  UINT32 *respSize,
  BYTE **resp
);

/**
 * TPM_SetCapability - sets values in the TPM
 * @capArea: [in] Partition of capabilities to be set
 * @subCapSize: [in] Size of subCap parameter
 * @subCap: [in] Further definition of information
 * @setValueSize: [in] Size of the value to set
 * @setValue: [in] Value to set
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 7.2)
 * This command sets values in the TPM.
 */
TPM_RESULT TPM_SetCapability(
  TPM_CAPABILITY_AREA capArea,
  UINT32 subCapSize,
  BYTE *subCap,
  UINT32 setValueSize,
  BYTE *setValue,
  TPM_AUTH *auth1
);

/**
 * TPM_GetCapabilityOwner (deprecated)
 * @auth1: [in, out] Authorization protocol parameters
 * @version: [out] Properly filled out version structure
 * @non_volatile_flags: [out] Current state of the non-volatile flags
 * @volatile_flags: [out] Current state of the volatile flags
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 7.3)
 * This command is deprecated.
 */
TPM_RESULT TPM_GetCapabilityOwner(
  TPM_AUTH *auth1,
  TPM_VERSION *version,
  UINT32 *non_volatile_flags,
  UINT32 *volatile_flags
);

/*
 * Auditing ([TPM_Part3], Section 8)
 * [tpm_audit.c]
 * The TPM generates an audit event in response to the TPM executing a 
 * function that has the audit flag set to TRUE for that function. The 
 * TPM maintains an extended value for all audited operations. 
 */

/**
 * tpm_audit_request - audits a TPM request
 * @ordinal: [in] The ordinal of the request
 * @req: [in] The request to audit
 */
void tpm_audit_request(
  TPM_COMMAND_CODE ordinal, 
  TPM_REQUEST *req
);

/**
 * tpm_audit_response - audits a TPM response
 * @ordinal: [in] The ordinal of the response
 * @rsp: [in] The response to audit
 */
void tpm_audit_response(
  TPM_COMMAND_CODE ordinal, 
  TPM_RESPONSE *rsp
);

/**
 * TPM_GetAuditDigest - provides the current audit digest
 * @startOrdinal: [in] The starting ordinal for the list of audited ordinals
 * @counterValue: [out] The current value of the audit monotonic counter
 * @auditDigest: [out] Log of all audited events
 * @more: [out] TRUE if the output does not contain all audited ordinals
 * @ordSize: [out] Size of the ordinal list in bytes
 * @ordList: [out] List of ordinals that are audited
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 8.3)
 * This provides the current audit digest. The external audit log has the 
 * responsibility to track the parameters that constitute the audit digest. 
 */
TPM_RESULT TPM_GetAuditDigest(  
  UINT32 startOrdinal,  
  TPM_COUNTER_VALUE *counterValue,
  TPM_DIGEST *auditDigest,
  BOOL *more,
  UINT32 *ordSize,
  UINT32 **ordList  
);

/**
 * TPM_GetAuditDigestSigned - provides the current (signed) audit digest
 * @keyHandle: [in] Handle of a loaded key that can perform digital signatures
 * @closeAudit: [in] Indication if audit session should be closed
 * @antiReplay: [in] A nonce to prevent replay attacks
 * @auth1: [in, out] Authorization protocol parameters
 * @counterValue: [out] The value of the audit monotonic counter
 * @auditDigest: [out] Log of all audited events
 * @ordinalDigest: [out] Digest of all audited ordinals
 * @sigSize: [out] The size of the sig parameter
 * @sig: [out] The signature of the area
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 8.4)
 * The signing of the audit log provides the entire digest value and the list 
 * of currently audited commands. The inclusion of the list of audited commands 
 * as an atomic operation is to tie the current digest value with the list of 
 * commands that are being audited. 
 */
TPM_RESULT TPM_GetAuditDigestSigned(  
  TPM_KEY_HANDLE keyHandle,
  BOOL closeAudit,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,  
  TPM_COUNTER_VALUE *counterValue,
  TPM_DIGEST *auditDigest,
  TPM_DIGEST *ordinalDigest,
  UINT32 *sigSize,
  BYTE **sig  
);

/**
 * TPM_SetOrdinalAuditStatus - set the audit flag for a given ordinal
 * @ordinalToAudit: [in] The ordinal whose audit flag is to be set
 * @auditState: [in] Value for audit flag
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 8.5)
 * Set the audit flag for a given ordinal. This command requires the 
 * authorization of the TPM Owner.
 */
TPM_RESULT TPM_SetOrdinalAuditStatus(  
  TPM_COMMAND_CODE ordinalToAudit,
  BOOL auditState,
  TPM_AUTH *auth1
);

/*
 * Administrative Functions ([TPM_Part3], Section 9)
 * [tpm_management.c]
 */

/**
 * TPM_FieldUpgrade - updates the protected capabilities
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 9.1)
 * This command provides a manufacturer specific method of updating
 * the protected capabilities
 */
TPM_RESULT TPM_FieldUpgrade(void);

/**
 * TPM_SetRedirection - attaches a key to a redirection receiver
 * @keyHandle: [in] Handle of a loaded key that can implement redirection
 * @redirCmd: [in] The command to execute
 * @inputDataSize: [in] The size of the input data
 * @inputData: [in] Manufacturer parameter
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 9.2)
 */
TPM_RESULT TPM_SetRedirection(
  TPM_KEY_HANDLE keyHandle,
  TPM_REDIR_COMMAND redirCmd,
  UINT32 inputDataSize,
  BYTE *inputData,
  TPM_AUTH *auth1
);

/**
 * TPM_ResetLockValue - resets the TPM dictionary attack mitigation values
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 9.3)
 */
TPM_RESULT TPM_ResetLockValue(
  TPM_AUTH *auth1
);

/*
 * Storage functions ([TPM_Part3], Section 10)
 * [tpm_storage.c]
 */

/**
 * TPM_Seal - seals the TPM configuration
 * @keyHandle: [in] Handle of a loaded key that can perform seal operations
 * @encAuth: [in] The encrypted authorization data for the sealed data
 * @pcrInfoSize: [in] The size of the pcrInfo parameter
 * @pcrInfo: [in] The PCR selection information
 * @inDataSize: [in] The size of the inData parameter
 * @inData: [in] The data to be sealed to the platform and any specified PCRs
 * @auth1: [in, out] Authorization protocol parameters
 * @sealedData: [out] Encrypted, integrity-protected data object
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.1)
 * The Seal operation allows software to explicitly state the future trusted
 * configuration that the platform must be in for the secret to be revealed.
 */
TPM_RESULT TPM_Seal(
  TPM_KEY_HANDLE keyHandle,
  TPM_ENCAUTH *encAuth,
  UINT32 pcrInfoSize,
  TPM_PCR_INFO *pcrInfo,
  UINT32 inDataSize,
  BYTE *inData,
  TPM_AUTH *auth1,
  TPM_STORED_DATA *sealedData
);

/**
 * TPM_Unseal - unseals the TPM configuration
 * @parentHandle: [in] Handle of a loaded key that can unseal the data
 * @inData: [in] The encrypted data generated by TPM_Seal
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @sealedDataSize: [out] The used size of the output area for secret
 * @secret: [out] Decrypted data that had been sealed
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.2)
 * The Unseal operation will reveal TPM_Sealed data only if it was encrypted 
 * on this platform and the current configuration (as defined by the named PCR 
 * contents) is the one named as qualified to decrypt it.
 */
TPM_RESULT TPM_Unseal(
  TPM_KEY_HANDLE parentHandle,
  TPM_STORED_DATA *inData,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  UINT32 *sealedDataSize,
  BYTE **secret
);

/**
 * TPM_UnBind - decrypts the result of a TSS_Bind command
 * @keyHandle: [in] Handle of a loaded key that can perform UnBind operations
 * @inDataSize: [in] The size of the input blob
 * @inData: [in] Encrypted blob to be decrypted
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The length of the returned decrypted data
 * @outData: [out] The resulting decrypted data
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.3)
 * TPM_UnBind takes the data blob that is the result of a TSS_Bind command and
 * decrypts it for export to the User. The caller must authorize the use of the
 * key that will decrypt the incoming blob. UnBInd operates on a block-by-block
 * basis, and has no notion of any relation between one block and another.
 */
TPM_RESULT TPM_UnBind(
  TPM_KEY_HANDLE keyHandle,
  UINT32 inDataSize,
  BYTE *inData,
  TPM_AUTH *auth1,
  UINT32 *outDataSize,
  BYTE **outData
);

/**
 * TPM_CreateWrapKey - generates and creates a wrapped asymmetric key
 * @parentHandle: [in] Handle of a loaded key that can perform key wrapping
 * @dataUsageAuth: [in] Encrypted usage authorization data
 * @dataMigrationAuth: [in] Encrypted migration authorization data
 * @keyInfo: [in] Information about key to be created
 * @auth1: [in, out] Authorization protocol parameters
 * @wrappedKey: [out] The public and encrypted private key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.4)
 * The TPM_CreateWrapKey command both generates and creates a secure storage
 * bundle for asymmetric keys. The newly created key can be locked to a
 * specific PCR value by specifying a set of PCR registers.
 */
TPM_RESULT TPM_CreateWrapKey(
  TPM_KEY_HANDLE parentHandle,
  TPM_ENCAUTH *dataUsageAuth,
  TPM_ENCAUTH *dataMigrationAuth,
  TPM_KEY *keyInfo,
  TPM_AUTH *auth1,
  TPM_KEY *wrappedKey
);

/**
 * TPM_LoadKey - loads a key into the TPM for further use
 * @parentHandle: [in] TPM handle of parent key
 * @inKey: [in] Incoming key structure, both private and public portions
 * @auth1: [in, out] Authorization protocol parameters
 * @inkeyHandle: [out] Internal TPM handle where decrypted key was loaded
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.5)
 * Before the TPM can use a key to either wrap, unwrap, bind, unbind, seal,
 * unseal, sign or perform any other action, it needs to be present in the
 * TPM. The TPM_LoadKey function loads the key into the TPM for further use.
 */
TPM_RESULT TPM_LoadKey(
  TPM_KEY_HANDLE parentHandle,
  TPM_KEY *inKey,
  TPM_AUTH *auth1,
  TPM_KEY_HANDLE *inkeyHandle
);

/**
 * TPM_LoadKey2 - loads a key into the TPM for further use
 * @parentHandle: [in] TPM handle of parent key
 * @inKey: [in] Incoming key structure, both private and public portions
 * @auth1: [in, out] Authorization protocol parameters
 * @inkeyHandle: [out] Internal TPM handle where decrypted key was loaded
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.5)
 * Before the TPM can use a key to either wrap, unwrap, bind, unbind, seal,
 * unseal, sign or perform any other action, it needs to be present in the
 * TPM. The TPM_LoadKey function loads the key into the TPM for further use.
 */
TPM_RESULT TPM_LoadKey2(
  TPM_KEY_HANDLE parentHandle,
  TPM_KEY *inKey,
  TPM_AUTH *auth1,
  TPM_KEY_HANDLE *inkeyHandle
);

/**
 * TPM_GetPubKey - provides the public key value from a loaded key
 * @keyHandle: [in] TPM handle of key
 * @auth1: [in, out] Authorization protocol parameters
 * @pubKey: [out] Public portion of key in keyHandle
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.6)
 * The owner of a key may wish to obtain the public key value from a loaded
 * key. This information may have privacy concerns so the command must have
 * authorization from the key owner.
 */
TPM_RESULT TPM_GetPubKey(
  TPM_KEY_HANDLE keyHandle,
  TPM_AUTH *auth1,
  TPM_PUBKEY *pubKey
);

/**
 * TPM_Sealx - seals encrypted data to a TPM configuration
 * @keyHandle: [in] Handle of a loaded key that can perform seal operations
 * @encAuth: [in] The encrypted authorization data for the sealed data
 * @pcrInfoSize: [in] The size of the pcrInfo parameter
 * @pcrInfo: [in] The PCR selection information (MUST be TPM_PCR_INFO_LONG)
 * @inDataSize: [in] The size of the inData parameter
 * @inData: [in] The data to be sealed to the platform and any specified PCRs
 * @auth1: [in, out] Authorization protocol parameters
 * @sealedData: [out] Encrypted, integrity-protected data object
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 10.7)
 * The SEALX command works exactly like the SEAL command with the additional
 * requirement of encryption for the inData parameter. This command also
 * places in the sealed blob the information that the unseal also requires
 * encryption.
 */
TPM_RESULT TPM_Sealx(
  TPM_KEY_HANDLE keyHandle,
  TPM_ENCAUTH *encAuth,
  UINT32 pcrInfoSize,
  TPM_PCR_INFO *pcrInfo,
  UINT32 inDataSize,
  BYTE *inData,
  TPM_AUTH *auth1,
  TPM_STORED_DATA *sealedData
);

/**
 * tpm_get_free_key - allocates a new key slot
 * Returns: the key handle on success, TPM_INVALID_HANDLE otherwise.

 */
TPM_KEY_HANDLE tpm_get_free_key(void);

/**
 * tpm_encrypt_public - encrypts the input data with the specified public key
 * @key: [in], Public key
 * @in: [in] Input data to encrypt
 * @in_size: [in] Size of the input data
 * @enc: [out] Encrypted data
 * @enc_size: [out] Size of the encrypted data
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_encrypt_public(
  TPM_PUBKEY_DATA *key,
  BYTE *in,
  UINT32 in_size,
  BYTE *enc,
  UINT32 *enc_size
);

/**
 * tpm_encrypt_private - encrypts the input data with the specified private key
 * @key: [in], Private key
 * @in: [in] Input data to encrypt
 * @in_size: [in] Size of the input data
 * @enc: [out] Encrypted data
 * @enc_size: [out] Size of the encrypted data
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_encrypt_private(
  TPM_KEY_DATA *key,
  BYTE *in,
  UINT32 in_size,
  BYTE *enc,
  UINT32 *enc_size
);

/**
 * tpm_decrypt - decrypts the input data with the specified private key
 * @key: [in], Private key
 * @enc: [in] Encrypted data
 * @enc_size: [in] Size of the encrypted data
 * @out: [out] Decrypted data
 * @out_size: [out] Size of the decrypted data
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_decrypt(
  TPM_KEY_DATA *key,
  BYTE *enc,
  UINT32 enc_size,
  BYTE *out,
  UINT32 *out_size
);

/**
 * tpm_encrypt_sealed_data - encrypts a TPM_SEALED_DATA structure
 * @key: [in], Private key
 * @seal: [in] Structure to encrypt
 * @enc: [out] Encrypted structure
 * @enc_size: [out] Size of the encrypted structure
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_encrypt_sealed_data(
  TPM_KEY_DATA *key,
  TPM_SEALED_DATA *seal,
  BYTE *enc,
  UINT32 *enc_size
);

/**
 * tpm_decrypt_sealed_data - decrypts a TPM_SEALED_DATA structure
 * @key: [in], Private key
 * @enc: [in] Encrypted structure
 * @enc_size: [in] Size of the encrypted structure
 * @seal: [out] Decrypted structure
 * @buf: [out] Buffer for the decrypted structure (to be freed by the caller)
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_decrypt_sealed_data(
  TPM_KEY_DATA *key,
  BYTE *enc,
  UINT32 enc_size,
  TPM_SEALED_DATA *seal,
  BYTE **buf
);

/**
 * tpm_encrypt_sealed_data - encrypts a TPM_STORE_ASYMKEY structure
 * @key: [in], Private key
 * @store: [in] Structure to encrypt
 * @enc: [out] Encrypted structure
 * @enc_size: [out] Size of the encrypted structure
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_encrypt_private_key(
  TPM_KEY_DATA *key,
  TPM_STORE_ASYMKEY *store,
  BYTE *enc,
  UINT32 *enc_size
);

/**
 * tpm_decrypt_sealed_data - decrypts a TPM_STORE_ASYMKEY structure
 * @key: [in], Private key
 * @enc: [in] Encrypted structure
 * @enc_size: [in] Size of the encrypted structure
 * @store: [out] Decrypted structure
 * @buf: [out] Buffer for the decrypted structure (to be freed by the caller)
 * @buf_size: [out] Size of the buffer
 * Returns: 0 on success, -1 otherwise.
 */
int tpm_decrypt_private_key(
  TPM_KEY_DATA *key,
  BYTE *enc,
  UINT32 enc_size,
  TPM_STORE_ASYMKEY *store,
  BYTE **buf,
  UINT32 *buf_size
);

/**
 * tpm_compute_key_digest - computes the digest of a key
 * @key: [in] Key
 * @digest: [out] Digest of the key
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_compute_key_digest(
  TPM_KEY *key,
  TPM_DIGEST *digest
);

/**
 * tpm_compute_key_data_digest - computes the digest of the public part of a key
 * @key: [in] Key
 * @digest: [out] Digest of the key
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_compute_key_data_digest(
  TPM_KEY_DATA *key,
  TPM_DIGEST *digest
);

/**
 * tpm_compute_pubkey_checksum - computes the checksum of a public key
 * @antiReplay: [in] Nonce to prevent replay of messages
 * @pubKey: [in] Public key
 * @checksum: [out] Checksum of the public key and the nonce
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_compute_pubkey_checksum(
  TPM_NONCE *antiReplay,
  TPM_PUBKEY *pubKey,
  TPM_DIGEST *checksum
);

/**
 * tpm_compute_pubkey_digest - computes the digest of a public key
 * @key: [in] Public key
 * @digest: [out] Digest of the key
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_compute_pubkey_digest(
  TPM_PUBKEY *key,
  TPM_DIGEST *digest
);

/**
 * tpm_setup_key_parms - sets the key parameters according to the given key
 * @key: [in] Key
 * @params: [out] Key parameters to set
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_setup_key_parms(
  TPM_KEY_DATA *key,
  TPM_KEY_PARMS *parms
);

/**
 * tpm_setup_pubkey_data - creates an internal public key based on the given key
 * @in: [in] Public Key of type TPM_PUBKEY
 * @out: [out] Internal public key of type TPM_PUBKEY_DATA
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_setup_pubkey_data(
  TPM_PUBKEY *in,
  TPM_PUBKEY_DATA *out
);

/**
 * tpm_extract_pubkey - extracts the public part of the specified key
 * @in: [in] Key
 * @out: [out] Public key
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_extract_pubkey(
  TPM_KEY_DATA *key,
  TPM_PUBKEY *pubKey
);

/**
 * tpm_extract_store_pubkey - extracts the public part of the specified key
 * @in: [in] Key
 * @out: [out] Public key
 * @Returns: 0 on success, -1 otherwise.
 */
int tpm_extract_store_pubkey(
  TPM_KEY_DATA *key,
  TPM_STORE_PUBKEY *pubKey
);

/**
 * internal_TPM_LoadKey - loads the specified key into the TPM
 * @inKey: [in] Incoming key structure, both private and public portions
 * @inkeyHandle: [out] Internal TPM handle where decrypted key was loaded
 */
TPM_RESULT internal_TPM_LoadKey(
  TPM_KEY *inKey,
  TPM_KEY_HANDLE *inkeyHandle
);

/*
 * Migration ([TPM_Part3], Section 11)
 * [tpm_migration.c]
 */

/**
 * TPM_CreateMigrationBlob - creates a migration blob
 * @parentHandle: [in] Handle of the parent key that can decrypt encData
 * @migrationType: [in] The migration type, either MIGRATE or REWRAP
 * @migrationKeyAuth: [in] Migration public key and its authorization digest
 * @encDataSize: [in] The size of the encData parameter
 * @encData: [in] The encrypted entity that is to be modified
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @randomSize: [out] The used size of the output area for random
 * @random: [out] String used for xor encryption 
 * @outDataSize: [out] The used size of the output area for outData
 * @outData: [out] The modified, encrypted entity
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.1)
 * The TPM_CreateMigrationBlob command implements the first step in the
 * process of moving a migratable key to a new parent or platform.
 */
TPM_RESULT TPM_CreateMigrationBlob(
  TPM_KEY_HANDLE parentHandle,
  TPM_MIGRATE_SCHEME migrationType,
  TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  UINT32 *randomSize,
  BYTE **random,
  UINT32 *outDataSize,
  BYTE **outData
);

/**
 * TPM_ConvertMigrationBlob - converts a migration into a wrapped blob
 * @parentHandle: [in] Handle of a loaded key that can decrypt keys
 * @inDataSize: [in] Size of inData
 * @inData: [in] The XOR d and encrypted key
 * @randomSize: [in] Size of random
 * @random: [in] Random value used to hide key data
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The used size of the output area for outData
 * @outData: [out] The encrypted private key that can be loaded with LoadKey
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.2)
 * This command takes a migration blob and creates a normal wrapped blob.
 * The migrated blob must be loaded into the TPM using the normal TPM_LoadKey
 * function. Note that the command migrates private keys, only.
 */
TPM_RESULT TPM_ConvertMigrationBlob(
  TPM_KEY_HANDLE parentHandle,
  UINT32 inDataSize,
  BYTE *inData,
  UINT32 randomSize,
  BYTE *random,
  TPM_AUTH *auth1,
  UINT32 *outDataSize,
  BYTE **outData
);

/**
 * TPM_AuthorizeMigrationKey - creates an authorization blob
 * @migrateScheme: [in] Migration operation that is to be permitted for this key
 * @migrationKey: [in] The public key to be authorized
 * @auth1: [in, out] Authorization protocol parameters
 * @outData: [out] Returned public key and authorization digest
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.3)
 * This command creates an authorization blob, to allow the TPM owner to
 * specify which migration facility they will use and allow users to migrate
 * information without further involvement with the TPM owner.
 */
TPM_RESULT TPM_AuthorizeMigrationKey(
  TPM_MIGRATE_SCHEME migrateScheme,
  TPM_PUBKEY *migrationKey,
  TPM_AUTH *auth1,
  TPM_MIGRATIONKEYAUTH *outData
);

/**
 * TPM_MigrateKey - performs the function of a migration authority
 * @maKeyHandle: [in] Handle of the key to be used to migrate the key
 * @pubKey: [in] Public key to which the blob is to be migrated
 * @inDataSize: [in] The size of inData
 * @inData: [in] The input blob
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The used size of the output area for outData
 * @outData: [out] The re-encrypted blob
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.4)
 */
TPM_RESULT TPM_MigrateKey(
  TPM_KEY_HANDLE maKeyHandle,
  TPM_PUBKEY *pubKey,
  UINT32 inDataSize,
  BYTE *inData,
  TPM_AUTH *auth1,
  UINT32 *outDataSize,
  BYTE **outData
);

/**
 * TPM_CMK_SetRestrictions - dictates the usage of a restricted migration key
 * @restriction: [in] The bit mask of how to set the restrictions on CMK keys
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.5)
 * This command is used by the Owner to dictate the usage of a restricted-
 * migration key with delegated authorisation (authorisation other than actual
 * Owner authorisation).
 */
TPM_RESULT TPM_CMK_SetRestrictions(
  TPM_CMK_DELEGATE restriction,
  TPM_AUTH *auth1
);

/**
 * TPM_CMK_ApproveMA - creates an authorization ticket
 * @migrationAuthorityDigest: [in] A digest of a TPM_MSA_COMPOSITE structure
 * @auth1: [in, out] Authorization protocol parameters
 * @outData: [out] HMAC of the migrationAuthorityDigest
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.6)
 */
TPM_RESULT TPM_CMK_ApproveMA(
  TPM_DIGEST *migrationAuthorityDigest,
  TPM_AUTH *auth1,
  TPM_HMAC *outData
);

/**
 * TPM_CMK_CreateKey - generates and creates a wrapped CMK
 * @parentHandle: [in] Handle of a loaded key that can perform key wrapping
 * @dataUsageAuth: [in] Encrypted usage authorization data for the sealed data
 * @keyInfo: [in] Information about key to be created
 * @migrationAuthorityApproval: [in] A ticket created by the TPM owner
 * @migrationAuthorityDigest: [in] The digest of the public key of the MSA or MA
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @wrappedKey: [out] The public and encrypted private key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.7)
 * The TPM_CreateWrapRestrictedKey command both generates and creates a
 * secure storage bundle for asymmetric keys whose migration is controlled
 * by a migration authority.
 */
TPM_RESULT TPM_CMK_CreateKey(
  TPM_KEY_HANDLE parentHandle,
  TPM_ENCAUTH *dataUsageAuth,
  TPM_KEY *keyInfo,
  TPM_HMAC *migrationAuthorityApproval,
  TPM_DIGEST *migrationAuthorityDigest,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_KEY *wrappedKey
);

/**
 * TPM_CMK_CreateTicket - creates a ticket for proving a signature verification
 * @verificationKey: [in] The public key to be used to check signatureValue
 * @signedData: [in] The data proported to be signed
 * @signatureValueSize: [in] The size of the signatureValue
 * @signatureValue: [in] The signatureValue to be verified
 * @auth1: [in, out] Authorization protocol parameters
 * @sigTicket: [out] Ticket that proves digest created on this TPM
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.8)
 * The TPM_verifySignature command uses a public key to verify the signature
 * over a digest. TPM_verifySignature provides a ticket that can be used to
 * prove to the same TPM that signature verification with a particular public
 * key was successful.
 */
TPM_RESULT TPM_CMK_CreateTicket(
  TPM_PUBKEY *verificationKey,
  TPM_DIGEST *signedData,
  UINT32 signatureValueSize,
  BYTE *signatureValue,
  TPM_AUTH *auth1,
  TPM_DIGEST *sigTicket
);

/**
 * TPM_CMK_CreateBlob - creates a migration blob
 * @parentHandle: [in] Handle of the parent key that can decrypt encData
 * @migrationType: [in] The migration type
 * @migrationKeyAuth: [in] Migration public key and its authorization digest
 * @pubSourceKeyDigest: [in] Digest of the entity's public key to be migrated
 * @msaList: [in] Digests of public keys belonging to MAs
 * @restrictTicket: [in] The digests of the public keys
 * @sigTicket: [in] A signature ticket, generate by the TPM
 * @encDataSize: [in] The size of the encData parameter
 * @encData: [in] The encrypted entity that is to be modified
 * @auth1: [in, out] Authorization protocol parameters
 * @randomSize: [out] The used size of the output area for random
 * @random: [out] String used for xor encryption
 * @outDataSize: [out] The used size of the output area for outData
 * @outData: [out] The modified, encrypted entity
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.9)
 * TPM_CMK_CreateBlob command is very similar to TPM_CreateMigrationBlob,
 * except that it (1) uses an extra ticket (restrictedKeyAuth) instead
 * of a migrationAuth authorization session; (2) uses the migration options
 * TPM_MS_RESTRICT_MIGRATE or TPM_MS_RESTRICT_APPROVE.
 */
TPM_RESULT TPM_CMK_CreateBlob(
  TPM_KEY_HANDLE parentHandle,
  TPM_MIGRATE_SCHEME migrationType,
  TPM_MIGRATIONKEYAUTH *migrationKeyAuth,
  TPM_DIGEST *pubSourceKeyDigest,
  TPM_MSA_COMPOSITE *msaList,
  TPM_CMK_AUTH *restrictTicket,
  TPM_HMAC *sigTicket,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,
  UINT32 *randomSize,
  BYTE **random,
  UINT32 *outDataSize,
  BYTE **outData
);

/**
 * TPM_CMK_ConvertMigration - completes the migration of certified blobs
 * @parentHandle: [in] Handle of a loaded key that can decrypt keys
 * @restrictTicket: [in] The digests of the public keys
 * @sigTicket: [in] A signature ticket, generated by the TPM
 * @migratedKey: [in] The public key of the key to be migrated
 * @msaList: [in] One or more digests of public keys belonging to MAs
 * @randomSize: [in] Size of random
 * @random: [in] Random value used to hide key data
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The used size of the output area for outData
 * @outData: [out] The encrypted private key that can be loaded
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 11.10)
 */
TPM_RESULT TPM_CMK_ConvertMigration(
  TPM_KEY_HANDLE parentHandle,
  TPM_CMK_AUTH *restrictTicket,
  TPM_HMAC *sigTicket,
  TPM_KEY *migratedKey,
  TPM_MSA_COMPOSITE *msaList,
  UINT32 randomSize,
  BYTE *random,
  TPM_AUTH *auth1,
  UINT32 *outDataSize,
  BYTE **outData
);

/*
 * Maintenance Functions ([TPM_Part3], Section 12)
 * [tpm_maintenance.c]
 */

/**
 * TPM_CreateMaintenanceArchive - creates the maintenance archive
 * @generateRandom: [in] Use RNG or Owner auth to generate random
 * @auth1: [in, out] Authorization protocol parameters
 * @randomSize: [out] Size of the returned random data
 * @random: [out] Random data to XOR with result
 * @archiveSize: [out] Size of the encrypted archive 
 * @archive: [out] Encrypted key archive
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 12.1)
 * This command creates the maintenance archive. It can only be executed by 
 * the owner, and may be shut off with the KillMaintenanceFeature command.
 */
TPM_RESULT TPM_CreateMaintenanceArchive(  
  BOOL generateRandom,
  TPM_AUTH *auth1,  
  UINT32 *randomSize,
  BYTE **random ,
  UINT32 *archiveSize,
  BYTE **archive  
);

/**
 * TPM_LoadMaintenanceArchive - loads in a maintenance archive
 * @archiveSize: [in] Size of encrypted key archive
 * @archive: [in] Encrypted key archive
 * @sigSize: [in] Size of archive signature
 * @sig: [in] archive signature
 * @randomSize: [in] Size of the random data
 * @random: [in] Random data to XOR with encrypted archive
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 12.2)
 * This command loads in a maintenance archive that has been massaged 
 * by the manufacturer to load into another TPM.
 */
TPM_RESULT TPM_LoadMaintenanceArchive(
  UINT32 archiveSize,
  BYTE *archive,
  UINT32 sigSize,
  BYTE *sig,
  UINT32 randomSize,
  BYTE *random,
  TPM_AUTH *auth1
);

/**
 * TPM_KillMaintenanceFeature - prevents the creation of a maintenance archive
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 12.3)
 * The KillMaintencanceFeature is a permanent action that prevents ANYONE from 
 * creating a maintenance archive. This action, once taken, is permanent until 
 * a new TPM Owner is set. This action is to allow those customers who do not 
 * want the maintenance feature to prohibit it. 
 */
TPM_RESULT TPM_KillMaintenanceFeature(  
  TPM_AUTH *auth1
);

/**
 * TPM_LoadManuMaintPub - loads the manufacturer's public key
 * @antiReplay: [in] AntiReplay and validation nonce 
 * @pubKey: [in] The public key of the manufacturer to be in use for maintenance
 * @checksum: [out] Digest of pubKey and antiReplay
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 12.4)
 * The LoadManuMaintPub command loads the manufacturer's public key for use in
 * the maintenance process. The command installs ManuMaintPub in persistent 
 * data storage inside a TPM. 
 */
TPM_RESULT TPM_LoadManuMaintPub(  
  TPM_NONCE *antiReplay,
  TPM_PUBKEY *pubKey,  
  TPM_DIGEST *checksum 
);

/**
 * TPM_ReadManuMaintPub - provides a digest of the manufacturer's public key
 * @antiReplay: [in] AntiReplay and validation nonce
 * @checksum: [out] Digest of pubKey and antiReplay
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 12.5)
 * The ReadManuMaintPub command is used to check whether the manufacturer's 
 * public maintenance key in a TPM has the expected value. The command 
 * provides a digest of the installed key, rather than the key itself. 
 */
TPM_RESULT TPM_ReadManuMaintPub(  
  TPM_NONCE *antiReplay,  
  TPM_DIGEST *checksum 
);

/*
 * Cryptographic Functions ([TPM_Part3], Section 13)
 * [tpm_crypto.c]
 */

/**
 * TPM_SHA1Start - starts the process of calculating a SHA-1 digest
 * @maxNumBytes: [out] Maximum number of bytes that can be sent to SHA1Update
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.1)
 * This capability starts the process of calculating a SHA-1 digest.
 */
TPM_RESULT TPM_SHA1Start(  
  UINT32 *maxNumBytes 
);

/**
 * TPM_SHA1Update - inputs blocks of data into a pending SHA-1 digest
 * @numBytes: [in] The number of bytes in hashData
 * @hashData: [in] Bytes to be hashed
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.2)
 * This capability inputs complete blocks of data into a pending SHA-1 digest. 
 * At the end of the process, the digest remains pending.
 */
TPM_RESULT TPM_SHA1Update(  
  UINT32 numBytes,
  BYTE *hashData
);

/**
 * TPM_SHA1Complete - terminates a pending SHA-1 calculation
 * @hashDataSize: [in] Number of bytes in hashData, MUST be 64 or less 
 * @hashData: [in] Final bytes to be hashed
 * @hashValue: [out] The output of the SHA-1 hash
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.3)
 * This capability terminates a pending SHA-1 calculation.
 */
TPM_RESULT TPM_SHA1Complete(  
  UINT32 hashDataSize,
  BYTE *hashData,  
  TPM_DIGEST *hashValue 
);

/**
 * TPM_SHA1CompleteExtend - terminates and extends a pending SHA-1 calculation
 * @pcrNum: [in] Index of the PCR to be modified
 * @hashDataSize: [in] Number of bytes in hashData, MUST be 64 or less 
 * @hashData: [in] Final bytes to be hashed
 * @hashValue: [out] The output of the SHA-1 hash
 * @outDigest: [out] The PCR value after execution of the command
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.4)
 * This capability terminates a pending SHA-1 calculation and EXTENDS the 
 * result into a Platform Configuration Register using a SHA-1 hash process. 
 */
TPM_RESULT TPM_SHA1CompleteExtend(  
  TPM_PCRINDEX pcrNum,
  UINT32 hashDataSize,
  BYTE *hashData,  
  TPM_DIGEST *hashValue,
  TPM_PCRVALUE *outDigest 
);

/**
 * tpm_verify - verifies the signature with the specified key
 * @key: [in] key to verify the signature
 * @auth: [in, out] Authorization protocol parameters
 * @isInfo: [in] True if the input data is of type TPM_SIGN_INFO
 * @data: [in] The input data
 * @dataSize: [in] The size of the input data
 * @sig: [in] The digital signature
 * @sigSize: [in] The size of the digital signature
 * Returns: TPM_SUCCESS if the signature is valid, a TPM error code otherwise.
 */
TPM_RESULT tpm_verify(
  TPM_PUBKEY_DATA *key,
  TPM_AUTH *auth,
  BOOL isInfo,
  BYTE *data,
  UINT32 dataSize,
  BYTE *sig,
  UINT32 sigSize
);

/**
 * tpm_sign - signs data with the specified key
 * @key: [in] key to compute the signature
 * @auth: [in, out] Authorization protocol parameters
 * @isInfo: [in] True if the input data is of type TPM_SIGN_INFO
 * @areaToSign: [in] The value to sign
 * @areaToSignSize: [in] The size of the areaToSign parameter
 * @sig: [out] The digital signature
 * @sigSize: [out] The size of the digital signature
 * Returns: TPM_SUCCESS if the signature is valid, a TPM error code otherwise.
 */
TPM_RESULT tpm_sign(
  TPM_KEY_DATA *key,
  TPM_AUTH *auth,
  BOOL isInfo,
  BYTE *areaToSign,
  UINT32 areaToSignSize,
  BYTE **sig,
  UINT32 *sigSize
);

/**
 * TPM_Sign - signs data and provides the resulting digital signature
 * @keyHandle: [in] Handle of a loaded key that can perform digital signatures
 * @areaToSignSize: [in] The size of the areaToSign parameter 
 * @areaToSign: [in] The value to sign
 * @auth1: [in, out] Authorization protocol parameters
 * @sigSize: [out] The length of the returned digital signature 
 * @sig: [out] The resulting digital signature
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.5)
 * The Sign command signs data and provides the resulting digital signature.
 */
TPM_RESULT TPM_Sign(  
  TPM_KEY_HANDLE keyHandle,
  UINT32 areaToSignSize,
  BYTE *areaToSign,
  TPM_AUTH *auth1,  
  UINT32 *sigSize,
  BYTE **sig  
);

/**
 * tpm_get_random_bytes - provides the requested amount of random bytes
 * @buf: [out] buffer to fill with random data
 * @nbytes: [in] requested number of random bytes
 */
void tpm_get_random_bytes(
  void *buf,
  size_t nbytes
);

/**
 * TPM_GetRandom - provides the next bytes from the RNG
 * @bytesRequested: [in] Number of bytes to return
 * @randomBytesSize: [out] The number of bytes returned 
 * @randomBytes: [out] The returned bytes
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.6)
 * GetRandom provides the next bytesRequested bytes from the random number 
 * generator to the caller. 
 */
TPM_RESULT TPM_GetRandom(  
  UINT32 bytesRequested,  
  UINT32 *randomBytesSize,
  BYTE **randomBytes  
);

/**
 * TPM_StirRandom - adds entropy to the RNG state
 * @dataSize: [in] Number of bytes of input (256) 
 * @inData: [in] Data to add entropy to RNG state
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.7)
 * StirRandom adds entropy to the RNG state.
 */
TPM_RESULT TPM_StirRandom(  
  UINT32 dataSize,
  BYTE *inData
);

/**
 * TPM_CertifyKey - certifies the public portion of a non-migratable key
 * @certHandle: [in] Handle of the key to be used to certify the key
 * @keyHandle: [in] Handle of the key to be certified
 * @antiReplay: [in] 160 bits of externally supplied data (typically a nonce)
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @certifyInfo: [out] Certify information relative to keyhandle 
 * @outDataSize: [out] The used size of the output area for outData 
 * @outData: [out] The signed public key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.8)
 * The TPM_CERTIFYKEY operation allows a key to certify the public portion of 
 * certain storage and signing keys. A TPM identity key may be used to certify 
 * non-migratable keys but is not permitted to certify migratory keys. 
 */
TPM_RESULT TPM_CertifyKey(  
  TPM_KEY_HANDLE certHandle,
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_CERTIFY_INFO *certifyInfo,
  UINT32 *outDataSize,
  BYTE **outData  
);

/**
 * TPM_CertifyKey2 - certifies a CMK
 * @certHandle: [in] Handle of the key to be used to certify the key
 * @keyHandle: [in] Handle of the key to be certified
 * @migrationPubDigest: [in] Digest of the public key of a Migration Authority 
 * @antiReplay: [in] 160 bits of externally supplied data (typically a nonce)
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @certifyInfo: [out] TPM_CERTIFY_INFO2 relative to keyHandle 
 * @outDataSize: [out] The used size of the output area for outData 
 * @outData: [out] The signed public key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 13.9)
 * This command provides the ability to certify a Certifiable Migration Key 
 * (CMK). This certification requires additional parameters and output then 
 * the TPM_CertifyKey. This command always uses the TPM_SIGN_INFO2 structure. 
 * All other aspects of the command are the same as TPM_CertifyKey. 
 */
TPM_RESULT TPM_CertifyKey2(  
  TPM_KEY_HANDLE certHandle,
  TPM_KEY_HANDLE keyHandle,
  TPM_DIGEST *migrationPubDigest,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_CERTIFY_INFO *certifyInfo,
  UINT32 *outDataSize,
  BYTE **outData  
);

/*
 * Credential Handling ([TPM_Part3], Section 14)
 * [tpm_credentials.c]
 * There are two create EK commands. The first matches the 1.1 functionality. 
 * The second provides the mechanism to enable revokeEK and provides 
 * FIPS 140-2 compatibility. 
 */

/**
 * TPM_CreateEndorsementKeyPair - creates the TPM endorsement key
 * @antiReplay: [in] Arbitrary data 
 * @keyInfo: [in] Information about key to be created
 * @pubEndorsementKey: [out] The public endorsement key
 * @Checksum: [out] Hash of pubEndorsementKey and antiReplay
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 14.1)
 * This command creates the TPM endorsement key. It returns a failure code if 
 * an endorsement key already exists.
 */
TPM_RESULT TPM_CreateEndorsementKeyPair(  
  TPM_NONCE *antiReplay,
  TPM_KEY_PARMS *keyInfo,  
  TPM_PUBKEY *pubEndorsementKey,
  TPM_DIGEST *Checksum 
);

/**
 * TPM_CreateRevocableEK - creates the TPM endorsement key
 * @antiReplay: [in] Arbitrary data 
 * @keyInfo: [in] Information about key to be created
 * @generateReset: [in] If TRUE generate EKreset otherwise use the passed value
 * @inputEKreset: [in] Authorization value to be used if generateReset is FALSE
 * @pubEndorsementKey: [out] The public endorsement key
 * @Checksum: [out] Hash of pubEndorsementKey and antiReplay
 * @outputEKreset: [out] The authorization value to use TPM_RevokeTrust
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 14.2)
 * This command creates the TPM endorsement key. It returns a failure code if 
 * an endorsement key already exists. 
 */
TPM_RESULT TPM_CreateRevocableEK(  
  TPM_NONCE *antiReplay,
  TPM_KEY_PARMS *keyInfo,
  BOOL generateReset,
  TPM_NONCE *inputEKreset,  
  TPM_PUBKEY *pubEndorsementKey,
  TPM_DIGEST *Checksum,
  TPM_NONCE *outputEKreset 
);

/**
 * TPM_RevokeTrust - clears the EK and sets the TPM to a pure default state
 * @EKReset: [in] The value that will be matched to EK Reset
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 14.3)
 * This command clears the EK and sets the TPM back to a pure default state. 
 * The generation of the authorization value occurs during the generation of 
 * the EK. It is the responsibility of the EK generator to properly protect 
 * and disseminate the RevokeTrust authorization. 
 */
TPM_RESULT TPM_RevokeTrust(  
  TPM_NONCE *EKReset
);

/**
 * tpm_get_pubek - extracts the public portion of the EK
 * @pubEndorsementKey: [out] The public endorsement key
 */
TPM_RESULT tpm_get_pubek(
  TPM_PUBKEY *pubEndorsementKey
);

/**
 * TPM_ReadPubek - provides the public portion of the EK
 * @antiReplay: [in] Arbitrary data
 * @pubEndorsementKey: [out] The public endorsement key
 * @checksum: [out] Hash of pubEndorsementKey and antiReplay
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 14.4)
 * Provides the endorsement key public portion. This value should have 
 * controls placed upon access as it is a privacy sensitive value.
 */
TPM_RESULT TPM_ReadPubek(  
  TPM_NONCE *antiReplay,  
  TPM_PUBKEY *pubEndorsementKey,
  TPM_DIGEST *checksum 
);

/**
 * TPM_DisablePubekRead - disables the TPM_ReadPubk command
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 14.5)
 * The TPM Owner may wish to prevent any entity from reading the PUBEK. 
 * This command sets the non-volatile flag so that the TPM_ReadPubek 
 * command always returns TPM_DISABLED_CMD.
 */
TPM_RESULT TPM_DisablePubekRead(  
  TPM_AUTH *auth1
);

/**
 * TPM_OwnerReadInternalPub - provides the public portion of the EK or SRK
 * @keyHandle: [in] Handle for either PUBEK or SRK
 * @auth1: [in, out] Authorization protocol parameters
 * @publicPortion: [out] The public portion of the requested key 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 14.6)
 * A TPM Owner authorized command that provides the public portion of 
 * the EK or SRK.
 */
TPM_RESULT TPM_OwnerReadInternalPub(  
  TPM_KEY_HANDLE keyHandle,
  TPM_AUTH *auth1,  
  TPM_PUBKEY *publicPortion 
);

/*
 * Identity Creation and Activation ([TPM_Part3], Section 15)
 * [tpm_identity.c]
 */

/**
 * TPM_MakeIdentity - generates a new AIK
 * @identityAuth: [in] Encrypted usage authorization data for the new identity 
 * @labelPrivCADigest: [in] Digest of the identity label and the new privacy CA
 * @idKeyParams: [in] All parameters of the new identity key
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @idKey: [out] The newly created identity key
 * @identityBindingSize: [out] The size of the output area for identityBinding 
 * @identityBinding: [out] Signature of TPM_IDENTITY_CONTENTS using idKey
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 15.1)
 * Generate a new Attestation Identity Key (AIK).
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
);

/**
 * TPM_ActivateIdentity - activates a TPM identity
 * @idKeyHandle: [in] Identity key to be activated 
 * @blobSize: [in] Size of encrypted blob from CA 
 * @blob: [in] The encrypted ASYM_CA_CONTENTS or TPM_EK_BLOB
 * @auth1: [in, out] Authorization protocol parameters (usageAuth)
 * @auth2: [in, out] Authorization protocol parameters (ownerAuth)
 * @symmetricKey: [out] The decrypted symmetric key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 15.2)
 * The purpose of TPM_ActivateIdentity is to twofold. The first purpose is to 
 * obtain assurance that the credential in the TPM_SYM_CA_ATTESTATION is for 
 * this TPM. The second purpose is to obtain the session key used to encrypt 
 * the TPM_IDENTITY_CREDENTIAL. 
 */
TPM_RESULT TPM_ActivateIdentity(  
  TPM_KEY_HANDLE idKeyHandle,
  UINT32 blobSize,
  BYTE *blob,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  TPM_SYMMETRIC_KEY *symmetricKey 
);

/*
 * Integrity Collection and Reporting ([TPM_Part3], Section 16)
 * [tpm_integrity.c]
 * This section deals with what commands have direct access to the PCR.
 */

/**
 * TPM_Extend - adds a new measurement to a PCR
 * @pcrNum: [in] The PCR to be updated
 * @inDigest: [in] The 160 bit value representing the event to be recorded
 * @outDigest: [out] The PCR value after execution of the command
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 16.1)
 * This adds a new measurement to a Platform Configuration Register (PCR).
 */
TPM_RESULT TPM_Extend(
  TPM_PCRINDEX pcrNum,
  TPM_DIGEST *inDigest,
  TPM_PCRVALUE *outDigest
);

/**
 * TPM_PCRRead - provides the contents of a named PCR
 * @pcrIndex: [in] Index of the PCR to be read
 * @outDigest: [out] The current contents of the named PCR
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 16.2)
 * The TPM_PCRRead operation provides non-cryptographic reporting of the
 * contents of a named PCR.
 */
TPM_RESULT TPM_PCRRead(
  TPM_PCRINDEX pcrIndex,
  TPM_PCRVALUE *outDigest
);

/**
 * TPM_Quote - provides cryptographic reporting of PCR values
 * @keyHandle: [in] Handle of a loaded key that can sign the PCR values
 * @extrnalData: [in] 160 bits of externally supplied data (typically a nonce)
 * @targetPCR: [in] The indices of the PCRs that are to be reported
 * @auth1: [in, out] Authorization protocol parameters
 * @pcrData: [out] The indices and values of the PCRs listed in targetPCR
 * @sigSize: [out] The used size of the output area for the signature
 * @sig: [out] The signed data blob
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 16.3)
 * The TPM_Quote operation provides cryptographic reporting of PCR values.
 * A loaded key is required for operation TPM_Quote uses a key to sign a
 * statement that names the current value of a chosen PCR and externally
 * supplied data (which may be a nonce supplied by a Challenger).
 */
TPM_RESULT TPM_Quote(
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *extrnalData,
  TPM_PCR_SELECTION *targetPCR,
  TPM_AUTH *auth1,
  TPM_PCR_COMPOSITE *pcrData,
  UINT32 *sigSize,
  BYTE **sig
);

/**
 * TPM_PCR_Reset - resets the indicated PCRs
 * @pcrSelection: [in] The PCRs to reset
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 16.4)
 * Resets the indicated PCRs. This command uses the locality modifier.
 * The modifier for a command to indicate locality is a platform specific
 * issue.
 */
TPM_RESULT TPM_PCR_Reset(
  TPM_PCR_SELECTION *pcrSelection
);

/**
 * TPM_Quote2 - provides cryptographic reporting of PCR values
 * @keyHandle: [in] Handle of a loaded key that can sign the PCR values
 * @extrnalData: [in] 160 bits of externally supplied data (typically a nonce)
 * @targetPCR: [in] The indices of the PCRs that are to be reported
 * @addVersion: [in] When TRUE add TPM_CAP_VERSION_INFO to the output
 * @auth1: [in, out] Authorization protocol parameters
 * @pcrData: [out] The value created and signed for the quote
 * @versionInfoSize: [out] Size of the version info
 * @versionInfo: [out] The version info
 * @sigSize: [out] The used size of the output area for the signature
 * @sig: [out] The signed data blob
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 16.5)
 */
TPM_RESULT TPM_Quote2(
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *externalData,
  TPM_PCR_SELECTION *targetPCR,
  BOOL addVersion,
  TPM_AUTH *auth1,
  TPM_PCR_INFO_SHORT *pcrData,
  UINT32 *versionInfoSize,
  TPM_CAP_VERSION_INFO *versionInfo,
  UINT32 *sigSize,
  BYTE **sig
);

/**
 * tpm_compute_pcr_digest - computes a PCR composite hash
 * @pcrSelection: [in] The PCRs to include
 * @digest: [out] The computed composite hash
 * @composite: [out] If not NULL the used composite is stored into it
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([TPM_Part3], Section 5.3.1)
 * Computes the PCR composite hash over a given set of PCRs.
 */
TPM_RESULT tpm_compute_pcr_digest(
  TPM_PCR_SELECTION *pcrSelection,
  TPM_COMPOSITE_HASH *digest,
  TPM_PCR_COMPOSITE *composite
);

/**
 * tpm_verify_pcr - verifies the PCR composite hash of the specified key
 * @key: [in] The key whose PCR composite hash should be verified
 * @atrelease: [in] If TRUE the AtRelease composite hash is verified
 * @atcreation: [in] If TRUE the AtCreation composite hash is verified
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([TPM_Part3], Section 5.3.1)
 * Computes the PCR composite hash over a given set of PCRs.
 */
TPM_RESULT tpm_verify_pcr(
  TPM_KEY_DATA *key, 
  BOOL atrelease, 
  BOOL atcreation
);

/*
 * Authorization Changing ([TPM_Part3], Section 17)
 * [tpm_authorization.c]
 */

/**
 * TPM_ChangeAuth - changes the authorization data for the entity
 * @parentHandle: [in] Handle of the parent key to the entity
 * @protocolID: [in] The protocol in use
 * @newAuth: [in] The encrypted new authorization data for the entity
 * @entityType: [in] The type of entity to be modified 
 * @encDataSize: [in] The size of the encData parameter 
 * @encData: [in] The encrypted entity that is to be modified
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The used size of the output area for outData 
 * @outData: [out] The modified, encrypted entity
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 17.1)
 * The TPM_ChangeAuth command allows the owner of an entity to change the 
 * authorization data for the entity. TPM_ChangeAuth requires the encryption 
 * of one parameter (NewAuth). 
 */
TPM_RESULT TPM_ChangeAuth(  
  TPM_KEY_HANDLE parentHandle,
  TPM_PROTOCOL_ID protocolID,
  TPM_ENCAUTH *newAuth,
  TPM_ENTITY_TYPE entityType,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,  
  UINT32 *outDataSize,
  BYTE **outData  
);

/**
 * TPM_ChangeAuthOwner - changes the authorization data for the TPM Owner
 * @protocolID: [in] The protocol in use
 * @newAuth: [in] The encrypted new authorization data for the entity
 * @entityType: [in] The type of entity to be modified
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 17.2)
 * The TPM_ChangeAuthOwner command allows the owner of an entity to change 
 * the authorization data for the TPM Owner or the SRK. This command requires 
 * authorization from the current TPM Owner to execute.
 */
TPM_RESULT TPM_ChangeAuthOwner(  
  TPM_PROTOCOL_ID protocolID,
  TPM_ENCAUTH *newAuth,
  TPM_ENTITY_TYPE entityType,
  TPM_AUTH *auth1
);

/*
 * Authorization Sessions ([TPM_Part3], Section 18)
 * [tpm_authorization.c]
 */

/**
 * TPM_OIAP - creates an authorization handle for the OIAP
 * @authHandle: [out] Handle that points to the authorization state
 * @nonceEven: [out] Nonce associated with session
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 18.1)
 * The TPM_OIAP command creates an authorization handle and generates 
 * nonceEven for the Object-Independent Authorization Protocol (OIAP).
 */
TPM_RESULT TPM_OIAP(  
  TPM_AUTHHANDLE *authHandle,
  TPM_NONCE *nonceEven 
);

/**
 * TPM_OSAP - creates an authorization handle for the OSAP
 * @entityType: [in] The type of entity in use
 * @entityValue: [in] The selection value based on entityType
 * @nonceOddOSAP: [in] The nonce generated by the caller
 * @authHandle: [out] Handle that points to the authorization state
 * @nonceEven: [out] Nonce associated with session
 * @nonceEvenOSAP: [out] Nonce associated with shared secret
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 18.2)
 * The TPM_OSAP command creates an authorization handle, the shared secret 
 * and generates nonceEven and nonceEvenOSAP for the Object-Specific 
 * Authorization Protocol (OSAP).
 */
TPM_RESULT TPM_OSAP(  
  TPM_ENTITY_TYPE entityType,
  UINT32 entityValue,
  TPM_NONCE *nonceOddOSAP,  
  TPM_AUTHHANDLE *authHandle,
  TPM_NONCE *nonceEven,
  TPM_NONCE *nonceEvenOSAP 
);

/**
 * TPM_DSAP - creates an authorization handle for the DSAP
 * @entityType [in] The type of delegation information to use
 * @keyHandle: [in] Key for which delegated authority corresponds
 * @nonceOddDSAP: [in] The nonce generated by the caller
 * @entityValueSize: [in] The size of entityValue 
 * @entityValue: [in] The entity value based on entityType
 * @authHandle: [out] Handle that points to the authorization state
 * @nonceEven: [out] Nonce associated with session
 * @nonceEvenDSAP: [out] Nonce associated with shared secret
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 18.3)
 * The TPM_DSAP command creates the authorization handle using a delegated 
 * authorization value passed into the command as an encrypted blob or from 
 * the internal delegation table for the Delegate-Specific Authorization 
 * Protocol (DSAP). 
 */
TPM_RESULT TPM_DSAP(
  TPM_ENTITY_TYPE entityType,
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *nonceOddDSAP,
  UINT32 entityValueSize,
  BYTE *entityValue,
  TPM_AUTHHANDLE *authHandle,
  TPM_NONCE *nonceEven,
  TPM_NONCE *nonceEvenDSAP 
);

/**
 * TPM_SetOwnerPointer - sets an owner secret for OIAP or OSAP 
 * @entityType: [in] The type of entity in use
 * @entityValue: [in] The selection value based on entityType,
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 18.4)
 * This command will set a reference to which secret the TPM will use when 
 * executing an owner secret related OIAP or OSAP session. This command 
 * should only be used if legacy code must be enabled for delegation to work.
 */
TPM_RESULT TPM_SetOwnerPointer(  
  TPM_ENTITY_TYPE entityType,
  UINT32 entityValue
);

/**
 * tpm_verify_auth - verifies an authorization session
 * @auth: [in] The handle to the authorization session
 * @secret: [in] The secret associated with the resource
 * @handle: [in] The handle used to access the resource
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description: ([TPM_Part3], Section 18.1.1 and 18.2.1)
 * Verifies a OIAP and OSAP session. In addition to the protocol 
 * parameters auth->digest is supposed to contain the the SHA-1 digest 
 * of the input parameters.
 */
TPM_RESULT tpm_verify_auth(
  TPM_AUTH *auth,
  TPM_SECRET secret,
  TPM_HANDLE handle
);

/**
 * tpm_decrypt_auth_secret - decrypts an authorization secret
 * @encAuth: [in] The encrypted authorization secret
 * @secret: [in] The shared secret of the OSAP session 
 * @nonce: [in] The nonce for decryption
 * @plainAuth: [out]: The decrypted authorization secret
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 *
 * Description:
 * Decrypts an encrypted authorization secret by xoring it with
 * the key SHA-1(secret||nonce).
 */
void tpm_decrypt_auth_secret(
  TPM_ENCAUTH encAuth, 
  TPM_SECRET secret,
  TPM_NONCE *nonce, 
  TPM_SECRET plainAuth
);

/*
 * Delegation Commands ([TPM_Part3], Section 19)
 * [tpm_delegation.c]
 */

/**
 * TPM_Delegate_Manage - manages the Family tables
 * @familyID: [in] The familyID that is to be managed 
 * @opFlag: [in] Operation to be performed by this command
 * @opDataSize: [in] Size in bytes of opData 
 * @opData: [in] Data necessary to implement opFlag
 * @auth1: [in, out] Authorization protocol parameters
 * @retDataSize: [out] Size in bytes of retData 
 * @retData: [out] Returned data 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.1)
 * TPM_Delegate_Manage is the fundamental process for managing the Family 
 * tables, including enabling/disabling Delegation for a selected Family. 
 */
TPM_RESULT TPM_Delegate_Manage(  
  TPM_FAMILY_ID familyID,
  TPM_FAMILY_OPERATION opFlag,
  UINT32 opDataSize,
  BYTE *opData,
  TPM_AUTH *auth1,  
  UINT32 *retDataSize,
  BYTE **retData  
);

/**
 * TPM_Delegate_CreateKeyDelegation - delegates privilege to use a key
 * @keyHandle: [in] Handle of a loaded key
 * @publicInfo: [in] The public information necessary to fill in the blob 
 * @delAuth: [in] The encrypted new authorization data for the blob
 * @auth1: [in, out] Authorization protocol parameters
 * @blob: [out] The partially encrypted delegation information
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.2)
 * This command delegates privilege to use a key by creating a blob that can 
 * be used by TPM_DSAP. 
 */
TPM_RESULT TPM_Delegate_CreateKeyDelegation(  
  TPM_KEY_HANDLE keyHandle,
  TPM_DELEGATE_PUBLIC *publicInfo,
  TPM_ENCAUTH *delAuth,
  TPM_AUTH *auth1,  
  TPM_DELEGATE_KEY_BLOB *blob 
);

/**
 * TPM_Delegate_CreateOwnerDelegation - delegates the Owner's privilege
 * @increment: [in] Flag dictates whether verificationCount will be incremented
 * @publicInfo: [in] The public parameters for the blob 
 * @delAuth: [in] The encrypted new authorization data for the blob
 * @auth1: [in, out] Authorization protocol parameters
 * @blob: [out] The partially encrypted delegation information
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.3)
 * TPM_Delegate_CreateOwnerDelegation delegates the Owner's privilege to use 
 * a set of command ordinals, by creating a blob. Such blobs can be used as 
 * input data for TPM_DSAP or TPM_Delegate_LoadOwnerDelegation. 
 */
TPM_RESULT TPM_Delegate_CreateOwnerDelegation(  
  BOOL increment,
  TPM_DELEGATE_PUBLIC *publicInfo,
  TPM_ENCAUTH *delAuth,
  TPM_AUTH *auth1,  
  TPM_DELEGATE_OWNER_BLOB *blob 
);

/**
 * TPM_Delegate_LoadOwnerDelegation - loads a delegate table row blob
 * @index: [in] The index of the delegate row to be written
 * @blob: [in] the delegation information
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.4)
 * This command loads a delegate table row blob into a non-volatile delegate 
 * table row. Delegate_LoadOwnerDelegation can be used during manufacturing or 
 * on first boot (when no Owner is installed), or after an Owner is installed. 
 */
TPM_RESULT TPM_Delegate_LoadOwnerDelegation(  
  TPM_DELEGATE_INDEX index,
  TPM_DELEGATE_OWNER_BLOB *blob,
  TPM_AUTH *auth1
);

/**
 * TPM_Delegate_ReadTable - reads from the family and delegate tables
 * @familyTableSize: [out] Size in bytes of familyTable 
 * @familyTable: [out] Array of TPM_FAMILY_TABLE_ENTRY elements
 * @delegateTableSize: [out] Size in bytes of delegateTable 
 * @delegateTable: [out] Array of TPM_DELEGATE_TABLE_PUBLIC elements
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.5)
 * This command is used to read from the TPM the public contents of the 
 * family and delegate tables that are stored on the TPM. 
 */
TPM_RESULT TPM_Delegate_ReadTable(  
  UINT32 *familyTableSize,
  BYTE **familyTable ,
  UINT32 *delegateTableSize,
  BYTE **delegateTable
);

/**
 * TPM_Delegate_UpdateVerification - updates the verificationCount 
 * @inputSize: [in] The size of inputData
 * @inputData: [in] TPM_DELEGATE_KEY_BLOB, -OWNER_BLOB or table index
 * @auth1: [in, out] Authorization protocol parameters
 * @outputSize: [out] The size of the output 
 * @outputData: [out] TPM_DELEGATE_KEY_BLOB or TPM_DELEGATE_OWNER_BLOB
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.6)
 * UpdateVerification sets the verificationCount in an entity (a blob or a 
 * delegation row) to the current family value, in order that the delegations 
 * represented by that entity will continue to be accepted by the TPM.
 */
TPM_RESULT TPM_Delegate_UpdateVerification(  
  UINT32 inputSize,
  BYTE *inputData,
  TPM_AUTH *auth1,  
  UINT32 *outputSize,
  BYTE **outputData  
);

/**
 * TPM_Delegate_VerifyDelegation - verifies a delegate blob
 * @delegateSize: [in] The length of the delegated information blob 
 * @delegation: [in] TPM_DELEGATE_KEY_BLOB or TPM_DELEGATE_OWNER_BLOB
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 19.7)
 * VerifyDelegation loads a delegate blob and returns success or failure, 
 * depending on whether the blob is currently valid.
 */
TPM_RESULT TPM_Delegate_VerifyDelegation(  
  UINT32 delegateSize,
  BYTE *delegation
);

/**
 * tpm_get_family_row - returns the family row for the specified id
 * @id: [in] family id
 * Returns: The matching family row on success, NULL otherwise.
 */
TPM_FAMILY_TABLE_ENTRY *tpm_get_family_row(
  TPM_FAMILY_ID id
);

/**
 * tpm_get_delegate_row - returns the delegate row for the specified index
 * @row: [in] row index
 * Returns: The matching delegate row on success, NULL otherwise.
 */
TPM_DELEGATE_TABLE_ROW *tpm_get_delegate_row(
  UINT32 row
);

/**
 * tpm_compute_owner_blob_digest - computes the digest of an owner blob
 * @blob: [in] Owner blob
 * @digest: [out] Digest of the specified owner blob
 */
void tpm_compute_owner_blob_digest(
  TPM_DELEGATE_OWNER_BLOB *blob,
  TPM_DIGEST *digest
);

/**
 * tpm_compute_key_blob_digest - computes the digest of a key blob
 * @blob: [in] Key blob
 * @digest: [out] Digest of the specified key blob
 */
void tpm_compute_key_blob_digest(
  TPM_DELEGATE_KEY_BLOB *blob,
  TPM_DIGEST *digest
);

/**
 * tpm_encrypt_sensitive - encrypts a TPM_DELEGATE_SENSITIVE structure
 * @iv: [in] IV value
 * @iv_size: [in] Size of the IV value
 * @sensitive: [in] structure to encrypt
 * @enc: [out] Encrypted structure
 * @enc_size: [out] Size of the encrypted structure
 * Returns 0 on success, -1 otherwise.
 */
int tpm_encrypt_sensitive(
  BYTE *iv,
  UINT32 iv_size,
  TPM_DELEGATE_SENSITIVE *sensitive,
  BYTE **enc,
  UINT32 *enc_size
);

/**
 * tpm_decrypt_sensitive - decrypts a TPM_DELEGATE_SENSITIVE structure
 * @iv: [in] IV value
 * @iv_size: [in] Size of the IV value
 * @enc: [in] Encrypted structure
 * @enc_size: [in] Size of the encrypted structure
 * @sensitive: [out] decrypted structure
 * Returns 0 on success, -1 otherwise.
 */
int tpm_decrypt_sensitive(
  BYTE *iv,
  UINT32 iv_size,
  BYTE *enc,
  UINT32 enc_size,
  TPM_DELEGATE_SENSITIVE *sensitive,
  BYTE **buf
);

/*
 * Non-volatile Storage ([TPM_Part3], Section 20)
 * [tpm_nv_storage.c]
 * This section handles the allocation and use of the TPM non-volatile storage.
 */

/**
 * TPM_NV_DefineSpace - establishes the necessary space
 * @pubInfo: [in] The public parameters of the NV area
 * @encAuth: [in] The encrypted authorization (if reqired)
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 20.1)
 * This establishes the space necessary for the indicated index. The definition 
 * will include the access requirements for writing and reading the area. The 
 * space definition size does not include the area needed to manage the space.
 */
TPM_RESULT TPM_NV_DefineSpace(  
  TPM_NV_DATA_PUBLIC *pubInfo,
  TPM_ENCAUTH *encAuth,
  TPM_AUTH *auth1
);

/**
 * TPM_NV_WriteValue - writes a value to a defined NV area
 * @nvIndex: [in] The index of the area to set
 * @offset: [in] The offset into the NV Area
 * @dataSize: [in] The size of the data area
 * @data: [in] The data to set the area to
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 20.2)
 * This command writes a value to a defined area. The write can be TPM Owner 
 * authorized or unauthorized and protected by other attributes and will work 
 * when no TPM Owner is present.
 */
TPM_RESULT TPM_NV_WriteValue(  
  TPM_NV_INDEX nvIndex,
  UINT32 offset,
  UINT32 dataSize,
  BYTE *data,
  TPM_AUTH *auth1
);

/**
 * TPM_NV_WriteValueAuth - writes a value to a protected NV area
 * @nvIndex: [in] The index of the area to set
 * @offset: [in] The offset into the chunk 
 * @dataSize: [in] The size of the data area 
 * @data: [in] The data to set the area to
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 20.3)
 * This command writes to a previously defined area. The area must require 
 * authorization to write. This command is for using when authorization other 
 * than the owner authorization is to be used. 
 */
TPM_RESULT TPM_NV_WriteValueAuth(  
  TPM_NV_INDEX nvIndex,
  UINT32 offset,
  UINT32 dataSize,
  BYTE *data,
  TPM_AUTH *auth1
);

/**
 * TPM_NV_ReadValue - reads a value from a defined NV area
 * @nvIndex: [in] The index of the area to set
 * @offset: [in] The offset into the area 
 * @inDataSize: [in] The size of the data area
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The size of the data area 
 * @data: [out] The data to set the area to
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 20.4)
 * Read a value from the NV store. This command uses optional owner 
 * authorization.
 */
TPM_RESULT TPM_NV_ReadValue(  
  TPM_NV_INDEX nvIndex,
  UINT32 offset,
  UINT32 inDataSize,
  TPM_AUTH *auth1,  
  UINT32 *outDataSize,
  BYTE **data  
);

/**
 * TPM_NV_ReadValueAuth - reads a value from a protected NV area
 * @nvIndex: [in] The index of the area to set
 * @offset: [in] The offset from the data area 
 * @inDataSize: [in] The size of the data area
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The size of the data area 
 * @data: [out] The data
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 20.5)
 * This command requires that the read be authorized by a value set 
 * with the blob.
 */
TPM_RESULT TPM_NV_ReadValueAuth(  
  TPM_NV_INDEX nvIndex,
  UINT32 offset,
  UINT32 inDataSize,
  TPM_AUTH *auth1,  
  UINT32 *outDataSize,
  BYTE **data  
);

/**
 * tpm_nv_remove_data - removes the specified data from the NV area
 * @nv: [in] Data area to be removed
 */
void tpm_nv_remove_data(
  TPM_NV_DATA_SENSITIVE *nv
);

/*
 * Session Management ([TPM_Part3], Section 21)
 * [tpm_context.c]
 */

/**
 * TPM_KeyControlOwner - controls attributes of keys within the key cache
 * @keyHandle: [in] Handle of a loaded key
 * @pubKey: [in] The public key associated with the loaded key
 * @bitName: [in] The name of the bit to be modified
 * @bitValue: [in] The value to set the bit to
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 21.1)
 * This command controls some attributes of keys that are stored within 
 * the TPM key cache. 
 */
TPM_RESULT TPM_KeyControlOwner(  
  TPM_KEY_HANDLE keyHandle,
  TPM_PUBKEY pubKey,
  UINT32 bitName,
  BOOL bitValue,
  TPM_AUTH *auth1
);

/**
 * TPM_SaveContext - saves a loaded resource outside the TPM
 * @handle: [in] Handle of the resource being saved
 * @resourceType: [in] The type of resource that is being saved
 * @label[16]: [in] Label for identification purposes
 * @contextSize: [out] The actual size of the outgoing context blob 
 * @contextBlob: [out] The context blob
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 21.2)
 * SaveContext saves a loaded resource outside the TPM. After successful 
 * execution of the command the TPM automatically releases the internal 
 * memory for sessions but leaves keys in place.
 */
TPM_RESULT TPM_SaveContext(  
  TPM_HANDLE handle,
  TPM_RESOURCE_TYPE resourceType,
  const BYTE label[16],  
  UINT32 *contextSize,
  TPM_CONTEXT_BLOB *contextBlob 
);

/**
 * TPM_LoadContext - loads a previously saved context into the TPM
 * @entityHandle: [in] The hint handle the TPM MAY use to locate a OSAP session
 * @keepHandle: [in] Indication if the handle MUST be preserved
 * @contextSize: [in] The size of the following context blob
 * @contextBlob: [in] The context blob
 * @handle: [out] Handle assigned to the resource
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 21.3)
 * LoadContext loads into the TPM a previously saved context. The command 
 * returns the type of blob and a handle.
 */
TPM_RESULT TPM_LoadContext(
  TPM_HANDLE entityHandle,
  BOOL keepHandle,
  UINT32 contextSize,
  TPM_CONTEXT_BLOB *contextBlob,  
  TPM_HANDLE *handle 
);

/**
 * tpm_get_free_session - allocates a new session
 * @type: [in] The session type
 * Returns: the session handle on success, TPM_INVALID_HANDLE otherwise.
 */
UINT32 tpm_get_free_session(
  BYTE type
);

/**
 * tpm_invalidate_sessions - invalidates all sessions associated with the handle
 * @handle: [in] Session handle
 */
void tpm_invalidate_sessions(
  TPM_HANDLE handle
);

/*
 * Eviction ([TPM_Part3], Section 22)
 * [tpm_eviction.c]
 * The TPM has numerous resources held inside of the TPM that may need 
 * eviction. The need for eviction occurs when the number or resources 
 * in use by the TPM exceed the available space. In version 1.1 there were 
 * separate commands to evict separate resource types. This new command 
 * set uses the resource types defined for context saving and creates a 
 * generic command that will evict all resource types.
 */

/**
 * TPM_FlushSpecific - flushes a specific handle
 * @handle: [in] Handle of the item to flush
 * @resourceType: [in] The type of resource that is being flushed
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 22.1)
 * TPM_FlushSpecific flushes from the TPM a specific handle.
 */
TPM_RESULT TPM_FlushSpecific(  
  TPM_HANDLE handle,
  TPM_RESOURCE_TYPE resourceType
);

/*
 * Timing Ticks ([TPM_Part3], Section 23)
 * [tpm_ticks.c]
 * The TPM timing ticks are always available for use. The association of 
 * timing ticks to actual time is a protocol that occurs outside of the TPM. 
 * See the design document for details. 
 */

/**
 * TPM_GetTicks - provides the current tick count
 * @currentTime: [out] The current time held in the TPM descriptions 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 23.2)
 * This command provides the current tick count of the TPM.
 */
TPM_RESULT TPM_GetTicks(  
  TPM_CURRENT_TICKS *currentTime 
);

/**
 * TPM_TickStampBlob - applies a time stamp to the passed blob
 * @keyHandle: [in] Handle of a loaded key that can perform digital signatures
 * @antiReplay: [in] Anti replay value to added to signature
 * @digestToStamp: [in] The digest to perform the tick stamp on  
 * @auth1: [in, out] Authorization protocol parameters
 * @currentTicks: [out] The current time according to the TPM
 * @sigSize: [out] The length of the returned digital signature 
 * @sig: [out] The resulting digital signature
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 23.3)
 * This command applies a time stamp to the passed blob. The TPM makes no 
 * representation regarding the blob merely that the blob was present at 
 * the TPM at the time indicated.
 */
TPM_RESULT TPM_TickStampBlob(  
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *antiReplay,
  TPM_DIGEST *digestToStamp,
  TPM_AUTH *auth1,  
  TPM_CURRENT_TICKS *currentTicks,
  UINT32 *sigSize,
  BYTE **sig  
);

/**
 * tpm_update_ticks - updates the current tick session
 */
void tpm_update_ticks(void);

/*
 * Transport Sessions ([TPM_Part3], Section 24)
 * [tpm_transport.c]
 */

/**
 * TPM_EstablishTransport - establishes a transport session
 * @encHandle: [in] Handle to the key that encrypted the blob 
 * @transPublic: [in] The public information describing the transport session
 * @secretSize: [in] The size of the secret Area 
 * @secret: [in] The encrypted secret area
 * @auth1: [in, out] Authorization protocol parameters
 * @transHandle: [out] Handle for the transport session
 * @locality [out] The locality that called this command
 * @currentTicks: [out] The current tick count 
 * @transNonce: [out] The even nonce in use for subsequent execute transport 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 24.1)
 * This establishes a transport session. Depending on the attributes 
 * specified for the session this may establish shared secrets, encryption 
 * keys and session logs. The session will be in use for by the 
 * TPM_ExecuteTransport command.
 */
TPM_RESULT TPM_EstablishTransport(  
  TPM_KEY_HANDLE encHandle,
  TPM_TRANSPORT_PUBLIC *transPublic,
  UINT32 secretSize,
  BYTE *secret,
  TPM_AUTH *auth1,  
  TPM_TRANSHANDLE *transHandle,
  TPM_MODIFIER_INDICATOR *locality,
  TPM_CURRENT_TICKS *currentTicks,
  TPM_NONCE *transNonce 
);

/**
 * TPM_ExecuteTransport - executes a wrapped TPM command
 * @inWrappedCmdSize: [in] Size of the wrapped command 
 * @inWrappedCmd: [in] The wrapped command
 * @auth1: [in, out] Authorization protocol parameters
 * @currentTicks: [out] The current ticks when the command was executed
 * @locality [out] The locality that called this command
 * @outWrappedCmdSize: [out] Size of the wrapped command 
 * @outWrappedCmd: [out] The wrapped command
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 24.2)
 * Delivers a wrapped TPM command to the TPM where the TPM unwraps the 
 * command and then executes the command. 
 */
TPM_RESULT TPM_ExecuteTransport(  
  UINT32 inWrappedCmdSize,
  BYTE *inWrappedCmd,
  TPM_AUTH *auth1,  
  UINT64 *currentTicks,
  TPM_MODIFIER_INDICATOR *locality,
  UINT32 *outWrappedCmdSize,
  BYTE **outWrappedCmd  
);

/**
 * TPM_ReleaseTransportSigned - completes a transport session
 * @Key: [in] The key that will perform the signing 
 * @antiReplay: [in] Value provided by caller for anti-replay protection
 * @auth1: [in, out] Authorization protocol parameters
 * @auth2: [in, out] Authorization protocol parameters
 * @locality [out] The locality that called this command
 * @currentTicks: [out] The current ticks when the command was executed
 * @signSize: [out] The size of the signature area 
 * @signature: [out] The signature of the digest 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 24.3)
 * This command completes a transport session. If logging for this session 
 * is turned on, then this command returns a signed hash of all operations 
 * performed during the session. This command serves no purpose if logging 
 * is turned off and results in an error if attempted. 
 */
TPM_RESULT TPM_ReleaseTransportSigned(  
  TPM_KEY_HANDLE Key,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,
  TPM_AUTH *auth2,
  TPM_MODIFIER_INDICATOR *locality,
  TPM_CURRENT_TICKS *currentTicks,
  UINT32 *signSize,
  BYTE **signature  
);

/*
 * Monotonic Counter ([TPM_Part3], Section 25)
 * [tpm_counter.c]
 */

/**
 * TPM_CreateCounter - creates a counter but does not select it
 * @authData: [in] The encrypted auth data for the new counter 
 * @label[4]: [in] Label to associate with counter
 * @auth1: [in, out] Authorization protocol parameters
 * @countID: [out] Handle for the counter
 * @counterValue: [out] The starting counter value
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 25.1)
 * This command creates a counter but does not select it. Counter creation 
 * assigns an authorization value to the counter and sets the counters 
 * original start value to the current internal base value plus one. 
 */
TPM_RESULT TPM_CreateCounter(  
  TPM_ENCAUTH *authData,
  BYTE label[4],
  TPM_AUTH *auth1,  
  TPM_COUNT_ID *countID,
  TPM_COUNTER_VALUE *counterValue 
);

/**
 * TPM_IncrementCounter - increments the indicated counter by one
 * @countID: [in] Handle of a valid counter
 * @auth1: [in, out] Authorization protocol parameters
 * @count: [out] The counter value
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 25.2)
 * This authorized command increments the indicated counter by one. Once a 
 * counter has been incremented then all subsequent increments must be for 
 * the same handle until a successful TPM_Startup(ST_CLEAR) is executed.
 */
TPM_RESULT TPM_IncrementCounter(  
  TPM_COUNT_ID countID,
  TPM_AUTH *auth1,  
  TPM_COUNTER_VALUE *count 
);

/**
 * TPM_ReadCounter - provides the current counter number
 * @countID: [in] ID value of the counter
 * @count: [out] The counter value
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 25.3)
 * Reading the counter provides the caller with the current number 
 * in the sequence.
 */
TPM_RESULT TPM_ReadCounter(  
  TPM_COUNT_ID countID,  
  TPM_COUNTER_VALUE *count 
);

/**
 * TPM_ReleaseCounter - releases a counter
 * @countID: [in] ID value of the counter
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 25.4)
 * This command releases a counter such that no reads or increments 
 * of the indicated counter will succeed.
 */
TPM_RESULT TPM_ReleaseCounter(  
  TPM_COUNT_ID countID,
  TPM_AUTH *auth1
);

/**
 * TPM_ReleaseCounterOwner - releases a counter
 * @countID: [in] ID value of the counter
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 25.5)
 * This command releases a counter such that no reads or increments 
 * of the indicated counter will succeed.
 */
TPM_RESULT TPM_ReleaseCounterOwner(  
  TPM_COUNT_ID countID,
  TPM_AUTH *auth1
);

/*
 * DAA commands ([TPM_Part3], Section 26)
 * [tpm_daa.c]
 * Operations that are necessary to setup a TPM for DAA, execute the 
 * JOIN process, and execute the SIGN process.
 */

/**
 * TPM_DAA_Join - establishes the DAA parameters
 * @handle: [in] Session handle
 * @stage: [in] Processing stage of join
 * @inputSize0: [in] Size of inputData0 for this stage of JOIN 
 * @inputData0: [in] Data to be used by this capability
 * @inputSize1: [in] Size of inputData1 for this stage of JOIN 
 * @inputData1: [in] Data to be used by this capability
 * @auth1: [in, out] Authorization protocol parameters
 * @ordinal: [out] Command ordinal: TPM_ORD_DAA_Join
 * @outputSize: [out] Size of outputData 
 * @outputData: [out] Data produced by this capability
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 26.1)
 * TPM_DAA_Join is the process that establishes the DAA parameters in 
 * the TPM for a specific DAA issuing authority.
 */
TPM_RESULT TPM_DAA_Join(  
  TPM_HANDLE handle,
  BYTE stage,
  UINT32 inputSize0,
  BYTE *inputData0,
  UINT32 inputSize1,
  BYTE *inputData1,
  TPM_AUTH *auth1,  
  TPM_COMMAND_CODE *ordinal,
  UINT32 *outputSize,
  BYTE **outputData  
);

/**
 * TPM_DAA_Sign - proves the attestation held by a TPM
 * @handle: [in] Handle to the sign session
 * @stage: [in] Stage of the sign process
 * @inputSize0: [in] Size of inputData0 for this stage of DAA_Sign 
 * @inputData0: [in] Data to be used by this capability
 * @inputSize1: [in] Size of inputData1 for this stage of DAA_Sign 
 * @inputData1: [in] Data to be used by this capability
 * @auth1: [in, out] Authorization protocol parameters
 * @ordinal: [out] Command ordinal:TPM_ORD_DAA_SIGN
 * @outputSize: [out] Size of outputData 
 * @outputData: [out] Data produced by this capability
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 26.2)
 * TPM_DAA_Sign responds to a challenge and proves the attestation 
 * held by a TPM without revealing the attestation held by that TPM.
 */
TPM_RESULT TPM_DAA_Sign(  
  TPM_HANDLE handle,
  BYTE stage,
  UINT32 inputSize0,
  BYTE *inputData0,
  UINT32 inputSize1,
  BYTE *inputData1,
  TPM_AUTH *auth1,  
  TPM_COMMAND_CODE *ordinal,
  UINT32 *outputSize,
  BYTE **outputData  
);

/**
 * tpm_get_free_daa_session - allocates a new DAA session
 * Returns: the session handle on success, TPM_INVALID_HANDLE otherwise.
 */
UINT32 tpm_get_free_daa_session(void);

/*
 * Deprecated commands ([TPM_Part3], Section 28)
 * [tpm_deprecated.c]
 * This section covers the commands that were in version 1.1 but now have 
 * new functionality in other functions. The deprecated commands are still 
 * available in 1.2 but all new software should use the new functionality. 
 * There is no requirement that the deprecated commands work with new 
 * structures.
 */

/**
 * TPM_EvictKey - evicts a key
 * @evictHandle: [in] Handle of the key to be evicted
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.1.1)
 * The key commands are deprecated as the new way to handle keys is to use
 * the standard context commands. So TPM_EvictKey is now handled by
 * TPM_FlushSpecific, TPM_TerminateHandle by TPM_FlushSpecific.
 */
TPM_RESULT TPM_EvictKey(  
  TPM_KEY_HANDLE evictHandle
);

/**
 * TPM_Terminate_Handle - clears out information in a session handle
 * @handle: [in] Handle to terminate
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.1.2)
 * This allows the TPM manager to clear out information in a session handle. 
 */
TPM_RESULT TPM_Terminate_Handle(  
  TPM_AUTHHANDLE handle
);

/**
 * TPM_SaveKeyContext - saves a loaded key outside the TPM
 * @keyHandle: [in] The key which will be kept outside the TPM
 * @keyContextSize: [out] The actual size of the outgoing key context blob
 * @keyContextBlob: [out] The key context blob
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.2.1)
 * SaveKeyContext saves a loaded key outside the TPM. After creation of the 
 * key context blob the TPM automatically releases the internal memory used 
 * by that key. The format of the key context blob is specific to a TPM.
 */
TPM_RESULT TPM_SaveKeyContext(  
  TPM_KEY_HANDLE keyHandle,  
  UINT32 *keyContextSize,
  BYTE **keyContextBlob  
);

/**
 * TPM_LoadKeyContext - loads a key context blob into the TPM
 * @keyContextSize: [in] The size of the following key context blob
 * @keyContextBlob: [in] The key context blob
 * @keyHandle: [out] Handle assigned to the key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.2.2)
 * LoadKeyContext loads a key context blob into the TPM previously retrieved 
 * by a SaveKeyContext call. After successful completion the handle returned 
 * by this command can be used to access the key.
 */
TPM_RESULT TPM_LoadKeyContext(  
  UINT32 keyContextSize,
  BYTE *keyContextBlob,  
  TPM_KEY_HANDLE *keyHandle 
);

/**
 * TPM_SaveAuthContext - saves an authorization session outside the TPM
 * @authHandle: [in] Authorization session which will be kept outside the TPM
 * @authContextSize: [out] The size of the outgoing authorization context blob
 * @authContextBlob: [out] The authorization context blob
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.2.3)
 * SaveAuthContext saves a loaded authorization session outside the TPM. 
 * The format of the authorization context blob is specific to a TPM.
 */
TPM_RESULT TPM_SaveAuthContext(  
  TPM_AUTHHANDLE authHandle,  
  UINT32 *authContextSize,
  BYTE **authContextBlob  
);

/**
 * TPM_LoadAuthContext - loads an authorization context blob into the TPM
 * @authContextSize: [in] The size of the following authorization context blob
 * @authContextBlob: [in] The authorization context blob
 * @authHandle: [out] Handle assigned to the authorization session
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.2.4)
 * LoadAuthContext loads an authorization context blob into the TPM previously 
 * retrieved by a SaveAuthContext call. After successful completion the handle 
 * returned by this command can be used to access the authorization session.
 */
TPM_RESULT TPM_LoadAuthContext(  
  UINT32 authContextSize,
  BYTE *authContextBlob,  
  TPM_KEY_HANDLE *authHandle 
);

/**
 * TPM_DirWriteAuth - provides write access to the DIRs
 * @dirIndex: [in] Index of the DIR
 * @newContents: [in] New value to be stored in named DIR
 * @auth1: [in, out] Authorization protocol parameters
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.3.1)
 * The TPM_DirWriteAuth operation provides write access to the Data Integrity 
 * Registers. DIRs are non-volatile memory registers held in a TPM-shielded 
 * location. 
 */
TPM_RESULT TPM_DirWriteAuth(  
  TPM_DIRINDEX dirIndex,
  TPM_DIRVALUE *newContents,
  TPM_AUTH *auth1
);

/**
 * TPM_DirRead - provides read access to the DIRs
 * @dirIndex: [in] Index of the DIR to be read
 * @dirContents: [out] The current contents of the named DIR
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.3.2)
 * The TPM_DirRead operation provides read access to the DIRs. No 
 * authentication is required to perform this action. 
 */
TPM_RESULT TPM_DirRead(  
  TPM_DIRINDEX dirIndex,  
  TPM_DIRVALUE *dirContents 
);

/**
 * TPM_ChangeAuthAsymStart - starts the ChangeAuth process
 * @idHandle: [in] Handle of a loaded identity ID key 
 * @antiReplay: [in] The nonce to be inserted into the certifyInfo structure 
 * @inTempKey: [in] Structure containing all parameters of the ephemeral key
 * @auth1: [in, out] Authorization protocol parameters
 * @certifyInfo: [out] The certifyInfo structure that is to be signed
 * @sigSize: [out] The used size of the output area for the signature 
 * @sig: [out] The signature of the certifyInfo parameter
 * @ephHandle: [out] Handle to be used by ChangeAuthAsymFinish for ephemeral key
 * @outTempKey: [out] Structure containing all parameters and public part of ephemeral key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.4.1)
 * The TPM_ChangeAuthAsymStart starts the process of changing authorization 
 * for an entity. It sets up an OIAP session that must be retained for use by 
 * its twin TPM_ChangeAuthAsymFinish command. 
 */
TPM_RESULT TPM_ChangeAuthAsymStart(  
  TPM_KEY_HANDLE idHandle,
  TPM_NONCE *antiReplay,
  TPM_KEY_PARMS *inTempKey,
  TPM_AUTH *auth1,  
  TPM_CERTIFY_INFO *certifyInfo,
  UINT32 *sigSize,
  BYTE **sig ,
  TPM_KEY_HANDLE *ephHandle,
  TPM_KEY *outTempKey 
);

/**
 * TPM_ChangeAuthAsymFinish - terminates the ChangeAuth process
 * @parentHandle: [in] Handle of the parent key for the input data
 * @ephHandle: [in] Handle for the ephemeral key
 * @entityType: [in] The type of entity to be modified 
 * @newAuthLink: [in] HMAC over the old and new authorization values
 * @newAuthSize: [in] Size of encNewAuth 
 * @encNewAuth: [in] New authorization data encrypted with ephemeral key
 * @encDataSize: [in] The size of the inData parameter 
 * @encData: [in] The encrypted entity that is to be modified
 * @auth1: [in, out] Authorization protocol parameters
 * @outDataSize: [out] The used size of the output area for outData 
 * @outData: [out] The modified, encrypted entity
 * @saltNonce: [out] A nonce value to add entropy to the changeProof value 
 * @changeProof: [out] Proof that authorization data has changed
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.4.2)
 * The TPM_ChangeAuth command allows the owner of an entity to change the 
 * authorization data for the entity. The command requires knowledge of 
 * the existing authorization information.
 */
TPM_RESULT TPM_ChangeAuthAsymFinish(  
  TPM_KEY_HANDLE parentHandle,
  TPM_KEY_HANDLE ephHandle,
  TPM_ENTITY_TYPE entityType,
  TPM_HMAC *newAuthLink,
  UINT32 newAuthSize,
  BYTE *encNewAuth,
  UINT32 encDataSize,
  BYTE *encData,
  TPM_AUTH *auth1,  
  UINT32 *outDataSize,
  BYTE **outData ,
  TPM_NONCE *saltNonce,
  TPM_DIGEST *changeProof 
);

/**
 * TPM_Reset - releases all resources 
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.5)
 * TPM_Reset releases all resources associated with existing authorization 
 * sessions. This is useful if a TSS driver has lost track of the state in 
 * the TPM.
 */
TPM_RESULT TPM_Reset(void);

/**
 * TPM_CertifySelfTest - performs a full self-test and signs the result
 * @keyHandle: [in] Handle of a loaded key that can perform digital signatures
 * @antiReplay: [in] AnitReplay nonce to prevent replay of messages
 * @auth1: [in, out] Authorization protocol parameters
 * @sigSize: [out] The length of the returned digital signature 
 * @sig: [out] The resulting digital signature
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.6)
 * CertifySelfTest causes the TPM to perform a full self-test and return 
 * an authenticated value if the test passes. 
 */
TPM_RESULT TPM_CertifySelfTest(  
  TPM_KEY_HANDLE keyHandle,
  TPM_NONCE *antiReplay,
  TPM_AUTH *auth1,  
  UINT32 *sigSize,
  BYTE **sig  
);

/**
 * TPM_OwnerReadPubek - provides the endorsement key public portion
 * @auth1: [in, out] Authorization protocol parameters
 * @pubEndorsementKey: [out] The public endorsement key
 * Returns: TPM_SUCCESS on success, a TPM error code otherwise.
 * 
 * Description: ([TPM_Part3], Section 28.7)
 * Provides the endorsement key public portion. 
 */
TPM_RESULT TPM_OwnerReadPubek(  
  TPM_AUTH *auth1,  
  TPM_PUBKEY *pubEndorsementKey 
);

/*
 * Error handling
 * [tpm_error.c]
 */

/**
 * tpm_error_to_string - converts the specified error code into a string message
 * @res: [in] Error code
 * Returns: Human-readable description of the error code.
 */
const char *tpm_error_to_string(
  TPM_RESULT res
);

#endif /* _TPM_COMMANDS_H_ */

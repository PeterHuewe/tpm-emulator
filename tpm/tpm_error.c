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
 * $Id: tpm_error.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_structures.h"

const char *tpm_error_to_string(TPM_RESULT res)
{
  switch (res) {
    case TPM_SUCCESS:
      return "Successful completion of the operation.";
    case TPM_AUTHFAIL:
      return "Authentication failed.";
    case TPM_BADINDEX:
      return "The index to a PCR, DIR or other register is incorrect.";
    case TPM_BAD_PARAMETER:
      return "One or more parameter is bad.";
    case TPM_AUDITFAILURE:
      return "An operation completed successfully but the auditing of "
	"that operation failed.";
    case TPM_CLEAR_DISABLED:
      return "The clear disable flag is set and all clear operations now "
	"require physical access.";
    case TPM_DEACTIVATED:
      return "The TPM is deactivated.";
    case TPM_DISABLED:
      return "The TPM is disabled.";
    case TPM_DISABLED_CMD:
      return "The target command has been disabled.";
    case TPM_FAIL:
      return "The operation failed.";
    case TPM_BAD_ORDINAL:
      return "The ordinal was unknown or inconsistent.";
    case TPM_INSTALL_DISABLED:
      return "The ability to install an owner is disabled.";
    case TPM_INVALID_KEYHANDLE:
      return "The key handle can not be interpreted.";
    case TPM_KEYNOTFOUND:
      return "The key handle points to an invalid key.";
    case TPM_INAPPROPRIATE_ENC:
      return "Unacceptable encryption scheme.";
    case TPM_MIGRATEFAIL:
      return "Migration authorization failed.";
    case TPM_INVALID_PCR_INFO:
      return "PCR information could not be interpreted.";
    case TPM_NOSPACE:
      return "No room to load key.";
    case TPM_NOSRK:
      return "There is no SRK set.";
    case TPM_NOTSEALED_BLOB:
      return "An encrypted blob is invalid or was not created by this TPM.";
    case TPM_OWNER_SET:
      return "There is already an Owner.";
    case TPM_RESOURCES:
      return "The TPM has insufficient internal resources to perform the "
	"requested action.";
    case TPM_SHORTRANDOM:
      return "A random string was too short.";
    case TPM_SIZE:
      return "The TPM does not have the space to perform the operation.";
    case TPM_WRONGPCRVAL:
      return "The named PCR value does not match the current PCR value.";
    case TPM_BAD_PARAM_SIZE:
      return "The paramSize argument to the command has the incorrect value.";
    case TPM_SHA_THREAD:
      return "There is no existing SHA-1 thread.";
    case TPM_SHA_ERROR:
      return "The calculation is unable to proceed because the existing SHA-1 "
	"thread has already encountered an error.";
    case TPM_FAILEDSELFTEST:
      return "Self-test has failed and the TPM has shutdown.";
    case TPM_AUTH2FAIL:
      return "The authorization for the second key in a 2 key function failed "
	"authorization.";
    case TPM_BADTAG:
      return "The tag value sent to for a command is invalid.";
    case TPM_IOERROR:
      return "An IO error occurred transmitting information to the TPM.";
    case TPM_ENCRYPT_ERROR:
      return "The encryption process had a problem.";
    case TPM_DECRYPT_ERROR:
      return "The decryption process did not complete.";
    case TPM_INVALID_AUTHHANDLE:
      return "An invalid handle was used.";
    case TPM_NO_ENDORSEMENT:
      return "The TPM does not a EK installed.";
    case TPM_INVALID_KEYUSAGE:
      return "The usage of a key is not allowed.";
    case TPM_WRONG_ENTITYTYPE:
      return "The submitted entity type is not allowed.";
    case TPM_INVALID_POSTINIT:
      return "The command was received in the wrong sequence relative to "
	"TPM_Init and a subsequent TPM_Startup.";
    case TPM_INAPPROPRIATE_SIG:
      return "Signed data cannot include additional DER information.";
    case TPM_BAD_KEY_PROPERTY:
      return "The key properties in TPM_KEY_PARMs are not supported "
	"by this TPM.";
    case TPM_BAD_MIGRATION:
      return "The migration properties of this key are incorrect.";
    case TPM_BAD_SCHEME:
      return "The signature or encryption scheme for this key is incorrect "
	"or not permitted in this situation.";
    case TPM_BAD_DATASIZE:
      return "The size of the data (or blob) parameter is bad or "
        "inconsistent with the referenced key.";
    case TPM_BAD_MODE:
      return "A mode parameter is bad, such as capArea or subCapArea for "
	"TPM_GetCapability, physicalPresence parameter for "
	"TPM_PhysicalPresence, or migrationType for TPM_CreateMigrationBlob.";
    case TPM_BAD_PRESENCE:
      return "Either the physicalPresence or physicalPresenceLock bits "
	"have the wrong value.";
    case TPM_BAD_VERSION:
      return "The TPM cannot perform this version of the capability.";
    case TPM_NO_WRAP_TRANSPORT:
      return "The TPM does not allow for wrapped transport sessions.";
    case TPM_AUDITFAIL_UNSUCCESSFUL:
      return "TPM audit construction failed and the underlying command was "
	"returning a failure code also.";
    case TPM_AUDITFAIL_SUCCESSFUL:
      return "TPM audit construction failed and the underlying command was "
	"returning success.";
    case TPM_NOTRESETABLE:
      return "Attempt to reset a PCR register that does not have the "
	"resettable attribute.";
    case TPM_NOTLOCAL:
      return "Attempt to reset a PCR register that requires locality and "
	"locality modifier not part of command transport.";
    case TPM_BAD_TYPE:
      return "Make identity blob not properly typed.";
    case TPM_INVALID_RESOURCE:
      return "When saving context identified resource type does not match "
	"actual resource.";
    case TPM_NOTFIPS:
      return "The TPM is attempting to execute a command only available "
	"when in FIPS mode.";
    case TPM_INVALID_FAMILY:
      return "The command is attempting to use an invalid family ID.";
    case TPM_NO_NV_PERMISSION:
      return "The permission to manipulate the NV storage is not available.";
    case TPM_REQUIRES_SIGN:
      return "The operation requires a signed command.";
    case TPM_KEY_NOTSUPPORTED:
      return "Wrong operation to load an NV key.";
    case TPM_AUTH_CONFLICT:
      return "NV_LoadKey blob requires both owner and blob authorization.";
    case TPM_AREA_LOCKED:
      return "The NV area is locked and not writable.";
    case TPM_BAD_LOCALITY:
      return "The locality is incorrect for the attempted operation.";
    case TPM_READ_ONLY:
      return "The NV area is read only and can't be written to.";
    case TPM_PER_NOWRITE:
      return "There is no protection on the write to the NV area.";
    case TPM_FAMILYCOUNT:
      return "The family count value does not match.";
    case TPM_WRITE_LOCKED:
      return "The NV area has already been written to.";
    case TPM_BAD_ATTRIBUTES:
      return "The NV area attributes conflict.";
    case TPM_INVALID_STRUCTURE:
      return "The structure tag and version are invalid or inconsistent.";
    case TPM_KEY_OWNER_CONTROL:
      return "The key is under control of the TPM Owner and can only be "
	"evicted by the TPM Owner.";
    case TPM_BAD_COUNTER:
      return "The counter handle is incorrect.";
    case TPM_NOT_FULLWRITE:
      return "The write is not a complete write of the area.";
    case TPM_CONTEXT_GAP:
      return "The gap between saved context counts is too large.";
    case TPM_MAXNVWRITES:
      return "The maximum number of NV writes without an "
	"owner has been exceeded.";
    case TPM_NOOPERATOR:
      return "No operator AuthData value is set.";
    case TPM_RESOURCEMISSING:
      return "The resource pointed to by context is not loaded.";
    case TPM_DELEGATE_LOCK:
      return "The delegate administration is locked.";
    case TPM_DELEGATE_FAMILY:
      return "Attempt to manage a family other then the delegated family.";
    case TPM_DELEGATE_ADMIN:
      return "Delegation table management not enabled.";
    case TPM_TRANSPORT_NOTEXCLUSIVE:
      return "There was a command executed outside of an exclusive "
	"transport session.";
    case TPM_OWNER_CONTROL:
      return "Attempt to context save a owner evict controlled key.";
    case TPM_DAA_RESOURCES:
      return "The DAA command has no resources available to "
	"execute the command.";
    case TPM_DAA_INPUT_DATA0:
      return "The consistency check on DAA parameter inputData0 has failed.";
    case TPM_DAA_INPUT_DATA1:
      return "The consistency check on DAA parameter inputData1 has failed.";
    case TPM_DAA_ISSUER_SETTINGS:
      return "The consistency check on DAA_issuerSettings has failed.";
    case TPM_DAA_TPM_SETTINGS:
      return "The consistency check on DAA_tpmSpecific has failed.";
    case TPM_DAA_STAGE:
      return "The atomic process indicated by the submitted DAA command "
	"is not the expected process.";
    case TPM_DAA_ISSUER_VALIDITY:
      return "The issuer's validity check has detected an inconsistency.";
    case TPM_DAA_WRONG_W:
      return "The consistency check on w has failed.";
    case TPM_BAD_HANDLE:
      return "The handle is incorrect.";
    case TPM_BAD_DELEGATE:
      return "Delegation is not correct.";
    case TPM_BADCONTEXT:
      return "The context blob is invalid.";
    case TPM_TOOMANYCONTEXTS:
      return "Too many contexts held by the TPM.";
    case TPM_MA_TICKET_SIGNATURE:
      return "Migration authority signature validation failure.";
    case TPM_MA_DESTINATION:
      return "Migration destination not authenticated.";
    case TPM_MA_SOURCE:
      return "Migration source incorrect.";
    case TPM_MA_AUTHORITY:
      return "Incorrect migration authority.";
    case TPM_PERMANENTEK:
      return "Attempt to revoke the EK and the EK is not revocable.";
    case TPM_BAD_SIGNATURE:
      return "Bad signature of CMK ticket.";
    case TPM_NOCONTEXTSPACE:
      return "There is no room in the context list for additional contexts.";
    case TPM_RETRY:
      return "The TPM is too busy to respond to the command immediately, "
	"but the command could be resubmitted at a later time.";
    default:
      return "Unknown TPM error";
  }
}

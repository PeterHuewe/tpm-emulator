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
 * $Id: tpm_marshalling.h 384 2010-02-17 14:17:43Z mast $
 */

#ifndef _TPM_MARSHALLING_H_
#define _TPM_MARSHALLING_H_

#include "tpm_emulator.h"
#include "tpm_structures.h"

/*
 * The following functions perform the data marshalling of all
 * TPM structures (as defined in [TPM_Part2]) which are used
 * either as an input or an output parameter by one of the
 * TPM commands (as defined in [TPM_Part3]).
 */

/**
 * tpm_marshal_TYPE - marshals a value of type TYPE
 * @ptr: target buffer to store the marshalled value into
 * @length: length of the target buffer
 * @v: value to marshal
 * Returns: 0 on success, -1 otherwise
 *
 * Description: Performs the data marshalling for values of type TYPE.
 * On success 0 is returned and the values of ptr as well as length are
 * updated (i.e., ptr := ptr + sizeof(marshalled value) and length :=
 * length - sizeof(marshalled value)). In case of an error, -1 is
 * returned and the values of ptr and length are undefined.
 */

/**
 * tpm_unmarshal_TYPE - unmarshals a value of type TYPE
 * @ptr: source buffer containing the marshalled value
 * @length: length of the source buffer
 * @v: variable to store the unmarshalled value into
 * Returns: 0 on success, -1 otherwise
 *
 * Description: Performs the data unmarshalling for values of type TYPE.
 * On success 0 is returned and the values of ptr as well as length are
 * updated (i.e., ptr := ptr + sizeof(marshalled value) and length :=
 * length - sizeof(marshalled value)). In case of an error, -1 is
 * returned and the values of ptr and length are undefined.
 */

static inline int tpm_marshal_BYTE(BYTE **ptr, UINT32 *length, BYTE v)
{
  if (*length < 1) return -1;
  **ptr = v;
  *ptr += 1; *length -= 1;
  return 0;
}

static inline int tpm_unmarshal_BYTE(BYTE **ptr, UINT32 *length, BYTE *v)
{
  if (*length < 1) return -1;
  *v = **ptr;
  *ptr += 1; *length -= 1;
  return 0;
}

static inline int tpm_marshal_UINT16(BYTE **ptr, UINT32 *length, UINT16 v)
{
  if (*length < 2) return -1;
  (*ptr)[0] = (BYTE)((v >> 8) & 0xff); 
  (*ptr)[1] = (BYTE)(v & 0xff);
  *ptr += 2; *length -= 2;
  return 0;
}

static inline int tpm_unmarshal_UINT16(BYTE **ptr, UINT32 *length, UINT16 *v)
{
  if (*length < 2) return -1;
  *v = (((UINT16)(*ptr)[0] << 8) | (*ptr)[1]);
  *ptr += 2; *length -= 2;
  return 0;
}

static inline int tpm_marshal_UINT32(BYTE **ptr, UINT32 *length, UINT32 v)
{
  if (*length < 4) return -1;
  (*ptr)[0] = (BYTE)((v >> 24) & 0xff); (*ptr)[1] = (BYTE)((v >> 16) & 0xff);
  (*ptr)[2] = (BYTE)((v >>  8) & 0xff); (*ptr)[3] = (BYTE)(v & 0xff);
  *ptr += 4; *length -= 4;
  return 0;
}

static inline int tpm_unmarshal_UINT32(BYTE **ptr, UINT32 *length, UINT32 *v)
{
  if (*length < 4) return -1;
  *v = (((UINT32)(*ptr)[0] << 24) | ((UINT32)(*ptr)[1] << 16) | 
        ((UINT32)(*ptr)[2] <<  8) | (*ptr)[3]);
  *ptr += 4; *length -= 4;
  return 0;
}

static inline int tpm_marshal_UINT64(BYTE **ptr, UINT32 *length, UINT64 v)
{
  if (*length < 8) return -1;
  (*ptr)[0] = (BYTE)((v >> 56) & 0xff); (*ptr)[1] = (BYTE)((v >> 48) & 0xff);
  (*ptr)[2] = (BYTE)((v >> 40) & 0xff); (*ptr)[3] = (BYTE)((v >> 32) & 0xff);
  (*ptr)[4] = (BYTE)((v >> 24) & 0xff); (*ptr)[5] = (BYTE)((v >> 16) & 0xff);
  (*ptr)[6] = (BYTE)((v >>  8) & 0xff); (*ptr)[7] = (BYTE)(v & 0xff);
  *ptr += 8; *length -= 8;
  return 0;
}

static inline int tpm_unmarshal_UINT64(BYTE **ptr, UINT32 *length, UINT64 *v)
{
  if (*length < 8) return -1;
  *v = (((UINT64)(*ptr)[0] << 56) | ((UINT64)(*ptr)[1] << 48) |
        ((UINT64)(*ptr)[2] << 40) | ((UINT64)(*ptr)[3] << 32) |
        ((UINT64)(*ptr)[4] << 24) | ((UINT64)(*ptr)[5] << 16) |
        ((UINT64)(*ptr)[6] <<  8) | (*ptr)[7]);
  *ptr += 8; *length -= 8;
  return 0;
}

static inline int tpm_marshal_BLOB(BYTE **ptr, UINT32 *ptr_length,
                                   BYTE *b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  if (b_length) memcpy(*ptr, b, b_length);
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tpm_unmarshal_BLOB(BYTE **ptr, UINT32 *ptr_length,
                                     BYTE **b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  *b = (b_length) ? *ptr : NULL;
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tpm_marshal_BYTE_ARRAY(BYTE **ptr, UINT32 *ptr_length,
                                         BYTE *b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  memcpy(*ptr, b, b_length);
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tpm_unmarshal_BYTE_ARRAY(BYTE **ptr, UINT32 *ptr_length,
                                           BYTE *b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  if (b_length) memcpy(b, *ptr, b_length);
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tpm_marshal_BOOL(BYTE **ptr, UINT32 *length, BOOL v)
{
  if (*length < 1) return -1;
  **ptr = v & 0x01;
  *ptr += 1; *length -= 1;
  return 0;
}

static inline int tpm_unmarshal_BOOL(BYTE **ptr, UINT32 *length, BOOL *v)
{
  if (*length < 1 || (**ptr & 0xfe)) return -1;
  *v = **ptr;
  *ptr += 1; *length -= 1;
  return 0;
}

#define tpm_marshal_BOOL_ARRAY                 tpm_marshal_BYTE_ARRAY
#define tpm_unmarshal_BOOL_ARRAY               tpm_unmarshal_BYTE_ARRAY
#define tpm_marshal_TPM_AUTH_DATA_USAGE        tpm_marshal_BYTE
#define tpm_unmarshal_TPM_AUTH_DATA_USAGE      tpm_unmarshal_BYTE
#define tpm_marshal_TPM_PAYLOAD_TYPE           tpm_marshal_BYTE
#define tpm_unmarshal_TPM_PAYLOAD_TYPE         tpm_unmarshal_BYTE
#define tpm_marshal_TPM_LOCALITY_SELECTION     tpm_marshal_BYTE
#define tpm_unmarshal_TPM_LOCALITY_SELECTION   tpm_unmarshal_BYTE
#define tpm_marshal_TPM_TAG                    tpm_marshal_UINT16
#define tpm_unmarshal_TPM_TAG                  tpm_unmarshal_UINT16
#define tpm_marshal_TPM_PROTOCOL_ID            tpm_marshal_UINT16
#define tpm_unmarshal_TPM_PROTOCOL_ID          tpm_unmarshal_UINT16
#define tpm_marshal_TPM_STARTUP_TYPE           tpm_marshal_UINT16
#define tpm_unmarshal_TPM_STARTUP_TYPE         tpm_unmarshal_UINT16
#define tpm_marshal_TPM_ENC_SCHEME             tpm_marshal_UINT16
#define tpm_unmarshal_TPM_ENC_SCHEME           tpm_unmarshal_UINT16
#define tpm_marshal_TPM_SIG_SCHEME             tpm_marshal_UINT16
#define tpm_unmarshal_TPM_SIG_SCHEME           tpm_unmarshal_UINT16
#define tpm_marshal_TPM_MIGRATE_SCHEME         tpm_marshal_UINT16
#define tpm_unmarshal_TPM_MIGRATE_SCHEME       tpm_unmarshal_UINT16
#define tpm_marshal_TPM_PHYSICAL_PRESENCE      tpm_marshal_UINT16
#define tpm_unmarshal_TPM_PHYSICAL_PRESENCE    tpm_unmarshal_UINT16
#define tpm_marshal_TPM_ENTITY_TYPE            tpm_marshal_UINT16
#define tpm_unmarshal_TPM_ENTITY_TYPE          tpm_unmarshal_UINT16
#define tpm_marshal_TPM_KEY_USAGE              tpm_marshal_UINT16
#define tpm_unmarshal_TPM_KEY_USAGE            tpm_unmarshal_UINT16
#define tpm_marshal_TPM_STRUCTURE_TAG          tpm_marshal_UINT16
#define tpm_unmarshal_TPM_STRUCTURE_TAG        tpm_unmarshal_UINT16
#define tpm_marshal_TPM_PLATFORM_SPECIFIC      tpm_marshal_UINT16
#define tpm_unmarshal_TPM_PLATFORM_SPECIFIC    tpm_unmarshal_UINT16
#define tpm_marshal_TPM_EK_TYPE                tpm_marshal_UINT16
#define tpm_unmarshal_TPM_EK_TYPE              tpm_unmarshal_UINT16
#define tpm_marshal_TPM_COMMAND_CODE           tpm_marshal_UINT32
#define tpm_unmarshal_TPM_COMMAND_CODE         tpm_unmarshal_UINT32
#define tpm_marshal_TPM_CAPABILITY_AREA        tpm_marshal_UINT32
#define tpm_unmarshal_TPM_CAPABILITY_AREA      tpm_unmarshal_UINT32
#define tpm_marshal_TPM_KEY_FLAGS              tpm_marshal_UINT32
#define tpm_unmarshal_TPM_KEY_FLAGS            tpm_unmarshal_UINT32
#define tpm_marshal_TPM_ALGORITHM_ID           tpm_marshal_UINT32
#define tpm_unmarshal_TPM_ALGORITHM_ID         tpm_unmarshal_UINT32
#define tpm_marshal_TPM_MODIFIER_INDICATOR     tpm_marshal_UINT32
#define tpm_unmarshal_TPM_MODIFIER_INDICATOR   tpm_unmarshal_UINT32
#define tpm_marshal_TPM_ACTUAL_COUNT           tpm_marshal_UINT32
#define tpm_unmarshal_TPM_ACTUAL_COUNT         tpm_unmarshal_UINT32
#define tpm_marshal_TPM_TRANSPORT_ATTRIBUTES   tpm_marshal_UINT32
#define tpm_unmarshal_TPM_TRANSPORT_ATTRIBUTES tpm_unmarshal_UINT32
#define tpm_marshal_TPM_AUTHHANDLE             tpm_marshal_UINT32
#define tpm_unmarshal_TPM_AUTHHANDLE           tpm_unmarshal_UINT32
#define tpm_marshal_TPM_RESULT                 tpm_marshal_UINT32
#define tpm_unmarshal_TPM_RESULT               tpm_unmarshal_UINT32
#define tpm_marshal_TPM_DIRINDEX               tpm_marshal_UINT32
#define tpm_unmarshal_TPM_DIRINDEX             tpm_unmarshal_UINT32
#define tpm_marshal_TPM_KEY_HANDLE             tpm_marshal_UINT32
#define tpm_unmarshal_TPM_KEY_HANDLE           tpm_unmarshal_UINT32
#define tpm_marshal_TPM_PCRINDEX               tpm_marshal_UINT32
#define tpm_unmarshal_TPM_PCRINDEX             tpm_unmarshal_UINT32
#define tpm_marshal_TPM_RESOURCE_TYPE          tpm_marshal_UINT32
#define tpm_unmarshal_TPM_RESOURCE_TYPE        tpm_unmarshal_UINT32
#define tpm_marshal_TPM_KEY_CONTROL            tpm_marshal_UINT32
#define tpm_unmarshal_TPM_KEY_CONTROL          tpm_unmarshal_UINT32  
#define tpm_marshal_TPM_NV_INDEX               tpm_marshal_UINT32
#define tpm_unmarshal_TPM_NV_INDEX             tpm_unmarshal_UINT32
#define tpm_marshal_TPM_FAMILY_ID              tpm_marshal_UINT32
#define tpm_unmarshal_TPM_FAMILY_ID            tpm_unmarshal_UINT32
#define tpm_marshal_TPM_FAMILY_VERIFICATION    tpm_marshal_UINT32
#define tpm_unmarshal_TPM_FAMILY_VERIFICATION  tpm_unmarshal_UINT32
#define tpm_marshal_TPM_STARTUP_EFFECTS        tpm_marshal_UINT32
#define tpm_unmarshal_TPM_STARTUP_EFFECTS      tpm_unmarshal_UINT32
#define tpm_marshal_TPM_SYM_MODE               tpm_marshal_UINT32
#define tpm_unmarshal_TPM_SYM_MODE             tpm_unmarshal_UINT32
#define tpm_marshal_TPM_FAMILY_FLAGS           tpm_marshal_UINT32
#define tpm_unmarshal_TPM_FAMILY_FLAGS         tpm_unmarshal_UINT32
#define tpm_marshal_TPM_DELEGATE_INDEX         tpm_marshal_UINT32
#define tpm_unmarshal_TPM_DELEGATE_INDEX       tpm_unmarshal_UINT32
#define tpm_marshal_TPM_COUNT_ID               tpm_marshal_UINT32
#define tpm_unmarshal_TPM_COUNT_ID             tpm_unmarshal_UINT32
#define tpm_marshal_TPM_TRANSHANDLE            tpm_marshal_UINT32
#define tpm_unmarshal_TPM_TRANSHANDLE          tpm_unmarshal_UINT32
#define tpm_marshal_TPM_HANDLE                 tpm_marshal_UINT32
#define tpm_unmarshal_TPM_HANDLE               tpm_unmarshal_UINT32
#define tpm_marshal_TPM_FAMILY_OPERATION       tpm_marshal_UINT32
#define tpm_unmarshal_TPM_FAMILY_OPERATION     tpm_unmarshal_UINT32
#define tpm_marshal_TPM_CMK_DELEGATE           tpm_marshal_UINT32
#define tpm_unmarshal_TPM_CMK_DELEGATE         tpm_unmarshal_UINT32
#define tpm_marshal_TPM_REDIR_COMMAND          tpm_marshal_UINT32
#define tpm_unmarshal_TPM_REDIR_COMMAND        tpm_unmarshal_UINT32
#define tpm_marshal_DAAHANDLE                  tpm_marshal_UINT32
#define tpm_unmarshal_DAAHANDLE                tpm_unmarshal_UINT32

int tpm_marshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length, UINT32 *v, UINT32 n);
int tpm_unmarshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length, UINT32 *v, UINT32 n);

int tpm_marshal_TPM_STRUCT_VER(BYTE **ptr, UINT32 *length, TPM_STRUCT_VER *v);
int tpm_unmarshal_TPM_STRUCT_VER(BYTE **ptr, UINT32 *length, TPM_STRUCT_VER *v);

int tpm_marshal_TPM_VERSION(BYTE **ptr, UINT32 *length, TPM_VERSION *v);
int tpm_unmarshal_TPM_VERSION(BYTE **ptr, UINT32 *length, TPM_VERSION *v);

int tpm_marshal_TPM_DIGEST(BYTE **ptr, UINT32 *length, TPM_DIGEST *v);
int tpm_unmarshal_TPM_DIGEST(BYTE **ptr, UINT32 *length, TPM_DIGEST *v);

#define tpm_marshal_TPM_CHOSENID_HASH          tpm_marshal_TPM_DIGEST
#define tpm_unmarshal_TPM_CHOSENID_HASH        tpm_unmarshal_TPM_DIGEST
#define tpm_marshal_TPM_COMPOSITE_HASH         tpm_marshal_TPM_DIGEST
#define tpm_unmarshal_TPM_COMPOSITE_HASH       tpm_unmarshal_TPM_DIGEST
#define tpm_marshal_TPM_DIRVALUE               tpm_marshal_TPM_DIGEST
#define tpm_unmarshal_TPM_DIRVALUE             tpm_unmarshal_TPM_DIGEST
#define tpm_marshal_TPM_HMAC                   tpm_marshal_TPM_DIGEST
#define tpm_unmarshal_TPM_HMAC                 tpm_unmarshal_TPM_DIGEST
#define tpm_marshal_TPM_PCRVALUE               tpm_marshal_TPM_DIGEST
#define tpm_unmarshal_TPM_PCRVALUE             tpm_unmarshal_TPM_DIGEST

int tpm_marshal_TPM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length, TPM_PCRVALUE *v, UINT32 n);
int tpm_unmarshal_TPM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length, TPM_PCRVALUE *v, UINT32 n);

int tpm_marshal_TPM_NONCE(BYTE **ptr, UINT32 *length, TPM_NONCE *v);
int tpm_unmarshal_TPM_NONCE(BYTE **ptr, UINT32 *length, TPM_NONCE *v);

int tpm_marshal_TPM_AUTHDATA(BYTE **ptr, UINT32 *length, TPM_AUTHDATA *v);
int tpm_unmarshal_TPM_AUTHDATA(BYTE **ptr, UINT32 *length, TPM_AUTHDATA *v);

#define tpm_marshal_TPM_SECRET                 tpm_marshal_TPM_AUTHDATA
#define tpm_unmarshal_TPM_SECRET               tpm_unmarshal_TPM_AUTHDATA
#define tpm_marshal_TPM_ENCAUTH                tpm_marshal_TPM_AUTHDATA
#define tpm_unmarshal_TPM_ENCAUTH              tpm_unmarshal_TPM_AUTHDATA

int tpm_marshal_TPM_AUTH(BYTE **ptr, UINT32 *length, TPM_AUTH *v);
int tpm_unmarshal_TPM_AUTH(BYTE **ptr, UINT32 *length, TPM_AUTH *v);

int tpm_marshal_TPM_KEY_HANDLE_LIST(BYTE **ptr, UINT32 *length, TPM_KEY_HANDLE_LIST *v);

int tpm_marshal_TPM_CHANGEAUTH_VALIDATE(BYTE **ptr, UINT32 *length, TPM_CHANGEAUTH_VALIDATE *v);
int tpm_unmarshal_TPM_CHANGEAUTH_VALIDATE(BYTE **ptr, UINT32 *length, TPM_CHANGEAUTH_VALIDATE *v);

int tpm_marshal_TPM_COUNTER_VALUE(BYTE **ptr, UINT32 *length, TPM_COUNTER_VALUE *v);
int tpm_unmarshal_TPM_COUNTER_VALUE(BYTE **ptr, UINT32 *length, TPM_COUNTER_VALUE *v);

int tpm_marshal_TPM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TPM_PCR_SELECTION *v);
int tpm_unmarshal_TPM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TPM_PCR_SELECTION *v);

int tpm_marshal_TPM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_PCR_COMPOSITE *v);
int tpm_unmarshal_TPM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_PCR_COMPOSITE *v);

int tpm_marshal_TPM_PCR_INFO(BYTE **ptr, UINT32 *length, TPM_PCR_INFO *v);
int tpm_unmarshal_TPM_PCR_INFO(BYTE **ptr, UINT32 *length, TPM_PCR_INFO *v);

int tpm_marshal_TPM_PCR_INFO_SHORT(BYTE **ptr, UINT32 *length, TPM_PCR_INFO_SHORT *v);
int tpm_unmarshal_TPM_PCR_INFO_SHORT(BYTE **ptr, UINT32 *length, TPM_PCR_INFO_SHORT *v);

int tpm_marshal_TPM_PCR_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_PCR_ATTRIBUTES *v);
int tpm_unmarshal_TPM_PCR_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_PCR_ATTRIBUTES *v);

int tpm_marshal_TPM_STORED_DATA(BYTE **ptr, UINT32 *length, TPM_STORED_DATA *v);
int tpm_unmarshal_TPM_STORED_DATA(BYTE **ptr, UINT32 *length, TPM_STORED_DATA *v);

int tpm_marshal_TPM_SEALED_DATA(BYTE **ptr, UINT32 *length, TPM_SEALED_DATA *v);
int tpm_unmarshal_TPM_SEALED_DATA(BYTE **ptr, UINT32 *length, TPM_SEALED_DATA *v);

int tpm_marshal_TPM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY *v);
int tpm_unmarshal_TPM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY *v);

int tpm_marshal_TPM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY_PARMS *v);
int tpm_unmarshal_TPM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_SYMMETRIC_KEY_PARMS *v);

int tpm_marshal_TPM_RSA_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_RSA_KEY_PARMS *v);
int tpm_unmarshal_TPM_RSA_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_RSA_KEY_PARMS *v);

int tpm_marshal_TPM_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_KEY_PARMS *v);
int tpm_unmarshal_TPM_KEY_PARMS(BYTE **ptr, UINT32 *length, TPM_KEY_PARMS *v);

int tpm_marshal_TPM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PUBKEY *v);
int tpm_unmarshal_TPM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PUBKEY *v);

int tpm_marshal_TPM_KEY(BYTE **ptr, UINT32 *length, TPM_KEY *v);
int tpm_unmarshal_TPM_KEY(BYTE **ptr, UINT32 *length, TPM_KEY *v);

int tpm_marshal_TPM_PUBKEY(BYTE **ptr, UINT32 *length, TPM_PUBKEY *v);
int tpm_unmarshal_TPM_PUBKEY(BYTE **ptr, UINT32 *length, TPM_PUBKEY *v);

int tpm_marshal_TPM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PRIVKEY *v);
int tpm_unmarshal_TPM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TPM_STORE_PRIVKEY *v);

int tpm_marshal_TPM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TPM_STORE_ASYMKEY *v);
int tpm_unmarshal_TPM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TPM_STORE_ASYMKEY *v);

int tpm_marshal_TPM_MIGRATIONKEYAUTH(BYTE **ptr, UINT32 *length, TPM_MIGRATIONKEYAUTH *v);
int tpm_unmarshal_TPM_MIGRATIONKEYAUTH(BYTE **ptr, UINT32 *length, TPM_MIGRATIONKEYAUTH *v);

int tpm_marshal_TPM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TPM_CERTIFY_INFO *v);
int tpm_unmarshal_TPM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TPM_CERTIFY_INFO *v);

int tpm_marshal_TPM_IDENTITY_CONTENTS(BYTE **ptr, UINT32 *length, TPM_IDENTITY_CONTENTS *v);
int tpm_unmarshal_TPM_IDENTITY_CONTENTS(BYTE **ptr, UINT32 *length, TPM_IDENTITY_CONTENTS *v);

int tpm_marshal_TPM_CURRENT_TICKS(BYTE **ptr, UINT32 *length, TPM_CURRENT_TICKS *v);
int tpm_unmarshal_TPM_CURRENT_TICKS(BYTE **ptr, UINT32 *length, TPM_CURRENT_TICKS *v);

int tpm_marshal_TPM_TRANSPORT_PUBLIC(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_PUBLIC *v);
int tpm_unmarshal_TPM_TRANSPORT_PUBLIC(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_PUBLIC *v);

int tpm_marshal_TPM_TRANSPORT_INTERNAL(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_INTERNAL *v);
int tpm_unmarshal_TPM_TRANSPORT_INTERNAL(BYTE **ptr, UINT32 *length, TPM_TRANSPORT_INTERNAL *v);

int tpm_marshal_TPM_CONTEXT_BLOB(BYTE **ptr, UINT32 *length, TPM_CONTEXT_BLOB *v);
int tpm_unmarshal_TPM_CONTEXT_BLOB(BYTE **ptr, UINT32 *length, TPM_CONTEXT_BLOB *v);

int tpm_marshal_TPM_CONTEXT_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_CONTEXT_SENSITIVE *v);
int tpm_unmarshal_TPM_CONTEXT_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_CONTEXT_SENSITIVE *v);

int tpm_marshal_TPM_DAA_BLOB(BYTE **ptr, UINT32 *length, TPM_DAA_BLOB *v);
int tpm_unmarshal_TPM_DAA_BLOB(BYTE **ptr, UINT32 *length, TPM_DAA_BLOB *v);

int tpm_marshal_TPM_DAA_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DAA_SENSITIVE *v);
int tpm_unmarshal_TPM_DAA_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DAA_SENSITIVE *v);

int tpm_marshal_TPM_DAA_ISSUER(BYTE **ptr, UINT32 *length, TPM_DAA_ISSUER *v);
int tpm_unmarshal_TPM_DAA_ISSUER(BYTE **ptr, UINT32 *length, TPM_DAA_ISSUER *v);

int tpm_marshal_TPM_DAA_TPM(BYTE **ptr, UINT32 *length, TPM_DAA_TPM *v);
int tpm_unmarshal_TPM_DAA_TPM(BYTE **ptr, UINT32 *length, TPM_DAA_TPM *v);

int tpm_marshal_TPM_DAA_CONTEXT(BYTE **ptr, UINT32 *length, TPM_DAA_CONTEXT *v);
int tpm_unmarshal_TPM_DAA_CONTEXT(BYTE **ptr, UINT32 *length, TPM_DAA_CONTEXT *v);

int tpm_marshal_TPM_DAA_JOINDATA(BYTE **ptr, UINT32 *length, TPM_DAA_JOINDATA *v);
int tpm_unmarshal_TPM_DAA_JOINDATA(BYTE **ptr, UINT32 *length, TPM_DAA_JOINDATA *v);

int tpm_marshal_TPM_DAA_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_DAA_SESSION_DATA *v);
int tpm_unmarshal_TPM_DAA_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_DAA_SESSION_DATA *v);

int tpm_marshal_TPM_MSA_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_MSA_COMPOSITE *v);
int tpm_unmarshal_TPM_MSA_COMPOSITE(BYTE **ptr, UINT32 *length, TPM_MSA_COMPOSITE *v);

int tpm_marshal_TPM_CMK_AUTH(BYTE **ptr, UINT32 *length, TPM_CMK_AUTH *v);
int tpm_unmarshal_TPM_CMK_AUTH(BYTE **ptr, UINT32 *length, TPM_CMK_AUTH *v);

int tpm_marshal_TPM_SELECT_SIZE(BYTE **ptr, UINT32 *length, TPM_SELECT_SIZE *v);
int tpm_unmarshal_TPM_SELECT_SIZE(BYTE **ptr, UINT32 *length, TPM_SELECT_SIZE *v);

int tpm_marshal_TPM_CAP_VERSION_INFO(BYTE **ptr, UINT32 *length, TPM_CAP_VERSION_INFO *v);
int tpm_unmarshal_TPM_CAP_VERSION_INFO(BYTE **ptr, UINT32 *length, TPM_CAP_VERSION_INFO *v);

int tpm_marshal_TPM_ASYM_CA_CONTENTS(BYTE **ptr, UINT32 *length, TPM_ASYM_CA_CONTENTS *v);
int tpm_unmarshal_TPM_ASYM_CA_CONTENTS(BYTE **ptr, UINT32 *length, TPM_ASYM_CA_CONTENTS *v);

int tpm_marshal_TPM_QUOTE_INFO2(BYTE **ptr, UINT32 *length, TPM_QUOTE_INFO2 *v);
int tpm_unmarshal_TPM_QUOTE_INFO2(BYTE **ptr, UINT32 *length, TPM_QUOTE_INFO2 *v);

int tpm_marshal_TPM_EK_BLOB(BYTE **ptr, UINT32 *length, TPM_EK_BLOB *v);
int tpm_unmarshal_TPM_EK_BLOB(BYTE **ptr, UINT32 *length, TPM_EK_BLOB *v);

int tpm_marshal_TPM_EK_BLOB_ACTIVATE(BYTE **ptr, UINT32 *length, TPM_EK_BLOB_ACTIVATE *v);
int tpm_unmarshal_TPM_EK_BLOB_ACTIVATE(BYTE **ptr, UINT32 *length, TPM_EK_BLOB_ACTIVATE *v);

int tpm_marshal_TPM_NV_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_NV_ATTRIBUTES *v);
int tpm_unmarshal_TPM_NV_ATTRIBUTES(BYTE **ptr, UINT32 *length, TPM_NV_ATTRIBUTES *v);

int tpm_marshal_TPM_NV_DATA_PUBLIC(BYTE **ptr, UINT32 *length, TPM_NV_DATA_PUBLIC *v);
int tpm_unmarshal_TPM_NV_DATA_PUBLIC(BYTE **ptr, UINT32 *length, TPM_NV_DATA_PUBLIC *v);

int tpm_marshal_TPM_DELEGATIONS(BYTE **ptr, UINT32 *length, TPM_DELEGATIONS *v);
int tpm_unmarshal_TPM_DELEGATIONS(BYTE **ptr, UINT32 *length, TPM_DELEGATIONS *v);

int tpm_marshal_TPM_FAMILY_LABEL(BYTE **ptr, UINT32 *length, TPM_FAMILY_LABEL *v);
int tpm_unmarshal_TPM_FAMILY_LABEL(BYTE **ptr, UINT32 *length, TPM_FAMILY_LABEL *v);

int tpm_marshal_TPM_FAMILY_TABLE_ENTRY(BYTE **ptr, UINT32 *length, TPM_FAMILY_TABLE_ENTRY *v);
int tpm_unmarshal_TPM_FAMILY_TABLE_ENTRY(BYTE **ptr, UINT32 *length, TPM_FAMILY_TABLE_ENTRY *v);

int tpm_marshal_TPM_DELEGATE_LABEL(BYTE **ptr, UINT32 *length, TPM_DELEGATE_LABEL *v);
int tpm_unmarshal_TPM_DELEGATE_LABEL(BYTE **ptr, UINT32 *length, TPM_DELEGATE_LABEL *v);

int tpm_marshal_TPM_DELEGATE_PUBLIC(BYTE **ptr, UINT32 *length, TPM_DELEGATE_PUBLIC *v);
int tpm_unmarshal_TPM_DELEGATE_PUBLIC(BYTE **ptr, UINT32 *length, TPM_DELEGATE_PUBLIC *v);

int tpm_marshal_TPM_DELEGATE_PUBLIC_ARRAY(BYTE **ptr, UINT32 *length, TPM_DELEGATE_PUBLIC *v, UINT32 n);
int tpm_unmarshal_TPM_DELEGATE_PUBLIC_ARRAY(BYTE **ptr, UINT32 *length, TPM_DELEGATE_PUBLIC *v, UINT32 n);

int tpm_marshal_TPM_DELEGATE_TABLE_ROW(BYTE **ptr, UINT32 *length, TPM_DELEGATE_TABLE_ROW *v);
int tpm_unmarshal_TPM_DELEGATE_TABLE_ROW(BYTE **ptr, UINT32 *length, TPM_DELEGATE_TABLE_ROW *v);

int tpm_marshal_TPM_DELEGATE_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DELEGATE_SENSITIVE *v);
int tpm_unmarshal_TPM_DELEGATE_SENSITIVE(BYTE **ptr, UINT32 *length, TPM_DELEGATE_SENSITIVE *v);

int tpm_marshal_TPM_DELEGATE_OWNER_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_OWNER_BLOB *v);
int tpm_unmarshal_TPM_DELEGATE_OWNER_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_OWNER_BLOB *v);

int tpm_marshal_TPM_DELEGATE_KEY_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_KEY_BLOB *v);
int tpm_unmarshal_TPM_DELEGATE_KEY_BLOB(BYTE **ptr, UINT32 *length, TPM_DELEGATE_KEY_BLOB *v);

int tpm_marshal_TPM_PERMANENT_FLAGS(BYTE **ptr, UINT32 *length, TPM_PERMANENT_FLAGS *v);
int tpm_unmarshal_TPM_PERMANENT_FLAGS(BYTE **ptr, UINT32 *length, TPM_PERMANENT_FLAGS *v);

int tpm_marshal_TPM_STCLEAR_FLAGS(BYTE **ptr, UINT32 *length, TPM_STCLEAR_FLAGS *v);
int tpm_unmarshal_TPM_STCLEAR_FLAGS(BYTE **ptr, UINT32 *length, TPM_STCLEAR_FLAGS *v);

int tpm_marshal_TPM_STANY_FLAGS(BYTE **ptr, UINT32 *length, TPM_STANY_FLAGS *v);
int tpm_unmarshal_TPM_STANY_FLAGS(BYTE **ptr, UINT32 *length, TPM_STANY_FLAGS *v);

int tpm_marshal_RSA(BYTE **ptr, UINT32 *length, tpm_rsa_private_key_t *v);
int tpm_unmarshal_RSA(BYTE **ptr, UINT32 *length, tpm_rsa_private_key_t *v);

int tpm_marshal_RSAPub(BYTE **ptr, UINT32 *length, tpm_rsa_public_key_t *v);
int tpm_unmarshal_RSAPub(BYTE **ptr, UINT32 *length, tpm_rsa_public_key_t *v);

int tpm_marshal_TPM_KEY_DATA(BYTE **ptr, UINT32 *length, TPM_KEY_DATA *v);
int tpm_unmarshal_TPM_KEY_DATA(BYTE **ptr, UINT32 *length, TPM_KEY_DATA *v);

int tpm_marshal_TPM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TPM_PERMANENT_DATA *);
int tpm_unmarshal_TPM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TPM_PERMANENT_DATA *);

int tpm_marshal_TPM_STCLEAR_DATA(BYTE **ptr, UINT32 *length, TPM_STCLEAR_DATA *v);
int tpm_unmarshal_TPM_STCLEAR_DATA(BYTE **ptr, UINT32 *length, TPM_STCLEAR_DATA *v);

int tpm_marshal_TPM_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_SESSION_DATA *v);
int tpm_unmarshal_TPM_SESSION_DATA(BYTE **ptr, UINT32 *length, TPM_SESSION_DATA *v);

int tpm_marshal_TPM_STANY_DATA(BYTE **ptr, UINT32 *length, TPM_STANY_DATA *v);
int tpm_unmarshal_TPM_STANY_DATA(BYTE **ptr, UINT32 *length, TPM_STANY_DATA *v);

int tpm_unmarshal_TPM_DATA(BYTE **ptr, UINT32 *length, TPM_DATA *v);
int tpm_marshal_TPM_DATA(BYTE **ptr, UINT32 *length, TPM_DATA *v);

int tpm_marshal_TPM_RESPONSE(BYTE **ptr, UINT32 *length, TPM_RESPONSE *v);
int tpm_unmarshal_TPM_REQUEST(BYTE **ptr, UINT32 *length, TPM_REQUEST *v);

#endif /* _TPM_MARSHALLING_H_ */

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

#ifndef _MTM_MARSHALLING_H_
#define _MTM_MARSHALLING_H_

#include "mtm_structures.h"
#include "tpm/tpm_marshalling.h"

#define tpm_marshal_TPM_VERIFICATION_KEY_ID        tpm_marshal_UINT32
#define tpm_unmarshal_TPM_VERIFICATION_KEY_ID      tpm_unmarshal_UINT32
#define tpm_marshal_TPM_VERIFICATION_KEY_HANDLE    tpm_marshal_UINT32
#define tpm_unmarshal_TPM_VERIFICATION_KEY_HANDLE  tpm_unmarshal_UINT32

int tpm_marshal_MTM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, MTM_PERMANENT_DATA *v);
int tpm_unmarshal_MTM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, MTM_PERMANENT_DATA *v);

int tpm_marshal_MTM_STANY_FLAGS(BYTE **ptr, UINT32 *length, MTM_STANY_FLAGS *v);
int tpm_unmarshal_MTM_STANY_FLAGS(BYTE **ptr, UINT32 *length, MTM_STANY_FLAGS *v);

int tpm_marshal_MTM_COUNTER_REFERENCE(BYTE **ptr, UINT32 *length, MTM_COUNTER_REFERENCE *v);
int tpm_unmarshal_MTM_COUNTER_REFERENCE(BYTE **ptr, UINT32 *length, MTM_COUNTER_REFERENCE *v);

int tpm_marshal_TPM_RIM_CERTIFICATE(BYTE **ptr, UINT32 *length, TPM_RIM_CERTIFICATE *v);
int tpm_unmarshal_TPM_RIM_CERTIFICATE(BYTE **ptr, UINT32 *length, TPM_RIM_CERTIFICATE *v);

int tpm_marshal_TPM_VERIFICATION_KEY(BYTE **ptr, UINT32 *length, TPM_VERIFICATION_KEY *v);
int tpm_unmarshal_TPM_VERIFICATION_KEY(BYTE **ptr, UINT32 *length, TPM_VERIFICATION_KEY *v);

int tpm_marshal_MTM_KEY_DATA(BYTE **ptr, UINT32 *length, MTM_KEY_DATA *v);
int tpm_unmarshal_MTM_KEY_DATA(BYTE **ptr, UINT32 *length, MTM_KEY_DATA *v);

int tpm_marshal_MTM_DATA(BYTE **ptr, UINT32 *length, MTM_DATA *v);
int tpm_unmarshal_MTM_DATA(BYTE **ptr, UINT32 *length, MTM_DATA *v);

#endif /* _MTM_MARSHALLING_H_ */


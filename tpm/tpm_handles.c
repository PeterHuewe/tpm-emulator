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
 * $Id: tpm_handles.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_handles.h"
#include "tpm_data.h"

TPM_KEY_DATA *tpm_get_key_slot(TPM_KEY_HANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE) return NULL;
  handle &= 0x00ffffff;
  if (handle >= TPM_MAX_KEYS) return NULL;
  return &tpmData.permanent.data.keys[handle];
}

TPM_SESSION_DATA *tpm_get_session_slot(TPM_HANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE) return NULL;
  handle &= 0x00ffffff;
  if (handle >= TPM_MAX_SESSIONS) return NULL;
  return &tpmData.stany.data.sessions[handle];
}

TPM_DAA_SESSION_DATA *tpm_get_daa_slot(TPM_HANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE) return NULL;
  handle &= 0x00ffffff;
  if (handle >= TPM_MAX_SESSIONS_DAA) return NULL;
  return &tpmData.stany.data.sessionsDAA[handle];
}

TPM_KEY_DATA *tpm_get_key(TPM_KEY_HANDLE handle)
{
  /* handle reserved key handles */
  switch (handle) {
    case TPM_KH_EK:
    case TPM_KH_OWNER:
    case TPM_KH_REVOKE:
    case TPM_KH_TRANSPORT:
    case TPM_KH_OPERATOR:
    case TPM_KH_ADMIN:
      return NULL;
    case TPM_KH_SRK:
      debug("SRK valid? %d", tpmData.permanent.data.srk.payload);
      return (tpmData.permanent.data.srk.payload) ?
        &tpmData.permanent.data.srk : NULL;
  }
  if (handle == TPM_INVALID_HANDLE 
      || (handle >> 24) != TPM_RT_KEY) return NULL;
  handle &= 0x00ffffff;
  if (handle >= TPM_MAX_KEYS
      || !tpmData.permanent.data.keys[handle].payload) return NULL;
  return &tpmData.permanent.data.keys[handle];
}

TPM_SESSION_DATA *tpm_get_auth(TPM_AUTHHANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE
      || (handle >> 24) != TPM_RT_AUTH) return NULL;
  handle &= 0x00ffffff;
  if (handle >= TPM_MAX_SESSIONS
      || (tpmData.stany.data.sessions[handle].type != TPM_ST_OIAP
          && tpmData.stany.data.sessions[handle].type != TPM_ST_OSAP
          && tpmData.stany.data.sessions[handle].type != TPM_ST_DSAP)) return NULL;
  return &tpmData.stany.data.sessions[handle];
}

TPM_SESSION_DATA *tpm_get_transport(TPM_TRANSHANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE
      || (handle >> 24) != TPM_RT_TRANS) return NULL;
  handle &= 0x00ffffff;
  if (handle >= TPM_MAX_SESSIONS
      || tpmData.stany.data.sessions[handle].type != TPM_ST_TRANSPORT) return NULL;
  return &tpmData.stany.data.sessions[handle];
}

TPM_COUNTER_VALUE *tpm_get_counter(TPM_COUNT_ID handle)
{
  if ((handle == TPM_INVALID_HANDLE) || ((handle >> 24) != TPM_RT_COUNTER))
    return NULL;
  handle &= 0x00ffffff;
  if ((handle >= TPM_MAX_COUNTERS)
    || !tpmData.permanent.data.counters[handle].valid) return NULL;
  return &tpmData.permanent.data.counters[handle];
}

TPM_DAA_SESSION_DATA *tpm_get_daa(TPM_DAAHANDLE handle)
{
  if ((handle == TPM_INVALID_HANDLE) || ((handle >> 24) != TPM_RT_DAA_TPM))
    return NULL;
  handle &= 0x00ffffff;
  if ((handle >= TPM_MAX_SESSIONS_DAA)
    || (tpmData.stany.data.sessionsDAA[handle].type != TPM_ST_DAA)) return NULL;
  return &tpmData.stany.data.sessionsDAA[handle];
}

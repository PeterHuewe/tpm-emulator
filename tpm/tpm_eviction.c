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
 * $Id: tpm_eviction.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_handles.h"
#include "tpm_data.h"
#include "crypto/rsa.h"

/*
 * Eviction ([TPM_Part3], Section 22)
 * The TPM has numerous resources held inside of the TPM that may need 
 * eviction. The need for eviction occurs when the number or resources 
 * in use by the TPM exceed the available space. In version 1.1 there were 
 * separate commands to evict separate resource types. This new command 
 * set uses the resource types defined for context saving and creates a 
 * generic command that will evict all resource types.
 */

static void dump_sessions(void)
{
  int i;
  for (i = 0; i < TPM_MAX_SESSIONS; i++) {
    if (tpmData.stany.data.sessions[i].type != TPM_ST_INVALID) {
      debug("session[%d] = %08x", i, INDEX_TO_AUTH_HANDLE(i));
    }
  }
}

TPM_RESULT TPM_FlushSpecific(TPM_HANDLE handle, 
                             TPM_RESOURCE_TYPE resourceType)
{
  TPM_SESSION_DATA *session;
  TPM_DAA_SESSION_DATA *sessionDAA;
  TPM_KEY_DATA *key;
  int i;
  
  info("TPM_FlushSpecific()");
  debug("handle = %08x, resourceType = %08x", handle, resourceType);
  switch (resourceType) {
    case TPM_RT_CONTEXT:
      for (i = 0; i < TPM_MAX_SESSION_LIST; i++)
        if (tpmData.stany.data.contextList[i] == handle) break;
      if (i != TPM_MAX_SESSION_LIST)
        tpmData.stany.data.contextList[i] = 0;
      return TPM_SUCCESS;
    
    case TPM_RT_KEY:
      key = tpm_get_key(handle);
      if (key != NULL) {
        if (key->keyControl & TPM_KEY_CONTROL_OWNER_EVICT)
          return TPM_KEY_OWNER_CONTROL;
        if (handle == TPM_KH_SRK) return TPM_FAIL;
        tpm_rsa_release_private_key(&key->key);
        memset(key, 0, sizeof(*key));
        tpm_invalidate_sessions(handle);
      }
      return TPM_SUCCESS;
    
    case TPM_RT_HASH:
    case TPM_RT_COUNTER:
    case TPM_RT_DELEGATE:
      return TPM_INVALID_RESOURCE;
    
    case TPM_RT_AUTH:
      session = tpm_get_auth(handle);
      if (session != NULL)
        memset(session, 0, sizeof(*session));
      dump_sessions();
      return TPM_SUCCESS;
    
    case TPM_RT_TRANS:
      session = tpm_get_transport(handle);
      if (session != NULL)
        memset(session, 0, sizeof(*session));
      dump_sessions();
      return TPM_SUCCESS;
    
    case TPM_RT_DAA_TPM:
      sessionDAA = tpm_get_daa(handle);
      if (sessionDAA != NULL) {
        memset(sessionDAA, 0, sizeof(*sessionDAA));
        if (handle == tpmData.stany.data.currentDAA)
          tpmData.stany.data.currentDAA = 0;
        tpm_invalidate_sessions(handle);
      }
      return TPM_SUCCESS;
  }
  return TPM_INVALID_RESOURCE;
}

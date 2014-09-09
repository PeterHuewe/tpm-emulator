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

#include "mtm_commands.h"
#include "mtm_handles.h"
#include "tpm/tpm_commands.h"

TPM_RESULT MTM_FlushSpecific(TPM_HANDLE handle, 
                             TPM_RESOURCE_TYPE resourceType)
{
  MTM_KEY_DATA *key;
  
  info("MTM_FlushSpecific()");
  debug("handle = %08x, resourceType = %08x", handle, resourceType);
  if (resourceType == TPM_RT_KEY) {
    key = mtm_get_key(handle);
    if (key != NULL) {
      free_MTM_KEY_DATA((*key)); 
      memset(key, 0, sizeof(*key));
      tpm_invalidate_sessions(handle);
      return TPM_SUCCESS;
    } 
  }
  return TPM_FlushSpecific(handle, resourceType);
}


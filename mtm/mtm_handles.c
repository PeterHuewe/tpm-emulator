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

#include "mtm_handles.h"
#include "mtm_data.h"

MTM_KEY_DATA *mtm_get_key_slot(TPM_VERIFICATION_KEY_HANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE) return NULL;
  handle &= 0x00ffffff;
  if (handle < TPM_MAX_KEYS) return NULL;
  handle -= TPM_MAX_KEYS;
  if (handle >= MTM_MAX_KEYS) return NULL;
  return &mtmData.permanent.data.keys[handle];
}

MTM_KEY_DATA *mtm_get_key(TPM_VERIFICATION_KEY_HANDLE handle)
{
  if (handle == TPM_INVALID_HANDLE
      || (handle >> 24) != TPM_RT_KEY) return NULL;
  handle &= 0x00ffffff;
  if (handle < TPM_MAX_KEYS) return NULL;
  handle -= TPM_MAX_KEYS;
  if (handle >= MTM_MAX_KEYS
      || !mtmData.permanent.data.keys[handle].valid) return NULL;
  return &mtmData.permanent.data.keys[handle]; 
}

MTM_KEY_DATA *mtm_get_key_by_id(TPM_VERIFICATION_KEY_ID id)
{
  int i;
  for (i = 0; i < MTM_MAX_KEYS; i++) {
    if (mtmData.permanent.data.keys[i].valid
        && mtmData.permanent.data.keys[i].myId == id)
      return &mtmData.permanent.data.keys[i];
  }
  return NULL;
}


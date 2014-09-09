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

#include "mtm_structures.h"
#include "tpm/tpm_handles.h"

MTM_KEY_DATA *mtm_get_key_slot(TPM_VERIFICATION_KEY_HANDLE handle);

MTM_KEY_DATA *mtm_get_key(TPM_VERIFICATION_KEY_HANDLE handle);

MTM_KEY_DATA *mtm_get_key_by_id(TPM_VERIFICATION_KEY_ID id); 


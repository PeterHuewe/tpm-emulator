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
 * $Id: tpm_data.h 368 2010-02-15 09:26:37Z mast $
 */

#ifndef _TPM_DATA_H_
#define _TPM_DATA_H

#include "tpm_structures.h"

extern TPM_DATA tpmData;
extern UINT32 tpmConf;

BOOL tpm_get_physical_presence(void);

void tpm_init_data(void);

void tpm_release_data(void);

int tpm_store_permanent_data(void);

int tpm_restore_permanent_data(void);

int tpm_erase_permanent_data(void);

#endif /* _TPM_DATA_H_ */

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
 * $Id: rc4.h 364 2010-02-11 10:24:45Z mast $
 */
 
#ifndef _RC4_H_
#define _RC4_H_

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t state[256];
    uint8_t x, y;
} tpm_rc4_ctx_t;

void tpm_rc4_init(tpm_rc4_ctx_t *s, uint8_t *key, size_t key_len);

void tpm_rc4_crypt(tpm_rc4_ctx_t *s, uint8_t *in, uint8_t *out, size_t length);

#endif /* _RC4_h_ */

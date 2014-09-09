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
 * $Id: sha1.h 364 2010-02-11 10:24:45Z mast $
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_LENGTH 20

typedef struct {
  uint32_t h[5];
  uint32_t count_lo, count_hi;
  uint8_t buf[64];
} tpm_sha1_ctx_t;

void tpm_sha1_init(tpm_sha1_ctx_t *ctx);

void tpm_sha1_update(tpm_sha1_ctx_t *ctx, const uint8_t *data, size_t length);

void tpm_sha1_update_be32(tpm_sha1_ctx_t *ctx, uint32_t data);

void tpm_sha1_final(tpm_sha1_ctx_t *ctx, uint8_t digest[SHA1_DIGEST_LENGTH]);

#endif /* _SHA1_H_ */

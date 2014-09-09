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
 * $Id: hmac.c 364 2010-02-11 10:24:45Z mast $
 */

#include "hmac.h"
#include <string.h>

void tpm_hmac_init(tpm_hmac_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
  uint8_t tk[SHA1_DIGEST_LENGTH];
  uint8_t k_ipad[HMAC_PAD_LENGTH];
  int i;

  /* if the key is longer than 64 bytes reset it to key := hash(key) */
  if (key_len > HMAC_PAD_LENGTH) {
    tpm_sha1_init(&ctx->ctx);
    tpm_sha1_update(&ctx->ctx, key, key_len);
    tpm_sha1_final(&ctx->ctx, tk);
    key = tk;
    key_len = SHA1_DIGEST_LENGTH;
  }
  /* start out by storing key in pads */
  memset(k_ipad, 0, HMAC_PAD_LENGTH);
  memset(ctx->k_opad, 0, HMAC_PAD_LENGTH);
  memcpy(k_ipad, key, key_len);
  memcpy(ctx->k_opad, key, key_len);
  /* xor key with ipad and opad values */
  for (i = 0; i < HMAC_PAD_LENGTH; i++) {
    k_ipad[i] ^= 0x36;
    ctx->k_opad[i] ^= 0x5C;
  }
  /* start inner hash */
  tpm_sha1_init(&ctx->ctx);
  tpm_sha1_update(&ctx->ctx, k_ipad, HMAC_PAD_LENGTH);
}

void tpm_hmac_update(tpm_hmac_ctx_t *ctx, const uint8_t *data, size_t length)
{
  /* update inner hash */
  tpm_sha1_update(&ctx->ctx, data, length);
}

void tpm_hmac_final(tpm_hmac_ctx_t *ctx, uint8_t *digest)
{
  /* complete inner hash */
  tpm_sha1_final(&ctx->ctx, digest);
  /* perform outer hash */
  tpm_sha1_init(&ctx->ctx);
  tpm_sha1_update(&ctx->ctx, ctx->k_opad, HMAC_PAD_LENGTH);
  tpm_sha1_update(&ctx->ctx, digest, SHA1_DIGEST_LENGTH);
  tpm_sha1_final(&ctx->ctx, digest);
}


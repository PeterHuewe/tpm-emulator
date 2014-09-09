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
 * $Id: rc4.c 364 2010-02-11 10:24:45Z mast $
 */

#include "rc4.h"

void tpm_rc4_init(tpm_rc4_ctx_t *ctx, uint8_t *key, size_t key_len)
{
    int i;
    uint8_t a, j, k;
    
    ctx->x = ctx->y = 0;
    for (i = 0; i < 256; i++) {
        ctx->state[i] = i;
    }
    for (i = j = k = 0; i < 256; i++) {
        a = ctx->state[i];
        j += a + key[k++];
        ctx->state[i] = ctx->state[j];
        ctx->state[j] = a;
        if (k >= key_len) k = 0;        
    }
    /* to strengthen the algorithm it is recommended to
       discard the first few (say 256) octets */
    for (i = 0; i < 16; i++) {
        uint8_t buf[16];
        tpm_rc4_crypt(ctx, buf, buf, sizeof(buf));
    }
}

void tpm_rc4_crypt(tpm_rc4_ctx_t *ctx, uint8_t *in, uint8_t *out, size_t length)
{
    uint8_t a, x, y, *state;
    
    x = ctx->x;
    y = ctx->y;
    state = ctx->state;     
    while (length--) {
        x++;
        y += state[x];
        a = state[x];
        state[x] = state[y];
        state[y] = a;
        a += state[x];        
        *out++ = *in++ ^ state[a];
    }
    ctx->x = x;
    ctx->y = y;
}


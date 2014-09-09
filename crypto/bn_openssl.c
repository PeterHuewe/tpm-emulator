/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2011 Mario Strasser <mast@gmx.net>
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
 * $Id: bn.c 406 2010-02-19 11:08:30Z mast $
 */
 
#include "bn.h"

BN_CTX *bn_ctx = NULL;

void tpm_bn_init(tpm_bn_t a)
{
  if (bn_ctx == NULL) bn_ctx = BN_CTX_new();
  BN_init(a);
}

void tpm_bn_init2(tpm_bn_t a, size_t nbits)
{
  tpm_bn_init(a);
  BN_set_bit(a, nbits);
  BN_clear_bit(a, nbits);
}

void tpm_bn_init_set(tpm_bn_t a, tpm_bn_t val)
{
  tpm_bn_init(a);
  BN_copy(a, val);
}

void tpm_bn_init_set_ui(tpm_bn_t a, uint32_t val)
{
  tpm_bn_init(a);
  BN_set_word(a, val);
}

void tpm_bn_set_ui(tpm_bn_t a, uint32_t val)
{
  BN_set_word(a, val);
}

void tpm_bn_clear(tpm_bn_t a)
{
  BN_clear_free(a);
}

void tpm_bn_swap(tpm_bn_t a, tpm_bn_t b)
{
  BN_swap(a, b);
}

uint32_t tpm_bn_bitsize(tpm_bn_t a)
{
  return BN_num_bits(a);
}

void tpm_bn_import(tpm_bn_t out, size_t count, int order, const void *in)
{
  //FIXME: reverse order if order != 1.
  BN_bin2bn(in, count, out);
}

void tpm_bn_export(void *out, size_t *count, int order, tpm_bn_t in)
{
  //FIXME: reverse order if order != 1.
  BN_bn2bin(in, out);
  if (count != NULL) *count = BN_num_bytes(in);
}

int tpm_bn_cmp(tpm_bn_t a, tpm_bn_t b)
{
  return BN_cmp(a, b);
}

int tpm_bn_cmp_ui(tpm_bn_t a, uint32_t b)
{
  tpm_bn_t b2;
  tpm_bn_init_set_ui(b2, b);
  int res = tpm_bn_cmp(a, b2);
  tpm_bn_clear(b2);
  return res;
}

int tpm_bn_sgn(tpm_bn_t a)
{
  if (BN_is_zero(a)) return 0;
  return BN_is_negative(a) ? -1 : 1;
}

void tpm_bn_setbit(tpm_bn_t res, uint32_t bit)
{
  BN_set_bit(res, bit);
}

void tpm_bn_add(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  BN_add(res, a, b);
}

void tpm_bn_add_ui(tpm_bn_t res, tpm_bn_t a, uint32_t b)
{
  BN_copy(res, a);
  BN_add_word(res, b);
}

void tpm_bn_sub(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  BN_sub(res, a, b);
}

void tpm_bn_sub_ui(tpm_bn_t res, tpm_bn_t a, uint32_t b)
{
  BN_copy(res, a);
  BN_sub_word(res, b);
}

void tpm_bn_mul(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  BN_mul(res, a, b, bn_ctx);
}

void tpm_bn_mod(tpm_bn_t res, tpm_bn_t a, tpm_bn_t mod)
{
  BN_mod(res, a, mod, bn_ctx);
}

void tpm_bn_powm(tpm_bn_t res, tpm_bn_t base, tpm_bn_t exp, tpm_bn_t mod)
{
  BN_mod_exp(res, base, exp, mod, bn_ctx);
}

void tpm_bn_ui_pow_ui(tpm_bn_t res, uint32_t base, uint32_t exp)
{
  //FIXME: 
  BIGNUM b, e;
  BN_init(&b);
  BN_init(&e);
  BN_set_word(&b, base);
  BN_set_word(&e, exp);    
  BN_exp(res, &b, &e, bn_ctx);
  BN_clear_free(&b);
  BN_clear_free(&e);
}

void tpm_bn_fdiv_q_2exp(tpm_bn_t res, tpm_bn_t n, uint32_t b)
{
  BN_rshift(res, n, b);
}

void tpm_bn_tdiv_q(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  BN_div(res, NULL, a, b, bn_ctx);
}

void tpm_bn_gcd(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  BN_gcd(res, a, b, bn_ctx);
}

void tpm_bn_invert(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  BN_mod_inverse(res, a, b, bn_ctx);
}

void tpm_bn_nextprime(tpm_bn_t res, tpm_bn_t a)
{
  BN_copy(res, a);
  BN_set_bit(res, 0);
  while (!BN_is_prime(res, BN_prime_checks, NULL, bn_ctx, NULL)) {
    BN_add_word(res, 2);
  }
}


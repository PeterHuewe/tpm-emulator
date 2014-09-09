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
 * $Id: bn_gmp.c 464 2011-07-09 14:57:41Z mast $
 */
 
#include "bn.h"

void tpm_bn_init(tpm_bn_t a)
{
  mpz_init(a);
}

void tpm_bn_init2(tpm_bn_t a, size_t nbits)
{
  mpz_init2(a, nbits + GMP_NUMB_BITS);
}

void tpm_bn_init_set(tpm_bn_t a, tpm_bn_t val)
{
  mpz_init_set(a, val);     
}

void tpm_bn_init_set_ui(tpm_bn_t a, uint32_t val)
{
  mpz_init_set_ui(a, val);
}

void tpm_bn_set_ui(tpm_bn_t a, uint32_t val)
{
  mpz_set_ui(a, val);
}

void tpm_bn_clear(tpm_bn_t a)
{
  mpz_clear(a);
}

void tpm_bn_swap(tpm_bn_t a, tpm_bn_t b)
{
  mpz_swap(a, b);
}

uint32_t tpm_bn_bitsize(tpm_bn_t a)
{
  return mpz_sizeinbase(a, 2);
}

void tpm_bn_import(tpm_bn_t out, size_t count, int order, const void *in)
{
  mpz_import(out, count, order, 1, 0, 0, in);
}

void tpm_bn_export(void *out, size_t *count, int order, tpm_bn_t in)
{
  size_t count_out;
  mpz_export(out, &count_out, order, 1, 0, 0, in);
  if (count != NULL) *count = count_out;
}

int tpm_bn_cmp(tpm_bn_t a, tpm_bn_t b)
{
  return mpz_cmp(a, b);
}

int tpm_bn_cmp_ui(tpm_bn_t a, uint32_t b)
{
  return mpz_cmp_ui(a, b);
}

int tpm_bn_sgn(tpm_bn_t a)
{
  return mpz_sgn(a);
}

void tpm_bn_setbit(tpm_bn_t res, uint32_t bit)
{
  mpz_setbit(res, bit);
}

void tpm_bn_add(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  mpz_add(res, a, b);
}

void tpm_bn_add_ui(tpm_bn_t res, tpm_bn_t a, uint32_t b)
{
  mpz_add_ui(res, a, b);
}

void tpm_bn_sub(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  mpz_sub(res, a, b);
}

void tpm_bn_sub_ui(tpm_bn_t res, tpm_bn_t a, uint32_t b)
{
  mpz_sub_ui(res, a, b);
}

void tpm_bn_mul(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  mpz_mul(res, a, b);
}

void tpm_bn_mod(tpm_bn_t res, tpm_bn_t a, tpm_bn_t mod)
{
  mpz_mod(res, a, mod);
}

void tpm_bn_powm(tpm_bn_t res, tpm_bn_t base, tpm_bn_t exp, tpm_bn_t mod)
{
  mpz_powm(res, base, exp, mod);
}

void tpm_bn_ui_pow_ui(tpm_bn_t res, uint32_t base, uint32_t exp)
{
  mpz_ui_pow_ui(res, base, exp);
}

void tpm_bn_fdiv_q_2exp(tpm_bn_t res, tpm_bn_t n, uint32_t b)
{
  mpz_fdiv_q_2exp(res, n, b);
}

void tpm_bn_tdiv_q(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  mpz_tdiv_q(res, a, b);
}

void tpm_bn_gcd(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  mpz_gcd(res, a, b);
}

void tpm_bn_invert(tpm_bn_t res, tpm_bn_t a, tpm_bn_t b)
{
  mpz_invert(res, a, b);
}

void tpm_bn_nextprime(tpm_bn_t res, tpm_bn_t a)
{
  mpz_nextprime(res, a);
}



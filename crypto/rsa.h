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
 * $Id: rsa.h 364 2010-02-11 10:24:45Z mast $
 */

#ifndef _RSA_H_
#define _RSA_H_

#include <stddef.h>
#include <stdint.h>
#include "bn.h"

typedef struct {
  tpm_bn_t n;
  tpm_bn_t e;
  tpm_bn_t d;
  tpm_bn_t p;
  tpm_bn_t q;
  tpm_bn_t u;
  uint16_t size;
} tpm_rsa_private_key_t;

typedef struct {
  tpm_bn_t n;
  tpm_bn_t e;
  uint16_t size;
} tpm_rsa_public_key_t;

enum { 
  RSA_ES_PKCSV15,
  RSA_ES_OAEP_SHA1,
  RSA_ES_PLAIN,
  RSA_SSA_PKCS1_SHA1,
  RSA_SSA_PKCS1_SHA1_RAW,
  RSA_SSA_PKCS1_DER
};

enum {
  RSA_LSB_FIRST = -1, RSA_MSB_FIRST = 1
};

#define TPM_RSA_EXTRACT_PUBLIC_KEY(priv_key, pub_key) { \
  tpm_bn_init_set(pub_key.n, priv_key.n); \
  tpm_bn_init_set(pub_key.e, priv_key.e); \
  pub_key.size = priv_key.size; }

int tpm_rsa_import_key(tpm_rsa_private_key_t *key, int endian, 
                       const uint8_t *n, size_t n_len,
                       const uint8_t *e, size_t e_len, 
                       const uint8_t *p, const uint8_t *q);

void tpm_rsa_copy_key(tpm_rsa_private_key_t *dst, tpm_rsa_private_key_t *src);

int tpm_rsa_import_public_key(tpm_rsa_public_key_t *key, int endian, 
                              const uint8_t *n, size_t n_len,
                              const uint8_t *e, size_t e_len);

int tpm_rsa_generate_key(tpm_rsa_private_key_t *key, uint16_t key_size);

void tpm_rsa_release_private_key(tpm_rsa_private_key_t *key);

void tpm_rsa_release_public_key(tpm_rsa_public_key_t *key);

void tpm_rsa_export_modulus(tpm_rsa_private_key_t *key, 
                            uint8_t *modulus, size_t *length);

void tpm_rsa_export_exponent(tpm_rsa_private_key_t *key, 
                             uint8_t *exponent, size_t *length);

void tpm_rsa_export_prime1(tpm_rsa_private_key_t *key, 
                           uint8_t *prime, size_t *length);

void tpm_rsa_export_prime2(tpm_rsa_private_key_t *key, 
                           uint8_t *prime, size_t *length);

size_t tpm_rsa_modulus_length(tpm_rsa_private_key_t *key);

size_t tpm_rsa_exponent_length(tpm_rsa_private_key_t *key);

size_t tpm_rsa_prime1_length(tpm_rsa_private_key_t *key);

size_t tpm_rsa_prime2_length(tpm_rsa_private_key_t *key);

void tpm_rsa_mask_generation(const uint8_t *seed, size_t seed_len, 
                             uint8_t *data, size_t data_len);

void tpm_rsa_export_public_modulus(tpm_rsa_public_key_t *key,
                                   uint8_t *modulus, size_t *length);

void tpm_rsa_export_public_exponent(tpm_rsa_public_key_t *key,
                                    uint8_t *exponent, size_t *length);

size_t tpm_rsa_public_modulus_length(tpm_rsa_public_key_t *key);

size_t tpm_rsa_public_exponent_length(tpm_rsa_public_key_t *key);

/* Note: Input and output areas MUST NOT overlap (i.e., one can't 
   use the same buffer for data and sig or in and out). */

int tpm_rsa_sign(tpm_rsa_private_key_t *key, int type,
                 const uint8_t *data, size_t data_len, uint8_t *sig);

int tpm_rsa_verify(tpm_rsa_public_key_t *key, int type,
                   const uint8_t *data, size_t data_len, uint8_t *sig);

int tpm_rsa_decrypt(tpm_rsa_private_key_t *key, int type,
                    const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

int tpm_rsa_encrypt(tpm_rsa_public_key_t *key, int type,
                    const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

#endif /* _RSA_H_ */


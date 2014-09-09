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
 * $Id: tpm_testing.c 364 2010-02-11 10:24:45Z mast $
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"
#include "tpm_data.h"
#include "crypto/sha1.h"
#include "crypto/hmac.h"
#include "crypto/rsa.h"

#define INTERVAL(x,a,b) ((a) <= (x) && (x) <= (b))
static int tpm_test_prng(void)
{
  int ones[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 }; 
  int run_len0 = 0;
  int run_len1 = 0;
  int monobit = 0;
  int poker[16] = {0};
  int run0[6] = {0};
  int run1[6] = {0};
  int run_34 = 0;
  unsigned long x = 0;
  unsigned int i, j, k;
  BYTE buf[25];
  
  debug("tpm_test_prng()");
  /* Statistical random number generator tests according to FIPS 140-1 */
  for (i = 0; i < 2500 / sizeof(buf); i++) {
    tpm_get_random_bytes(buf, sizeof(buf));
    for (j = 0; j < sizeof(buf); j++) {
      BYTE hi = (buf[j] >> 4) & 0x0f;
      BYTE lo = buf[j] & 0x0f;
      monobit += ones[hi] + ones[lo];
      poker[hi]++; poker[lo]++;
      for (k = 0; k < 8; k++) {
        if ((buf[j] >> k) & 0x01) {
          run_len1++;
          if (run_len0 >= 34) run_34 = 1;
          if (run_len0 >= 6) run0[5]++;
          else if (run_len0 > 0) run0[run_len0 - 1]++;
          run_len0 = 0;
        } else {
          run_len0++;  
          if (run_len1 >= 34) run_34 = 1;
          if (run_len1 >= 6) run1[5]++;
          else if (run_len1 > 0) run1[run_len1 - 1]++;
          run_len1 = 0;
        }
      }    
    }
  }
  /* evaluate result */
  /* x = sum(poker[i]^2) * 16 / 5000 - 5000 */
  for (i = 0; i < 16; i++) x += 16 * poker[i] * poker[i] / 50;
  x -= 5000 * 100;
  debug("Monobit: %d", monobit);
  debug("Poker:   %d.%d", (int)(x/100), (int)(x/10)%10);
  debug("run_1:   %d, %d", run0[0], run1[0]); 
  debug("run_2:   %d, %d", run0[1], run1[1]);
  debug("run_3:   %d, %d", run0[2], run1[2]);
  debug("run_4:   %d, %d", run0[3], run1[3]);
  debug("run_5:   %d, %d", run0[4], run1[4]);
  debug("run_6+:  %d, %d", run0[5], run1[5]); 
  debug("run_34:  %d", run_34);
  if (INTERVAL(monobit, 9654, 10346) && INTERVAL(x, 103, 5740)
      && INTERVAL(run0[0], 2267, 2733) && INTERVAL(run1[0], 2267, 2733)
      && INTERVAL(run0[1], 1079, 1421) && INTERVAL(run1[1], 1079, 1421)
      && INTERVAL(run0[2],  502,  748) && INTERVAL(run1[2],  502,  748)
      && INTERVAL(run0[3],  223,  402) && INTERVAL(run1[3],  223,  402)
      && INTERVAL(run0[4],   90,  223) && INTERVAL(run1[4],   90,  223)
      && INTERVAL(run0[5],   90,  223) && INTERVAL(run1[5],   90,  223)
      && !run_34) return 0;
  return -1;
}

static int tpm_test_sha1(void)
{
  tpm_sha1_ctx_t ctx;
  BYTE digest[SHA1_DIGEST_LENGTH];
  unsigned int i, j;
  /* test cases for SHA-1 given in FIPS PUB 180-1 */
  struct {
    const char *data; uint32_t repetitions; const char *digest;
  } test_cases[] =  {{
    "abc", 1,
    "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D"
  }, {
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
    "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1"
  }, {
    "a", 1000000,
    "\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F"
  }, {
    "0123456701234567012345670123456701234567012345670123456701234567", 10,
    "\xDE\xA3\x56\xA2\xCD\xDD\x90\xC7\xA7\xEC\xED\xC5\xEB\xB5\x63\x93\x4F\x46\x04\x52"
  }};

  debug("tpm_test_sha1()");
  for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
    tpm_sha1_init(&ctx);
    for (j = 0; j < test_cases[i].repetitions; j++)
      tpm_sha1_update(&ctx, (uint8_t*)test_cases[i].data, strlen(test_cases[i].data));
    tpm_sha1_final(&ctx, digest);
    if (memcmp(digest, test_cases[i].digest, SHA1_DIGEST_LENGTH) != 0) return -1;
  }
  return 0;
}

static int tpm_test_hmac(void)
{
  tpm_hmac_ctx_t ctx;
  uint8_t digest[SHA1_DIGEST_LENGTH];
  unsigned int i, j;
  /* test cases for HMAC-SHA-1 given in RFC 2202 */
  struct {
    const char *key; uint8_t key_len;
    const char *data; uint8_t data_len;
    const char *digest;
  } test_cases[] = {{
    "\x0b", 20, "Hi There", 8,
    "\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00"
  }, {
    "Jefe", 4, "what do ya want for nothing?", 28,
    "\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79"
  }, {
    "\xaa", 20, "\xdd", 50,
    "\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3"
  }, {
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
    "\x15\x16\x17\x18\x19", 25, "\xcd", 50,
    "\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda"
  }, {
    "\x0c", 20, "Test With Truncation", 20,
    "\x4c\x1a\x03\x42\x4b\x55\xe0\x7f\xe7\xf2\x7b\xe1\xd5\x8b\xb9\x32\x4a\x9a\x5a\x04"
  }, {
    "\xaa", 80, "Test Using Larger Than Block-Size Key - Hash Key First", 54,
    "\xaa\x4a\xe5\xe1\x52\x72\xd0\x0e\x95\x70\x56\x37\xce\x8a\x3b\x55\xed\x40\x21\x12"
  }, {
    "\xaa", 80,
    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73,
    "\xe8\xe9\x9d\x0f\x45\x23\x7d\x78\x6d\x6b\xba\xa7\x96\x5c\x78\x08\xbb\xff\x1a\x91"
  }};

  debug("tpm_test_hmac()");
  for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
    if (strlen(test_cases[i].key) < test_cases[i].key_len) {
      uint8_t key[test_cases[i].key_len];
      memset(key, test_cases[i].key[0], test_cases[i].key_len);
      tpm_hmac_init(&ctx, (uint8_t*)key, test_cases[i].key_len);
    } else {
      tpm_hmac_init(&ctx, (uint8_t*)test_cases[i].key, test_cases[i].key_len);
    }
    for (j = 0; j < test_cases[i].data_len; j += strlen(test_cases[i].data)) {
      tpm_hmac_update(&ctx, (uint8_t *)test_cases[i].data, strlen(test_cases[i].data));
    }
    tpm_hmac_final(&ctx, digest);
    if (memcmp(digest, test_cases[i].digest, SHA1_DIGEST_LENGTH) != 0) return -1;
  }
  return 0;
}

static int tpm_test_rsa_EK(void)
{
  int res = 0;
  uint8_t *data = (uint8_t*)"RSA PKCS #1 v1.5 Test-String";
  uint8_t buf[256];
  size_t buf_len, data_len = strlen((char*)data);
  tpm_rsa_private_key_t priv_key;
  tpm_rsa_public_key_t pub_key;

  debug("tpm_test_rsa_EK()");
  /* generate and test key-pair */
  debug("tpm_rsa_generate_key()");
  res = tpm_rsa_generate_key(&priv_key, 512);
  tpm_rsa_release_private_key(&priv_key);
  if (res) return res;
  /* test endorsement key */
  debug("testing endorsement key");
  do {
    priv_key = tpmData.permanent.data.endorsementKey;
    if (!priv_key.size) return 0;
    TPM_RSA_EXTRACT_PUBLIC_KEY(priv_key, pub_key);
    /* test sign and verify functions */
    debug("tpm_rsa_sign(RSA_SSA_PKCS1_SHA1)");
    res = tpm_rsa_sign(&priv_key, RSA_SSA_PKCS1_SHA1, data, data_len, buf);
    if (res) break;
    debug("tpm_rsa_verify(RSA_SSA_PKCS1_SHA1)");
    res = tpm_rsa_verify(&pub_key, RSA_SSA_PKCS1_SHA1, data, data_len, buf);
    if (res) break;
    debug("tpm_rsa_sign(RSA_SSA_PKCS1_DER)");
    res = tpm_rsa_sign(&priv_key, RSA_SSA_PKCS1_DER, data, data_len, buf);
    if (res) break;
    debug("tpm_rsa_verify(RSA_SSA_PKCS1_DER)");
    res = tpm_rsa_verify(&pub_key, RSA_SSA_PKCS1_DER, data, data_len, buf);
    if (res) break;
    /* test encryption and decryption */
    debug("tpm_rsa_encrypt(RSA_ES_PKCSV15)");
    res = tpm_rsa_encrypt(&pub_key, RSA_ES_PKCSV15,
      data, data_len, buf, &buf_len);
    if (res) break;
    debug("tpm_rsa_decrypt(RSA_ES_PKCSV15)");
    res = tpm_rsa_decrypt(&priv_key, RSA_ES_PKCSV15,
      buf, buf_len, buf, &buf_len);
    if (res) break;
    debug("verify plain text");
    res = !((buf_len == data_len) && !memcmp(buf, data, buf_len));
    if (res) break;
    debug("tpm_rsa_encrypt(RSA_ES_OAEP_SHA1)");
    res = tpm_rsa_encrypt(&pub_key, RSA_ES_OAEP_SHA1,
      data, data_len/2, buf, &buf_len);
    if (res) break;
    debug("tpm_rsa_decrypt(RSA_ES_OAEP_SHA1)");
    res = tpm_rsa_decrypt(&priv_key, RSA_ES_OAEP_SHA1,
      buf, buf_len, buf, &buf_len);
    if (res) break;
    debug("verify plain text");
    res = !(buf_len == data_len/2 && !memcmp(buf, data, buf_len));
  } while (0);
  /* release public key and exit */
  tpm_rsa_release_public_key(&pub_key);
  return res;
}

/*
 * Admin Testing ([TPM_Part3], Section 4)
 */

TPM_RESULT TPM_SelfTestFull(void)
{
  info("TPM_SelfTestFull()");
  if (tpm_test_prng() != 0) {
    tpmData.permanent.data.testResult = "tpm_test_prng() failed";
    tpmData.permanent.flags.selfTestSucceeded = FALSE;
  } else if (tpm_test_sha1() != 0) {
    tpmData.permanent.data.testResult = "tpm_test_sha1() failed";
    tpmData.permanent.flags.selfTestSucceeded = FALSE;
  } else if (tpm_test_hmac() != 0) {
    tpmData.permanent.data.testResult = "tpm_test_hmac() failed";
    tpmData.permanent.flags.selfTestSucceeded = FALSE;
  } else if (tpm_test_rsa_EK() != 0) {
    tpmData.permanent.data.testResult = "tpm_test_rsa_EK() failed";
    tpmData.permanent.flags.selfTestSucceeded = FALSE;
  } else {
    tpmData.permanent.data.testResult = "Success";
    tpmData.permanent.flags.selfTestSucceeded = TRUE;
  }
  if (tpmData.permanent.flags.selfTestSucceeded) {
    info("Self-Test succeeded");
  } else {
    error("Self-Test failed: %s", tpmData.permanent.data.testResult);
  }
  return TPM_SUCCESS;
}

TPM_RESULT TPM_ContinueSelfTest(void)
{
  info("TPM_ContinueSelfTest()");
  /* we just run a complete self-test */
  return TPM_SelfTestFull();
}

TPM_RESULT TPM_GetTestResult(UINT32 *outDataSize, BYTE **outData)
{
  info("TPM_GetTestResult()");
  if (tpmData.permanent.data.testResult == NULL) return TPM_FAIL;
  *outDataSize = strlen(tpmData.permanent.data.testResult) + 1;
  *outData = tpm_malloc(*outDataSize);
  if (*outData == NULL) return TPM_FAIL;
  memcpy(*outData, tpmData.permanent.data.testResult, *outDataSize);
  return TPM_SUCCESS;;
}


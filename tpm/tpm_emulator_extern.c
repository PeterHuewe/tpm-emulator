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
 * $Id: tpm_emulator_extern.c 477 2012-04-28 09:15:26Z mast $
 */

#include "tpm_emulator_extern.h"
#include "config.h"

#ifndef TPM_NO_EXTERN

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

const char *tpm_storage_file = TPM_STORAGE_NAME;
const char *tpm_log_file = TPM_LOG_FILE;
const char *tpm_random_device = "/dev/urandom";

static int mkdirs(const char *path)
{
  char *copy = strdup(path);
  char *p = strchr(copy + 1, '/');
  while (p != NULL) {
    *p = '\0';
#if defined(_WIN32) || defined(_WIN64)
    if ((mkdir(copy) == -1) && (errno != EEXIST)) {
#else
    if ((mkdir(copy, 0755) == -1) && (errno != EEXIST)) {
#endif
      free(copy);
      return errno;
    }
    *p = '/';
    p = strchr(p + 1, '/');
  }
  free(copy);
  return 0;
}

#if defined(_WIN32) || defined(_WIN64)

#include <windows.h>
#include <wincrypt.h>

static HCRYPTPROV rand_ch;

static int _tpm_extern_init()
{
  info("_tpm_extern_init()");
  mkdirs(tpm_storage_file);
  mkdirs(tpm_log_file);
  debug("initializing crypto context for RNG");
  BOOL res = CryptAcquireContext(&rand_ch, NULL, NULL,
                                 PROV_RSA_FULL, CRYPT_SILENT);
  if (!res) {
    /* try it again with CRYPT_NEWKEYSET enabled */
    res = CryptAcquireContext(&rand_ch, NULL, NULL,
                              PROV_RSA_FULL, CRYPT_SILENT | CRYPT_NEWKEYSET);
  }
  if (!res) {
    error("CryptAcquireContext() failed: %d", GetLastError());
    return -1;
  }
  return 0;
}

void _tpm_extern_release()
{
  info("_tpm_extern_release()");
  CryptReleaseContext(rand_ch, 0);
}

void _tpm_get_extern_random_bytes(void *buf, size_t nbytes)
{
  CryptGenRandom(rand_ch, nbytes, (BYTE*)buf);
}

#else

static int rand_fh = -1;

static int _tpm_extern_init()
{
  info("_tpm_extern_init()");
  mkdirs(tpm_storage_file);
  mkdirs(tpm_log_file);
  debug("openening random device %s", tpm_random_device);
  rand_fh = open(tpm_random_device, O_RDONLY);
  if (rand_fh < 0) {
    error("open(%s) failed: %s", tpm_random_device, strerror(errno));
    return -1;
  }
  return 0;
}

static void _tpm_extern_release()
{
  info("_tpm_extern_release()");
  if (rand_fh != -1) close(rand_fh);
}

static void _tpm_get_extern_random_bytes(void *buf, size_t nbytes)
{
  uint8_t *p = (uint8_t*)buf;
  ssize_t res;
  while (nbytes > 0) {
    res = read(rand_fh, p, nbytes);
    if (res > 0) {
      nbytes -= res;
      p += res;
    }
  }
}

#endif

static void *_tpm_malloc(size_t size)
{
  return malloc(size);
}

static void _tpm_free(/*const*/ void *ptr)
{
  if (ptr != NULL) free((void*)ptr);
}

static void _tpm_log(int priority, const char *fmt, ...)
{
  FILE *fh;
  va_list ap;
  time_t tv;
  struct tm t;
  va_start(ap, fmt);
  fh = fopen(tpm_log_file, "a");
  if (fh != NULL) {
    time(&tv);
#if defined(_WIN32) || defined(_WIN64)
    memcpy(&t, localtime(&tv), sizeof(t));
#else
    localtime_r(&tv, &t);
#endif
    fprintf(fh, "%04d-%02d-%02d %02d:%02d:%02d ",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
    vfprintf(fh, fmt, ap);
    fclose(fh);
  }
  va_end(ap);
}

static uint64_t _tpm_get_ticks(void)
{
  static uint64_t old_t = 0;
  uint64_t new_t, res_t;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  new_t = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
  res_t = (old_t > 0) ? new_t - old_t : 0;
  old_t = new_t;
  return res_t;
}

static int _tpm_write_to_storage(uint8_t *data, size_t data_length)
{
  int fh;
  ssize_t res;

#if defined(_WIN32) || defined(_WIN64)
  fh = open(tpm_storage_file, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY, S_IRUSR | S_IWUSR); 
#else
  fh = open(tpm_storage_file, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
#endif
  if (fh < 0) return -1;
  while (data_length > 0) {
    res = write(fh, data, data_length);
    if (res < 0) {
      close(fh);
      return -1;
    }
    data_length -= res; 
    data += res;
  }
  close(fh);
  return 0;
}

static int _tpm_read_from_storage(uint8_t **data, size_t *data_length)
{
  int fh;
  ssize_t res;
  size_t total_length;

#if defined(_WIN32) || defined(_WIN64)
  fh = open(tpm_storage_file, O_RDONLY | O_BINARY); 
#else
  fh = open(tpm_storage_file, O_RDONLY);
#endif
  if (fh < 0) return -1;
  total_length = lseek(fh, 0, SEEK_END);
  lseek(fh, 0, SEEK_SET);
  *data = tpm_malloc(total_length);
  if (*data == NULL) {
    close(fh);
    return -1;
  }
  *data_length = 0;
  while (total_length > 0) {
    res = read(fh, &(*data)[*data_length], total_length);
    if (res < 0) {
      close(fh);
      tpm_free(*data);
      return -1;
    }
    if (res == 0) break;
    *data_length += res;
    total_length -= res;
  }
  close(fh);
  return 0;
}

int (*tpm_extern_init)(void)                                      = _tpm_extern_init;
void (*tpm_extern_release)(void)                                  = _tpm_extern_release;
void* (*tpm_malloc)(size_t size)                                  = _tpm_malloc;
void (*tpm_free)(/*const*/ void *ptr)                             = _tpm_free;
void (*tpm_log)(int priority, const char *fmt, ...)               = _tpm_log;
void (*tpm_get_extern_random_bytes)(void *buf, size_t nbytes)     = _tpm_get_extern_random_bytes;
uint64_t (*tpm_get_ticks)(void)                                   = _tpm_get_ticks;
int (*tpm_write_to_storage)(uint8_t *data, size_t data_length)    = _tpm_write_to_storage;
int (*tpm_read_from_storage)(uint8_t **data, size_t *data_length) = _tpm_read_from_storage;

#else /* TPM_NO_EXTERN */

int (*tpm_extern_init)(void)                                      = NULL;
void (*tpm_extern_release)(void)                                  = NULL;
void* (*tpm_malloc)(size_t size)                                  = NULL;
void (*tpm_free)(/*const*/ void *ptr)                             = NULL;
void (*tpm_log)(int priority, const char *fmt, ...)               = NULL;
void (*tpm_get_extern_random_bytes)(void *buf, size_t nbytes)     = NULL;
uint64_t (*tpm_get_ticks)(void)                                   = NULL;
int (*tpm_write_to_storage)(uint8_t *data, size_t data_length)    = NULL;
int (*tpm_read_from_storage)(uint8_t **data, size_t *data_length) = NULL;

#endif /* TPM_NO_EXTERN */


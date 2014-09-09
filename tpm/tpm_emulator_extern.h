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
 * $Id: tpm_emulator_extern.h 440 2010-03-17 22:53:07Z mast $
 */

#ifndef _TPM_EMULATOR_EXTERN_H_
#define _TPM_EMULATOR_EXTERN_H_

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/* log functions */

enum {
  TPM_LOG_DEBUG,
  TPM_LOG_INFO,
  TPM_LOG_ERROR
};

void (*tpm_log)(int priority, const char *fmt, ...);

#if defined(_WIN32) || defined(_WIN64)
#define __BFILE__ ((strrchr(__FILE__, '\\') ? : __FILE__ - 1) + 1)
#else
#define __BFILE__ ((strrchr(__FILE__, '/') ? : __FILE__ - 1) + 1)
#endif

#define debug(fmt, ...) tpm_log(TPM_LOG_DEBUG, "%s:%d: Debug: " fmt "\n", \
                                __BFILE__, __LINE__, ## __VA_ARGS__)
#define info(fmt, ...)  tpm_log(TPM_LOG_INFO, "%s:%d: Info: " fmt "\n", \
                                __BFILE__, __LINE__, ## __VA_ARGS__)
#define error(fmt, ...) tpm_log(TPM_LOG_ERROR, "%s:%d: Error: " fmt "\n", \
                                __BFILE__, __LINE__, ## __VA_ARGS__)
/* initialization */
int (*tpm_extern_init)(void);
void (*tpm_extern_release)(void);

/* memory allocation */

void* (*tpm_malloc)(size_t size);

void (*tpm_free)(/*const*/ void *ptr);

/* random numbers */

void (*tpm_get_extern_random_bytes)(void *buf, size_t nbytes);

/* usec since last call */

uint64_t (*tpm_get_ticks)(void);

/* file handling */

int (*tpm_write_to_storage)(uint8_t *data, size_t data_length);
int (*tpm_read_from_storage)(uint8_t **data, size_t *data_length);

#endif /* _TPM_EMULATOR_EXTERN_H_ */


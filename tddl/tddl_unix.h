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
 * $Id: tddl.c 364 2010-02-11 10:24:45Z mast $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

/* library lock */
static pthread_mutex_t tddli_lock = PTHREAD_MUTEX_INITIALIZER;

#define tddli_mutex_lock(a)   pthread_mutex_lock(a)
#define tddli_mutex_unlock(a) pthread_mutex_unlock(a)

static TSS_RESULT open_device(const char *device_name)
{
  tddli_dh = open(device_name, O_RDWR);
  if (tddli_dh < 0) {
    if (errno == ENOENT || errno == ENXIO) {
      tddli_driver_status = TDDL_DRIVER_FAILED;
      tddli_device_status = TDDL_DEVICE_NOT_FOUND;
    } else {
      tddli_driver_status = TDDL_DRIVER_NOT_OPENED;
      tddli_device_status = TDDL_DEVICE_RECOVERABLE;
    }
    return TDDL_E_FAIL;
  } else {
    tddli_driver_status = TDDL_DRIVER_OK;
    tddli_device_status = TDDL_DEVICE_OK;
    return TDDL_SUCCESS;
  }
}

static TSS_RESULT open_socket(const char *socket_name)
{
  struct sockaddr_un addr;
  tddli_dh = socket(AF_UNIX, SOCK_STREAM, 0);
  if (tddli_dh < 0) {
    tddli_driver_status = TDDL_DRIVER_FAILED;
    tddli_device_status = TDDL_DEVICE_NOT_FOUND;
    return TDDL_E_FAIL;
  }
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_name, sizeof(addr.sun_path));
  if (connect(tddli_dh, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
    tddli_driver_status = TDDL_DRIVER_FAILED;
    tddli_device_status = TDDL_DEVICE_NOT_FOUND;
    return TDDL_E_FAIL;
  }
  tddli_driver_status = TDDL_DRIVER_OK;
  tddli_device_status = TDDL_DEVICE_OK;
  return TDDL_SUCCESS;
}


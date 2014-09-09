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

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <windows.h>
#include <config.h>
#include "tddl.h"

/* library lock */
static CRITICAL_SECTION tddli_lock;

#define tddli_mutex_lock(a)   EnterCriticalSection(a)
#define tddli_mutex_unlock(a) LeaveCriticalSection(a)

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
  switch(reason) {
    case DLL_PROCESS_ATTACH:
      InitializeCriticalSection(&tddli_lock);
      break;
    case DLL_PROCESS_DETACH:
      DeleteCriticalSection(&tddli_lock);
      break;
    default:
      break;
  }
  return TRUE;
}

static TSS_RESULT open_device(const char *device_name)
{
  /* open the named pipe and generate a posix file handle */
  DWORD mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE;
  HANDLE ph = CreateFile(device_name, GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  SetNamedPipeHandleState(ph, &mode, NULL, NULL);
  tddli_dh = _open_osfhandle((DWORD)ph, O_RDWR | O_BINARY);
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
  return TDDL_E_FAIL;
}


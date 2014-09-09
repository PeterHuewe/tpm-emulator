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
 * $Id: test_tddl.c 364 2010-02-11 10:24:45Z mast $
 */

#include <stdio.h>
#include <tddl.h>

const char *get_error(TSS_RESULT res)
{
  switch (res) {
    case TDDL_SUCCESS:
      return "success";
    case TDDL_E_FAIL:
      return "operation failed";
    case TDDL_E_BAD_PARAMETER:
      return "bad patameter";
    case TDDL_E_TIMEOUT:
      return "timeout";
    case TDDL_E_ALREADY_OPENED:
      return "already opened";
    case TDDL_E_ALREADY_CLOSED:
      return "already closed";
    case TDDL_E_INSUFFICIENT_BUFFER:
      return "insufficient buffer";
    case TDDL_E_COMMAND_COMPLETED:
      return "comand completed";
    case TDDL_E_COMMAND_ABORTED:
      return "command aborted";
    case TDDL_E_IOERROR:
      return "IO error";
    case TDDL_E_BADTAG:
      return "bad tag";
    case TDDL_E_COMPONENT_NOT_FOUND:
      return "component not found";
    default:
      return "unknown error";
   }
}

const char *get_status(UINT32 status)
{
  switch (status) {
    case TDDL_DRIVER_OK: return "DRIVER OK";
    case TDDL_DRIVER_FAILED: return "DRIVER FAILED"; 
    case TDDL_DRIVER_NOT_OPENED: return "DRIVER NOT OPENED";
    case TDDL_DEVICE_OK: return "DEVICE OK"; 
    case TDDL_DEVICE_UNRECOVERABLE: return "DEVICE UNRECOVERABLE";
    case TDDL_DEVICE_RECOVERABLE: return "DEVICE RECOVERABLE";
    case TDDL_DEVICE_NOT_FOUND: return "DEVICE NOT FOUND";
    default: return "";
  }
}

int main()
{
  TSS_RESULT res;
  UINT32 status;
  BYTE buf[256];
  UINT32 buf_size = sizeof(buf);
  BYTE reset[] = {0, 193, 0, 0, 0, 10, 0, 0, 0, 90};
  unsigned int i;
  
  res = Tddli_Open();
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_Open() failed: %s (%04x)\n", get_error(res), res);
    return -1;
  }

  /* get driver and device status */
  res = Tddli_GetStatus(TDDL_DRIVER_STATUS, &status);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_GetStatus() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  printf("Driver status: %s\n", get_status(status));
  res = Tddli_GetStatus(TDDL_DEVICE_STATUS, &status);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_GetStatus() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  printf("Device status: %s\n", get_status(status));
  /* get version */
  buf_size = sizeof(buf);
  res = Tddli_GetCapability(TDDL_CAP_VERSION, TDDL_CAP_VER_DRV, buf, &buf_size);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_GetCapability() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  printf("DRV version: %d.%d.%d.%d\n", buf[0], buf[1], buf[2], buf[3]);
  buf_size = sizeof(buf);
  res = Tddli_GetCapability(TDDL_CAP_VERSION, TDDL_CAP_VER_FW, buf, &buf_size);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_GetCapability() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  printf("TPM Version: %d.%d.%d.%d\n", buf[0], buf[1], buf[2], buf[3]);
  /* get properties */
  buf_size = sizeof(buf);
  res = Tddli_GetCapability(TDDL_CAP_PROPERTY, TDDL_CAP_PROP_MANUFACTURER, buf, &buf_size);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_GetCapability() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  buf[buf_size] = 0;
  printf("Manufacturer: %s\n", buf);
  buf_size = sizeof(buf);
  res = Tddli_GetCapability(TDDL_CAP_PROPERTY, TDDL_CAP_PROP_MODULE_TYPE, buf, &buf_size);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_GetCapability() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  buf[buf_size] = 0;
  printf("Module type: %s\n", buf);
  /* reset tpm */
  printf("Transmit: ");
  for (i = 0; i < sizeof(reset); i++) printf("%02x ", reset[i]);
  printf("\n");
  buf_size = sizeof(buf);
  res = Tddli_TransmitData(reset, sizeof(reset), buf, &buf_size);
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_TransmitData() failed: %s (%04x)\n", get_error(res), res);
    Tddli_Close();
    return -1;
  }
  printf("Result:   ");
  for (i = 0; i < buf_size; i++) printf("%02x ", buf[i]);
  printf("\n");

  res = Tddli_Close();
  if (res != TDDL_SUCCESS) {
    printf("Error: Tddli_Close() failed: %s (%04x)\n", get_error(res), res);
    return -1;
  }
  return 0;
}

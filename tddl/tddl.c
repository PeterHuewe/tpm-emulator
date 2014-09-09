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

#include <unistd.h>
#include <string.h>
#include <config.h>
#include "tddl.h"

/* device and socket names */
static const char *tpm_device_name = TPM_DEVICE_NAME;
static const char *tpmd_socket_name = TPM_SOCKET_NAME;

/* TPM device handle */
static int tddli_dh = -1;

/* status of the TPM device driver and the TPM itself */
static TSS_RESULT tddli_driver_status = TDDL_DRIVER_FAILED;
static TSS_RESULT tddli_device_status = TDDL_DEVICE_NOT_FOUND;

#if defined(_WIN32) || defined(_WIN64)
#include "tddl_windows.h"
#else
#include "tddl_unix.h"
#endif

TSS_RESULT Tddli_Open()
{
  TSS_RESULT res;
  tddli_mutex_lock(&tddli_lock);
  if (tddli_dh != -1) {
    res = TDDL_E_ALREADY_OPENED;
  } else {
    res = open_socket(tpmd_socket_name);
    if (res != TDDL_SUCCESS) {
      res = open_device(tpm_device_name);
    }
  }
  tddli_mutex_unlock(&tddli_lock);
  return res;
} 

TSS_RESULT Tddli_Close()
{
  TSS_RESULT res = TDDL_SUCCESS;
  tddli_mutex_lock(&tddli_lock);
  if (tddli_dh >= 0) {
    close(tddli_dh);
    tddli_dh = -1;
  } else {
    res = TDDL_E_ALREADY_CLOSED;
  }
  tddli_mutex_unlock(&tddli_lock); 
  return res;
}
 
TSS_RESULT Tddli_Cancel()
{
  /* this is not supported by the TPM emulator */
  return TDDL_E_NOTIMPL;
}

static TSS_RESULT send_to_tpm(BYTE* pTransmitBuf, UINT32 TransmitBufLen)
{
  ssize_t res;
  res = write(tddli_dh, pTransmitBuf, TransmitBufLen);
  if (res < 0 || (UINT32)res != TransmitBufLen) return TDDL_E_IOERROR;
  return TDDL_SUCCESS;
}

static TSS_RESULT receive_from_tpm(BYTE* pReceiveBuf, UINT32* puntReceiveBufLen)
{
  ssize_t res;
  uint32_t len;
  if (*puntReceiveBufLen < 10) return TDDL_E_INSUFFICIENT_BUFFER;
  res = read(tddli_dh, pReceiveBuf, *puntReceiveBufLen);
  if (res < 10) return TDDL_E_IOERROR;
  *puntReceiveBufLen = res;
  len = ((uint32_t)pReceiveBuf[2] << 24) | ((uint32_t)pReceiveBuf[3] << 16)
        | ((uint32_t)pReceiveBuf[4] << 8) | (uint32_t)pReceiveBuf[5];
  if (len != *puntReceiveBufLen) return TDDL_E_INSUFFICIENT_BUFFER;
  return TDDL_SUCCESS;
}

TSS_RESULT Tddli_TransmitData(BYTE* pTransmitBuf, UINT32 TransmitBufLen,
                              BYTE* pReceiveBuf, UINT32* puntReceiveBufLen)
{
  TSS_RESULT res;
  tddli_mutex_lock(&tddli_lock);
  if (tddli_dh >= 0) {
    res = send_to_tpm(pTransmitBuf, TransmitBufLen);
    if (res == TDDL_SUCCESS)
      res = receive_from_tpm(pReceiveBuf, puntReceiveBufLen);
  } else {
    res = TDDL_E_FAIL;
  }
  tddli_mutex_unlock(&tddli_lock);
  return res;
}

static TSS_RESULT cap_version(UINT32 SubCap, BYTE* pCapBuf,
                              UINT32* puntCapBufLen)
{
  TSS_RESULT res;
  UINT32 len = 18;
  BYTE buf[18];

  switch (SubCap) {
    case TDDL_CAP_VER_DRV:
      if (*puntCapBufLen < 4) return TDDL_E_INSUFFICIENT_BUFFER;
      *puntCapBufLen = 4;
      memcpy(pCapBuf, "\x01\x05\x00\x00", 4);
      return TDDL_SUCCESS;

    case TDDL_CAP_VER_FW:
      if (*puntCapBufLen < 4) return TDDL_E_INSUFFICIENT_BUFFER;
      *puntCapBufLen = 4;
      res = send_to_tpm((uint8_t*)"\x00\xc1\x00\x00\x00\x12\x00\x00\x00\x65"
        "\x00\x00\x00\x06\x00\x00\x00\x00", 18);
      if (res != TDDL_SUCCESS) return res;
      res = receive_from_tpm(buf, &len);
      if (res != TDDL_SUCCESS) return res;
      if (len != 18 || (buf[6] | buf[7] | buf[8] | buf[9]) != 0) return TDDL_E_FAIL;
      memcpy(pCapBuf, &buf[14], 4);
      return TDDL_SUCCESS;

    case TDDL_CAP_VER_FW_DATE:
      /* this is not yet supported by the TPM emulator */
      return TDDL_E_NOTIMPL;

    default:
      return TDDL_E_BAD_PARAMETER;
  }
}

static TSS_RESULT cap_property(UINT32 SubCap, BYTE* pCapBuf,
                               UINT32* puntCapBufLen)
{
  static const char *manufacturer = "Mario Strasser, ETH Zurich";
  static const char *type = "Software-based TPM Emulator";

  switch (SubCap) {
    case TDDL_CAP_PROP_MANUFACTURER:
      if (*puntCapBufLen < strlen(manufacturer))
        return TDDL_E_INSUFFICIENT_BUFFER;
      *puntCapBufLen = strlen(manufacturer);
      memcpy(pCapBuf, manufacturer, *puntCapBufLen);
      return TDDL_SUCCESS;

    case TDDL_CAP_PROP_MODULE_TYPE:
      if (*puntCapBufLen < strlen(type)) return TDDL_E_INSUFFICIENT_BUFFER;
      *puntCapBufLen = strlen(type);
      memcpy(pCapBuf, type, *puntCapBufLen);
      return TDDL_SUCCESS;

    default:
      return TDDL_E_BAD_PARAMETER;
  }
}

TSS_RESULT Tddli_GetCapability(UINT32 CapArea, UINT32 SubCap, 
                               BYTE* pCapBuf, UINT32* puntCapBufLen)
{
  TSS_RESULT res = TDDL_SUCCESS;
  if (tddli_dh < 0) return TDDL_E_FAIL;
  tddli_mutex_lock(&tddli_lock);
  switch (CapArea) {
    case TDDL_CAP_VERSION:
      res = cap_version(SubCap, pCapBuf, puntCapBufLen);    
      break;
    case TDDL_CAP_PROPERTY:
      res = cap_property(SubCap, pCapBuf, puntCapBufLen);
      break;
    default:
      res = TDDL_E_BAD_PARAMETER;
  }
  tddli_mutex_unlock(&tddli_lock);
  return res;
}

TSS_RESULT Tddli_SetCapability(UINT32 CapArea, UINT32 SubCap, 
                               BYTE* pCapBuf, UINT32* puntCapBufLen) 
{
  /* no vendor-specific capabilities available, yet */
  return TDDL_E_BAD_PARAMETER;
}

TSS_RESULT Tddli_GetStatus(UINT32 ReqStatusType, UINT32* puntStatus) 
{
  TSS_RESULT res = TDDL_SUCCESS;
  tddli_mutex_lock(&tddli_lock);
  switch (ReqStatusType) {
    case TDDL_DRIVER_STATUS:
      *puntStatus = tddli_driver_status;
      break;
    case TDDL_DEVICE_STATUS:
      *puntStatus = tddli_device_status;
      break;
    default:
      res = TDDL_E_BAD_PARAMETER;
  }
  tddli_mutex_unlock(&tddli_lock);
  return res;
}

TSS_RESULT Tddli_SetPowerManagement(TSS_BOOL SendSaveStateCommand,
                                    UINT32 *QuerySetNewTPMPowerState)
{
  return TDDL_E_NOTIMPL;
}

TSS_RESULT Tddli_PowerManagementControl(TSS_BOOL SendPowerManager,
                                        UINT32 DriverManagesPowerStates)
{
  return TDDL_E_NOTIMPL;
}

/* 
 * Export also TDDL_* function aliases as they are
 * used by some non standard-conform applications.
 */

TSS_RESULT TDDL_Open()
{
  return Tddli_Open();
}


TSS_RESULT TDDL_Close()
{
  return Tddli_Close();
}
 
TSS_RESULT TDDL_Cancel()
{
  return Tddli_Cancel();
}

TSS_RESULT TDDL_TransmitData(BYTE* pTransmitBuf, UINT32 TransmitBufLen,
                              BYTE* pReceiveBuf, UINT32* puntReceiveBufLen)
{
  return Tddli_TransmitData(pTransmitBuf, TransmitBufLen,
                            pReceiveBuf, puntReceiveBufLen);
}

TSS_RESULT TDDL_GetCapability(UINT32 CapArea, UINT32 SubCap, 
                              BYTE* pCapBuf, UINT32* puntCapBufLen)
{
  return Tddli_GetCapability(CapArea, SubCap, pCapBuf, puntCapBufLen);
}

TSS_RESULT TDDL_SetCapability(UINT32 CapArea, UINT32 SubCap, 
                              BYTE* pCapBuf, UINT32* puntCapBufLen)
{
  return Tddli_SetCapability(CapArea, SubCap, pCapBuf, puntCapBufLen);
}

TSS_RESULT TDDL_GetStatus(UINT32 ReqStatusType, UINT32* puntStatus)
{
  return Tddli_GetStatus(ReqStatusType, puntStatus);
}

TSS_RESULT TDDL_SetPowerManagement(TSS_BOOL SendSaveStateCommand,
                                    UINT32 *QuerySetNewTPMPowerState)
{
  return Tddli_SetPowerManagement(SendSaveStateCommand, QuerySetNewTPMPowerState);
}

TSS_RESULT TDDL_PowerManagementControl(TSS_BOOL SendPowerManager,
                                        UINT32 DriverManagesPowerStates)
{
  return Tddli_PowerManagementControl(SendPowerManager, DriverManagesPowerStates);
}


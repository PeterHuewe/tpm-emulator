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
 * $Id: tddl.h 364 2010-02-11 10:24:45Z mast $
 */

#ifndef _TDDL_H_
#define _TDDL_H_

#include <stdint.h>

/*
 * The following types and functions are specified in the
 * TCPA Software Stack (TSS) Specification [TSS_Spec].
 */

/*
 * Basic Data Types
 */
typedef uint8_t  BYTE;
typedef uint8_t  TSS_BOOL;
typedef uint32_t UINT32;
typedef uint32_t TSS_RESULT;

/*
 * TDDL Return Codes
 */
#define TSS_E_BASE                     0x00000000
#define TDDL_SUCCESS                   (TSS_E_BASE + 0x00)
#define TDDL_E_FAIL                    (TSS_E_BASE + 0x02)
#define TDDL_E_BAD_PARAMETER           (TSS_E_BASE + 0x03)
#define TDDL_E_NOTIMPL                 (TSS_E_BASE + 0x06)
#define TDDL_E_TIMEOUT                 (TSS_E_BASE + 0x12)
#define TDDL_E_ALREADY_OPENED          (TSS_E_BASE + 0x81)
#define TDDL_E_ALREADY_CLOSED          (TSS_E_BASE + 0x82)
#define TDDL_E_INSUFFICIENT_BUFFER     (TSS_E_BASE + 0x83)
#define TDDL_E_COMMAND_COMPLETED       (TSS_E_BASE + 0x84)
#define TDDL_E_COMMAND_ABORTED         (TSS_E_BASE + 0x85)
#define TDDL_E_IOERROR                 (TSS_E_BASE + 0x87)
#define TDDL_E_BADTAG                  (TSS_E_BASE + 0x88)
#define TDDL_E_COMPONENT_NOT_FOUND     (TSS_E_BASE + 0x89)

/*
 * Capability Flag Definitions
 */
#define TDDL_CAP_VERSION               0x0100 
#define TDDL_CAP_VER_DRV               0x0101 
#define TDDL_CAP_VER_FW                0x0102 
#define TDDL_CAP_VER_FW_DATE           0x0103 
#define TDDL_CAP_PROPERTY              0x0200 
#define TDDL_CAP_PROP_MANUFACTURER     0x0201 
#define TDDL_CAP_PROP_MODULE_TYPE      0x0202 
#define TDDL_CAP_PROP_GLOBAL_STATE     0x0203

/*
 * Driver and Device Status Codes
 */
#define TDDL_DRIVER_STATUS             0x0010
#define TDDL_DRIVER_OK                 0x0010
#define TDDL_DRIVER_FAILED             0x0011
#define TDDL_DRIVER_NOT_OPENED         0x0012
#define TDDL_DEVICE_STATUS             0x0020
#define TDDL_DEVICE_OK                 0x0020
#define TDDL_DEVICE_UNRECOVERABLE      0x0021
#define TDDL_DEVICE_RECOVERABLE        0x0022 
#define TDDL_DEVICE_NOT_FOUND          0x0023

/*
 * TDDL Interface Functions
 */
#ifdef __cplusplus 
extern "C" {
#endif 

/**
 * Tddli_Open - establish a connection to the TPM device driver
 *
 * This function establishes a connection with the TPM device driver. The 
 * application utilizing the TPM DDL is guaranteed to  have exclusive access 
 * to the TPM device. This function must be called before calling GetStatus, 
 * GetCapability, SetCapability, or TransmitData.
 */
TSS_RESULT Tddli_Open(void); 

/**
 * Tddli_Close - close a open connection to the TPM device driver
 *
 * This function closes a connection with the TPM device driver. Following 
 * a successful response to this function, the TPM device driver can clean 
 * up any resources used to maintain a connection with the TPM device driver 
 * library. 
 */
TSS_RESULT Tddli_Close(void); 

/**
 * Tddli_Cancel - cancels the last outstanding TPM command
 * 
 * This function cancels an outstanding TPM command. An application can call 
 * this function, in a separate context, to interrupt a TPM command that has 
 * not completed.  The TPM device driver must acknowledge this function if 
 * it has not returned from a previous TPM command and return 
 * TDDL_COMMAND_ABORTED for the call in process. 
 */
TSS_RESULT Tddli_Cancel(void); 

/**
 * Tddli_GetCapability - read the attributes returned by the TPM
 *
 * @CapArea: [in] Partition of capabilities to be interrogated.
 * @SubCap: [in] Subcode of the requested capabilities.
 * @pCapBuf: [out] Pointer to a buffer containing the received attribute data.
 * @puntCapBufLen: [in] Size of the receive buffer in bytes. 
                   [out] Number of written bytes.
 *
 * This function queries the TPM hardware, firmware and device driver 
 * attributes such as firmware version, driver version, etc.  
 */ 
TSS_RESULT Tddli_GetCapability(UINT32 CapArea, UINT32 SubCap, 
                               BYTE* pCapBuf, UINT32* puntCapBufLen);

/**
 * Tddli_SetCapability - set parameters to the TPM
 *
 * @CapArea: [in] Partition of capabilities to be set.
 * @SubCap: [in] Subcode of the capabilities to be set.
 * @pCapBuf: [in] Pointer to a buffer containing the capability data to set.
 * @puntCapBufLen: [in] Size of the request buffer in bytes.
 *
 * This function sets parameters in the TPM hardware, firmware and device
 * driver attributes. An application can set TPM device driver and operating
 * parameters that may be defined by the TPM vendor. For now, the parameter
 * definitions are vendor-defined.
 */ 
TSS_RESULT Tddli_SetCapability(UINT32 CapArea, UINT32 SubCap, 
                               BYTE* pCapBuf, UINT32* puntCapBufLen); 

/**
 * Tddli_GetStatus - get status of the TPM driver and device TDDLI
 *
 * @ReqStatusType: [in] Requested type of status information.
 * @puntStatus: [out] Requested status.
 *
 * This function queries the status the TPM driver and device. An application 
 * can determine the health of the TPM subsystem by utilizing this function.
 */ 
TSS_RESULT Tddli_GetStatus(UINT32 ReqStatusType, UINT32* puntStatus); 

/** 
 * Tddli_TransmitData - send any data to the TPM module TDDLI
 *
 * @pTransmitBuf: [in] Pointer to a buffer containing TPM transmit data. 
 * @TransmitBufLen: [in] Size of TPM transmit data in bytes. 
 * @pReceiveBuf: [out] Pointer to a buffer containing TPM receive data 
 * @puntReceiveBufLen: [in] Size of TPM receive buffer in bytes. 
 *                     [out] Number of written bytes.
 *
 * The function sends a TPM command directly to a TPM device driver, causing 
 * the TPM to perform the corresponding operation.
 */ 
TSS_RESULT Tddli_TransmitData(BYTE* pTransmitBuf, UINT32 TransmitBufLen, 
                              BYTE* pReceiveBuf, UINT32* puntReceiveBufLen);


/**
 * Tddli_SetPowerManagement - sets and queries the TPM's power states
 *
 * @SendSaveStateCommand: [in]
 * @QuerySetNewTPMPowerState: [in] 
 *                            [out]
 *
 * This function sets and queries the TPM’s power states.
 */
TSS_RESULT Tddli_SetPowerManagement(TSS_BOOL SendSaveStateCommand,
                                    UINT32 *QuerySetNewTPMPowerState);

/**
 * Tddli_PowerManagementControl - gets and sets the power state management
 *
 * @SendPowerManager: [in]
 * @DriverManagesPowerStates: [out]
 *
 * This command determines and sets which component, TCS or the Driver,
 * receives and handles the platform’s OS power state management signals.
 */
TSS_RESULT Tddli_PowerManagementControl(TSS_BOOL SendPowerManager,
                                        UINT32 DriverManagesPowerStates);

#ifdef __cplusplus
}
#endif

#endif /* _TDDL_H_ */


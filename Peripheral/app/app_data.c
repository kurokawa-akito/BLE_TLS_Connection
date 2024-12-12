/******************************************************************************

@file  app_data.c

@brief This file contains the application data functionality

Group: WCS, BTS
Target Device: cc23xx

******************************************************************************

 Copyright (c) 2022-2024, Texas Instruments Incorporated
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

 *  Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

 *  Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 *  Neither the name of Texas Instruments Incorporated nor the names of
    its contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

******************************************************************************


*****************************************************************************/

//*****************************************************************************
//! Includes
//*****************************************************************************
#include <string.h>
#include <ti/bleapp/ble_app_util/inc/bleapputil_api.h>
#include <ti/bleapp/menu_module/menu_module.h>
#include <app_main.h>
#include <ti/bleapp/profiles/simple_gatt/simple_gatt_profile.h>

#include <ti/drivers/SHA2.h>
#include <ti/drivers/ECDSA.h>
#include <ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h>
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
//*****************************************************************************
//! Defines
//*****************************************************************************
#define SHA2_INSTANCE 0
#define CHECK_INTERVAL_MS 100
#define TIMEOUT_MS 10000
#define TIMEOUT_12S 12000
//*****************************************************************************
//! Globals
//*****************************************************************************
gapBondOOBData_t remoteOobData;

static void GATT_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData);
static void Challenge_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData);
// Events handlers struct, contains the handlers and event masks
// of the application data module
BLEAppUtil_EventHandler_t dataGATTHandler =
{
    .handlerType    = BLEAPPUTIL_GATT_TYPE,
    .pEventHandler  = GATT_EventHandler,
    .eventMask      = BLEAPPUTIL_ATT_FLOW_CTRL_VIOLATED_EVENT |
                      BLEAPPUTIL_ATT_MTU_UPDATED_EVENT |
                      BLEAPPUTIL_ATT_READ_RSP |
                      BLEAPPUTIL_ATT_WRITE_CMD |
                      BLEAPPUTIL_ATT_WRITE_REQ |
                      BLEAPPUTIL_ATT_WRITE_RSP |
                      BLEAPPUTIL_ATT_EXCHANGE_MTU_RSP |
                      BLEAPPUTIL_ATT_ERROR_RSP |
                      BLEAPPUTIL_ATT_HANDLE_VALUE_NOTI
};

BLEAppUtil_EventHandler_t challengeHandler =
{
    .handlerType    = BLEAPPUTIL_GATT_TYPE,
    .pEventHandler  = Challenge_EventHandler,
    .eventMask      = BLEAPPUTIL_ATT_READ_RSP
};

//*****************************************************************************
//! Functions
//*****************************************************************************

/*********************************************************************
 * @fn      GATT_EventHandler
 *
 * @brief   The purpose of this function is to handle GATT events
 *          that rise from the GATT and were registered in
 *          @ref BLEAppUtil_RegisterGAPEvent
 *
 * @param   event - message event.
 * @param   pMsgData - pointer to message data.
 *
 * @return  none
 */
static void GATT_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData)
{
  gattMsgEvent_t *gattMsg = ( gattMsgEvent_t * )pMsgData;
  switch ( gattMsg->method )
  {
    case ATT_FLOW_CTRL_VIOLATED_EVENT:
      {
          MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE, 0, "GATT status: ATT flow control is violated");
      }
      break;

    case ATT_MTU_UPDATED_EVENT:
      {
//          MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE1, 0, "GATT status: ATT MTU update to %d",
//                            gattMsg->msg.mtuEvt.MTU);
          doAttReadReq(37, 1);
      }
      break;

    case ATT_READ_RSP:
      {
          if (gattMsg->msg.readRsp.len == 32)
          {
              MenuModule_printf(APP_MENU_CONN_EVENT, 0, "OOB data = 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x ",
                                gattMsg->msg.readRsp.pValue[0], gattMsg->msg.readRsp.pValue[1], gattMsg->msg.readRsp.pValue[2],
                                gattMsg->msg.readRsp.pValue[3], gattMsg->msg.readRsp.pValue[4]);

              uint8_t oobEnabled = TRUE;
              GAPBondMgr_SetParameter(GAPBOND_OOB_ENABLED, sizeof(uint8_t), &oobEnabled);

              for (int i = 0; i < 16; i++) {
                  remoteOobData.confirm[i] = gattMsg->msg.readRsp.pValue[i];
              }

              for (int i = 0; i < 16; i++) {
                  remoteOobData.rand[i] = gattMsg->msg.readRsp.pValue[i + 16];
              }
              GAPBondMgr_SCSetRemoteOOBParameters(&remoteOobData, 1);
          }
      }
          break;

    case ATT_WRITE_RSP:
    {
        MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE, 0, "type: 0x%02x ", gattMsg->msg.writeReq.pValue[0]);
    }

        break;

    case ATT_EXCHANGE_MTU_RSP:
      {
          MenuModule_printf(APP_MENU_PAIRING_EVENT, 0, "MTU max size client = %d MTU max size server = %d",
                            gattMsg->msg.exchangeMTUReq.clientRxMTU, gattMsg->msg.exchangeMTURsp.serverRxMTU);
          break;
      }

    case ATT_HANDLE_VALUE_NOTI:
      {
          MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE4, 0, "Notification received = %d 0x%02x 0x%02x",
                            gattMsg->msg.handleValueNoti.len, gattMsg->msg.handleValueNoti.pValue[0], gattMsg->msg.handleValueNoti.pValue[1]);
      }
      break;

    case ATT_ERROR_RSP:
      {
          attErrorRsp_t  *pReq = (attErrorRsp_t  *)pMsgData;
          MenuModule_printf(APP_MENU_CONN_EVENT, 0, "Error %d",
                            pReq->errCode);
          break;
      }

    default:
      break;
  }
}

static void Challenge_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData)
{
    gattMsgEvent_t *gattMsg = ( gattMsgEvent_t * )pMsgData;
    switch ( gattMsg->method )
    {
        case ATT_READ_RSP:
            {
                if (gattMsg->msg.readRsp.len == 33)
                {
                    MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE1, 0, "32 bytes Nonce received = %d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
                                      gattMsg->msg.readRsp.len, gattMsg->msg.readRsp.pValue[0], gattMsg->msg.readRsp.pValue[1],
                                      gattMsg->msg.readRsp.pValue[2], gattMsg->msg.readRsp.pValue[3], gattMsg->msg.readRsp.pValue[31], gattMsg->msg.readRsp.pValue[32]);
                    /*
                     *  Send sign command + gattMsg->msg.handleValueNoti.pValue[1] ~ gattMsg->msg.handleValueNoti.pValue[32] to TA010
                     */

                    // set signature to char 6
                    uint8_t ta010Signature[64] = {0x60, 0x1E, 0xAF, 0xC6, 0x69, 0xEF, 0x3C, 0xFE, 0x96, 0x49, 0x3A, 0xAC, 0xD0, 0x45, 0xBF, // signature r
                                                  0x74, 0xF8, 0x1B, 0xD6, 0xCE, 0x34, 0x65, 0x8F, 0x79, 0x34, 0x59, 0x3F, 0x74, 0xF2, 0x0C,
                                                  0xA8, 0x3F,
                                                  0xAF, 0x00, 0xFA, 0x71, 0x3B, 0x53, 0xDC, 0x40, 0x25, 0x39, 0x6D, 0xE8, 0xAC, 0x0D, 0x41, // signature s
                                                  0xA2, 0x7C, 0x38, 0x06, 0xCA, 0x7E, 0x04, 0x34, 0x40, 0x3C, 0xAD, 0x8F, 0x48, 0x30, 0xA1,
                                                  0xA9, 0xA7};
                    bStatus_t status = SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR6, SIMPLEGATTPROFILE_CHAR6_LEN,
                                                                       ta010Signature );
                    if (status == SUCCESS)
                    {
                        MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE4, 0 ,"64 bytes signature set status = %d", status);
                    }
                }
            }
            break;

        default:
            break;
    }
}

//xTaskCreate(VerifySignatureTask, "VerifySignature", 1024, NULL, 1, NULL);
//xTaskCreate(ResponseChallengeSuccessTask, "ChallengeResult", 128, NULL, 2, NULL);
/*********************************************************************
 * @fn      Data_start
 *
 * @brief   This function is called after stack initialization,
 *          the purpose of this function is to initialize and
 *          register the specific events handlers of the data
 *          application module
 *
 * @return  SUCCESS, errorInfo
 */
bStatus_t Data_start( void )
{
  bStatus_t status = SUCCESS;

  // Register the handlers
  status = BLEAppUtil_registerEventHandler( &dataGATTHandler );
  status = BLEAppUtil_registerEventHandler( &challengeHandler );
  // Return status value
  return( status );
}

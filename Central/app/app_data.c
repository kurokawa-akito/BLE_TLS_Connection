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
//*****************************************************************************
//! Defines
//*****************************************************************************
 #define SHA2_INSTANCE 0
//*****************************************************************************
//! Globals
//*****************************************************************************
gapBondOOBData_t remoteOobData;

static void GATT_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData);
static void Verify_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData);
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
                      BLEAPPUTIL_ATT_EXCHANGE_MTU_RSP |
                      BLEAPPUTIL_ATT_ERROR_RSP
};

BLEAppUtil_EventHandler_t verifyHandler =
{
    .handlerType    = BLEAPPUTIL_GATT_TYPE,
    .pEventHandler  = Verify_EventHandler,
    .eventMask      = BLEAPPUTIL_ATT_HANDLE_VALUE_NOTI
};

BLEAppUtil_EventHandler_t challengeHandler =
{
    .handlerType    = BLEAPPUTIL_GATT_TYPE,
    .pEventHandler  = Challenge_EventHandler,
    .eventMask      = BLEAPPUTIL_ATT_READ_RSP |
                      BLEAPPUTIL_ATT_HANDLE_VALUE_NOTI
};

// ECDSA param
//uint8_t signerPrivateKeyingMaterial[32] = {0x80, 0x6B, 0xA4, 0x5D, 0x93, 0x02, 0x48, 0xD5, 0x33, 0x31,
//                                           0x87, 0xE5, 0xDD, 0xE7, 0x4C, 0x06, 0x24, 0xDB, 0x71, 0x00,
//                                           0xF4, 0xAB, 0x11, 0x63, 0x80, 0x7E, 0x48, 0x0D, 0x7C, 0x3B,
//                                           0x8E, 0xC7};

//uint8_t devicePrivateKeyingMaterial[32] = {0x31, 0xE8, 0xEA, 0xAC, 0x81, 0x44, 0xF8, 0x51, 0xDD, 0xE8,
//                                           0x64, 0x21, 0xCD, 0xFA, 0x97, 0x05, 0x34, 0x6D, 0x27, 0xA9,
//                                           0x0C, 0xF9, 0x24, 0x1D, 0x9D, 0xE5, 0x8C, 0xCE, 0x2A, 0xB5,
//                                           0x2D, 0xC5};

uint8_t signerCert[137] = {0x02, // signer Certificate id
                           0x3E, 0x12, 0xCB, 0x3D, 0x01, 0x32, 0x36, 0x6F, //8 bytes data
                           0xC4, 0xBC, 0x58, 0x1D, 0xAE, 0xA6, 0xB6, 0x44, 0x15, 0xBE, 0x3E, // public key X
                           0x1F, 0x59, 0x8B, 0x83, 0xBA, 0x17, 0x57, 0xD6, 0x1A, 0x81, 0xB9,
                           0xD1, 0xD6, 0xAB, 0xF6, 0xDF, 0x6D, 0xFD, 0xEE, 0x89, 0x24,
                           0x2F, 0xB7, 0x2B, 0x22, 0x54, 0xDF, 0x99, 0x1E, 0x7D, 0xF3, 0xAD, // public key Y
                           0x88, 0xA5, 0x99, 0x51, 0x4D, 0xF7, 0x4C, 0x91, 0x09, 0x06, 0x47,
                           0x20, 0x77, 0x4B, 0x7E, 0x3A, 0xB4, 0x2D, 0xC0, 0x08, 0xBA,
                           0x84, 0xE6, 0x0D, 0x13, 0x37, 0xAB, 0x47, 0xDA, 0xA9, 0x5E, 0x2D, // signature R + S
                           0xBA, 0x80, 0x7A, 0x10, 0x99, 0x9A, 0x15, 0xAF, 0x92, 0x22, 0x1C,
                           0xC1, 0x3B, 0xE7, 0x22, 0x6F, 0x74, 0xAF, 0x69, 0x67, 0x00, 0x5B,
                           0x84, 0xD9, 0x8F, 0x0B, 0x30, 0x3F, 0xEC, 0xD0, 0x4D, 0xA4, 0x05,
                           0x15, 0x43, 0x87, 0xC9, 0xEF, 0x01, 0xBB, 0x8E, 0x87, 0x39, 0x20,
                           0x57, 0x84, 0x50, 0x9D, 0x63, 0xC6, 0x2C, 0x87, 0x56};  // store the local signer certificates
uint8_t deviceCert[137] = {0x01, // device Certificate id
                           0x74, 0x79, 0x41, 0x3A, 0x50, 0xEF, 0x4B, 0x34, // 8 bytes data
                           0xBB, 0x12, 0xBF, 0xEF, 0x48, 0xE8, 0xAC, 0x5E, 0x54, 0x07, 0x90, // public key X
                           0xA9, 0x58, 0xD0, 0x99, 0xC4, 0xA7, 0xEF, 0x31, 0x58, 0xD4, 0xBD,
                           0xAF, 0x3A, 0x86, 0x8C, 0x33, 0x96, 0x1D, 0x73, 0x45, 0x90,
                           0x74, 0xC2, 0xC9, 0x63, 0xB4, 0xA0, 0xE2, 0xDC, 0xF6, 0x96, 0x02, // public key Y
                           0xBA, 0xDF, 0xFC, 0x8E, 0x5D, 0x40, 0x7A, 0xEF, 0x61, 0xEE, 0x98,
                           0x61, 0xFB, 0xB1, 0x2A, 0x9C, 0x46, 0xA9, 0x99, 0x50, 0x46,
                           0x1F, 0x2A, 0x03, 0x4A, 0x0C, 0xCE, 0xDC, 0x97, 0xC8, 0x83, 0x55, // signature R + S
                           0x3D, 0x08, 0x4D, 0x4C, 0x5D, 0xDA, 0x46, 0x44, 0x65, 0xBB, 0x47,
                           0x37, 0x49, 0x4A, 0xE4, 0xE2, 0x09, 0x5D, 0xA5, 0x0F, 0x52, 0x91,
                           0x29, 0xCD, 0xD4, 0xD1, 0xEA, 0xE3, 0xFC, 0x1B, 0xBC, 0xA7, 0x37,
                           0xC7, 0xA9, 0x15, 0xB6, 0x79, 0xC6, 0xB6, 0x9F, 0x18, 0xE6, 0x15,
                           0x59, 0xAB, 0x02, 0xD2, 0xF5, 0xE6, 0xDB, 0x16, 0xF5};   // store the local device certificates
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

    case ATT_WRITE_CMD:
    {
        MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE, 0, "type: 0x%02x ", gattMsg->method);
    }

        break;

    case ATT_WRITE_REQ:
    {
        MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE, 0, "type: 0x%02x ", gattMsg->method);
    }

        break;

    case ATT_READ_RSP:

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

            // send the signer cert req to tpms
            uint8_t signerCertReqCmd[2] = {5, 3};
            doAttWriteNoRsp(43, signerCertReqCmd, sizeof(signerCertReqCmd));
        }
        break;

    case ATT_EXCHANGE_MTU_RSP:
      {
//          MenuModule_printf(APP_MENU_PAIRING_EVENT, 0, "MTU max size client = %d MTU max size server = %d",
//                            gattMsg->msg.exchangeMTUReq.clientRxMTU, gattMsg->msg.exchangeMTURsp.serverRxMTU);
          break;
      }

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

static void Verify_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData)
{
    gattMsgEvent_t *gattMsg = ( gattMsgEvent_t * )pMsgData;
    switch ( gattMsg->method )
    {
        case ATT_HANDLE_VALUE_NOTI:
        {
            if (gattMsg->msg.handleValueNoti.pValue[0] == 2) //verify signer certificate
            {
                uint8_t signerPublicKeyingMaterial[65] = {0};
                signerPublicKeyingMaterial[0] = 4;
                memcpy(&signerPublicKeyingMaterial[1], &signerCert[9], 64);

                uint8_t r[32] = {0};
                uint8_t s[32] = {0};
                int_fast16_t shaResult;
                int_fast16_t verifyResult;
                // SHA256 signer public key
                SHA2_Params params;
                SHA2_Handle handle;
                uint8_t message[64] = {0};
                for (int i = 0 ; i < 64 ; i++)
                {
                    message[i] = gattMsg->msg.handleValueNoti.pValue[ 9 + i ];
                }
                uint8_t shaDigest[32]; // 32 bytes hash values
                SHA2_init();
                SHA2_Params_init(&params);
                handle = SHA2_open(SHA2_INSTANCE, NULL);

                shaResult = SHA2_hashData(handle, message, sizeof(message), shaDigest);
                SHA2_close(handle);

                // ecdsa verify signer certificate
                for (int i = 0; i < 32; i++) {
                    r[i] = gattMsg->msg.handleValueNoti.pValue[73 + i];
                    s[i] = gattMsg->msg.handleValueNoti.pValue[105 + i];
                }
                CryptoKey signerPublicKey;
                ECDSA_Handle ecdsaHandle;
                ECDSA_Params ecdsaParams;
                ECDSA_OperationVerify operationVerify;

                ECDSA_init();
                ECDSA_Params_init(&ecdsaParams);
                ecdsaHandle = ECDSA_open(0, NULL);
                CryptoKeyPlaintext_initKey(&signerPublicKey,
                                           signerPublicKeyingMaterial,
                                           sizeof(signerPublicKeyingMaterial));

                ECDSA_OperationVerify_init(&operationVerify);
                operationVerify.curve           = &ECCParams_NISTP256;
                operationVerify.theirPublicKey  = &signerPublicKey;
                operationVerify.hash            = shaDigest;
                operationVerify.r               = r;
                operationVerify.s               = s;

                verifyResult = ECDSA_verify(ecdsaHandle, &operationVerify);
                if (verifyResult == ECDSA_STATUS_SUCCESS)
                {
                    MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE2, 0 ,"signer verify status = %d", verifyResult);
                    ECDSA_close(ecdsaHandle);
                    uint8_t deviceCertReqCmd[2] = {6, 3};
                    doAttWriteNoRsp(40, deviceCertReqCmd, sizeof(deviceCertReqCmd));
                }
            }
            else if (gattMsg->msg.handleValueNoti.pValue[0] == 1) //verify device certificate
            {
                uint8_t devicePublicKeyingMaterial[65] = {0};
                devicePublicKeyingMaterial[0] = 4;
                memcpy(&devicePublicKeyingMaterial[1], &deviceCert[9], 64);

                uint8_t r[32] = {0};
                uint8_t s[32] = {0};
                int_fast16_t shaResult;
                int_fast16_t verifyResult;
                // SHA256 signer public key
                SHA2_Params params;
                SHA2_Handle handle;
                uint8_t message[64] = {0};
                for (int i = 0 ; i < 64 ; i++)
                {
                    message[i] = gattMsg->msg.handleValueNoti.pValue[ 9 + i ];
                }
                uint8_t shaDigest[32]; // 32 bytes hash values
                SHA2_init();
                SHA2_Params_init(&params);
                handle = SHA2_open(SHA2_INSTANCE, NULL);

                shaResult = SHA2_hashData(handle, message, sizeof(message), shaDigest);
                SHA2_close(handle);

                // ecdsa verify signer certificate
                for (int i = 0; i < 32; i++) {
                    r[i] = gattMsg->msg.handleValueNoti.pValue[73 + i];
                    s[i] = gattMsg->msg.handleValueNoti.pValue[105 + i];
                }
                CryptoKey devicePublicKey;
                ECDSA_Handle ecdsaHandle;
                ECDSA_Params ecdsaParams;
                ECDSA_OperationVerify operationVerify;

                ECDSA_init();
                ECDSA_Params_init(&ecdsaParams);
                ecdsaHandle = ECDSA_open(0, NULL);
                CryptoKeyPlaintext_initKey(&devicePublicKey,
                                           devicePublicKeyingMaterial,
                                           sizeof(devicePublicKeyingMaterial));

                ECDSA_OperationVerify_init(&operationVerify);
                operationVerify.curve           = &ECCParams_NISTP256;
                operationVerify.theirPublicKey  = &devicePublicKey;
                operationVerify.hash            = shaDigest;
                operationVerify.r               = r;
                operationVerify.s               = s;

                verifyResult = ECDSA_verify(ecdsaHandle, &operationVerify);
                if (verifyResult == ECDSA_STATUS_SUCCESS)
                {
                    MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE3, 0, "device verify status = %d", verifyResult);
                    ECDSA_close(ecdsaHandle);
//                    uint8_t successMsg[2] = {0xaa, 0xbb};
                    doAttWriteNoRsp(43, signerCert, sizeof(signerCert));
//                    SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR3, SIMPLEGATTPROFILE_CHAR3_LEN,
//                                                    signerCert);
//                    SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR2, SIMPLEGATTPROFILE_CHAR2_LEN,
//                                                    deviceCert);
                }
            }

            else if (gattMsg->msg.handleValueNoti.pValue[0] == 0x55 && gattMsg->msg.handleValueNoti.pValue[1] == 0x66)
            {
                doAttWriteNoRsp(40, deviceCert, sizeof(deviceCert));
            }

            else if (gattMsg->msg.handleValueNoti.pValue[0] == 0xaa && gattMsg->msg.handleValueNoti.pValue[1] == 0xbb)
            {
                uint8_t nonceReq[2] = {0x12, 0x23};
                doAttWriteNoRsp(50, nonceReq, sizeof(nonceReq));
            }

            else if (gattMsg->msg.handleValueNoti.pValue[0] == 0xcc && gattMsg->msg.handleValueNoti.pValue[1] == 0xdd)
            {
                /*
                 * Send a nonce commands to TA010 to get the 32 bytes random number
                 */
                uint8_t ta010Nonce[33] = {0x03, // nonce id
                                          0x6B, 0x54, 0x38, 0xE5, 0xE3, 0xC0, 0x1B, 0xF1,
                                          0x44, 0x1E, 0x90, 0xDB, 0x8E, 0x9D, 0x0D, 0xB8,
                                          0xE4, 0xBB, 0xA1, 0x0D, 0xD9, 0x05, 0xDC, 0x0C,
                                          0xC0, 0xCA, 0x3F, 0x48, 0xB3, 0x7C, 0xA8, 0x79};
                doAttWriteNoRsp(50, ta010Nonce, sizeof(ta010Nonce));
            }
        }
            break;

        default:
            break;

    }
}

static void Challenge_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData)
{
    gattMsgEvent_t *gattMsg = ( gattMsgEvent_t * )pMsgData;
    switch ( gattMsg->method )
    {
        case ATT_HANDLE_VALUE_NOTI:
            {
                if (gattMsg->msg.handleValueNoti.pValue[0] == 3)
                {
                    MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE1, 0, "32 bytes Nonce received = %d 0x%02x 0x%02x 0x%02x ",
                                      gattMsg->msg.handleValueNoti.len, gattMsg->msg.handleValueNoti.pValue[0], gattMsg->msg.handleValueNoti.pValue[1],
                                      gattMsg->msg.handleValueNoti.pValue[2]);
                    /*
                     *  Send sign command + gattMsg->msg.handleValueNoti.pValue[1] ~ gattMsg->msg.handleValueNoti.pValue[32] to TA010
                     */
                    uint8_t ta010Signature[65] = {0x06,
                                                  0x60, 0x1E, 0xAF, 0xC6, 0x69, 0xEF, 0x3C, 0xFE, 0x96, 0x49, 0x3A, 0xAC, 0xD0, 0x45, 0xBF, // signature r
                                                  0x74, 0xF8, 0x1B, 0xD6, 0xCE, 0x34, 0x65, 0x8F, 0x79, 0x34, 0x59, 0x3F, 0x74, 0xF2, 0x0C,
                                                  0xA8, 0x3F,
                                                  0xAF, 0x00, 0xFA, 0x71, 0x3B, 0x53, 0xDC, 0x40, 0x25, 0x39, 0x6D, 0xE8, 0xAC, 0x0D, 0x41, // signature s
                                                  0xA2, 0x7C, 0x38, 0x06, 0xCA, 0x7E, 0x04, 0x34, 0x40, 0x3C, 0xAD, 0x8F, 0x48, 0x30, 0xA1,
                                                  0xA9, 0xA7};
                    doAttWriteNoRsp(53, ta010Signature, sizeof(ta010Signature));
                }
                else if (gattMsg->msg.handleValueNoti.pValue[0] == 6)
                {
                    uint8_t devicePublicKeyingMaterial[65] = {0};
                    devicePublicKeyingMaterial[0] = 4;
                    memcpy(&devicePublicKeyingMaterial[1], &deviceCert[9], 64);

                    uint8_t r[32] = {0};
                    uint8_t s[32] = {0};
                    int_fast16_t shaResult;
                    int_fast16_t verifyResult;
                    // SHA256 signer public key
                    SHA2_Params params;
                    SHA2_Handle handle;
                    uint8_t message[32] = {0x6B, 0x54, 0x38, 0xE5, 0xE3, 0xC0, 0x1B, 0xF1, 0x44, 0x1E, 0x90, 0xDB, 0x8E, 0x9D, 0x0D, 0xB8,
                                           0xE4, 0xBB, 0xA1, 0x0D, 0xD9, 0x05, 0xDC, 0x0C, 0xC0, 0xCA, 0x3F, 0x48, 0xB3, 0x7C, 0xA8, 0x79};
                    uint8_t shaDigest[32]; // 32 bytes hash values
                    SHA2_init();
                    SHA2_Params_init(&params);
                    handle = SHA2_open(SHA2_INSTANCE, NULL);

                    shaResult = SHA2_hashData(handle, message, sizeof(message), shaDigest);
                    SHA2_close(handle);

                    // verify signature
                    for (int i = 0; i < 32; i++) {
                        r[i] = gattMsg->msg.handleValueNoti.pValue[1 + i];
                        s[i] = gattMsg->msg.handleValueNoti.pValue[33 + i];
                    }
                    CryptoKey devicePublicKey;
                    ECDSA_Handle ecdsaHandle;
                    ECDSA_Params ecdsaParams;
                    ECDSA_OperationVerify operationVerify;

                    ECDSA_init();
                    ECDSA_Params_init(&ecdsaParams);
                    ecdsaHandle = ECDSA_open(0, NULL);
                    CryptoKeyPlaintext_initKey(&devicePublicKey,
                                               devicePublicKeyingMaterial,
                                               sizeof(devicePublicKeyingMaterial));

                    ECDSA_OperationVerify_init(&operationVerify);
                    operationVerify.curve           = &ECCParams_NISTP256;
                    operationVerify.theirPublicKey  = &devicePublicKey;
                    operationVerify.hash            = shaDigest;
                    operationVerify.r               = r;
                    operationVerify.s               = s;

                    verifyResult = ECDSA_verify(ecdsaHandle, &operationVerify);
                    if (verifyResult == ECDSA_STATUS_SUCCESS)
                    {
                        MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE4, 0 ,"challenge verify status = %d", verifyResult);
                        ECDSA_close(ecdsaHandle);

                        ClockP_sleep(1);
                        GAPBondMgr_Pair(0);
                    }
                }
            }
            break;

        default:
            break;
    }
}

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
  status = BLEAppUtil_registerEventHandler( &verifyHandler );
  status = BLEAppUtil_registerEventHandler( &challengeHandler );

  // Return status value
  return( status );
}

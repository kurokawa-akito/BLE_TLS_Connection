/******************************************************************************

@file  app_simple_gatt.c

@brief This file contains the Simple GATT application functionality

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
#include <ti/bleapp/profiles/simple_gatt/simple_gatt_profile.h>
#include <ti/bleapp/menu_module/menu_module.h>
#include <app_main.h>

#include <ti/drivers/SHA2.h>
#include <ti/drivers/ECDSA.h>
#include <ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h>
//*****************************************************************************
//! Defines
//*****************************************************************************

//*****************************************************************************
//! Globals
//*****************************************************************************
static void SimpleGatt_changeCB( uint8_t paramId );
void SimpleGatt_notifyChar4();

// Simple GATT Profile Callbacks
static SimpleGattProfile_CBs_t simpleGatt_profileCBs =
{
  SimpleGatt_changeCB // Simple GATT Characteristic value change callback
};

//uint8_t signerPrivateKeyingMaterial[32] = {0x80, 0x6B, 0xA4, 0x5D, 0x93, 0x02, 0x48, 0xD5, 0x33, 0x31,
//                                           0x87, 0xE5, 0xDD, 0xE7, 0x4C, 0x06, 0x24, 0xDB, 0x71, 0x00,
//                                           0xF4, 0xAB, 0x11, 0x63, 0x80, 0x7E, 0x48, 0x0D, 0x7C, 0x3B,
//                                           0x8E, 0xC7};
//uint8_t devicePrivateKeyingMaterial[32] = {0x31, 0xE8, 0xEA, 0xAC, 0x81, 0x44, 0xF8, 0x51, 0xDD, 0xE8,
//                                           0x64, 0x21, 0xCD, 0xFA, 0x97, 0x05, 0x34, 0x6D, 0x27, 0xA9,
//                                           0x0C, 0xF9, 0x24, 0x1D, 0x9D, 0xE5, 0x8C, 0xCE, 0x2A, 0xB5,
//                                           0x2D, 0xC5};
static uint8_t deviceCert[137] = {0x01,
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
static uint8_t signerCert[137] = {0x02,
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

//*****************************************************************************
//! Functions
//*****************************************************************************

/*********************************************************************
 * @fn      SimpleGatt_ChangeCB
 *
 * @brief   Callback from Simple Profile indicating a characteristic
 *          value change.
 *
 * @param   paramId - parameter Id of the value that was changed.
 *
 * @return  None.
 */
static void SimpleGatt_changeCB( uint8_t paramId )
{
//  uint8_t newValue = 0;
    static uint8_t newValue1[SIMPLEGATTPROFILE_CHAR1_LEN] = {0};
    static uint8_t newValue2[SIMPLEGATTPROFILE_CHAR2_LEN] = {0};
    static uint8_t newValue3[SIMPLEGATTPROFILE_CHAR3_LEN] = {0};
//    static uint8_t newValue4[SIMPLEGATTPROFILE_CHAR4_LEN] = {0};
    static uint8_t newValue5[SIMPLEGATTPROFILE_CHAR5_LEN] = {0};
    static uint8_t newValue6[SIMPLEGATTPROFILE_CHAR6_LEN] = {0};

  switch( paramId )
  {
    case SIMPLEGATTPROFILE_CHAR1:
      {
        SimpleGattProfile_getParameter( SIMPLEGATTPROFILE_CHAR1, newValue1 );

        // Print the new value of char 1
        MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE, 0, "Profile status: Simple profile - "
                          "Char 1 value = " MENU_MODULE_COLOR_YELLOW "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d " MENU_MODULE_COLOR_RESET,
                          newValue1[0], newValue1[1], newValue1[2], newValue1[3], newValue1[4], newValue1[5], newValue1[6], newValue1[7], newValue1[8],
                          newValue1[9], newValue1[10], newValue1[11], newValue1[12], newValue1[13], newValue1[14], newValue1[15]);
      }
      break;

    case SIMPLEGATTPROFILE_CHAR2:
    {
        SimpleGattProfile_getParameter( SIMPLEGATTPROFILE_CHAR2, newValue2 );
        if (newValue2[0] == 6 && newValue2[1] == 3)
        {
            doAttNotification(46, deviceCert, sizeof(deviceCert));
        }

        else if (newValue2[0] == 1) //verify device certificate
        {
            static uint8_t devicePublicKeyingMaterial[65] = {0};
            devicePublicKeyingMaterial[0] = 4;
            memcpy(&devicePublicKeyingMaterial[1], &newValue2[9], 64);

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
                message[i] = newValue2[ 9 + i ];
            }
            uint8_t shaDigest[32]; // 32 bytes hash values
            SHA2_init();
            SHA2_Params_init(&params);
            handle = SHA2_open(0, NULL);

            shaResult = SHA2_hashData(handle, message, sizeof(message), shaDigest);
            SHA2_close(handle);

            // ecdsa verify signer certificate
            for (int i = 0; i < 32; i++) {
                r[i] = newValue2[73 + i];
                s[i] = newValue2[105 + i];
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
                MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE3, 0 ,"device verify status = %d", verifyResult);
                ECDSA_close(ecdsaHandle);
                uint8_t deviceVerifySuccessMsg[2] = {0xaa, 0xbb};
                doAttNotification(46, deviceVerifySuccessMsg, sizeof(deviceVerifySuccessMsg));
                /*
                 * Send a nonce commands to TA010 to get the 32 bytes random number
                 */
                uint8_t ta010Nonce[33] = {0x03, // nonce id
                                          0x6B, 0x54, 0x38, 0xE5, 0xE3, 0xC0, 0x1B, 0xF1,
                                          0x44, 0x1E, 0x90, 0xDB, 0x8E, 0x9D, 0x0D, 0xB8,
                                          0xE4, 0xBB, 0xA1, 0x0D, 0xD9, 0x05, 0xDC, 0x0C,
                                          0xC0, 0xCA, 0x3F, 0x48, 0xB3, 0x7C, 0xA8, 0x79};
                SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR5, SIMPLEGATTPROFILE_CHAR5_LEN,
                                                ta010Nonce );
            }
        }
      }
      break;

    case SIMPLEGATTPROFILE_CHAR3:
      {
        SimpleGattProfile_getParameter(SIMPLEGATTPROFILE_CHAR3, newValue3);
        if (newValue3[0] == 2) //verify signer certificate
        {
            static uint8_t signerPublicKeyingMaterial[65] = {0};
            signerPublicKeyingMaterial[0] = 4;
            memcpy(&signerPublicKeyingMaterial[1], &newValue3[9], 64);

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
                message[i] = newValue3[ 9 + i ];
            }
            uint8_t shaDigest[32]; // 32 bytes hash values
            SHA2_init();
            SHA2_Params_init(&params);
            handle = SHA2_open(0, NULL);

            shaResult = SHA2_hashData(handle, message, sizeof(message), shaDigest);
            SHA2_close(handle);

            // ecdsa verify signer certificate
            for (int i = 0; i < 32; i++) {
                r[i] = newValue3[73 + i];
                s[i] = newValue3[105 + i];
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

                uint8_t signerSuccessVerifyMsg[2] = {0x55, 0x66};
                doAttNotification(46, signerSuccessVerifyMsg, sizeof(signerSuccessVerifyMsg));
            }
        }
        else if (newValue3[0] == 5 && newValue3[1] == 3)
        {
            doAttNotification(46, signerCert, sizeof(signerCert));
        }

        break;
      }

    case SIMPLEGATTPROFILE_CHAR4:
      {
//          SimpleGattProfile_getParameter(SIMPLEGATTPROFILE_CHAR4, newValue4);

          // Print Notification registration to user
          MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE, 0, "Profile status: Simple profile - "
                                    "Char 4 = Notification registration");

          SimpleGatt_notifyChar4();
          break;
      }

    case SIMPLEGATTPROFILE_CHAR5:
      {
        SimpleGattProfile_getParameter(SIMPLEGATTPROFILE_CHAR5, newValue5);
        if (newValue5[0] == 3)
        {
            /*
             * Send a Sign command to TA010 and get a 64 bytes signature
             */
            static uint8_t ta010Signature[65] = {0x06,
                                                 0x60, 0x1E, 0xAF, 0xC6, 0x69, 0xEF, 0x3C, 0xFE, 0x96, 0x49, 0x3A, 0xAC, 0xD0, 0x45, 0xBF, // signature r
                                                 0x74, 0xF8, 0x1B, 0xD6, 0xCE, 0x34, 0x65, 0x8F, 0x79, 0x34, 0x59, 0x3F, 0x74, 0xF2, 0x0C,
                                                 0xA8, 0x3F,
                                                 0xAF, 0x00, 0xFA, 0x71, 0x3B, 0x53, 0xDC, 0x40, 0x25, 0x39, 0x6D, 0xE8, 0xAC, 0x0D, 0x41, // signature s
                                                 0xA2, 0x7C, 0x38, 0x06, 0xCA, 0x7E, 0x04, 0x34, 0x40, 0x3C, 0xAD, 0x8F, 0x48, 0x30, 0xA1,
                                                 0xA9, 0xA7};
            doAttNotification(46, ta010Signature, sizeof(ta010Signature));
        }

//        SimpleGatt_notifyChar4();
      }
      break;

    case SIMPLEGATTPROFILE_CHAR6:
      {
          SimpleGattProfile_getParameter(SIMPLEGATTPROFILE_CHAR6, newValue6);
          if (newValue6[0] == 6)
          {
              static uint8_t devicePublicKeyingMaterial[65] = {0};
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
              handle = SHA2_open(0, NULL);

              shaResult = SHA2_hashData(handle, message, sizeof(message), shaDigest);
              SHA2_close(handle);

              // ecdsa verify signature
              for (int i = 0; i < 32; i++) {
                  r[i] = newValue6[1 + i];
                  s[i] = newValue6[33 + i];
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
                  MenuModule_printf(APP_MENU_PROFILE_STATUS_LINE4, 0, "challenge verify status = %d", verifyResult);
                  ECDSA_close(ecdsaHandle);
                  uint8_t successMsg[2] = {0xcc, 0xdd};
                  doAttNotification(46, successMsg, sizeof(successMsg));
              }
          }
          break;
      }
    default:
      // should not reach here!
      break;
  }
}

/*********************************************************************
 * @fn      SimpleGatt_start
 *
 * @brief   This function is called after stack initialization,
 *          the purpose of this function is to initialize and
 *          register the Simple GATT profile.
 *
 * @return  SUCCESS or stack call status
 */
bStatus_t SimpleGatt_start( void )
{
  bStatus_t status = SUCCESS;

  // Add Simple GATT service
  status = SimpleGattProfile_addService();
  if(status != SUCCESS)
  {
    // Return status value
    return(status);
  }

  // Setup the Simple GATT Characteristic Values
  // For more information, see the GATT and GATTServApp sections in the User's Guide:
  // http://software-dl.ti.com/lprf/ble5stack-latest/
  {
//      status = GAPBondMgr_SCGetLocalOOBParameters(&localOobData);

      uint8_t charValue1[SIMPLEGATTPROFILE_CHAR1_LEN] = {0};
      uint8_t charValue2[SIMPLEGATTPROFILE_CHAR2_LEN] = {0};
//      memcpy(charValue1, localOobData.confirm, KEYLEN);
//      memcpy(charValue1 + KEYLEN, localOobData.rand, KEYLEN);
      uint8_t charValue3[SIMPLEGATTPROFILE_CHAR3_LEN] = {0};
      uint8_t charValue4[SIMPLEGATTPROFILE_CHAR4_LEN] = {0};
      uint8_t charValue5[SIMPLEGATTPROFILE_CHAR5_LEN] = {0};
      uint8_t charValue6[SIMPLEGATTPROFILE_CHAR6_LEN] = {0};

      SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR1, SIMPLEGATTPROFILE_CHAR1_LEN,
                                    charValue1 );
      SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR2, SIMPLEGATTPROFILE_CHAR2_LEN,
                                    charValue2 );
      SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR3, SIMPLEGATTPROFILE_CHAR3_LEN,
                                    charValue3 );
      SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR4, SIMPLEGATTPROFILE_CHAR4_LEN,
                                    charValue4 );
      SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR5, SIMPLEGATTPROFILE_CHAR5_LEN,
                                    charValue5 );
      SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR6, SIMPLEGATTPROFILE_CHAR6_LEN,
                                    charValue6 );
  }
  // Register callback with SimpleGATTprofile
  status = SimpleGattProfile_registerAppCBs( &simpleGatt_profileCBs );

  // Return status value
  return(status);
}

/*********************************************************************
 * @fn      SimpleGatt_notifyChar4
 *
 * @brief   This function is called when WriteReq has been received to Char 4 or to Char 3.
 *          The purpose of this function is to send notification of Char 3 with the value
 *          of Char 3.
 *
 * @return  void
 */
void SimpleGatt_notifyChar4()
{
  uint8_t value;
  if (SimpleGattProfile_getParameter(SIMPLEGATTPROFILE_CHAR3, &value) == SUCCESS)
    {
      // Call to set that value of the fourth characteristic in the profile.
      // Note that if notifications of the fourth characteristic have been
      // enabled by a GATT client device, then a notification will be sent
      // every time there is a change in Char 3 or Char 4.
      SimpleGattProfile_setParameter(SIMPLEGATTPROFILE_CHAR4, sizeof(uint8_t),
                                 &value);
    }
}

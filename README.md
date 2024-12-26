# Introduction
This project integrates an HSM to implement the standard TLS authentication process over Bluetooth Low Energy connection.  
## Contents  
- [Tools](#tools)
- [IDE](#ide)
- [SDK](#sdk)
- [Procedure](#procedure)
- [Detail](#detail)
- [Verify ECDSA Signature](#verify-ecdsa-signature)
- [End of Procedure](#end-of-procedure)
- [TA010 Commands](#ta010-commands)

## Tools
* CC2340R5 LaunchPad *2 (TI BLE chip)
* TA010 *2 (Microchip HSM)
## IDE
* Code Composer Studio 12.7.1 (CC2340R5)  
* MPLAB X IDE v6.20 (TA010)
## SDK
* simplelink_lowpower_f3_sdk_8_10_01_02\examples\rtos\LP_EM_CC2340R5\ble5stack\basic_ble  
  * This repository only provides the **app** and **GATT profile** parts of the sample code, primarily used to demonstrate how to implement TLS in BLE connections.  
* Trust Platform Design Suite (Usecases\TA010-TFLXAUTH\Asymmetric Authentication)
## Procedure
* The process of generating OOB data and exchanging it via ATT
![image](https://github.com/user-attachments/assets/283de8bf-32e5-4144-b3df-39e57752f125)
* Certificates Chain Verification and challenge validation between two BLE devices
![image](https://github.com/user-attachments/assets/dabd6a73-319f-4d65-b4f3-60c2a49e2ee6)
* Standard BLE OOB Pairing procedure
![image](https://github.com/user-attachments/assets/0258b4d5-c172-4b50-8c22-c7e4c5dde74b)
## Detail
### Central
#### Scanning stage
When Central scan the specified address, it will automatically initiate the connection.  
```c
        case BLEAPPUTIL_ADV_REPORT:
        {
            bleStk_GapScan_Evt_AdvRpt_t *pScanRpt = &scanMsg->pBuf->pAdvReport;
            if (pScanRpt->pData != NULL)
            {
                if(pScanRpt->addr[0] == 0x96 && // 96
                   pScanRpt->addr[1] == 0x5D && // 5D
                   pScanRpt->addr[2] == 0x3C && // 3C
                   pScanRpt->addr[3] == 0x93 &&
                   pScanRpt->addr[4] == 0x72 &&
                   pScanRpt->addr[5] == 0x84)
                {
                    BLEAppUtil_ConnectParams_t connParams =
                    {
                      .peerAddrType = pScanRpt->addrType,
                      .phys = INIT_PHY_1M,
                      .timeout = 3000
                    };
                    memcpy(connParams.pPeerAddress, pScanRpt->addr, B_ADDR_LEN);
                    bStatus_t status = BLEAppUtil_connect(&connParams);
                }
            }

            break;
        }
```
#### Connection stage
Since the default maximum length of ATT packets (ATT_MTU) after connection is 23 bytes (or 65 bytes if Secure Connection is used), it is necessary to send an ATT_EXCHANGE_MTU_REQ within the BLEAPPUTIL_LINK_ESTABLISHED_EVENT case to increase the maximum payload length of ATT packets.  
Use GAPBondMgr_SCGetLocalOOBParameters() to calculate the Local OOB Data (random value & confirm value). This calculation can also be performed before establishing a connection, but it must be completed and exchanged before pairing begins.
```c
void Central_GAPConnEventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData)
{
    switch(event)
    {
        case BLEAPPUTIL_LINK_ESTABLISHED_EVENT:
        {
            gapEstLinkReqEvent_t *gapEstMsg = (gapEstLinkReqEvent_t *)pMsgData;
            HCI_LE_SetDataLenCmd(0, 251, 2120);

            bStatus_t status = GAPBondMgr_SCGetLocalOOBParameters(&localOobData);

            uint8_t charValue1[SIMPLEGATTPROFILE_CHAR1_LEN] = {0};
            memcpy(charValue1, localOobData.confirm, KEYLEN);
            memcpy(charValue1 + KEYLEN, localOobData.rand, KEYLEN);
            SimpleGattProfile_setParameter( SIMPLEGATTPROFILE_CHAR1, SIMPLEGATTPROFILE_CHAR1_LEN,
                                          charValue1 );

            doAttMtuExchange(251);
        }
        break;


        default:
        {
            break;
        }
    }
}
```
doAttMtuExchange() is defined in app_main.c
```c
bStatus_t doAttMtuExchange(uint16 MTUVals)
{
    // Exchange and set Max MTU
    attExchangeMTUReq_t req;
    req.clientRxMTU = MTUVals - L2CAP_HDR_SIZE;
    bStatus_t status = GATT_ExchangeMTU(0, &req, BLEAppUtil_getSelfEntity());

    return status;
}
```
When the BLE stack receives an ATT_RSP packet, the eventHandler can be used to process the received packet. For example, upon receiving an ATT_READ_RSP, the subsequent behavior can be customized using the gattMsgEvent_t structure.  
In app_data.c:
```c
static void GATT_EventHandler(uint32 event, BLEAppUtil_msgHdr_t *pMsgData)
{
  gattMsgEvent_t *gattMsg = ( gattMsgEvent_t * )pMsgData;
  switch ( gattMsg->method )
  {
    ...
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
```
It is important to note that the eventHandler for processing ATT packets cannot handle REQ types or ATT_WRITE_CMD packets. Therefore, if specific actions need to be executed upon receiving an ATT_WRITE_CMD, it should be implemented within the callback function.
![image](https://github.com/user-attachments/assets/080806e0-8250-4e23-8ce4-2e3e2f74a7e5)    
in app_simple_gatt.c:
```c
// Simple GATT Profile Callbacks
static SimpleGattProfile_CBs_t simpleGatt_profileCBs =
{
  SimpleGatt_changeCB // Simple GATT Characteristic value change callback
};
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
    uint8_t newValue1[SIMPLEGATTPROFILE_CHAR1_LEN] = {0};
    uint8_t newValue2[SIMPLEGATTPROFILE_CHAR2_LEN] = {0};
    uint8_t newValue3[SIMPLEGATTPROFILE_CHAR3_LEN] = {0};
    uint8_t newValue4[SIMPLEGATTPROFILE_CHAR4_LEN] = {0};
    uint8_t newValue5[SIMPLEGATTPROFILE_CHAR5_LEN] = {0};
    uint8_t newValue6[SIMPLEGATTPROFILE_CHAR6_LEN] = {0};

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

```
### Peripheral
Basically, the Peripheral executes corresponding actions based on the commands from the Central.  
## Verify ECDSA Signature  
The spirit of a certificate is to use a trusted source's private key to sign someone else's public key.
### Signing
![image](https://github.com/user-attachments/assets/266b8e58-8686-42e0-a42d-4881903b4ae0)  
### Verify  
![image](https://github.com/user-attachments/assets/ff1d6c9b-8ce9-4d23-b521-8866e7a6d75a)
When verifying signatures or certificates, the SHA2 and ECDSA drivers provided by TI are required.  
app_simple_gatt.c in Peripheral:
```c
#include <ti/drivers/SHA2.h>
#include <ti/drivers/ECDSA.h>
#include <ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h>
...
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
        break;
      }
```

## End of Procedure
Secure Connection pairing initiated by Central.

## TA010 Commands
In this project, the commands used are Read, GenKey, Nonce, and Sign.
### Read
Read data from the EEPROM.  
![image](https://github.com/user-attachments/assets/605a223c-412b-4676-a514-1f5e7e74c101)  
#### Command format  
![image](https://github.com/user-attachments/assets/1ecd1a05-fbcb-468f-9e75-961ec691469b)
### GenKey
Generate a ECC public key associated with the ECC private key in slot 0.
#### Command format
![image](https://github.com/user-attachments/assets/58d81cdc-79f8-4e08-96bd-68d611a4cd3e)
### Nonce
Generate a 32 bytes random number.
#### Command format
![image](https://github.com/user-attachments/assets/20232808-cd47-4e64-85c7-b0815d4e803e)
### Sign
Use ECDSA to calculate the signature of a piece of data.
#### Command format
![image](https://github.com/user-attachments/assets/80a92261-2ce8-4cfa-8a10-52bbc8692e46)

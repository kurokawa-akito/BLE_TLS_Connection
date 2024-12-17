# Introduction
This project integrates an HSM to implement the standard TLS authentication process over Bluetooth Low Energy connection.
## Tools
* CC2340R5 LaunchPad *2 (TI BLE chip)
* TA010 *2 (Microchip HSM)
## IDE
TI Code Composer Studio 12.7.1
## SDK
simplelink_lowpower_f3_sdk_8_10_01_02\examples\rtos\LP_EM_CC2340R5\ble5stack\basic_ble
## Procedure
* The process of generating OOB data and exchanging it via ATT
![image](https://github.com/user-attachments/assets/283de8bf-32e5-4144-b3df-39e57752f125)
* Certificates Chain Verification and challenge validation between two BLE devices
![image](https://github.com/user-attachments/assets/f3e13024-365a-473a-b611-02cab9dd0edb)
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




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
![image](https://github.com/user-attachments/assets/d31d1a88-43bf-46b1-97de-00466f7e5b56)
* Certificates Chain Verification and challenge validation between two BLE devices
![image](https://github.com/user-attachments/assets/e51c71de-1fc5-4296-b701-049df57c2865)
* Standard BLE OOB Pairing procedure
![image](https://github.com/user-attachments/assets/2f32dbc1-0d85-48f0-ac79-24cc3466df78)




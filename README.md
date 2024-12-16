# Introduction
This project integrates an HSM to implement the standard TLS authentication process over Bluetooth Low Energy.
## Tools
* CC2340R5 LaunchPad *2 (TI BLE chip)
* TA010 *2 (Microchip HSM)
## IDE
TI Code Composer Studio 12.7.1
## SDK
simplelink_lowpower_f3_sdk_8_10_01_02\examples\rtos\LP_EM_CC2340R5\ble5stack\basic_ble
## Procedure
* The process of generating OOB data and exchanging it via ATT
![image](https://github.com/user-attachments/assets/a559a9f1-f5ee-40ea-9172-6eb99d6dcac5)
* Certificates Chain Verification and challenge validation between two BLE devices
![image](https://github.com/user-attachments/assets/e51c71de-1fc5-4296-b701-049df57c2865)
* Standard BLE OOB Pairing procedure
![image](https://github.com/user-attachments/assets/dd0c0491-d170-41e6-b656-5b85603173f4)


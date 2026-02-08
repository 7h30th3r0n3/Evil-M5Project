# ESP32-C5 — Slave & Stand-Alone

## Explanation

This repository part bundles ready-to-flash firmware for **ESP32-C5** boards which have dualband 2.4 and 5.8Ghz that can be used with/or alongside ​the Evil-M5Project.

- **Multi C5** – ESP32-C5 scan / deauth / sniff and send EAPOL to **evil** ro save it in a pcap on 2.4 and/or 5.8Ghz.
- **Wardriving Slave** – ESP32-C5 collects SSIDs from nearby access points (APs) by hopping across predefined channels on 2.4 and/or 5.8Ghz.  
- **Sniffer Slave** – Captures EAPOL frames by hopping across predefined channels on 2.4 and/or 5.8Ghz.   
- **Evil Twin C5** – Standalone captive-portal with deauth implementation on 2.4 and/or 5.8Ghz.  
- **Auto-Deauther** – Standalone deauthentication module that can be paired with the Sniffer Slave to trigger EAPOL captures on 2.4 and/or 5.8Ghz.

Deploying multiple ESP32-C5 nodes improves coverage and reliability: a “static” slave locked to one channel prevents packet loss caused by hopping.  
Boards with external antennas yield far better results than stock M5Stack devices. 

---

### `Evil-Twin-C5.ino`
Standalone webui configurable Evil-Twin access point that can deauth an original one.

### `slave_deauther_C5.ino`
Continuously performs deauthentication attacks on preconfigured channel on 2.4 and/or 5.8Ghz.

### `slave_gps_channel_multi_C5_5GHz.ino`
Designed for use with the Wardriving Master: logs GPS data while sweeping multiple 2.4 GHz **and** 5 GHz channels—perfect for geolocating dual-band APs.

### `slave_multi_C5.ino`
ESP32-C5 scan / deauth / sniff and send EAPOL to **evil** ro save it in a pcap on 2.4 and/or 5.8Ghz, in this way just need to add one to your rig.

### `slave_sniffer_channel_hopping_c5.ino`
Captures EAPOL frames passively by hopping across predefined channels on 2.4 and/or 5.8Ghz.  

---

## Installation

> Tested with **Arduino IDE 1.x** (1.8.19) and the official Espressif **ESP32-C5 Dev Module** core.

1. **Install / update Arduino IDE 1.x**  
   *Download*: <https://www.arduino.cc/en/software>  

2. **Add the ESP32 core**
   ⚠️⚠️⚠️ These version work on esp32 3.3.0-alpha1 only ⚠️⚠️⚠️
   * File → Preferences → *Additional Boards Manager URLs*  
     ```
      https://espressif.github.io/arduino-esp32/package_esp32_dev_index.json
     ```  
   * Tools → Board → Boards Manager… → search **esp32** → install or update.

4. **Select the board**  
   * Tools → Board → **ESP32C5 Dev Module** (sometimes shown as *ESP32-C5 Dev Board* in older core builds).  
   * Pick the correct **Flash Size** & **Upload Speed** (default 115200 works fine).

5. **Install required libraries**  
   * Tools → Manage Libraries… → search **Adafruit NeoPixel** → *Install*.  
   * No other external libraries are needed; all Wi-Fi / BLE functionality comes from the ESP32 core itself.

6. **patch esp32**  
   * Use this to patch your esp32 dependencies : https://github.com/7h30th3r0n3/Evil-M5Project/tree/main/utilities/compilation_prerequisites.  

7. **Get the firmware**  
   * Clone this repo or download the ZIP.  
   * Open the desired `.ino` file (e.g. `Evil-Twin-C5.ino`) in Arduino IDE.

8. **Compile & flash**  
   * Connect the ESP32-C5 via USB-C/USB-TTL.  
   * Tools → Port → select the correct COM/tty port.  
   * Click **Upload** (⭱).  
   * After flashing, open the Serial Monitor at 115200 baud to check the boot logs.

> **Tip**: If compilation fails with “cannot open source file ‘Arduino.h’”, make sure the ESP32 core finished installing and restart the IDE.  
> For “Timed out waiting for packet header” errors, try lowering the upload speed to 921600 or 460800 baud.

---

## Disclaimer

> This code is provided for educational and research purposes only.  
> Using sniffing, deauthentication or Evil-Twin tools on a network without the owner’s explicit permission is illegal in most jurisdictions.  
> **The author assumes no liability** for any misuse of these scripts.

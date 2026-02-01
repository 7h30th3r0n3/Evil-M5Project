# ESP32 Deauthentication & BadUSB – Prerequisites

> ⚠️ **Educational & authorized use only**  
> These scripts are intended for **research, lab testing, and authorized environments only**.

All original concepts and early implementations are based on the excellent **n0xa / NEMO project**:  
https://github.com/n0xa/m5stick-nemo/tree/main/deauth_prerequisites  

This repository **extends, generalizes and modernizes** that work to support:
- ESP32 **2.x / 3.x / 3.3.x**
- **ESP32-C5**
- Multiple vendors (`esp32`, `m5stack`, forks)
- **Windows, Linux, macOS**
- Optional **BadUSB core injection**

---

## DEAUTHENTICATION – Why prerequisites are required

When compiling for ESP32 boards, the Arduino core performs **sanity checks** to prevent the use of raw 802.11 frames for non-standard purposes.

One of these protections is the internal function:

```
ieee80211_raw_frame_sanity_check()
```

This function blocks transmission of raw Wi-Fi frames, including:
- Deauthentication frames
- Custom management frames
- Other low-level 802.11 injections

To enable deauthentication broadcasting, two things are required:

1. **Silence compiler warnings and linker conflicts**
2. **Override the sanity check at runtime**

---

## Runtime bypass (required)

Your firmware **must override** the sanity check function:

```cpp
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t, int32_t) {
    return (arg == 31337) ? 1 : 0;
}
```

---

## Automated solution (recommended)

This repository provides **universal, vendor-agnostic patchers**.

### Windows
- `patch-esp32-arduino-all.ps1`

### Linux / macOS
- `patch-esp32-arduino-all.sh`

---

## Optional: BadUSB core patch

If the following scripts are detected:

```
utilities/Bad_Usb_Lib/USB-LIB-PATCH.ps1
utilities/Bad_Usb_Lib/USB-LIB-PATCH.sh
```

You will be prompted at the end of the ESP32 patch to optionally run the BadUSB patch.

---

## Credits / Thanks

- **n0xa**  
  Original NEMO project, initial deauthentication work  
  https://github.com/n0xa/m5stick-nemo  

- **@bmorcelli**  
  Major contributor to Deauthentication support, SD fixes, and core improvements  
  via Pull Request #84  
  https://github.com/n0xa/m5stick-nemo/pull/84  

- **@danny8972**  
  macOS & Linux prerequisite script adaptations  

- **Spacehuhn**  
  Original patch : https://github.com/SpacehuhnTech/esp8266_deauther 

---

## Notes

- Always restart **Arduino IDE** after patching
- Updating ESP32 boards **requires re-running the patch**
- Use **only in authorized environments**

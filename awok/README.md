# Evil-Cardputer → AWOK Dual ESP32 Mini v2

Port of **Evil-Cardputer v1.5.6** (Evil-M5Project, originally for the M5Cardputer / ESP32-S3)
to the **AWOK Dual ESP32 Mini v2** — the **white port** side = classic **ESP32-D0WD-V3**
(16 MB flash, **no PSRAM**), driving a 1.44" **128×128 ST7735S** display.

## Hardware

| Item | Detail |
|---|---|
| MCU | ESP32-D0WD-V3 (classic, white USB port via CP2102 `/dev/ttyUSB0`) |
| Flash | 16 MB · PSRAM: **none** |
| Display | 1.44" 128×128 **ST7735S** — VSPI SCK18/MISO19/MOSI23, CS17/DC16/RST5, backlight GPIO32 (active LOW) |
| SD | shared VSPI, CS GPIO4 |
| Input | 5-way joystick → NavAction: Up=`;` Down=`.` Left=BACKSPACE Right=`/` Center=ENTER (`,` PGUP unreachable) |
| GPS | UART2 RX21 / TX22 @ 9600 |
| DIP switch | routes the CP2102 programmer (and GPS) between the ESP32 (display) and the ESP32-S2 |

## Files

- `awok.ino` — main sketch (edited copy of `EvilCardputer-v-1-5-6.ino`)
- `awok_config.h` — pins, NavAction enum, `menuItemAvailable()` (hides unsupported menu items)
- `awok_lgfx.h` — LovyanGFX `Panel_ST7735S` device + `AwokLcd` (integer text scaling)
- `awok_m5_shim.h` — M5Unified / M5Cardputer compatibility shim over LovyanGFX
- `awok_input.h` — joystick polling + virtual keyboard
- `awok_usb_stub.h`, `awok_audio_stub.h` — stubs for absent USB-HID / speaker

All AWOK-specific code is gated behind `#define AWOK_MINI 1` (in `awok_config.h`).

## Build & flash

Arduino core **m5stack:esp32 2.1.4**, LovyanGFX 1.2.28.

```sh
arduino-cli compile --fqbn "m5stack:esp32:m5stack_core:FlashSize=16M,PartitionScheme=huge_app" --build-path build .
arduino-cli upload -p /dev/ttyUSB0 --fqbn "m5stack:esp32:m5stack_core:FlashSize=16M,PartitionScheme=huge_app,UploadSpeed=115200" --input-dir build .
```

- **UploadSpeed=115200 is required** (CP2102 fails at 1.5 Mbaud).
- If upload reports *"This chip is ESP32-S2"*, flip the DIP switch back to the **white ESP32** side.
- App footprint ≈ **86 %** of the 3 MB `huge_app` partition; globals ≈ **26 %** RAM.

## Status

- ✅ Compiles, flashes, boots; WiFi + BLE features working (no PSRAM — BLE stabilised by removing dead code).
- ✅ Full 128×128 UI pass: menu (unsupported items hidden), taskbar, popups, network list, CSI, Dead Drop,
  IMSI, Handshake, PwnGrid, SSDP, CCTV toolkit, and the 6 BLE screens
  (Wall of Flipper, BLE NameFlood, Wall of AirTags, FindMyEvil, WhisperPair, AppleSniff).
- ✅ CCTV MJPEG viewer: resolution-agnostic decode, centered, no per-frame flash; non-blocking stream connect.
- ✅ Dead code of hardware-absent features removed via dispatch guards + linker `--gc-sections` (−269 KB flash).
- ✅ Virtual keyboard driven by the joystick.

### Remaining / ideas
- **NimBLE** migration — the main remaining lever for RAM (~6 KB static + ~25 KB runtime) and BLE stability.
- Remove the ~30 dead `/tt/*` (TagTinker web) routes still linked (flash).
- Remap remaining joystick-unreachable `kp()` keys as encountered.

---
*Based on [Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project) by 7h30th3r0n3.*

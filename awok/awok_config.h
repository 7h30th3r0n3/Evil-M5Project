#pragma once
// ============================================================================
// awok_config.h — board selection, pin map, storage helpers and feature gates
// for the EvilCardputer-v1.5.6 -> AWOK Dual ESP32 Mini v2 (white/display port)
// build. Target silicon: ESP32-D0WD-V3 (classic dual-core), 16 MB flash, NO PSRAM.
//
// MUST be the FIRST #include in EvilCardputer-v-1-5-6.ino, before any M5/LGFX
// header, so AWOK_MINI conditions the whole translation unit.
//
// These headers assume a SINGLE translation unit (the .ino). awokLcd, M5,
// M5Cardputer are defined (not merely declared) in the shim headers.
// ============================================================================

// --- Board profile ----------------------------------------------------------
// Choose ONE. Both are "classic ESP32" AWOK boards, so both keep AWOK_MINI as
// the master gate (same silicon -> same feature amputations + same 128x128
// logical UI). AWOK_TOUCH_V2 only swaps the PHYSICAL display (ILI9341 240x320)
// and the INPUT (XPT2046 resistive touch instead of the joystick): the 128x128
// UI is rendered into a sprite and up-scaled x1.875 into the top 240x240, with
// a 240x80 touch control bar at the bottom.
//
//   * Mini v2  -> leave AWOK_BOARD_MINI_V2 defined below.
//   * Touch v2 -> comment MINI_V2 and uncomment TOUCH_V2.
#define AWOK_BOARD_MINI_V2   1
//#define AWOK_BOARD_TOUCH_V2  1

#if defined(AWOK_BOARD_TOUCH_V2)
  #define AWOK_DUAL_ESP32_TOUCH_V2 1
  #define AWOK_TOUCH_V2            1   // display=ILI9341 240x320 + XPT2046 touch
#else
  #define AWOK_DUAL_ESP32_MINI_V2  1
#endif
#define AWOK_MINI               1   // master gate used by every #ifdef below (both boards)

// --- Optional sub-features ---------------------------------------------------
// SSH compiles on classic ESP32 but the libssh_esp32 dependency is heavy.
// Leave 0 unless the RAM/flash budget has been confirmed on hardware.
#ifndef AWOK_ENABLE_SSH
#define AWOK_ENABLE_SSH 0
#endif

#include <Arduino.h>
#include <SPI.h>
#include <SD.h>

// --- Pin map (source: AWOKxDAG board_pins.h) ---------------------------------
// Shared VSPI bus (display + SD + touch live on the SAME bus, unlike the Cardputer).
#define AWOK_SPI_SCK    18
#define AWOK_SPI_MISO   19
#define AWOK_SPI_MOSI   23
// Display CS/DC identical on both boards.
#define AWOK_LCD_CS     17
#define AWOK_LCD_DC     16
#define AWOK_LCD_BL     32   // backlight GPIO (active level differs per board)

#if defined(AWOK_TOUCH_V2)
// ===== AWOK Dual ESP32 Touch v2 : ILI9341 240x320 + XPT2046 resistive touch ==
#define AWOK_LCD_RST    -1   // reset not driven by a GPIO (tied)
#define AWOK_LCD_BL_INVERT false  // backlight ACTIVE HIGH
#define AWOK_TOUCH_CS   21   // XPT2046 chip-select (shares the VSPI bus)
#define AWOK_SD_CS      14
#define AWOK_SD_HZ      10000000UL
// Physical panel geometry (portrait) + logical UI canvas + scaled blit target.
#define AWOK_PANEL_W    240
#define AWOK_PANEL_H    320
#define AWOK_UI_LOGICAL 128           // firmware draws in a 128x128 space
#define AWOK_UI_DRAW_W  240           // up-scaled UI area (top), full width
#define AWOK_UI_DRAW_H  240           // 128 * 1.875 = 240
#define AWOK_TOUCHBAR_Y 240           // control bar starts here
#define AWOK_TOUCHBAR_H 80            // 320 - 240
// Joystick pins are UNUSED on the Touch (input = XPT2046 bar). Defined as -1 so
// the shared awok_joy::kBtns[] table (whose .act/.repeat ARE used) still compiles.
#define AWOK_JOY_LEFT   -1
#define AWOK_JOY_CENTER -1
#define AWOK_JOY_UP     -1
#define AWOK_JOY_RIGHT  -1
#define AWOK_JOY_DOWN   -1
// GPS on UART2 (Touch wiring + faster default baud)
#define AWOK_GPS_UART    2
#define AWOK_GPS_RX      4   // ESP RX <- GPS TX
#define AWOK_GPS_TX     13
#define AWOK_GPS_BAUD   115200UL
#else
// ===== AWOK Dual ESP32 Mini v2 : ST7735S 128x128 + 5-way joystick ============
#define AWOK_LCD_RST     5
#define AWOK_LCD_BL_INVERT true   // backlight ACTIVE LOW
#define AWOK_SD_CS       4
#define AWOK_SD_HZ       10000000UL
// 5-way joystick. 34/35/36/39 are INPUT-ONLY on classic ESP32 (no internal
// pull-ups; the PCB provides external pull-ups). GPIO13 has an internal pull-up.
#define AWOK_JOY_LEFT   13
#define AWOK_JOY_CENTER 34
#define AWOK_JOY_UP     36
#define AWOK_JOY_RIGHT  39
#define AWOK_JOY_DOWN   35
// GPS on UART2
#define AWOK_GPS_UART    2
#define AWOK_GPS_RX     21
#define AWOK_GPS_TX     22
#define AWOK_GPS_BAUD   9600UL
#endif

// --- Navigation injection contract (shared with the .ino) --------------------
// The enum lives here so the shim/input headers (included near the top of the
// sketch) can name the type. In the .ino: COMMENT OUT the duplicate
//   enum NavAction : uint8_t { ... };
// around L1088, but KEEP the four navPending* variable DEFINITIONS that follow
// it. The headers reference those variables with `extern` declarations.
enum NavAction : uint8_t {
  NAV_NONE = 0, NAV_UP, NAV_DOWN, NAV_ENTER, NAV_BACK, NAV_PGUP, NAV_PGDOWN
};

// --- Storage helpers (single shared VSPI bus) --------------------------------
// Call awokSpiBegin() ONCE in setup() BEFORE awokLcd.init(): the LGFX bus and
// the Arduino SD driver share host VSPI/SPI3. The panel is configured with
// bus_shared=true + use_lock=true so the two cohabit; the second internal
// spi_bus_initialize() returns ESP_ERR_INVALID_STATE and is ignored.
static inline void awokSpiBegin() {
  pinMode(AWOK_LCD_CS, OUTPUT); digitalWrite(AWOK_LCD_CS, HIGH); // deselect LCD
  pinMode(AWOK_SD_CS,  OUTPUT); digitalWrite(AWOK_SD_CS,  HIGH); // deselect SD
  SPI.begin(AWOK_SPI_SCK, AWOK_SPI_MISO, AWOK_SPI_MOSI, -1);
}

// Drop-in replacement for EVERY SD.begin() site (10 MHz on the shared bus).
// Replaces:  SD.begin(12, SPI, 40000000UL)   (boot, L1908)
//            SD.begin()                        (bare form, L15705)
//            SD.begin(sdChipSelectPin, spiInterface, 40000000UL) (MSC, L19947)
static inline bool awokSdBegin() {
  return SD.begin(AWOK_SD_CS, SPI, AWOK_SD_HZ);
}

// ============================================================================
// FEATURE AMPUTATIONS — blocks of the .ino to wrap in `#ifndef AWOK_MINI`.
// Keep the menu string table AND the switch/case fully populated (they are
// indexed in parallel); route each guarded feature's entry function to a stub
// of the SAME signature under `#else`, e.g.:
//
//   #ifndef AWOK_MINI
//     void subGhzMenu() { ... real code ... }
//   #else
//     void subGhzMenu() { waitAndReturnToMenu("Sub-GHz indisponible"); }
//   #endif
//
// Blocks to guard (line numbers per EvilCardputer-v-1-5-6.ino, verify locally):
//   USB native (S3 only)
//     - includes  L916 <USBHIDKeyboard.h>, L918 <USBHIDMouse.h>, L920 <USB.h>
//     - BadUSB     global Kb L924; key_input L14574; chooseKb L14738;
//                  showKeyboardLayoutOptions L14745; showScriptOptions L14769;
//                  runScript L14799; badUSB L14816   -> case 44
//     - Mouse      global Mouse L20356; runMouseJiggler L20361-20458 -> case 43
//     - MSC        L19865-19983 (USBMSC/tusb) -> case 58; pins L19872-19878
//   CC1101 Sub-GHz   whole block L42041-44262 (+ fwd decls L208, L210-213) -> case 89
//                    (CC_CS=5 collides with LCD RST=5; CC_SCLK=40 does not exist)
//   NFC ST25R3916    whole block L44263-47565 (+ fwd decls L209, L214-215) -> case 90
//                    (shares cc_spi/CC_CS with CC1101 -> guard the two together)
//   IR TagTinker     whole block L47566-52576 (+ fwd decls L202, L216-232) -> case 86
//                    (TT_IR_PIN=44 and GPIO.out1_w1ts are S3-only)
//   LoRa SX1262      include L158 <RadioLib.h>; block L40396-40543 -> case 88
//                    (NSS=5 collides with LCD RST; falls back to ESP-NOW only)
//   Audio/MP3        includes L931-934 (ESP8266Audio); class AudioOutputM5Speaker
//                    L936-978; globals/fns L980-1004; play sites L1979-2003,
//                    L7505-7511; all M5.Speaker.tone() calls. Set soundOn=false.
//   NeoPixel LED     L830-834 (PIN 21 collides with GPS RX 21). The shim
//                    provides a no-op Adafruit_NeoPixel stub, so the pixels.*
//                    call sites (L1974-1976, L2140-2143, L2178) need no edits;
//                    just comment the real #include at L136.
//   SSH (optional)   includes L189-190; globals L247-248; fwd L2229; block
//                    L12969-13434 -> case 35.  Guard with `#if !AWOK_ENABLE_SSH`.
//
// DO NOT guard: case 45 initBluetoothKeyboard (BLE HID works on classic ESP32,
// but see TODO re ASCII->HID), case 87 csiRadarMenu (CSI WiFi, no external HW).
// ============================================================================

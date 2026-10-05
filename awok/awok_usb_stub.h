#pragma once
// awok_usb_stub.h — no-op stand-ins for the ESP32-S3 native-USB API, which does
// not exist on the classic ESP32 (AWOK Dual Mini v2). Included by awok_m5_shim.h
// under AWOK_MINI so BadUSB / mouse-jiggler / ducky code COMPILES (as no-ops)
// without touching the feature code. The real <USBHIDKeyboard.h>/<USBHIDMouse.h>/
// <USB.h> are #ifndef AWOK_MINI-guarded out in the sketch.
#include <Arduino.h>

// --- HID key codes (only those not already set in awok_m5_shim.h) ------------
// Values are arbitrary-but-distinct; the stub never emits them.
#ifndef KEY_LEFT_SHIFT
#define KEY_LEFT_SHIFT   0x85
#endif
#ifndef KEY_LEFT_ALT
#define KEY_LEFT_ALT     0x86
#endif
#ifndef KEY_LEFT_GUI
#define KEY_LEFT_GUI     0x87
#endif
#ifndef KEY_RIGHT_CTRL
#define KEY_RIGHT_CTRL   0x88
#endif
#ifndef KEY_RIGHT_SHIFT
#define KEY_RIGHT_SHIFT  0x89
#endif
#ifndef KEY_RIGHT_ALT
#define KEY_RIGHT_ALT    0x8A
#endif
#ifndef KEY_RIGHT_GUI
#define KEY_RIGHT_GUI    0x8B
#endif
#ifndef KEY_UP_ARROW
#define KEY_UP_ARROW     0xDA
#endif
#ifndef KEY_DOWN_ARROW
#define KEY_DOWN_ARROW   0xD9
#endif
#ifndef KEY_LEFT_ARROW
#define KEY_LEFT_ARROW   0xD8
#endif
#ifndef KEY_RIGHT_ARROW
#define KEY_RIGHT_ARROW  0xD7
#endif
#ifndef KEY_RETURN
#define KEY_RETURN       0xB0
#endif
#ifndef KEY_ESC
#define KEY_ESC          0xB1
#endif
#ifndef KEY_INSERT
#define KEY_INSERT       0xD1
#endif
#ifndef KEY_HOME
#define KEY_HOME         0xD2
#endif
#ifndef KEY_PAGE_UP
#define KEY_PAGE_UP      0xD3
#endif
#ifndef KEY_END
#define KEY_END          0xD5
#endif
#ifndef KEY_PAGE_DOWN
#define KEY_PAGE_DOWN    0xD6
#endif
#ifndef KEY_CAPS_LOCK
#define KEY_CAPS_LOCK    0xC1
#endif
#ifndef KEY_PRINT_SCREEN
#define KEY_PRINT_SCREEN 0xCE
#endif
#ifndef KEY_SCROLL_LOCK
#define KEY_SCROLL_LOCK  0xCF
#endif
#ifndef KEY_PAUSE
#define KEY_PAUSE        0xD0
#endif
#ifndef KEY_MENU
#define KEY_MENU         0xED
#endif
#ifndef KEY_SPACE
#define KEY_SPACE        0x20
#endif
#ifndef KEY_F
#define KEY_F            0x46
#endif
#ifndef KEY_F1
#define KEY_F1 (0xE0+1)
#endif
#ifndef KEY_F2
#define KEY_F2 (0xE0+2)
#endif
#ifndef KEY_F3
#define KEY_F3 (0xE0+3)
#endif
#ifndef KEY_F4
#define KEY_F4 (0xE0+4)
#endif
#ifndef KEY_F5
#define KEY_F5 (0xE0+5)
#endif
#ifndef KEY_F6
#define KEY_F6 (0xE0+6)
#endif
#ifndef KEY_F7
#define KEY_F7 (0xE0+7)
#endif
#ifndef KEY_F8
#define KEY_F8 (0xE0+8)
#endif
#ifndef KEY_F9
#define KEY_F9 (0xE0+9)
#endif
#ifndef KEY_F10
#define KEY_F10 (0xE0+10)
#endif
#ifndef KEY_F11
#define KEY_F11 (0xE0+11)
#endif
#ifndef KEY_F12
#define KEY_F12 (0xE0+12)
#endif
#ifndef KEYTAB
#define KEYTAB 0x09
#endif
#ifndef KEYBACKSPACE
#define KEYBACKSPACE 0x08
#endif
#ifndef LED_NUMLOCK
#define LED_NUMLOCK 0x01
#endif

// --- Keyboard layout tables (referenced by chooseKb / Kb.begin) --------------
static const uint8_t KeyboardLayout_en_US[] = {0};
static const uint8_t KeyboardLayout_pt_BR[] = {0};
static const uint8_t KeyboardLayout_pt_PT[] = {0};
static const uint8_t KeyboardLayout_fr_FR[] = {0};
static const uint8_t KeyboardLayout_es_ES[] = {0};
static const uint8_t KeyboardLayout_it_IT[] = {0};
static const uint8_t KeyboardLayout_de_DE[] = {0};
static const uint8_t KeyboardLayout_sv_SE[] = {0};
static const uint8_t KeyboardLayout_da_DK[] = {0};
static const uint8_t KeyboardLayout_hu_HU[] = {0};

// --- USB HID keyboard stub (inherits Print -> print/println for free) --------
class USBHIDKeyboard : public Print {
 public:
  void begin() {}
  void begin(const uint8_t*) {}
  void end() {}
  void setLayout(const uint8_t*) {}
  size_t press(uint8_t) { return 0; }
  size_t release(uint8_t) { return 0; }
  void releaseAll() {}
  void sendReport(void*) {}
  size_t write(uint8_t) override { return 1; }          // no-op sink
  using Print::write;
};

// --- USB HID mouse stub ------------------------------------------------------
class USBHIDMouse {
 public:
  void begin() {}
  void end() {}
  void move(int8_t = 0, int8_t = 0, int8_t = 0, int8_t = 0) {}
  void click(uint8_t = 1) {}
  void press(uint8_t = 1) {}
  void release(uint8_t = 1) {}
};

// --- Global USB device stub (USB.begin()) ------------------------------------
struct AwokUSBStub {
  bool begin() { return false; }
  void productName(const char*) {}
  void manufacturerName(const char*) {}
};
static AwokUSBStub USB;

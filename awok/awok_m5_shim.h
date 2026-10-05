#pragma once
// ============================================================================
// awok_m5_shim.h — drop-in replacement for <M5Unified.h> + "M5Cardputer.h".
//
// Routes M5.Display / M5.Lcd / M5Cardputer.Display to the single LGFX device
// (awokLcd), typedefs M5Canvas -> lgfx::LGFX_Sprite, provides the KEY_*
// constants, a no-op Speaker/Power, a board_t enum, a NeoPixel no-op stub, and
// a Keyboard_Class that synthesizes input from the joystick + virtual keyboard
// via the navPendingAction / navPendingChar channels.
//
// Include order in the .ino:  awok_config.h -> awok_m5_shim.h -> awok_input.h
// (this file forward-declares initJoystick()/pollJoystick(), which awok_input.h
//  defines.)
// ============================================================================
#include "awok_config.h"
#include <driver/adc.h>       // ADC1_CHANNEL_*, adc1_*
#include <esp_adc_cal.h>       // esp_adc_cal_* (lecture batterie)
#include "awok_lgfx.h"
#include <vector>
#include <cstring>

// Bring LovyanGFX names to global scope, exactly as M5GFX does, so the
// firmware's unqualified LGFX_Sprite / IFont / fonts::Font0 compile unchanged.
using lgfx::LGFX_Sprite;              // PAS `using namespace lgfx` (lgfx::millis/delay ambigus)

// Sprite alias. SANS PSRAM this typedef (vs the M5Canvas subclass, which forces
// _psram=true) makes createSprite() allocate straight in DRAM — preferable here.
typedef lgfx::LGFX_Sprite M5Canvas;

// ---- nav-channel externs (defined in the .ino) + forward decls --------------
extern volatile NavAction     navPendingAction;
extern volatile unsigned long navActionTime;
extern volatile uint8_t       navPendingChar;
extern volatile bool          navPendingCharValid;
void initJoystick();   // defined in awok_input.h
void pollJoystick();   // defined in awok_input.h

// ---- colour name fallbacks --------------------------------------------------
// LovyanGFX normally defines TFT_*; the guards make this safe either way, and
// also cover the bare names (BLACK/WHITE/...) the firmware uses in a few places.
#ifndef TFT_BLACK
#define TFT_BLACK       0x0000
#define TFT_NAVY        0x000F
#define TFT_DARKGREEN   0x03E0
#define TFT_DARKCYAN    0x03EF
#define TFT_MAROON      0x7800
#define TFT_PURPLE      0x780F
#define TFT_OLIVE       0x7BE0
#define TFT_LIGHTGREY   0xD69A
#define TFT_DARKGREY    0x7BEF
#define TFT_BLUE        0x001F
#define TFT_GREEN       0x07E0
#define TFT_CYAN        0x07FF
#define TFT_RED         0xF800
#define TFT_MAGENTA     0xF81F
#define TFT_YELLOW      0xFFE0
#define TFT_WHITE       0xFFFF
#define TFT_ORANGE      0xFDA0
#define TFT_GREENYELLOW 0xB7E0
#define TFT_PINK        0xFE19
#define TFT_SILVER      0xC618
#define TFT_GOLD        0xFEA0
#define TFT_SKYBLUE     0x867D
#define TFT_VIOLET      0x915C
#define TFT_BROWN       0x9A60
#define TFT_DARKGRAY    0x7BEF
#endif
#ifndef BLACK
#define BLACK   TFT_BLACK
#define WHITE   TFT_WHITE
#define RED     TFT_RED
#define GREEN   TFT_GREEN
#define BLUE    TFT_BLUE
#define YELLOW  TFT_YELLOW
#define CYAN    TFT_CYAN
#define MAGENTA TFT_MAGENTA
#endif

// ---- KEY_* sentinels --------------------------------------------------------
// The virtual keyboard pushes these exact codes into navPendingChar and kp()
// compares navPendingChar == key, so values only need to be self-consistent.
// FN / LEFT_CTRL are out of the 0..127 range so they never match a printable.
#ifndef KEY_ENTER
#define KEY_ENTER      13
#endif
#ifndef KEY_BACKSPACE
#define KEY_BACKSPACE  8
#endif
#ifndef KEY_TAB
#define KEY_TAB        9
#endif
#ifndef KEY_DELETE
#define KEY_DELETE     127
#endif
#ifndef KEY_FN
#define KEY_FN         0x81
#endif
#ifndef KEY_LEFT_CTRL
#define KEY_LEFT_CTRL  0x82
#endif

// ---- board identity ---------------------------------------------------------
namespace m5 {
enum board_t : uint8_t {
  board_unknown = 0,
  board_M5Stack, board_M5StackCore2, board_M5StickC, board_M5StickCPlus,
  board_M5StackCoreInk, board_M5Paper, board_M5Tough, board_M5Station,
  board_M5StackCoreS3, board_M5AtomS3, board_M5Cardputer, board_M5CardputerADV,
};
}  // namespace m5
using namespace m5;  // board_t utilisable qualifié (m5::) ET non qualifié

// ---- Speaker (no HP / codec on the display port) ----------------------------
class Speaker_Class {
 public:
  bool begin()                 { return true; }
  void end()                   {}
  bool tone(float, uint32_t = 0)               { return true; }
  bool tone(float, uint32_t, int, bool = true) { return true; }
  void setVolume(uint8_t)      {}
  uint8_t getVolume()          { return 0; }
  void setChannelVolume(uint8_t, uint8_t) {}
  void stop()                  {}
  void stop(int)               {}
  bool isEnabled()             { return false; }
  bool isPlaying()             { return false; }
  void playRaw(const int16_t*, size_t, unsigned int=44100, bool=false, uint8_t=1, uint8_t=0) {}
};

namespace m5 { typedef ::Speaker_Class Speaker_Class; }  // couvre m5::Speaker_Class (L939/971) si guard Audio saute

// ---- Power (no PMIC / fuel gauge here) --------------------------------------
class Power_Class {
 public:
  void begin()                 {}
  int  getBatteryLevel()       { return -1; }
  int  getBatteryCurrent()     { return 0; }
  float getBatteryVoltage()    { return 0.0f; }
  bool isCharging()            { return false; }
  void setLed(uint8_t)         {}
  void powerOff()              {}
  void deepSleep(uint64_t = 0) {}
};

// ---- Keyboard: synthesized from the nav channels ----------------------------
class Keyboard_Class {
 public:
  // Mirrors m5::Keyboard_Class::KeysState. `word` is std::vector<char>; the
  // firmware iterates it and appends to String/char[] buffers.
  struct KeysState {
    bool tab = false, fn = false, shift = false, ctrl = false, opt = false,
         alt = false, del = false, enter = false, space = false;
    std::vector<uint8_t> modifier_keys;
    std::vector<uint8_t> hid_keys;   // stays empty (BT-HID scancodes unavailable)
    std::vector<char>    word;
  };

  void begin()            {}
  void update()           { pollJoystick(); }
  bool isPressed()        { return false; }        // no physical keys; kp() OR-s nav
  bool isKeyPressed(char) { return false; }        // kp() maps nav itself
  bool isChange()         { return navPendingCharValid || navPendingAction != NAV_NONE; }
  bool isChanged()        { return isChange(); }

  // Consumption rules (per verifier): build .word ONLY from navPendingChar
  // 32..126 and consume it; 8/127 -> del, 13 -> enter. From the d-pad consume
  // ONLY NAV_ENTER/NAV_BACK (so kp(';')/kp('.') that follow keysState() in
  // selectBaudMenu still see NAV_UP/NAV_DOWN).
  KeysState keysState() {
    KeysState k;
    if (navPendingCharValid) {
      const uint8_t c = navPendingChar;
      navPendingCharValid = false;
      if      (c == KEY_BACKSPACE || c == KEY_DELETE) k.del   = true;
      else if (c == KEY_ENTER)                        k.enter = true;
      else if (c >= 32 && c < 127) { k.word.push_back((char)c);
                                     if (c == ' ') k.space = true; }
    }
    if (navPendingAction == NAV_ENTER) { k.enter = true; navPendingAction = NAV_NONE; }
    else if (navPendingAction == NAV_BACK) { k.del = true; navPendingAction = NAV_NONE; }
    return k;
  }
};

// ---- M5Unified facade -------------------------------------------------------
// ---- IMU (aucun capteur inertiel sur ce port) -------------------------------
class IMU_Class {
 public:
  bool isEnabled()            { return false; }
  bool getTemp(float* t)      { if (t) *t = 0.0f; return false; }
  bool getGyro(float* x, float* y, float* z)  { if (x)*x=0; if (y)*y=0; if (z)*z=0; return false; }
  bool getAccel(float* x, float* y, float* z) { if (x)*x=0; if (y)*y=0; if (z)*z=0; return false; }
};

struct M5Config {                  // stand-in for m5::M5Unified::config_t
  uint32_t serial_baudrate = 115200;
  bool clear_display   = true;
  bool internal_imu    = false, internal_rtc = false, internal_spk = false,
       internal_mic    = false, external_imu = false, external_rtc = false,
       external_spk    = false, external_display = false;
  uint8_t led_brightness = 0;
  bool output_power    = true;
};

class M5Unified_Shim {
 public:
  AwokLcd&      Display = awokLcd;
  AwokLcd&      Lcd     = awokLcd;
  Speaker_Class Speaker;
  Power_Class   Power;
  IMU_Class     Imu;

  M5Config config() { return M5Config(); }
  void begin() {                    // replaces M5.begin()
#if defined(AWOK_TOUCH_V2)
    awokLcd.initDisplay();          // init ILI9341 + create 128 logical sprite
    awokLcd.fillScreen(0x0000);
    awokLcd.present();
#else
    awokLcd.init();
    awokLcd.setRotation(0);         // 180° via offset_rotation=2 (awok_lgfx.h)
    awokLcd.setBrightness(200);
    awokLcd.fillScreen(0x0000);      // écran noir plein (évite pixels d'allumage)
#endif
    initJoystick();                 // Touch: initialise le pavé tactile (awok_input.h)
  }
  void begin(const M5Config&) { begin(); }
  void update() {
    pollJoystick();                 // Touch: pollJoystick == lecture tactile -> NavAction
#if defined(AWOK_TOUCH_V2)
    awokLcd.presentThrottled();     // blit périodique du sprite -> écran
#endif
  }
  m5::board_t getBoard() { return m5::board_M5Cardputer; }
};

// ---- M5Cardputer facade -----------------------------------------------------
class M5Cardputer_Shim {
 public:
  AwokLcd&       Display = awokLcd;
  Keyboard_Class Keyboard;
  Speaker_Class  Speaker;

  void begin(const M5Config&, bool = true) { initJoystick(); }  // 'true' == kbd -> joystick init
  void begin(bool = true)                  { initJoystick(); }
  void update() {
    pollJoystick();
#if defined(AWOK_TOUCH_V2)
    awokLcd.presentThrottled();
#endif
  }
};

// Global instances (single TU). The real libraries also expose globals `M5` /
// `M5Cardputer`, so the ~5000 M5.Display.* and ~520 kp() sites compile unchanged.
M5Unified_Shim   M5;
M5Cardputer_Shim M5Cardputer;

// ---- Adafruit_NeoPixel no-op stub -------------------------------------------
// PIN 21 (NeoPixel data) collides with GPS RX 21 on this board and there is no
// LED on the display port. Comment the real `#include <Adafruit_NeoPixel.h>`
// (L136) in the .ino; this stub keeps `pixels.*` call sites compiling as no-ops.
#ifndef NEO_GRB
#define NEO_GRB    0x52
#define NEO_KHZ800 0x0000
#endif
class Adafruit_NeoPixel {
 public:
  Adafruit_NeoPixel(uint16_t = 0, int16_t = -1, uint8_t = 0) {}
  void begin() {}
  void show() {}
  void clear() {}
  void setBrightness(uint8_t) {}
  void setPixelColor(uint16_t, uint32_t) {}
  void setPixelColor(uint16_t, uint8_t, uint8_t, uint8_t, uint8_t = 0) {}
  void fill(uint32_t = 0, uint16_t = 0, uint16_t = 0) {}
  uint16_t numPixels() const { return 0; }
  static uint32_t Color(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
  }
};

#include "awok_audio_stub.h"  // stubs ESP8266Audio no-op
#include "awok_usb_stub.h"  // stubs USB HID/MSC no-op (classic ESP32, pas d USB natif)

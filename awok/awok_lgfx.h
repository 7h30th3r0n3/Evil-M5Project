#pragma once
// ============================================================================
// awok_lgfx.h — LovyanGFX device for the AWOK ST7735 128x128 (1.44" green tab).
//
// Aggregates Bus_SPI (shared VSPI) + Panel_ST7735 + Light_PWM (backlight active
// LOW). One global instance `awokLcd`, aliased by the shim as M5.Display /
// M5.Lcd / M5Cardputer.Display. All ~39 screen methods the firmware calls are
// native LovyanGFX (M5GFX is a thin subclass of LovyanGFX): display(), clear(),
// scroll(), setBrightness(), startWrite/endWrite, drawJpgFile, etc.
// ============================================================================
#include "awok_config.h"

// Filesystem headers BEFORE LovyanGFX so its Arduino filesystem mixin
// (lgfx_filesystem_support -> drawJpgFile(fs::FS&, ...)) is compiled INTO
// LGFXBase and LGFX_Sprite. This is the fix for the "no matching function for
// drawJpgFile" gotcha on the bare LGFX_Sprite g_spr (and M5.Display.drawJpgFile(SD,...)).
#include <FS.h>
#include <SD.h>

#define LGFX_USE_V1
#include <LovyanGFX.hpp>

// Global font shrink (both boards draw in 128x128 logical space). Ajuste ici.
#ifndef AWOK_TEXT_SCALE
#define AWOK_TEXT_SCALE 0.6f
#endif

#if defined(AWOK_TOUCH_V2)
// ============================================================================
// ===== AWOK Dual ESP32 Touch v2 : ILI9341 240x320 + XPT2046 (portrait) ======
// Physical device. The firmware never draws to it directly: it draws into the
// 128x128 logical sprite `awokLcd` (below), which up-scales x1.875 into the top
// 240x240 via present(). The bottom 240x80 is the touch control bar.
// ============================================================================
class LGFX_TOUCH : public lgfx::LGFX_Device {
  lgfx::Bus_SPI        _bus;
  lgfx::Panel_ILI9341  _panel;
  lgfx::Light_PWM      _light;
  lgfx::Touch_XPT2046  _touch;
 public:
  LGFX_TOUCH() {
    { // ---- shared VSPI bus ----
      auto c = _bus.config();
#ifdef VSPI_HOST
      c.spi_host = VSPI_HOST;
#else
      c.spi_host = SPI3_HOST;
#endif
      c.spi_mode    = 0;
      c.freq_write  = 40000000;      // ILI9341 supporte 40 MHz
      c.freq_read   = 16000000;
      c.spi_3wire   = false;
      c.use_lock    = true;
      c.dma_channel = SPI_DMA_CH_AUTO;
      c.pin_sclk    = AWOK_SPI_SCK;
      c.pin_mosi    = AWOK_SPI_MOSI;
      c.pin_miso    = AWOK_SPI_MISO;
      c.pin_dc      = AWOK_LCD_DC;
      _bus.config(c);
      _panel.setBus(&_bus);
    }
    { // ---- ILI9341 panel, portrait 240x320 ----
      auto c = _panel.config();
      c.pin_cs          = AWOK_LCD_CS;
      c.pin_rst         = AWOK_LCD_RST;   // -1: reset tied on the Touch v2
      c.pin_busy        = -1;
      c.panel_width     = 240;
      c.panel_height    = 320;
      c.offset_x        = 0;
      c.offset_y        = 0;
      c.offset_rotation = 0;              // BRING-UP: adjust if the image is turned
      c.readable        = true;
      c.invert          = false;         // BRING-UP: flip if colours are inverted
      c.rgb_order       = false;         // BRING-UP: true if red/blue swapped
      c.dlen_16bit      = false;
      c.bus_shared      = true;
      _panel.config(c);
    }
    { // ---- backlight GPIO32, ACTIVE HIGH on the Touch ----
      auto c = _light.config();
      c.pin_bl      = AWOK_LCD_BL;
      c.invert      = AWOK_LCD_BL_INVERT;   // false = active HIGH
      c.freq        = 12000;
      c.pwm_channel = 7;
      _light.config(c);
      _panel.setLight(&_light);
    }
    { // ---- XPT2046 resistive touch (shares the VSPI bus, own CS) ----
      auto c = _touch.config();
      c.bus_shared = true;
      c.spi_host   = _bus.config().spi_host;
      c.pin_sclk   = AWOK_SPI_SCK;
      c.pin_mosi   = AWOK_SPI_MOSI;
      c.pin_miso   = AWOK_SPI_MISO;
      c.pin_cs     = AWOK_TOUCH_CS;
      c.pin_int    = -1;
      c.freq       = 1000000;
      // BRING-UP: raw ADC extents -> panel coords (use awokPanel.calibrateTouch()).
      c.x_min = 300;  c.x_max = 3900;
      c.y_min = 300;  c.y_max = 3900;
      c.offset_rotation = 0;
      _touch.config(c);
      _panel.setTouch(&_touch);
    }
    setPanel(&_panel);
  }
};
// ============================================================================
// AwokLcd (Touch) = the physical ILI9341 device, wrapped so the firmware keeps
// drawing in 128x128 LOGICAL space (all the Mini layout is reused as-is) while
// every primitive is magnified x1.875 and rendered NATIVELY (16-bit, single
// sample -> crisp, no sprite -> 0 extra RAM) into the top 240x240. The bottom
// 240x80 stays free for the touch bar (fillScreen only clears the top 240).
//   scale: 240/128 = 15/8. sc() logical->physical, un() physical->logical.
// ============================================================================
class AwokLcd : public LGFX_TOUCH {
  static inline int32_t sc(int32_t v) { return v * 15 / 8; }
  static inline int32_t un(int32_t v) { return v * 8 / 15; }
  // Same font shrink as the Mini (so the 128 layout's text stays proportional),
  // THEN magnified x1.875 for the native 240 render.
  static int shrink(float s) { int n = (int)(s * AWOK_TEXT_SCALE + 0.5f); return n < 1 ? 1 : n; }
 public:
  bool initDisplay() {
    init();
    LGFX_TOUCH::setRotation(2);              // portrait 240x320, 180° (dalle à l'envers)
    LGFX_TOUCH::setBrightness(200);
    LGFX_TOUCH::fillRect(0, 0, AWOK_PANEL_W, AWOK_PANEL_H, 0);
    return true;
  }
  void present() {}                          // dessin direct: rien à blitter
  void presentThrottled() {}

  // ---- logical geometry: the firmware thinks it draws 128x128 ----
  int32_t width(void)  const { return AWOK_UI_LOGICAL; }   // 128
  int32_t height(void) const { return AWOK_UI_LOGICAL; }   // 128

  // ---- text: position + size scaled; drawing (print/println/printf) flows
  //      through the scaled base cursor & text size, so no need to wrap those.
  using LGFX_TOUCH::setCursor;
  void setCursor(int32_t x, int32_t y) { LGFX_TOUCH::setCursor(sc(x), sc(y)); }
  using LGFX_TOUCH::setTextSize;
  void setTextSize(float s)            { LGFX_TOUCH::setTextSize((float)shrink(s) * 1.875f); }
  void setTextSize(float sx, float sy) { LGFX_TOUCH::setTextSize((float)shrink(sx) * 1.875f, (float)shrink(sy) * 1.875f); }
  // queries returned in LOGICAL units (firmware centres with width()=128)
  int32_t textWidth(const char* s)       { return un(LGFX_TOUCH::textWidth(s)); }
  int32_t textWidth(const String& s)     { return un(LGFX_TOUCH::textWidth(s)); }
  int32_t fontHeight(void)               { return un(LGFX_TOUCH::fontHeight()); }
  int32_t getCursorX(void)               { return un(LGFX_TOUCH::getCursorX()); }
  int32_t getCursorY(void)               { return un(LGFX_TOUCH::getCursorY()); }

  // ---- fills / clears: only the top 240x240 (keep the touch bar) ----
  template<typename T> void fillScreen(const T& c) { LGFX_TOUCH::fillRect(0, 0, AWOK_UI_DRAW_W, AWOK_UI_DRAW_H, c); }
  void clear(void)                                 { LGFX_TOUCH::fillRect(0, 0, AWOK_UI_DRAW_W, AWOK_UI_DRAW_H, 0); }
  template<typename T> void clear(const T& c)      { LGFX_TOUCH::fillRect(0, 0, AWOK_UI_DRAW_W, AWOK_UI_DRAW_H, c); }

  // ---- coordinate primitives: template forwards (handle LGFX's templated
  //      colour arg) with logical->physical scaling. ----
  template<typename T> void fillRect(int32_t x,int32_t y,int32_t w,int32_t h,const T& c){ LGFX_TOUCH::fillRect(sc(x),sc(y),sc(w),sc(h),c); }
  template<typename T> void drawRect(int32_t x,int32_t y,int32_t w,int32_t h,const T& c){ LGFX_TOUCH::drawRect(sc(x),sc(y),sc(w),sc(h),c); }
  template<typename T> void fillRoundRect(int32_t x,int32_t y,int32_t w,int32_t h,int32_t r,const T& c){ LGFX_TOUCH::fillRoundRect(sc(x),sc(y),sc(w),sc(h),sc(r),c); }
  template<typename T> void drawRoundRect(int32_t x,int32_t y,int32_t w,int32_t h,int32_t r,const T& c){ LGFX_TOUCH::drawRoundRect(sc(x),sc(y),sc(w),sc(h),sc(r),c); }
  template<typename T> void fillCircle(int32_t x,int32_t y,int32_t r,const T& c){ LGFX_TOUCH::fillCircle(sc(x),sc(y),sc(r),c); }
  template<typename T> void drawCircle(int32_t x,int32_t y,int32_t r,const T& c){ LGFX_TOUCH::drawCircle(sc(x),sc(y),sc(r),c); }
  template<typename T> void drawPixel(int32_t x,int32_t y,const T& c){ LGFX_TOUCH::fillRect(sc(x),sc(y),(15/8)+1,(15/8)+1,c); }
  template<typename T> void drawLine(int32_t x0,int32_t y0,int32_t x1,int32_t y1,const T& c){ LGFX_TOUCH::drawLine(sc(x0),sc(y0),sc(x1),sc(y1),c); }
  template<typename T> void drawFastHLine(int32_t x,int32_t y,int32_t w,const T& c){ LGFX_TOUCH::fillRect(sc(x),sc(y),sc(w),2,c); }
  template<typename T> void drawFastVLine(int32_t x,int32_t y,int32_t h,const T& c){ LGFX_TOUCH::fillRect(sc(x),sc(y),2,sc(h),c); }
  template<typename T> void fillTriangle(int32_t x0,int32_t y0,int32_t x1,int32_t y1,int32_t x2,int32_t y2,const T& c){ LGFX_TOUCH::fillTriangle(sc(x0),sc(y0),sc(x1),sc(y1),sc(x2),sc(y2),c); }
  void setClipRect(int32_t x,int32_t y,int32_t w,int32_t h){ LGFX_TOUCH::setClipRect(sc(x),sc(y),sc(w),sc(h)); }

  // ---- misc passthroughs ----
  void display(void)             {}          // direct draw
  void setRotation(uint_fast8_t) {}          // fixed at init (portrait 180°); ignore feature calls
  void setRotationRaw(uint_fast8_t r) { LGFX_TOUCH::setRotation(r); }
};
AwokLcd awokLcd;

#else  // ===================== AWOK Mini v2 (ST7735S 128x128) ==================

class LGFX_AWOK : public lgfx::LGFX_Device {
  lgfx::Bus_SPI       _bus;
  lgfx::Panel_ST7735S _panel;   // variant S (dalles 1.44" 128x128 green-tab courantes)
  lgfx::Light_PWM     _light;
 public:
  LGFX_AWOK() {
    { // ---- SPI bus: shared VSPI / SPI3_HOST with the SD card ---------------
      auto c = _bus.config();
#ifdef VSPI_HOST
      c.spi_host  = VSPI_HOST;        // classic ESP32: SPI == VSPI == SPI3_HOST
#else
      c.spi_host  = SPI3_HOST;        // Arduino-ESP32 3.x naming
#endif
      c.spi_mode    = 0;
      c.freq_write  = 20000000;       // 20 MHz (AWOKxDAG reference); raise cautiously
      c.freq_read   = 8000000;
      c.spi_3wire   = false;
      c.use_lock    = true;           // cohabit with the Arduino SD driver
      c.dma_channel = SPI_DMA_CH_AUTO;  // LGFX gère le bus -> DMA activé (config canonique)
      c.pin_sclk    = AWOK_SPI_SCK;
      c.pin_mosi    = AWOK_SPI_MOSI;
      c.pin_miso    = AWOK_SPI_MISO;
      c.pin_dc      = AWOK_LCD_DC;
      _bus.config(c);
      _panel.setBus(&_bus);
    }
    { // ---- ST7735 panel (INITR_144GREENTAB equivalent) ---------------------
      auto c = _panel.config();
      c.pin_cs           = AWOK_LCD_CS;
      c.pin_rst          = AWOK_LCD_RST;
      c.pin_busy         = -1;
      c.memory_width     = 132;       // ST7735 GRAM is 132 x 162
      c.memory_height    = 132;
      c.panel_width      = 128;
      c.panel_height     = 128;
      c.offset_x         = 2;         // INITR_144GREENTAB colstart
      c.offset_y         = 1;         // AWOK 180deg: rowstart miroité (fix 2 lignes bas)
      c.offset_rotation  = 2;         // AWOK: dalle à l'envers -> offset miroité par LovyanGFX (fix 2 lignes bas)
      c.dummy_read_pixel = 8;
      c.dummy_read_bits  = 1;
      c.readable         = false;     // MISO not usable on this panel -> readRect off
      c.invert           = false;     // VERIFY on panel; flip if the image is inverted
      c.rgb_order        = false;     // VERIFY; true if red/blue are swapped
      c.dlen_16bit       = false;
      c.bus_shared       = true;      // release the bus for SD between transactions
      _panel.config(c);
    }
    { // ---- Backlight on GPIO32, ACTIVE LOW ---------------------------------
      auto c = _light.config();
      c.pin_bl      = AWOK_LCD_BL;
      c.invert      = true;           // active LOW: PWM duty is inverted
      c.freq        = 12000;
      c.pwm_channel = 7;
      _light.config(c);
      _panel.setLight(&_light);
    }
    setPanel(&_panel);
  }
};

// Single global device (defined here; these headers are used from one TU).
// Sous-classe: réduit globalement la taille de police (gain rapide pour 128x128,
// SANS framebuffer -> aucun coût RAM, WiFi intact).
class AwokLcd : public LGFX_AWOK {
  // Réduit vers une taille ENTIÈRE >=1 (jamais <1 -> évite les glyphes "mangés"
  // de la police bitmap 6x8). Ex @0.6: 1->1, 1.5->1, 2->1, 3->2.
  static int shrink(float s) { int n = (int)(s * AWOK_TEXT_SCALE + 0.5f); return n < 1 ? 1 : n; }
 public:
  void setTextSize(float s)            { LGFX_AWOK::setTextSize((float)shrink(s)); }
  void setTextSize(float sx, float sy) { LGFX_AWOK::setTextSize((float)shrink(sx), (float)shrink(sy)); }
};
AwokLcd awokLcd;

#endif  // AWOK_TOUCH_V2 / Mini display selection

// ============================================================================
// AwokDisplay — (Mini only, DÉSACTIVÉ) tampon logique 240x135 réduit à 128x128.
// Conservé pour référence; sur Touch v2 awokLcd EST déjà un sprite -> ne pas
// compiler cette classe (elle appelle awokLcd.init(), absent d'un Sprite).
// ============================================================================
#if !defined(AWOK_TOUCH_V2)
class AwokDisplay : public lgfx::LGFX_Sprite {
  unsigned long _lastFlush = 0;
 public:
  AwokDisplay() { setColorDepth(16); }
  bool initDisplay() {
    awokLcd.init();
    awokLcd.setRotation(0);           // 180° géré par offset_rotation=2
    awokLcd.setBrightness(200);
    setPsram(false);                  // pas de PSRAM: allocation DRAM
    if (!createSprite(240, 135)) {    // 64800 octets
      Serial.println("[AWOK] createSprite(240,135) FAILED");
      return false;
    }
    fillScreen(0);
    return true;
  }
  // Down-scale non-uniforme 240x135 -> 128x128 (remplit tout l'écran).
  void flush() {
    pushRotateZoom(&awokLcd, 64.0f, 64.0f, 0.0f, 128.0f / 240.0f, 128.0f / 135.0f);
    _lastFlush = millis();
  }
  void flushThrottled() { if (millis() - _lastFlush >= 25) flush(); }
  // Passe-plats panneau (méthodes absentes de LGFX_Sprite)
  void setBrightness(uint8_t b) { awokLcd.setBrightness(b); }
  uint8_t getBrightness(void)   { return awokLcd.getBrightness(); }
  void setRotation(uint_fast8_t) {}    // le sprite reste 240x135
  void display(void) { flush(); }
};
// AwokDisplay awokScreen;  // désactivé: framebuffer 65KB -> bootloop (pas de PSRAM)
#endif  // !AWOK_TOUCH_V2

// ============================================================================
// awokPushSprite — push a feature's own LGFX_Sprite to the display.
//   Mini : native pushSprite (1:1).
//   Touch: magnify x1.875 onto the 240 panel (so sprite-based screens fill the
//          screen like the direct-drawn ones, instead of a tiny 128 corner).
// The sprite keeps drawing in its native (128-logical) size; only the final
// push is scaled -> reuses every feature's existing rendering unchanged.
// ============================================================================
template<typename S> static inline void awokPushSprite(S& spr, int32_t x, int32_t y) {
#if defined(AWOK_TOUCH_V2)
  const float z = 15.0f / 8.0f;   // 240/128 = 1.875
  spr.pushRotateZoom(&awokLcd, (x + spr.width()  / 2.0f) * z,
                               (y + spr.height() / 2.0f) * z, 0.0f, z, z);
#else
  spr.pushSprite(x, y);
#endif
}

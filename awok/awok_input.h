#pragma once
// ============================================================================
// awok_input.h — 5-way joystick reader + minimal on-screen virtual keyboard.
//
// CONTRACT with the .ino (do NOT redefine these; they live in the sketch, and
// the NavAction enum lives in awok_config.h):
//   volatile NavAction     navPendingAction;    // d-pad channel  (kp() maps it)
//   volatile unsigned long navActionTime;        // millis() of last action
//   volatile uint8_t       navPendingChar;       // raw ASCII channel
//   volatile bool          navPendingCharValid;
//
// pollJoystick() reads the 5 GPIOs (active-LOW, edge + 350/150 ms repeat like
// AWOKxDAG updateMiniJoystick) and pushes navPendingAction. When vkActive is
// set (by getUserInput()/promptInput()), it instead drives the virtual keyboard,
// which pushes navPendingChar. kp()/kpAny()/keysState() (unchanged) consume both.
//
// Include AFTER awok_m5_shim.h (needs KEY_* and the awokLcd device).
// ============================================================================
#include "awok_config.h"
#include "awok_lgfx.h"
#include <cstring>

extern volatile NavAction     navPendingAction;
extern volatile unsigned long navActionTime;
extern volatile uint8_t       navPendingChar;
extern volatile bool          navPendingCharValid;

// Set true by text-entry functions (getUserInput/promptInput) so the joystick
// drives the on-screen keyboard instead of raw menu navigation. See TODOs.
volatile bool vkActive = false;

// ---- joystick button table --------------------------------------------------
namespace awok_joy {
  struct Btn { uint8_t pin; NavAction act; bool repeat; };
  // Priority order; center (ENTER) is edge-only to avoid a double activation.
  // Left  -> NAV_BACK  (menu: back / text: delete)
  // Right -> NAV_PGDOWN(menu: page down)   [NAV_PGUP is not reachable at the
  //                                          joystick; use the virtual keyboard]
  static Btn kBtns[5] = {
    { AWOK_JOY_UP,     NAV_UP,     true  },
    { AWOK_JOY_DOWN,   NAV_DOWN,   true  },
    { AWOK_JOY_LEFT,   NAV_BACK,   true  },
    { AWOK_JOY_RIGHT,  NAV_PGDOWN, true  },
    { AWOK_JOY_CENTER, NAV_ENTER,  false },
  };
}

#if defined(AWOK_TOUCH_V2)
// awokLcd IS the physical device but its draw calls are SCALED (128->240 logical
// wrapper). The touch bar + getTouch must use PHYSICAL 240x320 coords, so alias
// the base type: calls through this reference use the unscaled LGFX_TOUCH methods.
LGFX_TOUCH& awokPanel = awokLcd;
// ---- Touch control bar (bottom 240x80) --------------------------------------
// 5 zones map to the SAME kBtns[] indices as the joystick, so pollJoystick() and
// updateVirtualKeyboard() reuse all their repeat / virtual-keyboard logic.
// Screen columns -> kBtns index:  BACK, UP, OK, DOWN, PGDN.
// D-pad "joystick" layout in the bottom bar (240x80):
//   top third   = UP (▲)      -> kBtns[0]
//   bottom third= DOWN (▼)    -> kBtns[1]
//   middle: left = BACK (◄)   -> kBtns[2]
//           center= OK (●)    -> kBtns[4]
//           right= PGDN (►)   -> kBtns[3]
// Touch axis correction: panel is setRotation(2); only Y needs flipping (the
// XPT2046 is mounted mirrored in Y), X already matches the display.
namespace awok_touch {
  // Axis flips are now handled by the stored touch calibration (calibrateTouch
  // at first boot), so both are false. Kept as an escape hatch if calibration
  // is unavailable (no SD) and an axis still reads inverted.
  static const bool kFlipX = false;
  static const bool kFlipY = false;
}
// First-boot touch calibration (LovyanGFX). Persisted to SD so it runs once.
// calibrateTouch() draws corner targets, the user taps them, and the resulting
// transform is applied + saved. On later boots it is just re-loaded.
void awokTouchCalibrate() {
  const char* CAL = "/evil/touch_cal.dat";
  uint16_t p[8];
  if (SD.exists(CAL)) {
    File f = SD.open(CAL);
    if (f && f.read((uint8_t*)p, sizeof(p)) == (int)sizeof(p)) {
      awokPanel.setTouchCalibrate(p);
      f.close();
      return;
    }
    if (f) f.close();
  }
  // First boot (or no saved data): interactive calibration.
  awokPanel.fillScreen(TFT_BLACK);
  awokPanel.setTextColor(TFT_WHITE, TFT_BLACK);
  awokPanel.setTextSize(1);
  awokPanel.setCursor(10, AWOK_PANEL_H / 2 - 20);
  awokPanel.print("Touch calibration:");
  awokPanel.setCursor(10, AWOK_PANEL_H / 2 - 6);
  awokPanel.print("tap each corner target");
  awokPanel.calibrateTouch(p, TFT_GREEN, TFT_BLACK, 22);
  File f = SD.open(CAL, FILE_WRITE);
  if (f) { f.write((const uint8_t*)p, sizeof(p)); f.close(); }
}
// Layout: LEFT = a 4-way directional pad (whole zone is directional, split into
// 4 triangles by dominant axis -> no dead spots). RIGHT = one big OK button.
//   ▲=UP(0)  ▼=DOWN(1)  ◄=LEFT/BACK(2)  ►=RIGHT/PGDN(3)  OK=ENTER(4)
static const int AWOK_TB_DPAD_W = 130;                     // dpad width; rest = OK
void drawTouchBar() {
  const int y0 = AWOK_TOUCHBAR_Y, h = AWOK_TOUCHBAR_H, W = AWOK_PANEL_W;
  const int dw = AWOK_TB_DPAD_W;
  const int cx = dw / 2, cy = y0 + h / 2;
  awokPanel.fillRect(0, y0, W, h, TFT_BLACK);
  awokPanel.drawFastHLine(0, y0, W, TFT_DARKGREY);
  awokPanel.drawFastVLine(dw, y0, h, TFT_DARKGREY);
  const uint16_t A = TFT_CYAN, G = 0x39C7;
  // diagonal guides showing the 4 triangular regions (= the real hitboxes)
  awokPanel.drawLine(0, y0, dw, y0 + h, G);
  awokPanel.drawLine(0, y0 + h, dw, y0, G);
  // big arrows filling each triangular quadrant (visual == hitbox)
  awokPanel.fillTriangle(cx, y0 + 6,      cx - 26, cy - 9, cx + 26, cy - 9, A); // ▲
  awokPanel.fillTriangle(cx, y0 + h - 6,  cx - 26, cy + 9, cx + 26, cy + 9, A); // ▼
  awokPanel.fillTriangle(7, cy,           34, cy - 24,     34, cy + 24,     A); // ◄
  awokPanel.fillTriangle(dw - 7, cy,      dw - 34, cy - 24, dw - 34, cy + 24, A); // ►
  // big OK button (right)
  const int okx = dw, okw = W - dw;
  awokPanel.drawRoundRect(okx + 6, y0 + 8, okw - 12, h - 16, 6, TFT_GREEN);
  awokPanel.setTextSize(3); awokPanel.setTextColor(TFT_GREEN, TFT_BLACK);
  int tw = awokPanel.textWidth("OK");
  awokPanel.setCursor(okx + (okw - tw) / 2, cy - 10); awokPanel.print("OK");
}
// Returns the pressed kBtns index (0-4) or -1, from the touch bar.
int awokTouchButton() {
  int32_t x, y;
  if (!awokPanel.getTouch(&x, &y)) return -1;
  if (awok_touch::kFlipX) x = AWOK_PANEL_W - 1 - x;
  if (awok_touch::kFlipY) y = AWOK_PANEL_H - 1 - y;
  if (y < AWOK_TOUCHBAR_Y) return -1;             // top 240 = display, ignore
  const int h = AWOK_TOUCHBAR_H, dw = AWOK_TB_DPAD_W;
  if (x >= dw) return 4;                          // OK / ENTER
  // directional pad: dominant axis from the zone centre (aspect-normalised)
  int dx = x - dw / 2;
  int dy = (y - AWOK_TOUCHBAR_Y) - h / 2;
  if (abs(dx) * h > abs(dy) * dw) return (dx < 0) ? 2 /*BACK*/ : 3 /*PGDN*/;
  return (dy < 0) ? 0 /*UP*/ : 1 /*DOWN*/;
}
static inline int awokActiveButton() { return awokTouchButton(); }

void initJoystick() {
  drawTouchBar();     // touch controller is initialised by the panel (setTouch)
}
#else
static inline int awokActiveButton() {
  for (int i = 0; i < 5; ++i)
    if (digitalRead(awok_joy::kBtns[i].pin) == LOW) return i;
  return -1;
}
void initJoystick() {
  // GPIO13 has an internal pull-up; 34/35/36/39 are input-only (PCB pull-ups).
  pinMode(AWOK_JOY_LEFT,   INPUT_PULLUP);
  pinMode(AWOK_JOY_CENTER, INPUT);
  pinMode(AWOK_JOY_UP,     INPUT);
  pinMode(AWOK_JOY_RIGHT,  INPUT);
  pinMode(AWOK_JOY_DOWN,   INPUT);
}
#endif

// ---- virtual keyboard state --------------------------------------------------
namespace awok_vk {
  // 43 printable cells, then 3 special cells (CAPS toggle / DEL / ENTER).
  static const char* kBase = "abcdefghijklmnopqrstuvwxyz0123456789.,:;/@-_!#$%&*()+=? ";
  static const int   kCols = 11;
  enum { SP_CAPS = 0, SP_DEL, SP_ENT, SP_OK, SP_DELK, SP_COUNT };  // +OK +DEL
  static int  cursor = 0;
  static bool caps   = false;

  static inline int baseLen() { return (int)strlen(kBase); }
  static inline int total()   { return baseLen() + SP_COUNT; }
  static inline int rows()    { return (total() + kCols - 1) / kCols; }
}

// Draw the grid along the bottom of the screen. Call EACH FRAME from the text
// function (getUserInput/promptInput), because those clear() the screen every
// iteration — a grid drawn only from pollJoystick would be erased.
void drawVirtualKeyboard() {
  using namespace awok_vk;
  const int cw = awokLcd.width() / kCols;             // ~11 px per cell
  const int ch = 11;
  const int y0 = awokLcd.height() - rows() * ch;
  awokLcd.fillRect(0, y0 - 1, awokLcd.width(), rows() * ch + 1, TFT_BLACK);
  awokLcd.setTextSize(1);
  awokLcd.setTextFont(1);
  for (int i = 0; i < total(); ++i) {
    const int cx = (i % kCols) * cw;
    const int cy = y0 + (i / kCols) * ch;
    const bool sel = (i == cursor);
    if (sel) awokLcd.fillRect(cx, cy, cw, ch, TFT_BLUE);
    awokLcd.setTextColor(sel ? TFT_WHITE : TFT_GREEN);
    awokLcd.setCursor(cx + 2, cy + 2);
    if (i < baseLen()) {
      char c = kBase[i];
      if (caps && c >= 'a' && c <= 'z') c -= 32;
      awokLcd.print(c);
    } else {
      switch (i - baseLen()) {
        case SP_CAPS: awokLcd.print(caps ? 'A' : 'a'); break;  // case toggle
        case SP_DEL:  awokLcd.print('<');              break;  // backspace
        case SP_ENT:  awokLcd.print('>');              break;  // enter
        case SP_OK:   awokLcd.print("OK");             break;  // valider
        case SP_DELK: awokLcd.print("DEL");            break;  // supprimer
      }
    }
  }
}

// Joystick-driven cursor moves + selection while vkActive. Directions move the
// grid cursor (navPendingAction is NOT posted); center emits navPendingChar.
// Emit the key currently under awok_vk::cursor (shared by tap + d-pad select).
static inline void awokVkEmitCursor() {
  using namespace awok_vk;
  if (cursor < baseLen()) {
    char c = kBase[cursor];
    if (caps && c >= 'a' && c <= 'z') c -= 32;
    navPendingChar = (uint8_t)c; navPendingCharValid = true;
  } else {
    switch (cursor - baseLen()) {
      case SP_CAPS: caps = !caps; break;
      case SP_DEL:  navPendingChar = KEY_BACKSPACE; navPendingCharValid = true; break;
      case SP_ENT:  navPendingChar = KEY_ENTER;     navPendingCharValid = true; break;
      case SP_OK:   navPendingChar = KEY_ENTER;     navPendingCharValid = true; break;
      case SP_DELK: navPendingChar = KEY_BACKSPACE; navPendingCharValid = true; break;
    }
  }
  navActionTime = millis();
}

void updateVirtualKeyboard() {
  using namespace awok_vk;
#if defined(AWOK_TOUCH_V2)
  // TOUCH: tap a key directly (no d-pad). Map the on-screen keyboard (drawn in
  // the 128 logical canvas, blitted x1.875 into the top 240x240) back to a cell.
  {
    static bool wasDown = false;
    int32_t tx, ty;
    bool down = awokPanel.getTouch(&tx, &ty);
    if (down) {
      if (awok_touch::kFlipX) tx = AWOK_PANEL_W - 1 - tx;
      if (awok_touch::kFlipY) ty = AWOK_PANEL_H - 1 - ty;
      if (ty >= AWOK_TOUCHBAR_Y) {
        // Bottom D-pad still active during input: OK validates the whole input,
        // arrows move the on-screen keyboard cursor (alternative to tapping).
        if (!wasDown) {
          switch (awokTouchButton()) {
            case 0: cursor = (cursor - kCols + total()) % total(); break;   // UP
            case 1: cursor = (cursor + kCols) % total();           break;   // DOWN
            case 2: cursor = (cursor - 1 + total()) % total();     break;   // LEFT
            case 3: cursor = (cursor + 1) % total();               break;   // RIGHT
            case 4: navPendingChar = KEY_ENTER; navPendingCharValid = true; // OK -> submit
                    navActionTime = millis(); break;
          }
        }
      } else {
        // keyboard area: tap a key directly
        const float z = (float)AWOK_UI_DRAW_W / (float)AWOK_UI_LOGICAL;   // 1.875
        const int lx = (int)(tx / z), ly = (int)(ty / z);                // -> 128 space
        const int cw = awokLcd.width() / kCols, ch = 11;
        const int y0 = awokLcd.height() - rows() * ch;
        if (ly >= y0 && lx >= 0 && lx < awokLcd.width()) {
          const int col = lx / cw, row = (ly - y0) / ch, i = row * kCols + col;
          if (col >= 0 && col < kCols && i >= 0 && i < total()) {
            cursor = i;
            if (!wasDown) awokVkEmitCursor();   // fire once per tap (edge)
          }
        }
      }
    }
    wasDown = down;
    drawVirtualKeyboard();
    return;
  }
#endif
  static uint32_t nextRepeat = 0;
  static int lastBtn = -1;
  const uint32_t now = millis();

  int active = awokActiveButton();
  if (active < 0) { lastBtn = -1; return; }

  const bool first  = (active != lastBtn);
  const bool center = (awok_joy::kBtns[active].act == NAV_ENTER);
  if (!(first || (!center && (int32_t)(now - nextRepeat) >= 0))) return;
  nextRepeat = now + (first ? 350 : 150);
  lastBtn = active;

  switch (awok_joy::kBtns[active].act) {
    case NAV_UP:     cursor = (cursor - kCols + total()) % total(); break;
    case NAV_DOWN:   cursor = (cursor + kCols) % total();           break;
    case NAV_BACK:   cursor = (cursor - 1 + total()) % total();     break; // left
    case NAV_PGDOWN: cursor = (cursor + 1) % total();               break; // right
    case NAV_ENTER: awokVkEmitCursor(); break;    // select
    default: break;
  }
  drawVirtualKeyboard();
}

// ---- main poll: call from cardUpdate()/M5.update()/M5Cardputer.update() -----
void pollJoystick() {
  if (vkActive) { updateVirtualKeyboard(); return; }

  static uint32_t nextRepeat = 0;
  static int lastBtn = -1;
  const uint32_t now = millis();

  int active = awokActiveButton();
  if (active < 0) { lastBtn = -1; return; }

  const bool first  = (active != lastBtn);
  const bool center = !awok_joy::kBtns[active].repeat;   // center: edge-only
  if (first || (!center && (int32_t)(now - nextRepeat) >= 0)) {
    navPendingAction = awok_joy::kBtns[active].act;
    navActionTime    = now;
    nextRepeat = now + (first ? 350 : 150);
    lastBtn = active;
  }
}

// AWOK: à l'entrée d'une saisie, attendre le relâchement du joystick et vider
// les événements en attente -> évite le caractère parasite ('a') dû à l'appui
// Centre de la sélection du menu qui déborde dans le clavier virtuel.
void vkEnterDebounce() {
  const uint32_t t0 = millis();
  while (millis() - t0 < 600) {
    if (awokActiveButton() < 0) break;
    delay(10);
  }
  delay(120);
  navPendingChar = 0; navPendingCharValid = false; navPendingAction = NAV_NONE;
}

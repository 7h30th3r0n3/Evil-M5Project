#pragma once
// ============================================================================
//  IR remote module for Evil-Cardputer
// ----------------------------------------------------------------------------
//  38 kHz infrared transmit on the Cardputer's built-in IR LED (GPIO 44), using
//  an LEDC carrier that is keyed on/off for each mark/space (the same pin and
//  approach proven by the TagTinker ESL code, but at a standard remote carrier).
//
//  Capabilities (TX only):
//    - Protocol encoders: NEC, NEC extended, Samsung32, Sony SIRC (12/15/20),
//      RC5, and arbitrary raw microsecond timing arrays.
//    - Flipper `.ir` file playback from the SD card (/evil/ir): both `type: raw`
//      (frequency + timing list) and `type: parsed` (protocol + address/command).
//    - Universal power blast (TV-B-Gone style) from a small embedded code table.
//    - Dazzler: continuous 38 kHz flood (disrupts IR receivers in range).
//
//  NOTE: the Cardputer has no onboard IR *receiver*, so capture/learn is not
//  possible here. A learn mode would need an external IR demodulator wired to a
//  Grove pin; that is intentionally left out of this module.
// ============================================================================

namespace irr {

#define IR_PIN        44          // Cardputer built-in IR LED
#define IR_CARRIER_HZ 38000       // default carrier
#define IR_GPIO_BIT   (1UL << (IR_PIN - 32))   // GPIO44 lives in the out1 bank (same as TagTinker)

static bool     ir_initialized   = false;
static bool     ir_stop_req      = false;
static uint32_t ir_cur_freq      = IR_CARRIER_HZ;
static uint32_t ir_half_us       = 13;         // half carrier period in us (38kHz ~ 13us)

// ---- low-level carrier keying: DIRECT GPIO bit-bang on GPIO44 --------------
// (LEDC does not reliably drive the Cardputer IR LED; TagTinker proves the
//  direct out1 register bit-bang radiates, so the carrier is generated the
//  same way here: a "mark" toggles GPIO44 at the carrier rate, a "space" holds low.)
inline void ir_gpio_hi() { GPIO.out1_w1ts.val = IR_GPIO_BIT; }
inline void ir_gpio_lo() { GPIO.out1_w1tc.val = IR_GPIO_BIT; }

inline void ir_set_freq(uint32_t hz) {
    if (hz < 30000 || hz > 56000) hz = IR_CARRIER_HZ;
    ir_cur_freq = hz;
    ir_half_us = 500000UL / hz;                // half period (us)
    if (ir_half_us < 1) ir_half_us = 1;
}
inline void ir_begin(uint32_t hz = IR_CARRIER_HZ) {
    pinMode(IR_PIN, OUTPUT);
    ir_gpio_lo();
    ir_set_freq(hz);
    ir_initialized = true;
    ir_stop_req    = false;
}
inline void ir_end() {
    ir_gpio_lo();
    pinMode(IR_PIN, OUTPUT);
    digitalWrite(IR_PIN, LOW);
    ir_initialized = false;
}
inline void ir_mark(uint32_t us) {             // modulated carrier for `us` microseconds
    uint32_t period = ir_half_us * 2;
    uint32_t cycles = (us + period / 2) / period;
    for (uint32_t i = 0; i < cycles; i++) {
        ir_gpio_hi(); delayMicroseconds(ir_half_us);
        ir_gpio_lo(); delayMicroseconds(ir_half_us);
    }
}
inline void ir_space(uint32_t us) {            // carrier off (idle low)
    ir_gpio_lo();
    while (us > 16000) { delayMicroseconds(16000); us -= 16000; }
    if (us) delayMicroseconds(us);
}

// ---- raw: alternating mark/space in microseconds, starting with a mark -----
inline void ir_send_raw(const uint16_t* t, size_t n) {
    for (size_t i = 0; i < n; i++) { if (i & 1) ir_space(t[i]); else ir_mark(t[i]); }
    ir_space(0);
}

// ---- NEC (and NEC extended) ------------------------------------------------
// 9 ms lead mark, 4.5 ms space, 32 data bits LSB-first, bit = 560us mark then
// 560us (0) / 1690us (1) space, trailing 560us mark.
inline void ir_send_nec32(uint32_t data) {
    ir_mark(9000); ir_space(4500);
    for (int i = 0; i < 32; i++) { ir_mark(560); ir_space((data & 1) ? 1690 : 560); data >>= 1; }
    ir_mark(560); ir_space(0);
}
inline void ir_send_nec(uint8_t addr, uint8_t cmd) {        // classic 8-bit NEC
    uint32_t d = (uint32_t)addr
               | ((uint32_t)(uint8_t)(~addr) << 8)
               | ((uint32_t)cmd  << 16)
               | ((uint32_t)(uint8_t)(~cmd) << 24);
    ir_send_nec32(d);
}
inline void ir_send_necext(uint16_t addr, uint16_t cmd) {   // NECext: 16-bit addr, cmd+~cmd
    uint32_t d = (uint32_t)(addr & 0xFF)
               | ((uint32_t)((addr >> 8) & 0xFF) << 8)
               | ((uint32_t)(cmd & 0xFF) << 16)
               | ((uint32_t)(uint8_t)(~(cmd & 0xFF)) << 24);
    ir_send_nec32(d);
}

// ---- Samsung32 -------------------------------------------------------------
// Like NEC but 4.5 ms lead mark + 4.5 ms space, 32 bits = addr, addr, cmd, ~cmd.
inline void ir_send_samsung32(uint8_t addr, uint8_t cmd) {
    uint32_t data = (uint32_t)addr | ((uint32_t)addr << 8)
                  | ((uint32_t)cmd << 16) | ((uint32_t)(uint8_t)(~cmd) << 24);
    ir_mark(4500); ir_space(4500);
    for (int i = 0; i < 32; i++) { ir_mark(560); ir_space((data & 1) ? 1690 : 560); data >>= 1; }
    ir_mark(560); ir_space(0);
}

// ---- Sony SIRC (12/15/20 bit), LSB-first, 40 kHz normally -----------------
inline void ir_send_sirc_bits(uint32_t data, int bits) {
    ir_mark(2400); ir_space(600);
    for (int i = 0; i < bits; i++) { ir_mark((data & 1) ? 1200 : 600); ir_space(600); data >>= 1; }
    ir_space(0);
}
inline void ir_send_sirc(uint8_t cmd, uint16_t addr, int bits = 12) {
    uint32_t data;
    if (bits == 20)      data = (uint32_t)(cmd & 0x7F) | ((uint32_t)(addr & 0x1FFF) << 7);
    else if (bits == 15) data = (uint32_t)(cmd & 0x7F) | ((uint32_t)(addr & 0xFF) << 7);
    else { bits = 12;    data = (uint32_t)(cmd & 0x7F) | ((uint32_t)(addr & 0x1F) << 7); }
    ir_send_sirc_bits(data, bits);
}

// ---- RC5 (14 bits, Manchester, 889us half-bit) -----------------------------
inline void ir_rc5_halfbit(bool level, uint32_t us) { if (level) ir_mark(us); else ir_space(us); }
inline void ir_send_rc5(uint8_t addr, uint8_t cmd, bool toggle = false) {
    // bits MSB-first: S1=1, S2=1, toggle, 5 addr, 6 cmd. Manchester: 0 => mark->space, 1 => space->mark
    uint16_t frame = (1 << 13) | (1 << 12) | ((toggle ? 1 : 0) << 11)
                   | ((addr & 0x1F) << 6) | (cmd & 0x3F);
    for (int i = 13; i >= 0; i--) {
        bool bit = (frame >> i) & 1;
        if (bit) { ir_space(889); ir_mark(889); } else { ir_mark(889); ir_space(889); }
    }
    ir_space(0);
}

// ---- NEC42 (42-bit NEC variant): addr(13) + ~addr(13) + cmd(8) + ~cmd(8) ---
inline void ir_send_nec42(uint16_t addr, uint8_t cmd) {
    uint16_t a = addr & 0x1FFF;
    ir_mark(9000); ir_space(4500);
    auto bits = [&](uint32_t v, int n) { for (int k = 0; k < n; k++) { ir_mark(560); ir_space(((v >> k) & 1) ? 1690 : 560); } };
    bits(a, 13); bits((~a) & 0x1FFF, 13); bits(cmd, 8); bits((uint8_t)(~cmd), 8);
    ir_mark(560); ir_space(0);
}

// ---- RCA: 24 bits = 12 data (A4|C8) MSB-first, then complement ------------
inline void ir_send_rca(uint8_t addr, uint8_t cmd) {
    uint16_t val = ((uint16_t)(addr & 0x0F) << 8) | cmd;   // 12 data bits
    ir_mark(4000); ir_space(4000);
    for (int i = 11; i >= 0; i--) { ir_mark(500); ir_space(((val >> i) & 1) ? 2000 : 1000); }
    for (int i = 11; i >= 0; i--) { ir_mark(500); ir_space((((~val) >> i) & 1) ? 2000 : 1000); }
    ir_mark(500); ir_space(0);
}

// ---- Kaseikyo / Panasonic: 48-bit, vendor 0x2002 + addr + cmd + checksum ---
inline void ir_send_kaseikyo(uint16_t addr, uint8_t cmd) {
    uint8_t d[6] = { 0x02, 0x20, (uint8_t)(addr & 0xFF), (uint8_t)((addr >> 8) & 0xFF), cmd, 0 };
    d[5] = d[0] ^ d[1] ^ d[2] ^ d[3] ^ d[4];
    ir_mark(3456); ir_space(1728);
    for (int i = 0; i < 6; i++) for (int k = 0; k < 8; k++) { ir_mark(432); ir_space(((d[i] >> k) & 1) ? 1296 : 432); }
    ir_mark(432); ir_space(0);
}

// ---- RC6 mode 0 (36 kHz): leader, start=1, mode 000, toggle(2x), 8 addr+8 cmd
inline void ir_send_rc6(uint8_t addr, uint8_t cmd) {
    const uint32_t u = 444;
    ir_mark(2666); ir_space(889);                 // leader
    auto mbit = [&](int b, uint32_t unit) { if (b) { ir_mark(unit); ir_space(unit); } else { ir_space(unit); ir_mark(unit); } };
    mbit(1, u);                                    // start bit (always 1)
    for (int i = 0; i < 3; i++) mbit(0, u);        // mode 000
    mbit(0, u * 2);                                // toggle bit (double width)
    for (int i = 7; i >= 0; i--) mbit((addr >> i) & 1, u);
    for (int i = 7; i >= 0; i--) mbit((cmd >> i) & 1, u);
    ir_space(0);
}

// ---- Centralized parsed-signal emitter (picks carrier per protocol) --------
// Returns false for an unsupported protocol (nothing sent).
inline bool ir_emit_parsed(const String& proto, uint16_t addr, uint16_t cmd) {
    uint32_t f = (proto == "SIRC" || proto == "SIRC15" || proto == "SIRC20" || proto == "Pioneer") ? 40000
               : (proto == "RC5" || proto == "RC5X" || proto == "RC6") ? 36000 : 38000;
    ir_begin(f);
    bool ok = true;
    if      (proto == "NEC")       ir_send_nec((uint8_t)addr, (uint8_t)cmd);
    else if (proto == "NECext")    ir_send_necext(addr, cmd);
    else if (proto == "NEC42")     ir_send_nec42(addr, (uint8_t)cmd);
    else if (proto == "Pioneer")   ir_send_nec((uint8_t)addr, (uint8_t)cmd);
    else if (proto == "Samsung32") ir_send_samsung32((uint8_t)addr, (uint8_t)cmd);
    else if (proto == "SIRC")      ir_send_sirc((uint8_t)cmd, addr, 12);
    else if (proto == "SIRC15")    ir_send_sirc((uint8_t)cmd, addr, 15);
    else if (proto == "SIRC20")    ir_send_sirc((uint8_t)cmd, addr, 20);
    else if (proto == "RC5" || proto == "RC5X") ir_send_rc5((uint8_t)addr, (uint8_t)cmd);
    else if (proto == "RC6")       ir_send_rc6((uint8_t)addr, (uint8_t)cmd);
    else if (proto == "Kaseikyo")  ir_send_kaseikyo(addr, (uint8_t)cmd);
    else if (proto == "RCA")       ir_send_rca((uint8_t)addr, (uint8_t)cmd);
    else ok = false;
    ir_end();
    return ok;
}

// ---- Universal power blast (compact TV-B-Gone-style set) -------------------
// A handful of the most common TV power codes across vendors. Not exhaustive,
// but enough to turn off a large share of sets in range.
inline void ir_power_blast() {
    // NEC-family power codes (addr, cmd)
    static const uint8_t nec_pwr[][2] = {
        {0x00,0x02},{0x04,0x08},{0x40,0x12},{0x00,0x0C},{0x20,0x10},
        {0x08,0x02},{0x70,0x13},{0x01,0xA8},{0x02,0xFD},{0x00,0x08},
    };
    // Samsung32 power
    static const uint8_t sam_pwr[][2] = { {0x07,0x02},{0x07,0x99} };
    // Sony SIRC power (cmd 21 / addr 1), 12/15/20 bit variants
    ir_begin(38000);
    for (auto& p : nec_pwr) { if (ir_stop_req) break; ir_send_nec(p[0], p[1]); delay(40); }
    for (auto& p : sam_pwr) { if (ir_stop_req) break; ir_send_samsung32(p[0], p[1]); delay(40); }
    ir_set_freq(40000);
    for (int b = 0; b < 1 && !ir_stop_req; b++) {
        ir_send_sirc(21, 1, 12); delay(40);
        ir_send_sirc(21, 1, 15); delay(40);
        ir_send_sirc(21, 26, 20); delay(40);
    }
    ir_end();
}

// ---- Dazzler: continuous 38 kHz flood -------------------------------------
inline void ir_dazzle(uint32_t ms) {
    ir_begin(38000);
    uint32_t start = millis();
    while (millis() - start < ms && !ir_stop_req) {
        ir_mark(600); ir_space(600);     // ~833 Hz envelope on a 38 kHz carrier
    }
    ir_end();
}

// ============================================================================
//  Flipper `.ir` file playback (SD: /evil/ir)
// ============================================================================
#define IR_DIR "/evil/ir"

static uint8_t ir_hex_first(const String& s) {         // first hex byte of "02 00 00 00"
    String t = s; t.trim();
    int sp = t.indexOf(' '); if (sp > 0) t = t.substring(0, sp);
    return (uint8_t)strtol(t.c_str(), nullptr, 16);
}
static uint16_t ir_hex_word_le(const String& s) {      // first two hex bytes, little-endian
    String t = s; t.trim();
    uint8_t b0 = 0, b1 = 0; int sp = t.indexOf(' ');
    b0 = (uint8_t)strtol((sp > 0 ? t.substring(0, sp) : t).c_str(), nullptr, 16);
    if (sp > 0) { String r = t.substring(sp + 1); r.trim(); int s2 = r.indexOf(' ');
        b1 = (uint8_t)strtol((s2 > 0 ? r.substring(0, s2) : r).c_str(), nullptr, 16); }
    return (uint16_t)b0 | ((uint16_t)b1 << 8);
}

// Count/collect the signal names (`name:` lines) in a .ir file.
inline int ir_list_signals(const char* path, std::vector<String>& names, int limit = 64) {
    names.clear();
    File f = SD.open(path); if (!f) return 0;
    while (f.available() && (int)names.size() < limit) {
        String line = f.readStringUntil('\n');
        if (line.startsWith("name:")) { String n = line.substring(5); n.trim(); names.push_back(n); }
    }
    f.close();
    return (int)names.size();
}

// Send the idx-th signal of a .ir file once. Returns false if not found/unsupported.
inline bool ir_send_file_signal(const char* path, int idx) {
    File f = SD.open(path); if (!f) return false;
    int cur = -1; bool ok = false;
    String proto; String type; uint32_t freq = 38000;
    uint16_t addr = 0, cmd = 0; bool haveA = false, haveC = false;
    // raw accumulation (local: no boot/static RAM)
    uint16_t raw[512]; size_t rawN = 0;
    auto flush_send = [&]() {
        if (cur != idx) return;
        if (type == "raw" && rawN > 0) { ir_begin(freq); ir_send_raw(raw, rawN); ir_end(); ok = true; }
        else if (type == "parsed") { ok = ir_emit_parsed(proto, addr, cmd); }
    };
    while (f.available()) {
        String line = f.readStringUntil('\n'); line.trim();
        if (line.startsWith("name:")) {
            if (cur == idx) { flush_send(); break; }       // we just finished the target signal
            cur++; type = ""; proto = ""; freq = 38000; rawN = 0; haveA = haveC = false;
        } else if (cur == idx) {
            if      (line.startsWith("type:"))      { type = line.substring(5); type.trim(); }
            else if (line.startsWith("protocol:"))  { proto = line.substring(9); proto.trim(); }
            else if (line.startsWith("frequency:")) { freq = (uint32_t)line.substring(10).toInt(); }
            else if (line.startsWith("address:"))   { addr = ir_hex_word_le(line.substring(8)); haveA = true; }
            else if (line.startsWith("command:"))   { cmd  = ir_hex_word_le(line.substring(8)); haveC = true; }
            else if (line.startsWith("data:")) {
                String d = line.substring(5); d.trim(); int p = 0;
                while (p < (int)d.length() && rawN < (sizeof(raw)/sizeof(raw[0]))) {
                    while (p < (int)d.length() && d[p] == ' ') p++;
                    int q = d.indexOf(' ', p); if (q < 0) q = d.length();
                    if (q > p) raw[rawN++] = (uint16_t)d.substring(p, q).toInt();
                    p = q + 1;
                }
            }
        }
    }
    if (cur == idx && !ok) flush_send();                   // last signal in file (EOF, no trailing name:)
    f.close();
    (void)haveA; (void)haveC;
    return ok;
}

// ============================================================================
//  On-device UI
// ============================================================================
static void ir_header(const char* title) {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841);
    M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(TFT_GREEN, 0x0841);
    int tw = (int)(strlen(title) * 9); int tx = (M5.Display.width() - tw) / 2; if (tx < 0) tx = 0;
    M5.Display.setCursor(tx, 0); M5.Display.println(title);
}
static void ir_msg(const char* title, const char* l1, uint16_t c1, const char* l2) {
    ir_header(title);
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(c1, TFT_BLACK); M5.Display.setCursor(6, 40); M5.Display.println(l1);
    if (l2) { M5.Display.setTextColor(0x5AEB, TFT_BLACK); M5.Display.setCursor(6, 64); M5.Display.println(l2); }
    M5.Display.display();
}
static void ir_wait_key() {
    enterDebounce();
    while (true) { M5.update(); cardUpdate(); if (kp(KEY_ENTER) || kp(KEY_BACKSPACE)) { keyRelease(); return; } delay(12); }
}
static int ir_pick(const char* title, const std::vector<String>& items, const char* empty) {
    if (items.empty()) { ir_msg(title, empty ? empty : "nothing here", TFT_ORANGE, nullptr); ir_wait_key(); return -1; }
    int sel = 0, top = 0; const int rowH = 17, headerY = 18, vis = 6; bool rd = true;
    enterDebounce();
    while (true) {
        if (rd) {
            ir_header(title); M5.Display.setTextSize(1.5);
            for (int i = 0; i < vis && top + i < (int)items.size(); i++) {
                int idx = top + i; int y = headerY + i * rowH;
                if (idx == sel) { M5.Display.fillRect(0, y, M5.Display.width(), rowH, menuSelectedBackgroundColor); M5.Display.setTextColor(menuTextFocusedColor); }
                else M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(6, y + 1); M5.Display.println(items[idx]);
            }
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return -1; }
        if (kp(KEY_ENTER))     { keyRelease(); return sel; }
        if (kp(';')) { keyRelease(); if (sel > 0) sel--; if (sel < top) top = sel; rd = true; delay(90); }
        if (kp('.')) { keyRelease(); if (sel < (int)items.size() - 1) sel++; if (sel >= top + vis) top = sel - vis + 1; rd = true; delay(90); }
        delay(10);
    }
}
static void ir_send_screen(const char* name, const char* path, int sigIdx) {
    ir_stop_req = false;
    int sent = 0;
    while (true) {
        ir_header("IR Send");
        M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        M5.Display.setCursor(6, 24); M5.Display.println(name);
        M5.Display.setTextColor(TFT_GREEN, TFT_BLACK); M5.Display.setCursor(6, 48);
        M5.Display.printf("sent: %d", sent);
        M5.Display.setTextColor(0x5AEB, TFT_BLACK);
        M5.Display.setCursor(6, 118); M5.Display.setTextSize(1);
        M5.Display.println("ENTER send   BACK exit");
        M5.Display.display();
        enterDebounce();
        while (true) {
            M5.update(); cardUpdate();
            if (kp(KEY_BACKSPACE)) { keyRelease(); return; }
            if (kp(KEY_ENTER)) { keyRelease(); bool ok = ir_send_file_signal(path, sigIdx); if (ok) sent++; break; }
            delay(12);
        }
    }
}
static void ir_browse_files() {
    SD.mkdir("/evil"); SD.mkdir(IR_DIR);
    std::vector<String> files;
    File dir = SD.open(IR_DIR);
    if (dir) { for (File e = dir.openNextFile(); e; e = dir.openNextFile()) {
        String n = e.name(); int sl = n.lastIndexOf('/'); if (sl >= 0) n = n.substring(sl + 1);
        if (n.endsWith(".ir")) files.push_back(n); e.close(); } dir.close(); }
    int fi = ir_pick("IR files", files, "no .ir in /evil/ir");
    if (fi < 0) return;
    char path[96]; snprintf(path, sizeof path, "%s/%s", IR_DIR, files[fi].c_str());
    std::vector<String> sigs; ir_list_signals(path, sigs);
    int si = ir_pick(files[fi].c_str(), sigs, "no signals");
    if (si < 0) return;
    ir_send_screen(sigs[si].c_str(), path, si);
}

// ---- TV-B-Gone: play every signal in a .ir file back-to-back (on-device) --
static int ir_play_all(const char* path) {
    File f = SD.open(path);
    if (!f) { ir_msg("TV-B-Gone", "no tvbgone.ir on SD", TFT_RED, "push it via 'ir add'"); ir_wait_key(); return 0; }
    // pre-count signals for the progress bar
    int total = 0;
    while (f.available()) { String l = f.readStringUntil('\n'); if (l.startsWith("name:")) total++; }
    f.seek(0);
    const int W = M5.Display.width();
    const int barX = 12, barY = 70, barW = W - 24, barH = 16;
    // ---- static UI, drawn once (then only dynamic regions refresh: no flicker) ----
    ir_header("TV-B-Gone");
    M5.Display.setTextSize(1); M5.Display.setTextColor(0x5AEB, TFT_BLACK);
    M5.Display.setCursor(12, 24); M5.Display.println("Blasting all TV power codes");
    M5.Display.setCursor(12, 36); M5.Display.print("Point the top edge at the TV");
    M5.Display.drawRect(barX, barY, barW, barH, TFT_GREEN);
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setCursor(12, 122); M5.Display.print("BACK = stop");
    M5.Display.display();
    int sent = 0, done = 0; bool have = false;
    String proto, type, lastname; uint32_t freq = 38000; uint16_t addr = 0, cmd = 0;
    uint16_t raw[512]; size_t rawN = 0;
    auto draw_progress = [&]() {
        int pct = total ? (done * 100 / total) : 0;
        int fill = total ? (done * (barW - 2) / total) : 0;
        if (fill < 0) fill = 0; if (fill > barW - 2) fill = barW - 2;
        M5.Display.fillRect(barX + 1, barY + 1, barW - 2, barH - 2, TFT_BLACK);     // clear bar interior
        if (fill > 0) M5.Display.fillRect(barX + 1, barY + 1, fill, barH - 2, TFT_GREEN);
        M5.Display.fillRect(12, 50, W - 24, 12, TFT_BLACK);                          // count line
        M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        M5.Display.setCursor(12, 48); M5.Display.printf("%d/%d  %d%%", done, total, pct);
        M5.Display.fillRect(12, 94, W - 24, 12, TFT_BLACK);                          // current signal line
        M5.Display.setTextSize(1); M5.Display.setTextColor(0xAD55, TFT_BLACK);
        M5.Display.setCursor(12, 96); M5.Display.printf("%.10s %.14s", proto.c_str(), lastname.c_str());
        M5.Display.display();
    };
    auto emit = [&]() {
        if (!have) return;
        if (type == "raw" && rawN > 0) { ir_begin(freq ? freq : 38000); ir_send_raw(raw, rawN); ir_end(); sent++; }
        else if (type == "parsed") { if (ir_emit_parsed(proto, addr, cmd)) sent++; }
        done++;
    };
    ir_stop_req = false; enterDebounce();
    uint32_t lastDraw = 0;
    while (f.available()) {
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); ir_stop_req = true; break; }
        String line = f.readStringUntil('\n'); line.trim();
        if (line.startsWith("name:")) {
            emit();                                   // emit the signal that just ended
            if (millis() - lastDraw > 60) { lastDraw = millis(); draw_progress(); }
            have = true; type = ""; proto = ""; freq = 38000; rawN = 0; addr = 0; cmd = 0;
            lastname = line.substring(5); lastname.trim();
        } else if (have) {
            if      (line.startsWith("type:"))      { type = line.substring(5); type.trim(); }
            else if (line.startsWith("protocol:"))  { proto = line.substring(9); proto.trim(); }
            else if (line.startsWith("frequency:")) { freq = (uint32_t)line.substring(10).toInt(); }
            else if (line.startsWith("address:"))   { addr = ir_hex_word_le(line.substring(8)); }
            else if (line.startsWith("command:"))   { cmd  = ir_hex_word_le(line.substring(8)); }
            else if (line.startsWith("data:")) {
                String d = line.substring(5); d.trim(); int p = 0;
                while (p < (int)d.length() && rawN < (sizeof(raw) / sizeof(raw[0]))) {
                    while (p < (int)d.length() && d[p] == ' ') p++;
                    int q = d.indexOf(' ', p); if (q < 0) q = d.length();
                    if (q > p) raw[rawN++] = (uint16_t)d.substring(p, q).toInt();
                    p = q + 1;
                }
            }
        }
    }
    if (!ir_stop_req) emit();                         // last signal (EOF, no trailing name:)
    f.close();
    draw_progress();                                  // bar to final state
    const int W2 = M5.Display.width();
    M5.Display.fillRect(12, 94, W2 - 24, 14, TFT_BLACK);
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(ir_stop_req ? TFT_ORANGE : TFT_GREEN, TFT_BLACK);
    M5.Display.setCursor(12, 94); M5.Display.printf("%s  %d codes", ir_stop_req ? "stopped" : "DONE", sent);
    M5.Display.fillRect(12, 120, W2 - 24, 12, TFT_BLACK);
    M5.Display.setTextSize(1); M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setCursor(12, 122); M5.Display.print("ENTER/BACK = exit");
    M5.Display.display();
    ir_wait_key();
    return sent;
}

// ---- on-device hex entry (Cardputer keyboard) -----------------------------
static bool ir_hex_input(const char* title, char* buf, size_t cap) {
    int len = (int)strlen(buf); bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            ir_header(title); M5.Display.setTextSize(2); M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
            M5.Display.setCursor(8, 44); M5.Display.print(strlen(buf) ? buf : ""); M5.Display.print('_');
            M5.Display.setTextSize(1); M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(6, 120); M5.Display.println("type hex 0-9 A-F   ENTER ok   DEL back");
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (M5Cardputer.Keyboard.isChange()) {
            auto st = M5Cardputer.Keyboard.keysState();
            for (auto c : st.word) {
                char up = (c >= 'a' && c <= 'z') ? (char)(c - 32) : (char)c;
                if (((up >= '0' && up <= '9') || (up >= 'A' && up <= 'F')) && len < (int)cap - 1) {
                    buf[len++] = up; buf[len] = 0; rd = true;
                }
            }
            if (st.del) { if (len > 0) { buf[--len] = 0; rd = true; } else { keyRelease(); return false; } }
            if (st.enter) { keyRelease(); return len > 0; }
        }
        delay(25);
    }
}

// ---- Type a protocol + address + command and send it ----------------------
static void ir_type_send() {
    const char* protos[] = { "NEC", "NECext", "Samsung32", "SIRC", "RC5" };
    std::vector<String> pv; for (auto p : protos) pv.push_back(p);
    int p = ir_pick("Protocol", pv, nullptr); if (p < 0) return;
    char addr[9] = "", cmd[9] = "";
    if (!ir_hex_input("Address (hex)", addr, sizeof addr)) return;
    if (!ir_hex_input("Command (hex)", cmd, sizeof cmd)) return;
    uint32_t a = (uint32_t)strtoul(addr, nullptr, 16);
    uint32_t c = (uint32_t)strtoul(cmd, nullptr, 16);
    uint32_t carrier = (p == 3) ? 40000 : (p == 4) ? 36000 : 38000;
    int sent = 0;
    while (true) {
        ir_header("IR Send"); M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
        M5.Display.setCursor(6, 24); M5.Display.printf("%s", protos[p]);
        M5.Display.setCursor(6, 44); M5.Display.printf("A:%s C:%s", addr, cmd);
        M5.Display.setTextColor(TFT_GREEN, TFT_BLACK); M5.Display.setCursor(6, 68); M5.Display.printf("sent: %d", sent);
        M5.Display.setTextColor(0x5AEB, TFT_BLACK); M5.Display.setTextSize(1);
        M5.Display.setCursor(6, 120); M5.Display.println("ENTER send   BACK exit");
        M5.Display.display();
        enterDebounce();
        bool go = false;
        while (true) {
            M5.update(); cardUpdate();
            if (kp(KEY_BACKSPACE)) { keyRelease(); return; }
            if (kp(KEY_ENTER)) { keyRelease(); go = true; break; }
            delay(12);
        }
        if (go) {
            ir_begin(carrier);
            for (int r = 0; r < 3; r++) {   // 3 bursts per press
                if (p == 0) ir_send_nec((uint8_t)a, (uint8_t)c);
                else if (p == 1) ir_send_necext((uint16_t)a, (uint16_t)c);
                else if (p == 2) ir_send_samsung32((uint8_t)a, (uint8_t)c);
                else if (p == 3) ir_send_sirc((uint8_t)c, (uint16_t)a, 12);
                else ir_send_rc5((uint8_t)a, (uint8_t)c);
                delay(40);
            }
            ir_end(); sent++;
        }
    }
}

inline void menu() {
    const char* items[] = { "Browse .ir files", "Type & send", "TV-B-Gone", "Dazzler (10s)", "About" };
    const int N = 5;
    int sel = 0; bool rd = true;
    enterDebounce();
    while (true) {
        if (rd) {
            ir_header("IR Remote"); M5.Display.setTextSize(1.5);
            for (int i = 0; i < N; i++) {
                int y = 22 + i * 19;
                if (i == sel) { M5.Display.fillRect(0, y - 1, M5.Display.width(), 18, menuSelectedBackgroundColor); M5.Display.setTextColor(menuTextFocusedColor); }
                else M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(8, y); M5.Display.println(items[i]);
            }
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return; }
        if (kp(';')) { keyRelease(); sel = (sel + N - 1) % N; rd = true; delay(90); }
        if (kp('.')) { keyRelease(); sel = (sel + 1) % N; rd = true; delay(90); }
        if (kp(KEY_ENTER)) {
            keyRelease();
            if (sel == 0) ir_browse_files();
            else if (sel == 1) ir_type_send();
            else if (sel == 2) { ir_msg("TV-B-Gone", "blasting all power...", TFT_YELLOW, "point at the TV"); ir_play_all("/evil/ir/tvbgone.ir"); }
            else if (sel == 3) { ir_msg("IR Remote", "Dazzler 10s...", TFT_YELLOW, "BACK after to exit"); ir_stop_req = false; ir_dazzle(10000); ir_msg("IR Remote", "Dazzler done", TFT_GREEN, nullptr); ir_wait_key(); }
            else { ir_msg("IR Remote", "38kHz TX on GPIO44", 0x5AEB, "TX only (no RX HW)"); ir_wait_key(); }
            rd = true;
        }
        delay(10);
    }
}

// ============================================================================
//  Serial console:  ir <sub> ...
// ============================================================================
inline void console(String a) {
    a.trim();
    auto tok = [&](int n)->String { String s = a; for (int i = 0; i < n; i++) { int sp = s.indexOf(' '); if (sp < 0) return ""; s = s.substring(sp + 1); } int sp = s.indexOf(' '); return sp < 0 ? s : s.substring(0, sp); };
    String sub = tok(0);
    if (sub == "" || sub == "help") {
        Serial.println(F("ir nec <addrHex> <cmdHex> | ir necext <addr> <cmd> | ir samsung <addr> <cmd>"));
        Serial.println(F("ir sirc <cmd> <addr> [12|15|20] | ir rc5 <addr> <cmd> | ir raw <us> <us> ..."));
        Serial.println(F("ir freq <hz> | ir file <path> [index] | ir power | ir dazzle <ms>"));
        Serial.println(F("ir ls | ir add <name>  (receive a .ir file into /evil/ir, end with line EOF)"));
        return;
    }
    if (sub == "nec")     { uint8_t ad = strtol(tok(1).c_str(),0,16), cm = strtol(tok(2).c_str(),0,16); ir_begin(38000); ir_send_nec(ad, cm); ir_end(); Serial.printf("ir nec %02X %02X sent\n", ad, cm); return; }
    if (sub == "necext")  { uint16_t ad = strtol(tok(1).c_str(),0,16), cm = strtol(tok(2).c_str(),0,16); ir_begin(38000); ir_send_necext(ad, cm); ir_end(); Serial.println(F("ir necext sent")); return; }
    if (sub == "samsung") { uint8_t ad = strtol(tok(1).c_str(),0,16), cm = strtol(tok(2).c_str(),0,16); ir_begin(38000); ir_send_samsung32(ad, cm); ir_end(); Serial.println(F("ir samsung sent")); return; }
    if (sub == "sirc")    { uint8_t cm = strtol(tok(1).c_str(),0,16); uint16_t ad = strtol(tok(2).c_str(),0,16); int b = tok(3).toInt(); if (b!=15&&b!=20) b=12; ir_begin(40000); ir_send_sirc(cm, ad, b); ir_end(); Serial.printf("ir sirc %d-bit sent\n", b); return; }
    if (sub == "rc5")     { uint8_t ad = strtol(tok(1).c_str(),0,16), cm = strtol(tok(2).c_str(),0,16); ir_begin(36000); ir_send_rc5(ad, cm); ir_end(); Serial.println(F("ir rc5 sent")); return; }
    if (sub == "freq")    { ir_cur_freq = (uint32_t)tok(1).toInt(); Serial.printf("ir freq=%lu\n", (unsigned long)ir_cur_freq); return; }
    if (sub == "power")   { ir_stop_req = false; ir_power_blast(); Serial.println(F("ir power blast done")); return; }
    if (sub == "dazzle")  { uint32_t ms = (uint32_t)tok(1).toInt(); if (!ms) ms = 5000; ir_stop_req = false; ir_dazzle(ms); Serial.println(F("ir dazzle done")); return; }
    if (sub == "raw") {
        uint16_t t[512]; size_t n = 0; String rest = a.substring(a.indexOf(' ') + 1);
        int p = 0; while (p < (int)rest.length() && n < 512) { while (p < (int)rest.length() && rest[p]==' ') p++; int q = rest.indexOf(' ', p); if (q<0) q = rest.length(); if (q>p) t[n++] = (uint16_t)rest.substring(p,q).toInt(); p = q+1; }
        if (n == 0) { Serial.println(F("usage: ir raw <us> <us> ...")); return; }
        ir_begin(ir_cur_freq ? ir_cur_freq : 38000); ir_send_raw(t, n); ir_end();
        Serial.printf("ir raw %u edges sent\n", (unsigned)n); return;
    }
    if (sub == "file") {
        String path = tok(1); if (path == "") { Serial.println(F("usage: ir file <path> [index]")); return; }
        String idxs = tok(2);
        if (idxs == "") { std::vector<String> sigs; int n = ir_list_signals(path.c_str(), sigs); Serial.printf("%d signals:\n", n); for (int i = 0; i < n; i++) Serial.printf("  [%d] %s\n", i, sigs[i].c_str()); return; }
        int idx = idxs.toInt(); bool ok = ir_send_file_signal(path.c_str(), idx);
        Serial.println(ok ? F("ir file signal sent") : F("ir file: not found / unsupported")); return;
    }
    if (sub == "add") {
        // ir add <name> : receive a .ir file over serial into /evil/ir/<name>.ir,
        // line by line, terminated by a line containing only "EOF". ~15s idle timeout.
        String name = tok(1);
        if (name == "") { Serial.println(F("usage: ir add <name>  (then send .ir lines, end with EOF)")); return; }
        int sl = name.lastIndexOf('/'); if (sl >= 0) name = name.substring(sl + 1);   // basename only
        if (!name.endsWith(".ir")) name += ".ir";
        SD.mkdir("/evil"); SD.mkdir(IR_DIR);
        char path[96]; snprintf(path, sizeof path, "%s/%s", IR_DIR, name.c_str());
        File f = SD.open(path, FILE_WRITE);
        if (!f) { Serial.println(F("ir add: cannot open SD file")); return; }
        Serial.printf("READY %s  (send lines, end with a line: EOF)\n", path);
        uint32_t last = millis(); size_t nbytes = 0; int nlines = 0;
        while (millis() - last < 15000) {
            if (Serial.available()) {
                String line = Serial.readStringUntil('\n');
                line.replace("\r", "");
                if (line == "EOF") break;
                f.print(line); f.print('\n');
                nbytes += line.length() + 1; nlines++;
                last = millis();
            }
            delay(1);
        }
        f.close();
        Serial.printf("ir add: wrote %s (%d lines, %u bytes)\n", path, nlines, (unsigned)nbytes);
        return;
    }
    if (sub == "ls") {
        SD.mkdir("/evil"); SD.mkdir(IR_DIR);
        File dir = SD.open(IR_DIR); int n = 0;
        if (dir) { for (File e = dir.openNextFile(); e; e = dir.openNextFile()) {
            String nm = e.name(); int s = nm.lastIndexOf('/'); if (s >= 0) nm = nm.substring(s + 1);
            if (nm.endsWith(".ir")) { Serial.printf("  %s (%u)\n", nm.c_str(), (unsigned)e.size()); n++; } e.close(); }
            dir.close(); }
        Serial.printf("ir ls: %d file(s) in %s\n", n, IR_DIR); return;
    }
    Serial.println(F("unknown ir sub; try 'ir help'"));
}

} // namespace irr

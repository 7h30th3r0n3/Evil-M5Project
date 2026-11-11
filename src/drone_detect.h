#pragma once
// ============================================================================
//  Drone RemoteID detector (passive) for Evil-Cardputer
// ----------------------------------------------------------------------------
//  Detects Open Drone ID / ASTM F3411 Remote ID broadcasts. Receive only, no
//  transmit. Two radios, used one at a time:
//    - WiFi: promiscuous capture of beacons carrying the ODID vendor IE
//      (OUI FA:0B:BC, vendor type 0x0D).
//    - BLE:  advertisement scan for ODID service data (16-bit UUID 0xFFFA,
//      application code 0x0D).
//  Parses Basic ID (operator/serial) and Location (lat/lon) messages and shows
//  a live list of nearby drones with RSSI and age.
// ============================================================================

namespace drone {

#define DRONE_MAX 16

struct DroneRec {
    uint8_t  mac[6];
    char     id[21];      // UAS serial / Basic ID (ASCII)
    double   lat, lon;
    int16_t  rssi;
    uint8_t  src;         // 0 = WiFi, 1 = BLE
    bool     has_id, has_loc;
    uint32_t last_ms;
};

static DroneRec* g_dr = nullptr;      // lazy-alloc'd while the detector runs (0 boot RAM)
static int       g_dr_count = 0;

static bool dr_alloc() { if (!g_dr) g_dr = (DroneRec*)calloc(DRONE_MAX, sizeof(DroneRec)); g_dr_count = 0; return g_dr != nullptr; }
static void dr_free()  { if (g_dr) { free(g_dr); g_dr = nullptr; } g_dr_count = 0; }

static int dr_find(const uint8_t* mac) {
    if (!g_dr) return -1;
    for (int i = 0; i < g_dr_count; i++) if (memcmp(g_dr[i].mac, mac, 6) == 0) return i;
    return -1;
}
static int dr_upsert(const uint8_t* mac, int rssi, uint8_t src) {
    if (!g_dr) return -1;
    int i = dr_find(mac);
    if (i < 0) {
        if (g_dr_count >= DRONE_MAX) {           // evict oldest
            int oldest = 0; for (int k = 1; k < g_dr_count; k++) if (g_dr[k].last_ms < g_dr[oldest].last_ms) oldest = k;
            i = oldest;
        } else i = g_dr_count++;
        memset(&g_dr[i], 0, sizeof(DroneRec));
        memcpy(g_dr[i].mac, mac, 6);
    }
    g_dr[i].rssi = (int16_t)rssi; g_dr[i].src = src; g_dr[i].last_ms = millis();
    return i;
}
static void dr_reset() { g_dr_count = 0; }

// ---- parse one 25-byte ODID message into a record --------------------------
static void odid_apply_message(int idx, const uint8_t* m, size_t avail) {
    if (avail < 25) return;
    uint8_t type = (m[0] >> 4) & 0x0F;
    if (type == 0x0) {                            // Basic ID: serial in bytes 2..21
        memcpy(g_dr[idx].id, &m[2], 20); g_dr[idx].id[20] = 0;
        // trim trailing spaces/nulls
        for (int k = 19; k >= 0 && (g_dr[idx].id[k] == ' ' || g_dr[idx].id[k] == 0); k--) g_dr[idx].id[k] = 0;
        if (g_dr[idx].id[0]) g_dr[idx].has_id = true;
    } else if (type == 0x1) {                      // Location/Vector
        int32_t lat = (int32_t)((uint32_t)m[5] | ((uint32_t)m[6] << 8) | ((uint32_t)m[7] << 16) | ((uint32_t)m[8] << 24));
        int32_t lon = (int32_t)((uint32_t)m[9] | ((uint32_t)m[10] << 8) | ((uint32_t)m[11] << 16) | ((uint32_t)m[12] << 24));
        if (lat != 0 || lon != 0) { g_dr[idx].lat = lat / 1e7; g_dr[idx].lon = lon / 1e7; g_dr[idx].has_loc = true; }
    }
}
// Parse an ODID payload that may be a single message or a Message Pack (type 0xF).
static void odid_apply_payload(int idx, const uint8_t* p, size_t n) {
    if (n < 1) return;
    uint8_t type = (p[0] >> 4) & 0x0F;
    if (type == 0xF) {                             // Message Pack: [0]=0xF., [1]=msgSize, [2]=qty, then qty*msgSize
        if (n < 3) return;
        uint8_t msz = p[1] ? p[1] : 25, qty = p[2];
        size_t off = 3;
        for (uint8_t q = 0; q < qty && off + msz <= n; q++, off += msz) odid_apply_message(idx, &p[off], msz);
    } else {
        odid_apply_message(idx, p, n);
    }
}

// ============================================================================
//  WiFi promiscuous path
// ============================================================================
static volatile bool g_wifi_active = false;

static void wifi_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_wifi_active) return;
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* pl = ppkt->payload; int len = ppkt->rx_ctrl.sig_len;
    if (len < 36) return;
    uint8_t ftype = (pl[0] >> 2) & 0x3, fsub = (pl[0] >> 4) & 0xF;
    if (ftype != 0) return;                        // management only
    if (fsub != 8 && fsub != 5) return;            // beacon or probe-resp carry the IE
    const uint8_t* sa = pl + 10;                   // source address
    // tagged params begin after 24-byte header + 12-byte fixed beacon fields
    int i = 36;
    while (i + 2 <= len) {
        uint8_t tid = pl[i], tlen = pl[i + 1]; const uint8_t* td = pl + i + 2;
        if (i + 2 + tlen > len) break;
        if (tid == 0xDD && tlen >= 5 && td[0] == 0xFA && td[1] == 0x0B && td[2] == 0xBC && td[3] == 0x0D) {
            // [OUI 3][vtype 0x0D][counter 1][ODID payload...]
            int idx = dr_upsert(sa, ppkt->rx_ctrl.rssi, 0);
            if (idx >= 0) odid_apply_payload(idx, td + 5, tlen - 5);
        }
        i += 2 + tlen;
    }
}

// ============================================================================
//  BLE path (parse one advertisement's raw AD structures)
// ============================================================================
static void ble_parse_adv(const uint8_t* mac, int rssi, const uint8_t* adv, size_t n) {
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t fl = adv[i]; if (fl == 0) break;
        if (i + 1 + fl > n) break;
        uint8_t adtype = adv[i + 1];
        const uint8_t* ad = adv + i + 2; int adlen = fl - 1;
        if (adtype == 0x16 && adlen >= 3 && ad[0] == 0xFA && ad[1] == 0xFF && ad[2] == 0x0D) {
            // service data UUID 0xFFFA (LE), app code 0x0D, [counter 1][ODID message 25]
            int idx = dr_upsert(mac, rssi, 1);
            if (idx >= 0 && adlen >= 4) odid_apply_payload(idx, ad + 4, adlen - 4);
        }
        i += 1 + fl;
    }
}

// ============================================================================
//  Rendering
// ============================================================================
static void dr_header(const char* title, int ch) {
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.fillRect(0, 0, M5.Display.width(), 14, 0x0841);
    M5.Display.drawFastHLine(0, 14, M5.Display.width(), TFT_GREEN);
    M5.Display.setTextSize(1.5); M5.Display.setTextColor(TFT_GREEN, 0x0841);
    char hd[32]; if (ch >= 0) snprintf(hd, sizeof hd, "%s ch%d  %d", title, ch, g_dr_count);
    else snprintf(hd, sizeof hd, "%s  %d", title, g_dr_count);
    int tw = (int)(strlen(hd) * 9); int tx = (M5.Display.width() - tw) / 2; if (tx < 0) tx = 0;
    M5.Display.setCursor(tx, 0); M5.Display.println(hd);
}
static void dr_draw_list(const char* title, int ch, int top) {
    dr_header(title, ch);
    M5.Display.setTextSize(1);
    if (g_dr_count == 0) {
        M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
        M5.Display.setCursor(5, 40); M5.Display.println("scanning for RemoteID...");
    } else {
        const int rowH = 20, headerY = 18, vis = 5;
        if (top > g_dr_count - 1) top = g_dr_count - 1; if (top < 0) top = 0;
        for (int i = 0; i < vis; i++) {
            int idx = top + i; if (idx >= g_dr_count) break;
            int y = headerY + i * rowH;
            DroneRec& d = g_dr[idx];
            uint32_t age = (millis() - d.last_ms) / 1000;
            M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
            M5.Display.setCursor(5, y);
            char line1[40];
            if (d.has_id && d.id[0]) snprintf(line1, sizeof line1, "%s", d.id);
            else snprintf(line1, sizeof line1, "%02X:%02X:%02X:%02X:%02X:%02X", d.mac[0],d.mac[1],d.mac[2],d.mac[3],d.mac[4],d.mac[5]);
            M5.Display.println(line1);
            M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(5, y + 9);
            if (d.has_loc) M5.Display.printf("%c %.5f,%.5f %ddBm %lus", d.src ? 'B' : 'W', d.lat, d.lon, d.rssi, (unsigned long)age);
            else           M5.Display.printf("%c (no GPS) %ddBm %lus", d.src ? 'B' : 'W', d.rssi, (unsigned long)age);
        }
    }
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setCursor(5, 122); M5.Display.println(";/. scroll  BACK stop");
    M5.Display.display();
}

// ============================================================================
//  WiFi run
// ============================================================================
static void run_wifi() {
    if (!dr_alloc()) return;
    WiFi.mode(WIFI_STA); WiFi.disconnect();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&wifi_cb);
    esp_wifi_set_promiscuous(true);
    g_wifi_active = true;
    static const uint8_t chs[] = {6, 1, 11, 3, 8}; int ci = 0;
    uint8_t ch = chs[0]; esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    uint32_t lastHop = millis(), lastDraw = 0; int top = 0;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE) || kp(KEY_ENTER)) { keyRelease(); break; }
        if (kp(';')) { keyRelease(); if (top > 0) top--; }
        if (kp('.')) { keyRelease(); if (top + 1 < g_dr_count) top++; }
        if (millis() - lastHop > 350) { lastHop = millis(); ci = (ci + 1) % 5; ch = chs[ci]; esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE); }
        if (millis() - lastDraw > 500) { lastDraw = millis(); dr_draw_list("Drone WiFi", ch, top); }
        delay(8);
    }
    g_wifi_active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    dr_free();
}

// ============================================================================
//  BLE run
// ============================================================================
class DroneBLECB : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice d) override {
        uint8_t* mac = (uint8_t*)d.getAddress().getNative();
        uint8_t* pl  = d.getPayload(); size_t n = d.getPayloadLength();
        if (mac && pl && n) ble_parse_adv(mac, d.getRSSI(), pl, n);
    }
};
static void run_ble() {
    if (!dr_alloc()) return;
    if (!BLEDevice::getInitialized()) BLEDevice::init("");
    isBLEInitialized = true;
    BLEScan* s = BLEDevice::getScan();
    static DroneBLECB cb; s->setAdvertisedDeviceCallbacks(&cb, true);
    s->setActiveScan(false); s->setInterval(100); s->setWindow(99);
    s->start(0, nullptr, false);
    uint32_t lastDraw = 0, lastClear = millis(); int top = 0;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate();
        if (kp(KEY_BACKSPACE) || kp(KEY_ENTER)) { keyRelease(); break; }
        if (kp(';')) { keyRelease(); if (top > 0) top--; }
        if (kp('.')) { keyRelease(); if (top + 1 < g_dr_count) top++; }
        if (millis() - lastClear > 5000) { lastClear = millis(); s->clearResults(); }
        if (millis() - lastDraw > 500) { lastDraw = millis(); dr_draw_list("Drone BLE", -1, top); }
        delay(8);
    }
    s->stop(); s->setAdvertisedDeviceCallbacks(nullptr); s->clearResults();
    dr_free();
}

inline void menu() {
    const char* items[] = { "WiFi RemoteID", "BLE RemoteID", "About" };
    int sel = 0; bool rd = true; enterDebounce();
    while (true) {
        if (rd) {
            dr_header("Drone Detector", -1); M5.Display.setTextSize(1.5);
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
            if (sel == 0) run_wifi();
            else if (sel == 1) run_ble();
            else { dr_header("Drone Detector", -1); M5.Display.setTextSize(1.5); M5.Display.setTextColor(0x5AEB, TFT_BLACK);
                   M5.Display.setCursor(6, 30); M5.Display.println("OpenDroneID / ASTM"); M5.Display.setCursor(6, 54); M5.Display.println("F3411 passive RX"); M5.Display.setCursor(6, 78); M5.Display.println("WiFi + BLE, no TX"); M5.Display.display();
                   enterDebounce(); while (true) { M5.update(); cardUpdate(); if (kp(KEY_ENTER) || kp(KEY_BACKSPACE)) { keyRelease(); break; } delay(12); } }
            rd = true;
        }
        delay(10);
    }
}

// ---- serial: drone <wifi|ble|list> ----------------------------------------
inline void console(String a) {
    a.trim();
    int sp = a.indexOf(' '); String sub = sp < 0 ? a : a.substring(0, sp);
    String arg = sp < 0 ? "" : a.substring(sp + 1); arg.trim();
    if (sub == "" || sub == "help") { Serial.println(F("drone wifi [secs] | drone ble [secs] | drone list")); return; }
    if (sub == "list") {
        Serial.printf("%d drones:\n", g_dr_count);
        for (int i = 0; i < g_dr_count; i++) { DroneRec& d = g_dr[i];
            Serial.printf("  [%c] %s  ", d.src ? 'B' : 'W', (d.has_id && d.id[0]) ? d.id : "?");
            if (d.has_loc) Serial.printf("%.6f,%.6f ", d.lat, d.lon);
            Serial.printf("%ddBm %02X:%02X:%02X:%02X:%02X:%02X\n", d.rssi, d.mac[0],d.mac[1],d.mac[2],d.mac[3],d.mac[4],d.mac[5]); }
        return;
    }
    if (sub == "wifi") {
        uint32_t secs = arg.toInt(); if (!secs) secs = 15; if (!dr_alloc()) { Serial.println(F("alloc fail")); return; }
        WiFi.mode(WIFI_STA); WiFi.disconnect();
        esp_wifi_set_promiscuous(false); esp_wifi_set_promiscuous_rx_cb(&wifi_cb); esp_wifi_set_promiscuous(true); g_wifi_active = true;
        static const uint8_t chs[] = {6,1,11,3,8}; int ci = 0; esp_wifi_set_channel(chs[0], WIFI_SECOND_CHAN_NONE);
        Serial.printf("drone wifi: scanning %lus...\n", (unsigned long)secs);
        uint32_t t0 = millis(), hop = millis();
        while (millis() - t0 < secs * 1000) { if (millis() - hop > 350) { hop = millis(); ci = (ci + 1) % 5; esp_wifi_set_channel(chs[ci], WIFI_SECOND_CHAN_NONE); } delay(20); }
        g_wifi_active = false; esp_wifi_set_promiscuous(false); esp_wifi_set_promiscuous_rx_cb(NULL);
        console(String("list")); dr_free(); return;
    }
    if (sub == "ble") {
        uint32_t secs = arg.toInt(); if (!secs) secs = 15; if (!dr_alloc()) { Serial.println(F("alloc fail")); return; }
        if (!BLEDevice::getInitialized()) BLEDevice::init(""); isBLEInitialized = true;
        BLEScan* s = BLEDevice::getScan(); static DroneBLECB cb; s->setAdvertisedDeviceCallbacks(&cb, true);
        s->setActiveScan(false); s->setInterval(100); s->setWindow(99); s->start(0, nullptr, false);
        Serial.printf("drone ble: scanning %lus...\n", (unsigned long)secs);
        uint32_t t0 = millis(); while (millis() - t0 < secs * 1000) delay(50);
        s->stop(); s->setAdvertisedDeviceCallbacks(nullptr); s->clearResults();
        console(String("list")); dr_free(); return;
    }
    Serial.println(F("unknown; try 'drone help'"));
}

} // namespace drone

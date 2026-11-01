// ============================================================================
//  wifi_radar.h  -  DragonRadar port for Evil-Cardputer (240x135)
//
//  Passive 2.4GHz WiFi radar (802.11 promiscuous) + passive BLE advertisement
//  scan, in a green phosphor scouter style, ported from the standalone
//  DragonRadar app (M5Stack StopWatch, 466x466 round AMOLED) to the Cardputer.
//
//  100% PASSIVE: WiFi listen only (no injection), BLE passive scan only (no
//  scan requests, no transmit). Detects deauth/disassoc attacks and EAPOL
//  handshakes, classifies every frame (mgmt / ctrl / data / attack), tracks
//  each device as a blip on a radar scope (angle = MAC hash, radius = RSSI).
//
//  Single 2.4GHz radio: WiFi promiscuous OR BLE scan, never both at once (the
//  BLE view switches the radio, matching the firmware's own beaconScanMenu
//  sequence that is known-good on this hardware).
//
//  Optional live pcap stream to Wireshark over USB-CDC, toggled with 'p'.
//
//  Nav (keyboard): ; / .  aim (cycle selected device)   , / /  channel -/+ (lock)
//                  ENTER   cycle view                    BACKSPACE  back / exit
//                  h unlock(hop)  p pcap  a alert-beep  c ctrl-frames  r reset
//
//  Header-only module, #included late in the main .ino: it relies on the
//  globals and helpers already defined there (M5, M5Cardputer, kp(), cardUpdate,
//  waitAndReturnToMenu, releaseBLE, inMenu, the menu theme colors).
//
//  SPDX-License-Identifier: GPL-3.0-or-later
//  Copyright (c) 7h30th3r0n3
// ============================================================================
#pragma once

#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/queue.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <math.h>

// ───────────────────────── config ─────────────────────────────────────────
#define RDR_MAX_DEV    32          // WiFi devices tracked (blips)
#define RDR_BLE_MAX    32          // BLE devices tracked
#define RDR_DEV_TIMEOUT 12000      // ms before a blip goes stale
#define RDR_CHAN_MIN   1
#define RDR_CHAN_MAX   13
#define RDR_RAW        96          // raw slice copied per frame (>= DS Param offset)
#define RDR_PCAP_CAP   512         // per-frame bytes streamed to Wireshark
// Internal RAM is tight once the BT controller (kept across BLE sessions) and the
// 32KB display sprite are resident, so the RTOS queues are kept small.
#define RDR_QDEPTH     64          // capture queue depth
#define RDR_PCAPQ      16          // pcap queue depth

static const float RDR_DEG2RAD = 0.017453292f;

// ───────────────────────── types ──────────────────────────────────────────
struct RdrFrame {                  // captured frame (RTOS queue); parse deferred to loop
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  type;                 // 0=mgmt 1=ctrl 2=data 3=ext
    uint8_t  subtype;              // 0..15
    bool     hasSrc;               // false for ACK/CTS (no transmitter)
    uint8_t  src[6];               // addr2
    bool     hasTarget;            // attack frame: addr1 = target
    uint8_t  target[6];
    uint8_t  enc;                  // 0=? 1=open 2=WEP 3=WPA 4=RSN
    uint16_t rawLen;
    uint8_t  raw[RDR_RAW];
};

struct RdrPcap {                   // full frame for the Wireshark pcap stream
    uint16_t caplen;
    uint16_t origlen;
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  data[RDR_PCAP_CAP];
};

struct RdrDev {                    // tracked WiFi device (blip)
    uint8_t  mac[6];
    float    angle;                // deg, stable hash of the MAC
    float    rssi;                 // smoothed
    uint8_t  channel;              // RX channel at reception
    uint8_t  apChannel;            // AP's declared channel (DS Param Set), 0 if unknown
    uint32_t last_seen;
    uint32_t frames;
    uint16_t fam[4];               // 0=mgmt 1=ctrl 2=data 3=attack
    uint8_t  lastType, lastSub;
    char     ssid[33];
    bool     attack;
    bool     active;
    bool     hidden;               // hidden SSID
    bool     eapol;                // at least one EAPOL-Key seen
    uint8_t  eapolMsgs;            // 4-way bitmask bit0=M1..bit3=M4
    uint8_t  enc;                  // 0=? 1=open 2=WEP 3=WPA 4=RSN
    bool     hasTarget;
    uint8_t  target[6];
};

struct RdrBle {                    // tracked BLE device (blip)
    uint8_t  addr[6];
    uint8_t  addrType;
    float    angle;
    float    rssi;
    uint32_t last_seen;
    uint32_t adv;
    char     name[21];
    uint16_t company;              // manufacturer company ID, 0xFFFF if absent
    bool     haveName;
    bool     active;
    bool     randomAddr;
};

enum RdrView  : uint8_t { RDRV_SPLASH, RDRV_SCOPE, RDRV_TYPES, RDRV_LIST, RDRV_CHANS, RDRV_BLE, RDRV_DETAIL };
enum RdrMode  : uint8_t { RDR_MODE_WIFI, RDR_MODE_BLE };

// ───────────────────────── state ──────────────────────────────────────────
static QueueHandle_t   rdr_queue   = nullptr;
static QueueHandle_t   rdr_pcapQ   = nullptr;
static RdrDev*         rdr_dev     = nullptr;
static int             rdr_devCount = 0;
static RdrBle*         rdr_ble     = nullptr;
static int             rdr_bleCount = 0;
static portMUX_TYPE    rdr_bleMux  = portMUX_INITIALIZER_UNLOCKED;

static uint32_t rdr_sub[3][16];           // per type/subtype counters
static uint32_t rdr_totalFrames = 0;
static uint32_t rdr_attackCount = 0;
static uint8_t  rdr_channel     = 1;
static bool     rdr_chanLock    = false;
static uint32_t rdr_attackFlashUntil = 0;
static uint32_t rdr_fpsWin = 0, rdr_fps = 0, rdr_fpsT0 = 0;
static volatile uint32_t rdr_dropped = 0;
static volatile uint32_t rdr_pcapDropped = 0;
static volatile uint32_t rdr_interestUntil = 0;
static bool     rdr_alertOn = false;      // deauth beep, OFF by default
static uint32_t rdr_chanFrames[14] = {}, rdr_chanAtk[14] = {};
static int      rdr_minRssi = -99;        // declutter: hide weaker blips
static bool     rdr_paused  = false;
static bool     rdr_ctrlCapture = false;  // capture control frames (ACK/CTS): OFF = more useful throughput
static volatile bool rdr_dropEncData = true;  // declutter ON: drop encrypted QoS data, keep EAPOL/mgmt/beacons
static volatile bool rdr_beepPending = false;
static volatile bool rdr_quit = false;        // serial 'Q': clean exit to menu (remote control / testing)

static volatile RdrMode rdr_mode = RDR_MODE_WIFI;
static volatile bool     rdr_pcapStream = false;
static volatile bool     rdr_pcapHdrSent = false;
static volatile uint16_t rdr_pcapLink = 127;   // 127=radiotap(WiFi) 256=BLE-LL-PHDR
static uint32_t rdr_bleAdvTotal = 0, rdr_bleFps = 0, rdr_bleFpsWin = 0;
static BLEScan*  rdr_bleScan = nullptr;

static RdrView  rdr_view = RDRV_SPLASH, rdr_prevView = RDRV_SCOPE;
static int      rdr_sel = 0;              // index into rdr_order
static uint8_t  rdr_anchorMac[6] = {}; static bool rdr_haveAnchor = false;
static uint8_t  rdr_detailMac[6] = {}; static bool rdr_haveDetail = false;
static uint32_t rdr_splashUntil = 0;
static int      rdr_order[RDR_MAX_DEV]; static int rdr_orderCount = 0;
static M5Canvas* rdr_spr = nullptr;       // double-buffer, allocated once and kept (BLE fragments the heap)
static bool      rdr_sprOk = false;

// ───────────────────────── classification ─────────────────────────────────
static const char* RDR_SUB_MGMT[16] = {"AssocReq","AssocResp","ReassocReq","ReassocResp","ProbeReq","ProbeResp","TimAdv","-","Beacon","ATIM","Disassoc","Auth","Deauth","Action","ActNoAck","-"};
static const char* RDR_SUB_DATA[16] = {"Data","Data+CFAck","Data+CFPoll","Data+CFAP","Null","CFAck","CFPoll","CFAckPoll","QoSData","QoSD+CFAck","QoSD+CFPoll","QoSD+CFAP","QoSNull","-","QoS+CFPoll","QoS+CFAP"};
static inline bool rdrIsAttack(uint8_t type, uint8_t sub) { return type == 0 && (sub == 12 || sub == 10); }
static inline int  rdrFamily(uint8_t type, uint8_t sub) {
    if (rdrIsAttack(type, sub)) return 3;
    return (type == 1) ? 1 : (type == 2) ? 2 : 0;
}
static const char* rdrEncName(uint8_t e) {
    switch (e) { case 1: return "OPEN"; case 2: return "WEP"; case 3: return "WPA"; case 4: return "WPA2"; default: return "?"; }
}

// ───────────────────────── sniffer callback (WiFi task context) ───────────
static void rdr_sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t ptype) {
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 10 || !rdr_queue) return;
    uint16_t fc = p[0] | (p[1] << 8);
    uint8_t type = (fc >> 2) & 3, sub = (fc >> 4) & 0xF;
    if (rdr_dropEncData && type == 2 && (fc & 0x4000)) return;   // drop encrypted data (EAPOL is in clear -> passes)
    RdrFrame f = {};
    f.rssi = pkt->rx_ctrl.rssi;
    f.channel = pkt->rx_ctrl.channel;
    f.type = type; f.subtype = sub;
    bool hasTA = !(type == 1 && (sub == 12 || sub == 13));       // ACK/CTS have no addr2
    if (hasTA && len >= 16) { memcpy(f.src, p + 10, 6); f.hasSrc = true; }
    if (rdrIsAttack(type, sub) && len >= 10) { memcpy(f.target, p + 4, 6); f.hasTarget = true; }
    if (type == 0 && (sub == 8 || sub == 5) && len >= 36) {      // beacon/probe-resp: encryption from the full IE list
        int scan = (len >= 4) ? len - 4 : len;
        uint8_t enc = 0;
        bool priv = (p[34] & 0x10);
        int i = 36;
        while (i + 2 <= scan) {
            uint8_t tag = p[i], tl = p[i + 1];
            if (i + 2 + tl > scan) break;
            if (tag == 48) { enc = 4; }
            else if (tag == 221 && tl >= 4 && enc < 4 &&
                     p[i+2]==0x00 && p[i+3]==0x50 && p[i+4]==0xF2 && p[i+5]==0x01) enc = 3;
            i += 2 + tl;
        }
        if (enc == 0) enc = priv ? 2 : 1;
        f.enc = enc;
    }
    uint16_t n = (len < RDR_RAW) ? (uint16_t)len : RDR_RAW;
    memcpy(f.raw, p, n); f.rawLen = n;
    if (xQueueSend(rdr_queue, &f, 0) != pdTRUE) rdr_dropped++;

    if (rdr_pcapStream && rdr_pcapQ) {   // Wireshark stream: full frame minus the 4-byte FCS (esp-idf #886)
        uint16_t flen = (len >= 4) ? (uint16_t)(len - 4) : (uint16_t)len;
        RdrPcap pf;
        pf.origlen = flen;
        pf.caplen  = (flen < RDR_PCAP_CAP) ? flen : RDR_PCAP_CAP;
        pf.rssi = pkt->rx_ctrl.rssi; pf.channel = pkt->rx_ctrl.channel;
        memcpy(pf.data, p, pf.caplen);
        if (xQueueSend(rdr_pcapQ, &pf, 0) != pdTRUE) rdr_pcapDropped++;
    }
}

// ───────────────────────── device table ───────────────────────────────────
static uint32_t rdrMacHash(const uint8_t* m) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= m[i]; h *= 16777619u; }
    return h;
}
static int rdrFindDev(const uint8_t* mac) {
    for (int i = 0; i < rdr_devCount; i++) if (memcmp(rdr_dev[i].mac, mac, 6) == 0) return i;
    int idx = -1;
    if (rdr_devCount < RDR_MAX_DEV) idx = rdr_devCount++;
    else {   // table full: evict oldest non-attack; if all attack, oldest overall
        uint32_t oldest = 0xFFFFFFFF, oldestAnyT = 0xFFFFFFFF; int oldestAny = 0;
        for (int i = 0; i < rdr_devCount; i++) {
            if (rdr_dev[i].last_seen < oldestAnyT) { oldestAnyT = rdr_dev[i].last_seen; oldestAny = i; }
            if (!rdr_dev[i].attack && rdr_dev[i].last_seen <= oldest) { oldest = rdr_dev[i].last_seen; idx = i; }
        }
        if (idx < 0) idx = oldestAny;
    }
    memset(&rdr_dev[idx], 0, sizeof(RdrDev));
    memcpy(rdr_dev[idx].mac, mac, 6);
    rdr_dev[idx].angle = (rdrMacHash(mac) % 3600) / 10.0f;
    rdr_dev[idx].rssi = -99;
    return idx;
}
static void rdrTriggerAlert() {
    rdr_attackFlashUntil = millis() + 400;
    if (rdr_alertOn) rdr_beepPending = true;
}
static void rdrProcess(const RdrFrame& f) {
    rdr_totalFrames++; rdr_fpsWin++;
    rdr_sub[f.type > 2 ? 2 : f.type][f.subtype & 15]++;
    uint8_t ch = (f.channel >= 1 && f.channel <= 13) ? f.channel : 0;
    rdr_chanFrames[ch]++;
    bool attack = rdrIsAttack(f.type, f.subtype);
    if (attack) { rdr_attackCount++; rdr_chanAtk[ch]++; rdrTriggerAlert(); rdr_interestUntil = millis() + 500; }
    if (!f.hasSrc) return;
    int d = rdrFindDev(f.src);
    if (d < 0) return;
    RdrDev& dev = rdr_dev[d];
    dev.rssi = dev.frames ? (dev.rssi * 0.7f + f.rssi * 0.3f) : f.rssi;
    dev.channel = f.channel;
    dev.last_seen = millis();
    dev.frames++;
    dev.fam[rdrFamily(f.type, f.subtype)]++;
    dev.lastType = f.type; dev.lastSub = f.subtype;
    dev.active = true;
    const uint8_t* p = f.raw; int len = f.rawLen;
    if (f.enc) dev.enc = f.enc;
    if (f.type == 0 && (f.subtype == 8 || f.subtype == 5)) {   // SSID + DS Param from the raw slice
        int i = 36;
        while (i + 2 <= len) {
            uint8_t tag = p[i], tl = p[i + 1];
            if (i + 2 + tl > len) break;
            if (tag == 0) {
                if (tl == 0) dev.hidden = true;
                else { uint8_t k = tl > 32 ? 32 : tl; memcpy(dev.ssid, p + i + 2, k); dev.ssid[k] = 0; }
            } else if (tag == 3 && tl >= 1) {
                uint8_t apc = p[i + 2];
                if (apc >= 1 && apc <= 14) dev.apChannel = apc;
            }
            i += 2 + tl;
        }
    }
    if (f.type == 2) {   // unprotected data: LLC/SNAP + EAPOL (88 8E)
        uint16_t fc = p[0] | (p[1] << 8);
        if (!(fc & 0x4000)) {
            int hl = 24;
            if ((fc & 0x0300) == 0x0300) hl += 6;   // 4 addresses
            if (f.subtype & 8)           hl += 2;   // QoS Control
            if (fc & 0x8000)             hl += 4;   // HT Control
            if (len >= hl + 8) { const uint8_t* s = p + hl;
                if (s[0]==0xAA && s[1]==0xAA && s[2]==0x03 && s[6]==0x88 && s[7]==0x8E) {
                    dev.eapol = true; rdr_interestUntil = millis() + 500;
                    if (len >= hl + 15 && s[9] == 3) {
                        uint16_t ki = (s[13] << 8) | s[14];
                        if (ki & 0x0008) {
                            bool ack = ki & 0x0080, mic = ki & 0x0100, sec = ki & 0x0200;
                            int m;
                            if (ack && !mic)     m = 1;
                            else if (ack && mic) m = 3;
                            else if (!sec)       m = 2;
                            else                 m = 4;
                            dev.eapolMsgs |= (1 << (m - 1));
                        }
                    }
                }
            }
        }
    }
    if (attack) { dev.attack = true; if (f.hasTarget) { memcpy(dev.target, f.target, 6); dev.hasTarget = true; } }
}
static void rdrDrainQueue() {   // single consumer (feature loop) -> no mutex needed
    if (!rdr_queue) return;
    RdrFrame f;
    int guard = 400;
    while (guard-- > 0 && xQueueReceive(rdr_queue, &f, 0) == pdTRUE) rdrProcess(f);
    uint32_t now = millis();
    if (now - rdr_fpsT0 >= 1000) { rdr_fps = rdr_fpsWin; rdr_fpsWin = 0; rdr_fpsT0 = now; }
}

// ───────────────────────── display order (by RSSI) ────────────────────────
static void rdrRebuildOrder() {
    uint32_t now = millis();
    rdr_orderCount = 0;
    for (int i = 0; i < rdr_devCount; i++) {
        if (now - rdr_dev[i].last_seen > RDR_DEV_TIMEOUT) { rdr_dev[i].active = false; continue; }
        rdr_dev[i].active = true;
        if (rdr_dev[i].rssi < rdr_minRssi) continue;
        rdr_order[rdr_orderCount++] = i;
    }
    for (int a = 0; a < rdr_orderCount; a++)
        for (int b = a + 1; b < rdr_orderCount; b++)
            if (rdr_dev[rdr_order[b]].rssi > rdr_dev[rdr_order[a]].rssi + 3) {
                int t = rdr_order[a]; rdr_order[a] = rdr_order[b]; rdr_order[b] = t;
            }
}
static void rdrSelAnchor() {
    if (rdr_orderCount > 0) { memcpy(rdr_anchorMac, rdr_dev[rdr_order[rdr_sel]].mac, 6); rdr_haveAnchor = true; }
}
static void rdrCycleSel(int dir) {
    if (rdr_orderCount == 0) { rdr_sel = 0; return; }
    rdr_sel = (rdr_sel + dir + rdr_orderCount) % rdr_orderCount;
    rdrSelAnchor();
}
static void rdrSelRecover() {
    if (rdr_haveAnchor)
        for (int oi = 0; oi < rdr_orderCount; oi++)
            if (!memcmp(rdr_dev[rdr_order[oi]].mac, rdr_anchorMac, 6)) { rdr_sel = oi; return; }
    if (rdr_sel >= rdr_orderCount) rdr_sel = rdr_orderCount > 0 ? rdr_orderCount - 1 : 0;
    if (rdr_sel < 0) rdr_sel = 0;
}

// ───────────────────────── channel hop ────────────────────────────────────
static const uint8_t RDR_HOP[] = {
    1,6,11, 2, 1,6,11, 3, 1,6,11, 4, 1,6,11, 5, 1,6,11, 7,
    1,6,11, 8, 1,6,11, 9, 1,6,11, 10, 1,6,11, 12, 1,6,11, 13 };
#define RDR_DWELL 120
static void rdrHop() {
    static uint32_t last = 0; static int si = 0; static uint32_t framesAtEntry = 0;
    if (rdr_chanLock) return;
    uint32_t now = millis();
    uint32_t dwell = RDR_DWELL;
    uint32_t seen = rdr_chanFrames[rdr_channel] - framesAtEntry;
    if (seen > 25) dwell = RDR_DWELL * 2; else if (seen == 0 && now - last > 60) dwell = 100;
    if ((int32_t)(rdr_interestUntil - now) > 0 && (now - last) < 1500) return;
    if (now - last < dwell) return;
    last = now;
    si = (si + 1) % (int)sizeof(RDR_HOP);
    rdr_channel = RDR_HOP[si];
    framesAtEntry = rdr_chanFrames[rdr_channel];
    esp_wifi_set_channel(rdr_channel, WIFI_SECOND_CHAN_NONE);
}
static void rdrSetFilter() {
    wifi_promiscuous_filter_t filt = {};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    if (rdr_ctrlCapture) filt.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filt);
}
static void rdrChanStep(int dir) {
    int c = (int)rdr_channel + dir;
    if (c > RDR_CHAN_MAX) c = RDR_CHAN_MIN; if (c < RDR_CHAN_MIN) c = RDR_CHAN_MAX;
    rdr_channel = (uint8_t)c;
    rdr_chanLock = true;
    esp_wifi_set_channel(rdr_channel, WIFI_SECOND_CHAN_NONE);
}
static void rdrLockToDev() {
    if (rdr_orderCount == 0) return;
    RdrDev& d = rdr_dev[rdr_order[rdr_sel]];
    uint8_t c = d.apChannel ? d.apChannel : d.channel;
    if (c >= RDR_CHAN_MIN && c <= RDR_CHAN_MAX) {
        rdr_channel = c; rdr_chanLock = true;
        esp_wifi_set_channel(rdr_channel, WIFI_SECOND_CHAN_NONE);
    }
}
static uint8_t rdrBusiestChannel() {
    uint8_t best = rdr_channel; uint32_t mx = 0;
    for (int c = 1; c <= 13; c++) if (rdr_chanFrames[c] > mx) { mx = rdr_chanFrames[c]; best = c; }
    return best;
}

// ───────────────────────── WiFi sniffer control ───────────────────────────
// WiFi promiscuous bring-up via the Arduino WiFi layer (re-enters cleanly across
// menu round-trips). BLE->WiFi recovery is handled by rebooting on BLE Radar exit.
static void rdrSnifferStart() {
    if (!rdr_queue) rdr_queue = xQueueCreate(RDR_QDEPTH, sizeof(RdrFrame));
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(60);
    rdrSetFilter();
    esp_wifi_set_promiscuous_rx_cb(rdr_sniffer_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(rdr_channel, WIFI_SECOND_CHAN_NONE);
}

// ───────────────────────── pcap -> Wireshark (USB-CDC) ────────────────────
static inline void rdrLe16(uint8_t* b, uint16_t v) { b[0]=v; b[1]=v>>8; }
static inline void rdrLe32(uint8_t* b, uint32_t v) { b[0]=v; b[1]=v>>8; b[2]=v>>16; b[3]=v>>24; }
static void rdrPcapHeader() {
    uint8_t gh[24];
    rdrLe32(gh+0, 0xa1b2c3d4); rdrLe16(gh+4, 2); rdrLe16(gh+6, 4);
    rdrLe32(gh+8, 0); rdrLe32(gh+12, 0); rdrLe32(gh+16, RDR_PCAP_CAP + 13); rdrLe32(gh+20, rdr_pcapLink);
    Serial.write(gh, 24);
}
static void rdrPcapRecord(const RdrPcap& pf) {
    uint32_t ms = millis();
    static uint8_t buf[16 + 13 + RDR_PCAP_CAP];
    rdrLe32(buf+0, ms/1000); rdrLe32(buf+4, (ms%1000)*1000);
    if (rdr_pcapLink == 256) {              // BLE pseudo-header (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)
        uint8_t* ph = buf + 16;
        ph[0] = pf.channel; ph[1] = (uint8_t)pf.rssi; ph[2] = 0; ph[3] = 0;
        rdrLe32(ph+4, 0x8E89BED6); rdrLe16(ph+8, 0x0013);
        rdrLe32(buf+8, 10 + pf.caplen); rdrLe32(buf+12, 10 + pf.origlen);
        memcpy(buf + 26, pf.data, pf.caplen);
        Serial.write(buf, 26 + pf.caplen);
        return;
    }
    rdrLe32(buf+8, 13 + pf.caplen); rdrLe32(buf+12, 13 + pf.origlen);
    uint8_t* rt = buf + 16;                 // radiotap 13o: Channel + dBm antenna signal
    rt[0]=0; rt[1]=0; rdrLe16(rt+2, 13); rdrLe32(rt+4, 0x28);
    uint16_t ch = pf.channel >= 1 ? pf.channel : 1;
    rdrLe16(rt+8, 2412 + (ch-1)*5); rdrLe16(rt+10, 0x0080);
    rt[12] = (uint8_t)pf.rssi;
    memcpy(buf + 29, pf.data, pf.caplen);
    Serial.write(buf, 29 + pf.caplen);
}
static void rdrPcapDrain() {
    if (!rdr_pcapStream || !rdr_pcapQ) return;
    if (!rdr_pcapHdrSent) { rdrPcapHeader(); rdr_pcapHdrSent = true; }
    RdrPcap pf; int guard = 48;
    while (guard-- > 0 && xQueueReceive(rdr_pcapQ, &pf, 0) == pdTRUE) rdrPcapRecord(pf);
}
static void rdrPcapToggle() {
    if (rdr_pcapStream) { rdr_pcapStream = false; return; }
    if (!rdr_pcapQ) rdr_pcapQ = xQueueCreate(RDR_PCAPQ, sizeof(RdrPcap));
    if (!rdr_pcapQ) return;
    xQueueReset(rdr_pcapQ);
    rdr_pcapHdrSent = false;
    rdr_pcapStream = true;
}

// ───────────────────────── BLE passive scan ───────────────────────────────
static int rdrBleFind(const uint8_t* addr) {
    for (int i = 0; i < rdr_bleCount; i++) if (memcmp(rdr_ble[i].addr, addr, 6) == 0) return i;
    int idx = -1;
    if (rdr_bleCount < RDR_BLE_MAX) idx = rdr_bleCount++;
    else { uint32_t oldest = 0xFFFFFFFF; for (int i = 0; i < rdr_bleCount; i++) if (rdr_ble[i].last_seen < oldest) { oldest = rdr_ble[i].last_seen; idx = i; } }
    memset(&rdr_ble[idx], 0, sizeof(RdrBle));
    memcpy(rdr_ble[idx].addr, addr, 6);
    rdr_ble[idx].angle = (rdrMacHash(addr) % 3600) / 10.0f;
    rdr_ble[idx].rssi = -99;
    rdr_ble[idx].company = 0xFFFF;
    return idx;
}
static void rdrBleEnqueuePcap(const uint8_t* addr, bool rnd, int rssi, const uint8_t* pl, size_t pn) {
    if (!(rdr_pcapStream && rdr_pcapQ && rdr_mode == RDR_MODE_BLE)) return;
    if (pn > 37) pn = 37;
    RdrPcap pf; int o = 0;
    pf.data[o++]=0xD6; pf.data[o++]=0xBE; pf.data[o++]=0x89; pf.data[o++]=0x8E;   // access addr 0x8E89BED6 (LE)
    pf.data[o++]= 0x00 | (rnd ? 0x40 : 0x00);
    pf.data[o++]= (uint8_t)(6 + pn);
    for (int i = 0; i < 6; i++) pf.data[o++] = addr[5 - i];
    if (pn) { memcpy(pf.data + o, pl, pn); o += (int)pn; }
    pf.data[o++]=0; pf.data[o++]=0; pf.data[o++]=0;
    pf.caplen = (uint16_t)o; pf.origlen = (uint16_t)o;
    pf.rssi = (int8_t)rssi; pf.channel = 37;
    if (xQueueSend(rdr_pcapQ, &pf, 0) != pdTRUE) rdr_pcapDropped++;
}
static void rdrBleRecord(const uint8_t* a, uint8_t at, bool rnd, int r, const char* name, uint16_t company) {
    portENTER_CRITICAL(&rdr_bleMux);
    int idx = rdrBleFind(a);
    if (idx >= 0) {
        RdrBle& dev = rdr_ble[idx];
        dev.rssi = dev.adv ? (dev.rssi * 0.7f + r * 0.3f) : r;
        dev.last_seen = millis();
        dev.adv++; dev.active = true; dev.addrType = at; dev.randomAddr = rnd;
        if (name && name[0]) { strncpy(dev.name, name, 20); dev.name[20] = 0; dev.haveName = true; }
        if (company != 0xFFFF) dev.company = company;
    }
    portEXIT_CRITICAL(&rdr_bleMux);
    rdr_bleAdvTotal++; rdr_bleFpsWin++;
}
class RdrBleCb : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice d) override {
        esp_bd_addr_t* na = d.getAddress().getNative();
        uint8_t a[6]; memcpy(a, *na, 6);
        int r = d.getRSSI();
        uint8_t at = (uint8_t)d.getAddressType();
        bool rnd = (at == BLE_ADDR_TYPE_RANDOM || at == BLE_ADDR_TYPE_RPA_RANDOM);
        char nm[21]; nm[0] = 0;
        if (d.haveName()) { std::string n = d.getName(); if (!n.empty()) { size_t k = n.size() > 20 ? 20 : n.size(); memcpy(nm, n.data(), k); nm[k] = 0; } }
        uint16_t company = 0xFFFF;
        if (d.haveManufacturerData()) { std::string m = d.getManufacturerData(); if (m.size() >= 2) company = (uint8_t)m[0] | ((uint8_t)m[1] << 8); }
        rdrBleRecord(a, at, rnd, r, nm, company);
        rdrBleEnqueuePcap(a, rnd, r, d.getPayload(), d.getPayloadLength());
    }
};
static RdrBleCb rdr_bleCb;

// BLE scan is a SEPARATE feature (bleRadarMenu), not an in-session toggle: the
// single 2.4GHz radio is switched WiFi<->BLE only at feature enter/exit, from a
// clean menu state. Switching promiscuous->BLE at runtime crashes the Bluedroid
// coex on this chip; entering BLE from the menu (WiFi not promiscuous) is the
// firmware's known-good path (same as beaconScanMenu).
static void rdrBleStart() {
    WiFi.mode(WIFI_OFF);                         // hand the radio to BLE (beaconScanMenu pattern)
    delay(200);                                  // let the radio settle
    portENTER_CRITICAL(&rdr_bleMux);
    rdr_bleCount = 0; memset(rdr_ble, 0, sizeof(RdrBle) * RDR_BLE_MAX);
    portEXIT_CRITICAL(&rdr_bleMux);
    rdr_bleAdvTotal = 0; rdr_bleFps = 0; rdr_bleFpsWin = 0;
    if (!BLEDevice::getInitialized()) BLEDevice::init("");
    rdr_bleScan = BLEDevice::getScan();
    rdr_bleScan->setAdvertisedDeviceCallbacks(&rdr_bleCb, true);
    rdr_bleScan->setActiveScan(false);          // PASSIVE: no scan requests, no transmit
    rdr_bleScan->setInterval(100);
    rdr_bleScan->setWindow(99);
    rdr_bleScan->start(0, nullptr, false);      // continuous, non-blocking
    rdr_pcapLink = 256;
    rdr_mode = RDR_MODE_BLE;
}
static void rdrBleStop() {
    if (rdr_bleScan) { rdr_bleScan->stop(); rdr_bleScan->clearResults(); }
    rdr_bleScan = nullptr;
    releaseBLE();                               // keep BT controller (deinit corrupts coex -> BLE re-init fails)
}

// ───────────────────────── HUD (240x135) ──────────────────────────────────
#define RDR_W 240
#define RDR_H 135
// scouter palette (RGB565)
#define RDR_C_BG     0x0000
#define RDR_C_GRID   0x0320   // dim green
#define RDR_C_RING   0x05E0   // mid green
#define RDR_C_FG     0x07E0   // phosphor green
#define RDR_C_DIM    0x03E0
#define RDR_C_BEACON 0x07E0   // green
#define RDR_C_PROBE  0x07FF   // cyan
#define RDR_C_DATA   0xFFE0   // yellow
#define RDR_C_CTRL   0x7BEF   // grey
#define RDR_C_MGMT   0xFFFF   // white
#define RDR_C_ATTACK 0xF800   // red
#define RDR_C_SEL    0xFD20   // orange

static float rdrRssiToFrac(float r) {   // strong (close) -> small radius
    float f = (-30.0f - r) / 60.0f;     // r=-30 -> 0 ; r=-90 -> 1
    if (f < 0.08f) f = 0.08f; if (f > 1.0f) f = 1.0f;
    return f;
}
static uint16_t rdrFamColor(uint8_t type, uint8_t sub) {
    if (rdrIsAttack(type, sub)) return RDR_C_ATTACK;
    if (type == 1) return RDR_C_CTRL;
    if (type == 2) return RDR_C_DATA;
    if (type == 0 && sub == 8) return RDR_C_BEACON;
    if (type == 0 && (sub == 4 || sub == 5)) return RDR_C_PROBE;
    return RDR_C_MGMT;
}
static void rdrHeader(LovyanGFX& sp) {
    sp.fillRect(0, 0, RDR_W, 11, RDR_C_BG);
    sp.setTextColor(RDR_C_FG, RDR_C_BG);
    sp.setTextSize(1);
    sp.setCursor(2, 2);
    const char* vn = rdr_view == RDRV_SCOPE ? "RADAR" : rdr_view == RDRV_TYPES ? "TYPES" :
                     rdr_view == RDRV_LIST ? "LIST" : rdr_view == RDRV_CHANS ? "CHANS" :
                     rdr_view == RDRV_BLE ? "BLE" : "DETAIL";
    if (rdr_mode == RDR_MODE_BLE)
        sp.printf("%s  adv/s %lu  dev %d", vn, (unsigned long)rdr_bleFps, rdr_bleCount);
    else
        sp.printf("%s ch%d%s fps%lu d%d", vn, rdr_channel, rdr_chanLock ? "*" : " ",
                  (unsigned long)rdr_fps, rdr_orderCount);
    if (millis() < rdr_attackFlashUntil) { sp.setTextColor(RDR_C_ATTACK, RDR_C_BG); sp.setCursor(RDR_W - 30, 2); sp.print("ATK"); }
    if (rdr_pcapStream) { sp.setTextColor(RDR_C_ATTACK, RDR_C_BG); sp.setCursor(RDR_W - 60, 2); sp.print("REC"); }
    sp.drawFastHLine(0, 10, RDR_W, RDR_C_GRID);
}
static void rdrFooter(LovyanGFX& sp, const char* hint) {
    sp.drawFastHLine(0, RDR_H - 10, RDR_W, RDR_C_GRID);
    sp.setTextColor(RDR_C_DIM, RDR_C_BG);
    sp.setTextSize(1);
    sp.setCursor(2, RDR_H - 8);
    sp.print(hint);
}
static void rdrDrawScope(LovyanGFX& sp) {
    const int cx = 62, cy = 72; const float R = 52;
    for (int k = 1; k <= 3; k++) sp.drawCircle(cx, cy, (int)(R * k / 3), RDR_C_RING);
    sp.drawFastHLine(cx - (int)R, cy, (int)(2 * R), RDR_C_GRID);
    sp.drawFastVLine(cx, cy - (int)R, (int)(2 * R), RDR_C_GRID);
    // sweep line
    float sweep = (millis() % 3000) / 3000.0f * 360.0f * RDR_DEG2RAD;
    sp.drawLine(cx, cy, cx + (int)(sinf(sweep) * R), cy - (int)(cosf(sweep) * R), RDR_C_DIM);
    // blips
    for (int oi = 0; oi < rdr_orderCount; oi++) {
        RdrDev& d = rdr_dev[rdr_order[oi]];
        float a = d.angle * RDR_DEG2RAD, frac = rdrRssiToFrac(d.rssi);
        int bx = cx + (int)(sinf(a) * frac * R), by = cy - (int)(cosf(a) * frac * R);
        uint16_t col = rdrFamColor(d.lastType, d.lastSub);
        if (d.attack) col = RDR_C_ATTACK;
        if (oi == rdr_sel) { sp.drawCircle(bx, by, 4, RDR_C_SEL); sp.fillCircle(bx, by, 2, col); }
        else sp.fillCircle(bx, by, 2, col);
    }
    // right column: stats + selected
    int x = 122, y = 14;
    sp.setTextSize(1);
    sp.setTextColor(RDR_C_BEACON, RDR_C_BG); sp.setCursor(x, y);      sp.printf("BEACON %lu", (unsigned long)rdr_sub[0][8]);
    sp.setTextColor(RDR_C_PROBE,  RDR_C_BG); sp.setCursor(x, y + 11); sp.printf("PROBE  %lu", (unsigned long)(rdr_sub[0][4] + rdr_sub[0][5]));
    sp.setTextColor(RDR_C_DATA,   RDR_C_BG); sp.setCursor(x, y + 22); sp.printf("DATA   %lu", (unsigned long)(rdr_sub[2][0] + rdr_sub[2][8]));
    sp.setTextColor(RDR_C_MGMT,   RDR_C_BG); sp.setCursor(x, y + 33); sp.printf("MGMT   %lu", (unsigned long)(rdr_sub[0][11] + rdr_sub[0][13]));
    sp.setTextColor(RDR_C_ATTACK, RDR_C_BG); sp.setCursor(x, y + 44); sp.printf("ATK    %lu", (unsigned long)rdr_attackCount);
    if (rdr_orderCount > 0) {
        RdrDev& d = rdr_dev[rdr_order[rdr_sel]];
        sp.setTextColor(RDR_C_SEL, RDR_C_BG);
        sp.setCursor(x, y + 58);
        const char* nm = d.hidden ? "<hidden>" : (d.ssid[0] ? d.ssid : "");
        if (nm[0]) sp.printf("%.12s", nm);
        else sp.printf("%02X%02X%02X", d.mac[3], d.mac[4], d.mac[5]);
        sp.setTextColor(RDR_C_FG, RDR_C_BG);
        sp.setCursor(x, y + 69); sp.printf("%ddBm c%d", (int)d.rssi, d.apChannel ? d.apChannel : d.channel);
        sp.setCursor(x, y + 80); sp.printf("%s%s%s", rdrEncName(d.enc), d.eapol ? " EAP" : "", d.attack ? " !!" : "");
    }
    rdrFooter(sp, ";. aim  ,/ ch  v:view  ent:info  bk:exit");
}
static void rdrDrawTypes(LovyanGFX& sp) {
    int y = 14;
    sp.setTextSize(1);
    sp.setTextColor(RDR_C_FG, RDR_C_BG);
    sp.setCursor(2, y); sp.printf("Total %lu   Dropped %lu", (unsigned long)rdr_totalFrames, (unsigned long)rdr_dropped);
    y += 12;
    struct { const char* n; uint32_t v; uint16_t c; } rows[] = {
        {"Beacon",   rdr_sub[0][8],  RDR_C_BEACON},
        {"ProbeReq", rdr_sub[0][4],  RDR_C_PROBE},
        {"ProbeRsp", rdr_sub[0][5],  RDR_C_PROBE},
        {"Auth/Asc", rdr_sub[0][11] + rdr_sub[0][0] + rdr_sub[0][1], RDR_C_MGMT},
        {"Data",     rdr_sub[2][0] + rdr_sub[2][8], RDR_C_DATA},
        {"Deauth",   rdr_sub[0][12], RDR_C_ATTACK},
        {"Disassoc", rdr_sub[0][10], RDR_C_ATTACK},
    };
    uint32_t mx = 1;
    for (auto& r : rows) if (r.v > mx) mx = r.v;
    for (auto& r : rows) {
        sp.setTextColor(r.c, RDR_C_BG);
        sp.setCursor(2, y); sp.printf("%-9s%6lu", r.n, (unsigned long)r.v);
        int bw = (int)((RDR_W - 120) * r.v / mx);
        sp.fillRect(118, y, bw, 7, r.c);
        y += 11;
    }
    rdrFooter(sp, "v:view  bk:back");
}
static void rdrDrawList(LovyanGFX& sp) {
    int rows = 9, top = rdr_sel - rows / 2;
    if (top > rdr_orderCount - rows) top = rdr_orderCount - rows;
    if (top < 0) top = 0;
    sp.setTextSize(1);
    for (int i = 0; i < rows; i++) {
        int oi = top + i; if (oi >= rdr_orderCount) break;
        RdrDev& d = rdr_dev[rdr_order[oi]];
        int y = 13 + i * 12;
        bool selrow = (oi == rdr_sel);
        if (selrow) sp.fillRect(0, y - 1, RDR_W, 11, 0x1082);
        uint16_t col = d.attack ? RDR_C_ATTACK : rdrFamColor(d.lastType, d.lastSub);
        sp.setTextColor(selrow ? RDR_C_SEL : col, selrow ? 0x1082 : RDR_C_BG);
        sp.setCursor(2, y);
        const char* nm = d.hidden ? "<hidden>" : (d.ssid[0] ? d.ssid : "");
        char tag[13];
        if (nm[0]) snprintf(tag, sizeof(tag), "%.12s", nm);
        else snprintf(tag, sizeof(tag), "%02X:%02X:%02X:%02X", d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
        sp.printf("%-13s%4d c%-2d %-4s%s%s", tag, (int)d.rssi, d.apChannel ? d.apChannel : d.channel,
                  rdrEncName(d.enc), d.eapol ? "E" : "", d.attack ? "!" : "");
    }
    rdrFooter(sp, ";. sel  ent:detail  v:view  bk:back");
}
static void rdrDrawChans(LovyanGFX& sp) {
    sp.setTextSize(1);
    sp.setTextColor(RDR_C_FG, RDR_C_BG);
    sp.setCursor(2, 13); sp.printf("Channels  minRSSI %d  %s", rdr_minRssi, rdr_paused ? "PAUSED" : "");
    uint32_t mx = 1;
    for (int c = 1; c <= 13; c++) if (rdr_chanFrames[c] > mx) mx = rdr_chanFrames[c];
    int x0 = 6, bw = 16, base = RDR_H - 14;
    for (int c = 1; c <= 13; c++) {
        int x = x0 + (c - 1) * (bw + 1);
        int h = (int)((base - 28) * rdr_chanFrames[c] / mx);
        sp.fillRect(x, base - h, bw, h, rdr_chanAtk[c] ? RDR_C_ATTACK : RDR_C_RING);
        sp.setTextColor(c == rdr_channel ? RDR_C_SEL : RDR_C_DIM, RDR_C_BG);
        sp.setCursor(x, base + 1); sp.printf("%d", c);
    }
    rdrFooter(sp, ";. rssi  ent:pause  c:ctrl  v:view");
}
static void rdrDrawBle(LovyanGFX& sp) {
    const int cx = 62, cy = 72; const float R = 52;
    for (int k = 1; k <= 3; k++) sp.drawCircle(cx, cy, (int)(R * k / 3), RDR_C_RING);
    sp.drawFastHLine(cx - (int)R, cy, (int)(2 * R), RDR_C_GRID);
    sp.drawFastVLine(cx, cy - (int)R, (int)(2 * R), RDR_C_GRID);
    float sweep = (millis() % 3000) / 3000.0f * 360.0f * RDR_DEG2RAD;   // rotating scan line
    sp.drawLine(cx, cy, cx + (int)(sinf(sweep) * R), cy - (int)(cosf(sweep) * R), RDR_C_DIM);
    portENTER_CRITICAL(&rdr_bleMux);
    uint32_t now = millis();
    for (int i = 0; i < rdr_bleCount; i++) {
        RdrBle& b = rdr_ble[i];
        if (now - b.last_seen > RDR_DEV_TIMEOUT) continue;
        float a = b.angle * RDR_DEG2RAD, frac = rdrRssiToFrac(b.rssi);
        int bx = cx + (int)(sinf(a) * frac * R), by = cy - (int)(cosf(a) * frac * R);
        sp.fillCircle(bx, by, 2, b.randomAddr ? RDR_C_PROBE : RDR_C_BEACON);
    }
    // nearest few by RSSI (simple top list)
    int x = 122, y = 14, shown = 0;
    sp.setTextSize(1);
    for (int pass = 0; pass < 6 && shown < 6; pass++) {
        int best = -1; float br = -200;
        for (int i = 0; i < rdr_bleCount; i++) {
            if (now - rdr_ble[i].last_seen > RDR_DEV_TIMEOUT) continue;
            bool used = false;
            for (int s = 0; s < shown; s++) if (rdr_order[s] == i) used = true;   // reuse rdr_order as scratch
            if (!used && rdr_ble[i].rssi > br) { br = rdr_ble[i].rssi; best = i; }
        }
        if (best < 0) break;
        rdr_order[shown] = best;
        RdrBle& b = rdr_ble[best];
        sp.setTextColor(b.randomAddr ? RDR_C_PROBE : RDR_C_BEACON, RDR_C_BG);
        sp.setCursor(x, y + shown * 11);
        if (b.haveName && b.name[0]) sp.printf("%.9s %d", b.name, (int)b.rssi);
        else sp.printf("%02X%02X %d", b.addr[4], b.addr[5], (int)b.rssi);
        shown++;
    }
    portEXIT_CRITICAL(&rdr_bleMux);
    rdrFooter(sp, "passive BLE scan   p:pcap   bk:exit");
}
static void rdrDrawDetail(LovyanGFX& sp) {
    int idx = -1;
    if (rdr_haveDetail) for (int i = 0; i < rdr_devCount; i++) if (!memcmp(rdr_dev[i].mac, rdr_detailMac, 6)) { idx = i; break; }
    sp.setTextSize(1);
    if (idx < 0) { sp.setTextColor(RDR_C_DIM, RDR_C_BG); sp.setCursor(4, 50); sp.print("device lost"); rdrFooter(sp, "bk back"); return; }
    RdrDev& d = rdr_dev[idx];
    int y = 14;
    sp.setTextColor(RDR_C_SEL, RDR_C_BG);  sp.setCursor(2, y); sp.printf("%s", d.hidden ? "<hidden>" : (d.ssid[0] ? d.ssid : "(no SSID)")); y += 12;
    sp.setTextColor(RDR_C_FG, RDR_C_BG);
    sp.setCursor(2, y); sp.printf("%02X:%02X:%02X:%02X:%02X:%02X", d.mac[0],d.mac[1],d.mac[2],d.mac[3],d.mac[4],d.mac[5]); y += 11;
    sp.setCursor(2, y); sp.printf("RSSI %ddBm  ch %d (rx%d)", (int)d.rssi, d.apChannel ? d.apChannel : d.channel, d.channel); y += 11;
    sp.setCursor(2, y); sp.printf("Enc %s   Frames %lu", rdrEncName(d.enc), (unsigned long)d.frames); y += 11;
    sp.setCursor(2, y); sp.printf("mgmt %u ctrl %u data %u atk %u", d.fam[0], d.fam[1], d.fam[2], d.fam[3]); y += 11;
    if (d.eapol) {
        sp.setTextColor(RDR_C_DATA, RDR_C_BG); sp.setCursor(2, y);
        sp.printf("EAPOL M1%c M2%c M3%c M4%c",
                  d.eapolMsgs&1?'+':'-', d.eapolMsgs&2?'+':'-', d.eapolMsgs&4?'+':'-', d.eapolMsgs&8?'+':'-'); y += 11;
    }
    if (d.attack && d.hasTarget) {
        sp.setTextColor(RDR_C_ATTACK, RDR_C_BG); sp.setCursor(2, y);
        sp.printf("ATK -> %02X:%02X:%02X:%02X:%02X:%02X", d.target[0],d.target[1],d.target[2],d.target[3],d.target[4],d.target[5]);
    }
    rdrFooter(sp, ";. next  ent lock  bk back");
}
static void rdrDrawSplash(LovyanGFX& sp) {
    sp.setTextColor(RDR_C_FG, RDR_C_BG);
    sp.setTextSize(2); sp.setCursor(44, 48); sp.print("WiFi RADAR");
    sp.setTextSize(1); sp.setTextColor(RDR_C_DIM, RDR_C_BG);
    sp.setCursor(40, 76); sp.print("passive 802.11 + BLE scouter");
}
static void rdrRender(M5Canvas* spr, bool use_sprite) {
    LovyanGFX& sp = use_sprite ? (LovyanGFX&)*spr : (LovyanGFX&)M5.Display;
    sp.fillScreen(RDR_C_BG);
    if (rdr_view != RDRV_SPLASH) rdrHeader(sp);
    switch (rdr_view) {
        case RDRV_SPLASH: rdrDrawSplash(sp); break;
        case RDRV_SCOPE:  rdrDrawScope(sp);  break;
        case RDRV_TYPES:  rdrDrawTypes(sp);  break;
        case RDRV_LIST:   rdrDrawList(sp);   break;
        case RDRV_CHANS:  rdrDrawChans(sp);  break;
        case RDRV_BLE:    rdrDrawBle(sp);    break;
        case RDRV_DETAIL: rdrDrawDetail(sp); break;
    }
    if (use_sprite) spr->pushSprite(0, 0);
}

// ───────────────────────── input / app logic ──────────────────────────────
static void rdrOpenDetail() {
    if (rdr_orderCount > 0) { memcpy(rdr_detailMac, rdr_dev[rdr_order[rdr_sel]].mac, 6); rdr_haveDetail = true; rdr_prevView = rdr_view; rdr_view = RDRV_DETAIL; }
}
static void rdrCycleView() {   // SCOPE -> TYPES -> LIST -> CHANS -> SCOPE (BLE is a separate feature)
    switch (rdr_view) {
        case RDRV_SCOPE: rdr_view = RDRV_TYPES; break;
        case RDRV_TYPES: rdr_view = RDRV_LIST;  break;
        case RDRV_LIST:  rdr_view = RDRV_CHANS; break;
        case RDRV_CHANS: rdr_view = RDRV_SCOPE; break;
        default:         rdr_view = RDRV_SCOPE; break;
    }
}
// returns false when the feature should exit to the menu
static bool rdrHandleInput() {
    static uint32_t lastKey = 0; const uint32_t deb = 180;
    uint32_t now = millis();
    bool gated = (now - lastKey) > deb;
    auto hit = [&](uint8_t k) -> bool { if (gated && kp(k)) { lastKey = now; return true; } return false; };

    if (rdr_view == RDRV_SPLASH) {
        if (now > rdr_splashUntil || kpAny()) rdr_view = RDRV_SCOPE;
        return true;
    }
    if (hit(KEY_BACKSPACE)) {
        if (rdr_view == RDRV_DETAIL) { rdr_view = rdr_prevView; return true; }
        if (rdr_view != RDRV_SCOPE) { rdr_view = RDRV_SCOPE; return true; }
        return false;   // exit from the scope view
    }
    if (hit('p')) rdrPcapToggle();
    if (hit('a')) rdr_alertOn = !rdr_alertOn;

    switch (rdr_view) {
        case RDRV_SCOPE:
            if (hit(';')) rdrCycleSel(-1);
            if (hit('.')) rdrCycleSel(+1);
            if (hit(',')) rdrChanStep(-1);
            if (hit('/')) rdrChanStep(+1);
            if (hit('h')) { rdr_chanLock = false; }
            if (hit('r')) { rdr_devCount = 0; rdr_totalFrames = 0; rdr_attackCount = 0; memset(rdr_sub, 0, sizeof(rdr_sub)); memset(rdr_chanFrames, 0, sizeof(rdr_chanFrames)); memset(rdr_chanAtk, 0, sizeof(rdr_chanAtk)); }
            if (hit(KEY_ENTER)) rdrOpenDetail();
            if (hit('v')) rdrCycleView();
            break;
        case RDRV_TYPES:
            if (hit(KEY_ENTER) || hit('v')) rdrCycleView();
            break;
        case RDRV_LIST:
            if (hit(';')) rdrCycleSel(-1);
            if (hit('.')) rdrCycleSel(+1);
            if (hit(KEY_ENTER)) rdrOpenDetail();
            if (hit('v')) rdrCycleView();
            if (hit('/')) rdrCycleView();
            break;
        case RDRV_CHANS:
            if (hit(';')) { rdr_minRssi += 5; if (rdr_minRssi > -40) rdr_minRssi = -40; }
            if (hit('.')) { rdr_minRssi -= 5; if (rdr_minRssi < -99) rdr_minRssi = -99; }
            if (hit('c')) { rdr_ctrlCapture = !rdr_ctrlCapture; rdrSetFilter(); }
            if (hit('x')) { rdr_dropEncData = !rdr_dropEncData; }
            if (hit(KEY_ENTER)) rdr_paused = !rdr_paused;
            if (hit('v')) rdrCycleView();
            break;
        case RDRV_DETAIL:
            if (hit(';')) { rdrCycleSel(-1); if (rdr_orderCount > 0) memcpy(rdr_detailMac, rdr_dev[rdr_order[rdr_sel]].mac, 6); }
            if (hit('.')) { rdrCycleSel(+1); if (rdr_orderCount > 0) memcpy(rdr_detailMac, rdr_dev[rdr_order[rdr_sel]].mac, 6); }
            if (hit(KEY_ENTER)) rdrLockToDev();
            break;
        default: break;
    }
    return true;
}

// extcap control (Wireshark): S start stream, X stop, Q quit. The radio mode is
// fixed by the active feature (WiFi Radar or BLE Radar), so the extcap's W/B
// interface-select bytes are accepted and ignored (pick the matching interface).
static void rdrPollSerialCmd() {
    while (Serial.available()) {
        int c = Serial.read();
        if (c == 'S') {
            if (!rdr_pcapQ) rdr_pcapQ = xQueueCreate(RDR_PCAPQ, sizeof(RdrPcap));
            if (rdr_pcapQ) { xQueueReset(rdr_pcapQ); rdr_pcapHdrSent = false; rdr_pcapStream = true; }
        } else if (c == 'X') {
            rdr_pcapStream = false;
        } else if (c == 'Q') {
            rdr_quit = true;       // clean exit to the menu
        }
        // 'W'/'B' ignored: radio is fixed per feature
    }
}

// Allocate the 240x135 sprite ONCE, on first radar entry (heap still contiguous),
// and keep it for the rest of the session. BLE fragments the heap, so a per-entry
// createSprite fails afterwards (falls back to direct draw = flicker); reusing one
// persistent sprite avoids that entirely.
static void rdrSpriteEnsure() {
    if (rdr_spr) return;
    rdr_spr = new (std::nothrow) M5Canvas(&M5.Display);
    if (rdr_spr) {
        rdr_spr->setColorDepth(8);
        rdr_sprOk = rdr_spr->createSprite(RDR_W, RDR_H);
        if (!rdr_sprOk) { delete rdr_spr; rdr_spr = nullptr; }
    }
}

// ───────────────────────── entry point (menu case) ────────────────────────
void wifiRadarMenu() {
    // allocate working set on entry (freed on exit) - nothing reserved at boot
    rdr_dev = (RdrDev*)calloc(RDR_MAX_DEV, sizeof(RdrDev));
    rdr_ble = nullptr;                   // BLE table only used by bleRadarMenu
    if (!rdr_dev) { waitAndReturnToMenu("WiFi Radar: out of memory"); return; }
    rdr_devCount = 0; rdr_bleCount = 0; rdr_orderCount = 0; rdr_sel = 0;
    rdr_totalFrames = rdr_attackCount = 0; rdr_dropped = rdr_pcapDropped = 0;
    memset(rdr_sub, 0, sizeof(rdr_sub)); memset(rdr_chanFrames, 0, sizeof(rdr_chanFrames)); memset(rdr_chanAtk, 0, sizeof(rdr_chanAtk));
    rdr_channel = 1; rdr_chanLock = false; rdr_paused = false; rdr_minRssi = -99;
    rdr_haveAnchor = rdr_haveDetail = false; rdr_pcapStream = false; rdr_mode = RDR_MODE_WIFI; rdr_quit = false;
    rdr_view = RDRV_SPLASH; rdr_splashUntil = millis() + 1500; rdr_fpsT0 = millis();

    M5.Display.clear();
    rdrSpriteEnsure();
    M5Canvas* sprite = rdr_spr; bool use_sprite = rdr_sprOk;

    // pcap linktype back to WiFi (a prior BLE session set 256), then arm promiscuous
    rdr_pcapLink = 127;
    rdrSnifferStart();

    enterDebounce();
    uint32_t lastDraw = 0;
    bool running = true;
    while (running) {
        esp_task_wdt_reset();
        // this feature owns the serial line (pcap stream + extcap control), so it
        // drives the keyboard directly instead of cardUpdate()'s web/serial pump
        M5.update(); M5Cardputer.update();
        rdrPollSerialCmd();                  // extcap S/X/Q

        if (!rdr_paused) { rdrHop(); rdrDrainQueue(); rdrRebuildOrder(); rdrSelRecover(); }
        rdrPcapDrain();
        if (rdr_beepPending) { rdr_beepPending = false; M5.Speaker.tone(2000, 60); }

        running = rdrHandleInput() && !rdr_quit;

        uint32_t now = millis();
        if (now - lastDraw >= 90) { lastDraw = now; rdrRender(sprite, use_sprite); }
        delay(5);
    }

    // teardown: stop promiscuous, hand WiFi back to the menu (Arduino-managed)
    rdr_pcapStream = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    WiFi.mode(WIFI_OFF);
    delay(80);

    if (rdr_queue) { vQueueDelete(rdr_queue); rdr_queue = nullptr; }
    if (rdr_pcapQ) { vQueueDelete(rdr_pcapQ); rdr_pcapQ = nullptr; }
    free(rdr_dev); rdr_dev = nullptr;   // sprite is kept (rdr_spr) for reuse

    if (rdr_quit) { inMenu = true; M5.Display.clear(); }   // serial Q: silent return to menu
    else waitAndReturnToMenu("WiFi Radar stopped");
}


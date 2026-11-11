// ===========================================================================
// ChameleonUltra BLE client (Bluedroid central) — Phase 1: transport + console
// ---------------------------------------------------------------------------
// The Evil firmware is built on the Bluedroid BLE host (BLEDevice.h), not
// NimBLE, so this is a native-Bluedroid port of the ChameleonUltra link:
//   * scan for a peripheral advertising name "ChameleonUltra" (or the NUS svc)
//   * connect, discover the Nordic UART Service, hook write + notify chars
//   * frame the ChameleonUltra command protocol and drive it over serial
//
// Protocol (verified against RfidResearchGroup/ChameleonUltra chameleon_com.py):
//   frame = 11 | LRC1 | CMD(2 BE) | STATUS(2 BE) | LEN(2 BE) | LRC2 | DATA | LRC3
//   LRC(range) = (0x100 - (sum(range) & 0xFF)) & 0xFF   (makes running sum 0)
//   LRC1 covers byte0; LRC2 covers bytes 0..7; LRC3 covers bytes 0..8+LEN.
//
// The Chameleon's NUS characteristics are open (no pairing needed to read/
// write/subscribe), confirmed by the M5Shark and ESP-ChameleonUltra clients
// which connect with no security setup. Bonding/MITM in the Chameleon firmware
// guards other services, not the UART. So a plain connect + subscribe works.
// ===========================================================================
#pragma once
// isBLEInitialized is a file-scope global in the main .ino, already in scope at
// the point this header is #included (near the other src/ NFC headers).

namespace chameleon {

// Nordic UART Service (modern firmware).
static const char* CU_SVC    = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
static const char* CU_WRITE  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";  // host -> device (write)
static const char* CU_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";  // device -> host (notify)

// Command IDs (chameleon_enum.py).
enum {
  CMD_GET_APP_VERSION      = 1000,
  CMD_CHANGE_DEVICE_MODE   = 1001,   // data: 1 byte (0=tag/emulate, 1=reader)
  CMD_GET_DEVICE_MODE      = 1002,
  CMD_SET_ACTIVE_SLOT      = 1003,   // data: 1 byte slot (0..7)
  CMD_SET_SLOT_TAG_TYPE    = 1004,
  CMD_GET_DEVICE_CHIP_ID   = 1011,
  CMD_GET_ACTIVE_SLOT      = 1018,
  CMD_GET_BATTERY_INFO     = 1025,   // resp: voltage(u16 BE mV) + percent(u8)
  CMD_HF14A_SCAN           = 2000,
  CMD_MF1_AUTH_ONE_KEY     = 2007,
  CMD_MF1_READ_ONE_BLOCK   = 2008,
  CMD_MF1_WRITE_ONE_BLOCK  = 2009,
  CMD_HF14A_RAW            = 2010,
  CMD_EM410X_SCAN          = 3000,
  CMD_MF1_WRITE_EMU_BLOCK  = 4000,
  CMD_HF14A_SET_ANTI_COLL  = 4001,
  CMD_MF1_READ_EMU_BLOCK   = 4008,
  CMD_HF14A_GET_ANTI_COLL  = 4018,
};

// ---- connection state -----------------------------------------------------
static BLEClient* cu_client = nullptr;   // reused, never deleted (Bluedroid UAF)
static BLERemoteCharacteristic* cu_write  = nullptr;
static BLERemoteCharacteristic* cu_notify = nullptr;
static bool cu_ready = false;
static BLEAdvertisedDevice cu_dev; static bool cu_found = false;

// ---- BLE security (ChameleonUltra fw requires LESC + MITM + bonding) -------
// The Chameleon's NUS characteristics need an encrypted link. The peripheral is
// DisplayOnly with a static 6-digit passkey (the "bind password" set in the
// app); we are the central and input it. IO cap = KeyboardOnly -> Passkey Entry.
static uint32_t cu_pin = 123456;                 // bind password (factory default; set via `pin`)
static volatile bool cu_auth_done = false, cu_auth_ok = false;

class ChamSecCB : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() override { Serial.printf("[cham] passkey request -> %06lu\n", (unsigned long)cu_pin); return cu_pin; }
  void onPassKeyNotify(uint32_t pk) override { Serial.printf("[cham] passkey notify %06lu\n", (unsigned long)pk); }
  bool onSecurityRequest() override { return true; }
  bool onConfirmPIN(uint32_t pin) override { Serial.printf("[cham] confirm pin %06lu (accept)\n", (unsigned long)pin); return true; }
  void onAuthenticationComplete(esp_ble_auth_cmpl_t a) override {
    cu_auth_ok = a.success; cu_auth_done = true;
    Serial.printf("[cham] auth %s%s\n", a.success ? "OK" : "FAIL", a.success ? "" : " (wrong PIN / bond mismatch?)");
  }
};
static void cu_sec_setup() {
  static bool done = false;
  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT_MITM);
  if (!done) { static ChamSecCB scb; BLEDevice::setSecurityCallbacks(&scb); done = true; }
  BLESecurity sec;
  sec.setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND);   // LESC + MITM + bonding
  sec.setCapability(ESP_IO_CAP_IN);                          // keyboard: input peripheral's passkey
  sec.setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
  sec.setRespEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
  sec.setKeySize(16);
}

// ---- RX frame assembly (notify callback appends; parser extracts frames) --
// Buffers are heap-allocated on connect and freed on disconnect, so the feature
// costs ~0 static RAM at boot / in the main menu.
static const int CU_RXBUF = 600;
static uint8_t* cu_rx = nullptr; static volatile uint16_t cu_rx_len = 0;
static uint16_t cu_resp_cmd = 0, cu_resp_status = 0, cu_resp_dlen = 0;
static uint8_t* cu_resp_data = nullptr;
static volatile bool cu_resp_ready = false;
static uint8_t cu_last_em[5]; static bool cu_have_em = false;   // last EM410x id (LF)

static uint8_t cu_lrc(const uint8_t* p, int n) {
  uint16_t s = 0; for (int i = 0; i < n; i++) s += p[i];
  return (uint8_t)((0x100 - (s & 0xFF)) & 0xFF);
}
static void cu_drop(int k) {   // consume k bytes from the head of cu_rx
  if (k <= 0) return; if (k >= cu_rx_len) { cu_rx_len = 0; return; }
  memmove(cu_rx, cu_rx + k, cu_rx_len - k); cu_rx_len -= k;
}
static void cu_try_parse() {
  if (!cu_rx || !cu_resp_data) return;
  for (;;) {
    while (cu_rx_len >= 1 && cu_rx[0] != 0x11) cu_drop(1);     // resync to SOF
    if (cu_rx_len < 10) return;                                // header(9)+LRC3(1)
    if (cu_rx[1] != cu_lrc(cu_rx, 1)) { cu_drop(1); continue; }
    if (cu_rx[8] != cu_lrc(cu_rx, 8)) { cu_drop(1); continue; }
    uint16_t cmd = (cu_rx[2] << 8) | cu_rx[3];
    uint16_t st  = (cu_rx[4] << 8) | cu_rx[5];
    uint16_t dl  = (cu_rx[6] << 8) | cu_rx[7];
    if (dl > 512) { cu_drop(1); continue; }
    uint16_t total = 9 + dl + 1;
    if (cu_rx_len < total) return;                             // wait for the rest
    if (cu_rx[9 + dl] != cu_lrc(cu_rx, 9 + dl)) { cu_drop(1); continue; }
    cu_resp_cmd = cmd; cu_resp_status = st; cu_resp_dlen = dl;
    memcpy(cu_resp_data, cu_rx + 9, dl);
    cu_resp_ready = true;
    cu_drop(total);
    return;
  }
}
static void cu_notify_cb(BLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  if (!cu_rx) return;
  for (size_t i = 0; i < len && cu_rx_len < CU_RXBUF; i++) cu_rx[cu_rx_len++] = data[i];
  cu_try_parse();
}

// Build + send one command frame, then wait (polled) for the matching reply.
static bool cu_cmd(uint16_t cmd, const uint8_t* data, uint16_t dlen, uint32_t to_ms = 1500) {
  if (!cu_ready || !cu_write) return false;
  if (dlen > 512) return false;
  uint8_t f[600]; int n = 0;
  f[n++] = 0x11; f[n++] = 0x00;                 // SOF, LRC1 (filled below)
  f[n++] = cmd >> 8; f[n++] = cmd & 0xFF;
  f[n++] = 0x00; f[n++] = 0x00;                 // status = 0 (host->device)
  f[n++] = dlen >> 8; f[n++] = dlen & 0xFF;
  f[n++] = 0x00;                                // LRC2 (filled below)
  if (data && dlen) { memcpy(f + n, data, dlen); n += dlen; }
  f[n++] = 0x00;                                // LRC3 (filled below)
  f[1] = cu_lrc(f, 1);
  f[8] = cu_lrc(f, 8);
  f[9 + dlen] = cu_lrc(f, 9 + dlen);
  cu_resp_ready = false; cu_rx_len = 0;
  cu_write->writeValue(f, n, true);             // write with response (matches Evil GATT path)
  uint32_t t0 = millis();
  while (!cu_resp_ready && millis() - t0 < to_ms) delay(5);
  return cu_resp_ready;
}

// ---- scan + connect -------------------------------------------------------
class ChamScanCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice d) override {
    if (cu_found) return;
    String nm = d.haveName() ? String(d.getName().c_str()) : String();
    bool match = nm.startsWith("ChameleonUltra");
    if (!match && d.haveServiceUUID() && d.isAdvertisingService(BLEUUID(CU_SVC))) match = true;
    if (match) { cu_dev = d; cu_found = true; }
  }
};

// Diagnostic: list every advertising BLE device seen in one scan window.
class ChamListCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice d) override {
    String nm = d.haveName() ? String(d.getName().c_str()) : String("(no name)");
    bool cham = nm.startsWith("ChameleonUltra") || (d.haveServiceUUID() && d.isAdvertisingService(BLEUUID(CU_SVC)));
    Serial.printf("  %s  rssi=%d  %s%s\n", d.getAddress().toString().c_str(), d.getRSSI(),
                  nm.c_str(), cham ? "   <== CHAMELEON" : "");
  }
};
static void cu_scanlist(uint32_t scan_s = 8) {
  WiFi.mode(WIFI_OFF); delay(30);
  if (!BLEDevice::getInitialized()) BLEDevice::init("");
  isBLEInitialized = true;
  BLEScan* scan = BLEDevice::getScan();
  static ChamListCB cb; scan->setAdvertisedDeviceCallbacks(&cb, true);
  scan->setActiveScan(true); scan->setInterval(100); scan->setWindow(99);
  Serial.printf("[cham] scanlist %lus (all BLE; press the Chameleon button to wake it)...\n", (unsigned long)scan_s);
  scan->start(scan_s, false); scan->stop(); scan->clearResults();
  Serial.println("[cham] scanlist done");
}

static bool cu_connect(uint32_t scan_s = 5) {
  WiFi.mode(WIFI_OFF); delay(30);
  if (!BLEDevice::getInitialized()) BLEDevice::init("");
  isBLEInitialized = true;
  cu_sec_setup();                       // LESC + MITM + bonding, passkey = cu_pin
  cu_found = false;
  BLEScan* scan = BLEDevice::getScan();
  static ChamScanCB cb; scan->setAdvertisedDeviceCallbacks(&cb, true);
  scan->setActiveScan(true); scan->setInterval(100); scan->setWindow(99);
  Serial.printf("[cham] scanning %lus for ChameleonUltra...\n", (unsigned long)scan_s);
  scan->start(scan_s, false); scan->stop(); scan->clearResults();
  if (!cu_found) { Serial.println("[cham] not found (BLE on? powered?)"); return false; }
  Serial.printf("[cham] found %s\n", cu_dev.getAddress().toString().c_str());
  if (!cu_client) cu_client = BLEDevice::createClient();
  if (cu_client->isConnected()) { cu_client->disconnect(); for (int i = 0; i < 50 && cu_client->isConnected(); i++) delay(20); }
  delay(60);
  if (!cu_client->connect(&cu_dev)) { Serial.println("[cham] connect failed"); return false; }
  cu_client->setMTU(247); delay(150);
  // Pair + encrypt the link (NUS chars require it). Peripheral asks for the
  // passkey; onPassKeyRequest() supplies cu_pin.
  cu_auth_done = false; cu_auth_ok = false;
  Serial.printf("[cham] pairing (PIN %06lu)...\n", (unsigned long)cu_pin);
  esp_ble_set_encryption(*cu_dev.getAddress().getNative(), ESP_BLE_SEC_ENCRYPT_MITM);
  { uint32_t t0 = millis(); while (!cu_auth_done && millis() - t0 < 12000) delay(20); }
  if (!cu_auth_ok) {
    Serial.printf("[cham] pairing failed with PIN %06lu\n", (unsigned long)cu_pin);
    Serial.println("[cham] -> set your bind password:  chameleon pin <your 6-digit code>");
    Serial.println("[cham] -> then reconnect:          chameleon connect");
    Serial.println("[cham]    (code is in the ChameleonUltra app > Settings > BLE pairing)");
    esp_ble_remove_bond_device(*cu_dev.getAddress().getNative());  // drop stale bond before retry
    cu_client->disconnect(); return false;
  }
  delay(200);
  BLERemoteService* svc = cu_client->isConnected() ? cu_client->getService(BLEUUID(CU_SVC)) : nullptr;
  if (!svc) { Serial.println("[cham] no NUS service"); cu_client->disconnect(); return false; }
  cu_write  = svc->getCharacteristic(BLEUUID(CU_WRITE));
  cu_notify = svc->getCharacteristic(BLEUUID(CU_NOTIFY));
  if (!cu_write || !cu_notify) { Serial.println("[cham] NUS chars missing"); cu_client->disconnect(); return false; }
  if (!cu_rx) cu_rx = (uint8_t*)malloc(CU_RXBUF);
  if (!cu_resp_data) cu_resp_data = (uint8_t*)malloc(CU_RXBUF);
  if (!cu_rx || !cu_resp_data) { Serial.println("[cham] OOM (rx bufs)"); cu_client->disconnect(); return false; }
  cu_rx_len = 0; cu_resp_ready = false;
  cu_notify->registerForNotify(cu_notify_cb);
  cu_ready = true;
  Serial.println("[cham] connected + NUS ready");
  return true;
}
static void cu_disconnect() {
  cu_ready = false;
  if (cu_notify) cu_notify->registerForNotify(nullptr);   // stop callbacks first
  cu_write = cu_notify = nullptr;
  if (cu_client && cu_client->isConnected()) cu_client->disconnect();
  if (cu_rx) { free(cu_rx); cu_rx = nullptr; }             // then free (no boot RAM cost)
  if (cu_resp_data) { free(cu_resp_data); cu_resp_data = nullptr; }
  Serial.println("[cham] disconnected");
}
static bool cu_is_connected() { return cu_ready && cu_client && cu_client->isConnected(); }

// Full BLE teardown: disconnect, delete the client, deinit the host so the big
// BT heap region is returned (otherwise the Cap NFC 32 KB sprite can't alloc).
// release=true also frees the BT controller memory (max heap back, but BLE
// cannot be re-inited until reboot).
static void cu_shutdown(bool release) {
  cu_disconnect();
  // Do NOT delete the Bluedroid BLEClient (deleting it is the known UAF); just
  // drop our pointer so the next connect makes a fresh one. The old object is
  // leaked (~hundreds of bytes) but deinit reclaims the big BT heap region.
  cu_client = nullptr;
  if (BLEDevice::getInitialized()) BLEDevice::deinit(release);
}

// ---- high-level helpers ---------------------------------------------------
static void cu_print_resp_hex(const char* tag) {
  Serial.printf("  %s status=%04X len=%u:", tag, cu_resp_status, cu_resp_dlen);
  for (int i = 0; i < cu_resp_dlen; i++) Serial.printf(" %02X", cu_resp_data[i]);
  Serial.println();
}
static bool cu_version() {
  if (!cu_cmd(CMD_GET_APP_VERSION, nullptr, 0)) return false;
  if (cu_resp_dlen >= 2) Serial.printf("  fw v%u.%u\n", cu_resp_data[0], cu_resp_data[1]);
  cu_print_resp_hex("version"); return true;
}
static bool cu_chipid() {
  if (!cu_cmd(CMD_GET_DEVICE_CHIP_ID, nullptr, 0)) return false;
  cu_print_resp_hex("chipid"); return true;
}
static bool cu_battery() {
  if (!cu_cmd(CMD_GET_BATTERY_INFO, nullptr, 0)) return false;
  if (cu_resp_dlen >= 3) {
    uint16_t mv = (cu_resp_data[0] << 8) | cu_resp_data[1];
    Serial.printf("  battery %u mV  %u%%\n", mv, cu_resp_data[2]);
  }
  cu_print_resp_hex("battery"); return true;
}
static bool cu_set_mode(bool reader) {
  uint8_t d = reader ? 1 : 0;
  bool ok = cu_cmd(CMD_CHANGE_DEVICE_MODE, &d, 1);
  Serial.printf("  mode -> %s (%s)\n", reader ? "reader" : "tag/emulate", ok ? "ok" : "fail");
  return ok;
}
static bool cu_get_mode() {
  if (!cu_cmd(CMD_GET_DEVICE_MODE, nullptr, 0)) return false;
  if (cu_resp_dlen >= 1) Serial.printf("  mode = %s\n", cu_resp_data[0] ? "reader" : "tag/emulate");
  return true;
}
static bool cu_set_slot(uint8_t slot) {
  bool ok = cu_cmd(CMD_SET_ACTIVE_SLOT, &slot, 1);
  Serial.printf("  slot -> %u (%s)\n", slot, ok ? "ok" : "fail"); return ok;
}
static bool cu_get_slot() {
  if (!cu_cmd(CMD_GET_ACTIVE_SLOT, nullptr, 0)) return false;
  if (cu_resp_dlen >= 1) Serial.printf("  active slot = %u\n", cu_resp_data[0]);
  return true;
}
static const char* cu_status_name(uint16_t s) {
  switch (s) {
    case 0x00: return "HF_TAG_OK";  case 0x01: return "HF_TAG_NO";  case 0x03: return "HF_ERR_CRC";
    case 0x40: return "LF_TAG_OK";  case 0x41: return "LF_TAG_NO";  case 0x60: return "PAR_ERR";
    case 0x66: return "MODE_ERROR"; case 0x67: return "INVALID_CMD";
    case 0x68: return "SUCCESS";    case 0x69: return "NOT_IMPL";   default: return "?";
  }
}
// HF ISO-14443A scan via the Chameleon reader. Needs reader mode first.
// Response: per tag  uidlen[1] uid[uidlen] atqa[2] sak[1] atslen[1] ats[atslen].
static bool cu_hf14a_scan() {
  cu_set_mode(true); delay(60);
  if (!cu_cmd(CMD_HF14A_SCAN, nullptr, 0, 2500)) { Serial.println("  scan: no reply"); return false; }
  if (cu_resp_status != 0x00) {   // 0x00 = HF_TAG_OK
    Serial.printf("  no 14443A tag (status %02X %s)\n", cu_resp_status, cu_status_name(cu_resp_status));
    return false;
  }
  const uint8_t* d = cu_resp_data; int dl = cu_resp_dlen, off = 0, tag = 0;
  while (off < dl) {
    int ul = d[off++]; if (ul < 4 || ul > 10 || off + ul + 3 > dl) break;
    Serial.printf("  tag%d UID:", ++tag); for (int i = 0; i < ul; i++) Serial.printf(" %02X", d[off + i]);
    int o = off + ul;
    Serial.printf("  ATQA %02X%02X  SAK %02X", d[o], d[o + 1], d[o + 2]); o += 3;
    int al = (o < dl) ? d[o++] : 0;
    if (al && o + al <= dl) { Serial.print("  ATS:"); for (int i = 0; i < al; i++) Serial.printf(" %02X", d[o + i]); }
    Serial.println(); off = o + al;
  }
  cu_print_resp_hex("hf14a"); return true;
}
static bool cu_em410x_scan() {
  cu_set_mode(true); delay(60);
  if (!cu_cmd(CMD_EM410X_SCAN, nullptr, 0, 2500)) { Serial.println("  em410x: no reply"); return false; }
  if (cu_resp_status != 0x40) {   // 0x40 = LF_TAG_OK
    Serial.printf("  no EM410x tag (status %02X %s)\n", cu_resp_status, cu_status_name(cu_resp_status));
    return false;
  }
  if (cu_resp_dlen >= 5) { memcpy(cu_last_em, cu_resp_data, 5); cu_have_em = true; }
  Serial.print("  EM410x ID:"); for (int i = 0; i < cu_resp_dlen; i++) Serial.printf(" %02X", cu_resp_data[i]);
  Serial.println(); return true;
}

// ---- Phase 2: reader / emulate / slots / transfer ops ---------------------
// last HF-14A scan (reused by dump + emulate + transfer)
static uint8_t cu_last_uid[10]; static int cu_last_uidlen = 0;
static uint8_t cu_last_atqa[2]; static uint8_t cu_last_sak = 0;

// MIFARE Classic key dictionary (common defaults).
static const uint8_t CU_MF_KEYS[][6] = {
  {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5},
  {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7}, {0x00,0x00,0x00,0x00,0x00,0x00},
  {0xA0,0xB0,0xC0,0xD0,0xE0,0xF0}, {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5},
  {0x4D,0x3A,0x99,0xC3,0x51,0xDD}, {0x1A,0x98,0x2C,0x7E,0x45,0x9A},
  {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, {0x71,0x4C,0x5C,0x88,0x6E,0x97},
  {0x58,0x7E,0xE5,0xF9,0x35,0x0F}, {0xA0,0x47,0x8C,0xC3,0x90,0x91},
  {0x53,0x3C,0xB6,0xC7,0x23,0xF6}, {0x8F,0xD0,0xA4,0xF2,0x56,0xE9},
};
static const int CU_MF_NKEYS = sizeof(CU_MF_KEYS) / 6;

static bool cu_set_reader() { uint8_t m = 1; return cu_cmd(CMD_CHANGE_DEVICE_MODE, &m, 1) && cu_resp_status == 0x68; }
static bool cu_set_tag()    { uint8_t m = 0; return cu_cmd(CMD_CHANGE_DEVICE_MODE, &m, 1) && cu_resp_status == 0x68; }

// HF-14A scan storing UID/SAK/ATQA into cu_last_*. Returns true if a tag answered.
static bool cu_hf_scan() {
  cu_set_reader(); delay(50);
  if (!cu_cmd(CMD_HF14A_SCAN, nullptr, 0, 2500) || cu_resp_status != 0x00) return false;
  const uint8_t* d = cu_resp_data; int dl = cu_resp_dlen;
  if (dl < 1) return false;
  int ul = d[0]; if (ul < 4 || ul > 10 || 1 + ul + 3 > dl) return false;
  memcpy(cu_last_uid, d + 1, ul); cu_last_uidlen = ul;
  cu_last_atqa[0] = d[1 + ul]; cu_last_atqa[1] = d[2 + ul]; cu_last_sak = d[3 + ul];
  return true;
}
// blocks for SAK: 1K(0x08)=64, 4K(0x18)=256, Mini(0x09)=20.
static int cu_mf_block_count(uint8_t sak) { return sak == 0x18 ? 256 : (sak == 0x09 ? 20 : 64); }

// Read one MF block (Chameleon READ_ONE_BLOCK auths+reads with the key).
static bool cu_mf_read(uint8_t block, uint8_t keytype, const uint8_t* key6, uint8_t out16[16]) {
  uint8_t req[8]; req[0] = keytype; req[1] = block; memcpy(req + 2, key6, 6);
  if (cu_cmd(CMD_MF1_READ_ONE_BLOCK, req, 8, 1200) && cu_resp_status == 0x00 && cu_resp_dlen >= 16) {
    memcpy(out16, cu_resp_data, 16); return true;
  }
  return false;
}
// Full dump with the key dictionary. Fills blocks[n][16], known[n]; returns # read.
static int cu_mf_dump(int nblocks, uint8_t (*blocks)[16], uint8_t* known) {
  int got = 0;
  for (int b = 0; b < nblocks; b++) {
    known[b] = 0; memset(blocks[b], 0, 16);
    for (int t = 0; t < 2 && !known[b]; t++) {
      uint8_t kt = t ? 0x61 : 0x60;
      for (int k = 0; k < CU_MF_NKEYS; k++)
        if (cu_mf_read((uint8_t)b, kt, CU_MF_KEYS[k], blocks[b])) { known[b] = 1; got++; break; }
    }
  }
  return got;
}
// Native fast dictionary key check across sectors (MF1_CHECK_KEYS_OF_SECTORS).
// nsectors = 16 (1K/Mini) or 40 (4K). Fills keyA/keyB + haveA/haveB per sector.
// Returns true if the command completed. Bounded by a per-slot timeout budget.
static bool cu_mf_checkkeys(int nsectors, bool* haveA, uint8_t keyA[][6], bool* haveB, uint8_t keyB[][6]) {
  for (int i = 0; i < nsectors; i++) { haveA[i] = haveB[i] = false; }
  // mask: 80 bits, bit set = SKIP that slot. slot = sector*2 + keytype(0=A,1=B).
  uint8_t mask[10]; memset(mask, 0xFF, 10);
  int nslots = nsectors * 2;
  for (int slot = 0; slot < nslots; slot++) mask[slot >> 3] &= ~(0x80 >> (slot & 7)); // clear = check
  uint8_t req[10 + 6 * CU_MF_NKEYS];
  memcpy(req, mask, 10);
  for (int k = 0; k < CU_MF_NKEYS; k++) memcpy(req + 10 + 6 * k, CU_MF_KEYS[k], 6);
  uint32_t to = 2000 + (uint32_t)(nslots + 1) * CU_MF_NKEYS * 120;   // worst-case budget
  if (to > 30000) to = 30000;
  if (!cu_cmd(2012 /*MF1_CHECK_KEYS_OF_SECTORS*/, req, 10 + 6 * CU_MF_NKEYS, to)) return false;
  if (cu_resp_status != 0x00 || cu_resp_dlen < 490) return false;
  const uint8_t* d = cu_resp_data;
  for (int slot = 0; slot < nslots; slot++) {
    bool found = (d[slot >> 3] >> (7 - (slot & 7))) & 1;       // found bitmap (MSB-first per byte)
    if (!found) continue;
    int sec = slot >> 1; const uint8_t* key = d + 10 + 6 * slot;
    if ((slot & 1) == 0) { memcpy(keyA[sec], key, 6); haveA[sec] = true; }
    else                 { memcpy(keyB[sec], key, 6); haveB[sec] = true; }
  }
  return true;
}

// Set the current HF slot anti-collision (UID/ATQA/SAK), no ATS.
static bool cu_set_anticoll(const uint8_t* uid, int ulen, const uint8_t* atqa2, uint8_t sak) {
  uint8_t d[20]; int n = 0; d[n++] = (uint8_t)ulen;
  memcpy(d + n, uid, ulen); n += ulen;
  d[n++] = atqa2[0]; d[n++] = atqa2[1]; d[n++] = sak; d[n++] = 0;   // atslen=0
  return cu_cmd(CMD_HF14A_SET_ANTI_COLL, d, n) && cu_resp_status == 0x68;
}
// Write emulator blocks starting at block_start (data = n*16 bytes).
static bool cu_write_emu(uint8_t block_start, const uint8_t* data, int nbytes) {
  uint8_t d[1 + 256]; if (nbytes > 256) nbytes = 256;
  d[0] = block_start; memcpy(d + 1, data, nbytes);
  return cu_cmd(CMD_MF1_WRITE_EMU_BLOCK, d, 1 + nbytes, 2000) && cu_resp_status == 0x68;
}
static bool cu_read_emu(uint8_t block_start, uint8_t count, uint8_t* out) {
  uint8_t d[2] = { block_start, count };
  if (cu_cmd(CMD_MF1_READ_EMU_BLOCK, d, 2, 2000) && cu_resp_status == 0x68) {
    memcpy(out, cu_resp_data, cu_resp_dlen); return true;
  }
  return false;
}
// Get current HF slot anti-coll (UID/ATQA/SAK). Returns uid len, fills out params.
static int cu_get_anticoll(uint8_t* uid, uint8_t* atqa2, uint8_t* sak) {
  if (!cu_cmd(CMD_HF14A_GET_ANTI_COLL, nullptr, 0) || cu_resp_status != 0x68) return 0;
  const uint8_t* d = cu_resp_data; int dl = cu_resp_dlen; if (dl < 1) return 0;
  int ul = d[0]; if (ul < 4 || ul > 10 || 1 + ul + 3 > dl) return 0;
  memcpy(uid, d + 1, ul); atqa2[0] = d[1 + ul]; atqa2[1] = d[2 + ul]; *sak = d[3 + ul];
  return ul;
}
static bool cu_set_slot_type(uint8_t slot, uint16_t tagtype) {
  uint8_t d[3] = { slot, (uint8_t)(tagtype >> 8), (uint8_t)(tagtype & 0xFF) };
  return cu_cmd(CMD_SET_SLOT_TAG_TYPE, d, 3) && cu_resp_status == 0x68;
}
static bool cu_slot_save() { return cu_cmd(1009 /*SLOT_DATA_CONFIG_SAVE*/, nullptr, 0, 2000) && cu_resp_status == 0x68; }
static bool cu_get_slot_info(uint16_t* hf, uint16_t* lf) {  // 8 slots
  if (!cu_cmd(1019 /*GET_SLOT_INFO*/, nullptr, 0) || cu_resp_status != 0x68) return false;
  for (int i = 0; i < 8 && (i * 4 + 3) < cu_resp_dlen; i++) {
    hf[i] = (cu_resp_data[i*4] << 8) | cu_resp_data[i*4+1];
    lf[i] = (cu_resp_data[i*4+2] << 8) | cu_resp_data[i*4+3];
  }
  return true;
}
static const char* cu_tagtype_name(uint16_t t) {
  switch (t) {
    case 0:    return "-";
    case 100:  return "EM410x"; case 1001: return "MF 1K"; case 1000: return "MF Mini";
    case 1002: return "MF 2K"; case 1003: return "MF 4K";
    case 1100: return "NTAG213"; case 1101: return "NTAG215"; case 1102: return "NTAG216";
    default:   return "other";
  }
}

// ---- LF 125 kHz (EM410x) — a band the Evil has no radio for at all ---------
// Read an EM410x tag (reader mode). Stores the 5-byte id in cu_last_em.
static bool cu_em_scan() {
  cu_set_reader(); delay(50);
  if (!cu_cmd(CMD_EM410X_SCAN, nullptr, 0, 2500) || cu_resp_status != 0x40) return false;
  if (cu_resp_dlen >= 5) { memcpy(cu_last_em, cu_resp_data, 5); cu_have_em = true; return true; }
  return false;
}
// Clone a 5-byte EM410x id onto a blank T5577 (reader mode). new_key + 1 old_key = 0.
static bool cu_em_clone_t55(const uint8_t* id5) {
  cu_set_reader(); delay(50);
  uint8_t d[13]; memcpy(d, id5, 5); memset(d + 5, 0, 8);
  return cu_cmd(3001 /*EM410X_WRITE_TO_T55XX*/, d, 13, 3000) && cu_resp_status == 0x40;
}
// Emulate a 5-byte EM410x id: set active slot LF type to EM410x, load the id,
// switch to tag mode and persist.
static bool cu_em_emulate(const uint8_t* id5) {
  uint8_t slot = 0; if (cu_cmd(CMD_GET_ACTIVE_SLOT, nullptr, 0) && cu_resp_dlen >= 1) slot = cu_resp_data[0];
  if (!cu_set_slot_type(slot, 100)) return false;                         // EM410X on the LF field
  if (!(cu_cmd(5000 /*EM410X_SET_EMU_ID*/, id5, 5) && cu_resp_status == 0x68)) return false;
  cu_set_tag(); return cu_slot_save();
}

// ---- HF-14A raw transceive (arbitrary APDU/command, e.g. EMV scripting) ----
// opt bitfield: b7 activate_rf b6 wait_resp b5 append_crc b4 auto_select
//               b3 keep_rf b2 check_resp_crc. Returns response length (-1 err).
static int cu_raw14(uint8_t opt, const uint8_t* data, int dlen, uint16_t to_ms, uint8_t* out, int omax) {
  if (dlen > 250) return -1;
  uint8_t req[5 + 256]; int n = 0;
  req[n++] = opt; req[n++] = to_ms >> 8; req[n++] = to_ms & 0xFF;
  uint16_t bits = (uint16_t)(dlen * 8); req[n++] = bits >> 8; req[n++] = bits & 0xFF;
  if (data && dlen) { memcpy(req + n, data, dlen); n += dlen; }
  if (!cu_cmd(CMD_HF14A_RAW, req, n, (uint32_t)(to_ms / 1000) + 2)) return -1;
  int c = cu_resp_dlen; if (c > omax) c = omax; if (c > 0) memcpy(out, cu_resp_data, c);
  return c;
}

} // namespace chameleon

// ---------------------------------------------------------------------------
// Serial console: "chameleon <sub>".
// ---------------------------------------------------------------------------
void chameleon_console(const String& rawArgs) {
  using namespace chameleon;
  String a = rawArgs; a.trim();
  int sp = a.indexOf(' ');
  String sub = (sp < 0 ? a : a.substring(0, sp)); sub.toLowerCase();
  String rest = (sp < 0 ? String() : a.substring(sp + 1)); rest.trim();

  if (sub == "" || sub == "help") {
    Serial.println("== chameleon (ChameleonUltra BLE) ==");
    Serial.println("  chameleon pin <123456>     set bind password before connect");
    Serial.println("  chameleon scanlist [secs]  list ALL advertising BLE (diagnostic)");
    Serial.println("  chameleon connect [secs]   scan + connect (pairs with pin)");
    Serial.println("  chameleon disconnect");
    Serial.println("  chameleon status");
    Serial.println("  chameleon version | chipid | batt");
    Serial.println("  chameleon mode r|t         reader / tag(emulate)");
    Serial.println("  chameleon modeget");
    Serial.println("  chameleon slot <0-7> | slotget");
    Serial.println("  chameleon scan             HF ISO-14443A scan (reader)");
    Serial.println("  chameleon dump             MIFARE Classic dump (reader)");
    Serial.println("  chameleon checkkeys        native dict key check -> SD");
    Serial.println("  chameleon em410x           LF EM410x scan (reader)");
    Serial.println("  chameleon lfclone          clone last EM410x id -> T5577");
    Serial.println("  chameleon lfemu [10hex]    emulate EM410x (LF)");
    Serial.println("  chameleon slotinfo         list slot tag types");
    Serial.println("  chameleon settype <s> <t>  set slot tag type");
    Serial.println("  chameleon save             persist slots to flash");
    Serial.println("  chameleon mfkey            enable detection + dump nonces");
    Serial.println("  chameleon raw14 <opt> <hex> raw 14A transceive (EMV/APDU)");
    Serial.println("  chameleon cmd <hhhh> [hex] raw protocol command");
    return;
  }
  if (sub == "pin")        { if (rest.length()) cu_pin = (uint32_t)rest.toInt(); Serial.printf("  pin = %06lu\n", (unsigned long)cu_pin); return; }
  if (sub == "scanlist")   { cu_scanlist(rest.length() ? (uint32_t)rest.toInt() : 8); return; }
  if (sub == "connect")    { cu_connect(rest.length() ? (uint32_t)rest.toInt() : 8); return; }
  if (sub == "disconnect") { cu_disconnect(); return; }
  if (sub == "status")     { Serial.printf("  %s\n", cu_is_connected() ? "connected" : "not connected"); return; }
  if (sub == "heap") { Serial.printf("  free=%u  largest=%u  (sprite needs 32400)\n", (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap()); return; }
  if (sub == "bleoff" || sub == "bleoffhard") {
    bool release = (sub == "bleoffhard");
    Serial.printf("  before: free=%u largest=%u\n", (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
    cu_shutdown(release); delay(60);
    Serial.printf("  after %s: free=%u largest=%u\n", release ? "deinit(true)" : "deinit(false)", (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
    return;
  }
  if (sub == "bletest") {   // isolate deinit heap behaviour without the Chameleon
    Serial.printf("  fresh:            largest=%u\n", (unsigned)ESP.getMaxAllocHeap());
    WiFi.mode(WIFI_OFF); delay(30);
    if (!BLEDevice::getInitialized()) BLEDevice::init("");
    Serial.printf("  after init:       largest=%u\n", (unsigned)ESP.getMaxAllocHeap());
    BLEDevice::deinit(false); delay(60);
    Serial.printf("  after deinit(F):  largest=%u\n", (unsigned)ESP.getMaxAllocHeap());
    BLEDevice::init(""); delay(30);
    BLEDevice::deinit(true); delay(60);
    Serial.printf("  after deinit(T):  largest=%u\n", (unsigned)ESP.getMaxAllocHeap());
    return;
  }

  if (!cu_is_connected()) { Serial.println("[cham] not connected (run: chameleon connect)"); return; }

  if (sub == "version")  { cu_version(); return; }
  if (sub == "chipid")   { cu_chipid(); return; }
  if (sub == "batt" || sub == "battery") { cu_battery(); return; }
  if (sub == "mode")     { cu_set_mode(rest.startsWith("r")); return; }
  if (sub == "modeget")  { cu_get_mode(); return; }
  if (sub == "slot")     { cu_set_slot((uint8_t)rest.toInt()); return; }
  if (sub == "slotget")  { cu_get_slot(); return; }
  if (sub == "scan")     { cu_hf14a_scan(); return; }
  if (sub == "em410x")   { cu_em410x_scan(); return; }
  if (sub == "slotinfo") {
    uint16_t hf[8] = {0}, lf[8] = {0};
    if (!cu_get_slot_info(hf, lf)) { Serial.println("  no response"); return; }
    uint8_t act = 0; if (cu_cmd(CMD_GET_ACTIVE_SLOT, nullptr, 0) && cu_resp_dlen >= 1) act = cu_resp_data[0];
    for (int i = 0; i < 8; i++) Serial.printf("  %c slot%d  HF:%s  LF:%s\n", i == act ? '*' : ' ', i + 1, cu_tagtype_name(hf[i]), cu_tagtype_name(lf[i]));
    return;
  }
  if (sub == "dump") {    // reader MIFARE Classic dump (serial)
    if (!cu_hf_scan()) { Serial.println("  no 14443A tag"); return; }
    Serial.printf("  UID:"); for (int i = 0; i < cu_last_uidlen; i++) Serial.printf(" %02X", cu_last_uid[i]);
    Serial.printf("  ATQA %02X%02X SAK %02X\n", cu_last_atqa[0], cu_last_atqa[1], cu_last_sak);
    int nb = cu_mf_block_count(cu_last_sak);
    uint8_t (*blk)[16] = (uint8_t(*)[16])malloc(256 * 16); uint8_t* known = (uint8_t*)malloc(256);
    if (!blk || !known) { if (blk) free(blk); if (known) free(known); Serial.println("  OOM"); return; }
    int got = cu_mf_dump(nb, blk, known);
    Serial.printf("  %d/%d blocks read\n", got, nb);
    for (int b = 0; b < nb; b++) { Serial.printf("  blk%02d%s:", b, known[b] ? "" : "?");
      for (int j = 0; j < 16; j++) Serial.printf(" %02X", blk[b][j]); Serial.println(); }
    free(blk); free(known);
    return;
  }
  if (sub == "checkkeys") {   // native dictionary key check across sectors
    if (!cu_hf_scan()) { Serial.println("  no 14443A tag"); return; }
    int nsec = (cu_last_sak == 0x18) ? 40 : 16;
    bool hA[40], hB[40]; uint8_t kA[40][6], kB[40][6];
    Serial.printf("  checking %d sectors (%d-key dict)...\n", nsec, CU_MF_NKEYS);
    if (!cu_mf_checkkeys(nsec, hA, kA, hB, kB)) { Serial.println("  check failed/timeout"); return; }
    SD.mkdir("/evil/nfc"); SD.mkdir("/evil/nfc/keys");
    char path[80]; int p = snprintf(path, sizeof path, "/evil/nfc/keys/cham_");
    for (int i = 0; i < cu_last_uidlen; i++) p += snprintf(path + p, sizeof path - p, "%02X", cu_last_uid[i]);
    snprintf(path + p, sizeof path - p, "_keys.txt");
    File f = SD.open(path, FILE_WRITE); int nf = 0;
    for (int s = 0; s < nsec; s++) {
      Serial.printf("  S%02d A:", s); if (hA[s]) { for (int j = 0; j < 6; j++) Serial.printf("%02X", kA[s][j]); nf++; } else Serial.print("------------");
      Serial.print(" B:"); if (hB[s]) { for (int j = 0; j < 6; j++) Serial.printf("%02X", kB[s][j]); nf++; } else Serial.print("------------");
      Serial.println();
      if (f) { f.printf("S%02d A:", s); if (hA[s]) for (int j = 0; j < 6; j++) f.printf("%02X", kA[s][j]); else f.print("------------");
               f.print(" B:"); if (hB[s]) for (int j = 0; j < 6; j++) f.printf("%02X", kB[s][j]); else f.print("------------"); f.println(); }
    }
    if (f) f.close();
    Serial.printf("  found %d/%d keys, saved %s\n", nf, nsec * 2, path);
    return;
  }
  if (sub == "mfkey") {   // enable detection + count + dump nonce log
    uint8_t en = 1; cu_cmd(4004, &en, 1);
    uint32_t cnt = 0; if (cu_cmd(4005, nullptr, 0) && cu_resp_dlen >= 4)
      cnt = ((uint32_t)cu_resp_data[0] << 24) | (cu_resp_data[1] << 16) | (cu_resp_data[2] << 8) | cu_resp_data[3];
    Serial.printf("  detection ON, nonces=%lu\n", (unsigned long)cnt);
    if (cnt) { uint8_t idx[4] = {0,0,0,0};
      if (cu_cmd(4006, idx, 4, 3000) && cu_resp_status == 0x68) {
        const uint8_t* d = cu_resp_data; int dl = cu_resp_dlen;
        for (int p = 0; p + 18 <= dl; p += 18) Serial.printf("  blk%u %c uid%02X%02X%02X%02X nt%02X%02X%02X%02X nr%02X%02X%02X%02X ar%02X%02X%02X%02X\n",
          d[p], (d[p+1]&1)?'B':'A', d[p+2],d[p+3],d[p+4],d[p+5], d[p+6],d[p+7],d[p+8],d[p+9], d[p+10],d[p+11],d[p+12],d[p+13], d[p+14],d[p+15],d[p+16],d[p+17]);
      }
    }
    return;
  }
  if (sub == "settype") { // settype <slot> <mf1k|mf4k|ntag215|em410x>
    int s2 = rest.indexOf(' '); if (s2 < 0) { Serial.println("  usage: settype <slot> <mf1k|mf4k|ntag215|em410x>"); return; }
    uint8_t slot = (uint8_t)rest.substring(0, s2).toInt(); String ty = rest.substring(s2 + 1); ty.trim();
    uint16_t tt = ty == "mf4k" ? 1003 : ty == "ntag215" ? 1101 : ty == "em410x" ? 100 : 1001;
    Serial.printf("  settype slot%u %s: %s\n", slot, ty.c_str(), cu_set_slot_type(slot, tt) ? "ok" : "fail"); return;
  }
  if (sub == "save") { Serial.printf("  slot save: %s\n", cu_slot_save() ? "ok" : "fail"); return; }
  if (sub == "lfclone") {   // clone last-read EM410x id onto a blank T5577
    if (!cu_have_em) { Serial.println("  no EM id (run: chameleon em410x first)"); return; }
    Serial.print("  cloning"); for (int i = 0; i < 5; i++) Serial.printf(" %02X", cu_last_em[i]);
    Serial.printf(" -> T5577: %s\n", cu_em_clone_t55(cu_last_em) ? "ok" : "fail"); return;
  }
  if (sub == "lfemu") {     // lfemu [5-byte hex] (defaults to last read EM id)
    uint8_t id[5]; bool have = false;
    String h = rest; h.replace(" ", "");
    if (h.length() >= 10) { for (int i = 0; i < 5; i++) id[i] = (uint8_t)strtol(h.substring(i*2, i*2+2).c_str(), nullptr, 16); have = true; }
    else if (cu_have_em) { memcpy(id, cu_last_em, 5); have = true; }
    if (!have) { Serial.println("  usage: chameleon lfemu <10 hex> (or em410x first)"); return; }
    Serial.printf("  emulate EM410x: %s\n", cu_em_emulate(id) ? "ok (tag mode, saved)" : "fail"); return;
  }
  if (sub == "raw14") {     // raw14 <optHex> <dataHex> — arbitrary 14A transceive
    int s2 = rest.indexOf(' ');
    String oh = (s2 < 0 ? rest : rest.substring(0, s2));
    String dh = (s2 < 0 ? String() : rest.substring(s2 + 1)); dh.replace(" ", "");
    uint8_t opt = (uint8_t)strtol(oh.c_str(), nullptr, 16);
    uint8_t data[128]; int dl = 0;
    for (int i = 0; i + 1 < (int)dh.length() && dl < 128; i += 2) data[dl++] = (uint8_t)strtol(dh.substring(i, i+2).c_str(), nullptr, 16);
    uint8_t out[256]; int n = cu_raw14(opt, dl ? data : nullptr, dl, 500, out, sizeof out);
    if (n < 0) { Serial.println("  raw14: no reply"); return; }
    Serial.printf("  resp (%d):", n); for (int i = 0; i < n; i++) Serial.printf(" %02X", out[i]); Serial.println(); return;
  }
  if (sub == "cmd") {
    int s2 = rest.indexOf(' ');
    String ch = (s2 < 0 ? rest : rest.substring(0, s2));
    String dh = (s2 < 0 ? String() : rest.substring(s2 + 1)); dh.replace(" ", "");
    uint16_t cmd = (uint16_t)strtol(ch.c_str(), nullptr, 16);
    uint8_t data[256]; int dl = 0;
    for (int i = 0; i + 1 < (int)dh.length() && dl < 256; i += 2)
      data[dl++] = (uint8_t)strtol(dh.substring(i, i + 2).c_str(), nullptr, 16);
    if (!cu_cmd(cmd, dl ? data : nullptr, dl, 2500)) { Serial.println("  no reply"); return; }
    cu_print_resp_hex("cmd"); return;
  }
  Serial.println("[cham] unknown subcommand (try: chameleon help)");
}

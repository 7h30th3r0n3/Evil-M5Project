#pragma once
// =============================================================================
//  Wigle upload + Geofences  (greffe sur le wardriving de l'Evil-Cardputer)
// -----------------------------------------------------------------------------
//  - Upload des CSV WigleWifi-1.4 (/evil/wardriving/*.csv) vers l'API Wigle.net
//    (multipart/form-data, Basic auth). Identifiants lus sur SD : /evil/wardriving/wigle.txt
//    = une ligne "apiname:apitoken" (jamais code en dur, jamais affiche en clair).
//  - Geofences : zones GPS chargees de /evil/wardriving/geofences.txt, detection entree/sortie
//    pendant le wardriving (notice ecran + log /evil/wardriving/geofence-events.txt).
//
//  ZERO RAM au boot : rien de lourd en statique. La liste de geofences et le
//  buffer d'upload sont alloues au runtime (entree de la feature) et liberes
//  a la sortie. Header auto-contenu, inclus depuis le .ino apres les globals
//  (SD, WiFi, M5, gps, cardUpdate, kpAny, confirmPopup...).
// =============================================================================

#include <Arduino.h>
#include <SD.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <math.h>
#include "mbedtls/base64.h"

// Helpers definis plus bas dans le .ino (ce header est inclus tot) :
String promptInput(const char *prompt);

// ----------------------------------------------------------------------------
//  Geofences
// ----------------------------------------------------------------------------
struct GeoFence {
  float lat;
  float lon;
  float radius;     // metres
  char  name[24];
  char  action[28]; // nom d'un module a lancer via runByName sur ENTER ("" = tracking seul)
  bool  inside;     // etat courant (pour detecter la transition entree/sortie)
};

struct GeoCtx {
  GeoFence* zones;
  int       count;
};

// Distance haversine en metres (float, suffisant pour des rayons de zone).
static inline float geoDistM(float lat1, float lon1, float lat2, float lon2) {
  const float R = 6371000.0f;
  float dLat = radians(lat2 - lat1);
  float dLon = radians(lon2 - lon1);
  float a = sinf(dLat / 2) * sinf(dLat / 2) +
            cosf(radians(lat1)) * cosf(radians(lat2)) * sinf(dLon / 2) * sinf(dLon / 2);
  return R * 2.0f * atan2f(sqrtf(a), sqrtf(1.0f - a));
}

// Cap/bearing de (lat1,lon1) vers (lat2,lon2) en degres 0..360 (0 = Nord).
static inline float geoBearing(float lat1, float lon1, float lat2, float lon2) {
  float dLon = radians(lon2 - lon1);
  float y = sinf(dLon) * cosf(radians(lat2));
  float x = cosf(radians(lat1)) * sinf(radians(lat2)) -
            sinf(radians(lat1)) * cosf(radians(lat2)) * cosf(dLon);
  float b = degrees(atan2f(y, x));
  if (b < 0) b += 360.0f;
  return b;
}

// Charge /evil/wardriving/geofences.txt : "lat,lon,radius_m,name[,action]" par ligne ('#' = commentaire).
// Le 5e champ "action" est optionnel = nom d'un module lance via runByName sur ENTER.
// Sans 5e champ (lignes a 4 colonnes) = tracking/log seul (retro-compatible). Le nom
// peut contenir des virgules UNIQUEMENT s'il n'y a pas d'action (sinon mets un nom sans
// virgule). Retourne un GeoCtx avec tableau alloue au runtime (liberer avec geoFree).
// count = 0 si fichier absent/vide.
static GeoCtx geoLoad(const char* path = "/evil/wardriving/geofences.txt") {
  GeoCtx ctx = { nullptr, 0 };
  File f = SD.open(path, FILE_READ);
  if (!f) return ctx;

  int n = 0;
  while (f.available()) {
    String l = f.readStringUntil('\n'); l.trim();
    if (l.length() && l[0] != '#') n++;
  }
  if (n <= 0) { f.close(); return ctx; }
  if (n > 32) n = 32;                       // plafond runtime

  ctx.zones = (GeoFence*)calloc(n, sizeof(GeoFence));
  if (!ctx.zones) { f.close(); return ctx; }

  f.seek(0);
  int i = 0;
  while (f.available() && i < n) {
    String l = f.readStringUntil('\n'); l.trim();
    if (!l.length() || l[0] == '#') continue;
    int c1 = l.indexOf(',');
    int c2 = (c1 >= 0) ? l.indexOf(',', c1 + 1) : -1;
    int c3 = (c2 >= 0) ? l.indexOf(',', c2 + 1) : -1;
    int c4 = (c3 >= 0) ? l.indexOf(',', c3 + 1) : -1;   // 5e champ = action (optionnel)
    if (c1 < 0 || c2 < 0) continue;
    ctx.zones[i].lat    = l.substring(0, c1).toFloat();
    ctx.zones[i].lon    = l.substring(c1 + 1, c2).toFloat();
    ctx.zones[i].radius = (c3 > 0 ? l.substring(c2 + 1, c3) : l.substring(c2 + 1)).toFloat();
    // c4 present -> name = entre c3 et c4, action = apres c4 ; sinon name = apres c3 (4 champs)
    String nm = (c3 > 0) ? (c4 > 0 ? l.substring(c3 + 1, c4) : l.substring(c3 + 1)) : String("zone");
    String ac = (c4 > 0) ? l.substring(c4 + 1) : String("");
    nm.trim(); ac.trim();
    strncpy(ctx.zones[i].name, nm.c_str(), sizeof(ctx.zones[i].name) - 1);
    ctx.zones[i].name[sizeof(ctx.zones[i].name) - 1] = 0;
    strncpy(ctx.zones[i].action, ac.c_str(), sizeof(ctx.zones[i].action) - 1);
    ctx.zones[i].action[sizeof(ctx.zones[i].action) - 1] = 0;
    ctx.zones[i].inside = false;
    i++;
  }
  f.close();
  ctx.count = i;
  return ctx;
}

static void geoFree(GeoCtx& ctx) {
  if (ctx.zones) { free(ctx.zones); ctx.zones = nullptr; }
  ctx.count = 0;
}

// Teste la position contre les zones. Sur transition : retourne 1 (entree) ou
// -1 (sortie), remplit outName et outAction (le module a lancer, "" si aucun) ;
// 0 si aucun changement.
static int geoCheck(GeoCtx& ctx, float lat, float lon, char* outName, size_t outLen,
                    char* outAction = nullptr, size_t outActionLen = 0) {
  for (int i = 0; i < ctx.count; i++) {
    float d = geoDistM(lat, lon, ctx.zones[i].lat, ctx.zones[i].lon);
    bool now = (d <= ctx.zones[i].radius);
    if (now != ctx.zones[i].inside) {
      ctx.zones[i].inside = now;
      if (outName && outLen) {
        strncpy(outName, ctx.zones[i].name, outLen - 1);
        outName[outLen - 1] = 0;
      }
      if (outAction && outActionLen) {
        strncpy(outAction, ctx.zones[i].action, outActionLen - 1);
        outAction[outActionLen - 1] = 0;
      }
      return now ? 1 : -1;
    }
  }
  return 0;
}

// Ajoute l'evenement au log geofence.
static void geoLogEvent(const char* name, int evt, float lat, float lon, const char* timeStr) {
  File f = SD.open("/evil/wardriving/geofence-events.txt", FILE_APPEND);
  if (!f) return;
  f.printf("%s,%s,%s,%.6f,%.6f\n", timeStr ? timeStr : "", evt > 0 ? "ENTER" : "EXIT", name, lat, lon);
  f.close();
}

// ----------------------------------------------------------------------------
//  Upload Wigle
// ----------------------------------------------------------------------------
static String wgB64(const uint8_t* data, size_t len) {
  size_t outLen = 0, outSize = 4 * ((len + 2) / 3) + 1;
  unsigned char* out = (unsigned char*)malloc(outSize);
  if (!out) return String("");
  if (mbedtls_base64_encode(out, outSize, &outLen, data, len) != 0) { free(out); return String(""); }
  out[outLen] = 0;
  String s((char*)out);
  free(out);
  return s;
}

// POST multipart du CSV vers api.wigle.net. Retourne le code HTTP (ou negatif
// sur erreur locale) et remplit outMsg. Streame le fichier (pas de copie RAM).
static int wigleUpload(const char* csvPath, String& outMsg) {
  if (WiFi.status() != WL_CONNECTED) { outMsg = "WiFi non connecte"; return -10; }

  File cf = SD.open("/evil/wardriving/wigle.txt", FILE_READ);
  if (!cf) { outMsg = "No /evil/wardriving/wigle.txt (apiname:apitoken)"; return -1; }
  String creds = cf.readStringUntil('\n'); cf.close(); creds.trim();
  if (creds.indexOf(':') < 0) { outMsg = "Format /evil/wardriving/wigle.txt invalide"; return -2; }
  String auth = wgB64((const uint8_t*)creds.c_str(), creds.length());
  creds = "";                                        // ne pas garder le token en RAM
  if (!auth.length()) { outMsg = "Base64 echec"; return -5; }

  File up = SD.open(csvPath, FILE_READ);
  if (!up) { outMsg = "CSV introuvable"; return -3; }
  size_t fsz = up.size();

  const char* boundary = "----EvilCardputerWigle";
  String fname = String(csvPath);
  int sl = fname.lastIndexOf('/');
  if (sl >= 0) fname = fname.substring(sl + 1);

  String head;
  head += "--"; head += boundary; head += "\r\n";
  head += "Content-Disposition: form-data; name=\"file\"; filename=\"" + fname + "\"\r\n";
  head += "Content-Type: text/csv\r\n\r\n";
  String tail = "\r\n--"; tail += boundary; tail += "--\r\n";
  size_t clen = head.length() + fsz + tail.length();

  WiFiClientSecure client;
  client.setInsecure();                              // pas de pinning (outil pentest)
  client.setTimeout(20000);
  if (ESP.getFreeHeap() < 50000) {                   // mbedTLS a besoin de ~40Ko contigus pour le handshake
    up.close(); outMsg = "Heap bas (" + String(ESP.getFreeHeap() / 1024) + "k) - ferme les autres vues"; return -11;
  }
  M5.Lcd.setTextColor(TFT_CYAN, TFT_BLACK); M5.Lcd.setTextSize(1); M5.Lcd.setCursor(8, 52); M5.Lcd.print("Connecting TLS...        ");
  if (!client.connect("api.wigle.net", 443)) { up.close(); outMsg = "TLS echec (heap " + String(ESP.getFreeHeap() / 1024) + "k)"; return -4; }

  client.print("POST /api/v2/file/upload HTTP/1.1\r\n");
  client.print("Host: api.wigle.net\r\n");
  client.print("Authorization: Basic " + auth + "\r\n");
  client.print("Accept: application/json\r\n");
  client.print("User-Agent: Evil-Cardputer\r\n");
  client.print("Content-Type: multipart/form-data; boundary=" + String(boundary) + "\r\n");
  client.print("Content-Length: " + String((unsigned)clen) + "\r\n");
  client.print("Connection: close\r\n\r\n");
  client.print(head);

  // barre de progression (l'upload est bloquant -> on dessine directement)
  const int bx = 8, bw = M5.Lcd.width() - 16, by = 70, bh = 16;
  M5.Lcd.drawRect(bx, by, bw, bh, TFT_WHITE);
  uint8_t buf[512];
  size_t sent = 0, wrote = 0; uint32_t lastDraw = 0, minHeap = 0xFFFFFFFF; bool earlyResp = false, txErr = false;
  String body;   // peut recevoir une reponse serveur PRECOCE (403/413...) pendant l'envoi
  while (up.available()) {
    // Cloudflare/Wigle peut repondre et fermer AVANT qu'on ait fini le corps (refus sur en-tetes :
    // taille/quota/WAF). On lit cette reponse precoce tout de suite, sinon le write suivant casse et
    // le stop() du wrapper la detruit (-> status/body vides, code=0 : exactement le bug observe).
    while (client.available() && body.length() < 2048) body += (char)client.read();
    if (body.length()) { earlyResp = true; break; }
    int r = up.read(buf, sizeof(buf));
    if (r <= 0) break;
    int off = 0;
    while (off < r) {
      if (!client.connected()) { txErr = true; break; }
      int w = client.write(buf + off, r - off);      // le wrapper draine tout, OU stop()+retourne 0 sur erreur
      if (w > 0) { off += w; wrote += w; }
      else { txErr = true; break; }                  // socket morte : on arrete honnetement
    }
    sent += off;
    if (txErr) break;
    // PACING ADAPTATIF (heap) : sur ESP32 sans PSRAM, le heap tombe tres bas pendant l'upload TLS
    // (buffers mbedTLS ~32K + pbuf lwIP). Quand lwIP ne peut plus allouer de pbuf -> ENOMEM ->
    // mbedTLS MBEDTLS_ERR_NET_SEND_FAILED (le core le reessaie desormais au lieu d'abandonner). Pour
    // ne JAMAIS froler l'OOM, on ralentit quand le heap chute : laisse le WiFi transmettre et liberer
    // les pbuf avant d'en redemander. Rapide quand le heap est sain.
    { uint32_t fh = ESP.getFreeHeap(); if (fh < minHeap) minHeap = fh;
      if (fh < 18000) delay(18); else if (fh < 30000) delay(6); else delay(1); }
    if (millis() - lastDraw > 100) {
      lastDraw = millis();
      int pct = fsz ? (int)(wrote * 100 / fsz) : 100; if (pct > 100) pct = 100;   // % REEL (octets transmis, pas lus)
      M5.Lcd.fillRect(bx + 1, by + 1, (bw - 2) * pct / 100, bh - 2, TFT_GREEN);
      M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK); M5.Lcd.setTextSize(1);
      M5.Lcd.setCursor(bx, 52); M5.Lcd.printf("Uploading %d%%  %u/%u B   ", pct, (unsigned)wrote, (unsigned)fsz);
      M5.Lcd.setCursor(bx, by + bh + 4); M5.Lcd.print("BKSP=annuler   ");
      // pompe le clavier/serie pendant l'upload (sinon device fige qq min sur gros fichier) + annulation
      cardUpdate();
      if (kp(KEY_BACKSPACE) || kp('`')) { txErr = true; keyRelease(); break; }
    }
  }
  up.close();
  if (!earlyResp && !txErr) client.print(tail);
  M5.Lcd.setTextColor(TFT_CYAN, TFT_BLACK); M5.Lcd.setTextSize(1);
  M5.Lcd.setCursor(bx, by + bh + 4); M5.Lcd.print("Waiting Wigle response...   ");

  // lecture reponse (body peut deja contenir une reponse precoce)
  uint32_t t0 = millis();
  while (client.connected() && millis() - t0 < 20000 && body.length() < 4096) {
    int got = 0;
    while (client.available() && body.length() < 4096) { body += (char)client.read(); got = 1; t0 = millis(); }
    if (!got) { cardUpdate(); delay(10); }
  }
  client.stop();
  int code = 0;
  int hp = body.indexOf("HTTP/1.");
  if (hp >= 0) { int sp = body.indexOf(' ', hp); if (sp > 0) code = body.substring(sp + 1, sp + 5).toInt(); }
  Serial.printf("[WIGLE] fsz=%u wrote=%u clen=%u early=%d txErr=%d code=%d minHeap=%u\n", (unsigned)fsz, (unsigned)wrote, (unsigned)clen, earlyResp, txErr, code, (unsigned)(minHeap==0xFFFFFFFF?0:minHeap));
  Serial.print("[WIGLE] resp: "); Serial.println(body.substring(0, 320));

  bool ok = (body.indexOf("\"success\":true") >= 0) || (body.indexOf("\"success\": true") >= 0);
  outMsg = "HTTP " + String(code) + (ok ? " OK" : (code == 200 ? " (verifier)" : " ECHEC"));
  return code;
}

// Dernier resultat d'upload (pour l'affichage de synthese Wigle M5GFX). 0 RAM boot.
static int    g_wigleLastCode = 0;
static String g_wigleLastMsg  = "(aucun upload)";

// Petit ecran de statut d'upload (appele depuis le wardriving).
static void wigleUploadUI(const char* csvPath) {
  M5.Lcd.fillScreen(TFT_BLACK);
  M5.Lcd.setTextSize(1);
  M5.Lcd.setTextColor(TFT_CYAN, TFT_BLACK);
  M5.Lcd.setCursor(4, 8);  M5.Lcd.print("WIGLE UPLOAD");
  M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
  int sl = String(csvPath).lastIndexOf('/');
  M5.Lcd.setCursor(4, 28); M5.Lcd.print(sl >= 0 ? csvPath + sl + 1 : csvPath);

  String msg;
  int code = wigleUpload(csvPath, msg);           // dessine Connecting / barre / Waiting
  g_wigleLastCode = code; g_wigleLastMsg = msg;   // memorise pour la vue de synthese M5GFX

  M5.Lcd.setTextSize(1.5);
  M5.Lcd.setTextColor((code == 200) ? TFT_GREEN : TFT_RED, TFT_BLACK);
  M5.Lcd.setCursor(4, 104); M5.Lcd.print(msg);
  M5.Lcd.setTextSize(1);
  M5.Lcd.setTextColor(TFT_DARKGREY, TFT_BLACK);
  M5.Lcd.setCursor(4, 124); M5.Lcd.print("Press any key");

  uint32_t t0 = millis();
  while (millis() - t0 < 6000) { cardUpdate(); if (kpAny()) break; delay(10); }
}

// ============================================================================
//  MENUS Wigle + Geofence (UI M5GFX, barre de selection verte)
// ============================================================================
#include <vector>

// Toggle runtime (scalaire, 0 RAM boot). Le wardriving peut le lire pour
// activer/desactiver les geofences sur la session courante.
static bool g_geofenceEnabled = true;

// ---- Liste de selection generique (barre verte, scrollable) ----
static int wgSelect(const char* title, const std::vector<String>& rows, const char* help) {
  if (rows.empty()) return -1;
  auto& d = M5Cardputer.Display;
  int idx = 0, last = -1;
  for (;;) {
    if (idx != last) {
      d.clear(); d.setTextWrap(false, false);
      d.setTextSize(1);                                  // titre + aide en petit (secondaires)
      d.setTextColor(menuTextFocusedColor, menuBackgroundColor); d.setCursor(4, 2); d.println(title);
      d.setTextSize(menuTextSize);                       // ELEMENTS a la taille du menu principal
      int top = 15, lh = menuLineH + 3, maxRows = (d.height() - top - 12) / lh; if (maxRows < 1) maxRows = 1;
      int first = 0;
      if ((int)rows.size() > maxRows) {
        first = idx - maxRows / 2;
        if (first < 0) first = 0;
        if (first > (int)rows.size() - maxRows) first = rows.size() - maxRows;
      }
      int maxch = (int)(230.0f / (6.0f * menuTextSize));
      for (int r = 0; r < maxRows && first + r < (int)rows.size(); r++) {
        int i = first + r, y = top + r * lh;
        if (i == idx) { d.fillRect(0, y - 1, d.width(), lh, menuSelectedBackgroundColor); d.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor); }
        else          { d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor); }
        d.setCursor(6, y); d.print(rows[i].substring(0, maxch));   // tronque a la largeur ecran
      }
      d.setTextSize(1);
      d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor); d.setCursor(4, d.height() - 10); d.print(help);
      d.display(); last = idx;
    }
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); return -1; }  // DEL = retour (attend relache -> pas de double-back)
    if (kp(KEY_ENTER)) { enterDebounce(); return idx; }   // edge-debounce: attend relache -> pas de saut
    if (kp(';')) { idx = (idx + rows.size() - 1) % rows.size(); delay(140); }
    if (kp('.')) { idx = (idx + 1) % rows.size(); delay(140); }
    delay(8);
  }
}

static void wgStatus(const char* l1, const char* l2 = nullptr, uint16_t col = TFT_WHITE) {
  auto& d = M5Cardputer.Display;
  d.clear(); d.setTextSize(1); d.setTextWrap(false, false);
  d.setTextColor(col, TFT_BLACK); d.setCursor(4, 20); d.print(l1);
  if (l2) { d.setTextColor(TFT_WHITE, TFT_BLACK); d.setCursor(4, 40); d.print(l2); }
  d.display();
}

static bool wgAnyKey(uint32_t ms = 8000) {
  uint32_t t0 = millis();
  while (millis() - t0 < ms) { cardUpdate(); if (kp('`') || kp(KEY_ENTER) || kpAny()) { keyRelease(); return true; } delay(10); }
  return false;
}

// ---- Wigle: liste des sessions CSV sur SD ----
static void wgListSessions(std::vector<String>& out) {
  File dir = SD.open("/evil/wardriving");
  if (!dir) return;
  File e;
  while ((e = dir.openNextFile())) {
    if (!e.isDirectory()) {
      String n = e.name(); int sl = n.lastIndexOf('/'); if (sl >= 0) n = n.substring(sl + 1);
      String low = n; low.toLowerCase();
      if (low.endsWith(".csv") || low.endsWith(".wiglecsv")) out.push_back(n);
    }
    e.close();
  }
  dir.close();
}

// Split CSV simple (SSID avec virgule -> les colonnes de queue restent fiables,
// on indexe depuis la fin pour lat/lon/type/channel/firstseen).
static int wgSplit(const String& line, String* tok, int maxTok) {
  int n = 0, start = 0;
  while (n < maxTok) {
    int c = line.indexOf(',', start);
    if (c < 0) { tok[n++] = line.substring(start); break; }
    tok[n++] = line.substring(start, c); start = c + 1;
  }
  return n;
}

// ---- Wigle: reliable per-CSV stats dashboard (M5GFX) + upload ----
// Session detail. `;/.` switch file WITHOUT leaving the detail ; DEL = back to list.
// Encryption is read from the WigleWifi AuthMode column (indexed from the end, so an
// SSID containing commas or the word "WPA" never skews the counts).
static void wgSessionStats(std::vector<String>& sessions, int idx) {
 for (;;) {
  if (sessions.empty()) return;
  if (idx < 0) idx = sessions.size() - 1;
  if (idx >= (int)sessions.size()) idx = 0;
  String base = sessions[idx];
  String path = "/evil/wardriving/" + base;
  File f = SD.open(path, FILE_READ);
  if (!f) { wgStatus("Read failed", base.c_str(), TFT_RED); delay(1200); return; }
  wgStatus("Loading...", base.c_str(), TFT_CYAN);   // le parse d'un gros CSV prend du temps -> feedback

  long nets = 0, gps = 0, wifi = 0, ble = 0;
  long opn = 0, wep = 0, wpa = 0, wpa2 = 0, wpa3 = 0;   // from AuthMode column
  long b24 = 0, b5 = 0;                                 // WiFi bands
  int bestRssi = -127; bool rssiSeen = false;
  String firstTs = "", lastTs = "";
  bool chSeen[201];                                     // stack (0 RAM boot)
  for (int i = 0; i < 201; i++) chSeen[i] = false;
  int chCount = 0, lineNo = 0;
  String tok[20];

  while (f.available()) {
    String l = f.readStringUntil('\n'); l.trim(); lineNo++;
    if (lineNo <= 2 || !l.length()) continue;           // 2 WigleWifi header lines
    nets++;
    int n = wgSplit(l, tok, 20);
    // tail columns (stable even if SSID holds commas): ... AuthMode(n-9) FirstSeen(n-8)
    //   Channel(n-7) RSSI(n-6) Lat(n-5) Lon(n-4) Alt(n-3) Acc(n-2) Type(n-1)
    if (n >= 9) {
      String type = tok[n - 1]; type.trim(); type.toUpperCase();
      bool isWifi = (type == "WIFI" || type.length() == 0);
      if (!isWifi) ble++; else wifi++;
      String lat = tok[n - 5], lon = tok[n - 4];
      if (lat.toFloat() != 0.0f || lon.toFloat() != 0.0f) gps++;
      int ch = tok[n - 7].toInt();
      if (ch >= 0 && ch <= 200 && !chSeen[ch]) { chSeen[ch] = true; chCount++; }
      if (isWifi && ch > 0) { if (ch <= 14) b24++; else b5++; }
      int rssi = tok[n - 6].toInt();
      if (rssi < 0 && rssi > -120) { rssiSeen = true; if (rssi > bestRssi) bestRssi = rssi; }
      String fs = tok[n - 8]; fs.trim();
      if (fs.length()) { if (!firstTs.length() || fs < firstTs) firstTs = fs; if (fs > lastTs) lastTs = fs; }
      if (isWifi) {                                      // encryption from the AuthMode column only
        String am = tok[n - 9]; am.toUpperCase();
        if (am.indexOf("WPA3") >= 0 || am.indexOf("SAE") >= 0) wpa3++;
        else if (am.indexOf("WPA2") >= 0 || am.indexOf("RSN") >= 0) wpa2++;
        else if (am.indexOf("WPA") >= 0) wpa++;
        else if (am.indexOf("WEP") >= 0) wep++;
        else opn++;                                      // [ESS] with no privacy = open
      }
    }
  }
  f.close();

  int gpsPct = nets ? (int)(gps * 100 / nets) : 0;
  long encTot = opn + wep + wpa + wpa2 + wpa3; if (encTot < 1) encTot = 1;

  auto& D = M5Cardputer.Display;
  const int W = D.width(), H = D.height();
  M5Canvas cv(&D); cv.setColorDepth(8); bool spr = cv.createSprite(W, H);
  const uint16_t BG = menuBackgroundColor, NAVY = menuSelectedBackgroundColor,
                 GRN = menuTextFocusedColor, WHT = menuTextUnFocusedColor,
                 RED = TFT_RED, ORG = TFT_ORANGE, CYN = TFT_CYAN, GRY = TFT_DARKGREY;
  auto drawTo = [&](lgfx::LovyanGFX* g) {
    g->fillScreen(BG);
    g->fillRect(0, 0, W, 14, NAVY);
    g->setTextSize(1); g->setTextColor(GRN); g->setCursor(4, 3); g->print("WIGLE SESSION");
    g->setTextColor(WHT); g->setCursor(W - 34, 3); g->printf("%d/%d", idx + 1, (int)sessions.size());
    g->setTextColor(CYN); g->setCursor(4, 17); g->print(base.substring(0, 39));
    int y = 30;
    g->setTextColor(WHT); g->setCursor(4, y); g->printf("Nets %ld  WiFi %ld  BLE %ld", nets, wifi, ble); y += 11;
    g->setCursor(4, y); g->printf("GPS %ld (%d%%)  2.4G %ld  5G %ld", gps, gpsPct, b24, b5); y += 11;
    g->setCursor(4, y); g->printf("OPN %ld WEP %ld WPA %ld W2 %ld W3 %ld", opn, wep, wpa, wpa2, wpa3); y += 11;
    // stacked encryption bar
    int bx = 4, bw = W - 8, by = y; y += 10;
    struct { long v; uint16_t c; } seg[5] = { {opn,GRY},{wep,RED},{wpa,ORG},{wpa2,GRN},{wpa3,CYN} };
    int cx = bx;
    for (int i = 0; i < 5; i++) { int sw = (int)(seg[i].v * bw / encTot); if (seg[i].v && sw < 2) sw = 2; g->fillRect(cx, by, sw, 7, seg[i].c); cx += sw; }
    g->drawRect(bx, by, bw, 7, WHT);
    g->setTextColor(WHT); g->setCursor(4, y);
    if (rssiSeen) g->printf("Chans %d   best RSSI %d dBm", chCount, bestRssi);
    else g->printf("Chans %d", chCount); y += 11;
    g->setTextColor(GRY); g->setCursor(4, y); g->print(("From " + firstTs).substring(0, 39)); y += 10;
    g->setCursor(4, y); g->print(("To   " + lastTs).substring(0, 39));
    g->fillRect(0, H - 22, W, 22, NAVY);
    g->setTextColor(WHT); g->setCursor(4, H - 19); g->print("ENT=upload  ;/.=session  d=del");
    g->setCursor(4, H - 9); g->print("DEL=back   (grey=open red=wep grn=wpa2)");
  };
  if (spr) { drawTo(&cv); cv.pushSprite(0, 0); } else drawTo(&D);

  for (;;) {
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); if (spr) cv.deleteSprite(); return; }
    if (kp(';')) { idx--; delay(150); if (spr) cv.deleteSprite(); break; }   // prev session (re-parse)
    if (kp('.')) { idx++; delay(150); if (spr) cv.deleteSprite(); break; }   // next session
    if (kp('d')) {
      enterDebounce();
      if (confirmPopup("Delete " + base + " ?")) {
        SD.remove(path);
        sessions.erase(sessions.begin() + idx);
        if (sessions.empty()) { if (spr) cv.deleteSprite(); return; }
        if (idx >= (int)sessions.size()) idx = sessions.size() - 1;
      }
      if (spr) cv.deleteSprite(); break;
    }
    if (kp(KEY_ENTER)) {
      enterDebounce();
      if (WiFi.status() != WL_CONNECTED) { wgStatus("WiFi not connected", "connect (STA) first", TFT_RED); delay(1500); }
      else { if (spr) { cv.deleteSprite(); spr = false; } wigleUploadUI(path.c_str()); }  // libere les 32Ko du sprite AVANT le handshake TLS (mbedTLS ~40Ko)
      if (spr) cv.deleteSprite(); break;                   // redraw after upload
    }
    delay(8);
  }
 }   // outer for(;;) : switch file while staying in the detail
}

// Vue de synthese Wigle en M5GFX (sprite anti-flicker) : etat WiFi/token, endpoint,
// nb de sessions CSV, resultat du dernier upload. ENTER -> liste des sessions, DEL -> retour.
static bool wigleStatusM5() {
  std::vector<String> sessions; wgListSessions(sessions);
  bool tokOk = SD.exists("/evil/wardriving/wigle.txt");
  auto& D = M5Cardputer.Display;
  const int W = D.width(), H = D.height();
  M5Canvas cv(&D); cv.setColorDepth(8);
  bool spr = cv.createSprite(W, H);
  const uint16_t BG = menuBackgroundColor, NAVY = menuSelectedBackgroundColor,
                 GRN = menuTextFocusedColor, WHT = menuTextUnFocusedColor,
                 RED = TFT_RED, GRY = TFT_DARKGREY;
  auto drawTo = [&](lgfx::LovyanGFX* g) {
    g->fillScreen(BG);
    g->fillRect(0, 0, W, 16, NAVY);
    g->setTextSize(1); g->setTextColor(GRN); g->setCursor(4, 4); g->print("WIGLE  upload wardriving");
    bool wifiOk = (WiFi.status() == WL_CONNECTED);
    g->setTextColor(wifiOk ? GRN : RED); g->setCursor(6, 22); g->printf("WiFi    : %s", wifiOk ? "connecte" : "non connecte");
    g->setTextColor(tokOk ? GRN : RED);  g->setCursor(6, 34); g->printf("Token   : %s", tokOk ? "OK" : "ABSENT");
    g->setTextColor(WHT); g->setCursor(6, 46); g->printf("Sessions: %d CSV", (int)sessions.size());
    g->setTextColor(GRY); g->setCursor(6, 58); g->print("api.wigle.net/api/v2/file/upload");
    uint16_t cc = (g_wigleLastCode == 200) ? GRN : (g_wigleLastCode == 0 ? GRY : RED);
    g->setTextColor(cc);  g->setCursor(6, 72); g->print(("Dernier : " + g_wigleLastMsg).substring(0, 40));
    g->fillRect(0, H - 24, W, 24, NAVY);
    g->setTextColor(WHT); g->setCursor(6, H - 20); g->print(tokOk ? "ENTER=sessions/upload" : "creds -> /evil/wardriving/wigle.txt");
    g->setCursor(6, H - 10); g->print("DEL=back");
  };
  if (spr) { drawTo(&cv); cv.pushSprite(0, 0); } else drawTo(&D);
  for (;;) {
    cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) { keyRelease(); if (spr) cv.deleteSprite(); return false; }
    if (kp(KEY_ENTER)) { keyRelease(); if (spr) cv.deleteSprite(); return true; }
    delay(20);
  }
}

void wigleMenu() {
  for (;;) {
    if (!wigleStatusM5()) return;        // vue synthese M5GFX ; DEL=quit, ENTER=liste sessions
    std::vector<String> sessions;
    wgListSessions(sessions);
    if (sessions.empty()) {
      std::vector<String> none = { "Rescan", "Back" };
      int a = wgSelect("Wigle - no session", none, "Put CSVs in /evil/wardriving/");
      if (a == 0) continue;
      return;
    }
    std::vector<String> rows = sessions;
    rows.push_back("** Rescan **");
    bool wifiOk = (WiFi.status() == WL_CONNECTED);
    bool tokOk  = SD.exists("/evil/wardriving/wigle.txt");
    String help = String(wifiOk ? "WiFi OK" : "WiFi KO") + (tokOk ? " token OK" : " token KO") + "  `=quit";
    int sel = wgSelect("Wigle - wardriving sessions", rows, help.c_str());
    if (sel < 0) continue;                             // DEL -> revient au dashboard M5GFX
    if (sel == (int)rows.size() - 1) continue;        // rescan
    wgSessionStats(sessions, sel);                     // stats + upload + changement de session (;/.)
  }
}

// ============================================================================
//  Geofence menu : programmer + stats/triggers + toggle
// ============================================================================
static inline void geoEnsureDir() { SD.mkdir("/evil"); SD.mkdir("/evil/wardriving"); }

static void geoWriteAll(GeoFence* z, int n) {
  geoEnsureDir();
  SD.remove("/evil/wardriving/geofences.txt");
  File f = SD.open("/evil/wardriving/geofences.txt", FILE_WRITE);
  if (!f) return;
  f.println("# lat,lon,radius_m,name[,action]  (action = name of a module launched on ENTRY ; empty = tracking only)");
  f.println("# ex tracking : 48.8584,2.2945,80,Tour Eiffel");
  f.println("# ex action   : 48.8584,2.2945,80,Bureau,Handshake Master");
  for (int i = 0; i < n; i++) {
    if (z[i].action[0]) f.printf("%.6f,%.6f,%.1f,%s,%s\n", z[i].lat, z[i].lon, z[i].radius, z[i].name, z[i].action);
    else                f.printf("%.6f,%.6f,%.1f,%s\n",    z[i].lat, z[i].lon, z[i].radius, z[i].name);
  }
  f.close();
}

static void geoAddZoneUI() {
  String la = promptInput("Latitude >");
  String lo = promptInput("Longitude >");
  String r  = promptInput("Radius (m) >");
  String nm = promptInput("Zone name >");
  nm.trim(); if (!nm.length()) nm = "zone";
  // action optionnelle = nom exact d'un module a lancer a l'entree (vide = tracking seul)
  String ac = promptInput("Action module (vide=aucune) >"); ac.trim();
  geoEnsureDir();
  File f = SD.open("/evil/wardriving/geofences.txt", FILE_APPEND);
  if (!f) { f = SD.open("/evil/wardriving/geofences.txt", FILE_WRITE);
            if (f) f.println("# lat,lon,radius_m,name[,action]"); }
  if (f) {
    if (ac.length()) f.printf("%.6f,%.6f,%.1f,%s,%s\n", la.toFloat(), lo.toFloat(), r.toFloat(), nm.c_str(), ac.c_str());
    else             f.printf("%.6f,%.6f,%.1f,%s\n",    la.toFloat(), lo.toFloat(), r.toFloat(), nm.c_str());
    f.close();
  }
  wgStatus("Zone added", (nm + (ac.length() ? (" -> " + ac) : String(" (tracking)"))).c_str(), TFT_GREEN); delay(1200);
}

// Ajoute une zone a la POSITION GPS COURANTE ("ici, dans un rayon de X") : pas de lat/lon a saisir.
static void geoAddZoneHereUI() {
  // attend un fix GPS (alimente en continu via cardgps), DEL = annuler
  uint32_t t0 = millis();
  while (!gps.location.isValid()) {
    while (cardgps.available()) gps.encode(cardgps.read());
    wgStatus("Position ICI : attente fix GPS", (String("sats ") + (int)gps.satellites.value() + "   DEL=annuler").c_str(), TFT_ORANGE);
    cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) { keyRelease(); return; }
    delay(80);
    if (millis() - t0 > 120000) { wgStatus("No GPS fix", "retry under open sky", TFT_RED); delay(1500); return; }
  }
  float la = gps.location.lat(), lo = gps.location.lng();
  wgStatus("Position captee", (String(la, 5) + ", " + String(lo, 5)).c_str(), TFT_GREEN); delay(900);
  String r  = promptInput("Radius (m, def 50) >"); r.trim();  float rad = r.length() ? r.toFloat() : 50.0f; if (rad < 1) rad = 50.0f;
  String nm = promptInput("Zone name >"); nm.trim(); if (!nm.length()) nm = "here";
  String ac = promptInput("Action module (vide=aucune) >"); ac.trim();
  geoEnsureDir();
  File f = SD.open("/evil/wardriving/geofences.txt", FILE_APPEND);
  if (!f) { f = SD.open("/evil/wardriving/geofences.txt", FILE_WRITE); if (f) f.println("# lat,lon,radius_m,name[,action]"); }
  if (f) {
    if (ac.length()) f.printf("%.6f,%.6f,%.1f,%s,%s\n", la, lo, rad, nm.c_str(), ac.c_str());
    else             f.printf("%.6f,%.6f,%.1f,%s\n",    la, lo, rad, nm.c_str());
    f.close();
  }
  wgStatus("Zone HERE added", (nm + " r" + String((int)rad) + "m" + (ac.length() ? (" -> " + ac) : String(" (tracking)"))).c_str(), TFT_GREEN); delay(1300);
}

static void geoProgramUI() {
  for (;;) {
    GeoCtx ctx = geoLoad();
    std::vector<String> rows;
    for (int i = 0; i < ctx.count; i++)
      rows.push_back(String(ctx.zones[i].name) + " r" + String((int)ctx.zones[i].radius) + "m"
                     + (ctx.zones[i].action[0] ? (String(" >") + ctx.zones[i].action) : String("")));
    rows.push_back("** + Add zone **");
    rows.push_back("** Back **");
    int sel = wgSelect("Programmed geofences", rows, ";/.=move ENT=ok `=back");
    if (sel < 0 || sel == (int)rows.size() - 1) { geoFree(ctx); return; }
    if (sel == (int)rows.size() - 2) { geoFree(ctx); geoAddZoneUI(); continue; }
    // action sur une zone existante
    std::vector<String> acts = { "Set/change action", "Remove action", "Delete zone", "Back" };
    int a = wgSelect(("Zone: " + String(ctx.zones[sel].name)).c_str(), acts, "ENT=ok `=back");
    if (a == 0) {                                   // definir/changer l'action (module a lancer a l'entree)
      String ac = promptInput("Action module (vide=aucune) >"); ac.trim();
      strncpy(ctx.zones[sel].action, ac.c_str(), sizeof(ctx.zones[sel].action) - 1);
      ctx.zones[sel].action[sizeof(ctx.zones[sel].action) - 1] = 0;
      geoWriteAll(ctx.zones, ctx.count);
      wgStatus("Action definie", ac.length() ? ac.c_str() : "(aucune)", TFT_GREEN); delay(1000);
    } else if (a == 1) {                            // retirer l'action -> redevient tracking seul
      ctx.zones[sel].action[0] = 0;
      geoWriteAll(ctx.zones, ctx.count);
      wgStatus("Action retiree", "tracking seul", TFT_ORANGE); delay(900);
    } else if (a == 2) {                            // supprimer la zone
      for (int i = sel; i < ctx.count - 1; i++) ctx.zones[i] = ctx.zones[i + 1];
      geoWriteAll(ctx.zones, ctx.count - 1);
      wgStatus("Zone deleted", nullptr, TFT_ORANGE); delay(900);
    }
    geoFree(ctx);
  }
}

static void geoStatsUI() {
  File f = SD.open("/evil/wardriving/geofence-events.txt", FILE_READ);
  if (!f) { wgStatus("No event", "(no trigger yet)", TFT_DARKGREY); wgAnyKey(4000); return; }
  long enters = 0, exits = 0;
  std::vector<String> last;
  while (f.available()) {
    String l = f.readStringUntil('\n'); l.trim();
    if (!l.length()) continue;
    if (l.indexOf("ENTER") >= 0) enters++; else if (l.indexOf("EXIT") >= 0) exits++;
    last.push_back(l);
    if (last.size() > 8) last.erase(last.begin());
  }
  f.close();
  std::vector<String> rows;
  rows.push_back("Triggers: ENTER " + String(enters) + "  EXIT " + String(exits));
  rows.push_back("--- recent events ---");
  for (auto& e : last) rows.push_back(e);
  rows.push_back("** Back **");
  int sel = wgSelect("Geofence - stats/triggers", rows, "`=back");
  (void)sel;
}

// ---- Vue GPS M5GFX : boussole radar des geofences (distance + direction) ----
// Boussole (nous au centre, Nord en haut) : chaque zone = un point a son cap, rayon
// proportionnel a la distance (sqrt pour l'etalement). ;/. change la zone focus (affichee
// en gros a gauche : nom, distance, cap, fleche cardinale, DANS LA ZONE si on y est).
// Sprite M5Canvas anti-flicker. GPS alimente en continu via cardgps.
static void geoRadarUI() {
  GeoCtx ctx = geoLoad();
  if (ctx.count == 0) { wgStatus("No geofence", "program zones first", TFT_ORANGE); wgAnyKey(3000); geoFree(ctx); return; }

  auto& D = M5Cardputer.Display;
  const int W = D.width(), H = D.height();
  M5Canvas cv(&D);
  cv.setColorDepth(8);
  bool spr = cv.createSprite(W, H);

  const uint16_t BG = menuBackgroundColor, NAVY = menuSelectedBackgroundColor,
                 GRN = menuTextFocusedColor, WHT = menuTextUnFocusedColor,
                 CY = TFT_CYAN, RED = TFT_RED, GRY = TFT_DARKGREY;
  const int cx = W - 62, cy = 76, Rr = 48;   // boussole a droite
  int focus = 0;

  auto drawTo = [&](lgfx::LovyanGFX* g) {
    g->fillScreen(BG);
    bool fix = gps.location.isValid();
    int sats = (int)gps.satellites.value();
    g->fillRect(0, 0, W, 16, NAVY);
    g->setTextSize(1); g->setTextColor(GRN); g->setCursor(4, 4); g->printf("GEOFENCES %d", ctx.count);
    g->setTextColor(fix ? GRN : RED); g->setCursor(W - 88, 4); g->printf(fix ? "GPS fix s%d" : "no fix s%d", sats);

    g->drawCircle(cx, cy, Rr, GRY);
    g->drawCircle(cx, cy, Rr / 2, 0x4208);
    g->fillCircle(cx, cy, 2, WHT);
    g->setTextColor(GRY);
    g->setCursor(cx - 3, cy - Rr - 9); g->print("N");
    g->setCursor(cx - 3, cy + Rr + 2);  g->print("S");
    g->setCursor(cx + Rr + 3, cy - 3);  g->print("E");
    g->setCursor(cx - Rr - 9, cy - 3);  g->print("O");

    if (!fix) {
      g->setTextColor(WHT); g->setCursor(6, 40); g->print("En attente de fix GPS...");
      g->setTextColor(GRY); g->setCursor(6, 54); g->print("go under open sky");
      g->setTextColor(WHT); g->setCursor(6, H - 10); g->print(";/.=zone  DEL=back");
      return;
    }
    float myLat = gps.location.lat(), myLon = gps.location.lng();
    float maxD = 1.0f;
    for (int i = 0; i < ctx.count; i++) { float d = geoDistM(myLat, myLon, ctx.zones[i].lat, ctx.zones[i].lon); if (d > maxD) maxD = d; }
    for (int i = 0; i < ctx.count; i++) {
      float d = geoDistM(myLat, myLon, ctx.zones[i].lat, ctx.zones[i].lon);
      float b = geoBearing(myLat, myLon, ctx.zones[i].lat, ctx.zones[i].lon);
      float rr = (Rr - 4) * sqrtf(d / maxD); if (rr > Rr - 3) rr = Rr - 3;
      float ang = radians(b - 90.0f);
      int px = cx + (int)(rr * cosf(ang)), py = cy + (int)(rr * sinf(ang));
      bool inside = (d <= ctx.zones[i].radius);
      uint16_t col = inside ? GRN : (i == focus ? CY : WHT);
      if (i == focus) g->drawLine(cx, cy, px, py, CY);
      g->fillCircle(px, py, (i == focus) ? 4 : 2, col);
    }
    GeoFence& z = ctx.zones[focus];
    float d = geoDistM(myLat, myLon, z.lat, z.lon);
    float b = geoBearing(myLat, myLon, z.lat, z.lon);
    bool inside = (d <= z.radius);
    g->setTextColor(CY);  g->setCursor(6, 22); g->printf("[%d/%d]", focus + 1, ctx.count);
    g->setTextColor(WHT); g->setCursor(6, 34); g->print(String(z.name).substring(0, 15));
    g->setTextColor(inside ? GRN : WHT); g->setCursor(6, 48);
    if (d < 1000) g->printf("%d m", (int)d); else g->printf("%.2f km", d / 1000.0f);
    g->setTextColor(WHT); g->setCursor(6, 60); g->printf("cap %d deg", (int)b);
    static const char* arr[] = { "N", "NE", "E", "SE", "S", "SO", "O", "NO" };
    int qi = ((int)((b + 22.5f) / 45.0f)) & 7;
    g->setTextColor(CY); g->setCursor(6, 72); g->printf("-> %s", arr[qi]);
    if (inside)            { g->setTextColor(GRN); g->setCursor(6, 86); g->print("DANS LA ZONE"); }
    else if (z.action[0])  { g->setTextColor(GRY); g->setCursor(6, 86); g->print(String("act:") + z.action); }
    g->setTextColor(WHT); g->setCursor(6, H - 10); g->print(";/.=zone  DEL=back");
  };

  for (;;) {
    while (cardgps.available()) gps.encode(cardgps.read());   // alimente le GPS
    if (spr) { drawTo(&cv); cv.pushSprite(0, 0); } else drawTo(&D);
    uint32_t t0 = millis();
    while (millis() - t0 < 250) {                             // ~4 fps, reactif aux touches
      cardUpdate();
      while (cardgps.available()) gps.encode(cardgps.read());
      if (kp('`') || kp(KEY_BACKSPACE)) { keyRelease(); if (spr) cv.deleteSprite(); geoFree(ctx); return; }
      if (kp(';')) { focus = (focus + ctx.count - 1) % ctx.count; delay(130); break; }
      if (kp('.')) { focus = (focus + 1) % ctx.count; delay(130); break; }
      delay(10);
    }
  }
}

// Vue carte offline + tracking GPS facon Strava (defini dans mapview.h, inclus apres).
namespace mapview { void mapViewUI(double startLat, double startLon); }

void geofenceMenu() {
  for (;;) {
    GeoCtx ctx = geoLoad();
    int nz = ctx.count; geoFree(ctx);
    std::vector<String> rows = {
      "Program zones (" + String(nz) + ")",
      "Add zone HERE (GPS)",
      "GPS view (radar)",
      "Offline map + track",
      "Stats / triggers",
      String("Active: ") + (g_geofenceEnabled ? "ON" : "OFF"),
      "Back"
    };
    int sel = wgSelect("Geofences", rows, ";/.=move ENT=ok `=back");
    if (sel < 0 || sel == 6) return;
    if (sel == 0) geoProgramUI();
    else if (sel == 1) geoAddZoneHereUI();
    else if (sel == 2) geoRadarUI();
    else if (sel == 3) {
      double sLat = 49.1829, sLon = -0.3707;             // Caen par defaut (si pas de fix)
      for (int i = 0; i < 400 && cardgps.available(); i++) gps.encode(cardgps.read());
      if (gps.location.isValid()) { sLat = gps.location.lat(); sLon = gps.location.lng(); }
      mapview::mapViewUI(sLat, sLon);
    }
    else if (sel == 4) geoStatsUI();
    else if (sel == 5) { g_geofenceEnabled = !g_geofenceEnabled; }
  }
}

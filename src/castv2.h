// ============================================================================
//  castv2.h — Chromecast Cast v2 (CastChannel : protobuf length-prefixe sur TLS :8009)
//  Objectif : lancer le receiver YouTube (appId 233637DE) et flinguer une video
//  par videoId (namespace YouTube MDX). Sequence inspiree de pychromecast.
//  Protobuf CastMessage encode a la main (champs connus) : pas de lib protobuf.
// ============================================================================
#pragma once
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

namespace castv2 {

// ---- encodeur protobuf minimal (CastMessage) --------------------------------
static void pbLen(String& out, uint32_t n) {           // varint longueur
  do { uint8_t b = n & 0x7F; n >>= 7; if (n) b |= 0x80; out += (char)b; } while (n);
}
static void pbVarintField(String& out, uint8_t tag, uint32_t val) {
  out += (char)tag; pbLen(out, val);
}
static void pbStringField(String& out, uint8_t tag, const String& s) {
  out += (char)tag; pbLen(out, s.length()); out += s;
}
// CastMessage avec payload STRING : v=0, src, dst, namespace, payload_type=0, payload_utf8
static String buildMsg(const String& src, const String& dst, const String& ns, const String& payload) {
  String m;
  pbVarintField(m, 0x08, 0);        // protocol_version = CASTV2_1_0
  pbStringField(m, 0x12, src);      // source_id
  pbStringField(m, 0x1A, dst);      // destination_id
  pbStringField(m, 0x22, ns);       // namespace
  pbVarintField(m, 0x28, 0);        // payload_type = STRING
  pbStringField(m, 0x32, payload);  // payload_utf8
  return m;
}
static bool sendMsg(WiFiClientSecure& c, const String& src, const String& dst,
                    const String& ns, const String& payload) {
  String m = buildMsg(src, dst, ns, payload);
  uint32_t n = m.length();
  uint8_t hdr[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
  if (c.write(hdr, 4) != 4) return false;
  return c.write((const uint8_t*)m.c_str(), n) == (int)n;
}
// Lit un CastMessage ; extrait namespace (champ 4) et payload_utf8 (champ 6).
static bool readMsg(WiFiClientSecure& c, String& nsOut, String& plOut, uint32_t toMs) {
  nsOut = ""; plOut = "";
  uint32_t t0 = millis();
  uint8_t hdr[4]; int got = 0;
  while (got < 4 && millis() - t0 < toMs) { if (c.available()) hdr[got++] = c.read(); else delay(2); }
  if (got < 4) return false;
  uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
  if (len == 0 || len > 8192) return false;
  uint8_t* buf = (uint8_t*)malloc(len);
  if (!buf) return false;
  uint32_t r = 0;
  while (r < len && millis() - t0 < toMs) { if (c.available()) buf[r++] = c.read(); else delay(2); }
  if (r < len) { free(buf); return false; }
  uint32_t i = 0;
  while (i < len) {
    uint8_t tag = buf[i++];
    if (tag == 0x08 || tag == 0x28) {                 // varint -> skip
      while (i < len && (buf[i] & 0x80)) i++; i++;
    } else if (tag == 0x12 || tag == 0x1A || tag == 0x22 || tag == 0x32) {  // length-delim
      uint32_t fl = 0; int sh = 0;
      while (i < len && (buf[i] & 0x80)) { fl |= (uint32_t)(buf[i] & 0x7F) << sh; sh += 7; i++; }
      if (i < len) { fl |= (uint32_t)(buf[i] & 0x7F) << sh; i++; }
      String s; for (uint32_t k = 0; k < fl && i < len; k++) s += (char)buf[i++];
      if (tag == 0x22) nsOut = s; else if (tag == 0x32) plOut = s;
    } else break;
  }
  free(buf);
  return true;
}

static const char* NS_CONN = "urn:x-cast:com.google.cast.tp.connection";
static const char* NS_HEART = "urn:x-cast:com.google.cast.tp.heartbeat";
static const char* NS_RECV  = "urn:x-cast:com.google.cast.receiver";
static const char* NS_YTMDX = "urn:x-cast:com.google.youtube.mdx";
static const char* YT_APPID = "233637DE";   // YouTube receiver

// --- Etape A : LAUNCH YouTube via Cast v2 + recup du screenId (persistant) ---
// Ferme la TLS Cast avant de rendre (sequentiel -> 1 seule TLS a la fois, heap-safe).
static bool castGetScreenId(IPAddress ip, String& screenId, String& log) {
  if (WiFi.status() != WL_CONNECTED) { log = "WiFi not connected"; return false; }
  WiFiClientSecure c;
  c.setInsecure(); c.setHandshakeTimeout(8);
  Serial.println("[CV2] TLS connect " + ip.toString() + ":8009...");
  if (!c.connect(ip, 8009)) { log = "M1 TLS KO"; return false; }
  log = "M1 TLS OK; "; Serial.println("[CV2] M1 TLS OK");
  const String SRC = "sender-0"; String ns, pl, transport;
  sendMsg(c, SRC, "receiver-0", NS_CONN, "{\"type\":\"CONNECT\"}");
  sendMsg(c, SRC, "receiver-0", NS_RECV,
          String("{\"type\":\"LAUNCH\",\"appId\":\"") + YT_APPID + "\",\"requestId\":1}");
  uint32_t t0 = millis();
  while (millis() - t0 < 10000) {
    if (!readMsg(c, ns, pl, 10000)) break;
    if (pl.indexOf("\"PING\"") >= 0) { sendMsg(c, SRC, "receiver-0", NS_HEART, "{\"type\":\"PONG\"}"); continue; }
    if (pl.indexOf("transportId") >= 0 && pl.indexOf(YT_APPID) >= 0) {
      int p = pl.indexOf("\"transportId\":\""); if (p >= 0) { p += 15; transport = pl.substring(p, pl.indexOf('"', p)); break; }
    }
  }
  if (!transport.length()) { log += "M2 pas de transportId"; c.stop(); return false; }
  log += "M2 launch OK; "; Serial.println("[CV2] M2 app lancee transport=" + transport);
  sendMsg(c, SRC, transport, NS_CONN, "{\"type\":\"CONNECT\"}");
  sendMsg(c, SRC, transport, NS_YTMDX, "{\"type\":\"getMdxSessionStatus\"}");
  uint32_t t1 = millis();
  while (millis() - t1 < 4000) {
    if (!readMsg(c, ns, pl, 4000)) break;
    if (pl.indexOf("\"PING\"") >= 0) { sendMsg(c, SRC, "receiver-0", NS_HEART, "{\"type\":\"PONG\"}"); }
    int p = pl.indexOf("\"screenId\":\""); if (p >= 0) { p += 12; screenId = pl.substring(p, pl.indexOf('"', p)); break; }
  }
  c.stop();                                    // ferme Cast : l'app reste vivante ~qq s
  if (!screenId.length()) { log += "M3 pas de screenId"; return false; }
  log += "M3 screenId OK; "; Serial.println("[CV2] M3 screenId=" + screenId.substring(0, 12) + "...");
  return true;
}

// --- Etape B : API YouTube Lounge (HTTPS youtube.com) : token -> bind -> setPlaylist ---
static String ytExtract(const String& s, const char* pre) {   // valeur entre guillemets apres `pre`
  int p = s.indexOf(pre); if (p < 0) return "";
  p += strlen(pre); int e = s.indexOf('"', p); return (e < 0) ? "" : s.substring(p, e);
}
// Session Lounge reutilisable : bind une fois, puis envoie plusieurs commandes.
struct LoungeSession { String base, sid, gsess; uint32_t rid = 0, ofs = 0; bool ok = false; };

static bool castLoungeBind(const String& screenId, LoungeSession& se) {
  WiFiClientSecure sec; sec.setInsecure();
  HTTPClient http; http.setReuse(false);
  String devid; for (int i = 0; i < 32; i++) devid += "0123456789abcdef"[esp_random() & 0xF];
  se.rid = 20000 + (esp_random() % 70000); se.ofs = 0; se.ok = false;
  String tok;
  if (http.begin(sec, "https://www.youtube.com/api/lounge/pairing/get_lounge_token_batch")) {
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    http.addHeader("Origin", "https://www.youtube.com");
    int code = http.POST("screen_ids=" + screenId);
    if (code == 200) tok = ytExtract(http.getString(), "\"loungeToken\":\"");
    http.end();
  }
  if (!tok.length()) { Serial.println("[CV2] Lounge token KO"); return false; }
  se.base = "device=REMOTE_CONTROL&id=" + devid + "&name=Evil-Cardputer&app=youtube-desktop"
            "&loungeIdToken=" + tok + "&VER=8&v=2&t=1&CVER=1";
  String url = "https://www.youtube.com/api/lounge/bc/bind?" + se.base +
               "&RID=" + String(se.rid) + "&zx=" + String(esp_random(), HEX);
  if (http.begin(sec, url)) {
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    http.addHeader("Origin", "https://www.youtube.com");
    int code = http.POST("count=0");
    if (code == 200) { String b = http.getString(); se.sid = ytExtract(b, "\"c\",\""); se.gsess = ytExtract(b, "\"S\",\""); }
    http.end();
  }
  se.ok = (se.sid.length() && se.gsess.length());
  Serial.println(se.ok ? ("[CV2] Lounge bind OK sid=" + se.sid) : "[CV2] Lounge bind KO");
  return se.ok;
}
// Envoie une commande Lounge (sc = setPlaylist/play/pause/next/previous/seekTo...).
// `extra` = parametres req0_* additionnels (sans & initial), optionnel.
static int castLoungeCmd(LoungeSession& se, const String& sc, const String& extra = "") {
  if (!se.ok) return -1;
  se.rid++; se.ofs++;
  WiFiClientSecure sec; sec.setInsecure();
  HTTPClient http; http.setReuse(false);
  String url = "https://www.youtube.com/api/lounge/bc/bind?" + se.base +
               "&RID=" + String(se.rid) + "&SID=" + se.sid + "&gsessionid=" + se.gsess +
               "&AID=5&zx=" + String(esp_random(), HEX);
  String body = "count=1&ofs=" + String(se.ofs) + "&req0__sc=" + sc + (extra.length() ? ("&" + extra) : "");
  int code = -1;
  if (http.begin(sec, url)) {
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    http.addHeader("Origin", "https://www.youtube.com");
    code = http.POST(body); http.end();
  }
  Serial.println("[CV2] Lounge " + sc + " -> " + String(code));
  return code;
}
static int castLoungePlay(const String& screenId, const String& videoId, String& log) {
  LoungeSession se;
  if (!castLoungeBind(screenId, se)) { log += "Lounge bind KO"; return -5; }
  int code = castLoungeCmd(se, "setPlaylist",
    "req0_videoId=" + videoId + "&req0_currentTime=0&req0_currentIndex=0&req0_listId="
    "&req0_audioOnly=false&req0_params=&req0_playerParams=");
  log += (code == 200) ? "setPlaylist OK (video lancee)" : ("setPlaylist HTTP " + String(code));
  return (code == 200) ? 0 : -6;
}

// --- Commandes receiver Cast (UNIVERSELLES : toutes versions Chromecast/Cast) ---
// Ouvre une TLS :8009, CONNECT receiver-0, envoie `payload` sur le receiver namespace,
// lit le RECEIVER_STATUS ; remplit *level (0..1) et *muted si fournis. Ferme la TLS.
static bool castV2ReceiverCmd(IPAddress ip, const String& payload, float* level = nullptr, bool* muted = nullptr) {
  WiFiClientSecure c; c.setInsecure(); c.setHandshakeTimeout(6);
  if (!c.connect(ip, 8009)) return false;
  const String SRC = "sender-0"; String ns, pl; bool got = false;
  sendMsg(c, SRC, "receiver-0", NS_CONN, "{\"type\":\"CONNECT\"}");
  sendMsg(c, SRC, "receiver-0", NS_RECV, payload);
  uint32_t t0 = millis();
  while (millis() - t0 < 2500) {
    if (!readMsg(c, ns, pl, 2500)) break;
    if (pl.indexOf("\"PING\"") >= 0) { sendMsg(c, SRC, "receiver-0", NS_HEART, "{\"type\":\"PONG\"}"); continue; }
    if (pl.indexOf("\"volume\"") >= 0) {
      if (level) { int p = pl.indexOf("\"level\":"); if (p >= 0) *level = pl.substring(p + 8).toFloat(); }
      if (muted) *muted = (pl.indexOf("\"muted\":true") >= 0);
      got = true; break;
    }
  }
  c.stop();
  Serial.println("[CV2] receiver cmd ok=" + String(got) + (level ? (" vol=" + String(*level, 2)) : ""));
  return got;
}
static bool castV2GetVolume(IPAddress ip, float& level, bool& muted) {
  return castV2ReceiverCmd(ip, "{\"type\":\"GET_STATUS\",\"requestId\":1}", &level, &muted);
}
static bool castV2SetVolume(IPAddress ip, float level) {   // 0.0 .. 1.0
  if (level < 0) level = 0; if (level > 1) level = 1;
  char buf[96]; snprintf(buf, sizeof(buf), "{\"type\":\"SET_VOLUME\",\"volume\":{\"level\":%.3f},\"requestId\":2}", level);
  return castV2ReceiverCmd(ip, buf);
}
static bool castV2SetMute(IPAddress ip, bool m) {
  return castV2ReceiverCmd(ip, String("{\"type\":\"SET_VOLUME\",\"volume\":{\"muted\":") + (m ? "true" : "false") + "},\"requestId\":3}");
}
static bool castV2StopApp(IPAddress ip) {   // ferme l'app en cours (retour Backdrop)
  return castV2ReceiverCmd(ip, "{\"type\":\"STOP\",\"requestId\":4}");
}

// Flow complet : Cast v2 (launch+screenId) PUIS Lounge (token+bind+setPlaylist).
static int flingYouTube(IPAddress ip, const String& videoId, String& log) {
  String screenId;
  if (!castGetScreenId(ip, screenId, log)) return -2;
  return castLoungePlay(screenId, videoId, log);
}

} // namespace castv2

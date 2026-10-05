// ============================================================================
//  tpms_multi.h — Décodeurs TPMS multi-marques
// ----------------------------------------------------------------------------
//  Portés du PR Bruce #2675 (BruceDevices/firmware), eux-mêmes dérivés des
//  décodeurs Flipper/rtl_433. Schrader / Ford / Renault / Citroën / Toyota.
//  Approche : durations -> bitmap suréchantillonné -> recherche sync ->
//  décodage line-code (Manchester/diff) -> CRC -> extraction id/pression/temp.
//  crc8 renommé tpmsx_crc8 (signature init,poly) pour ne pas entrer en
//  collision avec le tpms_crc8(poly,init) déjà présent dans le firmware.
// ============================================================================
#pragma once
#include <vector>
#include <cstdint>
#include <cstring>

// ─────────────────────────────── Helpers ───────────────────────────────────
static inline std::vector<bool> tpms_durations_to_bitmap(
    const std::vector<int>& durations, unsigned int te, unsigned int te_delta) {
    (void)te_delta;
    // Bornes anti-explosion : une trame TPMS fait < 200 bits. Sans borne, une
    // longue impulsion (bruit/gap, jusqu'a 20 ms) avec te=52 vaut ~380 "bits" et,
    // multiplie par des milliers de durations de bruit, fait exploser le vecteur
    // -> alloc/free repetee de gros vector<bool> -> fragmentation du tas -> OOM/abort
    // au bout de quelques secondes de scan en environnement bruyant.
    const size_t   BITS_CAP     = 8192;   // >> toute trame reelle
    const unsigned COUNT_CAP    = 64;     // un seul edge ne peut pas valoir des centaines de bits
    std::vector<bool> bits;
    bits.reserve(durations.size() * 2 + 16);
    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = raw > 0 ? (unsigned)raw : (unsigned)(-raw);
        unsigned int count = (dur + te / 2) / te;
        if (count == 0) count = 1;
        if (count > COUNT_CAP) count = COUNT_CAP;
        for (unsigned int i = 0; i < count && bits.size() < BITS_CAP; i++) bits.push_back(level);
        if (bits.size() >= BITS_CAP) break;
    }
    return bits;
}

#define TPMS_SEEK_NOT_FOUND UINT32_MAX

static inline uint32_t tpms_bitmap_seek_bits(
    const std::vector<bool>& bits, uint32_t startpos, uint32_t maxbits, const char* pattern) {
    uint32_t patlen = (uint32_t)strlen(pattern);
    if (patlen == 0 || startpos + patlen > maxbits) return TPMS_SEEK_NOT_FOUND;
    for (uint32_t i = startpos; i + patlen <= maxbits; i++) {
        bool match = true;
        for (uint32_t j = 0; j < patlen; j++)
            if (bits[i + j] != (pattern[j] == '1')) { match = false; break; }
        if (match) return i;
    }
    return TPMS_SEEK_NOT_FOUND;
}

static inline uint32_t tpms_convert_from_line_code(
    uint8_t* buf, uint32_t buflen, const std::vector<bool>& bits,
    uint32_t offset, uint32_t maxbits, const char* zero_pattern, const char* one_pattern) {
    uint32_t zlen = (uint32_t)strlen(zero_pattern);
    uint32_t olen = (uint32_t)strlen(one_pattern);
    if (zlen != olen) return 0;
    uint32_t symlen = zlen, bitpos = 0, byte_pos = 0;
    while (offset + symlen <= maxbits && byte_pos < buflen) {
        bool is_zero = true;
        for (uint32_t j = 0; j < symlen; j++)
            if (bits[offset + j] != (zero_pattern[j] == '1')) { is_zero = false; break; }
        if (is_zero) {
            if (bitpos == 0) buf[byte_pos] = 0;
            buf[byte_pos] = (uint8_t)((buf[byte_pos] << 1) | 0);
            bitpos++; offset += symlen; if (bitpos == 8) { bitpos = 0; byte_pos++; }
            continue;
        }
        bool is_one = true;
        for (uint32_t j = 0; j < symlen; j++)
            if (bits[offset + j] != (one_pattern[j] == '1')) { is_one = false; break; }
        if (is_one) {
            if (bitpos == 0) buf[byte_pos] = 0;
            buf[byte_pos] = (uint8_t)((buf[byte_pos] << 1) | 1);
            bitpos++; offset += symlen; if (bitpos == 8) { bitpos = 0; byte_pos++; }
            continue;
        }
        break;
    }
    return byte_pos * 8 + bitpos;
}

static inline uint32_t tpms_convert_from_diff_manchester(
    uint8_t* buf, uint32_t buflen, const std::vector<bool>& bits,
    uint32_t offset, uint32_t maxbits, bool previous) {
    uint32_t byte_pos = 0; int bitpos = 0;
    while (offset + 2 <= maxbits && byte_pos < buflen) {
        bool start_level = bits[offset];
        bool mid_level = bits[offset + 1];
        bool bit_val = (start_level != previous) ? false : true;
        previous = mid_level;
        if (bitpos == 0) buf[byte_pos] = 0;
        buf[byte_pos] = (uint8_t)((buf[byte_pos] << 1) | (bit_val ? 1 : 0));
        bitpos++; offset += 2; if (bitpos == 8) { bitpos = 0; byte_pos++; }
    }
    return byte_pos * 8 + (uint32_t)bitpos;
}

static inline uint8_t tpmsx_crc8(const uint8_t* data, size_t len, uint8_t init, uint8_t poly) {
    uint8_t crc = init;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ poly) : (uint8_t)(crc << 1);
    }
    return crc;
}

// Résultat décodé (sous-ensemble de RfCodes Bruce + pression/temp explicites)
struct TpmsCode {
    uint64_t key = 0;
    uint32_t serial = 0;
    uint8_t  btn = 0;
    uint16_t cnt = 0;
    uint32_t fix = 0;      // batterie (Citroën)
    int      Bit = 0;
    int      te = 0;
    const char* protocol = "";
    const char* preset = "";
    float kpa = 0.0f;      // pression en kPa
    int   temp = 0;        // température en °C
    uint8_t raw[10] = {0}; // trame brute décodée (pour spoof/ré-émission)
    uint8_t raw_len = 0;
};
typedef TpmsCode RfCodes;

// ────────────────────────────── Décodeurs ──────────────────────────────────
// Schrader (OOK/AM, 120us, 64 bits)
static bool rf_decode_schrader_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 120, 40);
    if (bits.size() < 64) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "1111010101" "01011010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 10;
    uint8_t raw[8];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 64) return false;
    raw[0] |= 0xf0;
    if (tpmsx_crc8(raw, sizeof(raw) - 1, 0xf0, 0x07) != raw[7]) return false;
    float kpa = (float)raw[5] * 2.5f; int temp = raw[6] - 50;
    uint8_t id[4] = {(uint8_t)(raw[1] & 0x0F), raw[2], raw[3], raw[4]};  // id 28-bit (rtl_433: &0x0F, pas &7)
    uint32_t id_val = ((uint32_t)id[0] << 24) | ((uint32_t)id[1] << 16) | ((uint32_t)id[2] << 8) | id[3];
    out.serial = id_val; out.kpa = kpa; out.temp = temp; out.Bit = 64; out.te = 120;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Schrader"; out.preset = "Ook270Async";
    return true;
}

// Ford (FSK/FM, 52us, 64 bits)
static bool rf_decode_ford_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 64) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "010101010101" "0110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 16;
    uint8_t raw[8];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 64) return false;
    uint8_t crc = 0; for (int j = 0; j < 7; j++) crc += raw[j];
    if (crc != raw[7]) return false;
    // Check syndrome flags/etat b[6] (rtl_433 tpms_ford) : le SUM-8 seul est faible
    // et laisse passer du bruit -> on exige un etat valide (learn/rest/moving) et
    // les bits 0x80/0x10 a 0. Sinon faux positif.
    { uint8_t st = raw[6] & 0x4c;
      if (st != 0x08 && st != 0x04 && st != 0x44) return false;
      if (raw[6] & 0x90) return false; }
    float psi = 0.25f * (float)(((raw[6] & 0x20) << 3) | raw[4]);
    int temp = (raw[5] & 0x80) ? 0 : raw[5] - 56;
    int flags = raw[5] & 0x7f;
    uint32_t id_val = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.serial = id_val; out.btn = (uint8_t)(flags & 0x7F);
    out.kpa = psi * 6.89476f; out.temp = temp; out.Bit = 64; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Ford"; out.preset = "2FSKDev238Async";
    return true;
}

// Renault (FSK/FM, 48us, 72 bits)
static bool rf_decode_renault_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    // Te=52us (aligne sur rtl_433 tpms_renault short_width=52, comme Citroen/Ford/Toyota ;
    // etait 48 -> pouvait manquer les capteurs Renault reels).
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 80) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "01010101010101010110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 20;
    uint8_t raw[9];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 72) return false;
    if (tpmsx_crc8(raw, 8, 0, 7) != raw[8]) return false;
    uint8_t flags = raw[0] >> 2;
    float kpa = 0.75f * (float)(((uint32_t)(raw[0] & 3) << 8) | raw[1]);
    int temp = raw[2] - 30;
    // id little-endian comme rtl_433 : b5<<16 | b4<<8 | b3
    uint32_t id_val = ((uint32_t)raw[5] << 16) | ((uint32_t)raw[4] << 8) | raw[3];
    out.serial = id_val; out.btn = flags; out.kpa = kpa; out.temp = temp; out.Bit = 72; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Renault"; out.preset = "2FSKDev238Async";
    return true;
}

// Citroën (FSK/FM, 52us, 80 bits)
static bool rf_decode_citroen_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 80) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "01010101010101010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 17;
    uint8_t raw[10];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 80) return false;
    uint8_t crc = 0; for (int j = 1; j < 10; j++) crc ^= raw[j];
    if (crc != 0) return false;
    // Sanity non-zero pression/temp (rtl_433 tpms_citroen) : le XOR-8 est le plus
    // faible de nos checksums -> rejette les trames a pression/temp nulles (bruit).
    if (raw[6] == 0 || raw[7] == 0) return false;
    int repeat = raw[5] & 0xf;
    float kpa = (float)raw[6] * 1.364f; int temp = raw[7] - 50; int battery = raw[8];
    uint32_t id_val = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    out.serial = id_val; out.cnt = (uint16_t)repeat; out.fix = (uint32_t)battery;
    out.kpa = kpa; out.temp = temp; out.Bit = 80; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Citroen"; out.preset = "2FSKDev238Async";
    return true;
}

// Toyota (FSK/FM, diff-Manchester, 72 bits)
static bool rf_decode_toyota_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 128) return false;
    static const char* toyota_sync[] = {"00111100","001111100","00111101","001111101", nullptr};
    uint32_t off = 0; bool found = false;
    for (int j = 0; toyota_sync[j]; j++) {
        off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), toyota_sync[j]);
        if (off != TPMS_SEEK_NOT_FOUND) { off += (uint32_t)strlen(toyota_sync[j]) - 2; found = true; break; }
    }
    if (!found) return false;
    uint8_t raw[9];
    if (tpms_convert_from_diff_manchester(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), true) < 72) return false;
    if (tpmsx_crc8(raw, 8, 0x80, 7) != raw[8]) return false;
    // Check redondance pression (rtl_433 tpms_toyota) : raw[7] = pression INVERSEE.
    // Sans ce controle, un signal non-Toyota passe le CRC par coincidence -> temp/psi
    // aberrants (ex. 191C). CRC + ce check => faux positif ~1/65536.
    uint8_t pressure1 = (uint8_t)(((raw[4] & 0x7f) << 1) | (raw[5] >> 7));
    uint8_t pressure2 = (uint8_t)(raw[7] ^ 0xFF);
    if (pressure1 != pressure2) return false;
    float psi = (float)pressure1 * 0.25f - 7.0f;
    int temp = (((raw[5] & 0x7f) << 1) | (raw[6] >> 7)) - 40;
    uint32_t id_val = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.serial = id_val; out.kpa = psi * 6.89476f; out.temp = temp; out.Bit = 72; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Toyota"; out.preset = "2FSKDev238Async";
    return true;
}

// Dispatcher : essaie les 5 décodeurs sur un buffer de durées.
static bool tpms_multi_decode(const std::vector<int>& durs, TpmsCode& out) {
    if (rf_decode_schrader_tpms(durs, out)) return true;
    if (rf_decode_renault_tpms(durs, out))  return true;
    if (rf_decode_citroen_tpms(durs, out))  return true;
    if (rf_decode_ford_tpms(durs, out))     return true;
    if (rf_decode_toyota_tpms(durs, out))   return true;
    return false;
}

// Liste des capteurs vus (défini ici pour éviter le bug de prototypes arduino).
#define TPMS_MAX 16
struct TpmsSensor {
    uint32_t id; float bar; int temp; int rssi; uint32_t last; const char* proto;
    // détail complet (page détail)
    uint8_t btn; uint16_t cnt; uint32_t fix; int Bit; int te; const char* preset;
    float kpa; float freq; uint32_t first; uint32_t hits;
    uint8_t raw[10]; uint8_t raw_len;   // trame brute (pour spoof)
};

static inline void tpms_store(TpmsSensor* sens, int& sens_cnt, const TpmsCode& c,
                              int rssi, uint32_t now, float freq) {
    int idx = -1;
    for (int i = 0; i < sens_cnt; i++) if (sens[i].id == c.serial) { idx = i; break; }
    bool isNew = (idx < 0);
    if (idx < 0 && sens_cnt < TPMS_MAX) idx = sens_cnt++;
    if (idx >= 0) {
        if (isNew) { sens[idx].first = now; sens[idx].hits = 0; }
        sens[idx].id = c.serial;
        sens[idx].kpa = c.kpa;
        sens[idx].bar = c.kpa / 100.0f;   // kPa -> bar
        sens[idx].temp = c.temp;
        sens[idx].rssi = rssi;
        sens[idx].last = now;
        sens[idx].proto = c.protocol;
        sens[idx].preset = c.preset;
        sens[idx].btn = c.btn;
        sens[idx].cnt = c.cnt;
        sens[idx].fix = c.fix;
        sens[idx].Bit = c.Bit;
        sens[idx].te = c.te;
        sens[idx].freq = freq;
        memcpy(sens[idx].raw, c.raw, 10); sens[idx].raw_len = c.raw_len;
        sens[idx].hits++;
    }
}

// ── Spoof / ré-émission : ré-encode une trame (pression/temp modifiées) ──
// Recalcule le CRC, encode en Manchester line-code (préambule + sync), sort des
// durées signées (+haut/-bas) pour cc_send_raw (OOK) / cc_send_raw_fsk (FSK).
static inline int tpms_emit_slot(int32_t* out, int n, int cap, int level, int te) {
    int32_t d = level ? te : -te;
    if (n > 0 && ((out[n - 1] > 0) == (level != 0))) { out[n - 1] += d; return n; }
    if (n < cap) out[n++] = d;
    return n;
}
// skip_bits : nb de bits data déjà fournis par la queue du sync (chevauchement,
// cas Schrader où le décodeur démarre à sync_start+10 sur un sync de 18 bits).
static int tpms_encode_frame(const uint8_t* raw, int nbytes, const char* sync,
                             int te, int preamble_pairs, int32_t* out, int cap, int skip_bits = 0) {
    int n = 0;
    for (int i = 0; i < preamble_pairs; i++) { n = tpms_emit_slot(out, n, cap, 1, te); n = tpms_emit_slot(out, n, cap, 0, te); }
    for (const char* p = sync; *p; ++p) n = tpms_emit_slot(out, n, cap, (*p == '1') ? 1 : 0, te);
    int total = nbytes * 8;
    for (int i = skip_bits; i < total; i++) {
        int v = (raw[i / 8] >> (7 - (i % 8))) & 1;
        if (v) { n = tpms_emit_slot(out, n, cap, 1, te); n = tpms_emit_slot(out, n, cap, 0, te); }  // bit1 -> "10"
        else   { n = tpms_emit_slot(out, n, cap, 0, te); n = tpms_emit_slot(out, n, cap, 1, te); }  // bit0 -> "01"
    }
    return n;
}
// Encode différentiel-Manchester (Toyota) : la donnée est portée par la
// transition en DÉBUT de symbole. bit0 est fourni par le cadrage du sync
// (le décodeur démarre 2 slots avant la fin du sync), on encode donc les bits
// 1..nbits-1. Chaque symbole = start puis mid=!start (transition mid obligatoire).
static int tpms_encode_diffmanch(const uint8_t* raw, int nbits, const char* sync,
                                 int te, int preamble_pairs, int32_t* out, int cap) {
    int n = 0;
    for (int i = 0; i < preamble_pairs; i++) { n = tpms_emit_slot(out, n, cap, 1, te); n = tpms_emit_slot(out, n, cap, 0, te); }
    for (const char* p = sync; *p; ++p) n = tpms_emit_slot(out, n, cap, (*p == '1') ? 1 : 0, te);
    int prev = 0;  // = mid du symbole de cadrage du sync
    for (int i = 1; i < nbits; i++) {
        int b = (raw[i / 8] >> (7 - (i % 8))) & 1;
        int start = b ? prev : !prev;   // bit1 = pas de transition ; bit0 = transition
        int mid = !start;
        n = tpms_emit_slot(out, n, cap, start, te);
        n = tpms_emit_slot(out, n, cap, mid, te);
        prev = mid;
    }
    return n;
}

// Ré-encode la trame stockée avec pression (kPa) + température (C) modifiées.
static int tpms_spoof_encode(const TpmsSensor& s, float kpa, int temp,
                             int32_t* out, int cap, bool* is_fsk) {
    uint8_t r[10]; memcpy(r, s.raw, 10);
    const char* proto = s.proto ? s.proto : "";
    if (!strcmp(proto, "Schrader")) {
        *is_fsk = false;
        r[0] |= 0xf0;
        int pv = (int)(kpa / 2.5f + 0.5f);  pv = pv < 0 ? 0 : (pv > 255 ? 255 : pv); r[5] = (uint8_t)pv;
        int tv = temp + 50;                 tv = tv < 0 ? 0 : (tv > 255 ? 255 : tv); r[6] = (uint8_t)tv;
        r[7] = tpmsx_crc8(r, 7, 0xf0, 0x07);
        return tpms_encode_frame(r, 8, "1111010101" "01011010", 120, 12, out, cap, 4);
    }
    if (!strcmp(proto, "Renault")) {
        *is_fsk = true;
        int pv = (int)(kpa / 0.75f + 0.5f); pv = pv < 0 ? 0 : (pv > 1023 ? 1023 : pv);
        r[0] = (uint8_t)((r[0] & 0xFC) | ((pv >> 8) & 3));
        r[1] = (uint8_t)(pv & 0xFF);
        int tv = temp + 30;                 tv = tv < 0 ? 0 : (tv > 255 ? 255 : tv); r[2] = (uint8_t)tv;
        r[8] = tpmsx_crc8(r, 8, 0, 7);
        return tpms_encode_frame(r, 9, "01010101010101010110", 48, 6, out, cap);
    }
    if (!strcmp(proto, "Citroen")) {
        *is_fsk = true;
        int pv = (int)(kpa / 1.364f + 0.5f); pv = pv < 0 ? 0 : (pv > 255 ? 255 : pv); r[6] = (uint8_t)pv;
        int tv = temp + 50;                  tv = tv < 0 ? 0 : (tv > 255 ? 255 : tv); r[7] = (uint8_t)tv;
        uint8_t x = 0; for (int j = 1; j < 9; j++) x ^= r[j]; r[9] = x;   // XOR(raw[1..9])==0
        return tpms_encode_frame(r, 10, "01010101010101010", 52, 6, out, cap);
    }
    if (!strcmp(proto, "Ford")) {
        *is_fsk = true;
        float psi = kpa / 6.89476f; int pv = (int)(psi / 0.25f + 0.5f); pv = pv < 0 ? 0 : (pv > 511 ? 511 : pv);
        r[4] = (uint8_t)(pv & 0xFF);
        r[6] = (uint8_t)((r[6] & ~0x20) | (((pv >> 8) & 1) ? 0x20 : 0));
        int tv = temp + 56; tv = tv < 0 ? 0 : (tv > 127 ? 127 : tv); r[5] = (uint8_t)(tv & 0x7F);
        uint8_t crc = 0; for (int j = 0; j < 7; j++) crc += r[j]; r[7] = crc;
        return tpms_encode_frame(r, 8, "010101010101" "0110", 52, 6, out, cap);
    }
    if (!strcmp(proto, "Toyota")) {
        *is_fsk = true;
        int pv = (int)((kpa / 6.89476f + 7.0f) / 0.25f + 0.5f); pv = pv < 0 ? 0 : (pv > 255 ? 255 : pv);
        int tv = temp + 40;                                     tv = tv < 0 ? 0 : (tv > 255 ? 255 : tv);
        r[4] = (uint8_t)((r[4] & 0x80) | ((pv >> 1) & 0x7F));
        r[5] = (uint8_t)(((pv & 1) << 7) | ((tv >> 1) & 0x7F));
        r[6] = (uint8_t)((r[6] & 0x7F) | ((tv & 1) << 7));
        r[8] = tpmsx_crc8(r, 8, 0x80, 7);
        return tpms_encode_diffmanch(r, 72, "00111100", 52, 8, out, cap);
    }
    *is_fsk = true;   // protocole inconnu
    return 0;
}

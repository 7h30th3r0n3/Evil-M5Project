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

// ===========================================================================
//  Décodeurs TPMS supplémentaires portés de rtl_433 (BMW/Audi, Mercedes,
//  Porsche, Hyundai-VDO, GM, Honda, Kia, Nissan, Jeep, TRW, Renault-0435R,
//  Abarth, Elantra, PMV-107J, AVE, Truck, Jansite x4, Steelmate, TyreGuard,
//  Airpuxem, EezRV, Gear/Hive, SmarTire, Schrader-moto, Sefis). Même patron :
//  durations -> bitmap -> seek sync -> line-code/diff-Manchester -> CRC -> champs.
// ===========================================================================
// ---- batchA.inc ----
// ============================================================================
//  batchA.inc — Décodeurs TPMS batch A (cluster allemand / Continental)
// ----------------------------------------------------------------------------
//  Portés de rtl_433 (src/devices/tpms_*.c). À inclure dans tpms_multi.h : ce
//  fichier n'utilise QUE les helpers déjà définis là-bas (tpms_durations_to_bitmap,
//  tpms_bitmap_seek_bits, tpms_convert_from_line_code, tpms_convert_from_diff_manchester,
//  tpmsx_crc8) + la struct RfCodes/TpmsCode. Aucune redéfinition, aucun #include.
//
//  Rappel pipeline (identique aux 5 décodeurs existants) :
//    durations signées (us) -> bitmap suréchantillonné à te -> seek préambule/sync
//    -> line-code / diff-Manchester -> CRC -> sanity -> remplissage out.
//
//  Toutes FSK -> preset "2FSKDev476Async".
//
//  Correspondance Manchester (vérifiée sur bitbuffer.c de rtl_433) :
//    bitbuffer_manchester_decode() émet le 2e bit de chaque paire :
//       "01"->1, "10"->0.
//    - BMW : manchester_decode PUIS bitbuffer_invert  => net "01"->0, "10"->1
//            => tpms_convert_from_line_code(..., "01","10")
//    - Hyundai : invert du buffer PUIS manchester_decode (pas d'invert final)
//            => depuis le bitmap non-inversé : "01"->0, "10"->1 => line_code("01","10")
//    - Sefis : manchester_decode PUIS XOR 0xff par octet
//            => net "01"->0, "10"->1 => line_code("01","10")
//    - Mercedes : FSK_PULSE_MANCHESTER_ZEROBIT (G.E. Thomas) : front descendant=1,
//            montant=0 => bit1="10", bit0="01" => line_code("01","10")
//  => les 4 protocoles Manchester de ce batch utilisent line_code("01","10"),
//     comme Schrader/Ford du fichier parent.
//
//  CRC : tpmsx_crc8(data,len,init,poly) == rtl_433 crc8(data,len,poly,init).
//        Pour ces protocoles crc8 est en forme "directe" : crc8(data||crc)==0
//        <=> tpmsx_crc8(data, n-1, init, poly) == data[n-1] (mult. par x^8 dans
//        GF(2^8) = bijection, donc l'équivalence tient). On compare donc au
//        dernier octet. CRC-16/CCITT (poly 0x1021) absent de tpmsx_crc8 : helper
//        local unique tpmsa_crc16_1021() ci-dessous (MSB-first, non réfléchi,
//        copie exacte de rtl_433 crc16()).
// ============================================================================

// CRC-16/CCITT MSB-first (poly 0x1021), init paramétrable. Copie exacte de
// rtl_433 src/bit_util.c crc16() : remainder ^= byte<<8 ; 8 décalages gauche ;
// si bit15 -> <<1 ^ poly sinon <<1. Utilisé par BMW Gen2/3, Porsche, Sefis M3.
static inline uint16_t tpmsa_crc16_1021(const uint8_t* data, size_t len, uint16_t init) {
    uint16_t rem = init;
    for (size_t i = 0; i < len; i++) {
        rem ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            rem = (rem & 0x8000) ? (uint16_t)((rem << 1) ^ 0x1021) : (uint16_t)(rem << 1);
    }
    return rem;
}

// Bornes de plausibilité communes (le CRC8 8 bits laisse passer ~1/256 du bruit
// par position de seek : on borne pression/température comme Ford/Citroën/Toyota).
static inline bool tpmsa_sane(float kpa, int temp) {
    return kpa >= 0.0f && kpa <= 800.0f && temp >= -50 && temp <= 110;
}

// ─────────────────────────────────── BMW ───────────────────────────────────
// rtl_433 tpms_bmw.c : BMW Gen4/Gen5 + Audi Pressure Alert. FSK PCM, s=l=25us,
// Manchester (zerobit coding => manchester_decode puis invert). Préambule 0xaa59.
// Charge utile 11 octets (BMW) ou 8 octets (Audi, pression alerte).
// Layout (après MC+invert) : MM II II II II PP TT F1 F2 F3 CC
//   MM=marque(00 Audi,03 HUF/Beru,23 Schrader,80 Continental,88 Audi)
//   PP*2.45=kPa ; TT-52=°C ; CC=crc8 poly0x2f init0xaa sur les octets précédents.
static bool rf_decode_bmw_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 25, 8);
    if (bits.size() < 64) return false;
    // préambule 0xaa 0x59 = 1010101001011001
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "1010101001011001");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 16;
    uint8_t raw[11];
    uint32_t nbits = tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10");
    int len_msg;
    if (nbits >= 88)      len_msg = 11;   // BMW
    else if (nbits >= 64) len_msg = 8;    // Audi Pressure Alert
    else return false;
    if (tpmsx_crc8(raw, len_msg - 1, 0xaa, 0x2f) != raw[len_msg - 1]) return false;
    int brand = raw[0];
    // sanity : marque connue (le CRC8 est faible) + all-zero reject + bornes
    if (brand != 0x00 && brand != 0x03 && brand != 0x23 && brand != 0x80 && brand != 0x88) return false;
    float kpa = (float)raw[5] * 2.45f;
    int   temp = raw[6] - 52;
    if (!tpmsa_sane(kpa, temp)) return false;
    uint32_t id = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    if (id == 0) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.btn = (len_msg == 11) ? raw[7] : 0;          // F1 (BMW seulement)
    out.cnt = (len_msg == 11) ? raw[8] : 0;          // F2 séquence
    out.fix = (uint32_t)brand;                       // marque fournisseur
    out.Bit = len_msg * 8; out.te = 25;
    uint8_t cp = (uint8_t)(len_msg < 10 ? len_msg : 10);  // raw[] = 10 octets max
    memcpy(out.raw, raw, cp); out.raw_len = cp;
    out.protocol = (len_msg == 11) ? "BMW" : "Audi";
    out.preset = "2FSKDev476Async";
    return true;
}

// ───────────────────────────────── BMW G3 ──────────────────────────────────
// rtl_433 tpms_bmw_g3.c : BMW Gen2/Gen3. FSK PCM, s=l=52us, Manchester
// DIFFÉRENTIEL. Préambule 0xcccd. Gen3 = 11 octets, Gen2 = 10 octets.
// Layout : II II II II PP TT F1 F2 [F3] CC CC
//   id=b0..b3 ; PP : kPa=(PP-43)*2.5 ; TT-40=°C ; CC=CRC-16 0x1021 init 0x0000.
static bool rf_decode_bmw_g3_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 17);
    if (bits.size() < 160) return false;
    // préambule 0xcc 0xcd = 1100110011001101
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "1100110011001101");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    uint32_t data_start = off + 16;   // = position de départ DM de rtl_433 (fin préambule)
    if (data_start + 2 >= (uint32_t)bits.size()) return false;
    // Correspondance helper<->rtl_433 bitbuffer_differential_manchester_decode :
    // le helper démarré à (rtl_start+1) avec previous=bits[rtl_start] reproduit
    // EXACTEMENT rtl_433 (décalage d'un demi-bit constant, indépendant des données).
    bool prev = bits[data_start];
    uint8_t raw[11];
    uint32_t nbits = tpms_convert_from_diff_manchester(raw, sizeof(raw), bits, data_start + 1, (uint32_t)bits.size(), prev);
    int msg_len;
    if (nbits >= 88)      msg_len = 11;   // Gen3
    else if (nbits >= 80) msg_len = 10;   // Gen2
    else return false;
    // CRC-16 sur msg_len octets (CRC inclus) doit valoir 0
    if (tpmsa_crc16_1021(raw, msg_len, 0x0000) != 0) return false;
    float kpa = (float)(raw[4] - 43) * 2.5f;
    int   temp = raw[5] - 40;
    if (!tpmsa_sane(kpa, temp)) return false;
    uint32_t id = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    if (id == 0) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.btn = raw[6]; out.cnt = raw[7];
    out.Bit = msg_len * 8; out.te = 52;
    uint8_t cp = (uint8_t)(msg_len < 10 ? msg_len : 10);
    memcpy(out.raw, raw, cp); out.raw_len = cp;
    out.protocol = "BMW"; out.preset = "2FSKDev476Async";
    return true;
}

// ───────────────────────────────── Mercedes ────────────────────────────────
// rtl_433 tpms_mercedes_benz.c : Sprinter 4500. FSK_PULSE_MANCHESTER_ZEROBIT,
// s=l=25us. Préambule décodé 0x002 (12 bits). 10 octets.
// Layout : ST II II II II PP TT CC FF XX
//   ST=état(0x83 arrêt / 0xa3 roule) ; PP/2.75=PSI ; TT-51=°C ;
//   CC=compteur&flags ; XX=crc8 poly0x2f init0xaa sur les 9 octets précédents.
// Le ZEROBIT slicer décode déjà le Manchester : on le refait en line_code sur le
// bitmap brut (front descendant=1 => "10", montant=0 => "01").
// Le préambule décodé "...00000010" -> brut "0101010101011001" ; data juste après.
static bool rf_decode_mercedes_benz_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 25, 8);
    if (bits.size() < 160) return false;
    // tail du préambule décodé 0x002 : "00000010" -> brut "01 01 01 01 01 01 10 01"
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "0101010101011001");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 16;
    uint8_t raw[10];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 80) return false;
    if (tpmsx_crc8(raw, 9, 0xaa, 0x2f) != raw[9]) return false;
    // sanity rtl_433 : octet d'état attendu 0x83 ou 0xa3
    if (raw[0] != 0x83 && raw[0] != 0xa3) return false;
    float psi = (float)raw[5] / 2.75f;
    float kpa = psi * 6.89476f;
    int   temp = raw[6] - 51;
    if (!tpmsa_sane(kpa, temp)) return false;
    uint32_t id = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    if (id == 0) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.cnt = (uint16_t)(raw[7] & 0x1f); out.btn = raw[8];
    out.Bit = 80; out.te = 25;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Mercedes"; out.preset = "2FSKDev476Async";
    return true;
}

// ───────────────────────────────── Porsche ─────────────────────────────────
// rtl_433 tpms_porsche.c : Boxster/Cayman (Typ 987). FSK PCM, s=l=52us,
// Manchester DIFFÉRENTIEL. Préambule {30}ccccccca (= "0011" répété côté bitmap).
// 10 octets. Layout : II II II II PP TT SS SS CC CC
//   id=b0..b3 ; kPa = PP*5/2-100 (entier) ; TT-40=°C ; CC=CRC-16 0x1021 init 0xffff.
// rtl_433 boucle sa recherche de préambule (bitpos+=2) ; sur capture réelle le
// "terminateur" du préambule coïncide avec les données (pas de 0x..32 littéral).
// On ancre donc sur le RUN de préambule "0011" puis on balaye le départ data en
// validant par le CRC-16 (fort : faux positif ~1/65536), fidèle à la boucle rtl_433.
static bool rf_decode_porsche_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 17);
    if (bits.size() < 160) return false;
    uint32_t bsz = (uint32_t)bits.size();
    // ancre sur le run de préambule "0011"x4 (= domaine 0x33, comme rtl_433)
    uint32_t anchor = tpms_bitmap_seek_bits(bits, 0, bsz, "0011001100110011");
    if (anchor == TPMS_SEEK_NOT_FOUND) return false;
    // balaye le départ DM candidat (fin de préambule + début data) et valide par CRC
    uint8_t raw[10];
    bool found = false;
    uint32_t scan_end = anchor + 56; if (scan_end + 2 >= bsz) scan_end = (bsz >= 2) ? bsz - 2 : 0;
    for (uint32_t ds = anchor; ds <= scan_end; ds++) {
        bool prev = bits[ds];         // principle : helper@(rtl_start+1), previous=bits[rtl_start]
        if (tpms_convert_from_diff_manchester(raw, sizeof(raw), bits, ds + 1, bsz, prev) < 80) continue;
        if (tpmsa_crc16_1021(raw, 10, 0xffff) == 0) { found = true; break; }
    }
    if (!found) return false;
    int pressure = raw[4];
    int kpa_i = pressure * 5 / 2 - 100;          // formule entière rtl_433
    int temp  = raw[5] - 40;
    float kpa = (float)kpa_i;
    if (!tpmsa_sane(kpa, temp)) return false;
    uint32_t id = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    if (id == 0) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.cnt = (uint16_t)(((uint16_t)raw[6] << 8) | raw[7]);   // flags/status
    out.Bit = 80; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Porsche"; out.preset = "2FSKDev476Async";
    return true;
}

// ─────────────────────────────── Hyundai VDO ───────────────────────────────
// rtl_433 tpms_hyundai_vdo.c : capteurs Continental/VDO (Hyundai i30 etc.).
// FSK PCM, s=l=52us, Manchester. Préambule brut 55 55 55 56 (rtl_433 inverse le
// buffer puis cherche aa aa aa a9 ; côté bitmap non-inversé on cherche 55..56).
// 10 octets. Layout : UU IIII IIII FR PP TT BB CC
//   UU=état ; id=b1..b4 ; F=flags R=repeat ; PP*1.375=kPa ; TT-50=°C ; BB=batt ;
//   CC=crc8 poly0x07 init0xaa sur les 9 octets précédents (UU inclus).
static bool rf_decode_hyundai_vdo_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 17);
    if (bits.size() < 160) return false;
    // préambule 55 55 55 56 = 01010101 01010101 01010101 01010110
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "01010101010101010101010101010110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 32;
    uint8_t raw[10];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 80) return false;
    if (tpmsx_crc8(raw, 9, 0xaa, 0x07) != raw[9]) return false;
    // sanity (note de l'auteur rtl_433) : pression nulle = quasi impossible -> bruit
    if (raw[6] == 0) return false;
    float kpa = (float)raw[6] * 1.375f;
    int   temp = raw[7] - 50;
    if (!tpmsa_sane(kpa, temp)) return false;
    uint32_t id = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    if (id == 0) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.btn = raw[0];                    // état UU
    out.cnt = (uint16_t)(raw[5] & 0x0f); // repeat
    out.fix = (uint32_t)raw[8];          // batterie ?
    out.Bit = 80; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Hyundai"; out.preset = "2FSKDev476Async";
    return true;
}

// ─────────────────────────────── Sefis M3 ──────────────────────────────────
// rtl_433 tpms_sefis_m3.c : Sefis M3 / Careud / Sykik SRTP300 (Infineon SP400).
// FSK PCM, s=l=52us, Manchester (IEEE 802.3) + XOR 0xff par octet. Préambule 0xaa
// long + mot de synchro brut {0x66,0x99,0x96,0xa6} (32 bits, = 0x5a9d décodé).
// Charge utile 9 octets : B0..B6 + CRC16. CRC-16 0x1021 init 0x0000 sur B0..B6.
// Pression : page = {7:0,4:1,5:2,2:3}[B4>>5], code=page<<13|(B4&0x1f)<<8|B5,
//            kPa=(code-0x0e00)/102.4. Température : 14 + ((B2+B5)&0x0f).
// Pas d'ID capteur stable identifié (cf. rtl_433) : on expose B0..B3 comme pseudo-id.
static bool rf_decode_sefis_m3_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 17);
    if (bits.size() < 160) return false;
    // sync brut 0x66 0x99 0x96 0xa6
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "01100110" "10011001" "10010110" "10100110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 32;
    uint8_t raw[9];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 72) return false;
    uint16_t crc = tpmsa_crc16_1021(raw, 7, 0x0000);
    if (crc != (uint16_t)(((uint16_t)raw[7] << 8) | raw[8])) return false;
    // pression : page non séquentielle
    int page = -1;
    switch (raw[4] >> 5) { case 7: page = 0; break; case 4: page = 1; break;
                           case 5: page = 2; break; case 2: page = 3; break; }
    float kpa = 0.0f;
    if (page >= 0) {
        int code = (page << 13) | ((raw[4] & 0x1f) << 8) | raw[5];
        kpa = (float)(code - 0x0e00) / 102.4f;
        if (kpa < 0.0f) kpa = 0.0f;
    }
    int temp = 14 + (((raw[2] + raw[5]) & 0xff) & 0x0f);
    if (!tpmsa_sane(kpa, temp)) return false;
    // sanity all-zero (CRC16 déjà fort, mais on rejette la trame nulle)
    bool allzero = true;
    for (int i = 0; i < 7; i++) if (raw[i]) { allzero = false; break; }
    if (allzero) return false;
    uint32_t pseudo_id = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.serial = pseudo_id; out.kpa = kpa; out.temp = temp;
    out.cnt = (uint16_t)(page >= 0 ? page : 0);
    out.Bit = 72; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Sefis"; out.preset = "2FSKDev476Async";
    return true;
}


// ---- batchB.inc ----
// ============================================================================
//  batchB.inc — Décodeurs TPMS batch B (OEM US / JDM)
// ----------------------------------------------------------------------------
//  Portés de rtl_433 (src/devices/tpms_*.c). À inclure dans tpms_multi.h : ce
//  fichier n'utilise QUE les helpers déjà définis là-bas (tpms_durations_to_bitmap,
//  tpms_bitmap_seek_bits, tpms_convert_from_line_code, tpms_convert_from_diff_manchester,
//  tpmsx_crc8) + la struct RfCodes/TpmsCode. Aucune redéfinition, aucun #include,
//  aucun dispatcher.
//
//  Pipeline (identique aux décodeurs existants) :
//    durations signées (us) -> bitmap suréchantillonné à te -> seek préambule/sync
//    -> line-code Manchester -> CRC/checksum -> sanity -> remplissage out.
//
//  CORRESPONDANCE MANCHESTER (vérifiée sur bitbuffer.c + pulse_slicer.c rtl_433) :
//    bitbuffer_manchester_decode() émet le 2e bit de chaque paire brute :
//       brut "01" -> 1 , brut "10" -> 0.
//    tpms_convert_from_line_code(..., zero="01", one="10")  : "01"->0, "10"->1
//    (l'exact inverse). D'où, selon ce que fait rtl_433 autour du decode :
//      - invert AVANT puis manchester_decode (Citroën/Jeep) : net "01"->0,"10"->1
//            => line_code("01","10")          [= défaut, comme Citroën parent]
//      - manchester_decode PUIS invert du résultat (Nissan) : idem net "01"->0,"10"->1
//            => line_code("01","10")
//      - manchester_decode SANS invert (Honda, Kia) : brut "01"->1,"10"->0
//            => il faut INVERSER les motifs => line_code(zero="10", one="01")
//      - OOK/FSK _MANCHESTER_ZEROBIT (GM, TRW) : pulse_slicer zerobit =>
//            front montant milieu-cellule = 0 (brut "01"), descendant = 1 (brut "10")
//            => line_code("01","10")          [= défaut, comme Schrader parent]
//
//  CRC : tpmsx_crc8(data,len,init,poly) == rtl_433 crc8(data,len,poly,init).
//    - Honda / TRW : CRC-8/SMBUS poly 0x07 init 0x00  -> tpmsx_crc8(.,.,0x00,0x07)
//    - Kia         : CRC-8       poly 0x07 init 0x76  -> tpmsx_crc8(.,.,0x76,0x07)
//    Checksums faibles (somme/XOR/2-bit) -> helper dédié + bornes de plausibilité
//    fortes (GM somme-8, Jeep XOR-8, Nissan somme-2-bit).
//
//  Presets alignés sur le fichier parent : FSK -> "2FSKDev238Async",
//  OOK -> "Ook270Async".
// ============================================================================

// Bornes de plausibilité communes (rejette le bruit qui passe un checksum faible).
static inline bool tpmsb_sane(float kpa, int temp) {
    return kpa >= 0.0f && kpa <= 900.0f && temp >= -50 && temp <= 150;
}

// ─────────────────────────────────── GM ────────────────────────────────────
// rtl_433 tpms_gm.c : "GM-Aftermarket". OOK_PULSE_MANCHESTER_ZEROBIT, s=120us,
// 130 bits. Préambule = 6 octets 0x00 (48 bits de donnée, PAS de mot de sync),
// puis flags(2) id(5) pression(1) température(1) checksum(1).
// Checksum = somme(octets 6..14) mod 256 == octet 15 (FAIBLE : 8 bits).
//
// Particularité de portage : AUCUN sync distinctif derrière le préambule nul.
// En codage zerobit chaque "0" de donnée = cellule brute "01", donc le préambule
// vaut brut "0101..." (alternance pure). On cherche une longue alternance : le
// PREMIER "0101..." après l'idle (idle = niveau bas = "000...") tombe forcément
// sur le début de cellule de la 1re cellule du préambule (démontrable : une
// fenêtre démarrant sur un 0 d'idle donnerait "00.." qui ne matche pas "01").
// On décode donc 130 cellules DEPUIS ce point. Garde-fous contre un mauvais
// cadrage : (a) octets 0..5 == 0 (48 bits), (b) checksum, (c) non-nul, (d) bornes.
// Un décalage d'1/2 cellule inverse tous les bits (octets 0..5 != 0 -> rejet) ;
// un décalage d'1 cellule casse l'alignement octet (checksum -> rejet).
static bool rf_decode_gm_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 120, 40);
    if (bits.size() < 260) return false;
    // 24 bits = 12 cellules de préambule (sur 48 dispo) -> verrouille la phase cellule
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "010101010101010101010101");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    uint8_t raw[17] = {0};
    // décode depuis le DÉBUT du préambule (les 48 bits nuls font partie de la trame)
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 128) return false;
    // préambule : 6 octets nuls
    for (int i = 0; i < 6; i++) if (raw[i] != 0) return false;
    // checksum somme-8 sur octets 6..14 == octet 15
    uint8_t sum = 0; int all_zero = 1;
    for (int i = 6; i < 15; i++) { sum += raw[i]; all_zero &= (raw[i] == 0); }
    if (sum != raw[15]) return false;
    if (all_zero && raw[15] == 0) return false;   // trame nulle (passe trivialement le checksum)
    int flags = (raw[6] << 8) | raw[7];
    float kpa = (float)raw[13] * 2.75f;            // rtl_433 : pressure_raw * 2.75 (déjà kPa)
    int temp = raw[14] - 60;
    if (!tpmsb_sane(kpa, temp)) return false;
    // id 40 bits (b8..b12) : serial 32 bits = octets bas, key = id complet
    uint64_t id64 = ((uint64_t)raw[8] << 32) | ((uint64_t)raw[9] << 24) | ((uint64_t)raw[10] << 16) | ((uint64_t)raw[11] << 8) | raw[12];
    out.key = id64;
    out.serial = ((uint32_t)raw[9] << 24) | ((uint32_t)raw[10] << 16) | ((uint32_t)raw[11] << 8) | raw[12];
    out.kpa = kpa; out.temp = temp;
    out.fix = (uint32_t)(((flags >> 5) & 1) ? 0 : 1);   // battery_ok (bit5 = low batt)
    out.Bit = 130; out.te = 120;
    // out.raw ne tient que 10 octets : on stocke la charge utile (octets 6..15)
    memcpy(out.raw, &raw[6], 10); out.raw_len = 10;
    out.protocol = "GM"; out.preset = "Ook270Async";
    return true;
}

// ────────────────────────────────── Honda ──────────────────────────────────
// rtl_433 tpms_honda.c : "Honda-TRW" (PPA-GF33). FSK_PULSE_PCM, s=l=50us, IEEE
// 802.3 Manchester (bitbuffer_manchester_decode SANS invert). Marqueur brut
// 0xda 0xe3 0x54 (23 bits, pré-Manchester) puis 8 octets Manchester (128 bits bruts).
// Layout : PP TT IIIIIIII FF CC. CRC-8/SMBUS (poly 0x07, init 0x00) sur octets 0..6.
// Manchester SANS invert => line_code(zero="10", one="01").
static bool rf_decode_honda_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 50, 16);
    if (bits.size() < 151) return false;
    // marqueur 23 bits bruts : 0xda 0xe3 + 7 bits de 0x54
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "11011010" "11100011" "0101010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 23;
    uint8_t raw[8];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "10", "01") < 64) return false;
    if (tpmsx_crc8(raw, 7, 0x00, 0x07) != raw[7]) return false;   // CRC-8/SMBUS fort
    int pressure_raw = raw[0];
    // overlap TRW GQ4-44T : pression non-nulle < 10 PSI (raw<50) rejetée (cf rtl_433)
    if (pressure_raw > 0 && pressure_raw < 50) return false;
    float kpa = (float)pressure_raw * 0.2f * 6.89476f;   // 0.2 PSI/pas -> kPa
    int temp = raw[1] - 50;
    if (!tpmsb_sane(kpa, temp)) return false;
    bool allzero = true; for (int i = 0; i < 8; i++) if (raw[i]) { allzero = false; break; }
    if (allzero) return false;
    uint32_t id = ((uint32_t)raw[2] << 24) | ((uint32_t)raw[3] << 16) | ((uint32_t)raw[4] << 8) | raw[5];
    out.serial = id; out.btn = raw[6];   // flags (0xe1 à l'arrêt)
    out.kpa = kpa; out.temp = temp; out.Bit = 64; out.te = 50;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Honda"; out.preset = "2FSKDev238Async";
    return true;
}

// ─────────────────────────────────── Kia ───────────────────────────────────
// rtl_433 tpms_kia.c : "Kia" (Rio UB III / Hyundai). FSK_PULSE_PCM, s=l=50us,
// Manchester SANS invert. Préambule 0xed 0x71 (16 bits bruts), puis 154-16=138
// bits bruts Manchester = 69 bits de donnée (8 octets + 5 bits de CRC).
// Layout (nibbles) : a pppppppp tttttttt iiiiiiii(32) dddddddd ccccc.
// CRC : poly 0x07 init 0x76 sur octets 0..7, dont les 5 bits de poids fort sont
// comparés à l'octet 8 complété par 000 (le capteur n'émet que 5 bits de CRC).
// Manchester SANS invert => line_code(zero="10", one="01").
//
// QUIRK fidèle à rtl_433 : la comparaison est `crc8(b,8) == (b[8] & ~0x7)`, soit
// une égalité 8 bits où les 3 bits bas valent 0 -> n'accepte en pratique que les
// trames dont le CRC calculé finit par 000. C'est le comportement littéral de
// rtl_433 (décodeur reconnu imparfait par son auteur), reproduit tel quel.
static bool rf_decode_kia_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 50, 16);
    if (bits.size() < 154) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "11101101" "01110001");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 16;
    uint8_t raw[9] = {0};
    uint32_t nb = tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "10", "01");
    if (nb < 69) return false;   // 8 octets + 5 bits de CRC
    // l'octet 8 ne contient que (nb-64) bits, cadrés à DROITE par le helper ;
    // rtl_433 les veut cadrés à GAUCHE (bits de poids fort) -> on recale.
    int kbits = (int)nb - 64; if (kbits > 8) kbits = 8;
    uint8_t b8 = (uint8_t)((raw[8] << (8 - kbits)) & 0xF8);
    if (tpmsx_crc8(raw, 8, 0x76, 0x07) != b8) return false;
    // rtl_433 affecte ces deux valeurs à des uint8_t -> tronquées 8 bits : on
    // masque, sinon raw[1]<<4 (int) déborde au-delà de 255 et fausse pression/temp.
    int pressure = ((raw[0] << 4) | (raw[1] >> 4)) & 0xFF;  // 8 bits à cheval
    int temperature = ((raw[1] << 4) | (raw[2] >> 4)) & 0xFF;
    float kpa = (float)pressure / 5.0f * 6.89476f;          // PSI*5 -> PSI -> kPa
    int temp = temperature - 50;
    if (!tpmsb_sane(kpa, temp)) return false;
    bool allzero = true; for (int i = 0; i < 9; i++) if (raw[i]) { allzero = false; break; }
    if (allzero) return false;
    uint32_t id = ((uint32_t)raw[2] << 28) | ((uint32_t)raw[3] << 20) | ((uint32_t)raw[4] << 12) | ((uint32_t)raw[5] << 4) | (raw[6] >> 4);
    out.serial = id; out.kpa = kpa; out.temp = temp; out.Bit = 69; out.te = 50;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = 9;
    out.protocol = "Kia"; out.preset = "2FSKDev238Async";
    return true;
}

// ────────────────────────────────── Nissan ─────────────────────────────────
// rtl_433 tpms_nissan.c : "Nissan". FSK_PULSE_PCM, s=l=120us (marqué TODO/incertain
// dans rtl_433 ; repris littéralement), Manchester puis INVERT du résultat.
// Préambule brut 0xf5 0x55 0x55 0x55 0xe (36 bits), puis 37 bits de donnée.
// Layout : MODE:3 ID:24 (PSI+3)*4:8 UNK:2. Pas de température.
// manchester_decode PUIS invert => net "01"->0,"10"->1 => line_code("01","10").
// Checksum "sum2N" 2 bits (TRÈS faible) : plausibilité forte + id non nul exigés.
static uint8_t tpms_nissan_chk(const uint8_t* b) {   // copie exacte de rtl_433
    uint8_t chk = 0;
    for (int i = 0; i < 4; i++) {
        chk += b[i] >> 7;
        chk += b[i] >> 5;
        chk += b[i] >> 3;
        chk += b[i] >> 1;
        chk += (uint8_t)(b[i] << 1);
    }
    chk += b[4] >> 7;
    chk += b[4] >> 5;
    chk += b[4] >> 3;
    return ~chk & 0x03;   // valide quand == 0
}
static bool rf_decode_nissan_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 120, 40);
    if (bits.size() < 110) return false;
    // préambule 36 bits : 0xf5 0x55 0x55 0x55 0xe
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "11110101" "01010101" "01010101" "01010101" "1110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 36;
    uint8_t raw[5] = {0};
    uint32_t nb = tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10");
    if (nb < 37) return false;
    // octet 4 = partiel (5 bits utiles) : le helper les cadre à DROITE, mais
    // rtl_433 (remplissage Manchester MSB-first dans un octet) les a à GAUCHE
    // (bits 7..3) ; tous les champs (checksum, pression) lisent les bits de poids
    // fort -> on recale à gauche avant toute lecture.
    int lb = (int)nb - 32; if (lb > 0 && lb < 8) raw[4] = (uint8_t)(raw[4] << (8 - lb));
    if (tpms_nissan_chk(raw) != 0) return false;
    int mode = raw[0] >> 5;
    uint32_t id = ((uint32_t)(raw[0] & 0x1F) << 19) | ((uint32_t)raw[1] << 11) | ((uint32_t)raw[2] << 3) | (raw[3] >> 5);
    int pressure_raw = ((raw[3] & 0x1F) << 3) | (raw[4] >> 5);
    float psi = (float)pressure_raw / 4.0f - 3.0f;
    float kpa = psi * 6.89476f;
    // sum2N = 2 bits -> plausibilité stricte : id non nul, trame non constante, pression bornée
    if (id == 0) return false;
    if (kpa < 0.0f || kpa > 700.0f) return false;
    bool alleq = true; for (int i = 1; i < 5; i++) if (raw[i] != raw[0]) { alleq = false; break; }
    if (alleq) return false;
    out.serial = id; out.btn = (uint8_t)mode;
    out.kpa = kpa; out.temp = 0; out.Bit = 37; out.te = 120;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Nissan"; out.preset = "2FSKDev238Async";
    return true;
}

// ─────────────────────────────────── Jeep ──────────────────────────────────
// rtl_433 tpms_jeep.c : "Jeep" (Continental). FSK_PULSE_PCM, s=l=52us. Format,
// cadrage, Manchester et XOR IDENTIQUES à Citroën (même préambule 0x5556, même
// layout octet, même checksum XOR) ; SEULE différence : pression = Citroën*2
// (soit raw * 2.728 kPa au lieu de 1.364). On copie donc exactement le décodeur
// Citroën du fichier parent (invert AVANT manchester => line_code("01","10")).
// Layout : UU IIIIIIII FR PP TT BB CC. XOR(octets 1..9) == 0 (FAIBLE).
static bool rf_decode_jeep_tpms(const std::vector<int>& durations, RfCodes& out) {
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
    // sanity non-nul pression/température (comme rtl_433 jeep/citroen) : XOR faible
    if (raw[6] == 0 || raw[7] == 0) return false;
    int repeat = raw[5] & 0xf;
    float kpa = (float)raw[6] * 2.728f;   // Jeep : double de Citroën
    int temp = raw[7] - 50; int battery = raw[8];
    if (!tpmsb_sane(kpa, temp)) return false;
    uint32_t id = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    out.serial = id; out.cnt = (uint16_t)repeat; out.fix = (uint32_t)battery;
    out.btn = (uint8_t)(raw[5] >> 4);   // flags
    out.kpa = kpa; out.temp = temp; out.Bit = 80; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Jeep"; out.preset = "2FSKDev238Async";
    return true;
}

// ─────────────────────────────── TRW (commun) ──────────────────────────────
// rtl_433 tpms_trw.c : "TRW" (GQ4-70T, Chrysler 2014-2022). DEUX variantes
// OOK_PULSE_MANCHESTER_ZEROBIT et FSK_PULSE_MANCHESTER_ZEROBIT, s=l=52us, seul le
// préambule change (décodé : 0x0001 OOK, 0x7fff FSK ; 16 bits). 11 octets utiles.
// Layout : MM IIIIIIII FN PP TT SS CC X. CRC-8/SMBUS poly 0x07 init 0x00 sur 0..8
// (octet 9 = CRC) => crc8(b,10)==0. Pression = raw*0.4 PSI (doc "échelle 2.5" =
// raw = PSI*2.5, cohérent). Température offset 50. zerobit => line_code("01","10").
// Les deux variantes décodent à l'identique après le préambule -> factorisé.
// NB: out.raw (10 o.) ne stocke que les octets 0..9 (le 11e, nibble OEM/clone, omis).
static bool trw_decode_common(const std::vector<int>& durations, RfCodes& out,
                              const char* preamble_raw, const char* preset) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 190) return false;   // 16 préamb + 88 data = 104 bits décodés -> ~208 bruts
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), preamble_raw);
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 32;   // 16 bits de préambule décodés = 32 bits bruts
    uint8_t raw[11] = {0};
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 80) return false;
    if (tpmsx_crc8(raw, 10, 0x00, 0x07) != 0) return false;   // CRC-8/SMBUS sur octets 0..9, fort
    float kpa = (float)raw[6] * 0.4f * 6.89476f;   // 0.4 PSI/pas -> kPa
    int temp = raw[7] - 50;
    if (!tpmsb_sane(kpa, temp)) return false;
    bool allzero = true; for (int i = 0; i < 10; i++) if (raw[i]) { allzero = false; break; }
    if (allzero) return false;
    uint32_t id = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    out.serial = id;
    out.btn = (uint8_t)(raw[5] >> 4);    // flags status (6/9 = alerte pression)
    out.cnt = (uint16_t)(raw[5] & 0x0f); // seq num
    out.fix = (uint32_t)raw[8];          // motion_flags (0x0e = parked)
    out.kpa = kpa; out.temp = temp; out.Bit = 88; out.te = 52;
    memcpy(out.raw, raw, 10); out.raw_len = 10;
    out.protocol = "TRW"; out.preset = preset;
    return true;
}
// TRW OOK : préambule décodé 0x0001 = 15 "0" + un "1" -> brut 15x"01" + "10".
static bool rf_decode_trw_ook_tpms(const std::vector<int>& durations, RfCodes& out) {
    return trw_decode_common(durations, out,
        "01010101010101010101010101010110", "Ook270Async");
}
// TRW FSK : préambule décodé 0x7fff = un "0" + 15 "1" -> brut "01" + 15x"10".
static bool rf_decode_trw_fsk_tpms(const std::vector<int>& durations, RfCodes& out) {
    return trw_decode_common(durations, out,
        "01101010101010101010101010101010", "2FSKDev238Async");
}


// ---- batchC.inc ----
// ============================================================================
//  batchC.inc — Décodeurs TPMS portés de rtl_433 (batch C : EU / PSA / misc OEM)
// ----------------------------------------------------------------------------
//  À #inclure APRÈS src/tpms_multi.h (réutilise ses helpers + struct TpmsCode/
//  RfCodes ; aucun #include, aucune redéfinition, aucun dispatcher ici).
//
//  Sources rtl_433 :
//    tpms_renault_0435r.c, tpms_abarth124.c, tpms_elantra2012.c,
//    tpms_pmv107j.c, tpms_ave.c, tpms_truck.c
//
//  Conventions (vérifiées par simulation bit-exacte contre bitbuffer.c de
//  rtl_433, cf. note ci-dessous) :
//   - durbuf = durées d'edges signées (positif=haut, négatif=bas) ; te = demi-bit
//     Manchester µs (= rtl_433 short_width) ; delta ≈ te/3 (inutilisé par le helper).
//   - Le bitmap suréchantillonné (te=short_width) == flux brut NON inversé de rtl_433.
//   - rtl_433 bitbuffer_manchester_decode émet bit2. Les décodeurs qui appellent
//     bitbuffer_invert AVANT (Renault0435R, Abarth, Truck) : sur le flux brut non
//     inversé cela équivaut à line-code "01"->0 / "10"->1 (identique aux décodeurs
//     existants de tpms_multi.h). Ceux SANS invert (Elantra) : "10"->0 / "01"->1.
//   - bitbuffer_differential_manchester_decode (PMV-107J, AVE) code la DONNÉE sur la
//     transition MÉDIANE ; le helper tpms_convert_from_diff_manchester la lit sur la
//     transition de FRONTIÈRE. Les deux cadrages sont décalés d'un demi-bit : on
//     démarre donc le helper à (fin_préambule + 1) avec previous = bits[fin_préambule].
//     (Prouvé : helper(offset=p+1, previous=sample[p]) == rtl steady-state(ipos=p).)
//   - CRC/checksum/offsets/échelles recopiés littéralement de rtl_433 ; pression en
//     kPa, température en °C.
// ============================================================================

// CRC-16/CCITT-FALSE (poly 0x1021, init 0xffff, MSB-first, non réfléchi) — requis par
// le variant Q85 d'Abarth ; non couvert par tpmsx_crc8. Nom préfixé marque (anti-collision).
static inline uint16_t tpms_abarth_crc16_ccitt(const uint8_t* data, size_t len) {
    uint16_t crc = 0xffff;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

// ── Renault 0435R / VDO S180052064Z (FSK, 52µs, 9 octets Manchester, XOR-8) ──
// rtl_433 tpms_renault_0435r.c : invert + préambule aa a9 (brut 55 56), 72 bits data,
// Manchester (émet bit2 sur flux inversé == line-code "01"->0 / "10"->1 sur brut).
// Layout nibbles : II II II fx PP TT AA CC tt (P=4/3 kPa, T offset -50, tt=has_tick+tick).
// XOR-8 faible -> on ajoute la sanity rtl sur l'octet de comptage + id non nul + borne temp.
static bool rf_decode_renault_0435r_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 160) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "0101010101010110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 16;
    uint8_t raw[9];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 72) return false;
    uint8_t x = 0; for (int j = 0; j < 9; j++) x ^= raw[j];
    if (x != 0) return false;
    // rtl_433 : sanity sur l'octet mesure raw[8] (has_tick=bit7, tick=bits0-6) — filtre le XOR faible
    uint8_t has_tick = raw[8] >> 7; uint8_t tick = raw[8] & 0x7f;
    if (raw[8] && (!has_tick || tick > 30)) return false;
    if (!raw[0] && !raw[1] && !raw[2]) return false;         // id 24-bit non nul
    int temp = (int)raw[5] - 50;
    if (temp < -50 || temp > 125) return false;
    float kpa = (float)raw[4] / 0.75f;                       // 4/3 kPa par incrément
    uint32_t id_val = ((uint32_t)raw[0] << 16) | ((uint32_t)raw[1] << 8) | raw[2];
    out.serial = id_val; out.btn = raw[3]; out.cnt = (uint16_t)tick;
    out.kpa = kpa; out.temp = temp; out.Bit = 72; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Renault-0435R"; out.preset = "2FSKDev238Async";
    return true;
}

// ── VDO TG1C (Abarth 124 Spider / Fiat / Mazda MX-5) + Shenzhen EGQ Q85 (FSK, 52µs) ──
// rtl_433 tpms_abarth124.c : invert + préambule aa aa a9 (brut 55 55 56), Manchester.
//   TG1C : 72 bits, XOR-8 sur 9 octets == 0, temp -50 (°C), pression * 1.38 kPa.
//   Q85  : 96 bits, XOR-8 sur 9 octets == 0 + CRC16/CCITT-FALSE sur 10 octets (LE),
//          temp -55 (°C), pression * 3 kPa.
// XOR-8 faible -> borne de température plausible (par type, plages documentées) + id non nul.
static bool rf_decode_abarth124_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 168) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "010101010101010101010110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 24;
    uint8_t raw[12];
    uint32_t nbits = tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10");
    if (nbits < 72) return false;
    uint8_t x = 0; for (int j = 0; j < 9; j++) x ^= raw[j];
    if (x != 0) return false;
    if (!raw[0] && !raw[1] && !raw[2] && !raw[3]) return false;   // id 32-bit non nul
    int press_raw = raw[5]; int temp_raw = raw[6];
    bool is_q85 = false;
    if (nbits >= 96) {
        uint16_t crc_le = (uint16_t)((raw[11] << 8) | raw[10]);
        if (tpms_abarth_crc16_ccitt(raw, 10) == crc_le) is_q85 = true;
    }
    float kpa; int temp;
    if (is_q85) {
        temp = temp_raw - 55; if (temp < -20 || temp > 80) return false;
        kpa = (float)press_raw * 3.0f;
        out.Bit = 96; out.protocol = "Abarth-Q85";
    } else {
        temp = temp_raw - 50; if (temp < -50 || temp > 125) return false;
        kpa = (float)press_raw * 1.38f;
        out.Bit = 72; out.protocol = "Abarth-124";
    }
    out.serial = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.btn = raw[7];                     // status
    out.kpa = kpa; out.temp = temp; out.te = 52;
    uint8_t n = is_q85 ? 10 : 9;          // out.raw[] = 10 octets : Q85 tronqué (CRC16 omis)
    memcpy(out.raw, raw, n); out.raw_len = n;
    out.preset = "2FSKDev238Async";
    return true;
}

// ── Hyundai Elantra 2012 / Honda Civic (TRW GQ4-44T, FSK ~49µs, Manchester, CRC-8) ──
// rtl_433 tpms_elantra2012.c : PAS d'invert, préambule 0x7155, 64 bits data.
// Manchester émet bit2 sur flux brut (non inversé) == line-code "10"->0 / "01"->1.
// Layout : PP TT IDID IDID FF CC (P offset +60 kPa, T offset -50, CRC-8 poly 0x07 init 0).
static bool rf_decode_elantra2012_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 49, 16);
    if (bits.size() < 144) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "0111000101010101");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 16;
    uint8_t raw[8];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "10", "01") < 64) return false;
    if (tpmsx_crc8(raw, 8, 0x00, 0x07) != 0) return false;        // CRC-8 poly 0x07 init 0x00
    if (!raw[2] && !raw[3] && !raw[4] && !raw[5]) return false;   // id 32-bit non nul
    int pressure = (int)raw[0] + 60; int temp = (int)raw[1] - 50;
    if (temp < -50 || temp > 125) return false;
    out.serial = ((uint32_t)raw[2] << 24) | ((uint32_t)raw[3] << 16) | ((uint32_t)raw[4] << 8) | raw[5];
    out.btn = raw[6];                                   // flags
    out.fix = (uint32_t)(((raw[6] & 0x02) >> 1) ? 0 : 1);   // battery_ok (bit battery_low inversé)
    out.cnt = (uint16_t)(raw[6] & 0x01);                // triggered
    out.kpa = (float)pressure; out.temp = temp; out.Bit = 64; out.te = 49;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Elantra2012"; out.preset = "2FSKDev238Async";
    return true;
}

// ── Pacific PMV-107J (Toyota, 315 MHz, FSK 100µs, Manchester différentiel, CRC-8 0x13) ──
// rtl_433 tpms_pmv107j.c : PAS d'invert, préambule 111110 (0xf8/6b), 66+ bits data.
// Tampon réaligné en préfixant 6 bits à 0 -> b[0]=2 premiers bits, b[1..8]=64 suivants.
// Diff-manch : on démarre le helper à (fin_préambule+1), previous = bits[fin_préambule].
// Fort : CRC-8 + redondance pression inversée (p1 == p2^0xff).
// NB : 315 MHz / 100µs — nécessite un preset RX adapté à ce timing (pas le FSK 52µs).
static bool rf_decode_pmv107j_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 100, 33);
    if (bits.size() < 139) return false;
    uint32_t base = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "111110");
    if (base == TPMS_SEEK_NOT_FOUND) return false;
    uint32_t off0 = base + 6;                           // début data rtl (fin préambule)
    if (off0 + 1 >= (uint32_t)bits.size()) return false;
    bool previous = bits[off0];
    uint8_t dec[9] = {0};
    uint32_t nb = tpms_convert_from_diff_manchester(dec, sizeof(dec), bits, off0 + 1, (uint32_t)bits.size(), previous);
    if (nb < 66) return false;
    // reconstruit les octets réalignés de rtl (le helper tasse un octet final partiel
    // dans les bits de POIDS FAIBLE) : b[0] = 2 bits de tête, b[1..8] = 64 bits suivants.
    uint8_t d[66]; uint32_t fb = nb & ~7u;
    for (uint32_t i = 0; i < 66; i++) {
        if (i < fb) d[i] = (dec[i >> 3] >> (7 - (i & 7))) & 1;
        else { uint32_t j = i - fb; d[i] = (dec[nb >> 3] >> ((nb & 7) - 1 - j)) & 1; }
    }
    uint8_t b[9];
    b[0] = (uint8_t)((d[0] << 1) | d[1]);
    for (int k = 0; k < 8; k++) { uint8_t v = 0; for (int j = 0; j < 8; j++) v = (uint8_t)((v << 1) | d[2 + k * 8 + j]); b[k + 1] = v; }
    if (tpmsx_crc8(b, 8, 0x00, 0x13) != b[8]) return false;       // CRC-8 poly 0x13 init 0
    uint8_t pressure1 = b[5]; uint8_t pressure2 = (uint8_t)(b[6] ^ 0xff);
    if (pressure1 != pressure2) return false;                     // redondance pression (fort)
    float kpa = ((float)pressure1 - 40.0f) * 2.48f;
    int temp = (int)b[7] - 40;
    uint32_t id = ((uint32_t)b[0] << 26) | ((uint32_t)b[1] << 18) | ((uint32_t)b[2] << 10) | ((uint32_t)b[3] << 2) | (b[4] >> 6);
    out.serial = id; out.btn = (uint8_t)(b[4] & 0x3f);            // status
    out.cnt = (uint16_t)((b[4] & 0x18) >> 3);                     // repeat counter
    out.fix = (uint32_t)(((b[4] & 0x20) >> 5) ? 0 : 1);          // battery_ok
    out.kpa = kpa; out.temp = temp; out.Bit = 66; out.te = 100;
    memcpy(out.raw, b, sizeof(b)); out.raw_len = sizeof(b);
    out.protocol = "PMV-107J"; out.preset = "2FSKDev238Async";
    return true;
}

// ── AVE TPMS (FSK 100µs, Manchester différentiel, CRC-8 poly 0x31 init 0xff) ──
// rtl_433 tpms_ave.c : PAS d'invert, préambule cc cc cc cd (brut, pré-diff-manch), 64 bits.
// Diff-manch : helper démarré à (fin_préambule+1), previous = bits[fin_préambule].
// Layout : IIIIIIII PP TT FF CC (T offset -50 ; 4 tables de pression selon mode = bits7-6 de FF).
// Fort : CRC-8 (résultat sur 8 octets == 0).
// NB : 100µs — nécessite un preset RX adapté à ce timing.
static bool rf_decode_ave_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 100, 33);
    if (bits.size() < 161) return false;
    uint32_t base = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "11001100110011001100110011001101");
    if (base == TPMS_SEEK_NOT_FOUND) return false;
    uint32_t off0 = base + 32;
    if (off0 + 1 >= (uint32_t)bits.size()) return false;
    bool previous = bits[off0];
    uint8_t raw[8];
    if (tpms_convert_from_diff_manchester(raw, sizeof(raw), bits, off0 + 1, (uint32_t)bits.size(), previous) < 64) return false;
    if (tpmsx_crc8(raw, 8, 0xff, 0x31) != 0) return false;        // CRC-8 poly 0x31 init 0xff
    if (!raw[0] && !raw[1] && !raw[2] && !raw[3]) return false;   // id 32-bit non nul
    int pressure_raw = raw[4]; int mode = (raw[6] >> 6) & 0x3; int battery_raw = (raw[6] >> 3) & 0x7;
    float ratio, offset;
    switch (mode) {
        case 0:  ratio = 2.352f; offset = 47.0f; break;
        case 2:  ratio = 5.491f; offset = 18.2f; break;
        case 3:  ratio = 5.491f; offset = 0.0f;  break;
        case 1:
        default: ratio = 2.352f; offset = 0.0f;  break;
    }
    float kpa = ((float)pressure_raw - offset) * ratio;
    int temp = (int)raw[5] - 50;
    int battery_pct = 100; if (battery_raw == 6) battery_pct = 75; else if (battery_raw == 7) battery_pct = 25;
    out.serial = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.btn = (uint8_t)(raw[6] & 0x7);          // flags
    out.cnt = (uint16_t)mode; out.fix = (uint32_t)battery_pct;
    out.kpa = kpa; out.temp = temp; out.Bit = 64; out.te = 100;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "AVE"; out.preset = "2FSKDev238Async";
    return true;
}

// ── Unbranded SolarTPMS for trucks (set de 6, compteur de roue, 433 MHz FSK 52µs, Manchester) ──
// rtl_433 tpms_truck.c : invert + préambule aa aa a9 (brut 55 55 56), puis un nibble d'état
// 4 bits (HORS checksum) précède la charge 72 bits -> on saute 4 bits décodés (= 8 bits bruts)
// pour réaligner sur l'octet. Layout : U IIII IIII WW F PPP TT CC ? (P 12 bits kPa, T signé).
// XOR-8 faible -> rejet id tout-à-zéro (rtl) + borne pression/température.
static bool rf_decode_truck_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 176) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "010101010101010101010110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 24 + 8;                              // préambule 24 bits + nibble d'état (8 bits bruts)
    uint8_t raw[9];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 72) return false;
    if (!raw[0] && !raw[1] && !raw[2] && !raw[3]) return false;   // rtl : rejet id tout-à-zéro
    uint8_t x = 0; for (int j = 0; j < 9; j++) x ^= raw[j];
    if (x != 0) return false;
    int pressure = (int)(((raw[5] & 0x0f) << 8) | raw[6]);        // kPa (plage 0.1..12.0 bar)
    if (pressure > 1300) return false;
    int temp = (int)(int8_t)raw[7];                               // °C signé
    int wheel = raw[4]; int flags = raw[5] >> 4;
    out.serial = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.btn = (uint8_t)wheel; out.cnt = (uint16_t)flags;
    out.fix = (uint32_t)(((flags & 0x3) == 0x3) ? 1 : 0);        // battery_ok (0x3=ok, 0x0=low)
    out.kpa = (float)pressure; out.temp = temp; out.Bit = 72; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Truck"; out.preset = "2FSKDev238Async";
    return true;
}


// ---- batchD.inc ----
// ============================================================================
//  batchD.inc — Décodeurs TPMS batch D (famille Jansite + aftermarket)
// ----------------------------------------------------------------------------
//  Portés 1:1 des décodeurs rtl_433 (src/devices/) vers le modèle du firmware
//  (tpms_multi.h) : durations -> bitmap suréchantillonné (demi-bits @ te) ->
//  recherche sync -> line-code Manchester -> CRC/checksum -> plausibilité.
//
//  Convention de polarité Manchester, déduite en comparant les 5 décodeurs
//  déjà portés (Renault/Citroen/Ford/Toyota/Schrader) à leurs sources rtl_433 :
//   - rtl_433 "bitbuffer_invert() PUIS bitbuffer_manchester_decode()"        -> line-code zero="01", one="10"
//   - rtl_433 "bitbuffer_manchester_decode() PUIS bitbuffer_invert(bytes)"   -> line-code zero="01", one="10"
//   - rtl_433 "bitbuffer_manchester_decode() SANS aucune inversion"          -> line-code zero="10", one="01"
//   - rtl_433 FSK/OOK_PULSE_MANCHESTER_ZEROBIT (slicer : front descendant=1,
//     front montant=0, bit de tête 0 matériel) -> en demi-bits : "10"=1, "01"=0
//     -> line-code zero="01", one="10".
//  bitbuffer_manchester_decode émet bit2 de chaque paire (raw "01"->1, "10"->0).
//  Le bitmap du firmware (haut=1/bas=0) == flux de demi-bits brut de rtl_433
//  (= le bitbuffer AVANT son éventuel bitbuffer_invert), d'où ces équivalences.
//
//  Dépend des helpers de tpms_multi.h (inclus avant ce .inc) : pas de #include,
//  pas de redéfinition, pas de dispatcher.
// ============================================================================

// ─── Helpers locaux uniques (non fournis par tpms_multi.h) ──────────────────

// CRC-16/BUYPASS (alias CRC-16/UMTS) : poly 0x8005, init 0x0000, non réfléchi,
// xorout 0x0000. Reproduit EXACTEMENT rtl_433 crc16(data,len,0x8005,0x0000)
// (MSB-first). Utilisé par Jansite-Solar (non couvert par tpmsx_crc8 qui est
// un CRC-8). Nom préfixé marque pour éviter toute collision.
static inline uint16_t jansite_crc16_buypass(const uint8_t* data, size_t len) {
    uint16_t rem = 0x0000;
    for (size_t i = 0; i < len; i++) {
        rem ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int b = 0; b < 8; b++)
            rem = (rem & 0x8000) ? (uint16_t)((rem << 1) ^ 0x8005) : (uint16_t)(rem << 1);
    }
    return rem;
}

// Inversion de l'ordre des bits d'un octet (= rtl_433 reverse8 / reflect_bytes).
// Utilisé par Steelmate (payload en MSB/LSB inversé). Nom préfixé marque.
static inline uint8_t steelmate_reverse8(uint8_t x) {
    x = (uint8_t)(((x & 0xF0) >> 4) | ((x & 0x0F) << 4));
    x = (uint8_t)(((x & 0xCC) >> 2) | ((x & 0x33) << 2));
    x = (uint8_t)(((x & 0xAA) >> 1) | ((x & 0x55) << 1));
    return x;
}

// ─── Décodeurs ──────────────────────────────────────────────────────────────

// Jansite TPMS Model TY02S (rtl_433 tpms_jansite.c)
//   FSK_PULSE_PCM, short_width 52us. rtl_433 : bitbuffer_invert() puis
//   manchester_decode -> line-code zero="01", one="10". Préambule (brut, non
//   inversé) 0x55 0x55 0x56, data commence 24 bits après. 7 octets Manchester.
//   ATTENTION : rtl_433 livre ce décodeur .disabled=1, « Unknown checksum » :
//   b[6] n'est PAS vérifié (algorithme inconnu). On n'a donc AUCUN MIC ->
//   plausibilité STRICTE (rejet tout-à-zéro, pression>0, bornes temp/pression).
//   Reste sujet aux faux positifs : best-effort, le sync 24 bits est le seul
//   vrai garde-fou. Layout : II II II IS PP TT CC (I=28b id, S=flags, P, T, C).
static bool rf_decode_jansite_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 112) return false;   // 56 bits data = 112 demi-bits
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "010101010101010101010110");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 24;
    uint8_t raw[7];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 56) return false;
    // Pas de checksum vérifiable -> plausibilité stricte.
    uint32_t id = ((uint32_t)raw[0] << 20) | ((uint32_t)raw[1] << 12) | ((uint32_t)raw[2] << 4) | (raw[3] >> 4);
    uint8_t flags = raw[3] & 0x0F;
    float kpa = (float)raw[4] * 1.7f;   // pression ~ quart de PSI, barème rtl_433
    int temp = (int)raw[5] - 50;
    if (raw[4] == 0) return false;                 // pression nulle = bruit
    if (kpa <= 0.0f || kpa > 400.0f) return false; // 0..350 kPa +/-7 selon spec
    if (temp < -40 || temp > 125) return false;    // plage de service capteur
    if (id == 0) return false;
    out.serial = id; out.btn = flags;
    out.kpa = kpa; out.temp = temp; out.Bit = 56; out.te = 52;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Jansite"; out.preset = "2FSKDev238Async";
    return true;
}

// Jansite TPMS Model Solar / TY02S Solar (rtl_433 tpms_jansite_solar.c)
//   FSK_PULSE_PCM, short_width 51us. rtl_433 : manchester_decode PUIS
//   bitbuffer_invert(bytes) -> line-code zero="01", one="10" donne directement
//   les octets post-inversion. Le préambule (brut) 0xa6 0xa6 0x5a EST le codage
//   Manchester du mot de sync 0xdd33 : on décode DÈS le préambule (pas d'avance).
//   11 octets : SS SS II II II 00 TT PP 00 CC CC. CRC-16/BUYPASS sur b[2..8].
static bool rf_decode_jansite_solar_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 51, 17);
    if (bits.size() < 176) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "101001101010011001011010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    // pas d'avance : la décode Manchester démarre sur le préambule (= sync 0xdd33)
    uint8_t raw[11];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 88) return false;
    if (raw[0] != 0xdd || raw[1] != 0x33) return false;          // mot de sync
    uint16_t crc = jansite_crc16_buypass(&raw[2], 7);            // CRC-16/0x8005 init 0
    if ((uint16_t)(((uint16_t)raw[9] << 8) | raw[10]) != crc) return false;
    uint32_t id = ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 8) | raw[4];
    uint8_t flags = raw[5];
    int temp = (int)raw[6] - 55;              // °C offset -55
    float kpa = (float)raw[7] * 1.6f;         // kPa, barème rtl_433
    if (temp < -50 || temp > 125) return false;
    if (kpa < 0.0f || kpa > 700.0f) return false;   // 0..6.6 bar selon spec
    out.serial = id; out.btn = flags;
    out.kpa = kpa; out.temp = temp; out.Bit = 88; out.te = 51;
    memcpy(out.raw, raw, 10); out.raw_len = 10;   // raw[] = 10 octets max (frame=11)
    out.protocol = "Jansite-Solar"; out.preset = "2FSKDev238Async";
    return true;
}

// Jansite TPMS TY-468-eu2 / KKMOON (rtl_433 tpms_jansite_ty468.c)
//   OOK_PULSE_PCM, short_width 50us (famille chip SP372, cf tpms_imars_t240).
//   rtl_433 : préambule alternant 0xaaaaaaaa (32 bits), decode à pos+32, puis
//   manchester_decode PUIS bitbuffer_invert(bytes) -> line-code zero="01",
//   one="10". 8 octets B0..B7. Pas de CRC : checksum = (B3+B4)&0xff qui
//   identifie l'un des 2 capteurs connus (0xfb / 0x64) avec ses offsets calibrés.
//   Un 3e capteur nécessiterait ses propres constantes (inconnues) -> rejeté.
static bool rf_decode_jansite_ty468_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 50, 16);
    if (bits.size() < 128) return false;   // 64 bits data = 128 demi-bits (hors préambule)
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "101010101010101010101010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 32;   // saute les 32 bits de préambule alternant
    uint8_t raw[8];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "01", "10") < 64) return false;
    if (raw[7] != raw[0]) return false;                       // B7 == B0 (intégrité queue)
    if ((raw[0] & 0x0F) != (raw[1] & 0x0F)) return false;     // nibbles bas égaux
    int checksum = (raw[3] + raw[4]) & 0xFF;
    int temp_off, pres_off;
    if (checksum == 0xfb)      { temp_off = 224; pres_off = 273; }
    else if (checksum == 0x64) { temp_off = 153; pres_off = 201; }
    else return false;                                        // capteur inconnu
    int temp = temp_off - ((raw[2] + raw[5]) & 0xFF);
    float kpa = (float)(pres_off - ((raw[5] + raw[6]) & 0xFF)) * 2.5f;
    if (temp < -50 || temp > 125) return false;
    if (kpa < 0.0f || kpa > 700.0f) return false;
    // Pas d'ID décodé par rtl_433 : pseudo-série depuis les octets bruts (dédup table).
    out.serial = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.kpa = kpa; out.temp = temp; out.Bit = 64; out.te = 50;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Jansite-TY468"; out.preset = "Ook270Async";
    return true;
}

// Jansite TPMS TY588-EU2 (rtl_433 tpms_jansite_ty588.c)
//   FSK_PULSE_PCM, short_width 51us. rtl_433 : manchester_decode SANS AUCUNE
//   inversion -> line-code zero="10", one="01". Préambule 44 bits "99aa5a6a9aa"
//   (cherché sur ses 24 premiers bits), data à +44. 8 octets B0..B7, pas de CRC.
//   MIC = B7==B0 ; checks structurels (B3+B4)&0xff==0x30 et nibbles bas égaux.
//   temp=(B2+B5)&0xff-139 ; pression=((B5+B6)&0xff-90)*2.5 kPa. Pas d'ID fixe
//   isolable (B0/B5 = compteur/état) -> pseudo-série depuis octets bruts.
static bool rf_decode_jansite_ty588_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 51, 17);
    if (bits.size() < 128) return false;   // 64 bits data = 128 demi-bits (hors préambule)
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "100110011010101001011010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 44;   // saute les 44 bits de préambule
    uint8_t raw[8];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off, (uint32_t)bits.size(), "10", "01") < 64) return false;
    if (raw[7] != raw[0]) return false;                          // MIC : B7 == B0
    if (((raw[3] + raw[4]) & 0xFF) != 0x30) return false;        // check structurel
    if ((raw[0] & 0x0F) != (raw[1] & 0x0F)) return false;        // nibbles bas égaux
    int raw_temp = (raw[2] + raw[5]) & 0xFF;
    int raw_pres = (raw[5] + raw[6]) & 0xFF;
    int temp = raw_temp - 139;
    int pres_raw = raw_pres - 90;
    if (pres_raw < 0 || temp < -40 || temp > 120) return false;  // bornes rtl_433
    float kpa = (float)pres_raw * 2.5f;
    out.serial = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    out.kpa = kpa; out.temp = temp; out.Bit = 64; out.te = 51;
    memcpy(out.raw, raw, sizeof(raw)); out.raw_len = sizeof(raw);
    out.protocol = "Jansite-TY588"; out.preset = "2FSKDev238Async";
    return true;
}

// Steelmate TPMS TP-S15 / R-Lake (rtl_433 steelmate.c)
//   FSK_PULSE_MANCHESTER_ZEROBIT, short_width 50us. rtl_433 : le slicer livre
//   déjà les bits décodés (front descendant=1/montant=0 => demi-bits "10"=1,
//   "01"=0 => line-code zero="01", one="10"), puis bitbuffer_invert + reflect
//   (MSB/LSB inversé). On ancre sur la transition de sync vers l'octet 0x7f
//   (préambule "A"=0x01 côté data) : "01"x3 + "10"x7, puis on décode 7 octets
//   R[2..8] à partir de 0x7f et on applique final = reverse8(~R).
//   Layout final : SS SS AA II II PP TT BB CC. Checksum = somme(b[2..7]) == b[8].
static bool rf_decode_steelmate_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 50, 16);
    if (bits.size() < 112) return false;   // 56 bits data (R[2..8]) = 112 demi-bits
    // sync : 3 bits d'horloge "01" + 7 bits à 1 ("10"x7) = le début de l'octet 0x7f
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(), "01010110101010101010");
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 4;   // avance de 2 bits d'horloge -> décode démarre sur le MSB de 0x7f
    uint8_t r[7];   // = R[2..8] de rtl_433 (post-slicer, avant invert/reflect)
    if (tpms_convert_from_line_code(r, sizeof(r), bits, off, (uint32_t)bits.size(), "01", "10") < 56) return false;
    uint8_t b[7];   // post invert + reflect : b[0]=AA, b[1..2]=ID, b[3]=P, b[4]=T, b[5]=B, b[6]=CRC
    for (int i = 0; i < 7; i++) b[i] = steelmate_reverse8((uint8_t)~r[i]);
    if (b[0] != 0x01) return false;                 // AA (préambule) attendu = 0x01
    int sum = b[0] + b[1] + b[2] + b[3] + b[4];
    sum += b[5];
    if ((sum & 0xFF) != b[6]) return false;         // checksum somme(b2..b7)==b8
    uint32_t id = ((uint32_t)b[1] << 8) | b[2];
    float kpa = (float)b[3] * 3.125f;               // Bar*32 -> kPa (issue #3200)
    int temp = (int)b[4] - 50;                      // °C offset +50
    if (id == 0 && b[3] == 0) return false;         // rejet tout-à-zéro
    if (kpa < 0.0f || kpa > 900.0f) return false;   // 0..7.9 bar selon spec
    if (temp < -50 || temp > 125) return false;
    out.serial = id; out.fix = (uint32_t)b[5];      // fix = octet batterie/alarme brut
    out.kpa = kpa; out.temp = temp; out.Bit = 72; out.te = 50;
    memcpy(out.raw, b, sizeof(b)); out.raw_len = sizeof(b);   // payload traduit (7 octets)
    out.protocol = "Steelmate"; out.preset = "2FSKDev238Async";
    return true;
}

// TyreGuard 400 — Davies Craig (rtl_433 tpms_tyreguard400.c)
//   OOK_PULSE_MANCHESTER_ZEROBIT, short_width 100us. Slicer => line-code
//   zero="01", one="10" (pas d'invert, pas de reflect). Sync "fd5fd5f" (28 bits)
//   -> en demi-bits 56 symboles ; le sync fait partie des octets décodés
//   (b[0..2]=fd 5f d5, nibble haut b[3]=f). 11 octets, 88 bits. CRC-8 poly 0x31
//   init 0xdd (résidu 0 sur les 11 octets) == rtl_433 crc8(b,11,0x31,0xdd)==0
//   == tpmsx_crc8(b,11,0xdd,0x31)==0. ID 28b @ b[3].lo..b[6].
static bool rf_decode_tyreguard400_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 100, 33);
    if (bits.size() < 176) return false;
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "10101010101001100110011010101010101001100110011010101010");  // Manchester de 0xfd5fd5f
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    // pas d'avance : le sync est inclus dans les octets décodés (b[0]=0xfd ...)
    uint8_t b[11];
    if (tpms_convert_from_line_code(b, sizeof(b), bits, off, (uint32_t)bits.size(), "01", "10") < 88) return false;
    if (tpmsx_crc8(b, 11, 0xdd, 0x31) != 0) return false;     // CRC-8/0x31 init 0xdd, résidu 0
    uint8_t flags = b[9];
    uint32_t id = (((uint32_t)(b[3] & 0x0F)) << 24) | ((uint32_t)b[4] << 16) | ((uint32_t)b[5] << 8) | b[6];
    // rtl_433 sort la valeur brute (b[7] | ((flags&0x70)<<4)) étiquetée pressure_kPa,
    // SANS mise à l'échelle (la doc évoque des psi mais le code n'applique rien) :
    // on suit le code à la lettre.
    int pressure_kpa = b[7] | ((flags & 0x70) << 4);
    int temp = (int)b[8] - 40;                                // °C offset +40
    if (temp < -50 || temp > 125) return false;
    if (pressure_kpa < 0 || pressure_kpa > 1200) return false;
    if (id == 0) return false;
    out.serial = id; out.btn = flags;
    out.kpa = (float)pressure_kpa; out.temp = temp; out.Bit = 88; out.te = 100;
    memcpy(out.raw, b, 10); out.raw_len = 10;   // raw[] = 10 octets max (frame=11)
    out.protocol = "TyreGuard400"; out.preset = "Ook270Async";
    return true;
}


// ---- batchE.inc ----
// ============================================================================
//  batchE.inc — Décodeurs TPMS niche / aftermarket (portés de rtl_433)
// ----------------------------------------------------------------------------
//  À inclure dans tpms_multi.h APRÈS les helpers (tpms_durations_to_bitmap,
//  tpms_bitmap_seek_bits, tpms_convert_from_line_code,
//  tpms_convert_from_diff_manchester, tpmsx_crc8) et la struct TpmsCode/RfCodes.
//  Aucune directive #include, aucun dispatcher, aucun main ici.
//
//  Calibrage rtl_433 -> template (vérifié sur Ford/Toyota déjà portés) :
//   - Le bitmap du template = échantillons RF « on-air » (1 = niveau haut),
//     suréchantillonnés à la résolution te (= rtl_433 short_width).
//   - rtl_433  [invert + bitbuffer_manchester_decode]  ==  line_code("01","10")
//   - rtl_433  [bitbuffer_manchester_decode] (sans invert) == line_code("10","01")
//     (bitbuffer_manchester_decode émet le 2e demi-bit : "01"->1, "10"->0 ;
//      le line_code du template fait l'inverse, cf. commentaire schraeder.c.)
//   - Slicer OOK_PULSE_MANCHESTER_ZEROBIT : front descendant = 1, montant = 0
//     => bit décodé 0 <-> "01" on-air, bit décodé 1 <-> "10" on-air
//        == line_code("01","10") (identique au cas « manchester sans invert »
//        quand rtl_433 n'inverse pas ; avec invert rtl_433 => line_code("10","01")).
//   - Le motif de synchro cherché est l'expansion Manchester on-air du préambule
//     rtl_433 : chaque bit décodé -> 2 échantillons. Si rtl_433 inverse avant de
//     chercher, l'on-air est l'INVERSE du motif rtl_433.
//   - Manchester différentiel : le helper du template porte la donnée sur la
//     transition de DÉBUT de symbole (horloge au milieu), rtl_433 fait l'inverse
//     (horloge au bord, donnée au milieu) : décalage d'un demi-symbole. Donc
//     offset_template = offset_DM_rtl433 + 1, previous = bits[offset_DM_rtl433].
//     Le DM est indépendant de la polarité pour la donnée (transitions).
// ============================================================================

// ─────────────────────── Helper CRC local (unique) ─────────────────────────
// CRC-7 de rtl_433 (bit_util.c crc7) : NON couvert par tpmsx_crc8 (registre
// 7 bits, poly et init décalés de 1, résultat >>1). Signature (data,len,poly,
// init) alignée sur rtl_433. Préfixé « smartire_ » pour rester unique.
static inline uint8_t smartire_crc7(const uint8_t* msg, unsigned nbytes,
                                    uint8_t poly, uint8_t init) {
    unsigned remainder = (unsigned)init << 1;   // LSB inutilisé
    unsigned p         = (unsigned)poly << 1;
    for (unsigned byte = 0; byte < nbytes; ++byte) {
        remainder ^= msg[byte];
        for (int bit = 0; bit < 8; ++bit)
            remainder = (remainder & 0x80) ? ((remainder << 1) ^ p) : (remainder << 1);
    }
    return (uint8_t)((remainder >> 1) & 0x7f);  // on jette le LSB
}

// ────────────────────────────── Décodeurs ──────────────────────────────────

// Airpuxem TYH11_EU6_ZQ (SENASIC SNP739D) — FSK PCM, te=52us, Manchester.
// rtl_433 tpms_airpuxem.c : invert -> preamble {aa aa a9} (24b) -> manchester.
// Layout décodé (après les 24 bits de préambule) :
//   nibble 0 = 0x5 (« FIVE »), puis 64b payload (CRC'd), puis CRC8, puis CRC8(2).
//   CRC-8 poly 0x2f init 0xaa sur les 8 octets du payload (= nibble-aligné à +4).
static bool rf_decode_airpuxem_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 52, 18);
    if (bits.size() < 192) return false;
    // on-air = INVERSE de 0xaaaaa9 (rtl_433 cherche après invert) = 0x555556.
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "01010101010101010101" "0110");                    // 0x555556 (24 échant.)
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 24;                                             // début des données
    uint8_t buf[11];
    // rtl_433 inverse puis manchester_decode => line_code("01","10").
    if (tpms_convert_from_line_code(buf, sizeof(buf), bits, off,
            (uint32_t)bits.size(), "01", "10") < 84) return false;
    if ((buf[0] >> 4) != 0x5) return false;                // en-tête « FIVE »
    // Ré-alignement nibble : payload[i] = bits décodés [4..67], i.e. buf décalé
    // de 4 bits (un nibble). crcbyte = bits décodés [68..75].
    uint8_t payload[8];
    for (int i = 0; i < 8; i++)
        payload[i] = (uint8_t)((buf[i] << 4) | (buf[i + 1] >> 4));
    uint8_t crcbyte = (uint8_t)((buf[8] << 4) | (buf[9] >> 4));
    if (tpmsx_crc8(payload, 8, 0xaa, 0x2f) != crcbyte) return false;
    uint32_t id = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                  ((uint32_t)payload[2] << 8) | payload[3];
    int flags    = (payload[4] >> 4) & 0x07;
    int position = payload[4] & 0x07;
    int pressure = (payload[5] | (((payload[4] >> 7) & 1) << 8) |
                    (((payload[4] >> 3) & 1) << 9)) - 100;  // kPa
    int temp     = (int8_t)payload[6];                      // °C signé
    int battery  = payload[7];                              // * 0.02 V
    (void)battery;
    if (id == 0) return false;
    if (pressure <= 0 || pressure > 1000) return false;     // datasheet 100-900 kPa
    if (temp < -40 || temp > 125) return false;             // plage de fonctionnement
    out.serial = id; out.kpa = (float)pressure; out.temp = temp;
    out.btn = (uint8_t)position; out.cnt = (uint16_t)flags; out.fix = (uint32_t)payload[7];
    out.Bit = 84; out.te = 52;
    memcpy(out.raw, payload, 8); out.raw[8] = crcbyte; out.raw_len = 9;
    out.protocol = "Airpuxem"; out.preset = "2FSKDev238Async";
    return true;
}

// EezTire E618 / Carchet / TST-507 — OOK Manchester ZEROBIT, te=50us.
// rtl_433 tpms_eezrv.c : invert -> preamble 0xffff (16b, DOIT être en tête) ->
//   octet checksum, puis 7 octets données.
// Checksum = somme(b[0..6]) ; si > 0xff on force le bit 0x80 ; &0xff == cc.
// NB : préambule uniforme (pas de sync distinctif après lui) => ancrage faible ;
// on s'appuie sur le checksum + bornes de plausibilité fortes (cf. consigne).
static bool rf_decode_eezrv_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 50, 16);
    if (bits.size() < 96) return false;
    // rtl_433 inverse puis cherche 0xffff => on-air (pré-invert) = 0x0000, soit
    // "01" x16 ; sous line_code("10","01") ce "0101.." se lit bien 0xffff.
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "01010101010101010101010101010101");               // 16 bits décodés
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 32;                                             // après le préambule
    uint8_t raw[8];                                        // raw[0]=cc, raw[1..7]=b[0..6]
    // rtl_433 [invert + ZEROBIT] => line_code("10","01").
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off,
            (uint32_t)bits.size(), "10", "01") < 64) return false;
    int cs = raw[1] + raw[2] + raw[3] + raw[4] + raw[5] + raw[6] + raw[7];
    if (cs > 0xff) cs |= 0x80;
    if ((cs & 0xff) != raw[0]) return false;
    uint32_t id = ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
    int temp = raw[5] - 50;                                // b[4]-50, °C
    float kpa = (float)((((raw[7] & 0x01) << 8) + raw[4]) * 2.5f);  // (b[6]&1)<<8 | b[3]
    int low_batt = raw[6] >> 7;                            // b[5]>>7
    if (id == 0) return false;
    if (kpa <= 0.0f || kpa > 1000.0f) return false;        // plausibilité (checksum faible)
    if (temp < -40 || temp > 125) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.fix = (uint32_t)low_batt; out.btn = (uint8_t)(raw[6] & 0x7f);
    out.Bit = 64; out.te = 50;
    memcpy(out.raw, raw, 8); out.raw_len = 8;
    out.protocol = "EezTire"; out.preset = "Ook270Async";
    return true;
}

// Gear Hive / aftermarket CMT2220LY — OOK Manchester ZEROBIT, te=120us.
// rtl_433 tpms_gear_hive.c : sync 0x2594 (16b, sans invert) -> 72b (9 octets),
//   puis décodage XOR différentiel (seed 0x94), puis sanity sur flags fixes.
//   P/T mappables (kPa / °C). Pas de CRC -> sanity + plausibilité forte.
static bool rf_decode_gear_hive_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 120, 40);
    if (bits.size() < 176) return false;
    // Sans invert, ZEROBIT => bit décodé 0->"01", 1->"10". Expansion de 0x2594 :
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "01011001011001101001011001100101");               // 0x2594 (32 échant.)
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 32;                                             // après le sync 16b
    uint8_t raw[9];
    if (tpms_convert_from_line_code(raw, sizeof(raw), bits, off,
            (uint32_t)bits.size(), "01", "10") < 72) return false;
    uint8_t p[9];
    p[0] = raw[0] ^ 0x94;
    for (int i = 1; i < 9; i++) p[i] = raw[i] ^ raw[i - 1];
    if ((p[6] & 0x3c) != 0x20) return false;               // flags fixes
    if ((p[7] & 0x3f) != 0x35) return false;
    int sensor_class = p[1] & 0x0f;
    int counter = ((p[1] >> 4) << 8) | p[0];
    uint32_t id = ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];
    int base = (80 + sensor_class * 64) & 0xff;
    float kpa = (float)((p[5] - base + 256) & 0xff) * 6.25f;
    int temp_bits = (p[7] >> 6) | ((p[6] & 0x03) << 2);
    int temp = temp_bits + 21;                             // °C (plage étroite 21..36)
    if (id == 0) return false;
    if (kpa <= 0.0f || kpa > 1000.0f) return false;
    if (temp < -40 || temp > 125) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.cnt = (uint16_t)counter; out.btn = (uint8_t)sensor_class;
    out.Bit = 72; out.te = 120;
    memcpy(out.raw, p, 9); out.raw_len = 9;
    out.protocol = "GearHive"; out.preset = "Ook270Async";
    return true;
}

// SmarTire (Aston Martin/Vantage DB9) — OOK PCM + Manchester DIFFÉRENTIEL, te=167us.
// rtl_433 tpms_smartire.c : preamble 0x32b4 (16b PCM, sans invert) -> DM 6 octets
//   à partir de pos+16 -> CRC-7 (poly 0x45 init 0x6f, final 0x00) == 0.
// Un message porte SOIT la pression (msg_type 0) SOIT la température (msg_type 1).
// Ancrage DM : offset_template = pos+16 + 1, previous = bits[pos+16] (décalage
//   d'un demi-symbole entre le DM du template et celui de rtl_433 ; cf. en-tête).
//   Le CRC-7 (fort) protège : une phase/polarité erronée échoue au CRC (pas de
//   faux positif). La polarité du préambule PCM suit rtl_433 (OOK : impulsion=1).
static bool rf_decode_smartire_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 167, 55);
    if (bits.size() < 112) return false;
    uint32_t sync = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "0011001010110100");                               // 0x32b4 (16 échant. PCM)
    if (sync == TPMS_SEEK_NOT_FOUND) return false;
    uint32_t dm_start = sync + 16;                         // = pos+16 (début DM rtl_433)
    if (dm_start + 1 >= (uint32_t)bits.size()) return false;
    bool previous = bits[dm_start];                        // dernier échant. avant DM
    uint8_t b[6];
    if (tpms_convert_from_diff_manchester(b, sizeof(b), bits, dm_start + 1,
            (uint32_t)bits.size(), previous) < 47) return false;  // dernier bit souvent manquant
    if (smartire_crc7(b, 6, 0x45, 0x6f) != 0) return false;
    int id       = ((b[1] & 0x3f) << 16) | (b[2] << 8) | b[3];
    int msg_type = (b[1] & 0xc0) >> 6;
    int value    = b[0] - 40;
    if (id == 0) return false;
    float kpa = 0.0f; int temp = 0;
    if (msg_type == 0) {                                   // pression
        kpa = value * 2.5f;
        if (kpa <= 0.0f || kpa > 1000.0f) return false;
    } else if (msg_type == 1) {                            // température
        temp = value;
        if (temp < -40 || temp > 125) return false;
    } else {
        return false;                                      // msg_type 2/3 inconnu
    }
    out.serial = (uint32_t)id; out.kpa = kpa; out.temp = temp;
    out.btn = (uint8_t)(b[4] & 0x7f);                      // flags (b[4]&0x80 = inflate)
    out.Bit = 48; out.te = 167;
    memcpy(out.raw, b, 6); out.raw_len = 6;
    out.protocol = "SmarTire"; out.preset = "Ook270Async";
    return true;
}

// Schrader Motorcycle (RDC3) — OOK Manchester ZEROBIT, te=122us.
// rtl_433 tpms_schrader_motorcycle.c : preamble 0x7ff8 (13b, sans invert) ->
//   56b (7 octets) -> CRC-8 poly 0x07 init 0xe0 sur les 7 octets == 0.
static bool rf_decode_schrader_motorcycle_tpms(const std::vector<int>& durations, RfCodes& out) {
    if (durations.size() < 32) return false;
    auto bits = tpms_durations_to_bitmap(durations, 122, 40);
    if (bits.size() < 140) return false;
    // Sans invert, ZEROBIT => bit décodé 0->"01", 1->"10". Préambule 13 bits
    // "0111111111111" -> "01" + "10" x12 :
    uint32_t off = tpms_bitmap_seek_bits(bits, 0, (uint32_t)bits.size(),
        "01" "101010101010101010101010");                  // 0x7ff8 /13 (26 échant.)
    if (off == TPMS_SEEK_NOT_FOUND) return false;
    off += 26;                                             // après le préambule 13b
    uint8_t b[7];
    if (tpms_convert_from_line_code(b, sizeof(b), bits, off,
            (uint32_t)bits.size(), "01", "10") < 56) return false;
    if (tpmsx_crc8(b, 7, 0xe0, 0x07) != 0) return false;   // CRC sur data+CRC == 0
    uint32_t id = ((uint32_t)(b[0] & 0x03) << 22) | ((uint32_t)b[1] << 14) |
                  ((uint32_t)b[2] << 6) | (b[3] >> 2);
    uint16_t pressure_raw = (uint16_t)(((b[3] & 0x03) << 8) | b[4]);
    float kpa = pressure_raw * 0.5f;
    int temp = b[5] - 50;
    if (id == 0) return false;
    if (kpa < 0.0f || kpa > 1000.0f) return false;
    if (temp < -40 || temp > 125) return false;
    out.serial = id; out.kpa = kpa; out.temp = temp;
    out.Bit = 56; out.te = 122;
    memcpy(out.raw, b, 7); out.raw_len = 7;
    out.protocol = "SchraderMoto"; out.preset = "Ook270Async";
    return true;
}

// ── SKIP : tpms_imars_t240.c ────────────────────────────────────────────────
// iMars T240 (OOK PCM + Manchester + invert). NON porté : rtl_433 lui-même NE
// décode NI la pression NI la température (commentaire source : « The mapping of
// B2/B5/B6 to temperature and pressure has not been determined: no capture ...
// has a corresponding ground truth reading to calibrate scale/offset against »).
// Il n'émet qu'un « code » brut + un checksum (B3+B4) propre à l'unité (0x41/0x3c).
// Porter ici reviendrait à INVENTER une échelle kPa/°C (interdit : « comment
// ambiguity rather than guess »). Le gabarit TpmsCode exige out.kpa/out.temp,
// inexploitables -> décodeur omis.



// Dispatcher : essaie TOUS les décodeurs TPMS sur un buffer de durées.
// Ordre : CRC forts d'abord (auto-rejet des non-correspondances), puis checksums
// faibles (sum/XOR/flags, bornés par des contrôles de plausibilité), et Jansite
// TY02S en tout dernier (AUCUN checksum — rtl_433 le livre désactivé, fort taux de
// faux positif ; gardé en dernier recours, seul son sync 24 bits le protège).
static bool tpms_multi_decode(const std::vector<int>& durs, TpmsCode& out) {
    // — CRC forts (existants) —
    if (rf_decode_schrader_tpms(durs, out))          return true;
    if (rf_decode_renault_tpms(durs, out))           return true;
    if (rf_decode_toyota_tpms(durs, out))            return true;
    // — CRC forts (nouveaux) —
    if (rf_decode_bmw_tpms(durs, out))               return true;
    if (rf_decode_bmw_g3_tpms(durs, out))            return true;
    if (rf_decode_mercedes_benz_tpms(durs, out))     return true;
    if (rf_decode_porsche_tpms(durs, out))           return true;
    if (rf_decode_hyundai_vdo_tpms(durs, out))       return true;
    if (rf_decode_sefis_m3_tpms(durs, out))          return true;
    if (rf_decode_honda_tpms(durs, out))             return true;
    if (rf_decode_kia_tpms(durs, out))               return true;
    if (rf_decode_trw_ook_tpms(durs, out))           return true;
    if (rf_decode_trw_fsk_tpms(durs, out))           return true;
    if (rf_decode_elantra2012_tpms(durs, out))       return true;
    if (rf_decode_pmv107j_tpms(durs, out))           return true;
    if (rf_decode_ave_tpms(durs, out))               return true;
    if (rf_decode_abarth124_tpms(durs, out))         return true;
    if (rf_decode_jansite_solar_tpms(durs, out))     return true;
    if (rf_decode_tyreguard400_tpms(durs, out))      return true;
    if (rf_decode_smartire_tpms(durs, out))          return true;
    if (rf_decode_schrader_motorcycle_tpms(durs, out)) return true;
    if (rf_decode_airpuxem_tpms(durs, out))          return true;
    // — checksums faibles (sum/XOR/flags, bornés par plausibilité) —
    if (rf_decode_citroen_tpms(durs, out))           return true;
    if (rf_decode_ford_tpms(durs, out))              return true;
    if (rf_decode_gm_tpms(durs, out))                return true;
    if (rf_decode_nissan_tpms(durs, out))            return true;
    if (rf_decode_jeep_tpms(durs, out))              return true;
    if (rf_decode_renault_0435r_tpms(durs, out))     return true;
    if (rf_decode_truck_tpms(durs, out))             return true;
    if (rf_decode_eezrv_tpms(durs, out))             return true;
    if (rf_decode_gear_hive_tpms(durs, out))         return true;
    if (rf_decode_jansite_ty468_tpms(durs, out))     return true;
    if (rf_decode_jansite_ty588_tpms(durs, out))     return true;
    if (rf_decode_steelmate_tpms(durs, out))         return true;
    // — sans checksum (dernier recours) —
    if (rf_decode_jansite_tpms(durs, out))           return true;
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

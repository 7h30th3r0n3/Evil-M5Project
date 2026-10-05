#pragma once
// ============================================================================
// nfc_mfemul.h — MIFARE Classic Crypto1 card emulation + reader-nonce capture
// (Phase 2b). ADDITIVE: reuses the existing Crypto1 cipher (c1_init / c1_bit /
// c1_byte / c1_word / c1_filter / c1_prng_successor / c1_iso14443a_crc /
// c1_pack_with_parity / C1_ODD_PARITY / mf_crypto) and the ST25R3916 target
// primitives already in the .ino (nfc_emul_start / nfc_emul_poll / nfc_emul_stop,
// nfc_wr / nfc_rr / nfc_cmd / nfc_fifo_w / nfc_fifo_r and the NFC_* registers).
//
// This header MUST be #included AFTER those symbols are defined in the .ino
// (i.e. right after nfc_emul_tx_isodep()). It touches NONE of the existing
// Read / Clone / Emulate-UID / ISO-DEP-Relay code paths.
//
// Two operating modes, exposed through mfe_service_once():
//
//  (1) DETECT-READER / mfkey32 nonce capture  ── ROBUST, no secret keys needed.
//      We present a card identity (UID/ATQA/SAK), answer the reader's AUTH with
//      a fixed tag nonce (nt), and capture the reader's encrypted {nr, ar}. The
//      tuple {uid, block, keytype, nt, nr, ar} is exactly what mfkey32 (mfkey.h)
//      needs to recover the reader's sector key offline. This path does NOT run
//      the cipher and is independent of key knowledge, so it is the reliable
//      deliverable.
//
//  (2) FULL EMULATION from a 1K dump  ── BEST EFFORT, timing-sensitive.
//      When a dump + the sector key are loaded we additionally complete the
//      Crypto1 handshake (feed nr, verify ar, answer at) and then serve
//      encrypted READ (0x30) responses and accept encrypted WRITE (0xA0). The
//      cipher logic mirrors the firmware's already-working *reader-side* auth
//      (nfc_mifare_auth_crypto1_cmd), byte-for-byte, so it is arithmetically
//      consistent. What CANNOT be validated without a real reader on hardware is
//      the ISO14443-A Frame-Delay-Time (~86 us): our response is driven from
//      firmware over SPI (nfc_emul_poll -> handle -> TX), and if that round trip
//      exceeds FDT a strict reader may abort after nt. See the report notes.
// ============================================================================

// ---- ISO14443A register bits reused here ----
//   NFC_ISO14443A (0x05): bit7 = no_tx_par, bit6 = no_rx_par  -> 0xC0 = both.
//   NFC_CMD_TX_NO_CRC (0xC5): transmit FIFO as-is, no CRC appended.
//   NFC_IRQ_MAIN bit4 (0x10) = RXE (receive done), bit3 (0x08) = TXE.

// ------------------------------- data model ---------------------------------

struct MfeDump {
    uint8_t  uid[4];
    uint8_t  sak;
    uint16_t atqa;
    uint8_t  data[64][16];    // MIFARE Classic 1K: 16 sectors x 4 blocks
    uint8_t  keyA[16][6];
    uint8_t  keyB[16][6];
    bool     haveKeyA[16];
    bool     haveKeyB[16];
    bool     loaded;
};

struct MfeNonce {
    uint8_t  block;
    uint8_t  keytype;         // 0x60 (KeyA) or 0x61 (KeyB)
    uint32_t nt;              // tag nonce we presented (plaintext)
    uint32_t nr;              // reader nonce, ENCRYPTED as received
    uint32_t ar;             // reader answer,  ENCRYPTED as received
    uint32_t uid;            // card UID (4 bytes, big-endian)
};

#define MFE_MAX_NONCES  24

// Persisted across calls within one emulation session.
MfeDump   g_mfe_dump;
MfeNonce  g_mfe_nonces[MFE_MAX_NONCES];
int       g_mfe_ncount = 0;

// Fixed tag nonce. A static nt (same value every auth) is ideal for mfkey32 and
// keeps the nt-generation cost out of the FDT budget.
#define MFE_STATIC_NT   0x01200145UL

// Live auth session state (mode 2 only).
struct MfeSession {
    bool     active;
    uint8_t  block;
    uint8_t  keytype;
    uint32_t nt;
};
MfeSession g_mfe_sess = {false, 0, 0, 0};

// Event codes returned by mfe_service_once().
enum {
    MFE_EV_IDLE   = 0,   // nothing received this poll
    MFE_EV_NONCE  = 1,   // AUTH answered, {nr,ar} captured (mode 1 always, mode 2 too)
    MFE_EV_AUTHOK = 2,   // full handshake completed, cipher active (mode 2)
    MFE_EV_READ   = 3,   // encrypted READ served (mode 2)
    MFE_EV_WRITE  = 4,   // encrypted WRITE accepted (mode 2)
    MFE_EV_HALT   = 5,   // HALT / reselect
    MFE_EV_OTHER  = 6,   // some other frame seen
};

// ------------------------------ TX helpers ----------------------------------

// Plaintext frame, standard hardware odd-parity, no CRC. Used for the tag nonce.
void mfe_tx_plain(const uint8_t* buf, int len) {
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_wr(NFC_ISO14443A, nfc_rr(NFC_ISO14443A) & ~0xC0); // std parity, we skip CRC via cmd
    nfc_fifo_w(buf, len);
    int bits = len << 3;
    nfc_wr(NFC_TX_BYTES1,     (bits >> 8) & 0xFF);
    nfc_wr(NFC_TX_BYTES1 + 1,  bits       & 0xFF);
    nfc_rr(NFC_IRQ_MAIN);                         // clear stale
    nfc_cmd(NFC_CMD_TX_NO_CRC);
}

// Encrypted frame: XOR each plaintext byte with the keystream, compute the
// Crypto1 (encrypted) parity, pack 9-bit-per-byte and send with no_tx_par, no
// CRC. Advances mf_crypto. Mirrors nfc_mifare_write_block()'s encrypt_pack.
void mfe_tx_enc(const uint8_t* plain, int len) {
    uint8_t enc[24], par[24];
    if (len > 24) len = 24;
    for (int i = 0; i < len; i++) {
        uint8_t ks = c1_byte(mf_crypto, 0, false);
        enc[i] = ks ^ plain[i];
        par[i] = (c1_filter(mf_crypto.odd) ^ C1_ODD_PARITY[plain[i]]) & 1;
    }
    uint8_t packed[28];
    int bits = c1_pack_with_parity(enc, par, len, packed);
    int nb = (bits + 7) / 8;
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_wr(NFC_ISO14443A, nfc_rr(NFC_ISO14443A) | 0xC0); // no_tx_par + no_rx_par
    nfc_fifo_w(packed, nb);
    nfc_wr(NFC_TX_BYTES1,     (bits >> 8) & 0xFF);
    nfc_wr(NFC_TX_BYTES1 + 1,  bits       & 0xFF);
    nfc_rr(NFC_IRQ_MAIN);
    nfc_cmd(NFC_CMD_TX_NO_CRC);
}

// ------------------------------ RX helper -----------------------------------

// Receive one frame while no_rx_par is set: the FIFO holds raw bits packed
// D7..D0 P D7..D0 P ...  Returns the number of 8-bit data bytes (parity bits
// stripped). Mirrors the unpack in nfc_mifare_read_block (line ~46258).
int mfe_rx_raw(uint8_t* out, int maxbytes, int timeout_ms) {
    unsigned long dl = millis() + timeout_ms;
    int n = 0;
    while (millis() < dl) {
        if (nfc_rr(NFC_IRQ_MAIN) & 0x10) { n = nfc_rr(NFC_FIFO_STA1); break; } // RXE
        delayMicroseconds(50);
    }
    if (n <= 0) return 0;
    uint8_t raw[40];
    int rl = nfc_fifo_r(raw, n > 40 ? 40 : n);
    int bit = 0, cnt = 0;
    while (bit + 8 <= rl * 8 && cnt < maxbytes) {
        uint8_t v = 0;
        for (int b = 0; b < 8; b++) {
            int by = (bit + b) / 8, bi = (bit + b) % 8;
            if (raw[by] & (1 << bi)) v |= (1 << b);
        }
        out[cnt++] = v;
        bit += 9;                                 // skip the parity bit
    }
    return cnt;
}

// ------------------------------ session -------------------------------------

void mfe_begin(const uint8_t* uid, int uid_len, uint16_t atqa, uint8_t sak) {
    g_mfe_ncount = 0;
    g_mfe_sess.active = false;
    nfc_emul_start(uid, uid_len, atqa, sak);
}

void mfe_end() {
    nfc_emul_stop();
}

// Load a raw MIFARE Classic 1K dump (1024 bytes, 64 x 16) from SD into g_mfe_dump.
// Sector keys are taken from each sector trailer (block s*4+3): bytes 0..5 = KeyA,
// 10..15 = KeyB. UID/SAK/ATQA come from block 0 + manufacturer byte. Returns true
// on success. Requires SD.h / SD already available in the sketch TU.
bool mfe_load_dump_bin(const char* path) {
    File f = SD.open(path, FILE_READ);
    if (!f) return false;
    int rd = f.read((uint8_t*)g_mfe_dump.data, 1024);
    f.close();
    if (rd < 1024) { g_mfe_dump.loaded = false; return false; }
    // Identity from block 0.
    memcpy(g_mfe_dump.uid, g_mfe_dump.data[0], 4);
    g_mfe_dump.atqa = 0x0004;
    g_mfe_dump.sak  = 0x08;                       // MIFARE Classic 1K
    for (int s = 0; s < 16; s++) {
        const uint8_t* tr = g_mfe_dump.data[s * 4 + 3];
        memcpy(g_mfe_dump.keyA[s], tr, 6);
        memcpy(g_mfe_dump.keyB[s], tr + 10, 6);
        g_mfe_dump.haveKeyA[s] = true;
        g_mfe_dump.haveKeyB[s] = true;
    }
    g_mfe_dump.loaded = true;
    return true;
}

// Return the sector key pointer for a block, or NULL if not known.
const uint8_t* mfe_key_for(const MfeDump* d, uint8_t block, uint8_t keytype) {
    if (!d || !d->loaded) return NULL;
    int sector = block / 4;                        // 1K: 4 blocks/sector
    if (sector < 0 || sector > 15) return NULL;
    if (keytype == 0x60) return d->haveKeyA[sector] ? d->keyA[sector] : NULL;
    else                 return d->haveKeyB[sector] ? d->keyB[sector] : NULL;
}

// Service a single reader command. `capture_only` forces mode (1): even with a
// dump loaded we only capture nonces and never complete the handshake.
// `dump` may be NULL. Returns an MFE_EV_* code.
int mfe_service_once(const MfeDump* dump, bool capture_only) {
    uint8_t buf[64]; uint8_t tgt = 0;
    int n = nfc_emul_poll(buf, sizeof(buf), 60, &tgt);
    if (n <= 0) return MFE_EV_IDLE;

    // ---- AUTH: 0x60 (KeyA) / 0x61 (KeyB) + block ----
    if ((buf[0] == 0x60 || buf[0] == 0x61) && n >= 2) {
        uint8_t keytype = buf[0];
        uint8_t block   = buf[1];
        uint32_t nt = MFE_STATIC_NT;

        // Answer with nt as fast as possible (plaintext, std parity, no CRC).
        uint8_t ntb[4] = { (uint8_t)(nt >> 24), (uint8_t)(nt >> 16),
                           (uint8_t)(nt >> 8),  (uint8_t)nt };
        mfe_tx_plain(ntb, 4);

        // Reader now sends {nr,ar} encrypted with Crypto1 parity -> raw capture.
        nfc_wr(NFC_ISO14443A, nfc_rr(NFC_ISO14443A) | 0xC0); // no_rx_par
        uint8_t na[10];
        int m = mfe_rx_raw(na, 8, 40);
        if (m < 8) return MFE_EV_NONCE;               // saw AUTH but nr/ar incomplete

        uint32_t nr = ((uint32_t)na[0] << 24) | ((uint32_t)na[1] << 16) |
                      ((uint32_t)na[2] << 8) | na[3];
        uint32_t ar = ((uint32_t)na[4] << 24) | ((uint32_t)na[5] << 16) |
                      ((uint32_t)na[6] << 8) | na[7];

        uint32_t cuid = ((uint32_t)g_mfe_dump.uid[0] << 24) | ((uint32_t)g_mfe_dump.uid[1] << 16) |
                        ((uint32_t)g_mfe_dump.uid[2] << 8) | g_mfe_dump.uid[3];

        // Record the tuple for mfkey32 (dedup identical repeats).
        bool dup = false;
        for (int i = 0; i < g_mfe_ncount; i++)
            if (g_mfe_nonces[i].nr == nr && g_mfe_nonces[i].ar == ar &&
                g_mfe_nonces[i].block == block && g_mfe_nonces[i].keytype == keytype) { dup = true; break; }
        if (!dup && g_mfe_ncount < MFE_MAX_NONCES) {
            MfeNonce& e = g_mfe_nonces[g_mfe_ncount++];
            e.block = block; e.keytype = keytype;
            e.nt = nt; e.nr = nr; e.ar = ar; e.uid = cuid;
        }

        // ---- Mode 2: complete the handshake if we hold the key ----
        const uint8_t* key = capture_only ? NULL : mfe_key_for(dump, block, keytype);
        if (key) {
            uint64_t k64 = 0;
            for (int i = 0; i < 6; i++) k64 = (k64 << 8) | key[i];
            c1_init(mf_crypto, k64);
            c1_word(mf_crypto, cuid ^ nt, false);      // absorb uid^nt (both sides identical)

            // Absorb the reader's nr: feed the ciphertext with is_enc=true so the
            // LFSR absorbs the decrypted nr (dual of the reader path which feeds
            // plaintext nr with is_enc=false).
            for (int i = 0; i < 4; i++) c1_byte(mf_crypto, na[i], true);

            // Verify ar == suc(nt,64), byte-for-byte exactly like the reader path.
            uint32_t ar_nt = c1_prng_successor(nt, 32);
            bool ok = true;
            for (int i = 0; i < 4; i++) {
                ar_nt = c1_prng_successor(ar_nt, 8);
                uint8_t expect = ar_nt & 0xFF;
                uint8_t ks = c1_byte(mf_crypto, 0, false);
                uint8_t got = ks ^ na[4 + i];
                if (got != expect) ok = false;
            }
            if (ok) {
                // Answer at = suc(nt,96), encrypted with encrypted parity, no CRC.
                uint32_t at_nt = c1_prng_successor(nt, 64);
                uint8_t atb[4], atp[4];
                for (int i = 0; i < 4; i++) {
                    at_nt = c1_prng_successor(at_nt, 8);
                    uint8_t b = at_nt & 0xFF;
                    atb[i] = c1_byte(mf_crypto, 0, false) ^ b;
                    atp[i] = (c1_filter(mf_crypto.odd) ^ C1_ODD_PARITY[b]) & 1;
                }
                uint8_t packed[6];
                int bits = c1_pack_with_parity(atb, atp, 4, packed);
                int nb = (bits + 7) / 8;
                nfc_cmd(NFC_CMD_CLEAR_FIFO);
                nfc_wr(NFC_ISO14443A, nfc_rr(NFC_ISO14443A) | 0xC0);
                nfc_fifo_w(packed, nb);
                nfc_wr(NFC_TX_BYTES1,     (bits >> 8) & 0xFF);
                nfc_wr(NFC_TX_BYTES1 + 1,  bits       & 0xFF);
                nfc_rr(NFC_IRQ_MAIN);
                nfc_cmd(NFC_CMD_TX_NO_CRC);

                g_mfe_sess.active  = true;
                g_mfe_sess.block   = block;
                g_mfe_sess.keytype = keytype;
                g_mfe_sess.nt      = nt;
                return MFE_EV_AUTHOK;
            }
        }
        return MFE_EV_NONCE;
    }

    // ---- Encrypted commands after auth (mode 2) ----
    if (g_mfe_sess.active && dump && dump->loaded) {
        // The command frame arrived under no_rx_par (raw bits). Decrypt 4 bytes.
        // buf currently holds packed raw; re-unpack (poll returned raw byte count).
        uint8_t enc[8]; int ec = 0, bit = 0;
        while (bit + 8 <= n * 8 && ec < 8) {
            uint8_t v = 0;
            for (int b = 0; b < 8; b++) { int by=(bit+b)/8, bi=(bit+b)%8; if (buf[by]&(1<<bi)) v|=(1<<b); }
            enc[ec++] = v; bit += 9;
        }
        if (ec >= 2) {
            uint8_t c0 = c1_byte(mf_crypto, 0, false) ^ enc[0];
            uint8_t c1 = c1_byte(mf_crypto, 0, false) ^ enc[1];
            // consume the 2 CRC bytes' keystream to stay in sync
            c1_byte(mf_crypto, 0, false); c1_byte(mf_crypto, 0, false);

            if (c0 == 0x30) {                              // READ block c1
                uint8_t resp[18];
                int blk = c1 & 0x3F;
                memcpy(resp, dump->data[blk], 16);
                uint16_t crc = c1_iso14443a_crc(resp, 16);
                resp[16] = crc & 0xFF; resp[17] = (crc >> 8) & 0xFF;
                mfe_tx_enc(resp, 18);
                return MFE_EV_READ;
            }
            if (c0 == 0xA0) {                              // WRITE block c1: ACK then data
                uint8_t ack = 0x0A;                        // 4-bit ACK, encrypted
                // encrypt 4-bit ACK
                uint8_t ks = 0; for (int i=0;i<4;i++) ks |= (c1_bit(mf_crypto,0,false)&1)<<i;
                uint8_t enca = (ks ^ ack) & 0x0F;
                nfc_cmd(NFC_CMD_CLEAR_FIFO);
                nfc_wr(NFC_ISO14443A, nfc_rr(NFC_ISO14443A) | 0xC0);
                nfc_fifo_w(&enca, 1);
                nfc_wr(NFC_TX_BYTES1, 0); nfc_wr(NFC_TX_BYTES1+1, 4); // 4 bits
                nfc_rr(NFC_IRQ_MAIN); nfc_cmd(NFC_CMD_TX_NO_CRC);
                // receive 16 enc data bytes (+2 CRC) and store
                uint8_t wn[24];
                int wm = mfe_rx_raw(wn, 18, 40);
                if (wm >= 16) {
                    int blk = c1 & 0x3F;
                    for (int i = 0; i < 16; i++) {
                        uint8_t k = c1_byte(mf_crypto, 0, false);
                        g_mfe_dump.data[blk][i] = k ^ wn[i];
                    }
                }
                return MFE_EV_WRITE;
            }
        }
        return MFE_EV_OTHER;
    }

    // ---- HALT (0x50 0x00) or anything else ----
    if (buf[0] == 0x50) { g_mfe_sess.active = false; return MFE_EV_HALT; }
    return MFE_EV_OTHER;
}

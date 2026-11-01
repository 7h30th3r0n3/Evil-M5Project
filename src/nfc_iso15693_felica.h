// nfc_iso15693_felica.h — ISO15693 (NFC-V) / FeliCa (NFC-F) / ISO14443-B pollers
// for the ST25R3916 Cap-NFC HAT on Evil-Cardputer.
//
// DESIGN / SAFETY CONTRACT
//   * This file is 100% ADDITIVE. It never touches the existing ISO14443-A
//     code paths. It only adds new poller entry points + a mode helper.
//   * Every poller SAVES nothing and always ends by calling nfcv_restore_isoa(),
//     which replays the exact NFC-A register setup from nfc_open() so the
//     working ISO-A reader is left healthy. The caller in nfcMenu() additionally
//     does a full nfc_close()/nfc_open() as belt-and-suspenders.
//   * Included AFTER the ST25R3916 primitives (nfc_wr/rr/cmd/fifo/transceive)
//     and register #defines, so it can use them directly. Being a .h, its
//     functions are exempt from Arduino's auto-prototype generation (no
//     `static extern "C"` breakage — see project notes).
//
// VALIDATION STATUS (be honest):
//   * FeliCa + ISO14443-B pollers are implemented against the ST25R3916
//     hardware-CRC transceive model and are believed correct, but they are
//     UNVALIDATED on real tags (no hardware in this build environment).
//   * ISO15693 (NFC-V) on the ST25R3916 requires subcarrier-STREAM mode
//     (om=0xE) + software 1-of-4 PPM coding + software SOF/EOF + software
//     CRC16 — it is NOT a plain om mode like A/B/F. The CRC16 + frame builder
//     are provided here as ready infrastructure, but the RF transmit path
//     needs stream-mode bring-up on hardware. nfcv_iso15693_inventory()
//     therefore returns NFCV_PENDING for now (deferred, "relayer en dernier").
//
// Refs: ST25R3916 datasheet (Mode Definition om[3:0], Bit Rate reg),
//       ST RFAL rfalSetMode(), Flipper furi_hal_nfc_* (same silicon).

#ifndef NFC_ISO15693_FELICA_H
#define NFC_ISO15693_FELICA_H

// ── ST25R3916 om (Mode Definition, bits 6:3 = om<<3) ──────────────────────
// ISO-A uses 0x09 in nfc_open() (om=0001 + low bit). B / F below match RFAL.
#define NFCV_MODE_ISO14443B   0x10   // om = 0010
#define NFCV_MODE_FELICA      0x18   // om = 0011
#define NFCV_MODE_SUBC_STREAM 0x70   // om = 1110 (ISO15693 uses this + stream cfg)

// ── Bit Rate Definition (reg 0x04): txrate<<4 | rxrate ; 0=106 1=212 2=424 ──
#define NFCV_RATE_106  0x00
#define NFCV_RATE_212  0x11
#define NFCV_RATE_424  0x22

// Poller return codes
#define NFCV_NOT_FOUND  0
#define NFCV_FOUND      1
#define NFCV_PENDING   -1   // feature deferred (ISO15693 stream-mode bring-up)

// ─────────────────────────────────────────────────────────────────────────
// Restore the ST25R3916 to the NFC-A reader configuration.
// Mirrors the NFC-A tail of nfc_open() (EvilCardputer .ino) verbatim so the
// existing ISO-A Read/EMV/Emul paths keep working after any B/F/V excursion.
// ─────────────────────────────────────────────────────────────────────────
void nfcv_restore_isoa() {
    nfc_cmd(NFC_CMD_STOP_ALL);
    nfc_wr(NFC_MODE_DEF, 0x09);          // NFC-A
    nfc_wr(NFC_BIT_RATE, 0x00);          // 106/106
    nfc_wr(NFC_ISO14443A, 0x00);         // clear no_tx_par + no_rx_par
    nfc_cmd(NFC_CMD_RESET_GAIN);
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_wr(NFC_OP_CTRL, 0x80 | 0x40 | 0x08);   // en | rx_en | tx_en
    delay(5);
    nfc_cmd(NFC_CMD_FIELD_ON);
    delay(10);
}

// Switch the reader to a given om + bit rate, keep the field on.
// Pattern mirrors nfc_open()'s mode/field tail (STOP_ALL → set mode → field on).
static void nfcv_set_mode(uint8_t mode_def, uint8_t bit_rate) {
    nfc_cmd(NFC_CMD_STOP_ALL);
    nfc_wr(NFC_MODE_DEF, mode_def);
    nfc_wr(NFC_BIT_RATE, bit_rate);
    nfc_cmd(NFC_CMD_RESET_GAIN);
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_wr(NFC_OP_CTRL, 0x80 | 0x40 | 0x08);
    delay(5);
    nfc_cmd(NFC_CMD_FIELD_ON);
    delay(10);
}

// ─────────────────────────────────────────────────────────────────────────
// FeliCa (NFC-F) — Polling command → IDm(8) + PMm(8)
// Frame written to FIFO: [LEN][cmd 0x00][syscode 0xFF 0xFF][reqcode 0x01][tsn 0x00]
// LEN counts itself. HW (FeliCa mode) prepends preamble/sync, appends CRC.
// Response FIFO: [LEN][0x01][IDm 8][PMm 8][opt reqdata]
// Returns NFCV_FOUND and fills idm/pmm (8 bytes each) on success.
// ─────────────────────────────────────────────────────────────────────────
int nfcv_felica_poll(uint8_t idm[8], uint8_t pmm[8]) {
    int rc = NFCV_NOT_FOUND;
    nfcv_set_mode(NFCV_MODE_FELICA, NFCV_RATE_212);

    // Polling: cmd=00, system code = FFFF (any), request code = 01 (system code),
    // time slot number = 00.
    uint8_t cmd[] = { 0x06, 0x00, 0xFF, 0xFF, 0x01, 0x00 };
    int rx_len = 0;
    uint8_t* rx = nfc_transceive(cmd, sizeof(cmd), &rx_len, 60);

    // Expect: LEN response=0x01 IDm[8] PMm[8]  → >= 18 bytes, rx[1]==0x01
    if (rx && rx_len >= 18 && rx[1] == 0x01) {
        memcpy(idm, rx + 2, 8);
        memcpy(pmm, rx + 10, 8);
        rc = NFCV_FOUND;
    }
    nfcv_restore_isoa();
    return rc;
}

// ─────────────────────────────────────────────────────────────────────────
// ISO14443-B — REQB/WUPB → ATQB (PUPI + app data + protocol info)
// Frame: [APf 0x05][AFI 0x00][PARAM 0x00]  (PARAM.b3=0 → REQB, N=1 slot)
// HW (ISO-B mode) appends CRC-B. Response ATQB: [0x50][PUPI 4][AppData 4][ProtInfo 3]
// Returns NFCV_FOUND, fills pupi(4). atqb/atqb_len optional (full ATQB copy).
// ─────────────────────────────────────────────────────────────────────────
int nfcv_isob_poll(uint8_t pupi[4], uint8_t* atqb, int atqb_max, int* atqb_len) {
    int rc = NFCV_NOT_FOUND;
    if (atqb_len) *atqb_len = 0;
    nfcv_set_mode(NFCV_MODE_ISO14443B, NFCV_RATE_106);

    uint8_t reqb[] = { 0x05, 0x00, 0x00 };   // APf, AFI=all, PARAM (REQB)
    int rx_len = 0;
    uint8_t* rx = nfc_transceive(reqb, sizeof(reqb), &rx_len, 60);

    // ATQB starts with 0x50 and is 12 bytes (before CRC, which HW strips).
    if (rx && rx_len >= 12 && rx[0] == 0x50) {
        memcpy(pupi, rx + 1, 4);
        if (atqb && atqb_max > 0) {
            int n = (rx_len < atqb_max) ? rx_len : atqb_max;
            memcpy(atqb, rx, n);
            if (atqb_len) *atqb_len = n;
        }
        rc = NFCV_FOUND;
    }
    nfcv_restore_isoa();
    return rc;
}

// ─────────────────────────────────────────────────────────────────────────
// ISO15693 (NFC-V) CRC16 — poly 0x8408 (reflected 0x1021), init 0xFFFF,
// final XOR 0xFFFF, transmitted LSB-first. Provided as ready infrastructure.
// ─────────────────────────────────────────────────────────────────────────
uint16_t nfcv_iso15693_crc(const uint8_t* data, int len) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? (crc >> 1) ^ 0x8408 : (crc >> 1);
    }
    return ~crc;   // caller transmits low byte then high byte
}

// Build an ISO15693 Inventory frame (single slot):
//   [flags 0x26][cmd 0x01][mask len 0x00] + CRC16 (2 bytes, LSB first)
// Returns total length written to buf (5). Ready for a stream-mode TX path.
int nfcv_iso15693_build_inventory(uint8_t* buf, int max) {
    if (max < 5) return 0;
    buf[0] = 0x26;   // flags: high data rate + inventory
    buf[1] = 0x01;   // Inventory command
    buf[2] = 0x00;   // mask length = 0
    uint16_t crc = nfcv_iso15693_crc(buf, 3);
    buf[3] = crc & 0xFF;
    buf[4] = (crc >> 8) & 0xFF;
    return 5;
}

// ───────────────────────────────────────────────────────────────────────────
// ISO15693 (NFC-V) subcarrier-STREAM bring-up on the ST25R3916.
// Register sequence + PPM coding ported from the ST25R3916 driver (ST RFAL /
// Flipper, same silicon): single-subcarrier OOK, 26 kbit/s high data rate.
// No hardware framer: TX = software 1-of-4 PPM (SOF 0x21 / LUT / EOF 0x04);
// RX = software decode of the raw digitized subcarrier stream from the FIFO.
// CRC16 (0x8408) is software, appended to the command and checked on reply.
// ───────────────────────────────────────────────────────────────────────────

// Space-B register access (ST25R3916): one SPI transaction = 0xFB prefix, then
// the normal write/read op. CORR_CONF1/2 and AUX_MOD live in space B.
static void nfc_wr_b(uint8_t reg, uint8_t val) {
    nfc_select();
    cc_spi->transfer(NFC_CMD_SPACE_B);     // 0xFB
    cc_spi->transfer(reg & 0x3F);
    cc_spi->transfer(val);
    nfc_deselect();
}
static uint8_t nfc_rr_b(uint8_t reg) {
    nfc_select();
    cc_spi->transfer(NFC_CMD_SPACE_B);
    cc_spi->transfer(NFC_OP_READ | (reg & 0x3F));
    uint8_t v = cc_spi->transfer(0x00);
    nfc_deselect();
    return v;
}

// ST25R3916 NFC-V reader configuration (hex values from the ST25R3916 reg map).
static void nfcv15_mode_on() {
    nfc_cmd(NFC_CMD_STOP_ALL);
    nfc_wr(0x03, 0xE0);          // MODE: om=subcarrier_stream, tr_am=ook
    nfc_wr(0x09, 0x38);          // STREAM_MODE: scf_sc424 | scp_8pulses | stx_106
    nfc_wr(0x0B, 0x13);          // RX_CONF1: z12k | h80 | lp_600khz
    nfc_wr(0x0C, 0x2D);          // RX_CONF2: agc6_3 | agc_m | agc_en | sqm_dyn
    nfc_wr(0x0D, 0x00);          // RX_CONF3
    nfc_wr(0x0E, 0x00);          // RX_CONF4
    nfc_wr_b(0x0C, 0x13);        // CORR_CONF1 (space B): corr_s0|s1|s4
    nfc_wr_b(0x0D, 0x01);        // CORR_CONF2 (space B): corr_s8
    uint8_t am = nfc_rr_b(0x08); // AUX_MOD (space B): clear dis_reg_am|res_am
    nfc_wr_b(0x08, am & ~0x88);
    nfc_wr(NFC_ISO14443A, 0x00); // no_tx_par / no_rx_par off (NFC-V has no parity here)
    nfc_cmd(NFC_CMD_RESET_GAIN);
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_wr(NFC_OP_CTRL, 0x80 | 0x40 | 0x08);
    delay(5);
    nfc_cmd(NFC_CMD_FIELD_ON);
    delay(10);
}

// TX: encode (SOF + 1-of-4 PPM + EOF) and transmit without hardware CRC.
static bool nfcv15_tx(const uint8_t* data, int len) {
    static const uint8_t lut[4] = {0x02, 0x08, 0x20, 0x80};
    uint8_t enc[1 + 64*4 + 1];
    if (len > 64) len = 64;
    int ei = 0;
    enc[ei++] = 0x21;                                   // SOF
    for (int i = 0; i < len; i++)
        for (int p = 0; p < 4; p++)                     // LSB pair first
            enc[ei++] = lut[(data[i] >> (p * 2)) & 0x03];
    enc[ei++] = 0x04;                                   // EOF
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_fifo_w(enc, ei);
    int bits = ei << 3;
    nfc_wr(NFC_TX_BYTES1, (bits >> 8) & 0xFF);
    nfc_wr(NFC_TX_BYTES1 + 1, bits & 0xFF);
    nfc_rr(NFC_IRQ_MAIN);
    nfc_cmd(NFC_CMD_TX_NO_CRC);                         // 0xC5 (CRC already in payload)
    unsigned long dl = millis() + 20;
    while (millis() < dl) { if (nfc_rr(NFC_IRQ_MAIN) & 0x08) return true; delayMicroseconds(50); }
    return true;   // proceed to RX even if TXE missed
}

// RX: wait RXE, read the raw subcarrier stream, software-decode to data bytes.
// Decode (Flipper model): SOF = first 5 bits == 0x17 (mask 0x1F); then 2 bits
// per data bit, 0x01 -> 0, 0x02 -> 1, until EOF (5 bits == 0x1D). Bit order is
// LSB-first within each FIFO byte. *** This is the HW-tuning point: if a real
// tag replies but decode fails, this bit packing is what to adjust (verify with
// a PM3 'hf 15 sniff'). ***
static int nfcv15_rx(uint8_t* out, int maxout, int timeout_ms) {
    unsigned long dl = millis() + timeout_ms;
    bool got = false;
    while (millis() < dl) { if (nfc_rr(NFC_IRQ_MAIN) & 0x10) { got = true; break; } delay(1); }
    if (!got) return 0;
    uint8_t raw[320];
    int rn = nfc_fifo_r(raw, sizeof(raw));
    if (rn < 2) return 0;
    int totbits = rn * 8;
    auto bit = [&](int i) -> int { return (raw[i >> 3] >> (i & 7)) & 1; };
    auto val = [&](int o, int n) -> int { int v = 0; for (int k = 0; k < n; k++) v |= bit(o + k) << k; return v; };
    if (totbits < 5 || (val(0, 5) & 0x1F) != 0x17) return 0;    // SOF
    int o = 5, nbits = 0;
    uint8_t cur = 0;
    memset(out, 0, maxout);
    while (o + 2 <= totbits && (nbits >> 3) < maxout) {
        if (o + 5 <= totbits && (val(o, 5) & 0x1F) == 0x1D) break; // EOF
        int v = val(o, 2) & 0x03;
        if (v == 0x02) cur |= (1 << (nbits & 7));                 // logical 1
        else if (v != 0x01) { /* noise */ }
        nbits++;
        if ((nbits & 7) == 0) { out[(nbits >> 3) - 1] = cur; cur = 0; }
        o += 2;
    }
    if (nbits & 7) out[nbits >> 3] = cur;
    return (nbits + 7) >> 3;    // bytes decoded (incl. CRC16)
}

// One command/response exchange: append CRC, TX, RX, verify + strip CRC.
// Returns payload length (resp holds data without the 2 CRC bytes), or <=0.
static int nfcv15_xcv(const uint8_t* cmd, int clen, uint8_t* resp, int maxresp, int timeout_ms) {
    uint8_t frame[66];
    if (clen > 64) return -1;
    memcpy(frame, cmd, clen);
    uint16_t crc = nfcv_iso15693_crc(frame, clen);   // ~crc already applied by helper
    frame[clen]     = crc & 0xFF;
    frame[clen + 1] = (crc >> 8) & 0xFF;
    nfcv15_tx(frame, clen + 2);
    uint8_t rx[320];
    int rn = nfcv15_rx(rx, sizeof(rx), timeout_ms);
    if (rn < 3) return 0;                            // need >=1 data + 2 CRC
    uint16_t rc = nfcv_iso15693_crc(rx, rn - 2);
    if ((rx[rn-2] != (rc & 0xFF)) || (rx[rn-1] != ((rc >> 8) & 0xFF))) {
        // CRC mismatch: still hand back the payload for debugging, flagged by negative.
        int n = rn - 2; if (n > maxresp) n = maxresp;
        memcpy(resp, rx, n);
        return -n;
    }
    int n = rn - 2; if (n > maxresp) n = maxresp;
    memcpy(resp, rx, n);
    return n;
}

// Inventory (single slot): flags 0x26, Inventory 0x01, mask len 0x00.
// Response: [flags][DSFID][UID 8 LSB-first]. uid[] returned MSB-first (human).
int nfcv_iso15693_inventory(uint8_t uid[8]) {
    nfcv15_mode_on();
    uint8_t cmd[3] = {0x26, 0x01, 0x00};
    uint8_t resp[16];
    int n = nfcv15_xcv(cmd, 3, resp, sizeof(resp), 20);
    int rc = NFCV_NOT_FOUND;
    if (n >= 10) {                       // flags + DSFID + 8-byte UID
        for (int i = 0; i < 8; i++) uid[i] = resp[9 - i];   // LSB-first -> MSB-first
        rc = NFCV_FOUND;
    }
    nfcv_restore_isoa();
    return rc;
}

// Get System Information (0x2B): addressed-less, flags 0x02 (high data rate).
// Fills *nblocks and *blocksize when present (0 if the tag omits them).
// Returns NFCV_FOUND on a valid reply. info_out (optional) gets the raw payload.
int nfcv_iso15693_sysinfo(uint8_t uid_msb[8], int* nblocks, int* blocksize,
                          uint8_t* info_out, int info_max, int* info_len) {
    nfcv15_mode_on();
    uint8_t cmd[2] = {0x02, 0x2B};       // non-addressed
    uint8_t resp[32];
    int n = nfcv15_xcv(cmd, 2, resp, sizeof(resp), 25);
    int rc = NFCV_NOT_FOUND;
    if (n >= 2 && (resp[0] & 0x01) == 0) {   // no error flag
        // resp: flags, info_flags, UID(8), [DSFID][AFI][blocks,size][icref]
        uint8_t inff = resp[1];
        int p = 10;                           // after flags + info_flags + UID
        if (inff & 0x01) p += 1;              // DSFID
        if (inff & 0x02) p += 1;              // AFI
        if ((inff & 0x04) && (p + 1) < n) {   // VICC memory size
            if (nblocks)  *nblocks  = resp[p] + 1;
            if (blocksize)*blocksize= (resp[p+1] & 0x1F) + 1;
        }
        if (uid_msb) for (int i = 0; i < 8; i++) uid_msb[i] = resp[9 - i];
        if (info_out) { int c = n < info_max ? n : info_max; memcpy(info_out, resp, c); if (info_len) *info_len = c; }
        rc = NFCV_FOUND;
    }
    nfcv_restore_isoa();
    return rc;
}

// Read Single Block (0x20), non-addressed. out gets the block data (blocksize
// bytes). Returns bytes read (block payload) or <=0. Leaves NFC-V mode ON for
// chained reads; caller restores ISO-A when done.
int nfcv_iso15693_read_block(uint8_t blk, uint8_t* out, int maxout) {
    uint8_t cmd[3] = {0x02, 0x20, blk};
    uint8_t resp[40];
    int n = nfcv15_xcv(cmd, 3, resp, sizeof(resp), 25);
    if (n < 2 || (resp[0] & 0x01)) return 0;   // error flag set
    int bl = n - 1;                             // minus the flags byte
    if (bl > maxout) bl = maxout;
    memcpy(out, resp + 1, bl);
    return bl;
}

// Write Single Block (0x21). Option flag (0x40) is set, required by many tags.
// Returns true on success (flags byte, no error bit).
bool nfcv_iso15693_write_block(uint8_t blk, const uint8_t* data, int blocksize) {
    uint8_t cmd[4 + 32];
    int ci = 0;
    cmd[ci++] = 0x42;        // flags: high data rate + option
    cmd[ci++] = 0x21;        // Write Single Block
    cmd[ci++] = blk;
    for (int i = 0; i < blocksize && i < 32; i++) cmd[ci++] = data[i];
    uint8_t resp[8];
    int n = nfcv15_xcv(cmd, ci, resp, sizeof(resp), 40);
    return (n >= 1 && (resp[0] & 0x01) == 0);
}

// ── NXP ICODE SLIX password layer ──────────────────────────────────────────
// SLIX2/SLIX-S protect READ/WRITE/privacy/EAS/destroy with 32-bit passwords.
// Protocol: GET_RANDOM_NUMBER (0xB2) returns a 16-bit challenge; SET_PASSWORD
// (0xB3) sends ident + the password XORed with {rnd,rnd} (double-16). We offer
// a dictionary attack over the common/default SLIX passwords.
// Password identifiers: 0x01 Read, 0x02 Write, 0x04 Privacy, 0x08 Destroy, 0x10 EAS.

static bool nfcv_slix_get_random(uint16_t* rnd) {
    uint8_t cmd[3] = {0x02, 0xB2, 0x04};     // flags, GET_RANDOM, NXP mfg code 0x04
    uint8_t resp[8];
    int n = nfcv15_xcv(cmd, 3, resp, sizeof(resp), 20);
    if (n >= 3 && (resp[0] & 0x01) == 0) { *rnd = resp[1] | (resp[2] << 8); return true; }
    return false;
}

// Try one password for a given identifier. Returns true if accepted.
static bool nfcv_slix_try_password(uint8_t pass_id, uint32_t pwd) {
    uint16_t rnd;
    if (!nfcv_slix_get_random(&rnd)) return false;
    uint32_t xpad = ((uint32_t)rnd << 16) | rnd;   // {rnd, rnd}
    uint32_t x = pwd ^ xpad;
    uint8_t cmd[8] = {0x02, 0xB3, 0x04, pass_id,
                      (uint8_t)(x & 0xFF), (uint8_t)((x >> 8) & 0xFF),
                      (uint8_t)((x >> 16) & 0xFF), (uint8_t)((x >> 24) & 0xFF)};
    uint8_t resp[8];
    int n = nfcv15_xcv(cmd, 8, resp, sizeof(resp), 30);
    return (n >= 1 && (resp[0] & 0x01) == 0);
}

// Common / default SLIX passwords to try first.
static const uint32_t NFCV_SLIX_DEFAULTS[] = {
    0x00000000, 0xFFFFFFFF, 0x0F0F0F0F, 0x7FFD6E5B /* NXP factory EAS on some */,
    0x11111111, 0x12345678, 0x0A0B0C0D, 0xAABBCCDD
};

// Dictionary crack of one password identifier. On success returns true and
// *found = the password. Does NOT brute the full 2^32 space (that is hours on
// this radio); it tries the defaults + an optional caller dictionary file
// /evil/nfc/slix_pwd.txt (one 8-hex password per line).
bool nfcv_iso15693_slix_crack(uint8_t pass_id, uint32_t* found, int* tried_out) {
    nfcv15_mode_on();
    int tried = 0; bool hit = false; uint32_t fp = 0;
    for (unsigned i = 0; i < sizeof(NFCV_SLIX_DEFAULTS)/4 && !hit; i++) {
        tried++;
        if (nfcv_slix_try_password(pass_id, NFCV_SLIX_DEFAULTS[i])) { hit = true; fp = NFCV_SLIX_DEFAULTS[i]; }
    }
    if (!hit) {
        File f = SD.open("/evil/nfc/slix_pwd.txt", FILE_READ);
        if (f) {
            while (f.available() && !hit) {
                String ln = f.readStringUntil('\n'); ln.trim();
                if (ln.length() < 8) continue;
                uint32_t pwd = (uint32_t)strtoul(ln.c_str(), NULL, 16);
                tried++;
                if (nfcv_slix_try_password(pass_id, pwd)) { hit = true; fp = pwd; }
            }
            f.close();
        }
    }
    if (found) *found = fp;
    if (tried_out) *tried_out = tried;
    nfcv_restore_isoa();
    return hit;
}

#endif // NFC_ISO15693_FELICA_H

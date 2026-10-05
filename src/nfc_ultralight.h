#ifndef NFC_ULTRALIGHT_H
#define NFC_ULTRALIGHT_H
// =====================================================================
// Ultralight / NTAG toolkit  (ADDITIVE — Phase 3)
// ---------------------------------------------------------------------
// Reuses the existing NFC primitives from the main .ino:
//   uint8_t* nfc_transceive(const uint8_t* tx,int len,int* rxlen,int tmo);
//   NfcCardInfo nfc_activate();
// This header is #included AFTER those are defined, so no fwd-decls are
// needed.  It is a header (not inline .ino code) to dodge the arduino
// "static extern C" auto-prototype bug, exactly like protopirate_port.h.
//
// Commands implemented (NXP MF0/NTAG datasheets):
//   GET_VERSION 0x60, READ 0x30, FAST_READ 0x3A, WRITE 0xA2,
//   READ_CNT 0x39, GET_SIG 0x3C, PWD_AUTH 0x1B.
// =====================================================================

// ---- product model -------------------------------------------------
struct UlType {
    const char* name;   // human label
    int   total;        // total pages (incl. lock/OTP/config)
    int   user_start;   // first user data page
    int   user_end;     // last user data page (inclusive)
    bool  has_version;  // GET_VERSION supported
    bool  has_pwd;      // PWD_AUTH / config present
};

// Identify from GET_VERSION (8-byte response). vlen must be >= 7.
// version[2]=product type (0x03=UL EV1, 0x04=NTAG), version[6]=storage size.
static UlType ul_identify(const uint8_t* v, int vlen) {
    UlType t = { "Ultralight EV1", 20, 4, 15, true, true };
    if (vlen < 7) { UlType u = { "Ultralight (MF0ICU1)", 16, 4, 15, false, false }; return u; }
    uint8_t prod = v[2];
    uint8_t stor = v[6];
    if (prod == 0x03) { // Ultralight EV1
        if (stor == 0x0B)      { UlType u = { "UL EV1 MF0UL11 (48B)",  20, 4, 15, true, true }; return u; }
        else if (stor == 0x0E) { UlType u = { "UL EV1 MF0UL21 (128B)", 41, 4, 35, true, true }; return u; }
        UlType u = { "Ultralight EV1", 20, 4, 15, true, true }; return u;
    }
    if (prod == 0x04) { // NTAG21x
        if (stor == 0x0F)      { UlType u = { "NTAG213", 45,  4, 39,  true, true }; return u; }
        else if (stor == 0x11) { UlType u = { "NTAG215", 135, 4, 129, true, true }; return u; }
        else if (stor == 0x13) { UlType u = { "NTAG216", 231, 4, 225, true, true }; return u; }
        UlType u = { "NTAG21x", 45, 4, 39, true, true }; return u;
    }
    return t;
}

// Fallback when GET_VERSION is unsupported (classic MF0ICU1 Ultralight).
static UlType ul_identify_legacy() {
    UlType u = { "Ultralight (MF0ICU1)", 16, 4, 15, false, false };
    return u;
}

// READ 0x30 <page>  -> 16 bytes (4 consecutive pages, wraps at end).
// Returns 16 on success, else 0.
static int ul_read(uint8_t page, uint8_t* out16) {
    uint8_t cmd[2] = { 0x30, page };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 2, &rl, 100);
    if (r && rl >= 16) { memcpy(out16, r, 16); return 16; }
    return 0;
}

// FAST_READ 0x3A <start> <end>  -> (end-start+1)*4 bytes. NTAG/UL EV1 only.
// Returns bytes read, or 0.
static int ul_fast_read(uint8_t start, uint8_t end, uint8_t* out, int outcap) {
    if (end < start) return 0;
    int want = (int)(end - start + 1) * 4;
    if (want > outcap) return 0;
    uint8_t cmd[3] = { 0x3A, start, end };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 3, &rl, 200);
    if (r && rl >= want) { memcpy(out, r, want); return want; }
    if (r && rl > 0)     { memcpy(out, r, rl);   return rl;   } // short (CRC-trim variance)
    return 0;
}

// GET_VERSION 0x60 -> up to 8 bytes. Returns length (<=8) or 0 if unsupported.
static int ul_get_version(uint8_t* out8) {
    uint8_t cmd[1] = { 0x60 };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 1, &rl, 100);
    if (r && rl >= 7) { int n = rl > 8 ? 8 : rl; memcpy(out8, r, n); return n; }
    return 0;
}

// READ_CNT 0x39 <idx> -> 3-byte counter (NTAG21x: idx 0). Returns 3 or 0.
static int ul_read_cnt(uint8_t idx, uint8_t* out3) {
    uint8_t cmd[2] = { 0x39, idx };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 2, &rl, 100);
    if (r && rl >= 3) { memcpy(out3, r, 3); return 3; }
    return 0;
}

// GET_SIG 0x3C 0x00 -> 32-byte ECC originality signature. Returns 32 or 0.
static int ul_get_sig(uint8_t* out32) {
    uint8_t cmd[2] = { 0x3C, 0x00 };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 2, &rl, 150);
    if (r && rl >= 32) { memcpy(out32, r, 32); return 32; }
    return 0;
}

// WRITE 0xA2 <page> <4 bytes>  -> 4-bit ACK (0x0A). Returns true on ACK.
static bool ul_write(uint8_t page, const uint8_t* data4) {
    uint8_t cmd[6] = { 0xA2, page, data4[0], data4[1], data4[2], data4[3] };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 6, &rl, 100);
    // ACK is a single 4-bit 0x0A; NAK is 0x00/0x01/0x04/0x05.
    if (r && rl >= 1 && (r[0] & 0x0F) == 0x0A) return true;
    return false;
}

// PWD_AUTH 0x1B <pwd[4]> -> PACK[2]. Returns true if the card answered a
// 2-byte PACK (password accepted). On wrong password the card NAKs / stays
// silent, so caller should re-activate before the next attempt.
static bool ul_pwd_auth(const uint8_t* pwd4, uint8_t* pack2) {
    uint8_t cmd[5] = { 0x1B, pwd4[0], pwd4[1], pwd4[2], pwd4[3] };
    int rl = 0;
    uint8_t* r = nfc_transceive(cmd, 5, &rl, 100);
    if (r && rl >= 2) { pack2[0] = r[0]; pack2[1] = r[1]; return true; }
    return false;
}

// Parse one 8-hex-char password line ("FFFFFFFF") -> 4 bytes. Returns true.
static bool ul_parse_pwd_line(const char* s, uint8_t* out4) {
    int got = 0; uint8_t b = 0; int nib = 0;
    for (const char* p = s; *p && got < 4; ++p) {
        char c = *p;
        int v;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        b = (uint8_t)((b << 4) | v);
        if (++nib == 2) { out4[got++] = b; b = 0; nib = 0; }
    }
    return got == 4;
}

#endif // NFC_ULTRALIGHT_H

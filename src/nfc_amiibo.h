#ifndef NFC_AMIIBO_H
#define NFC_AMIIBO_H
// Amiibo (NTAG215) emulation + clone for Evil-Cardputer (Cap NFC / ST25R3916).
//
// Amiibo = NTAG215: 135 pages x 4 bytes (540 B), 7-byte UID, SAK 0x00,
// ATQA 0x0044. The data blob is AES/HMAC signed by Nintendo and the HMAC is
// bound to the UID, but the Switch does NOT verify the per-chip ECC signature
// (READ_SIG) — so replaying a dump verbatim (its own UID + 540 B) is a valid,
// self-consistent amiibo with NO Nintendo keys needed. That is exactly what
// this module does.
//
// Emulation: builds on the generic ST25R3916 target primitives already in the
// .ino (nfc_emul_start / nfc_emul_poll / nfc_emul_tx). Anticollision/UID/SAK are
// handled in hardware; we only answer the NTAG215 higher-layer command set in
// plaintext (no Crypto1, unlike nfc_mfemul.h). UI stays in the .ino: call
// amiibo_emul_begin() once, then amiibo_service_once() in a loop, then
// amiibo_emul_end() — same shape as mfe_service_once().
//
// Clone: writes the 135 pages with WRITE 0xA2 (ul_write from nfc_ultralight.h).
// A VALID amiibo clone needs the target UID to equal the dump UID, so it only
// works on UID-writable ("magic") NTAG215; on a fixed-UID blank it writes pages
// 3..134 and the result is an invalid amiibo until re-encrypted for the new UID
// (amiitool, not implemented here). NOTE: the clone path is not yet HW-tested.
//
// Load formats: Flipper .nfc (via fnfc_parse) and raw .bin (540 B dump).

#include "nfc_flipper_fmt.h"   // fnfc_parse, FlipperNfcDump
#include "nfc_ultralight.h"    // ul_write (clone)

#define AMIIBO_PAGES 135
#define AMIIBO_BYTES (AMIIBO_PAGES * 4)   // 540

struct AmiiboTag {
    uint8_t pages[AMIIBO_BYTES];
    int     npages;             // pages actually loaded (should be 135)
    uint8_t uid[7];             // 7-byte NFCID, rebuilt from pages 0-1
    uint8_t pack[2];            // PACK returned on PWD_AUTH (page 134)
    uint8_t sig[32];            // READ_SIG response (0 if dump had none)
    bool    loaded;
    char    name[40];           // file basename for the UI
};

// NTAG215 GET_VERSION (0x60) response.
static const uint8_t AMIIBO_VERSION[8] = {0x00,0x04,0x04,0x02,0x01,0x00,0x11,0x03};

// ── UID: pages 0-1 hold UID0..2|BCC0 then UID3..6 ──────────────────────────
static inline void amiibo_uid_from_pages(AmiiboTag* t) {
    // page0 = UID0 UID1 UID2 BCC0 ; page1 = UID3 UID4 UID5 UID6
    t->uid[0] = t->pages[0]; t->uid[1] = t->pages[1]; t->uid[2] = t->pages[2];
    t->uid[3] = t->pages[4]; t->uid[4] = t->pages[5];
    t->uid[5] = t->pages[6]; t->uid[6] = t->pages[7];
}

static inline void amiibo_finish_load(AmiiboTag* t) {
    amiibo_uid_from_pages(t);
    // PACK lives in page 134 (bytes 0-1) on NTAG215.
    if (t->npages >= 135) { t->pack[0] = t->pages[134*4]; t->pack[1] = t->pages[134*4+1]; }
    else { t->pack[0] = t->pack[1] = 0; }
    memset(t->sig, 0, sizeof(t->sig));   // Flipper .nfc parser does not expose the sig; Switch ignores it
    t->loaded = (t->npages >= 20);       // a sane minimum
}

// Raw .bin amiibo dump (540 B, or 532/572 — we take the first 540).
static inline bool amiibo_load_bin(AmiiboTag* t, const char* path) {
    memset(t, 0, sizeof(*t));
    File f = SD.open(path, FILE_READ);
    if (!f) return false;
    int rd = f.read(t->pages, AMIIBO_BYTES);
    f.close();
    if (rd < 80) return false;                 // way too short
    t->npages = rd / 4;
    if (t->npages > AMIIBO_PAGES) t->npages = AMIIBO_PAGES;
    const char* b = strrchr(path, '/'); strncpy(t->name, b ? b+1 : path, sizeof(t->name)-1);
    amiibo_finish_load(t);
    return t->loaded;
}

// Flipper .nfc NTAG215 dump.
static inline bool amiibo_load_nfc(AmiiboTag* t, const char* path) {
    memset(t, 0, sizeof(*t));
    File f = SD.open(path, FILE_READ);
    if (!f) return false;
    char* txt = (char*)malloc(8192);           // on-demand (was 8K static BSS), freed below
    if (!txt) { f.close(); return false; }
    int n = f.read((uint8_t*)txt, 8191);
    f.close();
    bool ok = false;
    if (n > 0) {
        txt[n] = 0;
        FlipperNfcDump d;
        static uint8_t known[AMIIBO_PAGES];
        if (fnfc_parse(txt, &d, t->pages, AMIIBO_BYTES, known, AMIIBO_PAGES) && d.dev == FNFC_UL) {
            t->npages = d.data_rows;
            if (t->npages > AMIIBO_PAGES) t->npages = AMIIBO_PAGES;
            const char* b = strrchr(path, '/'); strncpy(t->name, b ? b+1 : path, sizeof(t->name)-1);
            amiibo_finish_load(t);
            ok = t->loaded;
        }
    }
    free(txt);
    return ok;
}

// Dispatch by extension.
static inline bool amiibo_load(AmiiboTag* t, const char* path) {
    int L = strlen(path);
    if (L > 4 && !strcasecmp(path + L - 4, ".bin")) return amiibo_load_bin(t, path);
    return amiibo_load_nfc(t, path);
}

// ── 4-bit ACK (0x0A) for an accepted WRITE, no CRC ─────────────────────────
static inline void amiibo_tx_ack4(uint8_t code4) {
    uint8_t b = code4 & 0x0F;
    nfc_cmd(NFC_CMD_CLEAR_FIFO);
    nfc_wr(NFC_ISO14443A, nfc_rr(NFC_ISO14443A) & ~0xC0);   // std parity
    nfc_fifo_w(&b, 1);
    nfc_wr(NFC_TX_BYTES1,     0x00);
    nfc_wr(NFC_TX_BYTES1 + 1, 0x04);                         // 4 bits
    nfc_rr(NFC_IRQ_MAIN);
    nfc_cmd(NFC_CMD_TX_NO_CRC);
}

// ── Emulation ──────────────────────────────────────────────────────────────
struct AmiiboStats { uint32_t reads, writes, pwd, other; };

static inline void amiibo_emul_begin(const AmiiboTag* t) {
    nfc_emul_start(t->uid, 7, 0x0044, 0x00);   // NTAG215: ATQA 0044, SAK 00
}
static inline void amiibo_emul_end() { nfc_emul_stop(); }

// Handle at most one reader frame. Returns the command byte handled, 0 on
// timeout. `allow_write` lets games write back (save data) into the RAM buffer.
static inline int amiibo_service_once(AmiiboTag* t, bool allow_write, AmiiboStats* st, int timeout_ms) {
    uint8_t buf[64]; uint8_t tgt = 0;
    int n = nfc_emul_poll(buf, sizeof(buf), timeout_ms, &tgt);
    if (n <= 0) return 0;
    uint8_t cmd = buf[0];

    if (cmd == 0x30 && n >= 2) {                 // READ: 16 bytes from page, wrapping
        uint8_t resp[16];
        int start = buf[1];
        for (int i = 0; i < 4; i++) {
            int pg = (start + i) % AMIIBO_PAGES;
            memcpy(resp + i*4, t->pages + pg*4, 4);
        }
        nfc_emul_tx(resp, 16);
        if (st) st->reads++;
        return cmd;
    }
    if (cmd == 0x3A && n >= 3) {                 // FAST_READ: pages [start..end]
        int s = buf[1], e = buf[2];
        if (e < s) e = s;
        int cnt = e - s + 1; if (cnt > 60) cnt = 60;   // bound to a safe FIFO/TX size (<=240 B)
        uint8_t resp[240];
        for (int i = 0; i < cnt; i++) {
            int pg = (s + i) % AMIIBO_PAGES;
            memcpy(resp + i*4, t->pages + pg*4, 4);
        }
        nfc_emul_tx(resp, cnt*4);
        if (st) st->reads++;
        return cmd;
    }
    if (cmd == 0x60) {                           // GET_VERSION
        nfc_emul_tx(AMIIBO_VERSION, 8);
        if (st) st->other++;
        return cmd;
    }
    if (cmd == 0x3C) {                           // READ_SIG
        nfc_emul_tx(t->sig, 32);
        if (st) st->other++;
        return cmd;
    }
    if (cmd == 0x1B) {                           // PWD_AUTH -> PACK
        nfc_emul_tx(t->pack, 2);
        if (st) st->pwd++;
        return cmd;
    }
    if (cmd == 0xA2 && n >= 6) {                 // WRITE one page
        int pg = buf[1];
        if (allow_write && pg >= 4 && pg < AMIIBO_PAGES) {
            memcpy(t->pages + pg*4, buf + 2, 4);
            amiibo_tx_ack4(0x0A);                // ACK
        } else {
            amiibo_tx_ack4(0x00);                // NAK (read-only / out of range)
        }
        if (st) st->writes++;
        return cmd;
    }
    if (cmd == 0x50) {                           // HALT -> re-arm passive target
        amiibo_emul_begin(t);
        return cmd;
    }
    if (st) st->other++;
    return cmd;
}

// ── Clone (write a dump to a physical NTAG215) ──────────────────────────────
// Writes pages via ul_write. When set_uid is true it also writes pages 0-2
// (only UID-writable "magic" tags accept this). Returns pages written; *failed
// gets the count that NAKed. Requires the tag to be already activated by the
// caller (nfc_activate). NOTE: not yet validated on hardware.
static inline int amiibo_clone_write(const AmiiboTag* t, bool set_uid, int* failed) {
    int ok = 0, bad = 0;
    int first = set_uid ? 0 : 3;               // page 3 = CC; skip UID/BCC/lock unless magic
    for (int pg = first; pg < t->npages && pg < AMIIBO_PAGES; pg++) {
        if (!set_uid && pg < 4) continue;      // leave UID/lock/CC on non-magic tags
        if (ul_write((uint8_t)pg, t->pages + pg*4)) ok++; else bad++;
        delay(3);
    }
    if (failed) *failed = bad;
    return ok;
}

#endif // NFC_AMIIBO_H

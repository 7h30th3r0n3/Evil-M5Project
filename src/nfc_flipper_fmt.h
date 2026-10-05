// nfc_flipper_fmt.h — Flipper Zero ".nfc" file interop (Version 4, unified NFC app)
// Export + import of MIFARE Classic and NTAG/Ultralight dumps for Evil-Cardputer.
//
// Pure C core (no Arduino types) so it round-trips on the host with g++.
// The writer streams one line at a time through a caller-supplied emit callback,
// so it works with an SD `File` (File::println) on device and a std::string on host.
//
// Format reference (Flipper firmware, Version 4):
//   Filetype: Flipper NFC device
//   Version: 4
//   Device type: Mifare Classic | NTAG/Ultralight
//   UID: AA BB CC ..            (cascade UID bytes, space hex, upper)
//   ATQA: 00 44                 (16-bit value, high byte first)
//   SAK: 00
//   -- Mifare Classic --
//   Mifare Classic type: 1K|4K|Mini
//   Data format version: 2
//   Block 0: 16 hex bytes | "?? .. ??" for unread
//   -- NTAG/Ultralight --
//   Data format version: 2
//   NTAG/Ultralight type: NTAG213|NTAG215|NTAG216|Mifare Ultralight|...
//   Pages total: N
//   Pages read: N
//   Page 0: 4 hex bytes
#ifndef NFC_FLIPPER_FMT_H
#define NFC_FLIPPER_FMT_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

enum FnfcDev { FNFC_UNKNOWN = 0, FNFC_MFC = 1, FNFC_UL = 2 };

// One flat dump description. `data` is row-major: `data_rows` rows of `data_width`
// bytes (16 for a Classic block, 4 for an Ultralight/NTAG page). `row_known`, when
// non-NULL, is one byte per row (1=known, 0=unknown -> written as "??").
struct FlipperNfcDump {
    uint8_t  uid[10];
    int      uid_len;
    uint16_t atqa;            // 16-bit value; ATQA line prints high byte then low
    uint8_t  sak;
    int      dev;             // FnfcDev
    char     subtype[24];     // MFC: "1K"/"4K"/"Mini"; UL: "NTAG215"/"Mifare Ultralight"/...
    const uint8_t* data;      // rows*width bytes, may be NULL
    const uint8_t* row_known; // rows bytes or NULL (=> all known)
    int      data_rows;
    int      data_width;
    int      pages_total;     // UL only; 0 => same as data_rows
};

static inline void fnfc_dump_init(FlipperNfcDump* d) {
    memset(d, 0, sizeof(*d));
}

// ── Classic type helpers ──────────────────────────────────────────────────
static inline const char* fnfc_mfc_type_from_sak(uint8_t sak) {
    if (sak == 0x18) return "4K";
    if (sak == 0x09) return "Mini";
    return "1K"; // sak 0x08 and everything else default
}
static inline int fnfc_mfc_blocks_from_type(const char* t) {
    if (t && (t[0] == '4')) return 256;             // 4K
    if (t && (t[0] == 'M' || t[0] == 'm')) return 20; // Mini (5 sectors)
    return 64;                                       // 1K
}

// Best-effort NTAG/Ultralight subtype from user-memory page count.
// (NTAG213=45, NTAG215=135, NTAG216=231 total pages; UL=16, UL-C=48.)
static inline const char* fnfc_ul_type_from_pages(int pages_total) {
    if (pages_total >= 231) return "NTAG216";
    if (pages_total >= 135) return "NTAG215";
    if (pages_total >= 45)  return "NTAG213";
    if (pages_total >= 48)  return "Mifare Ultralight C";
    return "Mifare Ultralight";
}
static inline int fnfc_ul_pages_from_type(const char* t) {
    if (!t) return 16;
    if (!strcmp(t, "NTAG216")) return 231;
    if (!strcmp(t, "NTAG215")) return 135;
    if (!strcmp(t, "NTAG213")) return 45;
    if (!strcmp(t, "Mifare Ultralight C")) return 48;
    return 16;
}

// ── hex helpers ───────────────────────────────────────────────────────────
static inline int fnfc_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
// Append " %02X" times n from src into buf (upper hex, space-separated, leading space).
static inline int fnfc_append_hex(char* buf, int cap, int pos, const uint8_t* src, int n) {
    for (int i = 0; i < n; i++)
        pos += snprintf(buf + pos, (cap > pos) ? (cap - pos) : 0, " %02X", src[i]);
    return pos;
}
static inline int fnfc_append_unknown(char* buf, int cap, int pos, int n) {
    for (int i = 0; i < n; i++)
        pos += snprintf(buf + pos, (cap > pos) ? (cap - pos) : 0, " ??");
    return pos;
}

// ── writer ────────────────────────────────────────────────────────────────
// emit(ctx, line): line has NO trailing newline; the sink adds it.
typedef void (*fnfc_emit_fn)(void* ctx, const char* line);

static inline void fnfc_write(const FlipperNfcDump* d, fnfc_emit_fn emit, void* ctx) {
    char line[160];
    emit(ctx, "Filetype: Flipper NFC device");
    emit(ctx, "Version: 4");

    const char* dtype = (d->dev == FNFC_MFC) ? "Mifare Classic"
                      : (d->dev == FNFC_UL)  ? "NTAG/Ultralight"
                                             : "Unknown";
    snprintf(line, sizeof(line), "Device type: %s", dtype);
    emit(ctx, line);

    int pos = snprintf(line, sizeof(line), "UID:");
    pos = fnfc_append_hex(line, sizeof(line), pos, d->uid, d->uid_len);
    emit(ctx, line);

    snprintf(line, sizeof(line), "ATQA: %02X %02X", (d->atqa >> 8) & 0xFF, d->atqa & 0xFF);
    emit(ctx, line);
    snprintf(line, sizeof(line), "SAK: %02X", d->sak);
    emit(ctx, line);

    if (d->dev == FNFC_MFC) {
        const char* t = d->subtype[0] ? d->subtype : fnfc_mfc_type_from_sak(d->sak);
        snprintf(line, sizeof(line), "Mifare Classic type: %s", t);
        emit(ctx, line);
        emit(ctx, "Data format version: 2");
        for (int b = 0; b < d->data_rows; b++) {
            int known = !d->row_known || d->row_known[b];
            pos = snprintf(line, sizeof(line), "Block %d:", b);
            if (known && d->data)
                pos = fnfc_append_hex(line, sizeof(line), pos, d->data + b * d->data_width, d->data_width);
            else
                pos = fnfc_append_unknown(line, sizeof(line), pos, d->data_width);
            emit(ctx, line);
        }
    } else if (d->dev == FNFC_UL) {
        emit(ctx, "Data format version: 2");
        const char* t = d->subtype[0] ? d->subtype
                       : fnfc_ul_type_from_pages(d->pages_total ? d->pages_total : d->data_rows);
        snprintf(line, sizeof(line), "NTAG/Ultralight type: %s", t);
        emit(ctx, line);
        int ptot = d->pages_total ? d->pages_total : d->data_rows;
        snprintf(line, sizeof(line), "Pages total: %d", ptot);
        emit(ctx, line);
        snprintf(line, sizeof(line), "Pages read: %d", d->data_rows);
        emit(ctx, line);
        for (int p = 0; p < d->data_rows; p++) {
            int known = !d->row_known || d->row_known[p];
            pos = snprintf(line, sizeof(line), "Page %d:", p);
            if (known && d->data)
                pos = fnfc_append_hex(line, sizeof(line), pos, d->data + p * d->data_width, d->data_width);
            else
                pos = fnfc_append_unknown(line, sizeof(line), pos, d->data_width);
            emit(ctx, line);
        }
    }
}

// ── parser ────────────────────────────────────────────────────────────────
// Parse one "K V" line: returns pointer to value start (after "key:" and spaces)
// if the line begins with `key`, else NULL. `key` must include the trailing ':'.
static inline const char* fnfc_match(const char* line, const char* key) {
    size_t kl = strlen(key);
    if (strncmp(line, key, kl) != 0) return NULL;
    const char* v = line + kl;
    while (*v == ' ' || *v == '\t') v++;
    return v;
}
// Parse space/whitespace-separated hex bytes from `s` into `out` (max n). "??" -> 0
// and sets *had_unknown. Returns bytes parsed.
static inline int fnfc_parse_hex_bytes(const char* s, uint8_t* out, int n, int* had_unknown) {
    int cnt = 0;
    while (*s && cnt < n) {
        while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
        if (!*s) break;
        if (s[0] == '?' && s[1] == '?') {
            if (had_unknown) *had_unknown = 1;
            out[cnt++] = 0x00;
            s += 2;
            continue;
        }
        int hi = fnfc_hexval(s[0]);
        int lo = (hi >= 0) ? fnfc_hexval(s[1]) : -1;
        if (hi < 0 || lo < 0) break;
        out[cnt++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return cnt;
}

// Parse a whole .nfc text buffer. Row data (blocks/pages) is written into
// `databuf` (capacity `databuf_bytes`); `d->data` is set to point at it.
// `row_known_buf` (capacity `known_cap` rows) receives per-row known flags and is
// pointed to by `d->row_known`. Returns 1 on a recognised Flipper NFC file.
static inline int fnfc_parse(const char* text,
                             FlipperNfcDump* d,
                             uint8_t* databuf, int databuf_bytes,
                             uint8_t* row_known_buf, int known_cap) {
    fnfc_dump_init(d);
    d->data = databuf;
    d->row_known = row_known_buf;

    int is_nfc = 0, max_row = -1;
    const char* p = text;
    char line[256];

    while (*p) {
        // copy one line
        int li = 0;
        while (*p && *p != '\n' && li < (int)sizeof(line) - 1) {
            if (*p != '\r') line[li++] = *p;
            p++;
        }
        line[li] = 0;
        if (*p == '\n') p++;
        if (li == 0 || line[0] == '#') continue;

        const char* v;
        if (fnfc_match(line, "Filetype:")) { is_nfc = 1; continue; }
        if ((v = fnfc_match(line, "Device type:"))) {
            if (strstr(v, "Mifare Classic")) d->dev = FNFC_MFC;
            else if (strstr(v, "Ultralight") || strstr(v, "NTAG")) d->dev = FNFC_UL;
            continue;
        }
        if ((v = fnfc_match(line, "UID:"))) {
            d->uid_len = fnfc_parse_hex_bytes(v, d->uid, 10, NULL);
            continue;
        }
        if ((v = fnfc_match(line, "ATQA:"))) {
            uint8_t a[2] = {0, 0};
            int nb = fnfc_parse_hex_bytes(v, a, 2, NULL);
            d->atqa = (nb >= 2) ? (uint16_t)((a[0] << 8) | a[1]) : a[0];
            continue;
        }
        if ((v = fnfc_match(line, "SAK:"))) {
            uint8_t s = 0; fnfc_parse_hex_bytes(v, &s, 1, NULL); d->sak = s;
            continue;
        }
        if ((v = fnfc_match(line, "Mifare Classic type:"))) {
            strncpy(d->subtype, v, sizeof(d->subtype) - 1); continue;
        }
        if ((v = fnfc_match(line, "NTAG/Ultralight type:"))) {
            strncpy(d->subtype, v, sizeof(d->subtype) - 1); continue;
        }
        if ((v = fnfc_match(line, "Pages total:"))) { d->pages_total = atoi(v); continue; }

        // Block N: / Page N:
        int is_block = !strncmp(line, "Block ", 6);
        int is_page  = !strncmp(line, "Page ", 5);
        if (is_block || is_page) {
            int width = is_block ? 16 : 4;
            if (d->dev == FNFC_UNKNOWN) d->dev = is_block ? FNFC_MFC : FNFC_UL;
            d->data_width = width;
            const char* numstart = line + (is_block ? 6 : 5);
            int row = atoi(numstart);
            const char* colon = strchr(line, ':');
            if (!colon || row < 0) continue;
            v = colon + 1;
            while (*v == ' ' || *v == '\t') v++;
            if ((long)(row + 1) * width > databuf_bytes) continue; // overflow guard
            int unk = 0;
            fnfc_parse_hex_bytes(v, databuf + row * width, width, &unk);
            if (row_known_buf && row < known_cap) row_known_buf[row] = unk ? 0 : 1;
            if (row > max_row) max_row = row;
            continue;
        }
    }

    d->data_rows = max_row + 1;
    if (d->pages_total == 0 && d->dev == FNFC_UL) d->pages_total = d->data_rows;
    return is_nfc && d->uid_len > 0;
}

#endif // NFC_FLIPPER_FMT_H

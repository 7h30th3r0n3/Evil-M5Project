// nfc_flipper_dev.h — device-side glue for Flipper ".nfc" export.
// Kept in a header (not the .ino) so arduino-builder does NOT generate broken
// `static extern "C"` prototypes for these helpers. Include AFTER NfcCardInfo,
// SD/File and nfc_flipper_fmt.h are available.
#ifndef NFC_FLIPPER_DEV_H
#define NFC_FLIPPER_DEV_H

#include "nfc_flipper_fmt.h"

// SD File sink for the Flipper .nfc writer (LF line endings, matching Flipper).
static inline void fnfc_emit_file(void* ctx, const char* line) {
    File* f = (File*)ctx;
    f->print(line);
    f->print('\n');
}

// Export the tag currently in memory to /evil/nfc/<UID>.nfc in Flipper format.
// Pass mf_blocks/mf_total_blocks for MIFARE Classic, or ul_pages/ul_pages_read for
// NTAG/Ultralight (leave the other pair NULL/0). Returns true on success.
static inline bool nfc_export_flipper(const NfcCardInfo& card,
                                      uint8_t (*mf_blocks)[16], int mf_total_blocks,
                                      const uint8_t* ul_pages, int ul_pages_read,
                                      char* out_path, int out_path_len) {
    SD.mkdir("/evil/nfc");
    char fname[80];
    int p = snprintf(fname, sizeof(fname), "/evil/nfc/");
    for (int i = 0; i < card.uid_len && i < 7; i++)
        p += snprintf(fname + p, sizeof(fname) - p, "%02X", card.uid[i]);
    snprintf(fname + p, sizeof(fname) - p, ".nfc");

    FlipperNfcDump d; fnfc_dump_init(&d);
    int ul = card.uid_len < 10 ? card.uid_len : 10;
    memcpy(d.uid, card.uid, ul);
    d.uid_len = card.uid_len;
    d.atqa = card.atqa;
    d.sak = card.sak;

    static uint8_t known[256];
    if (mf_blocks && mf_total_blocks > 0) {
        d.dev = FNFC_MFC;
        strncpy(d.subtype, fnfc_mfc_type_from_sak(card.sak), sizeof(d.subtype) - 1);
        int nr = mf_total_blocks < 256 ? mf_total_blocks : 256;
        for (int b = 0; b < nr; b++) {
            bool has = (b == 0);
            for (int j = 0; j < 16 && !has; j++) if (mf_blocks[b][j]) has = true;
            known[b] = has ? 1 : 0;
        }
        d.data = &mf_blocks[0][0];
        d.data_width = 16;
        d.data_rows = nr;
        d.row_known = known;
    } else if (ul_pages && ul_pages_read > 0) {
        d.dev = FNFC_UL;
        strncpy(d.subtype, fnfc_ul_type_from_pages(ul_pages_read), sizeof(d.subtype) - 1);
        d.data = ul_pages;
        d.data_width = 4;
        d.data_rows = ul_pages_read;
        d.pages_total = ul_pages_read;
        d.row_known = NULL;
    } else {
        d.dev = (card.sak == 0x00) ? FNFC_UL : FNFC_MFC;  // UID-only fallback
    }

    File f = SD.open(fname, FILE_WRITE);
    if (!f) return false;
    fnfc_write(&d, fnfc_emit_file, &f);
    f.close();
    if (out_path && out_path_len > 0) {
        strncpy(out_path, fname, out_path_len - 1);
        out_path[out_path_len - 1] = 0;
    }
    return true;
}

#endif // NFC_FLIPPER_DEV_H

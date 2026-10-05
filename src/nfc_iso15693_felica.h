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

// ISO15693 Inventory poller.
// DEFERRED: the ST25R3916 drives ISO15693 through subcarrier-STREAM mode
// (om=0xE) with software 1-of-4 PPM coding and software SOF/EOF — that RF
// bring-up must be validated on hardware. Until then this returns NFCV_PENDING
// (never touches the field beyond a safe no-op) so it can't mislead. The CRC16
// + frame builder above are the reusable pieces the completion will need.
int nfcv_iso15693_inventory(uint8_t uid[8]) {
    (void)uid;
    Serial.println("[ISO15693] deferred: needs ST25R3916 stream-mode bring-up (hardware)");
    return NFCV_PENDING;
}

#endif // NFC_ISO15693_FELICA_H

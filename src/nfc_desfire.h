// =====================================================================
// nfc_desfire.h  —  Phase 5 : MIFARE DESFire (EV1/EV2/EV3)
//   * énumération : GET_VERSION, applications (AIDs), fichiers, settings
//   * authentification : DES (D40 legacy 0x0A), ISO 3DES (0x1A),
//                        AES-128 (EV1 0xAA)  — challenge RndA/RndB CBC
//
//  RÉUTILISE le transport ISO-DEP existant du .ino (nfc_transceive_apdu :
//  I-block PCB + chaining + WTX) — ce header ne réécrit PAS le transport
//  et ne touche PAS au relais. Commandes DESFire "natives" : l'octet de
//  commande + data forme le champ INF d'un I-block ; la réponse = octet de
//  statut (0x00=OK, 0xAF=frame supplémentaire) + payload.
//
//  Crypto via mbedtls (déjà linké dans le firmware : aes/des).
//  Réfs : NXP AN, libfreefare, Flipper mf_desfire, Ridrix DESFire notes.
// =====================================================================
#pragma once
#include <stdint.h>
#include <string.h>
#include "mbedtls/aes.h"
// NB: MBEDTLS_DES_C est désactivé dans le sdkconfig ESP32-S3 de ce core
// (link error si on appelle mbedtls_des*). On embarque donc un DES autonome
// ci-dessous pour l'auth DESFire legacy (D40 / 2K3DES). AES reste via mbedtls.

// --- transport défini plus haut dans le .ino (ce header est inclus après) ---
uint8_t* nfc_transceive_apdu(const uint8_t* apdu, int apdu_len, int* rx_len, int timeout_ms);

// ---- statuts ----
#define DF_ST_OK              0x00
#define DF_ST_ADDITIONAL      0xAF
#define DF_ST_AUTH_ERROR      0xAE
#define DF_ST_LENGTH_ERROR    0x7E
#define DF_ST_PERMISSION      0x9D
// ---- commandes natives ----
#define DF_CMD_GET_VERSION        0x60
#define DF_CMD_ADDITIONAL_FRAME   0xAF
#define DF_CMD_GET_APP_IDS        0x6A
#define DF_CMD_GET_DF_NAMES       0x6D
#define DF_CMD_GET_FREE_MEM       0x6E
#define DF_CMD_SELECT_APP         0x5A
#define DF_CMD_GET_FILE_IDS       0x6F
#define DF_CMD_GET_FILE_SETTINGS  0xF5
#define DF_CMD_GET_KEY_SETTINGS   0x45
#define DF_CMD_AUTH_DES           0x0A   // D40 legacy DES / 2K3DES
#define DF_CMD_AUTH_ISO           0x1A   // ISO 3DES / 3K3DES
#define DF_CMD_AUTH_AES           0xAA   // AES-128

typedef enum { DF_KEY_DES, DF_KEY_2K3DES, DF_KEY_AES } DfKeyType;

// ---------------------------------------------------------------------
//  Envoi d'une commande native brute -> renvoie le statut (>=0),
//  remplit resp/resp_len (payload APRÈS l'octet de statut). -1 = pas de rép.
// ---------------------------------------------------------------------
static int df_raw(const uint8_t* frame, int flen, uint8_t* resp, int* resp_len, int timeout_ms) {
    int rx = 0;
    uint8_t* r = nfc_transceive_apdu(frame, flen, &rx, timeout_ms);
    if (!r || rx < 1) { if (resp_len) *resp_len = 0; return -1; }
    int st = r[0];
    int n  = rx - 1;
    if (n > 0 && resp) memcpy(resp, r + 1, n);
    if (resp_len) *resp_len = n;
    return st;
}

// ---------------------------------------------------------------------
//  Commande + data, puis boucle les frames 0xAF (assemble tout le payload).
//  out doit pouvoir contenir jusqu'à ~512 o. Renvoie le statut FINAL.
// ---------------------------------------------------------------------
static int df_cmd(uint8_t cmd, const uint8_t* data, int dlen,
                  uint8_t* out, int* out_len, int timeout_ms) {
    uint8_t frame[64];
    frame[0] = cmd;
    if (dlen < 0) dlen = 0;
    if (dlen > 60) dlen = 60;
    if (dlen && data) memcpy(frame + 1, data, dlen);

    uint8_t buf[256]; int blen = 0, total = 0;
    int st = df_raw(frame, 1 + dlen, buf, &blen, timeout_ms);
    if (st < 0) { if (out_len) *out_len = 0; return -1; }
    if (blen > 0 && out) { memcpy(out, buf, blen); total = blen; }

    int guard = 0;
    while (st == DF_ST_ADDITIONAL && guard++ < 16) {
        uint8_t af = DF_CMD_ADDITIONAL_FRAME;
        st = df_raw(&af, 1, buf, &blen, timeout_ms);
        if (st < 0) break;
        if (blen > 0 && out && total + blen <= 512) { memcpy(out + total, buf, blen); total += blen; }
    }
    if (out_len) *out_len = total;
    return st;
}

// ---- helpers énumération ----
static inline int df_select_app(const uint8_t aid[3]) {
    uint8_t out[8]; int ol = 0;
    return df_cmd(DF_CMD_SELECT_APP, aid, 3, out, &ol, 200);
}
// GET_VERSION -> 28 octets (7 HW + 7 SW + 14 UID/batch/prod). Renvoie longueur.
static inline int df_get_version(uint8_t* out28) {
    int ol = 0; int st = df_cmd(DF_CMD_GET_VERSION, NULL, 0, out28, &ol, 300);
    return (st == DF_ST_OK) ? ol : -1;
}
// GET_APPLICATION_IDS -> N*3 octets. Renvoie nombre d'AIDs (>=0) ou -1.
static inline int df_get_app_ids(uint8_t* out, int out_cap) {
    int ol = 0; int st = df_cmd(DF_CMD_GET_APP_IDS, NULL, 0, out, &ol, 300);
    if (st != DF_ST_OK) return -1;
    if (ol > out_cap) ol = out_cap;
    return ol / 3;
}
// GET_FILE_IDS -> N octets. Renvoie nombre de fichiers.
static inline int df_get_file_ids(uint8_t* out, int out_cap) {
    int ol = 0; int st = df_cmd(DF_CMD_GET_FILE_IDS, NULL, 0, out, &ol, 300);
    if (st != DF_ST_OK) return -1;
    if (ol > out_cap) ol = out_cap;
    return ol;
}
// GET_FILE_SETTINGS(fid) -> settings. Renvoie longueur.
static inline int df_get_file_settings(uint8_t fid, uint8_t* out, int out_cap) {
    int ol = 0; int st = df_cmd(DF_CMD_GET_FILE_SETTINGS, &fid, 1, out, &ol, 200);
    if (st != DF_ST_OK) return -1;
    if (ol > out_cap) ol = out_cap;
    return ol;
}

// ---- Lecture du CONTENU des fichiers (necessite les droits d'acces adequats,
//      ex. apres df_auth_* ; les fichiers "free read" passent sans auth). --------
#define DF_CMD_READ_DATA     0xBD   // fichiers data (standard/backup)
#define DF_CMD_GET_VALUE     0x6C   // fichiers value
#define DF_CMD_READ_RECORDS  0xBB   // fichiers record (linear/cyclic)

// Lit jusqu'a 'length' octets d'un fichier data. offset/length sur 3 octets LE.
// Retourne le nb d'octets lus (<0 si erreur/permission refusee).
static inline int df_read_data(uint8_t fid, uint32_t offset, uint32_t length, uint8_t* out, int out_cap) {
    uint8_t p[7];
    p[0] = fid;
    p[1] = offset & 0xFF; p[2] = (offset >> 8) & 0xFF; p[3] = (offset >> 16) & 0xFF;
    p[4] = length & 0xFF; p[5] = (length >> 8) & 0xFF; p[6] = (length >> 16) & 0xFF;
    int ol = 0; int st = df_cmd(DF_CMD_READ_DATA, p, 7, out, &ol, 500);
    if (st != DF_ST_OK) return -1;
    if (ol > out_cap) ol = out_cap;
    return ol;
}
// Lit la valeur (int32 LE) d'un fichier value.
static inline int df_get_value(uint8_t fid, int32_t* val) {
    uint8_t out[8]; int ol = 0;
    int st = df_cmd(DF_CMD_GET_VALUE, &fid, 1, out, &ol, 300);
    if (st != DF_ST_OK || ol < 4) return -1;
    *val = (int32_t)((uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                     ((uint32_t)out[2] << 16) | ((uint32_t)out[3] << 24));
    return 0;
}
// Lit 'num' records d'un fichier record (recsize connu via GET_FILE_SETTINGS).
// offset/num sur 3 octets LE. Retourne le nb d'octets lus.
static inline int df_read_records(uint8_t fid, uint32_t offset, uint32_t num, uint8_t* out, int out_cap) {
    uint8_t p[7];
    p[0] = fid;
    p[1] = offset & 0xFF; p[2] = (offset >> 8) & 0xFF; p[3] = (offset >> 16) & 0xFF;
    p[4] = num & 0xFF; p[5] = (num >> 8) & 0xFF; p[6] = (num >> 16) & 0xFF;
    int ol = 0; int st = df_cmd(DF_CMD_READ_RECORDS, p, 7, out, &ol, 500);
    if (st != DF_ST_OK) return -1;
    if (ol > out_cap) ol = out_cap;
    return ol;
}

// =====================================================================
//  CRYPTO  —  transformations pures (host-testables)
// =====================================================================
static inline void df_rotl1(const uint8_t* in, uint8_t* out, int n) {
    for (int i = 0; i < n - 1; i++) out[i] = in[i + 1];
    out[n - 1] = in[0];
}

// AES-128 CBC (mbedtls met à jour iv en place = dernier bloc chiffré/entrée)
static void df_aes_cbc(bool enc, const uint8_t key[16], uint8_t iv[16],
                       const uint8_t* in, uint8_t* out, int len) {
    mbedtls_aes_context c; mbedtls_aes_init(&c);
    if (enc) mbedtls_aes_setkey_enc(&c, key, 128);
    else     mbedtls_aes_setkey_dec(&c, key, 128);
    mbedtls_aes_crypt_cbc(&c, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                          len, iv, in, out);
    mbedtls_aes_free(&c);
}

// ---------------------------------------------------------------------
//  DES autonome (bit-array, non optimisé — appelé qques fois pour l'auth).
//  Tables standard FIPS 46-3. Validé host contre TripleDES de référence.
// ---------------------------------------------------------------------
static const uint8_t DES_IP[64] = {
  58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6,
  64,56,48,40,32,24,16,8, 57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7 };
static const uint8_t DES_FP[64] = {
  40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30,
  37,5,45,13,53,21,61,29, 36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25 };
static const uint8_t DES_E[48] = {
  32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
  16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1 };
static const uint8_t DES_P[32] = {
  16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25 };
static const uint8_t DES_PC1[56] = {
  57,49,41,33,25,17,9, 1,58,50,42,34,26,18, 10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
  63,55,47,39,31,23,15, 7,62,54,46,38,30,22, 14,6,61,53,45,37,29, 21,13,5,28,20,12,4 };
static const uint8_t DES_PC2[48] = {
  14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8, 16,7,27,20,13,2,
  41,52,31,37,47,55, 30,40,51,45,33,48, 44,49,39,56,34,53, 46,42,50,36,29,32 };
static const uint8_t DES_SHIFT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const uint8_t DES_S[8][64] = {
 {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
 {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
 {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
 {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
 {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
 {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
 {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
 {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} };

static void des_bytes_to_bits(const uint8_t* b, uint8_t* bits, int nbytes) {
    for (int i = 0; i < nbytes * 8; i++) bits[i] = (b[i >> 3] >> (7 - (i & 7))) & 1;
}
static void des_bits_to_bytes(const uint8_t* bits, uint8_t* b, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        uint8_t v = 0; for (int j = 0; j < 8; j++) v = (v << 1) | bits[i*8+j];
        b[i] = v;
    }
}
static void des_permute(const uint8_t* in, const uint8_t* table, int n, uint8_t* out) {
    for (int i = 0; i < n; i++) out[i] = in[table[i] - 1];
}
// key[8] -> 16 sous-clés de 48 bits (bit-array)
static void des_keyschedule(const uint8_t key[8], uint8_t sub[16][48]) {
    uint8_t kb[64], pc1[56]; des_bytes_to_bits(key, kb, 8);
    des_permute(kb, DES_PC1, 56, pc1);
    uint8_t C[28], D[28]; memcpy(C, pc1, 28); memcpy(D, pc1 + 28, 28);
    for (int r = 0; r < 16; r++) {
        for (int s = 0; s < DES_SHIFT[r]; s++) {
            uint8_t t = C[0]; for (int i = 0; i < 27; i++) C[i] = C[i+1]; C[27] = t;
            t = D[0]; for (int i = 0; i < 27; i++) D[i] = D[i+1]; D[27] = t;
        }
        uint8_t cd[56]; memcpy(cd, C, 28); memcpy(cd + 28, D, 28);
        des_permute(cd, DES_PC2, 48, sub[r]);
    }
}
// bloc 8 o, decrypt=1 => sous-clés inversées
static void des_crypt(const uint8_t in[8], uint8_t sub[16][48], int decrypt, uint8_t out[8]) {
    uint8_t bits[64], ip[64]; des_bytes_to_bits(in, bits, 8);
    des_permute(bits, DES_IP, 64, ip);
    uint8_t L[32], R[32]; memcpy(L, ip, 32); memcpy(R, ip + 32, 32);
    for (int r = 0; r < 16; r++) {
        const uint8_t* K = sub[decrypt ? (15 - r) : r];
        uint8_t er[48]; des_permute(R, DES_E, 48, er);
        for (int i = 0; i < 48; i++) er[i] ^= K[i];
        uint8_t sout[32];
        for (int box = 0; box < 8; box++) {
            const uint8_t* b = er + box*6;
            int row = (b[0] << 1) | b[5];
            int col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4];
            int v = DES_S[box][row*16 + col];
            sout[box*4+0] = (v >> 3) & 1; sout[box*4+1] = (v >> 2) & 1;
            sout[box*4+2] = (v >> 1) & 1; sout[box*4+3] = v & 1;
        }
        uint8_t pf[32]; des_permute(sout, DES_P, 32, pf);
        uint8_t newR[32];
        for (int i = 0; i < 32; i++) newR[i] = L[i] ^ pf[i];
        memcpy(L, R, 32); memcpy(R, newR, 32);
    }
    uint8_t pre[64]; memcpy(pre, R, 32); memcpy(pre + 32, L, 32); // R16 L16
    uint8_t fp[64]; des_permute(pre, DES_FP, 64, fp);
    des_bits_to_bytes(fp, out, 8);
}

// DESFire "legacy" (D40) : la couche PCD utilise le DÉCHIFFREMENT DES dans
// les DEUX sens (convention libfreefare MCD_SEND/RECEIVE = decipher).
// CBC "à la DESFire" : bloc ^= iv ; decrypt ; iv = résultat (texte clair).
// key 8 o = single DES ; key 16 o = 2K3DES (K1,K2,K1) decrypt EDE.
static void df_des_block_decrypt(const uint8_t* key, int keylen, const uint8_t in[8], uint8_t out[8]) {
    if (keylen == 8) {
        uint8_t sub[16][48]; des_keyschedule(key, sub);
        des_crypt(in, sub, 1, out);
    } else { // 2K3DES decrypt : D_K1( E_K2( D_K1(in) ) )
        uint8_t s1[16][48], s2[16][48];
        des_keyschedule(key, s1); des_keyschedule(key + 8, s2);
        uint8_t t1[8], t2[8];
        des_crypt(in, s1, 1, t1);
        des_crypt(t1, s2, 0, t2);
        des_crypt(t2, s1, 1, out);
    }
}
// CBC decipher chaîné "DESFire legacy" (send & receive) : voir ci-dessus.
static void df_des_cbc_dec(const uint8_t* key, int keylen, uint8_t iv[8],
                           const uint8_t* in, uint8_t* out, int len) {
    for (int off = 0; off < len; off += 8) {
        uint8_t tmp[8];
        df_des_block_decrypt(key, keylen, in + off, tmp);
        for (int i = 0; i < 8; i++) out[off + i] = tmp[i] ^ iv[i];
        memcpy(iv, in + off, 8);   // iv = dernier bloc chiffré reçu/émis
    }
}

// ---------------------------------------------------------------------
//  Étape crypto AES pure (testable host) :
//   enc_rndb (16, du carte) + key + rnda(16) -> token(32) à renvoyer,
//   et exp_enc_rnda_rot' attendu pour vérifier la réponse carte.
//   iv_after = dernier bloc chiffré du token (pour déchiffrer la réponse).
// ---------------------------------------------------------------------
static void df_aes_build_token(const uint8_t key[16], const uint8_t enc_rndb[16],
                               const uint8_t rnda[16], uint8_t token_out[32],
                               uint8_t rndb_out[16]) {
    uint8_t iv[16]; memset(iv, 0, 16);
    uint8_t rndb[16];
    df_aes_cbc(false, key, iv, enc_rndb, rndb, 16);   // decrypt, iv <- enc_rndb
    uint8_t rndb_rot[16]; df_rotl1(rndb, rndb_rot, 16);
    uint8_t plain[32]; memcpy(plain, rnda, 16); memcpy(plain + 16, rndb_rot, 16);
    // iv reste = enc_rndb (chaînage CBC continu) -> chiffre le token
    df_aes_cbc(true, key, iv, plain, token_out, 32);  // iv <- dernier bloc token
    if (rndb_out) memcpy(rndb_out, rndb, 16);
}

// =====================================================================
//  AUTHENTIFICATIONS (device : parlent à la vraie carte via df_cmd/df_raw)
//  Renvoie true si mutuellement authentifié. session_key optionnel (16 o AES).
// =====================================================================
extern "C" uint32_t esp_random(void);
static inline uint32_t df_rand32() { return esp_random(); }

static bool df_auth_aes(uint8_t keyno, const uint8_t key[16], uint8_t* session_key_out) {
    uint8_t p = keyno;
    uint8_t buf[64]; int bl = 0;
    uint8_t init[2] = { DF_CMD_AUTH_AES, keyno };
    int st = df_raw(init, 2, buf, &bl, 400);
    if (st != DF_ST_ADDITIONAL || bl < 16) return false;
    uint8_t enc_rndb[16]; memcpy(enc_rndb, buf, 16);

    uint8_t rnda[16];
    for (int i = 0; i < 16; i += 4) { uint32_t r = df_rand32(); memcpy(rnda + i, &r, 4); }

    uint8_t token[32], rndb[16];
    df_aes_build_token(key, enc_rndb, rnda, token, rndb);

    // frame = 0xAF + token(32)
    uint8_t frame[33]; frame[0] = DF_CMD_ADDITIONAL_FRAME; memcpy(frame + 1, token, 32);
    uint8_t resp[64]; int rl = 0;
    st = df_raw(frame, 33, resp, &rl, 400);
    if (st != DF_ST_OK || rl < 16) return false;

    // déchiffre enc(rotl(RndA)) : IV = dernier bloc chiffré du token
    uint8_t iv[16]; memcpy(iv, token + 16, 16);
    uint8_t rnda_rot_card[16];
    df_aes_cbc(false, key, iv, resp, rnda_rot_card, 16);
    uint8_t rnda_rot[16]; df_rotl1(rnda, rnda_rot, 16);
    if (memcmp(rnda_rot_card, rnda_rot, 16) != 0) return false;

    if (session_key_out) { // AES: RndA[0..3]|RndB[0..3]|RndA[12..15]|RndB[12..15]
        memcpy(session_key_out + 0,  rnda + 0,  4);
        memcpy(session_key_out + 4,  rndb + 0,  4);
        memcpy(session_key_out + 8,  rnda + 12, 4);
        memcpy(session_key_out + 12, rndb + 12, 4);
    }
    (void)p;
    return true;
}

// DES (D40 legacy 0x0A) et 2K3DES via même flux, 8 octets de challenge.
static bool df_auth_des(uint8_t keyno, const uint8_t* key, int keylen /*8 ou 16*/) {
    uint8_t buf[32]; int bl = 0;
    uint8_t init[2] = { DF_CMD_AUTH_DES, keyno };
    int st = df_raw(init, 2, buf, &bl, 400);
    if (st != DF_ST_ADDITIONAL || bl < 8) return false;
    uint8_t enc_rndb[8]; memcpy(enc_rndb, buf, 8);

    uint8_t iv[8]; memset(iv, 0, 8);
    uint8_t rndb[8];
    df_des_cbc_dec(key, keylen, iv, enc_rndb, rndb, 8);   // iv <- enc_rndb
    uint8_t rndb_rot[8]; df_rotl1(rndb, rndb_rot, 8);

    uint8_t rnda[8];
    for (int i = 0; i < 8; i += 4) { uint32_t r = df_rand32(); memcpy(rnda + i, &r, 4); }

    // token = decipher-CBC( RndA || RndB' ) avec chaînage legacy (iv = enc_rndb)
    uint8_t plain[16]; memcpy(plain, rnda, 8); memcpy(plain + 8, rndb_rot, 8);
    uint8_t token[16];
    df_des_cbc_dec(key, keylen, iv, plain, token, 16);

    uint8_t frame[17]; frame[0] = DF_CMD_ADDITIONAL_FRAME; memcpy(frame + 1, token, 16);
    uint8_t resp[32]; int rl = 0;
    st = df_raw(frame, 17, resp, &rl, 400);
    if (st != DF_ST_OK || rl < 8) return false;

    uint8_t iv2[8]; memcpy(iv2, token + 8, 8);   // dernier bloc chiffré émis
    uint8_t rnda_rot_card[8];
    df_des_cbc_dec(key, keylen, iv2, resp, rnda_rot_card, 8);
    uint8_t rnda_rot[8]; df_rotl1(rnda, rnda_rot, 8);
    return memcmp(rnda_rot_card, rnda_rot, 8) == 0;
}

// ---- dictionnaire de clés (zéro + SD /evil/nfc/desfire_keys.txt) ----
// La lecture SD réelle est câblée dans le .ino (accès FS) ; ici on expose
// juste la clé "usine" tout-à-zéro comme premier essai.
static const uint8_t DF_KEY_ZERO16[16] = {0};
static const uint8_t DF_KEY_ZERO8[8]   = {0};

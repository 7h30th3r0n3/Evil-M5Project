// ============================================================================
//  garage_brute.h — Brute-force codes FIXES de garages (De Bruijn / DIP)
// ----------------------------------------------------------------------------
//  Portage de l'algorithme OpenSesame de Samy Kamkar (samyk/opensesame :
//  garages.h + rf.c) + confirmation des timings par les .sub CC1101 du firmware
//  EvilCrowRF (h-RAT). Protocoles a CODE FIXE (Linear/Stanley Multicode,
//  Chamberlain, Linear MooreMatic) — PAS du rolling code, PAS du jamming :
//  on emet tous les codes possibles sur SON PROPRE garage.
//
//  Encodage commun (verbatim garages.h : baud=2000 -> Te=500us, len=4, b0=0x8,
//  b1=0xe, MSB-first) : OOK PWM, chaque bit protocole = 1 mot de 2000us :
//    bit 0 = "1000" = 500us HIGH + 1500us LOW   -> impulsions {+500, -1500}
//    bit 1 = "1110" = 1500us HIGH + 500us LOW   -> impulsions {+1500, -500}
//  De Bruijn : sequence B(2,n) de longueur 2^n + (n-1), emise en continu SANS
//  gap -> toute fenetre de n bits = un code distinct -> les 2^n codes en ~2^n
//  symboles (au lieu de 2^n trames). 10b~2.07s, 9b~1.04s, 8b~0.53s / passe.
// ============================================================================
#ifndef GARAGE_BRUTE_H
#define GARAGE_BRUTE_H

#include <string.h>
#include <stdint.h>

// Un protocole garage : nom, nb de bits, frequence par defaut (Hz).
struct GarageProto { const char* name; uint8_t bits; uint32_t def_hz; };

// Liste alignee sur OpenSesame/EvilCrowRF (freq canoniques ; modifiables via C).
static const GarageProto GARAGE_PROTOS[] = {
    { "Linear Multicode 10b", 10, 310000000 },
    { "Stanley Multicode 10b", 10, 310000000 },
    { "Chamberlain 9b (US)",    9, 390000000 },
    { "Chamberlain 9b (CA)",    9, 315000000 },
    { "Chamberlain 8b",         8, 390000000 },
    { "Chamberlain 7b",         7, 390000000 },
    { "Linear MooreMatic 8b",   8, 310000000 },
};
static const int GARAGE_PROTO_COUNT = (int)(sizeof(GARAGE_PROTOS) / sizeof(GARAGE_PROTOS[0]));

// Frequences selectionnables (Hz) — union des sets Willy/EvilCrowRF.
static const uint32_t GARAGE_FREQS[] = {
    300000000, 310000000, 315000000, 390000000, 433920000, 868350000
};
static const int GARAGE_FREQ_COUNT = (int)(sizeof(GARAGE_FREQS) / sizeof(GARAGE_FREQS[0]));

// ---- Generateur De Bruijn B(2,n) (recursion FKM "prefer-larger", rf.c db()) ----
struct GbDbState { uint8_t a[16]; uint8_t* seq; int s; int n; };
static void gb_db(GbDbState* st, int t, int p) {
    if (t > st->n) {
        if (st->n % p == 0)
            for (int j = 1; j <= p; j++) st->seq[st->s++] = st->a[j];
    } else {
        st->a[t] = st->a[t - p];
        gb_db(st, t + 1, p);
        for (int j = st->a[t - p] + 1; j <= 1; j++) { st->a[t] = (uint8_t)j; gb_db(st, t + 1, t); }
    }
}
// Remplit seq[] (1 octet/bit, 0/1), longueur retournee = 2^n + (n-1). seq doit
// avoir au moins (2^n + n) octets. n <= 10.
static int gb_debruijn(int n, uint8_t* seq) {
    GbDbState st; memset(st.a, 0, sizeof(st.a)); st.seq = seq; st.s = 0; st.n = n;
    gb_db(&st, 1, 1);
    for (int i = 0; i < n - 1; i++) seq[st.s++] = 0;   // complete le "wrap"
    return st.s;
}

// ---- Conversion bits -> impulsions OOK (Te=500us) ----
// De Bruijn : flux continu. Retourne le nb d'int32 ecrits (= 2*len). cap >= 2*len.
static int gb_bits_to_pulses(const uint8_t* seq, int len, int32_t* pulses, int cap) {
    int k = 0;
    for (int i = 0; i < len && k + 2 <= cap; i++) {
        if (seq[i]) { pulses[k++] = 1500; pulses[k++] = -500; }   // bit1 = 1110
        else        { pulses[k++] = 500;  pulses[k++] = -1500; }  // bit0 = 1000
    }
    return k;
}
// Un code n-bits (MSB-first) -> impulsions (mode DIP frame-par-frame).
static int gb_code_to_pulses(uint32_t code, int n, int32_t* pulses, int cap) {
    int k = 0;
    for (int b = n - 1; b >= 0 && k + 2 <= cap; b--) {
        if ((code >> b) & 1) { pulses[k++] = 1500; pulses[k++] = -500; }
        else                 { pulses[k++] = 500;  pulses[k++] = -1500; }
    }
    return k;
}

#endif // GARAGE_BRUTE_H

// mfkey.h
// -----------------------------------------------------------------------------
// Self-contained, host-testable MIFARE Classic (Crypto1) key recovery.
//
// Implements the classic "mfkey32" known-plaintext attack (Nohl / Ploetz),
// as found in the public crapto1 library and the Proxmark tools
// (lfsr_recovery32 + mfkey32). Given two authentication traces captured on the
// SAME sector/key, it recovers the 48-bit Crypto1 key.
//
// This is a well-documented, public algorithm used for authorized
// access-control auditing.
//
// SELF-CONTAINED: the only dependencies are <cstdint>, <cstring>, <vector>.
//
// NAMING: every global-ish symbol is prefixed with mfk_ (functions) or MFK_
// (constants / macros) so this header can be #included into firmware that
// already defines its own Crypto1 (c1_filter, Crypto1State, c1_init, c1_bit, ...)
// without any ODR / name collision.
//
// Everything is `static inline` so it can be pulled into an Arduino .ino later.
// -----------------------------------------------------------------------------
#ifndef MFK_MFKEY_H
#define MFK_MFKEY_H

#include <cstdint>
#include <cstring>
#include <vector>

// -----------------------------------------------------------------------------
// Bit helpers
// -----------------------------------------------------------------------------
#define MFK_BIT(x, n)   (uint32_t)(((x) >> (n)) & 1)
#define MFK_BEBIT(x, n) MFK_BIT((x), (n) ^ 24)

// Crypto1 LFSR feedback polynomial, split across the odd / even sub-registers
// (canonical crapto1 constants).
static const uint32_t MFK_LF_POLY_ODD  = 0x29CE5C;
static const uint32_t MFK_LF_POLY_EVEN = 0x870804;

// Even parity of a 32-bit word (1 if an odd number of set bits).
static inline uint32_t mfk_parity(uint32_t x) {
    return (uint32_t)__builtin_parity(x);
}

// -----------------------------------------------------------------------------
// The 20-bit Crypto1 filter function f(x)  (standard crapto1 implementation)
// -----------------------------------------------------------------------------
static inline int mfk_filter(uint32_t x) {
    uint32_t f;
    f  = 0xf22c0u >> (x        & 0xf) & 16;
    f |= 0x6c9c0u >> (x >>  4  & 0xf) &  8;
    f |= 0x3c8b0u >> (x >>  8  & 0xf) &  4;
    f |= 0x1e458u >> (x >> 12  & 0xf) &  2;
    f |= 0x0d938u >> (x >> 16  & 0xf) &  1;
    return (int)MFK_BIT(0xEC57E80Au, f);
}

// -----------------------------------------------------------------------------
// Crypto1 cipher state (48-bit LFSR, odd/even split into two 24-bit halves)
// -----------------------------------------------------------------------------
struct mfk_State {
    uint32_t odd;
    uint32_t even;
};

// Load a 48-bit key into the LFSR (identical bit ordering to crapto1).
static inline void mfk_crypto1_init(mfk_State* s, uint64_t key) {
    s->odd  = 0;
    s->even = 0;
    for (int i = 47; i > 0; i -= 2) {
        s->odd  = (s->odd  << 1) | MFK_BIT(key, (i - 1) ^ 7);
        s->even = (s->even << 1) | MFK_BIT(key, i ^ 7);
    }
}

// Clock the cipher one bit.
//   in            : the bit fed into the LFSR (plaintext, or ciphertext if encrypted)
//   is_encrypted  : if non-zero, the keystream bit is also fed back (encrypted feed)
// Returns the keystream bit.
static inline uint8_t mfk_crypto1_bit(mfk_State* s, uint8_t in, int is_encrypted) {
    uint8_t  ret    = (uint8_t)mfk_filter(s->odd);
    uint32_t feedin = (uint32_t)(ret & (is_encrypted ? 1 : 0));
    feedin ^= (in ? 1u : 0u);
    feedin ^= MFK_LF_POLY_ODD  & s->odd;
    feedin ^= MFK_LF_POLY_EVEN & s->even;
    s->even = (s->even << 1) | mfk_parity(feedin);
    uint32_t t = s->odd; s->odd = s->even; s->even = t;   // swap halves
    return ret;
}

// Clock the cipher one 32-bit word (big-endian bit order, as on the wire).
static inline uint32_t mfk_crypto1_word(mfk_State* s, uint32_t in, int is_encrypted) {
    uint32_t ret = 0;
    for (int i = 0; i < 32; i++)
        ret |= (uint32_t)mfk_crypto1_bit(s, (uint8_t)MFK_BEBIT(in, i), is_encrypted) << (24 ^ i);
    return ret;
}

// Roll the cipher back one bit (inverse of mfk_crypto1_bit).
static inline uint8_t mfk_lfsr_rollback_bit(mfk_State* s, uint32_t in, int fb) {
    uint8_t  ret;
    uint32_t out;

    s->odd &= 0xffffff;
    uint32_t t = s->odd; s->odd = s->even; s->even = t;   // un-swap halves

    out  = s->even & 1;
    s->even >>= 1;
    out ^= MFK_LF_POLY_EVEN & s->even;
    out ^= MFK_LF_POLY_ODD  & s->odd;
    out ^= (in ? 1u : 0u);
    ret  = (uint8_t)mfk_filter(s->odd);
    out ^= (uint32_t)(ret & (fb ? 1 : 0));

    s->even |= mfk_parity(out) << 23;
    return ret;
}

// Roll the cipher back one 32-bit word.
static inline uint32_t mfk_lfsr_rollback_word(mfk_State* s, uint32_t in, int fb) {
    uint32_t ret = 0;
    for (int i = 31; i >= 0; --i)
        ret |= (uint32_t)mfk_lfsr_rollback_bit(s, MFK_BEBIT(in, i), fb) << (24 ^ i);
    return ret;
}

// Extract the 48-bit LFSR value from an odd/even split state.
static inline void mfk_crypto1_get_lfsr(const mfk_State* s, uint64_t* lfsr) {
    uint64_t l = 0;
    for (int i = 23; i >= 0; --i) {
        l = (l << 1) | (uint64_t)MFK_BIT(s->odd,  i ^ 3);
        l = (l << 1) | (uint64_t)MFK_BIT(s->even, i ^ 3);
    }
    *lfsr = l;
}

// -----------------------------------------------------------------------------
// The 16-bit MIFARE PRNG successor (nested-nonce prediction).
//   prng_successor(x, 64) == suc2(x), used to derive the reader/tag answers.
// -----------------------------------------------------------------------------
static inline uint32_t mfk_swapendian(uint32_t x) {
    x = (x >> 8 & 0xff00ffu) | (x & 0xff00ffu) << 8;
    x = (x >> 16) | (x << 16);
    return x;
}
static inline uint32_t mfk_prng_successor(uint32_t x, uint32_t n) {
    x = mfk_swapendian(x);
    while (n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    return mfk_swapendian(x);
}

// -----------------------------------------------------------------------------
// lfsr_recovery32 : rollback-based state recovery
//
// Given 32 bits of keystream (ks2) produced by an autonomous Crypto1 LFSR
// (in == 0 for the mfkey32 use-case), enumerate every 48-bit cipher state that
// produces exactly that keystream. Uses the canonical crapto1 approach:
//   * split ks2 into its odd- and even-clocked keystream bits,
//   * build all 20-bit sub-states matching the first keystream bit,
//   * grow them 4 bits with the simple table extender,
//   * finish with the contribution-carrying extender + bucket intersection
//     join (odd x even), which enforces the LFSR feedback coupling.
// -----------------------------------------------------------------------------

// Fold the two feedback-parity "contribution" bits into the top byte of the
// word, keeping the 24-bit sub-state in the low bits.
static inline void mfk_update_contribution(uint32_t& item, uint32_t m1, uint32_t m2) {
    uint32_t p = item >> 25;
    p = (p << 1) | mfk_parity(item & m1);
    p = (p << 1) | mfk_parity(item & m2);
    item = (p << 24) | (item & 0xffffff);
}

// Extend a candidate list by one clock, keeping only states whose filter output
// matches `bit`. Simple variant (no contribution tracking; sub-state < 24 bits).
static inline void mfk_extend_table_simple(std::vector<uint32_t>& tbl, int bit) {
    std::vector<uint32_t> out;
    out.reserve(tbl.size() + 64);
    for (uint32_t s : tbl) {
        uint32_t s0 = s << 1;
        int f0 = mfk_filter(s0);
        int f1 = mfk_filter(s0 | 1);
        if (f0 ^ f1) {
            out.push_back(s0 | (uint32_t)(f0 ^ bit));
        } else if (f0 == bit) {
            out.push_back(s0);
            out.push_back(s0 | 1);
        }
    }
    tbl.swap(out);
}

// Extend a candidate list by one clock, carrying the feedback contribution in
// the top byte so odd/even lists can later be intersected.
static inline void mfk_extend_table(std::vector<uint32_t>& tbl, int bit,
                                    uint32_t m1, uint32_t m2, uint32_t in) {
    uint32_t inh = in << 24;
    std::vector<uint32_t> out;
    out.reserve(tbl.size() + 64);
    for (uint32_t s : tbl) {
        uint32_t s0 = s << 1;
        int f0 = mfk_filter(s0);
        int f1 = mfk_filter(s0 | 1);
        if (f0 ^ f1) {
            uint32_t x = s0 | (uint32_t)(f0 ^ bit);
            mfk_update_contribution(x, m1, m2);
            x ^= inh;
            out.push_back(x);
        } else if (f0 == bit) {
            uint32_t a = s0;
            mfk_update_contribution(a, m1, m2);
            a ^= inh;
            out.push_back(a);
            uint32_t b = s0 | 1;
            mfk_update_contribution(b, m1, m2);
            b ^= inh;
            out.push_back(b);
        }
    }
    tbl.swap(out);
}

// Recursive join: extend odd/even 4 clocks at a time, intersect on the 8-bit
// contribution byte, recurse per surviving bucket; emit full states at the end.
static inline void mfk_recover(std::vector<uint32_t> odd, std::vector<uint32_t> even,
                               uint32_t oks, uint32_t eks, int rem,
                               uint32_t in, std::vector<mfk_State>& out) {
    if (rem == -1) {
        for (uint32_t e : even) {
            uint32_t ea = (e << 1)
                        ^ mfk_parity(e & MFK_LF_POLY_EVEN)
                        ^ (uint32_t)((in >> 2) & 1);
            for (uint32_t o : odd) {
                mfk_State st;
                st.even = o & 0xffffff;
                st.odd  = (ea ^ mfk_parity(o & MFK_LF_POLY_ODD)) & 0xffffff;
                out.push_back(st);
            }
        }
        return;
    }

    // Replicates the crapto1 `for(i = 0; i < 4 && rem--; i++)` semantics exactly,
    // decrementing `rem` as part of the loop condition.
    int localrem = rem;
    for (int i = 0; i < 4; i++) {
        int old = localrem;
        localrem--;
        if (old == 0) break;   // rem-- evaluated to 0 -> loop stops (rem now -1)

        oks >>= 1;
        eks >>= 1;
        in  >>= 2;
        mfk_extend_table(odd,  oks & 1, MFK_LF_POLY_EVEN << 1 | 1, MFK_LF_POLY_ODD << 1, 0);
        if (odd.empty())  return;
        mfk_extend_table(even, eks & 1, MFK_LF_POLY_ODD,       MFK_LF_POLY_EVEN << 1 | 1, in & 3);
        if (even.empty()) return;
    }

    // Bucket-sort intersection on the contribution byte.
    std::vector<uint32_t> obk[256], ebk[256];
    for (uint32_t x : odd)  obk[(x >> 24) & 0xff].push_back(x);
    for (uint32_t x : even) ebk[(x >> 24) & 0xff].push_back(x);
    for (int b = 0; b < 256; b++) {
        if (!obk[b].empty() && !ebk[b].empty())
            mfk_recover(obk[b], ebk[b], oks, eks, localrem, in, out);
    }
}

static inline std::vector<mfk_State> mfk_lfsr_recovery32(uint32_t ks2, uint32_t in) {
    std::vector<mfk_State> out;

    uint32_t oks = 0, eks = 0;
    for (int i = 31; i >= 0; i -= 2) oks = (oks << 1) | MFK_BEBIT(ks2, i);
    for (int i = 30; i >= 0; i -= 2) eks = (eks << 1) | MFK_BEBIT(ks2, i);

    std::vector<uint32_t> odd, even;
    odd.reserve(1u << 19);
    even.reserve(1u << 19);
    for (uint32_t i = 0; i < (1u << 20); i++) {
        if ((uint32_t)mfk_filter(i) == (oks & 1)) odd.push_back(i);
        if ((uint32_t)mfk_filter(i) == (eks & 1)) even.push_back(i);
    }

    for (int i = 0; i < 4; i++) {
        mfk_extend_table_simple(odd,  (oks >>= 1) & 1);
        mfk_extend_table_simple(even, (eks >>= 1) & 1);
    }

    mfk_recover(odd, even, oks, eks, 11, in << 1, out);
    return out;
}

// -----------------------------------------------------------------------------
// mfkey32 : recover the key from two auths on the same sector/key.
//
//   uid            : card UID
//   nt0, nr0, ar0  : first  trace (tag nonce, encrypted reader nonce, encrypted aR)
//   nt1, nr1, ar1  : second trace
//   out_key        : receives the recovered 48-bit key on success
// Returns true iff a unique key was recovered.
// -----------------------------------------------------------------------------
static inline bool mfk_mfkey32(uint32_t uid,
                               uint32_t nt0, uint32_t nr0, uint32_t ar0,
                               uint32_t nt1, uint32_t nr1, uint32_t ar1,
                               uint64_t* out_key) {
    uint32_t p64  = mfk_prng_successor(nt0, 64);
    uint32_t p64b = mfk_prng_successor(nt1, 64);
    uint32_t ks2  = ar0 ^ p64;

    std::vector<mfk_State> states = mfk_lfsr_recovery32(ks2, 0);

    for (mfk_State st : states) {
        mfk_State t = st;
        mfk_lfsr_rollback_word(&t, 0,          0);   // undo the aR keystream word
        mfk_lfsr_rollback_word(&t, nr0,        1);   // undo the encrypted reader nonce
        mfk_lfsr_rollback_word(&t, uid ^ nt0,  0);   // undo the uid^nt feed

        uint64_t key;
        mfk_crypto1_get_lfsr(&t, &key);

        // Confirm the candidate against the second trace.
        mfk_State v;
        mfk_crypto1_init(&v, key);
        mfk_crypto1_word(&v, uid ^ nt1, 0);
        mfk_crypto1_word(&v, nr1, 1);
        uint32_t ks2b = mfk_crypto1_word(&v, 0, 0);
        if (ar1 == (ks2b ^ p64b)) {
            if (out_key) *out_key = key;
            return true;
        }
    }
    return false;
}

#endif // MFK_MFKEY_H

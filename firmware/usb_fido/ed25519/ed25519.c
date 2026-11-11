#include "ed25519.h"
#include "sha512/sha512.h"
#include <string.h>
#include <stdbool.h>

/* ==================== TweetNaCl Curve25519 / Ed25519 Field & Group Core ==================== */
typedef int64_t gf[16];

#define FOR(i,n) for (int i = 0; i < (n); ++i)
#define sv static void

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                      0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                     0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};

static inline void set25519(gf r, const gf a) {
    FOR(i, 16) r[i] = a[i];
}

static inline void car25519(gf o) {
    int64_t c;
    FOR(i, 16) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static inline void sel25519(gf p, gf q, int b) {
    int64_t t, c = ~(int64_t)(b - 1);
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

sv pack25519(uint8_t *o, const gf n) {
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        m[14] &= 0xffff;
        int b = (m[15] >> 16) & 1;
        b ^= 1;
        sel25519(t, m, b);
    }
    FOR(i, 16) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static inline uint8_t par25519(const gf a) {
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static inline void A(gf o, const gf a, const gf b) {
    FOR(i, 16) o[i] = a[i] + b[i];
}

static inline void Z(gf o, const gf a, const gf b) {
    FOR(i, 16) o[i] = a[i] - b[i];
}

sv M(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    FOR(i, 16) {
        FOR(j, 16) {
            t[i + j] += a[i] * b[j];
        }
    }
    FOR(i, 15) {
        t[i] += 38 * t[i + 16];
    }
    FOR(i, 16) {
        o[i] = t[i];
    }
    car25519(o);
    car25519(o);
}

static inline void S(gf o, const gf a) {
    M(o, a, a);
}

sv inv25519(gf o, const gf i) {
    gf c;
    FOR(a, 16) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) {
            M(c, c, i);
        }
    }
    FOR(a, 16) o[a] = c[a];
}

sv cswap(gf p[4], gf q[4], uint8_t b) {
    FOR(i, 4) {
        sel25519(p[i], q[i], b);
    }
}

sv add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
        uint8_t b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const uint8_t *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

sv pack(uint8_t *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

/* ==================== Modular arithmetic modulo L ==================== */
static const uint64_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
};

static void modL(uint8_t *r, int64_t x[64]) {
    int64_t carry, j;
    for (int i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * L[j];
    for (int i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce(uint8_t *b) {
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = (uint64_t)b[i];
    for (int i = 0; i < 64; i++) b[i] = 0;
    modL(b, x);
}

/* ==================== Ed25519 Public API ==================== */

void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    uint8_t az[64];
    sha512(seed, 32, az);

    /* Clamp private scalar */
    az[0]  &= 248;
    az[31] &= 127;
    az[31] |= 64;

    gf p[4];
    scalarbase(p, az);
    pack(pk, p);

    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);
}

void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                  const uint8_t pk[32], const uint8_t sk[64]) {
    uint8_t az[64];
    sha512(sk, 32, az);
    az[0]  &= 248;
    az[31] &= 127;
    az[31] |= 64;

    /* r = SHA-512(az[32..63] || msg) */
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, az + 32, 32);
    sha512_update(&ctx, msg, msg_len);
    uint8_t nonce[64];
    sha512_final(&ctx, nonce);

    reduce(nonce);

    /* R = r * B */
    gf R[4];
    scalarbase(R, nonce);
    pack(sig, R);

    /* h = SHA-512(R || pk || msg) */
    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);
    sha512_update(&ctx, pk, 32);
    sha512_update(&ctx, msg, msg_len);
    uint8_t hram[64];
    sha512_final(&ctx, hram);

    reduce(hram);

    /* S = r + h * az mod L */
    int64_t x[64] = {0};
    for (int i = 0; i < 32; i++) x[i] = (uint64_t)nonce[i];
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            x[i + j] += (uint64_t)hram[i] * (uint64_t)az[j];
        }
    }
    modL(sig + 32, x);
}

void ed25519_sc_reduce32(uint8_t s[32]) {
    uint8_t tmp[64] = {0};
    memcpy(tmp, s, 32);
    reduce(tmp);
    memcpy(s, tmp, 32);
}

void ed25519_scalarmult_base(uint8_t out[32], const uint8_t scalar[32]) {
    gf P[4];
    scalarbase(P, scalar);
    pack(out, P);
}

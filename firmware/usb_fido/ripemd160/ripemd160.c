#include "ripemd160.h"
#include <string.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void ripemd160_process(ripemd160_ctx *ctx, const uint8_t data[64]) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++) {
        X[i] = ((uint32_t)data[i * 4]) |
               (((uint32_t)data[i * 4 + 1]) << 8) |
               (((uint32_t)data[i * 4 + 2]) << 16) |
               (((uint32_t)data[i * 4 + 3]) << 24);
    }

    uint32_t A = ctx->state[0], B = ctx->state[1], C = ctx->state[2], D = ctx->state[3], E = ctx->state[4];
    uint32_t Ap = A, Bp = B, Cp = C, Dp = D, Ep = E;

    /* Round 1 */
    #define F1(x, y, z) ((x) ^ (y) ^ (z))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F1((b), (c), (d)) + (x); \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(A, B, C, D, E, X[0], 11);  STEP(E, A, B, C, D, X[1], 14);
    STEP(D, E, A, B, C, X[2], 15);  STEP(C, D, E, A, B, X[3], 12);
    STEP(B, C, D, E, A, X[4], 5);   STEP(A, B, C, D, E, X[5], 8);
    STEP(E, A, B, C, D, X[6], 7);   STEP(D, E, A, B, C, X[7], 9);
    STEP(C, D, E, A, B, X[8], 11);  STEP(B, C, D, E, A, X[9], 13);
    STEP(A, B, C, D, E, X[10], 14); STEP(E, A, B, C, D, X[11], 15);
    STEP(D, E, A, B, C, X[12], 6);  STEP(C, D, E, A, B, X[13], 7);
    STEP(B, C, D, E, A, X[14], 9);  STEP(A, B, C, D, E, X[15], 8);
    #undef F1
    #undef STEP

    /* Round 2 */
    #define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F2((b), (c), (d)) + (x) + 0x5A827999UL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(E, A, B, C, D, X[7], 7);   STEP(D, E, A, B, C, X[4], 6);
    STEP(C, D, E, A, B, X[13], 8);  STEP(B, C, D, E, A, X[1], 13);
    STEP(A, B, C, D, E, X[10], 11); STEP(E, A, B, C, D, X[6], 9);
    STEP(D, E, A, B, C, X[15], 7);  STEP(C, D, E, A, B, X[3], 15);
    STEP(B, C, D, E, A, X[12], 7);  STEP(A, B, C, D, E, X[0], 12);
    STEP(E, A, B, C, D, X[9], 15);  STEP(D, E, A, B, C, X[5], 9);
    STEP(C, D, E, A, B, X[2], 11);  STEP(B, C, D, E, A, X[14], 7);
    STEP(A, B, C, D, E, X[11], 13); STEP(E, A, B, C, D, X[8], 12);
    #undef F2
    #undef STEP

    /* Round 3 */
    #define F3(x, y, z) (((x) | ~(y)) ^ (z))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F3((b), (c), (d)) + (x) + 0x6ED9EBA1UL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(D, E, A, B, C, X[3], 11);  STEP(C, D, E, A, B, X[10], 13);
    STEP(B, C, D, E, A, X[14], 6);  STEP(A, B, C, D, E, X[4], 7);
    STEP(E, A, B, C, D, X[9], 14);  STEP(D, E, A, B, C, X[15], 9);
    STEP(C, D, E, A, B, X[8], 13);  STEP(B, C, D, E, A, X[1], 15);
    STEP(A, B, C, D, E, X[2], 14);  STEP(E, A, B, C, D, X[7], 8);
    STEP(D, E, A, B, C, X[0], 13);  STEP(C, D, E, A, B, X[6], 6);
    STEP(B, C, D, E, A, X[13], 5);  STEP(A, B, C, D, E, X[11], 12);
    STEP(E, A, B, C, D, X[5], 7);   STEP(D, E, A, B, C, X[12], 5);
    #undef F3
    #undef STEP

    /* Round 4 */
    #define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F4((b), (c), (d)) + (x) + 0x8F1BBCDCUL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(C, D, E, A, B, X[1], 11);  STEP(B, C, D, E, A, X[9], 12);
    STEP(A, B, C, D, E, X[11], 14); STEP(E, A, B, C, D, X[10], 15);
    STEP(D, E, A, B, C, X[0], 14);  STEP(C, D, E, A, B, X[8], 15);
    STEP(B, C, D, E, A, X[12], 9);  STEP(A, B, C, D, E, X[4], 8);
    STEP(E, A, B, C, D, X[13], 9);  STEP(D, E, A, B, C, X[3], 14);
    STEP(C, D, E, A, B, X[7], 5);   STEP(B, C, D, E, A, X[15], 6);
    STEP(A, B, C, D, E, X[14], 8);  STEP(E, A, B, C, D, X[5], 6);
    STEP(D, E, A, B, C, X[6], 5);   STEP(C, D, E, A, B, X[2], 12);
    #undef F4
    #undef STEP

    /* Round 5 */
    #define F5(x, y, z) ((x) ^ ((y) | ~(z)))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F5((b), (c), (d)) + (x) + 0xA953FD4EUL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(B, C, D, E, A, X[4], 9);   STEP(A, B, C, D, E, X[0], 15);
    STEP(E, A, B, C, D, X[5], 5);   STEP(D, E, A, B, C, X[9], 11);
    STEP(C, D, E, A, B, X[7], 6);   STEP(B, C, D, E, A, X[12], 8);
    STEP(A, B, C, D, E, X[2], 13);  STEP(E, A, B, C, D, X[10], 12);
    STEP(D, E, A, B, C, X[14], 5);  STEP(C, D, E, A, B, X[1], 12);
    STEP(B, C, D, E, A, X[3], 13);  STEP(A, B, C, D, E, X[8], 14);
    STEP(E, A, B, C, D, X[11], 11); STEP(D, E, A, B, C, X[6], 8);
    STEP(C, D, E, A, B, X[15], 5);  STEP(B, C, D, E, A, X[13], 6);
    #undef F5
    #undef STEP

    /* Parallel Round 1 */
    #define F5(x, y, z) ((x) ^ ((y) | ~(z)))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F5((b), (c), (d)) + (x) + 0x50A28BE6UL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(Ap, Bp, Cp, Dp, Ep, X[5], 8);   STEP(Ep, Ap, Bp, Cp, Dp, X[14], 9);
    STEP(Dp, Ep, Ap, Bp, Cp, X[7], 9);   STEP(Cp, Dp, Ep, Ap, Bp, X[0], 11);
    STEP(Bp, Cp, Dp, Ep, Ap, X[9], 13);  STEP(Ap, Bp, Cp, Dp, Ep, X[2], 15);
    STEP(Ep, Ap, Bp, Cp, Dp, X[11], 15); STEP(Dp, Ep, Ap, Bp, Cp, X[4], 5);
    STEP(Cp, Dp, Ep, Ap, Bp, X[13], 7);  STEP(Bp, Cp, Dp, Ep, Ap, X[6], 7);
    STEP(Ap, Bp, Cp, Dp, Ep, X[15], 8);  STEP(Ep, Ap, Bp, Cp, Dp, X[8], 11);
    STEP(Dp, Ep, Ap, Bp, Cp, X[1], 14);  STEP(Cp, Dp, Ep, Ap, Bp, X[10], 14);
    STEP(Bp, Cp, Dp, Ep, Ap, X[3], 12);  STEP(Ap, Bp, Cp, Dp, Ep, X[12], 6);
    #undef F5
    #undef STEP

    /* Parallel Round 2 */
    #define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F4((b), (c), (d)) + (x) + 0x5C4DD124UL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(Ep, Ap, Bp, Cp, Dp, X[6], 9);   STEP(Dp, Ep, Ap, Bp, Cp, X[11], 13);
    STEP(Cp, Dp, Ep, Ap, Bp, X[3], 15);  STEP(Bp, Cp, Dp, Ep, Ap, X[7], 7);
    STEP(Ap, Bp, Cp, Dp, Ep, X[0], 12);  STEP(Ep, Ap, Bp, Cp, Dp, X[13], 8);
    STEP(Dp, Ep, Ap, Bp, Cp, X[5], 9);   STEP(Cp, Dp, Ep, Ap, Bp, X[10], 11);
    STEP(Bp, Cp, Dp, Ep, Ap, X[14], 7);  STEP(Ap, Bp, Cp, Dp, Ep, X[15], 7);
    STEP(Ep, Ap, Bp, Cp, Dp, X[8], 12);  STEP(Dp, Ep, Ap, Bp, Cp, X[12], 7);
    STEP(Cp, Dp, Ep, Ap, Bp, X[4], 6);   STEP(Bp, Cp, Dp, Ep, Ap, X[9], 15);
    STEP(Ap, Bp, Cp, Dp, Ep, X[1], 13);  STEP(Ep, Ap, Bp, Cp, Dp, X[2], 11);
    #undef F4
    #undef STEP

    /* Parallel Round 3 */
    #define F3(x, y, z) (((x) | ~(y)) ^ (z))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F3((b), (c), (d)) + (x) + 0x6D703EF3UL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(Dp, Ep, Ap, Bp, Cp, X[15], 9);  STEP(Cp, Dp, Ep, Ap, Bp, X[5], 7);
    STEP(Bp, Cp, Dp, Ep, Ap, X[1], 15);  STEP(Ap, Bp, Cp, Dp, Ep, X[3], 11);
    STEP(Ep, Ap, Bp, Cp, Dp, X[7], 8);   STEP(Dp, Ep, Ap, Bp, Cp, X[14], 6);
    STEP(Cp, Dp, Ep, Ap, Bp, X[6], 6);   STEP(Bp, Cp, Dp, Ep, Ap, X[9], 14);
    STEP(Ap, Bp, Cp, Dp, Ep, X[11], 12); STEP(Ep, Ap, Bp, Cp, Dp, X[8], 13);
    STEP(Dp, Ep, Ap, Bp, Cp, X[12], 5);  STEP(Cp, Dp, Ep, Ap, Bp, X[2], 14);
    STEP(Bp, Cp, Dp, Ep, Ap, X[10], 13); STEP(Ap, Bp, Cp, Dp, Ep, X[0], 13);
    STEP(Ep, Ap, Bp, Cp, Dp, X[4], 7);   STEP(Dp, Ep, Ap, Bp, Cp, X[13], 5);
    #undef F3
    #undef STEP

    /* Parallel Round 4 */
    #define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F2((b), (c), (d)) + (x) + 0x7A6D76E9UL; \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(Cp, Dp, Ep, Ap, Bp, X[8], 15);  STEP(Bp, Cp, Dp, Ep, Ap, X[6], 5);
    STEP(Ap, Bp, Cp, Dp, Ep, X[4], 8);   STEP(Ep, Ap, Bp, Cp, Dp, X[1], 11);
    STEP(Dp, Ep, Ap, Bp, Cp, X[3], 14);  STEP(Cp, Dp, Ep, Ap, Bp, X[11], 14);
    STEP(Bp, Cp, Dp, Ep, Ap, X[15], 6);  STEP(Ap, Bp, Cp, Dp, Ep, X[0], 14);
    STEP(Ep, Ap, Bp, Cp, Dp, X[5], 6);   STEP(Dp, Ep, Ap, Bp, Cp, X[12], 9);
    STEP(Cp, Dp, Ep, Ap, Bp, X[2], 12);  STEP(Bp, Cp, Dp, Ep, Ap, X[13], 9);
    STEP(Ap, Bp, Cp, Dp, Ep, X[9], 12);  STEP(Ep, Ap, Bp, Cp, Dp, X[7], 5);
    STEP(Dp, Ep, Ap, Bp, Cp, X[10], 15); STEP(Cp, Dp, Ep, Ap, Bp, X[14], 8);
    #undef F2
    #undef STEP

    /* Parallel Round 5 */
    #define F1(x, y, z) ((x) ^ (y) ^ (z))
    #define STEP(a, b, c, d, e, x, s) { \
        (a) += F1((b), (c), (d)) + (x); \
        (a) = ROL((a), (s)) + (e); \
        (c) = ROL((c), 10); \
    }
    STEP(Bp, Cp, Dp, Ep, Ap, X[12], 8);  STEP(Ap, Bp, Cp, Dp, Ep, X[15], 5);
    STEP(Ep, Ap, Bp, Cp, Dp, X[10], 12); STEP(Dp, Ep, Ap, Bp, Cp, X[4], 9);
    STEP(Cp, Dp, Ep, Ap, Bp, X[1], 12);  STEP(Bp, Cp, Dp, Ep, Ap, X[5], 5);
    STEP(Ap, Bp, Cp, Dp, Ep, X[8], 14);  STEP(Ep, Ap, Bp, Cp, Dp, X[7], 6);
    STEP(Dp, Ep, Ap, Bp, Cp, X[6], 8);   STEP(Cp, Dp, Ep, Ap, Bp, X[2], 13);
    STEP(Bp, Cp, Dp, Ep, Ap, X[13], 6);  STEP(Ap, Bp, Cp, Dp, Ep, X[14], 5);
    STEP(Ep, Ap, Bp, Cp, Dp, X[0], 15);  STEP(Dp, Ep, Ap, Bp, Cp, X[3], 13);
    STEP(Cp, Dp, Ep, Ap, Bp, X[9], 11);  STEP(Bp, Cp, Dp, Ep, Ap, X[11], 11);
    #undef F1
    #undef STEP

    uint32_t t = ctx->state[1] + C + Dp;
    ctx->state[1] = ctx->state[2] + D + Ep;
    ctx->state[2] = ctx->state[3] + E + Ap;
    ctx->state[3] = ctx->state[4] + A + Bp;
    ctx->state[4] = ctx->state[0] + B + Cp;
    ctx->state[0] = t;
}

void ripemd160_init(ripemd160_ctx *ctx) {
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xEFCDAB89UL;
    ctx->state[2] = 0x98BADCFEUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xC3D2E1F0UL;
}

void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *input, size_t length) {
    size_t left = ctx->total[0] & 0x3F;
    size_t fill = 64 - left;

    ctx->total[0] += (uint32_t)length;
    if (ctx->total[0] < (uint32_t)length) ctx->total[1]++;

    if (left && length >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        ripemd160_process(ctx, ctx->buffer);
        length -= fill;
        input  += fill;
        left = 0;
    }

    while (length >= 64) {
        ripemd160_process(ctx, input);
        length -= 64;
        input  += 64;
    }

    if (length > 0) {
        memcpy(ctx->buffer + left, input, length);
    }
}

void ripemd160_final(ripemd160_ctx *ctx, uint8_t digest[RIPEMD160_DIGEST_SIZE]) {
    uint8_t msglen[8];
    uint32_t high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    uint32_t low  = (ctx->total[0] << 3);

    for (int i = 0; i < 4; i++) {
        msglen[i]     = (uint8_t)(low >> (i * 8));
        msglen[i + 4] = (uint8_t)(high >> (i * 8));
    }

    size_t last = ctx->total[0] & 0x3F;
    size_t padn = (last < 56) ? (56 - last) : (120 - last);

    static const uint8_t padding[64] = { 0x80 };
    ripemd160_update(ctx, padding, padn);
    ripemd160_update(ctx, msglen, 8);

    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }
}

void ripemd160(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_SIZE]) {
    ripemd160_ctx ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, data, len);
    ripemd160_final(&ctx, digest);
}

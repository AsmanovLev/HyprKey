#include "fips202.h"
#include <string.h>

static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint8_t KeccakF_RhoOffsets[5][5] = {
    { 0, 36,  3, 41, 18 },
    { 1, 44, 10, 45,  2 },
    { 62, 6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};

static inline uint64_t rol64(uint64_t x, unsigned int n) {
    return (x << (n & 63)) | (x >> ((64 - n) & 63));
}

static void keccak_p(uint64_t state[25]) {
    uint64_t A[5][5];
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            A[x][y] = state[x + 5 * y];
        }
    }

    for (int round = 0; round < 24; round++) {
        /* Theta */
        uint64_t C[5];
        for (int x = 0; x < 5; x++) {
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
        }
        uint64_t D[5];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x][y] ^= D[x];
            }
        }

        /* Rho and Pi */
        uint64_t B[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y][(2 * x + 3 * y) % 5] = rol64(A[x][y], KeccakF_RhoOffsets[x][y]);
            }
        }

        /* Chi */
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
            }
        }

        /* Iota */
        A[0][0] ^= KeccakF_RoundConstants[round];
    }

    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            state[x + 5 * y] = A[x][y];
        }
    }
}

static void keccak_absorb_block(uint64_t state[25], const uint8_t *block, size_t rate) {
    size_t words = rate / 8;
    for (size_t i = 0; i < words; i++) {
        uint64_t w = 0;
        for (int b = 0; b < 8; b++) {
            w |= ((uint64_t)block[i * 8 + b]) << (b * 8);
        }
        state[i] ^= w;
    }
    keccak_p(state);
}

/* ==================== SHAKE-128 ==================== */
void shake128_init(shake128_ctx *ctx) {
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->buf_len = 0;
}

void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        if (ctx->buf_len == 0 && inlen >= SHAKE128_RATE) {
            keccak_absorb_block(ctx->s, in, SHAKE128_RATE);
            in += SHAKE128_RATE;
            inlen -= SHAKE128_RATE;
        } else {
            size_t take = SHAKE128_RATE - ctx->buf_len;
            if (take > inlen) take = inlen;
            memcpy(ctx->buf + ctx->buf_len, in, take);
            ctx->buf_len += take;
            in += take;
            inlen -= take;
            if (ctx->buf_len == SHAKE128_RATE) {
                keccak_absorb_block(ctx->s, ctx->buf, SHAKE128_RATE);
                ctx->buf_len = 0;
            }
        }
    }
}

void shake128_finalize(shake128_ctx *ctx) {
    memset(ctx->buf + ctx->buf_len, 0, SHAKE128_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len] ^= 0x1F;
    ctx->buf[SHAKE128_RATE - 1] ^= 0x80;
    keccak_absorb_block(ctx->s, ctx->buf, SHAKE128_RATE);
    ctx->buf_len = 0;
}

void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        if (ctx->buf_len == 0) {
            size_t words = SHAKE128_RATE / 8;
            for (size_t i = 0; i < words; i++) {
                uint64_t w = ctx->s[i];
                for (int b = 0; b < 8; b++) {
                    ctx->buf[i * 8 + b] = (uint8_t)(w >> (b * 8));
                }
            }
        }
        size_t avail = SHAKE128_RATE - ctx->buf_len;
        size_t take = (outlen < avail) ? outlen : avail;
        memcpy(out, ctx->buf + ctx->buf_len, take);
        out += take;
        outlen -= take;
        ctx->buf_len += take;
        if (ctx->buf_len == SHAKE128_RATE) {
            keccak_p(ctx->s);
            ctx->buf_len = 0;
        }
    }
}

void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, in, inlen);
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, out, outlen);
}

/* ==================== SHAKE-256 ==================== */
void shake256_init(shake256_ctx *ctx) {
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->buf_len = 0;
}

void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        if (ctx->buf_len == 0 && inlen >= SHAKE256_RATE) {
            keccak_absorb_block(ctx->s, in, SHAKE256_RATE);
            in += SHAKE256_RATE;
            inlen -= SHAKE256_RATE;
        } else {
            size_t take = SHAKE256_RATE - ctx->buf_len;
            if (take > inlen) take = inlen;
            memcpy(ctx->buf + ctx->buf_len, in, take);
            ctx->buf_len += take;
            in += take;
            inlen -= take;
            if (ctx->buf_len == SHAKE256_RATE) {
                keccak_absorb_block(ctx->s, ctx->buf, SHAKE256_RATE);
                ctx->buf_len = 0;
            }
        }
    }
}

void shake256_finalize(shake256_ctx *ctx) {
    memset(ctx->buf + ctx->buf_len, 0, SHAKE256_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len] ^= 0x1F;
    ctx->buf[SHAKE256_RATE - 1] ^= 0x80;
    keccak_absorb_block(ctx->s, ctx->buf, SHAKE256_RATE);
    ctx->buf_len = 0;
}

void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        if (ctx->buf_len == 0) {
            size_t words = SHAKE256_RATE / 8;
            for (size_t i = 0; i < words; i++) {
                uint64_t w = ctx->s[i];
                for (int b = 0; b < 8; b++) {
                    ctx->buf[i * 8 + b] = (uint8_t)(w >> (b * 8));
                }
            }
        }
        size_t avail = SHAKE256_RATE - ctx->buf_len;
        size_t take = (outlen < avail) ? outlen : avail;
        memcpy(out, ctx->buf + ctx->buf_len, take);
        out += take;
        outlen -= take;
        ctx->buf_len += take;
        if (ctx->buf_len == SHAKE256_RATE) {
            keccak_p(ctx->s);
            ctx->buf_len = 0;
        }
    }
}

void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, in, inlen);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, outlen);
}

/* ==================== SHA3-256 ==================== */
void sha3_256_init(sha3_256_ctx *ctx) {
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->buf_len = 0;
}

void sha3_256_absorb(sha3_256_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        if (ctx->buf_len == 0 && inlen >= SHA3_256_RATE) {
            keccak_absorb_block(ctx->s, in, SHA3_256_RATE);
            in += SHA3_256_RATE;
            inlen -= SHA3_256_RATE;
        } else {
            size_t take = SHA3_256_RATE - ctx->buf_len;
            if (take > inlen) take = inlen;
            memcpy(ctx->buf + ctx->buf_len, in, take);
            ctx->buf_len += take;
            in += take;
            inlen -= take;
            if (ctx->buf_len == SHA3_256_RATE) {
                keccak_absorb_block(ctx->s, ctx->buf, SHA3_256_RATE);
                ctx->buf_len = 0;
            }
        }
    }
}

void sha3_256_finalize(sha3_256_ctx *ctx, uint8_t out[32]) {
    memset(ctx->buf + ctx->buf_len, 0, SHA3_256_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len] ^= 0x06;
    ctx->buf[SHA3_256_RATE - 1] ^= 0x80;
    keccak_absorb_block(ctx->s, ctx->buf, SHA3_256_RATE);
    ctx->buf_len = 0;

    for (size_t i = 0; i < 4; i++) {
        uint64_t w = ctx->s[i];
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(w >> (b * 8));
        }
    }
}

void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_absorb(&ctx, in, inlen);
    sha3_256_finalize(&ctx, out);
}

void keccak_256_finalize(sha3_256_ctx *ctx, uint8_t out[32]) {
    memset(ctx->buf + ctx->buf_len, 0, SHA3_256_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len] ^= 0x01; /* Keccak original padding */
    ctx->buf[SHA3_256_RATE - 1] ^= 0x80;
    keccak_absorb_block(ctx->s, ctx->buf, SHA3_256_RATE);
    ctx->buf_len = 0;

    for (size_t i = 0; i < 4; i++) {
        uint64_t w = ctx->s[i];
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(w >> (b * 8));
        }
    }
}

void keccak_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_absorb(&ctx, in, inlen);
    keccak_256_finalize(&ctx, out);
}

/* ==================== SHA3-512 ==================== */
void sha3_512_init(sha3_512_ctx *ctx) {
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->buf_len = 0;
}

void sha3_512_absorb(sha3_512_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        if (ctx->buf_len == 0 && inlen >= SHA3_512_RATE) {
            keccak_absorb_block(ctx->s, in, SHA3_512_RATE);
            in += SHA3_512_RATE;
            inlen -= SHA3_512_RATE;
        } else {
            size_t take = SHA3_512_RATE - ctx->buf_len;
            if (take > inlen) take = inlen;
            memcpy(ctx->buf + ctx->buf_len, in, take);
            ctx->buf_len += take;
            in += take;
            inlen -= take;
            if (ctx->buf_len == SHA3_512_RATE) {
                keccak_absorb_block(ctx->s, ctx->buf, SHA3_512_RATE);
                ctx->buf_len = 0;
            }
        }
    }
}

void sha3_512_finalize(sha3_512_ctx *ctx, uint8_t out[64]) {
    memset(ctx->buf + ctx->buf_len, 0, SHA3_512_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len] ^= 0x06;
    ctx->buf[SHA3_512_RATE - 1] ^= 0x80;
    keccak_absorb_block(ctx->s, ctx->buf, SHA3_512_RATE);
    ctx->buf_len = 0;

    for (size_t i = 0; i < 8; i++) {
        uint64_t w = ctx->s[i];
        for (int b = 0; b < 8; b++) {
            out[i * 8 + b] = (uint8_t)(w >> (b * 8));
        }
    }
}

void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]) {
    sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_absorb(&ctx, in, inlen);
    sha3_512_finalize(&ctx, out);
}

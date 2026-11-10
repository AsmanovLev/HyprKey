#include "chacha20poly1305.h"
#include <string.h>

/* ========================================================================= */
/*                          ChaCha20 (RFC 8439)                              */
/* ========================================================================= */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QUARTERROUND(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8);  \
        c += d; b ^= c; b = ROTL32(b, 7);  \
    } while (0)

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val);
    p[1] = (uint8_t)(val >> 8);
    p[2] = (uint8_t)(val >> 16);
    p[3] = (uint8_t)(val >> 24);
}

static void chacha20_block(const uint32_t state_in[16], uint8_t stream_out[64]) {
    uint32_t x[16];
    memcpy(x, state_in, sizeof(x));

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        CHACHA20_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA20_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA20_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA20_QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        CHACHA20_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA20_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA20_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA20_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; i++) {
        store32_le(stream_out + (i * 4), x[i] + state_in[i]);
    }
}

static void chacha20_xor_stream(const uint8_t key[32], const uint8_t nonce[12],
                                uint32_t initial_counter, const uint8_t *src,
                                uint8_t *dst, size_t len) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + (i * 4));
    }
    state[12] = initial_counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    uint8_t stream[64];
    while (len > 0) {
        chacha20_block(state, stream);
        state[12]++;

        size_t block_bytes = (len < 64) ? len : 64;
        for (size_t i = 0; i < block_bytes; i++) {
            dst[i] = src[i] ^ stream[i];
        }

        src += block_bytes;
        dst += block_bytes;
        len -= block_bytes;
    }
}

/* ========================================================================= */
/*                          Poly1305 (RFC 8439)                              */
/* ========================================================================= */

typedef struct {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t pad[4];
    uint8_t  buffer[16];
    size_t   buffer_len;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    /* r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
    uint32_t t0 = load32_le(&key[0]);
    uint32_t t1 = load32_le(&key[4]);
    uint32_t t2 = load32_le(&key[8]);
    uint32_t t3 = load32_le(&key[12]);

    ctx->r0 = (t0)                        & 0x3ffffff;
    ctx->r1 = ((t0 >> 26) | (t1 << 6))    & 0x3ffff03;
    ctx->r2 = ((t1 >> 20) | (t2 << 12))   & 0x3ffc0ff;
    ctx->r3 = ((t2 >> 14) | (t3 << 18))   & 0x3f03fff;
    ctx->r4 = (t3 >> 8)                   & 0x00fffff;

    ctx->s1 = ctx->r1 * 5;
    ctx->s2 = ctx->r2 * 5;
    ctx->s3 = ctx->r3 * 5;
    ctx->s4 = ctx->r4 * 5;

    ctx->h0 = 0;
    ctx->h1 = 0;
    ctx->h2 = 0;
    ctx->h3 = 0;
    ctx->h4 = 0;

    ctx->pad[0] = load32_le(&key[16]);
    ctx->pad[1] = load32_le(&key[20]);
    ctx->pad[2] = load32_le(&key[24]);
    ctx->pad[3] = load32_le(&key[28]);

    ctx->buffer_len = 0;
}

static void poly1305_blocks(poly1305_ctx *ctx, const uint8_t *m, size_t bytes, uint32_t hibit) {
    while (bytes >= 16) {
        uint32_t t0 = load32_le(&m[0]);
        uint32_t t1 = load32_le(&m[4]);
        uint32_t t2 = load32_le(&m[8]);
        uint32_t t3 = load32_le(&m[12]);

        ctx->h0 += (t0)                        & 0x3ffffff;
        ctx->h1 += ((t0 >> 26) | (t1 << 6))    & 0x3ffffff;
        ctx->h2 += ((t1 >> 20) | (t2 << 12))   & 0x3ffffff;
        ctx->h3 += ((t2 >> 14) | (t3 << 18))   & 0x3ffffff;
        ctx->h4 += (t3 >> 8) | (hibit << 24);

        /* d = h * r */
        uint64_t d0 = (uint64_t)ctx->h0 * ctx->r0 +
                      (uint64_t)ctx->h1 * ctx->s4 +
                      (uint64_t)ctx->h2 * ctx->s3 +
                      (uint64_t)ctx->h3 * ctx->s2 +
                      (uint64_t)ctx->h4 * ctx->s1;

        uint64_t d1 = (uint64_t)ctx->h0 * ctx->r1 +
                      (uint64_t)ctx->h1 * ctx->r0 +
                      (uint64_t)ctx->h2 * ctx->s4 +
                      (uint64_t)ctx->h3 * ctx->s3 +
                      (uint64_t)ctx->h4 * ctx->s2;

        uint64_t d2 = (uint64_t)ctx->h0 * ctx->r2 +
                      (uint64_t)ctx->h1 * ctx->r1 +
                      (uint64_t)ctx->h2 * ctx->r0 +
                      (uint64_t)ctx->h3 * ctx->s4 +
                      (uint64_t)ctx->h4 * ctx->s3;

        uint64_t d3 = (uint64_t)ctx->h0 * ctx->r3 +
                      (uint64_t)ctx->h1 * ctx->r2 +
                      (uint64_t)ctx->h2 * ctx->r1 +
                      (uint64_t)ctx->h3 * ctx->r0 +
                      (uint64_t)ctx->h4 * ctx->s4;

        uint64_t d4 = (uint64_t)ctx->h0 * ctx->r4 +
                      (uint64_t)ctx->h1 * ctx->r3 +
                      (uint64_t)ctx->h2 * ctx->r2 +
                      (uint64_t)ctx->h3 * ctx->r1 +
                      (uint64_t)ctx->h4 * ctx->r0;

        /* Carry reduction */
        uint32_t c;
        c = (uint32_t)(d0 >> 26); ctx->h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); ctx->h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); ctx->h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); ctx->h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); ctx->h4 = (uint32_t)d4 & 0x3ffffff; ctx->h0 += c * 5;
        c = ctx->h0 >> 26;        ctx->h0 &= 0x3ffffff;                ctx->h1 += c;

        m += 16;
        bytes -= 16;
    }
}

static void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    if (ctx->buffer_len > 0) {
        size_t want = 16 - ctx->buffer_len;
        if (want > bytes) want = bytes;
        memcpy(ctx->buffer + ctx->buffer_len, m, want);
        ctx->buffer_len += want;
        m += want;
        bytes -= want;

        if (ctx->buffer_len == 16) {
            poly1305_blocks(ctx, ctx->buffer, 16, 1);
            ctx->buffer_len = 0;
        }
    }

    if (bytes >= 16) {
        size_t full = bytes & ~((size_t)15);
        poly1305_blocks(ctx, m, full, 1);
        m += full;
        bytes -= full;
    }

    if (bytes > 0) {
        memcpy(ctx->buffer + ctx->buffer_len, m, bytes);
        ctx->buffer_len += bytes;
    }
}

static void poly1305_finish(poly1305_ctx *ctx, uint8_t mac[16]) {
    if (ctx->buffer_len > 0) {
        ctx->buffer[ctx->buffer_len++] = 1;
        while (ctx->buffer_len < 16) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        poly1305_blocks(ctx, ctx->buffer, 16, 0);
    }

    /* Final reduction mod 2^130 - 5 */
    uint32_t c = ctx->h1 >> 26; ctx->h1 &= 0x3ffffff; ctx->h2 += c;
    c = ctx->h2 >> 26;          ctx->h2 &= 0x3ffffff; ctx->h3 += c;
    c = ctx->h3 >> 26;          ctx->h3 &= 0x3ffffff; ctx->h4 += c;
    c = ctx->h4 >> 26;          ctx->h4 &= 0x3ffffff; ctx->h0 += c * 5;
    c = ctx->h0 >> 26;          ctx->h0 &= 0x3ffffff; ctx->h1 += c;

    uint32_t g0 = ctx->h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = ctx->h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = ctx->h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = ctx->h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = ctx->h4 + c - (1 << 26);

    uint32_t mask = (g4 >> 31) - 1;
    ctx->h0 ^= mask & (g0 ^ ctx->h0);
    ctx->h1 ^= mask & (g1 ^ ctx->h1);
    ctx->h2 ^= mask & (g2 ^ ctx->h2);
    ctx->h3 ^= mask & (g3 ^ ctx->h3);
    ctx->h4 ^= mask & (g4 ^ ctx->h4);

    /* Convert to 32-bit limbs and add pad */
    uint64_t f0 = ((uint64_t)ctx->h0)       | ((uint64_t)ctx->h1 << 26);
    uint64_t f1 = ((uint64_t)ctx->h1 >> 6)  | ((uint64_t)ctx->h2 << 20);
    uint64_t f2 = ((uint64_t)ctx->h2 >> 12) | ((uint64_t)ctx->h3 << 14);
    uint64_t f3 = ((uint64_t)ctx->h3 >> 18) | ((uint64_t)ctx->h4 << 8);

    f0 += ctx->pad[0];
    f1 += ctx->pad[1] + (f0 >> 32);
    f2 += ctx->pad[2] + (f1 >> 32);
    f3 += ctx->pad[3] + (f2 >> 32);

    store32_le(mac + 0,  (uint32_t)f0);
    store32_le(mac + 4,  (uint32_t)f1);
    store32_le(mac + 8,  (uint32_t)f2);
    store32_le(mac + 12, (uint32_t)f3);
}

/* ========================================================================= */
/*                   ChaCha20-Poly1305 AEAD (RFC 8439)                       */
/* ========================================================================= */

static const uint8_t s_zeroes[16] = {0};

void chacha20_poly1305_encrypt(const uint8_t key[32],
                               const uint8_t nonce[12],
                               const void *aad, size_t aad_len,
                               const uint8_t *plain,
                               uint8_t *cipher, size_t len,
                               uint8_t tag_out[16]) {
    /* 1. Generate one-time Poly1305 key with counter=0 */
    uint8_t otk_block[64];
    uint8_t otk_zero[64] = {0};
    chacha20_xor_stream(key, nonce, 0, otk_zero, otk_block, 64);

    poly1305_ctx pctx;
    poly1305_init(&pctx, otk_block);

    /* 2. Encrypt plaintext with counter=1 */
    if (len > 0) {
        chacha20_xor_stream(key, nonce, 1, plain, cipher, len);
    }

    /* 3. Authenticate AAD */
    if (aad && aad_len > 0) {
        poly1305_update(&pctx, (const uint8_t *)aad, aad_len);
        size_t pad = (16 - (aad_len % 16)) % 16;
        if (pad > 0) {
            poly1305_update(&pctx, s_zeroes, pad);
        }
    }

    /* 4. Authenticate Ciphertext */
    if (len > 0) {
        poly1305_update(&pctx, cipher, len);
        size_t pad = (16 - (len % 16)) % 16;
        if (pad > 0) {
            poly1305_update(&pctx, s_zeroes, pad);
        }
    }

    /* 5. Authenticate lengths (64-bit LE each) */
    uint8_t lens[16];
    store32_le(&lens[0], (uint32_t)aad_len);
    store32_le(&lens[4], 0);
    store32_le(&lens[8], (uint32_t)len);
    store32_le(&lens[12], 0);
    poly1305_update(&pctx, lens, 16);

    poly1305_finish(&pctx, tag_out);
}

bool chacha20_poly1305_decrypt(const uint8_t key[32],
                               const uint8_t nonce[12],
                               const void *aad, size_t aad_len,
                               const uint8_t *cipher,
                               uint8_t *plain, size_t len,
                               const uint8_t tag[16]) {
    /* 1. Generate one-time Poly1305 key with counter=0 */
    uint8_t otk_block[64];
    uint8_t otk_zero[64] = {0};
    chacha20_xor_stream(key, nonce, 0, otk_zero, otk_block, 64);

    poly1305_ctx pctx;
    poly1305_init(&pctx, otk_block);

    /* 2. Authenticate AAD */
    if (aad && aad_len > 0) {
        poly1305_update(&pctx, (const uint8_t *)aad, aad_len);
        size_t pad = (16 - (aad_len % 16)) % 16;
        if (pad > 0) {
            poly1305_update(&pctx, s_zeroes, pad);
        }
    }

    /* 3. Authenticate Ciphertext */
    if (len > 0) {
        poly1305_update(&pctx, cipher, len);
        size_t pad = (16 - (len % 16)) % 16;
        if (pad > 0) {
            poly1305_update(&pctx, s_zeroes, pad);
        }
    }

    /* 4. Authenticate lengths (64-bit LE each) */
    uint8_t lens[16];
    store32_le(&lens[0], (uint32_t)aad_len);
    store32_le(&lens[4], 0);
    store32_le(&lens[8], (uint32_t)len);
    store32_le(&lens[12], 0);
    poly1305_update(&pctx, lens, 16);

    uint8_t computed_tag[16];
    poly1305_finish(&pctx, computed_tag);

    /* 5. Constant-time tag verification */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (computed_tag[i] ^ tag[i]);
    }

    if (diff != 0) {
        if (plain && len > 0) {
            memset(plain, 0, len);
        }
        return false;
    }

    /* 6. Decrypt ciphertext only after tag is verified */
    if (len > 0) {
        chacha20_xor_stream(key, nonce, 1, cipher, plain, len);
    }
    return true;
}

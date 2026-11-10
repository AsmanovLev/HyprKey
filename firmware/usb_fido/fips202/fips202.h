#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>
#include <stddef.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
    uint64_t s[25];
    uint8_t  buf[SHAKE128_RATE];
    size_t   buf_len;
} shake128_ctx;

typedef struct {
    uint64_t s[25];
    uint8_t  buf[SHAKE256_RATE];
    size_t   buf_len;
} shake256_ctx;

typedef struct {
    uint64_t s[25];
    uint8_t  buf[SHA3_256_RATE];
    size_t   buf_len;
} sha3_256_ctx;

typedef struct {
    uint64_t s[25];
    uint8_t  buf[SHA3_512_RATE];
    size_t   buf_len;
} sha3_512_ctx;

void shake128_init(shake128_ctx *ctx);
void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen);
void shake128_finalize(shake128_ctx *ctx);
void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen);
void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

void shake256_init(shake256_ctx *ctx);
void shake256_absorb(shake256_ctx *ctx, const uint8_t *in, size_t inlen);
void shake256_finalize(shake256_ctx *ctx);
void shake256_squeeze(shake256_ctx *ctx, uint8_t *out, size_t outlen);
void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

void sha3_256_init(sha3_256_ctx *ctx);
void sha3_256_absorb(sha3_256_ctx *ctx, const uint8_t *in, size_t inlen);
void sha3_256_finalize(sha3_256_ctx *ctx, uint8_t out[32]);
void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);

void sha3_512_init(sha3_512_ctx *ctx);
void sha3_512_absorb(sha3_512_ctx *ctx, const uint8_t *in, size_t inlen);
void sha3_512_finalize(sha3_512_ctx *ctx, uint8_t out[64]);
void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]);

#endif /* FIPS202_H */

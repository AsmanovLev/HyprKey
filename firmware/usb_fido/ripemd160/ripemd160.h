#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD160_DIGEST_SIZE 20

typedef struct {
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
} ripemd160_ctx;

void ripemd160_init(ripemd160_ctx *ctx);
void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *input, size_t length);
void ripemd160_final(ripemd160_ctx *ctx, uint8_t digest[RIPEMD160_DIGEST_SIZE]);
void ripemd160(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_SIZE]);

#endif /* RIPEMD160_H */

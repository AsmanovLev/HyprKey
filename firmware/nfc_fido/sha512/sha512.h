#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buffer[128];
} sha512_ctx_t;

void sha512_init(sha512_ctx_t *ctx);
void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx_t *ctx, uint8_t hash[64]);
void sha512(const uint8_t *data, size_t len, uint8_t hash[64]);

#endif /* SHA512_H */

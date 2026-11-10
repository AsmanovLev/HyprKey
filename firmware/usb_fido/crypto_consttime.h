#ifndef CRYPTO_CONSTTIME_H
#define CRYPTO_CONSTTIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Constant-time memory comparison to protect against timing side-channel attacks.
 * Returns true if both buffers match, false otherwise.
 */
static inline bool crypto_consttime_eq(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return (diff == 0U);
}

#endif /* CRYPTO_CONSTTIME_H */

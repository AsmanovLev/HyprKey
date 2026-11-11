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

/**
 * Secure memory zeroization to wipe sensitive keys from SRAM/stack.
 */
static inline void crypto_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0U;
    }
}

/**
 * Hardware True Random Number Generator (TRNG) on nRF52840.
 * Directly reads entropy from silicon noise generator with Bias Correction.
 */
#define HW_RNG_BASE_ADDR        0x4000D000UL
#define HW_RNG_TASKS_START      (*(volatile uint32_t *)(HW_RNG_BASE_ADDR + 0x000))
#define HW_RNG_TASKS_STOP       (*(volatile uint32_t *)(HW_RNG_BASE_ADDR + 0x004))
#define HW_RNG_EVENTS_VALRDY    (*(volatile uint32_t *)(HW_RNG_BASE_ADDR + 0x100))
#define HW_RNG_CONFIG           (*(volatile uint32_t *)(HW_RNG_BASE_ADDR + 0x504))
#define HW_RNG_VALUE            (*(volatile uint32_t *)(HW_RNG_BASE_ADDR + 0x508))

static inline int hw_trng_get_bytes(uint8_t *dest, unsigned size) {
    HW_RNG_CONFIG = 1UL; /* Enable Digital Error Correction */
    HW_RNG_TASKS_START = 1UL;
    while (size--) {
        HW_RNG_EVENTS_VALRDY = 0UL;
        uint32_t timeout = 100000UL;
        while (!HW_RNG_EVENTS_VALRDY && --timeout);
        if (timeout == 0UL) {
            HW_RNG_TASKS_STOP = 1UL;
            return 0;
        }
        *dest++ = (uint8_t)HW_RNG_VALUE;
    }
    HW_RNG_TASKS_STOP = 1UL;
    return 1;
}

/**
 * Strict ISO/IEC 7816-4 APDU parser.
 * Accurately parses Cases 1, 2S, 2E, 3S, 3E, 4S, 4E, correctly separating Lc data from Le.
 */
static inline bool iso7816_parse_apdu(const uint8_t *apdu, uint16_t apdu_len,
                                      const uint8_t **data_out, uint16_t *lc_out) {
    *data_out = NULL;
    *lc_out   = 0U;

    if (apdu_len < 4U) {
        return false;
    }
    if (apdu_len == 4U) {
        return true; /* Case 1: [CLA INS P1 P2] */
    }
    if (apdu_len == 5U) {
        return true; /* Case 2S: [CLA INS P1 P2 Le] — No body (Lc = 0) */
    }

    if (apdu[4] == 0x00U) {
        /* Extended APDU */
        if (apdu_len == 7U) {
            return true; /* Case 2E: [CLA INS P1 P2 00 Le1 Le2] — No body (Lc = 0) */
        }
        uint16_t lc = (uint16_t)(((uint16_t)apdu[5] << 8U) | apdu[6]);
        if (lc == 0U) {
            return false;
        }
        /* Case 3E: (7 + lc) or Case 4E: (7 + lc + 2 bytes Le) */
        if (apdu_len != (uint16_t)(7U + lc) && apdu_len != (uint16_t)(7U + lc + 2U)) {
            return false;
        }
        *data_out = &apdu[7];
        *lc_out   = lc;
        return true;
    } else {
        /* Short APDU */
        uint16_t lc = apdu[4];
        /* Case 3S: (5 + lc) or Case 4S: (5 + lc + 1 byte Le) */
        if (apdu_len != (uint16_t)(5U + lc) && apdu_len != (uint16_t)(5U + lc + 1U)) {
            return false;
        }
        *data_out = &apdu[5];
        *lc_out   = lc;
        return true;
    }
}

#endif /* CRYPTO_CONSTTIME_H */


#include "mldsa.h"

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int val, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)val;
    return dst;
}

uint8_t g_seed[32];
uint8_t g_pk[2000];
uint8_t g_sig[3500];
uint8_t g_msg[128];

void run_keygen65(void) {
    mldsa65_keygen(g_seed, g_pk, 0);
}

void run_sign65(size_t msglen) {
    mldsa65_sign_seed(g_seed, g_msg, msglen, 0, g_sig);
}

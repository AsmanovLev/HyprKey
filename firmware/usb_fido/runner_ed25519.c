#include "ed25519/ed25519.h"
#include <string.h>

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
uint8_t g_pk[32];
uint8_t g_sk[64];
uint8_t g_msg[128];
uint32_t g_msg_len = 0;
uint8_t g_sig[64];

void run_ed25519_keygen(void) {
    ed25519_create_keypair(g_pk, g_sk, g_seed);
}

void run_ed25519_sign(void) {
    ed25519_sign(g_sig, g_msg, g_msg_len, g_pk, g_sk);
}

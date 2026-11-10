#include "mlkem/mlkem.h"
#include <stdint.h>
#include <stddef.h>

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

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

/* Global buffers for test runner */
uint8_t g_d[32];
uint8_t g_z[32];
uint8_t g_m[32];
uint8_t g_pk[1568];
uint8_t g_sk[3168];
uint8_t g_ct[1568];
uint8_t g_ss[32];

void run_mlkem768_keygen(void) {
    mlkem768_keygen_internal(g_pk, g_sk, g_d, g_z);
}

void run_mlkem768_encaps(void) {
    mlkem768_encaps_internal(g_ct, g_ss, g_pk, g_m);
}

void run_mlkem768_decaps(void) {
    mlkem768_decaps_internal(g_ss, g_ct, g_sk);
}

void run_mlkem1024_keygen(void) {
    mlkem1024_keygen_internal(g_pk, g_sk, g_d, g_z);
}

void run_mlkem1024_encaps(void) {
    mlkem1024_encaps_internal(g_ct, g_ss, g_pk, g_m);
}

void run_mlkem1024_decaps(void) {
    mlkem1024_decaps_internal(g_ss, g_ct, g_sk);
}

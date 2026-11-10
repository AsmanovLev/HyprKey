
#include "oath/oath.h"
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

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

uint8_t g_apdu_req[512];
uint8_t g_apdu_rsp[512];
uint16_t g_apdu_rsp_len = 0;

void test_init(void) {
    oath_init();
}

void run_apdu(uint16_t req_len) {
    g_apdu_rsp_len = oath_process_apdu(g_apdu_req, req_len, g_apdu_rsp, sizeof(g_apdu_rsp));
}

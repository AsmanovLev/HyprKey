
#include "ccid/ccid.h"
#include "openpgp/openpgp.h"
#include "micro_ecc/uECC.h"

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

static int test_rng(uint8_t *dest, unsigned size) {
    static uint32_t s_seed = 0x12345678;
    while (size--) {
        s_seed = s_seed * 1103515245 + 12345;
        *dest++ = (uint8_t)(s_seed >> 16);
    }
    return 1;
}

uint8_t g_ccid_req[2048];
uint8_t g_ccid_rsp[2048];
uint16_t g_ccid_rsp_len = 0;

void test_init(void) {
    uECC_set_rng(test_rng);
    ccid_init();
}

void run_ccid(uint16_t req_len) {
    g_ccid_rsp_len = ccid_process_message(g_ccid_req, req_len, g_ccid_rsp, sizeof(g_ccid_rsp));
}

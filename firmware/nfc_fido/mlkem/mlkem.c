#include "mlkem.h"
#include "fips202.h"
#include <string.h>

#define KYBER_Q 3329

/* FIPS 203 Table of 128 zetas (powers of 17 in bit-reversed order) */
static const int16_t zetas[128] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
};

static inline int16_t fq_mod(int32_t x) {
    int32_t r = x % KYBER_Q;
    if (r < 0) r += KYBER_Q;
    return (int16_t)r;
}

static void ntt(int16_t f[256]) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int32_t t = (int32_t)zeta * f[j + len];
                int16_t t_mod = fq_mod(t);
                f[j + len] = fq_mod((int32_t)f[j] - t_mod);
                f[j] = fq_mod((int32_t)f[j] + t_mod);
            }
        }
    }
}

static void ntt_inv(int16_t f[256]) {
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = zetas[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = f[j];
                f[j] = fq_mod((int32_t)t + f[j + len]);
                f[j + len] = fq_mod((int32_t)zeta * (f[j + len] - t));
            }
        }
    }
    for (int j = 0; j < 256; j++) {
        f[j] = fq_mod((int32_t)f[j] * 3303);
    }
}

static void multiply_ntts(int16_t c[256], const int16_t a[256], const int16_t b[256]) {
    for (int i = 0; i < 64; i++) {
        int16_t gamma = zetas[64 + i];
        int16_t a0 = a[4*i], a1 = a[4*i + 1];
        int16_t b0 = b[4*i], b1 = b[4*i + 1];
        c[4*i]     = fq_mod((int32_t)a0 * b0 + (int32_t)a1 * b1 % KYBER_Q * gamma);
        c[4*i + 1] = fq_mod((int32_t)a0 * b1 + (int32_t)a1 * b0);

        int16_t neg_gamma = KYBER_Q - gamma;
        a0 = a[4*i + 2]; a1 = a[4*i + 3];
        b0 = b[4*i + 2]; b1 = b[4*i + 3];
        c[4*i + 2] = fq_mod((int32_t)a0 * b0 + (int32_t)a1 * b1 % KYBER_Q * neg_gamma);
        c[4*i + 3] = fq_mod((int32_t)a0 * b1 + (int32_t)a1 * b0);
    }
}

static void sample_ntt(int16_t a[256], const uint8_t rho[32], uint8_t i, uint8_t j) {
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, rho, 32);
    uint8_t ij[2] = {i, j};
    shake128_absorb(&ctx, ij, 2);
    shake128_finalize(&ctx);

    int count = 0;
    uint8_t buf[SHAKE128_RATE];
    while (count < 256) {
        shake128_squeeze(&ctx, buf, sizeof(buf));
        for (size_t pos = 0; pos + 2 < sizeof(buf) && count < 256; pos += 3) {
            uint16_t d1 = buf[pos] | ((uint16_t)(buf[pos+1] & 0x0F) << 8);
            uint16_t d2 = (buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4);
            if (d1 < KYBER_Q) {
                a[count++] = (int16_t)d1;
            }
            if (d2 < KYBER_Q && count < 256) {
                a[count++] = (int16_t)d2;
            }
        }
    }
}

static void sample_cbd2(int16_t r[256], const uint8_t buf[128]) {
    for (int i = 0; i < 32; i++) {
        uint32_t t = (uint32_t)buf[4*i]
                   | ((uint32_t)buf[4*i + 1] << 8)
                   | ((uint32_t)buf[4*i + 2] << 16)
                   | ((uint32_t)buf[4*i + 3] << 24);
        uint32_t d = (t & 0x55555555U) + ((t >> 1) & 0x55555555U);
        for (int j = 0; j < 8; j++) {
            int16_t a = (d >> (4 * j)) & 0x03;
            int16_t b = (d >> (4 * j + 2)) & 0x03;
            r[8 * i + j] = fq_mod((int32_t)a - b);
        }
    }
}

static void prf_eta2(uint8_t out[128], const uint8_t seed[32], uint8_t N) {
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, seed, 32);
    shake256_absorb(&ctx, &N, 1);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, 128);
}

static inline uint16_t compress_d(int16_t x, int d) {
    uint32_t t = ((uint32_t)x << d) + 1664;
    return (uint16_t)((t / KYBER_Q) & ((1U << d) - 1));
}

static inline int16_t decompress_d(uint16_t y, int d) {
    uint32_t t = (uint32_t)y * KYBER_Q + (1U << (d - 1));
    return (int16_t)(t >> d);
}

static void byte_encode12(uint8_t out[384], const int16_t a[256]) {
    for (int i = 0; i < 128; i++) {
        uint16_t t0 = (uint16_t)a[2 * i];
        uint16_t t1 = (uint16_t)a[2 * i + 1];
        out[3 * i + 0] = (uint8_t)(t0 & 0xFF);
        out[3 * i + 1] = (uint8_t)(((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4));
        out[3 * i + 2] = (uint8_t)((t1 >> 4) & 0xFF);
    }
}

static void byte_decode12(int16_t a[256], const uint8_t in[384]) {
    for (int i = 0; i < 128; i++) {
        uint8_t b0 = in[3 * i + 0];
        uint8_t b1 = in[3 * i + 1];
        uint8_t b2 = in[3 * i + 2];
        a[2 * i + 0] = (int16_t)(b0 | ((b1 & 0x0F) << 8));
        a[2 * i + 1] = (int16_t)((b1 >> 4) | (b2 << 4));
    }
}

static void poly_compress_du10(uint8_t out[320], const int16_t a[256]) {
    for (int i = 0; i < 64; i++) {
        uint16_t c0 = compress_d(a[4 * i + 0], 10);
        uint16_t c1 = compress_d(a[4 * i + 1], 10);
        uint16_t c2 = compress_d(a[4 * i + 2], 10);
        uint16_t c3 = compress_d(a[4 * i + 3], 10);
        out[5 * i + 0] = (uint8_t)(c0 & 0xFF);
        out[5 * i + 1] = (uint8_t)(((c0 >> 8) & 0x03) | ((c1 & 0x3F) << 2));
        out[5 * i + 2] = (uint8_t)(((c1 >> 6) & 0x0F) | ((c2 & 0x0F) << 4));
        out[5 * i + 3] = (uint8_t)(((c2 >> 4) & 0x3F) | ((c3 & 0x03) << 6));
        out[5 * i + 4] = (uint8_t)((c3 >> 2) & 0xFF);
    }
}

static void poly_decompress_du10(int16_t a[256], const uint8_t in[320]) {
    for (int i = 0; i < 64; i++) {
        uint8_t b0 = in[5 * i + 0], b1 = in[5 * i + 1], b2 = in[5 * i + 2];
        uint8_t b3 = in[5 * i + 3], b4 = in[5 * i + 4];
        uint16_t c0 = b0 | ((b1 & 0x03) << 8);
        uint16_t c1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
        uint16_t c2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
        uint16_t c3 = (b3 >> 6) | (b4 << 2);
        a[4 * i + 0] = decompress_d(c0, 10);
        a[4 * i + 1] = decompress_d(c1, 10);
        a[4 * i + 2] = decompress_d(c2, 10);
        a[4 * i + 3] = decompress_d(c3, 10);
    }
}

static void poly_compress_dv4(uint8_t out[128], const int16_t a[256]) {
    for (int i = 0; i < 128; i++) {
        uint8_t c0 = (uint8_t)compress_d(a[2 * i + 0], 4);
        uint8_t c1 = (uint8_t)compress_d(a[2 * i + 1], 4);
        out[i] = (uint8_t)(c0 | (c1 << 4));
    }
}

static void poly_decompress_dv4(int16_t a[256], const uint8_t in[128]) {
    for (int i = 0; i < 128; i++) {
        uint8_t b = in[i];
        a[2 * i + 0] = decompress_d(b & 0x0F, 4);
        a[2 * i + 1] = decompress_d((b >> 4) & 0x0F, 4);
    }
}

static void poly_compress_du11(uint8_t out[352], const int16_t a[256]) {
    for (int i = 0; i < 32; i++) {
        uint16_t c0 = compress_d(a[8 * i + 0], 11);
        uint16_t c1 = compress_d(a[8 * i + 1], 11);
        uint16_t c2 = compress_d(a[8 * i + 2], 11);
        uint16_t c3 = compress_d(a[8 * i + 3], 11);
        uint16_t c4 = compress_d(a[8 * i + 4], 11);
        uint16_t c5 = compress_d(a[8 * i + 5], 11);
        uint16_t c6 = compress_d(a[8 * i + 6], 11);
        uint16_t c7 = compress_d(a[8 * i + 7], 11);

        out[11 * i + 0]  = (uint8_t)(c0 & 0xFF);
        out[11 * i + 1]  = (uint8_t)(((c0 >> 8) & 0x07) | ((c1 & 0x1F) << 3));
        out[11 * i + 2]  = (uint8_t)(((c1 >> 5) & 0x3F) | ((c2 & 0x03) << 6));
        out[11 * i + 3]  = (uint8_t)((c2 >> 2) & 0xFF);
        out[11 * i + 4]  = (uint8_t)(((c2 >> 10) & 0x01) | ((c3 & 0x7F) << 1));
        out[11 * i + 5]  = (uint8_t)(((c3 >> 7) & 0x0F) | ((c4 & 0x0F) << 4));
        out[11 * i + 6]  = (uint8_t)(((c4 >> 4) & 0x7F) | ((c5 & 0x01) << 7));
        out[11 * i + 7]  = (uint8_t)((c5 >> 1) & 0xFF);
        out[11 * i + 8]  = (uint8_t)(((c5 >> 9) & 0x03) | ((c6 & 0x3F) << 2));
        out[11 * i + 9]  = (uint8_t)(((c6 >> 6) & 0x1F) | ((c7 & 0x07) << 5));
        out[11 * i + 10] = (uint8_t)((c7 >> 3) & 0xFF);
    }
}

static void poly_decompress_du11(int16_t a[256], const uint8_t in[352]) {
    for (int i = 0; i < 32; i++) {
        const uint8_t *b = &in[11 * i];
        uint16_t c0 = (uint16_t)b[0] | ((uint16_t)(b[1] & 0x07) << 8);
        uint16_t c1 = (uint16_t)(b[1] >> 3) | ((uint16_t)(b[2] & 0x3F) << 5);
        uint16_t c2 = (uint16_t)(b[2] >> 6) | ((uint16_t)b[3] << 2) | ((uint16_t)(b[4] & 0x01) << 10);
        uint16_t c3 = (uint16_t)(b[4] >> 1) | ((uint16_t)(b[5] & 0x0F) << 7);
        uint16_t c4 = (uint16_t)(b[5] >> 4) | ((uint16_t)(b[6] & 0x7F) << 4);
        uint16_t c5 = (uint16_t)(b[6] >> 7) | ((uint16_t)b[7] << 1) | ((uint16_t)(b[8] & 0x03) << 9);
        uint16_t c6 = (uint16_t)(b[8] >> 2) | ((uint16_t)(b[9] & 0x1F) << 6);
        uint16_t c7 = (uint16_t)(b[9] >> 5) | ((uint16_t)b[10] << 3);

        a[8 * i + 0] = decompress_d(c0, 11);
        a[8 * i + 1] = decompress_d(c1, 11);
        a[8 * i + 2] = decompress_d(c2, 11);
        a[8 * i + 3] = decompress_d(c3, 11);
        a[8 * i + 4] = decompress_d(c4, 11);
        a[8 * i + 5] = decompress_d(c5, 11);
        a[8 * i + 6] = decompress_d(c6, 11);
        a[8 * i + 7] = decompress_d(c7, 11);
    }
}

static void poly_compress_dv5(uint8_t out[160], const int16_t a[256]) {
    for (int i = 0; i < 32; i++) {
        uint8_t c0 = (uint8_t)compress_d(a[8 * i + 0], 5);
        uint8_t c1 = (uint8_t)compress_d(a[8 * i + 1], 5);
        uint8_t c2 = (uint8_t)compress_d(a[8 * i + 2], 5);
        uint8_t c3 = (uint8_t)compress_d(a[8 * i + 3], 5);
        uint8_t c4 = (uint8_t)compress_d(a[8 * i + 4], 5);
        uint8_t c5 = (uint8_t)compress_d(a[8 * i + 5], 5);
        uint8_t c6 = (uint8_t)compress_d(a[8 * i + 6], 5);
        uint8_t c7 = (uint8_t)compress_d(a[8 * i + 7], 5);

        out[5 * i + 0] = (uint8_t)((c0 & 0x1F) | ((c1 & 0x07) << 5));
        out[5 * i + 1] = (uint8_t)(((c1 >> 3) & 0x03) | ((c2 & 0x1F) << 2) | ((c3 & 0x01) << 7));
        out[5 * i + 2] = (uint8_t)(((c3 >> 1) & 0x0F) | ((c4 & 0x0F) << 4));
        out[5 * i + 3] = (uint8_t)(((c4 >> 4) & 0x01) | ((c5 & 0x1F) << 1) | ((c6 & 0x03) << 6));
        out[5 * i + 4] = (uint8_t)(((c6 >> 2) & 0x07) | ((c7 & 0x1F) << 3));
    }
}

static void poly_decompress_dv5(int16_t a[256], const uint8_t in[160]) {
    for (int i = 0; i < 32; i++) {
        const uint8_t *b = &in[5 * i];
        uint8_t c0 = b[0] & 0x1F;
        uint8_t c1 = (b[0] >> 5) | ((b[1] & 0x03) << 3);
        uint8_t c2 = (b[1] >> 2) & 0x1F;
        uint8_t c3 = (b[1] >> 7) | ((b[2] & 0x0F) << 1);
        uint8_t c4 = (b[2] >> 4) | ((b[3] & 0x01) << 4);
        uint8_t c5 = (b[3] >> 1) & 0x1F;
        uint8_t c6 = (b[3] >> 6) | ((b[4] & 0x07) << 2);
        uint8_t c7 = (b[4] >> 3) & 0x1F;

        a[8 * i + 0] = decompress_d(c0, 5);
        a[8 * i + 1] = decompress_d(c1, 5);
        a[8 * i + 2] = decompress_d(c2, 5);
        a[8 * i + 3] = decompress_d(c3, 5);
        a[8 * i + 4] = decompress_d(c4, 5);
        a[8 * i + 5] = decompress_d(c5, 5);
        a[8 * i + 6] = decompress_d(c6, 5);
        a[8 * i + 7] = decompress_d(c7, 5);
    }
}

static void poly_frommsg(int16_t a[256], const uint8_t m[32]) {
    for (int i = 0; i < 32; i++) {
        for (int bit = 0; bit < 8; bit++) {
            uint8_t b = (m[i] >> bit) & 1;
            a[8 * i + bit] = (int16_t)(b ? 1665 : 0);
        }
    }
}

static void poly_tomsg(uint8_t m[32], const int16_t a[256]) {
    memset(m, 0, 32);
    for (int i = 0; i < 32; i++) {
        for (int bit = 0; bit < 8; bit++) {
            uint16_t bit_val = compress_d(a[8 * i + bit], 1);
            m[i] |= (uint8_t)(bit_val << bit);
        }
    }
}

/* ==================== Generic K-PKE Internal Functions ==================== */

static void kpke_keygen(uint8_t *pk, uint8_t *sk, const uint8_t d[32], int k_val) {
    uint8_t d_k[33];
    memcpy(d_k, d, 32);
    d_k[32] = (uint8_t)k_val;

    uint8_t g_out[64];
    sha3_512(d_k, 33, g_out);
    const uint8_t *rho = g_out;
    const uint8_t *sigma = g_out + 32;

    int16_t s_hat[4][256];
    int16_t e_hat[4][256];
    uint8_t prf_buf[128];

    for (int i = 0; i < k_val; i++) {
        prf_eta2(prf_buf, sigma, (uint8_t)i);
        sample_cbd2(s_hat[i], prf_buf);
        ntt(s_hat[i]);
    }

    for (int i = 0; i < k_val; i++) {
        prf_eta2(prf_buf, sigma, (uint8_t)(k_val + i));
        sample_cbd2(e_hat[i], prf_buf);
        ntt(e_hat[i]);
    }

    /* t_hat[i] = sum_j A_hat[i][j] * s_hat[j] + e_hat[i] */
    int16_t t_hat[4][256];
    int16_t A_elem[256];
    int16_t prod[256];

    for (int i = 0; i < k_val; i++) {
        memset(t_hat[i], 0, sizeof(t_hat[i]));
        for (int j = 0; j < k_val; j++) {
            /* Note: matrix ordering is (j, i) as verified against FIPS 203 */
            sample_ntt(A_elem, rho, (uint8_t)j, (uint8_t)i);
            multiply_ntts(prod, A_elem, s_hat[j]);
            for (int p = 0; p < 256; p++) {
                t_hat[i][p] = fq_mod((int32_t)t_hat[i][p] + prod[p]);
            }
        }
        for (int p = 0; p < 256; p++) {
            t_hat[i][p] = fq_mod((int32_t)t_hat[i][p] + e_hat[i][p]);
        }
    }

    /* Encode pk = ByteEncode12(t_hat) || rho */
    for (int i = 0; i < k_val; i++) {
        byte_encode12(pk + 384 * i, t_hat[i]);
    }
    memcpy(pk + 384 * k_val, rho, 32);

    /* Encode sk (dk_pke) = ByteEncode12(s_hat) */
    for (int i = 0; i < k_val; i++) {
        byte_encode12(sk + 384 * i, s_hat[i]);
    }
}

static void kpke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t m[32], const uint8_t r[32],
                         int k_val, int d_u, int d_v) {
    int16_t t_hat[4][256];
    for (int i = 0; i < k_val; i++) {
        byte_decode12(t_hat[i], pk + 384 * i);
    }
    const uint8_t *rho = pk + 384 * k_val;

    int16_t y[4][256];
    int16_t e1[4][256];
    int16_t e2[256];
    uint8_t prf_buf[128];

    for (int i = 0; i < k_val; i++) {
        prf_eta2(prf_buf, r, (uint8_t)i);
        sample_cbd2(y[i], prf_buf);
        ntt(y[i]);
    }
    for (int i = 0; i < k_val; i++) {
        prf_eta2(prf_buf, r, (uint8_t)(k_val + i));
        sample_cbd2(e1[i], prf_buf);
    }
    prf_eta2(prf_buf, r, (uint8_t)(2 * k_val));
    sample_cbd2(e2, prf_buf);

    /* u = NTT^-1(A_hat^T * y) + e1 */
    int16_t A_elem[256];
    int16_t prod[256];
    int16_t u[4][256];

    for (int i = 0; i < k_val; i++) {
        int16_t poly_acc[256] = {0};
        for (int j = 0; j < k_val; j++) {
            sample_ntt(A_elem, rho, (uint8_t)i, (uint8_t)j);
            multiply_ntts(prod, A_elem, y[j]);
            for (int p = 0; p < 256; p++) {
                poly_acc[p] = fq_mod((int32_t)poly_acc[p] + prod[p]);
            }
        }
        ntt_inv(poly_acc);
        for (int p = 0; p < 256; p++) {
            u[i][p] = fq_mod((int32_t)poly_acc[p] + e1[i][p]);
        }
    }

    /* v = NTT^-1(t_hat^T * y) + e2 + mu */
    int16_t v_acc[256] = {0};
    for (int j = 0; j < k_val; j++) {
        multiply_ntts(prod, t_hat[j], y[j]);
        for (int p = 0; p < 256; p++) {
            v_acc[p] = fq_mod((int32_t)v_acc[p] + prod[p]);
        }
    }
    ntt_inv(v_acc);

    int16_t mu[256];
    poly_frommsg(mu, m);
    for (int p = 0; p < 256; p++) {
        v_acc[p] = fq_mod((int32_t)v_acc[p] + e2[p] + mu[p]);
    }

    /* Compress and pack ciphertext */
    if (d_u == 10) {
        for (int i = 0; i < k_val; i++) {
            poly_compress_du10(ct + 320 * i, u[i]);
        }
    } else {
        for (int i = 0; i < k_val; i++) {
            poly_compress_du11(ct + 352 * i, u[i]);
        }
    }

    size_t c1_len = (size_t)32 * d_u * k_val;
    if (d_v == 4) {
        poly_compress_dv4(ct + c1_len, v_acc);
    } else {
        poly_compress_dv5(ct + c1_len, v_acc);
    }
}

static void kpke_decrypt(uint8_t m[32], const uint8_t *sk_pke, const uint8_t *ct,
                         int k_val, int d_u, int d_v) {
    int16_t s_hat[4][256];
    for (int i = 0; i < k_val; i++) {
        byte_decode12(s_hat[i], sk_pke + 384 * i);
    }

    int16_t u[4][256];
    if (d_u == 10) {
        for (int i = 0; i < k_val; i++) {
            poly_decompress_du10(u[i], ct + 320 * i);
            ntt(u[i]);
        }
    } else {
        for (int i = 0; i < k_val; i++) {
            poly_decompress_du11(u[i], ct + 352 * i);
            ntt(u[i]);
        }
    }

    size_t c1_len = (size_t)32 * d_u * k_val;
    int16_t v[256];
    if (d_v == 4) {
        poly_decompress_dv4(v, ct + c1_len);
    } else {
        poly_decompress_dv5(v, ct + c1_len);
    }

    /* su = NTT^-1(sum_j s_hat[j] * u_hat[j]) */
    int16_t su_acc[256] = {0};
    int16_t prod[256];
    for (int j = 0; j < k_val; j++) {
        multiply_ntts(prod, s_hat[j], u[j]);
        for (int p = 0; p < 256; p++) {
            su_acc[p] = fq_mod((int32_t)su_acc[p] + prod[p]);
        }
    }
    ntt_inv(su_acc);

    int16_t w[256];
    for (int p = 0; p < 256; p++) {
        w[p] = fq_mod((int32_t)v[p] - su_acc[p]);
    }

    poly_tomsg(m, w);
}

/* Constant-time buffer comparison: returns 0 on match, non-zero on mismatch */
static int ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *p1 = (const uint8_t *)a;
    const uint8_t *p2 = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (p1[i] ^ p2[i]);
    }
    return diff;
}

/* ==================== ML-KEM-768 API ==================== */

int mlkem768_keygen_internal(uint8_t pk[MLKEM768_PUBLICKEYBYTES],
                             uint8_t sk[MLKEM768_SECRETKEYBYTES],
                             const uint8_t d[32],
                             const uint8_t z[32]) {
    /* Step 1: K-PKE.KeyGen */
    kpke_keygen(pk, sk, d, MLKEM768_K);

    /* Full sk = dk_pke (1152) || ek (1184) || H(ek) (32) || z (32) */
    memcpy(sk + 384 * MLKEM768_K, pk, MLKEM768_PUBLICKEYBYTES);

    uint8_t h_ek[32];
    sha3_256(pk, MLKEM768_PUBLICKEYBYTES, h_ek);
    memcpy(sk + 384 * MLKEM768_K + MLKEM768_PUBLICKEYBYTES, h_ek, 32);

    memcpy(sk + 384 * MLKEM768_K + MLKEM768_PUBLICKEYBYTES + 32, z, 32);
    return 0;
}

int mlkem768_encaps_internal(uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                             uint8_t ss[32],
                             const uint8_t pk[MLKEM768_PUBLICKEYBYTES],
                             const uint8_t m[32]) {
    uint8_t h_ek[32];
    sha3_256(pk, MLKEM768_PUBLICKEYBYTES, h_ek);

    uint8_t m_h[64];
    memcpy(m_h, m, 32);
    memcpy(m_h + 32, h_ek, 32);

    uint8_t g_out[64];
    sha3_512(m_h, 64, g_out);
    const uint8_t *K = g_out;
    const uint8_t *r = g_out + 32;

    kpke_encrypt(ct, pk, m, r, MLKEM768_K, 10, 4);
    memcpy(ss, K, 32);
    return 0;
}

int mlkem768_decaps_internal(uint8_t ss[32],
                             const uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                             const uint8_t sk[MLKEM768_SECRETKEYBYTES]) {
    const uint8_t *dk_pke = sk;
    const uint8_t *ek = sk + 384 * MLKEM768_K;
    const uint8_t *h_ek = ek + MLKEM768_PUBLICKEYBYTES;
    const uint8_t *z = h_ek + 32;

    uint8_t m_prime[32];
    kpke_decrypt(m_prime, dk_pke, ct, MLKEM768_K, 10, 4);

    uint8_t m_h[64];
    memcpy(m_h, m_prime, 32);
    memcpy(m_h + 32, h_ek, 32);

    uint8_t g_out[64];
    sha3_512(m_h, 64, g_out);
    const uint8_t *K_prime = g_out;
    const uint8_t *r_prime = g_out + 32;

    /* Implicit rejection key K_bar = SHAKE256(z || ct, 32) */
    shake256_ctx j_ctx;
    shake256_init(&j_ctx);
    shake256_absorb(&j_ctx, z, 32);
    shake256_absorb(&j_ctx, ct, MLKEM768_CIPHERTEXTBYTES);
    shake256_finalize(&j_ctx);
    uint8_t K_bar[32];
    shake256_squeeze(&j_ctx, K_bar, 32);

    /* Re-encrypt */
    uint8_t ct_prime[MLKEM768_CIPHERTEXTBYTES];
    kpke_encrypt(ct_prime, ek, m_prime, r_prime, MLKEM768_K, 10, 4);

    int diff = ct_memcmp(ct, ct_prime, MLKEM768_CIPHERTEXTBYTES);
    /* Constant-time select: if diff == 0 ss = K_prime, else ss = K_bar */
    uint8_t mask = (diff == 0) ? 0xFF : 0x00;
    for (int i = 0; i < 32; i++) {
        ss[i] = (K_prime[i] & mask) | (K_bar[i] & ~mask);
    }
    return 0;
}

/* ==================== ML-KEM-1024 API ==================== */

int mlkem1024_keygen_internal(uint8_t pk[MLKEM1024_PUBLICKEYBYTES],
                              uint8_t sk[MLKEM1024_SECRETKEYBYTES],
                              const uint8_t d[32],
                              const uint8_t z[32]) {
    kpke_keygen(pk, sk, d, MLKEM1024_K);

    memcpy(sk + 384 * MLKEM1024_K, pk, MLKEM1024_PUBLICKEYBYTES);

    uint8_t h_ek[32];
    sha3_256(pk, MLKEM1024_PUBLICKEYBYTES, h_ek);
    memcpy(sk + 384 * MLKEM1024_K + MLKEM1024_PUBLICKEYBYTES, h_ek, 32);

    memcpy(sk + 384 * MLKEM1024_K + MLKEM1024_PUBLICKEYBYTES + 32, z, 32);
    return 0;
}

int mlkem1024_encaps_internal(uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                              uint8_t ss[32],
                              const uint8_t pk[MLKEM1024_PUBLICKEYBYTES],
                              const uint8_t m[32]) {
    uint8_t h_ek[32];
    sha3_256(pk, MLKEM1024_PUBLICKEYBYTES, h_ek);

    uint8_t m_h[64];
    memcpy(m_h, m, 32);
    memcpy(m_h + 32, h_ek, 32);

    uint8_t g_out[64];
    sha3_512(m_h, 64, g_out);
    const uint8_t *K = g_out;
    const uint8_t *r = g_out + 32;

    kpke_encrypt(ct, pk, m, r, MLKEM1024_K, 11, 5);
    memcpy(ss, K, 32);
    return 0;
}

int mlkem1024_decaps_internal(uint8_t ss[32],
                              const uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                              const uint8_t sk[MLKEM1024_SECRETKEYBYTES]) {
    const uint8_t *dk_pke = sk;
    const uint8_t *ek = sk + 384 * MLKEM1024_K;
    const uint8_t *h_ek = ek + MLKEM1024_PUBLICKEYBYTES;
    const uint8_t *z = h_ek + 32;

    uint8_t m_prime[32];
    kpke_decrypt(m_prime, dk_pke, ct, MLKEM1024_K, 11, 5);

    uint8_t m_h[64];
    memcpy(m_h, m_prime, 32);
    memcpy(m_h + 32, h_ek, 32);

    uint8_t g_out[64];
    sha3_512(m_h, 64, g_out);
    const uint8_t *K_prime = g_out;
    const uint8_t *r_prime = g_out + 32;

    shake256_ctx j_ctx;
    shake256_init(&j_ctx);
    shake256_absorb(&j_ctx, z, 32);
    shake256_absorb(&j_ctx, ct, MLKEM1024_CIPHERTEXTBYTES);
    shake256_finalize(&j_ctx);
    uint8_t K_bar[32];
    shake256_squeeze(&j_ctx, K_bar, 32);

    uint8_t ct_prime[MLKEM1024_CIPHERTEXTBYTES];
    kpke_encrypt(ct_prime, ek, m_prime, r_prime, MLKEM1024_K, 11, 5);

    int diff = ct_memcmp(ct, ct_prime, MLKEM1024_CIPHERTEXTBYTES);
    uint8_t mask = (diff == 0) ? 0xFF : 0x00;
    for (int i = 0; i < 32; i++) {
        ss[i] = (K_prime[i] & mask) | (K_bar[i] & ~mask);
    }
    return 0;
}

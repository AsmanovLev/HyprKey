#include "mldsa.h"
#include "../fips202/fips202.h"
#include <string.h>

#define Q 8380417
#define D 13
#define N 256

static const int32_t zetas[256] = {
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
    394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
    348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
    1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
    6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
    3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
};

typedef struct {
    int32_t coeffs[N];
} poly;

/* Modular reduction to canonical range [0, Q-1] */
static inline int32_t modq(int64_t a) {
    int32_t r = (int32_t)(a % Q);
    if (r < 0) r += Q;
    return r;
}

/* Forward NTT */
static void poly_ntt(poly *p) {
    int k = 0;
    for (int l = 128; l > 0; l >>= 1) {
        int start = 0;
        while (start < 256) {
            k++;
            int32_t zeta = zetas[k];
            for (int j = start; j < start + l; j++) {
                int64_t t = (int64_t)zeta * p->coeffs[j + l];
                int32_t t_mod = (int32_t)(t % Q);
                if (t_mod < 0) t_mod += Q;

                int32_t pj = p->coeffs[j];
                int32_t sub = pj - t_mod;
                if (sub < 0) sub += Q;

                int32_t add = pj + t_mod;
                if (add >= Q) add -= Q;

                p->coeffs[j + l] = sub;
                p->coeffs[j] = add;
            }
            start += 2 * l;
        }
    }
}

/* Inverse NTT */
static void poly_invntt(poly *p) {
    int k = 256;
    for (int l = 1; l < 256; l <<= 1) {
        int start = 0;
        while (start < 256) {
            k--;
            int32_t zeta = Q - zetas[k];
            for (int j = start; j < start + l; j++) {
                int32_t pj = p->coeffs[j];
                int32_t pjl = p->coeffs[j + l];

                int32_t add = pj + pjl;
                if (add >= Q) add -= Q;

                int32_t sub = pj - pjl;
                if (sub < 0) sub += Q;

                int64_t t = (int64_t)zeta * sub;
                int32_t t_mod = (int32_t)(t % Q);
                if (t_mod < 0) t_mod += Q;

                p->coeffs[j] = add;
                p->coeffs[j + l] = t_mod;
            }
            start += 2 * l;
        }
    }

    /* Multiply by n^-1 mod Q (256^-1 mod 8380417 = 8347681) */
    const int64_t f = 8347681;
    for (int i = 0; i < N; i++) {
        p->coeffs[i] = (int32_t)(((int64_t)p->coeffs[i] * f) % Q);
    }
}

/* Pointwise multiplication in NTT domain */
static void poly_pointwise(poly *out, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        out->coeffs[i] = (int32_t)(((int64_t)a->coeffs[i] * b->coeffs[i]) % Q);
    }
}

static void poly_add(poly *out, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        int32_t s = a->coeffs[i] + b->coeffs[i];
        if (s >= Q) s -= Q;
        out->coeffs[i] = s;
    }
}

static void poly_sub(poly *out, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        int32_t s = a->coeffs[i] - b->coeffs[i];
        if (s < 0) s += Q;
        out->coeffs[i] = s;
    }
}

/* Rejection sampling of NTT polynomial from seed (SHAKE128) */
static void poly_uniform(poly *p, const uint8_t rho[32], uint8_t i, uint8_t j) {
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, rho, 32);
    uint8_t idx[2] = { j, i }; /* Note: j (column) then i (row) */
    shake128_absorb(&ctx, idx, 2);
    shake128_finalize(&ctx);

    int count = 0;
    while (count < N) {
        uint8_t buf[3];
        shake128_squeeze(&ctx, buf, 3);
        uint32_t val = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | (((uint32_t)buf[2] & 0x7F) << 16);
        if (val < Q) {
            p->coeffs[count++] = (int32_t)val;
        }
    }
}

/* Rejection sampling of bounded secret polynomial from seed (SHAKE256) */
static void poly_uniform_eta(poly *p, const uint8_t rho_prime[64], uint16_t idx, int eta) {
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, rho_prime, 64);
    uint8_t idx_bytes[2] = { (uint8_t)(idx & 0xFF), (uint8_t)(idx >> 8) };
    shake256_absorb(&ctx, idx_bytes, 2);
    shake256_finalize(&ctx);

    int count = 0;
    while (count < N) {
        uint8_t byte;
        shake256_squeeze(&ctx, &byte, 1);
        uint8_t t0 = byte & 0x0F;
        uint8_t t1 = byte >> 4;

        if (eta == 2) {
            if (t0 < 15) {
                int32_t c = 2 - (int32_t)(t0 % 5);
                p->coeffs[count++] = (c < 0) ? (c + Q) : c;
                if (count == N) break;
            }
            if (t1 < 15) {
                int32_t c = 2 - (int32_t)(t1 % 5);
                p->coeffs[count++] = (c < 0) ? (c + Q) : c;
                if (count == N) break;
            }
        } else { /* eta == 4 */
            if (t0 < 9) {
                int32_t c = 4 - (int32_t)t0;
                p->coeffs[count++] = (c < 0) ? (c + Q) : c;
                if (count == N) break;
            }
            if (t1 < 9) {
                int32_t c = 4 - (int32_t)t1;
                p->coeffs[count++] = (c < 0) ? (c + Q) : c;
                if (count == N) break;
            }
        }
    }
}

/* Sample masking polynomial gamma1 from seed */
static void poly_uniform_gamma1(poly *p, const uint8_t rho_prime[64], uint16_t idx, int32_t gamma_1) {
    int bit_count = (gamma_1 == (1 << 17)) ? 18 : 20;
    size_t total_bytes = (N * bit_count) / 8; /* 576 or 640 */

    uint8_t buf[640];
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, rho_prime, 64);
    uint8_t idx_bytes[2] = { (uint8_t)(idx & 0xFF), (uint8_t)(idx >> 8) };
    shake256_absorb(&ctx, idx_bytes, 2);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, buf, total_bytes);

    /* Unpack bits into coefficients */
    uint32_t mask = (1UL << bit_count) - 1;
    for (int i = 0; i < N; i++) {
        size_t bit_offset = (size_t)i * bit_count;
        size_t byte_offset = bit_offset / 8;
        int bit_shift = bit_offset % 8;

        uint32_t raw = (uint32_t)buf[byte_offset] |
                       ((uint32_t)buf[byte_offset + 1] << 8) |
                       ((uint32_t)buf[byte_offset + 2] << 16);
        if (bit_shift + bit_count > 24) {
            raw |= ((uint32_t)buf[byte_offset + 3] << 24);
        }
        uint32_t val = (raw >> bit_shift) & mask;
        int32_t c = gamma_1 - (int32_t)val;
        p->coeffs[i] = (c < 0) ? (c + Q) : c;
    }
}

/* Sample in ball */
static void sample_in_ball(poly *c, const uint8_t *seed, size_t seed_len, int tau) {
    memset(c->coeffs, 0, sizeof(c->coeffs));

    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, seed, seed_len);
    shake256_finalize(&ctx);

    uint8_t sign_bytes[8];
    shake256_squeeze(&ctx, sign_bytes, 8);
    uint64_t sign_int = 0;
    for (int b = 0; b < 8; b++) {
        sign_int |= ((uint64_t)sign_bytes[b]) << (b * 8);
    }

    for (int i = 256 - tau; i < 256; i++) {
        uint8_t j;
        do {
            shake256_squeeze(&ctx, &j, 1);
        } while (j > i);

        c->coeffs[i] = c->coeffs[j];
        int32_t val = (sign_int & 1) ? (Q - 1) : 1;
        sign_int >>= 1;
        c->coeffs[j] = val;
    }
}

/* Power2Round */
static void power2round(int32_t r, int32_t *r1, int32_t *r0) {
    int32_t rp = r % Q;
    if (rp < 0) rp += Q;

    int32_t r0_val = rp % 8192;
    if (r0_val > 4096) r0_val -= 8192;

    *r0 = r0_val;
    *r1 = (rp - r0_val) >> D;
}

/* Decompose */
static void decompose(int32_t r, int32_t alpha, int32_t *r1, int32_t *r0) {
    int32_t rp = r % Q;
    if (rp < 0) rp += Q;

    int32_t r0_val = rp % alpha;
    if (r0_val > (alpha >> 1)) r0_val -= alpha;

    if (rp - r0_val == Q - 1) {
        *r1 = 0;
        *r0 = r0_val - 1;
    } else {
        *r1 = (rp - r0_val) / alpha;
        *r0 = r0_val;
    }
}

static inline int32_t high_bits(int32_t r, int32_t alpha) {
    int32_t r1, r0;
    decompose(r, alpha, &r1, &r0);
    return r1;
}

static inline int32_t low_bits(int32_t r, int32_t alpha) {
    int32_t r1, r0;
    decompose(r, alpha, &r1, &r0);
    return r0;
}

static inline int make_hint(int32_t z, int32_t r, int32_t alpha) {
    int32_t r1 = high_bits(r, alpha);
    int32_t v1 = high_bits(modq((int64_t)r + z), alpha);
    return (r1 != v1) ? 1 : 0;
}

static inline int check_norm_bound(int32_t n, int32_t bound) {
    int32_t x = n % Q;
    if (x < 0) x += Q;
    if (x > (Q - 1) / 2) x = Q - x;
    return (x >= bound);
}

/* ==================== Bit Packing ==================== */
static void bit_pack_poly(uint8_t *out, const int32_t *coeffs, int n_bits, size_t n_bytes) {
    memset(out, 0, n_bytes);
    for (int i = 0; i < N; i++) {
        uint32_t val = (uint32_t)coeffs[i] & ((1UL << n_bits) - 1);
        size_t bit_offset = (size_t)i * n_bits;
        size_t byte_offset = bit_offset / 8;
        int bit_shift = bit_offset % 8;

        out[byte_offset] |= (uint8_t)(val << bit_shift);
        if (bit_shift + n_bits > 8) {
            out[byte_offset + 1] |= (uint8_t)(val >> (8 - bit_shift));
        }
        if (bit_shift + n_bits > 16) {
            out[byte_offset + 2] |= (uint8_t)(val >> (16 - bit_shift));
        }
    }
}

static void __attribute__((unused)) bit_unpack_poly(int32_t *coeffs, const uint8_t *in, int n_bits) {
    uint32_t mask = (1UL << n_bits) - 1;
    for (int i = 0; i < N; i++) {
        size_t bit_offset = (size_t)i * n_bits;
        size_t byte_offset = bit_offset / 8;
        int bit_shift = bit_offset % 8;

        uint32_t raw = (uint32_t)in[byte_offset] |
                       ((uint32_t)in[byte_offset + 1] << 8);
        if (bit_shift + n_bits > 16) {
            raw |= ((uint32_t)in[byte_offset + 2] << 16);
        }
        coeffs[i] = (int32_t)((raw >> bit_shift) & mask);
    }
}

static void pack_t1(uint8_t *out, const poly *t1, int k) {
    for (int i = 0; i < k; i++) {
        bit_pack_poly(out + i * 320, t1[i].coeffs, 10, 320);
    }
}

static void pack_z(uint8_t *out, const poly *z, int l, int32_t gamma_1) {
    int n_bits = (gamma_1 == (1 << 17)) ? 18 : 20;
    size_t poly_bytes = (N * n_bits) / 8; /* 576 or 640 */

    for (int i = 0; i < l; i++) {
        int32_t altered[N];
        for (int j = 0; j < N; j++) {
            int32_t c = modq((int64_t)gamma_1 - z[i].coeffs[j]);
            altered[j] = c;
        }
        bit_pack_poly(out + i * poly_bytes, altered, n_bits, poly_bytes);
    }
}

static void pack_w(uint8_t *out, const poly *w1, int k, int32_t gamma_2) {
    int n_bits = (gamma_2 == 95232) ? 6 : 4;
    size_t poly_bytes = (N * n_bits) / 8; /* 192 or 128 */

    for (int i = 0; i < k; i++) {
        bit_pack_poly(out + i * poly_bytes, w1[i].coeffs, n_bits, poly_bytes);
    }
}

static void pack_hints(uint8_t *out, const poly *h, int k, int omega) {
    memset(out, 0, omega + k);
    int pos = 0;
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < N; j++) {
            if (h[i].coeffs[j] != 0) {
                out[pos++] = (uint8_t)j;
            }
        }
        out[omega + i] = (uint8_t)pos;
    }
}

/* ==================== KeyGen & Sign Core ==================== */

typedef struct {
    poly s1_hat[7];
    poly s2_hat[8];
    poly t0_hat[8];
    poly y[7];
    poly y_hat[7];
    poly w[8];
    poly w1[8];
    poly cs2[8];
    poly ct0[8];
} mldsa_work_t;

static mldsa_work_t s_mldsa_work;

static int mldsa_keygen_internal(const uint8_t seed[32], uint8_t *pk, uint8_t *sk,
                                 int k, int l, int eta) {
    /* 1. Expand seed: H(seed || k || l, 128) */
    uint8_t domain_sep[34];
    memcpy(domain_sep, seed, 32);
    domain_sep[32] = (uint8_t)k;
    domain_sep[33] = (uint8_t)l;

    uint8_t seed_bytes[128];
    shake256(domain_sep, 34, seed_bytes, 128);

    const uint8_t *rho = seed_bytes;        /* 32 bytes */
    const uint8_t *rho_prime = seed_bytes + 32; /* 64 bytes */
    const uint8_t *K = seed_bytes + 96;     /* 32 bytes */

    poly *s1     = s_mldsa_work.y;
    poly *s2     = s_mldsa_work.cs2;
    poly *s1_hat = s_mldsa_work.s1_hat;
    poly *t1     = s_mldsa_work.w;
    poly *t0     = s_mldsa_work.t0_hat;

    /* 2. Sample secrets s1 in R^l and s2 in R^k */
    for (int i = 0; i < l; i++) {
        poly_uniform_eta(&s1[i], rho_prime, (uint16_t)i, eta);
        s1_hat[i] = s1[i];
        poly_ntt(&s1_hat[i]);
    }
    for (int i = 0; i < k; i++) {
        poly_uniform_eta(&s2[i], rho_prime, (uint16_t)(l + i), eta);
    }

    /* 4. Matrix A (k x l) in NTT domain, compute t = A * s1 + s2 */
    for (int r = 0; r < k; r++) {
        poly t_row;
        memset(&t_row, 0, sizeof(t_row));

        for (int c = 0; c < l; c++) {
            poly A_elem;
            poly_uniform(&A_elem, rho, (uint8_t)r, (uint8_t)c);
            poly prod;
            poly_pointwise(&prod, &A_elem, &s1_hat[c]);
            poly_add(&t_row, &t_row, &prod);
        }

        poly_invntt(&t_row);
        poly_add(&t_row, &t_row, &s2[r]);

        for (int j = 0; j < N; j++) {
            power2round(t_row.coeffs[j], &t1[r].coeffs[j], &t0[r].coeffs[j]);
        }
    }

    /* 5. Pack pk = rho (32) || t1 (320 * k) */
    memcpy(pk, rho, 32);
    pack_t1(pk + 32, t1, k);

    /* 6. If sk requested, pack sk */
    if (sk != NULL) {
        /* sk = rho(32) || K(32) || tr(64) || s1 || s2 || t0 */
        memcpy(sk, rho, 32);
        memcpy(sk + 32, K, 32);

        uint8_t tr[64];
        shake256(pk, 32 + 320 * k, tr, 64);
        memcpy(sk + 64, tr, 64);

        size_t off = 128;
        int s_bits = (eta == 2) ? 3 : 4;
        size_t s_bytes = (N * s_bits) / 8; /* 96 or 128 */

        for (int i = 0; i < l; i++) {
            int32_t altered[N];
            for (int j = 0; j < N; j++) altered[j] = modq((int64_t)eta - s1[i].coeffs[j]);
            bit_pack_poly(sk + off, altered, s_bits, s_bytes);
            off += s_bytes;
        }

        for (int i = 0; i < k; i++) {
            int32_t altered[N];
            for (int j = 0; j < N; j++) altered[j] = modq((int64_t)eta - s2[i].coeffs[j]);
            bit_pack_poly(sk + off, altered, s_bits, s_bytes);
            off += s_bytes;
        }

        for (int i = 0; i < k; i++) {
            int32_t altered[N];
            for (int j = 0; j < N; j++) altered[j] = (1 << 12) - t0[i].coeffs[j];
            bit_pack_poly(sk + off, altered, 13, 416);
            off += 416;
        }
    }

    memset(&s_mldsa_work, 0, sizeof(s_mldsa_work));
    return 0;
}

static int mldsa_sign_seed_internal(const uint8_t seed[32], const uint8_t *msg, size_t msglen,
                                    const uint8_t rnd[32], uint8_t *sig,
                                    int k, int l, int eta, int tau, int beta,
                                    int32_t gamma_1, int32_t gamma_2, int omega,
                                    size_t c_tilde_bytes) {
    /* 1. Generate key components from seed */
    uint8_t domain_sep[34];
    memcpy(domain_sep, seed, 32);
    domain_sep[32] = (uint8_t)k;
    domain_sep[33] = (uint8_t)l;

    uint8_t seed_bytes[128];
    shake256(domain_sep, 34, seed_bytes, 128);

    const uint8_t *rho = seed_bytes;
    const uint8_t *rho_prime = seed_bytes + 32;
    const uint8_t *K = seed_bytes + 96;

    poly *s1_hat = s_mldsa_work.s1_hat;
    poly *s2_hat = s_mldsa_work.s2_hat;
    poly *t0_hat = s_mldsa_work.t0_hat;
    poly *t1     = s_mldsa_work.w;      /* w temporarily holds t1 */

    for (int i = 0; i < l; i++) {
        poly_uniform_eta(&s1_hat[i], rho_prime, (uint16_t)i, eta);
        poly_ntt(&s1_hat[i]);
    }
    for (int i = 0; i < k; i++) {
        poly_uniform_eta(&s2_hat[i], rho_prime, (uint16_t)(l + i), eta);
    }

    /* Compute t0 & t1 */
    for (int r = 0; r < k; r++) {
        poly t_row;
        memset(&t_row, 0, sizeof(t_row));
        for (int c = 0; c < l; c++) {
            poly A_elem;
            poly_uniform(&A_elem, rho, (uint8_t)r, (uint8_t)c);
            poly prod;
            poly_pointwise(&prod, &A_elem, &s1_hat[c]);
            poly_add(&t_row, &t_row, &prod);
        }
        poly_invntt(&t_row);
        poly_add(&t_row, &t_row, &s2_hat[r]);

        for (int j = 0; j < N; j++) {
            int32_t t0_c;
            power2round(t_row.coeffs[j], &t1[r].coeffs[j], &t0_c);
            t0_hat[r].coeffs[j] = (t0_c < 0) ? (t0_c + Q) : t0_c;
        }
        poly_ntt(&t0_hat[r]);
        poly_ntt(&s2_hat[r]);
    }

    /* Compute tr = SHAKE256(pk, 64) */
    uint8_t pk_buf[32 + 320 * 8];
    memcpy(pk_buf, rho, 32);
    pack_t1(pk_buf + 32, t1, k);
    uint8_t tr[64];
    shake256(pk_buf, 32 + 320 * k, tr, 64);

    /* Formatted message M' = 0x00 || 0x00 || msg (for pure mode with empty context) */
    /* mu = SHAKE256(tr || M', 64) */
    shake256_ctx mu_ctx;
    shake256_init(&mu_ctx);
    shake256_absorb(&mu_ctx, tr, 64);
    uint8_t ctx_prefix[2] = { 0x00, 0x00 };
    shake256_absorb(&mu_ctx, ctx_prefix, 2);
    shake256_absorb(&mu_ctx, msg, msglen);
    shake256_finalize(&mu_ctx);
    uint8_t mu[64];
    shake256_squeeze(&mu_ctx, mu, 64);

    /* rho_prime_sig = SHAKE256(K || rnd || mu, 64) */
    uint8_t zero_rnd[32] = { 0 };
    const uint8_t *use_rnd = (rnd != NULL) ? rnd : zero_rnd;

    shake256_ctx sig_seed_ctx;
    shake256_init(&sig_seed_ctx);
    shake256_absorb(&sig_seed_ctx, K, 32);
    shake256_absorb(&sig_seed_ctx, use_rnd, 32);
    shake256_absorb(&sig_seed_ctx, mu, 64);
    shake256_finalize(&sig_seed_ctx);
    uint8_t rho_prime_sig[64];
    shake256_squeeze(&sig_seed_ctx, rho_prime_sig, 64);

    int32_t alpha = gamma_2 << 1;
    uint16_t kappa = 0;

    poly *y     = s_mldsa_work.y;
    poly *y_hat = s_mldsa_work.y_hat;
    poly *w     = s_mldsa_work.w;
    poly *w1    = s_mldsa_work.w1;
    poly *cs2   = s_mldsa_work.cs2;
    poly *ct0   = s_mldsa_work.ct0;

    /* Rejection sampling loop */
    while (1) {
        /* Sample y in R^l */
        for (int i = 0; i < l; i++) {
            poly_uniform_gamma1(&y[i], rho_prime_sig, kappa + (uint16_t)i, gamma_1);
            y_hat[i] = y[i];
            poly_ntt(&y_hat[i]);
        }
        kappa += (uint16_t)l;

        /* w = A * y */
        for (int r = 0; r < k; r++) {
            memset(&w[r], 0, sizeof(w[r]));
            for (int c = 0; c < l; c++) {
                poly A_elem;
                poly_uniform(&A_elem, rho, (uint8_t)r, (uint8_t)c);
                poly prod;
                poly_pointwise(&prod, &A_elem, &y_hat[c]);
                poly_add(&w[r], &w[r], &prod);
            }
            poly_invntt(&w[r]);

            for (int j = 0; j < N; j++) {
                w1[r].coeffs[j] = high_bits(w[r].coeffs[j], alpha);
            }
        }

        /* c_tilde = SHAKE256(mu || w1_packed, c_tilde_bytes) */
        uint8_t w1_packed[192 * 8];
        pack_w(w1_packed, w1, k, gamma_2);

        shake256_ctx c_ctx;
        shake256_init(&c_ctx);
        shake256_absorb(&c_ctx, mu, 64);
        size_t w1_bytes = (k * N * ((gamma_2 == 95232) ? 6 : 4)) / 8;
        shake256_absorb(&c_ctx, w1_packed, w1_bytes);
        shake256_finalize(&c_ctx);

        uint8_t c_tilde[64];
        shake256_squeeze(&c_ctx, c_tilde, c_tilde_bytes);

        /* c = SampleInBall(c_tilde, tau) */
        poly c_poly, c_hat;
        sample_in_ball(&c_poly, c_tilde, c_tilde_bytes, tau);
        c_hat = c_poly;
        poly_ntt(&c_hat);

        /* z = y + c * s1 */
        poly z[7];
        int z_fail = 0;
        for (int i = 0; i < l; i++) {
            poly cs1;
            poly_pointwise(&cs1, &s1_hat[i], &c_hat);
            poly_invntt(&cs1);
            poly_add(&z[i], &y[i], &cs1);

            for (int j = 0; j < N; j++) {
                if (check_norm_bound(z[i].coeffs[j], gamma_1 - beta)) {
                    z_fail = 1;
                    break;
                }
            }
            if (z_fail) break;
        }
        if (z_fail) continue;

        /* r0 = LowBits(w - c * s2) */
        int r0_fail = 0;
        for (int r = 0; r < k; r++) {
            poly_pointwise(&cs2[r], &s2_hat[r], &c_hat);
            poly_invntt(&cs2[r]);

            poly w_minus_cs2;
            poly_sub(&w_minus_cs2, &w[r], &cs2[r]);

            for (int j = 0; j < N; j++) {
                int32_t r0 = low_bits(w_minus_cs2.coeffs[j], alpha);
                if (check_norm_bound(r0, gamma_2 - beta)) {
                    r0_fail = 1;
                    break;
                }
            }
            if (r0_fail) break;
        }
        if (r0_fail) continue;

        /* Check ct0 bound: c * t0 */
        int ct0_fail = 0;
        for (int r = 0; r < k; r++) {
            poly_pointwise(&ct0[r], &t0_hat[r], &c_hat);
            poly_invntt(&ct0[r]);

            for (int j = 0; j < N; j++) {
                if (check_norm_bound(ct0[r].coeffs[j], gamma_2)) {
                    ct0_fail = 1;
                    break;
                }
            }
            if (ct0_fail) break;
        }
        if (ct0_fail) continue;

        /* Hints: h = MakeHint(-ct0, w - cs2 + ct0) */
        poly h[8];
        int hint_count = 0;
        for (int r = 0; r < k; r++) {
            for (int j = 0; j < N; j++) {
                int32_t neg_ct0 = modq(Q - ct0[r].coeffs[j]);
                int32_t target = modq((int64_t)w[r].coeffs[j] - cs2[r].coeffs[j] + ct0[r].coeffs[j]);
                int hint_bit = make_hint(neg_ct0, target, alpha);
                h[r].coeffs[j] = hint_bit;
                if (hint_bit) hint_count++;
            }
        }
        if (hint_count > omega) continue;

        /* Success! Pack signature = c_tilde || z || h */
        memcpy(sig, c_tilde, c_tilde_bytes);
        size_t z_bytes = (l * N * ((gamma_1 == (1 << 17)) ? 18 : 20)) / 8;
        pack_z(sig + c_tilde_bytes, z, l, gamma_1);
        pack_hints(sig + c_tilde_bytes + z_bytes, h, k, omega);

        memset(&s_mldsa_work, 0, sizeof(s_mldsa_work));
        return 0;
    }
}

/* ==================== Public API ==================== */

int mldsa44_keygen(const uint8_t seed[32], uint8_t *pk, uint8_t *sk) {
    return mldsa_keygen_internal(seed, pk, sk, 4, 4, 2);
}

int mldsa44_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t msglen,
                      const uint8_t rnd[32], uint8_t *sig) {
    return mldsa_sign_seed_internal(seed, msg, msglen, rnd, sig,
                                   4, 4, 2, 39, 78, 1 << 17, 95232, 80, 32);
}

int mldsa65_keygen(const uint8_t seed[32], uint8_t *pk, uint8_t *sk) {
    return mldsa_keygen_internal(seed, pk, sk, 6, 5, 4);
}

int mldsa65_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t msglen,
                      const uint8_t rnd[32], uint8_t *sig) {
    return mldsa_sign_seed_internal(seed, msg, msglen, rnd, sig,
                                   6, 5, 4, 49, 196, 1 << 19, 261888, 55, 48);
}

int mldsa87_keygen(const uint8_t seed[32], uint8_t *pk, uint8_t *sk) {
    return mldsa_keygen_internal(seed, pk, sk, 8, 7, 2);
}

int mldsa87_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t msglen,
                      const uint8_t rnd[32], uint8_t *sig) {
    return mldsa_sign_seed_internal(seed, msg, msglen, rnd, sig,
                                   8, 7, 2, 60, 120, 1 << 19, 261888, 75, 64);
}

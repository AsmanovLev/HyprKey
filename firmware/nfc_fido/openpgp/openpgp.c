#include "openpgp.h"
#include "micro_ecc/uECC.h"
#include "sha256/sha256.h"
#include "fips202.h"
#include "mlkem.h"
#include <string.h>

/* Master secret for deterministic key derivation */
static const uint8_t OPENPGP_MASTER_KEY[32] = {
    0x48, 0x79, 0x70, 0x72, 0x4B, 0x65, 0x79, 0x5F,
    0x4F, 0x70, 0x65, 0x6E, 0x50, 0x47, 0x50, 0x5F,
    0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5F, 0x4E,
    0x52, 0x46, 0x35, 0x32, 0x38, 0x34, 0x30, 0x01
};

/* AID: D2 76 00 01 24 01 (OpenPGP) 03 04 (v3.4) 00 01 (Manuf) 00 00 00 01 (Serial) 00 00 */
static const uint8_t s_openpgp_aid[16] = {
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    0x03, 0x04,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00
};

/* Historical bytes (ISO 7816-4) - 10 bytes */
static const uint8_t s_historical_bytes[] = {
    0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01, 0x40, 0x00, 0x90, 0x00
};

/* ISO 7816-3 Answer To Reset (ATR) for OpenPGP Card v2/v3 with valid TCK (0x0C) - 21 bytes */
static const uint8_t s_openpgp_atr[21] = {
    0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75,
    0x1F, 0x03, 0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01,
    0x40, 0x00, 0x90, 0x00, 0x0C
};

/* ECC curve secp256r1 OID: 1.2.840.10045.3.1.7 (8 bytes) */
static const uint8_t s_oid_secp256r1[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* Algorithm attributes: 0x13 (ECDSA) or 0x12 (ECDH) + OID */
static const uint8_t s_alg_attr_sig[] = { 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t s_alg_attr_dec[] = { 0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t s_alg_attr_aut[] = { 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/* Extended Capabilities (DO 0xC0) - 10 bytes */
static const uint8_t s_extended_capabilities[10] = {
    0x7C,       /* Support for GET CHALLENGE, Key Import, PW Status change */
    0x00,       /* No SM */
    0x01, 0x00, /* Max challenge length = 256 */
    0x04, 0x00, /* Max cert length = 1024 */
    0x0C, 0x00, /* Max special DO length = 3072 */
    0x00,       /* PIN block 2 format */
    0x00        /* MSE command support */
};

/* Key material */
typedef struct {
    uint8_t  privkey[32];
    uint8_t  pubkey[64];
    uint8_t  fingerprint[20];
    uint32_t creation_time;
    bool     valid;
} openpgp_key_t;

static openpgp_key_t s_key_sig;
static openpgp_key_t s_key_dec;
static openpgp_key_t s_key_aut;

/* Post-Quantum ML-KEM Key Material */
static uint8_t s_mlkem768_pk[MLKEM768_PUBLICKEYBYTES];
static uint8_t s_mlkem768_sk[MLKEM768_SECRETKEYBYTES];
static bool    s_mlkem768_valid = false;

/* PINs & State */
static char    s_pw1[32] = "123456";
static uint8_t s_pw1_len = 6;
static uint8_t s_pw1_tries = 3;
static bool    s_pw1_sign_verified = false;
static bool    s_pw1_other_verified = false;

static char    s_pw3[32] = "12345678";
static uint8_t s_pw3_len = 8;
static uint8_t s_pw3_tries = 3;
static bool    s_pw3_verified = false;

static uint32_t s_sig_counter = 0;

/* Cardholder data */
static char    s_name[40] = "hyprkey OpenPGP User";
static char    s_lang[4]  = "en";
static uint8_t s_sex      = 0x00; /* Unspecified */
static char    s_login[32]= "";

/* Helper: Simple SHA-1 for OpenPGP V4 Fingerprint calculation */
static void sha1_calc(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint8_t buf[64];
    size_t i = 0;
    uint64_t total_bits = (uint64_t)len * 8;

    while (i + 64 <= len) {
        uint32_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)data[i + t * 4] << 24) |
                   ((uint32_t)data[i + t * 4 + 1] << 16) |
                   ((uint32_t)data[i + t * 4 + 2] << 8) |
                   ((uint32_t)data[i + t * 4 + 3]);
        }
        for (int t = 16; t < 80; t++) {
            uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (val << 1) | (val >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int t = 0; t < 80; t++) {
            uint32_t f, k;
            if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        i += 64;
    }

    size_t rem = len - i;
    memcpy(buf, data + i, rem);
    buf[rem++] = 0x80;
    if (rem > 56) {
        while (rem < 64) buf[rem++] = 0;
        uint32_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)buf[t * 4] << 24) | ((uint32_t)buf[t * 4 + 1] << 16) |
                   ((uint32_t)buf[t * 4 + 2] << 8) | ((uint32_t)buf[t * 4 + 3]);
        }
        for (int t = 16; t < 80; t++) {
            uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (val << 1) | (val >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int t = 0; t < 80; t++) {
            uint32_t f, k;
            if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        rem = 0;
    }
    while (rem < 56) buf[rem++] = 0;
    for (int t = 0; t < 8; t++) buf[56 + t] = (uint8_t)(total_bits >> ((7 - t) * 8));
    uint32_t w[80];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)buf[t * 4] << 24) | ((uint32_t)buf[t * 4 + 1] << 16) |
               ((uint32_t)buf[t * 4 + 2] << 8) | ((uint32_t)buf[t * 4 + 3]);
    }
    for (int t = 16; t < 80; t++) {
        uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = (val << 1) | (val >> 31);
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int t = 0; t < 80; t++) {
        uint32_t f, k;
        if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;

    for (int t = 0; t < 5; t++) {
        out[t * 4]     = (uint8_t)(h[t] >> 24);
        out[t * 4 + 1] = (uint8_t)(h[t] >> 16);
        out[t * 4 + 2] = (uint8_t)(h[t] >> 8);
        out[t * 4 + 3] = (uint8_t)(h[t]);
    }
}

/* Compute V4 fingerprint for ECC secp256r1 key */
static void compute_v4_fingerprint(uint8_t alg, uint32_t ctime, const uint8_t pubkey[64], uint8_t fp_out[20]) {
    /* V4 Public Key Packet:
     * 0x99 || 2-byte body length ||
     * 0x04 (version) || 4-byte creation time || alg (0x13 or 0x12) ||
     * 0x08 (OID len) || OID (8 bytes) ||
     * 0x02, 0x08 (MPI bitlen 520) || 0x04 (uncompressed) || X (32) || Y (32)
     */
    uint8_t pkt[128];
    uint16_t body_len = 1 + 4 + 1 + 1 + sizeof(s_oid_secp256r1) + 2 + 1 + 64; /* = 82 bytes */
    uint16_t idx = 0;

    pkt[idx++] = 0x99;
    pkt[idx++] = (uint8_t)(body_len >> 8);
    pkt[idx++] = (uint8_t)(body_len & 0xFF);

    pkt[idx++] = 0x04; /* Version 4 */
    pkt[idx++] = (uint8_t)(ctime >> 24);
    pkt[idx++] = (uint8_t)(ctime >> 16);
    pkt[idx++] = (uint8_t)(ctime >> 8);
    pkt[idx++] = (uint8_t)(ctime & 0xFF);

    pkt[idx++] = alg;
    pkt[idx++] = sizeof(s_oid_secp256r1);
    memcpy(&pkt[idx], s_oid_secp256r1, sizeof(s_oid_secp256r1));
    idx += sizeof(s_oid_secp256r1);

    /* MPI bitlength = 520 (0x02, 0x08) */
    pkt[idx++] = 0x02;
    pkt[idx++] = 0x08;
    pkt[idx++] = 0x04; /* Uncompressed point tag */
    memcpy(&pkt[idx], pubkey, 64);
    idx += 64;

    sha1_calc(pkt, idx, fp_out);
}

/* Initialize keys deterministically from master secret */
static void init_key(openpgp_key_t *k, const char *role_tag, uint8_t alg, uint32_t ctime) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, OPENPGP_MASTER_KEY, 32);
    sha256_update(&ctx, (const uint8_t *)role_tag, strlen(role_tag));
    sha256_final(&ctx, k->privkey);

    /* Ensure valid scalar for secp256r1 */
    k->privkey[0] &= 0x7F; /* keep strictly < order */

    uECC_compute_public_key(k->privkey, k->pubkey, uECC_secp256r1());
    k->creation_time = ctime;
    k->valid = true;

    compute_v4_fingerprint(alg, ctime, k->pubkey, k->fingerprint);
}

void openpgp_init(void) {
    /* Creation timestamp: e.g. 1700000000 (0x6554F700) */
    uint32_t default_ctime = 0x6554F700;

    init_key(&s_key_sig, "OPENPGP_SIGN_KEY", 0x13, default_ctime);
    init_key(&s_key_dec, "OPENPGP_DEC_KEY",  0x12, default_ctime);
    init_key(&s_key_aut, "OPENPGP_AUTH_KEY", 0x13, default_ctime);

    /* Derive deterministic ML-KEM-768 keypair */
    uint8_t d[32], z[32];
    sha3_256_ctx hctx;
    sha3_256_init(&hctx);
    sha3_256_absorb(&hctx, OPENPGP_MASTER_KEY, 32);
    sha3_256_absorb(&hctx, (const uint8_t *)"MLKEM768_D", 10);
    sha3_256_finalize(&hctx, d);

    sha3_256_init(&hctx);
    sha3_256_absorb(&hctx, OPENPGP_MASTER_KEY, 32);
    sha3_256_absorb(&hctx, (const uint8_t *)"MLKEM768_Z", 10);
    sha3_256_finalize(&hctx, z);

    mlkem768_keygen_internal(s_mlkem768_pk, s_mlkem768_sk, d, z);
    s_mlkem768_valid = true;

    s_pw1_sign_verified = false;
    s_pw1_other_verified = false;
    s_pw3_verified = false;
}

uint16_t openpgp_get_atr(uint8_t *out, uint16_t max_len) {
    if (max_len < sizeof(s_openpgp_atr)) return 0;
    memcpy(out, s_openpgp_atr, sizeof(s_openpgp_atr));
    return sizeof(s_openpgp_atr);
}

/* ==================== TLV Helpers ==================== */

static uint16_t put_tlv(uint8_t *buf, uint16_t max_len, uint16_t tag, const uint8_t *val, uint16_t val_len) {
    uint16_t idx = 0;
    if (tag > 0xFF) {
        if (idx + 2 > max_len) return 0;
        buf[idx++] = (uint8_t)(tag >> 8);
        buf[idx++] = (uint8_t)(tag & 0xFF);
    } else {
        if (idx + 1 > max_len) return 0;
        buf[idx++] = (uint8_t)tag;
    }

    if (val_len < 128) {
        if (idx + 1 > max_len) return 0;
        buf[idx++] = (uint8_t)val_len;
    } else if (val_len < 256) {
        if (idx + 2 > max_len) return 0;
        buf[idx++] = 0x81;
        buf[idx++] = (uint8_t)val_len;
    } else {
        if (idx + 3 > max_len) return 0;
        buf[idx++] = 0x82;
        buf[idx++] = (uint8_t)(val_len >> 8);
        buf[idx++] = (uint8_t)(val_len & 0xFF);
    }

    if (idx + val_len > max_len) return 0;
    if (val_len > 0 && val) {
        memcpy(buf + idx, val, val_len);
        idx += val_len;
    }
    return idx;
}

/* Build DO 0x6E: Application Related Data */
static uint16_t build_do_6e(uint8_t *out, uint16_t max_len) {
    uint8_t disc_buf[256];
    uint16_t d_idx = 0;

    /* Extended capabilities (0xC0) */
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC0, s_extended_capabilities, sizeof(s_extended_capabilities));
    /* Algorithm attributes: Sig (0xC1), Dec (0xC2), Aut (0xC3) */
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC1, s_alg_attr_sig, sizeof(s_alg_attr_sig));
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC2, s_alg_attr_dec, sizeof(s_alg_attr_dec));
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC3, s_alg_attr_aut, sizeof(s_alg_attr_aut));

    /* PW Status Bytes (0xC4) - 7 bytes:
     * [0]: PW1 status (0 = not valid for multiple sigs)
     * [1]: max PW1 len (64)
     * [2]: max Reset Code len (64)
     * [3]: max PW3 len (64)
     * [4]: PW1 retry counter (s_pw1_tries)
     * [5]: Reset Code retry counter (0)
     * [6]: PW3 retry counter (s_pw3_tries)
     */
    uint8_t pw_status[7] = { 0x00, 64, 64, 64, s_pw1_tries, 0, s_pw3_tries };
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC4, pw_status, 7);

    /* Fingerprints (0xC5) - exactly 60 bytes: Sig (20) || Dec (20) || Aut (20) */
    uint8_t all_fps[60];
    memcpy(&all_fps[0],  s_key_sig.fingerprint, 20);
    memcpy(&all_fps[20], s_key_dec.fingerprint, 20);
    memcpy(&all_fps[40], s_key_aut.fingerprint, 20);
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC5, all_fps, 60);

    /* CA Fingerprints (0xC6) - exactly 60 bytes */
    uint8_t ca_fps[60] = {0};
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC6, ca_fps, 60);

    /* Creation timestamps (0xCD) - 12 bytes */
    uint8_t ctimes[12];
    ctimes[0] = (uint8_t)(s_key_sig.creation_time >> 24);
    ctimes[1] = (uint8_t)(s_key_sig.creation_time >> 16);
    ctimes[2] = (uint8_t)(s_key_sig.creation_time >> 8);
    ctimes[3] = (uint8_t)(s_key_sig.creation_time & 0xFF);
    ctimes[4] = (uint8_t)(s_key_dec.creation_time >> 24);
    ctimes[5] = (uint8_t)(s_key_dec.creation_time >> 16);
    ctimes[6] = (uint8_t)(s_key_dec.creation_time >> 8);
    ctimes[7] = (uint8_t)(s_key_dec.creation_time & 0xFF);
    ctimes[8] = (uint8_t)(s_key_aut.creation_time >> 24);
    ctimes[9] = (uint8_t)(s_key_aut.creation_time >> 16);
    ctimes[10]= (uint8_t)(s_key_aut.creation_time >> 8);
    ctimes[11]= (uint8_t)(s_key_aut.creation_time & 0xFF);
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xCD, ctimes, 12);

    /* Combine into 0x6E body: 0x4F (AID) + 0x5F52 (Hist) + 0x73 (Discretionary) */
    uint8_t body_buf[512];
    uint16_t b_idx = 0;
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x4F, s_openpgp_aid, sizeof(s_openpgp_aid));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5F52, s_historical_bytes, sizeof(s_historical_bytes));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x73, disc_buf, d_idx);

    return put_tlv(out, max_len, 0x6E, body_buf, b_idx);
}

/* Build DO 0x65: Cardholder Related Data */
static uint16_t build_do_65(uint8_t *out, uint16_t max_len) {
    uint8_t body_buf[128];
    uint16_t b_idx = 0;
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5B, (const uint8_t *)s_name, strlen(s_name));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5F2D, (const uint8_t *)s_lang, strlen(s_lang));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5F35, &s_sex, 1);
    return put_tlv(out, max_len, 0x65, body_buf, b_idx);
}

/* Build DO 0x7A: Security Support Template */
static uint16_t build_do_7a(uint8_t *out, uint16_t max_len) {
    uint8_t body_buf[16];
    uint8_t cnt[3] = {
        (uint8_t)(s_sig_counter >> 16),
        (uint8_t)(s_sig_counter >> 8),
        (uint8_t)(s_sig_counter & 0xFF)
    };
    uint16_t b_idx = put_tlv(body_buf, sizeof(body_buf), 0x93, cnt, 3);
    return put_tlv(out, max_len, 0x7A, body_buf, b_idx);
}

/* ==================== APDU Dispatcher ==================== */

uint16_t openpgp_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* Wrong length */
        return 2;
    }

    uint8_t cla = apdu[0];
    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    uint8_t p2  = apdu[3];

    (void)cla;

    /* Parse Lc and Data pointer (Short and Extended APDUs) */
    uint16_t lc = 0;
    const uint8_t *data = NULL;
    if (apdu_len > 4) {
        if (apdu[4] == 0x00 && apdu_len >= 7) {
            /* Extended APDU: [CLA INS P1 P2 00 B1 B2 ...DATA...] */
            lc = ((uint16_t)apdu[5] << 8) | apdu[6];
            if (lc > 0 && apdu_len >= 7 + lc) {
                data = &apdu[7];
            }
        } else {
            /* Short APDU: [CLA INS P1 P2 Lc ...DATA...] */
            lc = apdu[4];
            if (lc > 0 && apdu_len >= 5 + lc) {
                data = &apdu[5];
            }
        }
    }

    /* 1. SELECT (0xA4) */
    if (ins == 0xA4) {
        if (p1 == 0x04) {
            /* Select by AID */
            /* We accept either prefix D2 76 00 01 24 01 or full 16-byte AID */
            if (lc >= 6 && memcmp(data, s_openpgp_aid, 6) == 0) {
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        } else if (p1 == 0x00) {
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        }
        rsp[0] = 0x6A; rsp[1] = 0x82; /* File not found */
        return 2;
    }

    /* 2. GET DATA (0xCA) */
    if (ins == 0xCA) {
        uint16_t tag = ((uint16_t)p1 << 8) | p2;
        uint16_t len = 0;

        switch (tag) {
            case 0x004F: /* AID */
                memcpy(rsp, s_openpgp_aid, sizeof(s_openpgp_aid));
                len = sizeof(s_openpgp_aid);
                break;

            case 0x006E: /* Application Related Data */
                len = build_do_6e(rsp, max_rsp_len - 2);
                break;

            case 0x0065: /* Cardholder Related Data */
                len = build_do_65(rsp, max_rsp_len - 2);
                break;

            case 0x005E: /* Login Data */
                memcpy(rsp, s_login, strlen(s_login));
                len = strlen(s_login);
                break;

            case 0x007A: /* Security Support Template */
                len = build_do_7a(rsp, max_rsp_len - 2);
                break;

            case 0x00C4: { /* PW Status Bytes */
                uint8_t pw_status[7] = { 0x00, 64, 64, 64, s_pw1_tries, 0, s_pw3_tries };
                memcpy(rsp, pw_status, 7);
                len = 7;
                break;
            }

            case 0x00C1: /* Sig algorithm attributes */
                memcpy(rsp, s_alg_attr_sig, sizeof(s_alg_attr_sig));
                len = sizeof(s_alg_attr_sig);
                break;

            case 0x00C2: /* Dec algorithm attributes */
                memcpy(rsp, s_alg_attr_dec, sizeof(s_alg_attr_dec));
                len = sizeof(s_alg_attr_dec);
                break;

            case 0x00C3: /* Aut algorithm attributes */
                memcpy(rsp, s_alg_attr_aut, sizeof(s_alg_attr_aut));
                len = sizeof(s_alg_attr_aut);
                break;

            case 0x00C5: /* Fingerprints (60 bytes: Sig || Dec || Aut) */
                memcpy(rsp, s_key_sig.fingerprint, 20);
                memcpy(rsp + 20, s_key_dec.fingerprint, 20);
                memcpy(rsp + 40, s_key_aut.fingerprint, 20);
                len = 60;
                break;

            case 0x00C6: /* CA Fingerprints (60 bytes) */
                memset(rsp, 0, 60);
                len = 60;
                break;

            case 0x00CD: { /* Generation timestamps (12 bytes) */
                rsp[0]  = (uint8_t)(s_key_sig.creation_time >> 24);
                rsp[1]  = (uint8_t)(s_key_sig.creation_time >> 16);
                rsp[2]  = (uint8_t)(s_key_sig.creation_time >> 8);
                rsp[3]  = (uint8_t)(s_key_sig.creation_time & 0xFF);
                rsp[4]  = (uint8_t)(s_key_dec.creation_time >> 24);
                rsp[5]  = (uint8_t)(s_key_dec.creation_time >> 16);
                rsp[6]  = (uint8_t)(s_key_dec.creation_time >> 8);
                rsp[7]  = (uint8_t)(s_key_dec.creation_time & 0xFF);
                rsp[8]  = (uint8_t)(s_key_aut.creation_time >> 24);
                rsp[9]  = (uint8_t)(s_key_aut.creation_time >> 16);
                rsp[10] = (uint8_t)(s_key_aut.creation_time >> 8);
                rsp[11] = (uint8_t)(s_key_aut.creation_time & 0xFF);
                len = 12;
                break;
            }

            case 0x00D6: /* Post-Quantum ML-KEM-768 Public Key */
                if (s_mlkem768_valid && max_rsp_len >= MLKEM768_PUBLICKEYBYTES + 2) {
                    memcpy(rsp, s_mlkem768_pk, MLKEM768_PUBLICKEYBYTES);
                    len = MLKEM768_PUBLICKEYBYTES;
                }
                break;

            case 0x00DE: { /* Extended length info: 2 bytes max cmd (3072), 2 bytes max rsp (3072) */
                uint8_t ext_len[8] = { 0x02, 0x02, 0x0C, 0x00, 0x02, 0x02, 0x0C, 0x00 };
                memcpy(rsp, ext_len, 8);
                len = 8;
                break;
            }

            default:
                /* Unknown or unsupported DO */
                rsp[0] = 0x6A; rsp[1] = 0x88; /* Referenced data not found */
                return 2;
        }

        rsp[len]     = 0x90;
        rsp[len + 1] = 0x00;
        return len + 2;
    }

    /* 3. VERIFY (0x20) */
    if (ins == 0x20) {
        if (p1 != 0x00) {
            rsp[0] = 0x6A; rsp[1] = 0x86;
            return 2;
        }

        if (p2 == 0x81 || p2 == 0x82) {
            /* PW1 verification */
            if (lc == 0) {
                /* Query status */
                bool v = (p2 == 0x81) ? s_pw1_sign_verified : s_pw1_other_verified;
                if (v) {
                    rsp[0] = 0x90; rsp[1] = 0x00;
                } else {
                    rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw1_tries);
                }
                return 2;
            }

            if (s_pw1_tries == 0) {
                rsp[0] = 0x69; rsp[1] = 0x83; /* Authentication method blocked */
                return 2;
            }

            if (lc == s_pw1_len && memcmp(data, s_pw1, lc) == 0) {
                s_pw1_tries = 3;
                if (p2 == 0x81) s_pw1_sign_verified = true;
                if (p2 == 0x82) s_pw1_other_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                if (s_pw1_tries > 0) s_pw1_tries--;
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw1_tries);
            }
            return 2;
        } else if (p2 == 0x83) {
            /* PW3 verification */
            if (lc == 0) {
                if (s_pw3_verified) {
                    rsp[0] = 0x90; rsp[1] = 0x00;
                } else {
                    rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw3_tries);
                }
                return 2;
            }

            if (s_pw3_tries == 0) {
                rsp[0] = 0x69; rsp[1] = 0x83; /* Blocked */
                return 2;
            }

            if (lc == s_pw3_len && memcmp(data, s_pw3, lc) == 0) {
                s_pw3_tries = 3;
                s_pw3_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                if (s_pw3_tries > 0) s_pw3_tries--;
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw3_tries);
            }
            return 2;
        }

        rsp[0] = 0x6A; rsp[1] = 0x88;
        return 2;
    }

    /* 4. PUT DATA (0xDA) */
    if (ins == 0xDA) {
        uint16_t tag = ((uint16_t)p1 << 8) | p2;
        if (!s_pw3_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied (need admin) */
            return 2;
        }

        if (tag == 0x005B) { /* Name */
            size_t n = (lc < sizeof(s_name) - 1) ? lc : sizeof(s_name) - 1;
            memcpy(s_name, data, n);
            s_name[n] = '\0';
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else if (tag == 0x5F2D) { /* Language */
            size_t n = (lc < sizeof(s_lang) - 1) ? lc : sizeof(s_lang) - 1;
            memcpy(s_lang, data, n);
            s_lang[n] = '\0';
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else if (tag == 0x5F35) { /* Sex */
            if (lc >= 1) s_sex = data[0];
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else if (tag == 0x005E) { /* Login */
            size_t n = (lc < sizeof(s_login) - 1) ? lc : sizeof(s_login) - 1;
            memcpy(s_login, data, n);
            s_login[n] = '\0';
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        }

        rsp[0] = 0x6A; rsp[1] = 0x88;
        return 2;
    }

    /* 5. GENERATE ASYMMETRIC KEY PAIR (0x47) */
    if (ins == 0x47) {
        /* P1 = 0x80: Generate Key Pair (requires PW3 / Admin PIN)
         * P1 = 0x81: Read Public Key (public operation, no PIN required) */
        if (p1 == 0x80 && !s_pw3_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }

        /* Check key reference template tag */
        uint8_t role = 0xB6; /* Default signature */
        if (lc >= 2) role = data[0];

        /* Role 0xBA: Post-Quantum ML-KEM-768 Decryption Key */
        if (role == 0xBA && s_mlkem768_valid) {
            uint16_t total = 0;
            rsp[total++] = 0x7F;
            rsp[total++] = 0x49;
            uint16_t inner_len = MLKEM768_PUBLICKEYBYTES + 4;
            rsp[total++] = 0x82;
            rsp[total++] = (uint8_t)(inner_len >> 8);
            rsp[total++] = (uint8_t)(inner_len & 0xFF);

            rsp[total++] = 0x86;
            rsp[total++] = 0x82;
            rsp[total++] = (uint8_t)(MLKEM768_PUBLICKEYBYTES >> 8);
            rsp[total++] = (uint8_t)(MLKEM768_PUBLICKEYBYTES & 0xFF);
            memcpy(rsp + total, s_mlkem768_pk, MLKEM768_PUBLICKEYBYTES);
            total += MLKEM768_PUBLICKEYBYTES;

            rsp[total++] = 0x90;
            rsp[total++] = 0x00;
            return total;
        }

        const openpgp_key_t *k = &s_key_sig;
        if (role == 0xB8) k = &s_key_dec;
        else if (role == 0xA4) k = &s_key_aut;

        /* Return public key template 0x7F49 containing 0x86 (0x04 || pubkey 64) */
        uint8_t raw_pt[65];
        raw_pt[0] = 0x04;
        memcpy(raw_pt + 1, k->pubkey, 64);

        uint8_t body[80];
        uint16_t b_len = put_tlv(body, sizeof(body), 0x86, raw_pt, 65);
        uint16_t total = put_tlv(rsp, max_rsp_len - 2, 0x7F49, body, b_len);

        rsp[total]     = 0x90;
        rsp[total + 1] = 0x00;
        return total + 2;
    }

    /* 6. PSO: COMPUTE DIGITAL SIGNATURE (0x2A with P1=0x9E, P2=0x9A or P1=0x80, P2=0x86) */
    if (ins == 0x2A && ((p1 == 0x9E && p2 == 0x9A) || (p1 == 0x80 && p2 == 0x86))) {
        if (!s_pw1_sign_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
            return 2;
        }

        /* Sign digest in data */
        uint8_t digest[32];
        if (lc == 32) {
            memcpy(digest, data, 32);
        } else {
            sha256_ctx_t sha;
            sha256_init(&sha);
            sha256_update(&sha, data, lc);
            sha256_final(&sha, digest);
        }

        /* Output raw r || s (64 bytes) */
        uECC_sign(s_key_sig.privkey, digest, 32, rsp, uECC_secp256r1());

        s_sig_counter++;
        s_pw1_sign_verified = false; /* Single signature per PIN verification */

        rsp[64] = 0x90;
        rsp[65] = 0x00;
        return 66;
    }

    /* 7. PSO: DECIPHER (0x2A with P1=0x86, P2=0x80) */
    if (ins == 0x2A && p1 == 0x86 && p2 == 0x80) {
        if (!s_pw1_other_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }

        /* Check for ML-KEM-768 ciphertext (1088 bytes) */
        if (lc == MLKEM768_CIPHERTEXTBYTES && s_mlkem768_valid) {
            uint8_t secret[32];
            mlkem768_decaps_internal(secret, data, s_mlkem768_sk);
            memcpy(rsp, secret, 32);
            rsp[32] = 0x90;
            rsp[33] = 0x00;
            return 34;
        }
        /* Check for ML-KEM-768 ciphertext with 0x00 padding prefix (1089 bytes) */
        if (lc == MLKEM768_CIPHERTEXTBYTES + 1 && data[0] == 0x00 && s_mlkem768_valid) {
            uint8_t secret[32];
            mlkem768_decaps_internal(secret, data + 1, s_mlkem768_sk);
            memcpy(rsp, secret, 32);
            rsp[32] = 0x90;
            rsp[33] = 0x00;
            return 34;
        }

        /* Classical ECDH NIST P-256 peer public point: 0x04 || X (32) || Y (32) */
        if (lc >= 65 && data[0] == 0x04) {
            uint8_t secret[32];
            uECC_shared_secret(data + 1, s_key_dec.privkey, secret, uECC_secp256r1());
            memcpy(rsp, secret, 32);
            rsp[32] = 0x90;
            rsp[33] = 0x00;
            return 34;
        }

        rsp[0] = 0x6A; rsp[1] = 0x80; /* Incorrect data */
        return 2;
    }

    /* 8. INTERNAL AUTHENTICATE (0x88) */
    if (ins == 0x88 && p1 == 0x00 && p2 == 0x00) {
        if (!s_pw1_other_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }

        uint8_t digest[32];
        if (lc == 32) {
            memcpy(digest, data, 32);
        } else {
            sha256_ctx_t sha;
            sha256_init(&sha);
            sha256_update(&sha, data, lc);
            sha256_final(&sha, digest);
        }

        /* Sign with authentication key */
        uECC_sign(s_key_aut.privkey, digest, 32, rsp, uECC_secp256r1());

        rsp[64] = 0x90;
        rsp[65] = 0x00;
        return 66;
    }

    /* 9. TERMINATE DF (0xE6) & ACTIVATE FILE (0x44) -> Factory Reset */
    if (ins == 0xE6 || ins == 0x44) {
        if (!s_pw3_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }
        openpgp_init();
        rsp[0] = 0x90; rsp[1] = 0x00;
        return 2;
    }

    /* 10. GET CHALLENGE (0x84) */
    if (ins == 0x84) {
        uint16_t le = (apdu_len > 4) ? apdu[apdu_len - 1] : 8;
        if (le == 0) le = 8;
        if (le > max_rsp_len - 2) le = max_rsp_len - 2;
        static uint32_t s_prng = 0x12345678;
        for (uint16_t i = 0; i < le; i++) {
            s_prng = s_prng * 1103515245 + 12345;
            rsp[i] = (uint8_t)(s_prng >> 16);
        }
        rsp[le]     = 0x90;
        rsp[le + 1] = 0x00;
        return le + 2;
    }

    /* Unsupported instruction */
    rsp[0] = 0x6D; rsp[1] = 0x00;
    return 2;
}

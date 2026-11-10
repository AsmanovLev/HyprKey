#include "piv.h"
#include "micro_ecc/uECC.h"
#include "sha256/sha256.h"
#include "ed25519/ed25519.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>

#define PIV_TAG_CHUID     0x5FC102
#define PIV_TAG_CCC       0x5FC107
#define PIV_TAG_CERT_9A   0x5FC105
#define PIV_TAG_CERT_9C   0x5FC10A
#define PIV_TAG_CERT_9D   0x5FC10B
#define PIV_TAG_CERT_9E   0x5FC101
#define PIV_TAG_DISCOVERY 0x007E

/* PIV AID: A0 00 00 03 08 00 00 10 00 01 00 */
static const uint8_t s_piv_aid[11] = {
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

/* CHUID (Card Holder Unique Identifier) */
static const uint8_t s_piv_chuid[] = {
    0x30, 0x19, /* FASC-N (25 bytes) */
    0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39,
    0xCE, 0x73, 0x9D, 0x83, 0xA0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x10, /* Card UUID (16 bytes) */
    0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x5F,
    0x50, 0x49, 0x56, 0x5F, 0x55, 0x55, 0x49, 0x44,
    0x35, 0x08, /* Expiration Date: 20360101 */
    '2', '0', '3', '6', '0', '1', '0', '1',
    0x3E, 0x00, /* Signature */
    0xFE, 0x00  /* Error detection code */
};

/* CCC (Card Capability Container) */
static const uint8_t s_piv_ccc[] = {
    0xF0, 0x15, /* Card Identifier (21 bytes) */
    0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF, 0x02,
    0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00,
    0xF1, 0x01, 0x21, /* Container version */
    0xF2, 0x01, 0x21, /* Grammar version */
    0xF3, 0x00,       /* Applet family */
    0xF4, 0x01, 0x00, /* Security object */
    0xF5, 0x01, 0x10, /* Extended application property */
    0xF6, 0x00,
    0xF7, 0x00,
    0xFA, 0x00,
    0xFB, 0x00,
    0xFC, 0x00,
    0xFD, 0x00,
    0xFE, 0x00  /* EDC */
};

/* Key structure */
typedef struct {
    uint8_t  privkey[32];
    uint8_t  pubkey[64];
    uint8_t  cert[512];
    uint16_t cert_len;
    bool     valid;
} piv_key_t;

static piv_key_t s_piv_key_9a; /* PIV Authentication (Windows Logon / SSH) */
static piv_key_t s_piv_key_9c; /* Digital Signature */
static piv_key_t s_piv_key_9d; /* Key Management (Decryption / BitLocker) */
static piv_key_t s_piv_key_9e; /* Card Authentication (Doors) */

/* PINs & State */
static uint8_t s_piv_pin[8] = { '1', '2', '3', '4', '5', '6', 0xFF, 0xFF };
static uint8_t s_piv_pin_tries = 3;
static bool    s_piv_pin_verified = false;

static uint8_t s_piv_puk[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
static uint8_t s_piv_puk_tries = 3;

/* ==================== ASN.1 DER Helpers ==================== */

static uint16_t encode_der_int(uint8_t *out, const uint8_t *val, size_t len) {
    size_t start = 0;
    while (start < len - 1 && val[start] == 0) start++;
    uint8_t pad = (val[start] & 0x80) ? 1 : 0;
    uint8_t int_len = (uint8_t)(len - start + pad);

    out[0] = 0x02;
    out[1] = int_len;
    uint16_t idx = 2;
    if (pad) out[idx++] = 0x00;
    memcpy(out + idx, val + start, len - start);
    return idx + (uint16_t)(len - start);
}

static uint16_t encode_der_signature(uint8_t *out, const uint8_t raw_sig[64]) {
    uint8_t r_buf[40];
    uint8_t s_buf[40];
    uint16_t r_len = encode_der_int(r_buf, raw_sig, 32);
    uint16_t s_len = encode_der_int(s_buf, raw_sig + 32, 32);

    uint16_t total = 0;
    out[total++] = 0x30;
    out[total++] = (uint8_t)(r_len + s_len);
    memcpy(out + total, r_buf, r_len);
    total += r_len;
    memcpy(out + total, s_buf, s_len);
    total += s_len;
    return total;
}

/* Helper to generate self-signed X.509 v3 certificate for P-256 key */
static void generate_self_signed_cert(piv_key_t *k, uint8_t slot_id, const char *cn, uint8_t key_usage) {
    uint8_t tbs[384];
    uint16_t t_idx = 0;

    /* Version v3: A0 03 02 01 02 */
    tbs[t_idx++] = 0xA0; tbs[t_idx++] = 0x03; tbs[t_idx++] = 0x02; tbs[t_idx++] = 0x01; tbs[t_idx++] = 0x02;

    /* Serial Number: 02 02 00 <slot_id> */
    tbs[t_idx++] = 0x02; tbs[t_idx++] = 0x02; tbs[t_idx++] = 0x00; tbs[t_idx++] = slot_id;

    /* Signature Algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2) */
    static const uint8_t alg_ecdsa_sha256[] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    memcpy(tbs + t_idx, alg_ecdsa_sha256, sizeof(alg_ecdsa_sha256));
    t_idx += sizeof(alg_ecdsa_sha256);

    /* Issuer Name: CN=<cn>, O=hyprkey */
    uint8_t cn_len = (uint8_t)strlen(cn);
    uint8_t name_buf[80];
    uint16_t n_idx = 0;
    name_buf[n_idx++] = 0x31; name_buf[n_idx++] = cn_len + 9;
    name_buf[n_idx++] = 0x30; name_buf[n_idx++] = cn_len + 7;
    name_buf[n_idx++] = 0x06; name_buf[n_idx++] = 0x03; name_buf[n_idx++] = 0x55; name_buf[n_idx++] = 0x04; name_buf[n_idx++] = 0x03;
    name_buf[n_idx++] = 0x0C; name_buf[n_idx++] = cn_len;
    memcpy(name_buf + n_idx, cn, cn_len); n_idx += cn_len;
    name_buf[n_idx++] = 0x31; name_buf[n_idx++] = 16;
    name_buf[n_idx++] = 0x30; name_buf[n_idx++] = 14;
    name_buf[n_idx++] = 0x06; name_buf[n_idx++] = 0x03; name_buf[n_idx++] = 0x55; name_buf[n_idx++] = 0x04; name_buf[n_idx++] = 0x0A;
    name_buf[n_idx++] = 0x0C; name_buf[n_idx++] = 7;
    memcpy(name_buf + n_idx, "hyprkey", 7); n_idx += 7;

    tbs[t_idx++] = 0x30; tbs[t_idx++] = (uint8_t)n_idx;
    memcpy(tbs + t_idx, name_buf, n_idx);
    t_idx += n_idx;

    /* Validity: 2026-01-01 to 2036-01-01 */
    static const uint8_t validity[] = {
        0x30, 0x1E,
        0x17, 0x0D, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
    };
    memcpy(tbs + t_idx, validity, sizeof(validity));
    t_idx += sizeof(validity);

    /* Subject Name: same as Issuer */
    tbs[t_idx++] = 0x30; tbs[t_idx++] = (uint8_t)n_idx;
    memcpy(tbs + t_idx, name_buf, n_idx);
    t_idx += n_idx;

    /* SubjectPublicKeyInfo: id-ecPublicKey + secp256r1 + 04 || pubkey 64 */
    static const uint8_t spki_prefix[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04
    };
    memcpy(tbs + t_idx, spki_prefix, sizeof(spki_prefix));
    t_idx += sizeof(spki_prefix);
    memcpy(tbs + t_idx, k->pubkey, 64);
    t_idx += 64;

    /* Extensions: KeyUsage */
    uint8_t ext[] = {
        0xA3, 0x12, 0x30, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F,
        0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x07, key_usage
    };
    memcpy(tbs + t_idx, ext, sizeof(ext));
    t_idx += sizeof(ext);

    /* Hash TBS */
    uint8_t tbs_full[400];
    uint16_t full_tbs_len = 0;
    tbs_full[full_tbs_len++] = 0x30;
    if (t_idx > 127) {
        tbs_full[full_tbs_len++] = 0x82;
        tbs_full[full_tbs_len++] = (uint8_t)(t_idx >> 8);
        tbs_full[full_tbs_len++] = (uint8_t)(t_idx & 0xFF);
    } else {
        tbs_full[full_tbs_len++] = (uint8_t)t_idx;
    }
    memcpy(tbs_full + full_tbs_len, tbs, t_idx);
    full_tbs_len += t_idx;

    uint8_t hash[32];
    sha256_ctx_t sha;
    sha256_init(&sha);
    sha256_update(&sha, tbs_full, full_tbs_len);
    sha256_final(&sha, hash);

    /* Sign with key */
    uint8_t raw_sig[64];
    uECC_sign(k->privkey, hash, 32, raw_sig, uECC_secp256r1());

    uint8_t der_sig[80];
    uint16_t der_sig_len = encode_der_signature(der_sig, raw_sig);

    /* Build outer certificate */
    uint8_t cert_body[512];
    uint16_t b_idx = 0;
    memcpy(cert_body + b_idx, tbs_full, full_tbs_len);
    b_idx += full_tbs_len;
    memcpy(cert_body + b_idx, alg_ecdsa_sha256, sizeof(alg_ecdsa_sha256));
    b_idx += sizeof(alg_ecdsa_sha256);

    cert_body[b_idx++] = 0x03;
    cert_body[b_idx++] = (uint8_t)(der_sig_len + 1);
    cert_body[b_idx++] = 0x00;
    memcpy(cert_body + b_idx, der_sig, der_sig_len);
    b_idx += der_sig_len;

    /* Wrap in SEQUENCE */
    uint16_t c_idx = 0;
    k->cert[c_idx++] = 0x30;
    if (b_idx > 127) {
        k->cert[c_idx++] = 0x82;
        k->cert[c_idx++] = (uint8_t)(b_idx >> 8);
        k->cert[c_idx++] = (uint8_t)(b_idx & 0xFF);
    } else {
        k->cert[c_idx++] = (uint8_t)b_idx;
    }
    memcpy(k->cert + c_idx, cert_body, b_idx);
    k->cert_len = c_idx + b_idx;
}

static void init_piv_key(piv_key_t *k, const char *role_tag, uint8_t slot_id, const char *cn, uint8_t key_usage) {
    uint8_t master_key[32];
    storage_get_device_master_key("PIV", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    sha256_update(&ctx, (const uint8_t *)role_tag, strlen(role_tag));
    sha256_final(&ctx, k->privkey);
    k->privkey[0] &= 0x7F;

    uECC_compute_public_key(k->privkey, k->pubkey, uECC_secp256r1());
    k->valid = true;

    generate_self_signed_cert(k, slot_id, cn, key_usage);
}

void piv_init(void) {
    init_piv_key(&s_piv_key_9a, "PIV_AUTH_KEY_9A", 0x9A, "hyprkey PIV Authentication",    0x80); /* digitalSignature */
    init_piv_key(&s_piv_key_9c, "PIV_SIGN_KEY_9C", 0x9C, "hyprkey PIV Digital Signature",   0x60); /* nonRepudiation | digitalSignature */
    init_piv_key(&s_piv_key_9d, "PIV_KEYM_KEY_9D", 0x9D, "hyprkey PIV Key Management",      0x28); /* keyEncipherment | keyAgreement */
    init_piv_key(&s_piv_key_9e, "PIV_CARD_KEY_9E", 0x9E, "hyprkey PIV Card Authentication", 0x80); /* digitalSignature */

    s_piv_pin_verified = false;
    s_piv_pin_tries = storage_get_pin_retries(PIN_TYPE_PIV_PIN);
}

/* ==================== PIV APDU Processing ==================== */

uint16_t piv_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    uint8_t p2  = apdu[3];

    uint16_t lc = 0;
    const uint8_t *data = NULL;
    if (apdu_len > 4) {
        if (apdu[4] == 0x00 && apdu_len >= 7) {
            lc = ((uint16_t)apdu[5] << 8) | apdu[6];
            if (apdu_len < (uint16_t)(7 + lc)) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            data = (lc > 0) ? &apdu[7] : NULL;
        } else {
            lc = apdu[4];
            if (apdu_len < (uint16_t)(5 + lc)) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            data = (lc > 0) ? &apdu[5] : NULL;
        }
    }

    /* 1. SELECT (0xA4) */
    if (ins == 0xA4) {
        if (p1 == 0x04 && p2 == 0x00) {
            /* Accept PIV AID (11 bytes or prefix 9 bytes) */
            if (data != NULL && lc >= 9 && memcmp(data, s_piv_aid, 9) == 0) {
                /* Return Application Property Template 0x7E */
                uint16_t idx = 0;
                rsp[idx++] = 0x7E;
                rsp[idx++] = 1 + sizeof(s_piv_aid) + 3;
                rsp[idx++] = 0x4F; /* AID */
                rsp[idx++] = sizeof(s_piv_aid);
                memcpy(rsp + idx, s_piv_aid, sizeof(s_piv_aid));
                idx += sizeof(s_piv_aid);
                rsp[idx++] = 0x7F; rsp[idx++] = 0x66; rsp[idx++] = 0x00; /* CTAA */
                rsp[idx++] = 0x90; rsp[idx++] = 0x00;
                return idx;
            }
        }
        rsp[0] = 0x6A; rsp[1] = 0x82; /* File not found */
        return 2;
    }

    /* 2. VERIFY (0x20) */
    if (ins == 0x20) {
        if (p2 == 0x80) { /* Card Application PIN */
            if (lc == 0) {
                if (s_piv_pin_verified) {
                    rsp[0] = 0x90; rsp[1] = 0x00;
                } else {
                    rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_piv_pin_tries);
                }
                return 2;
            }

            if (s_piv_pin_tries == 0) {
                rsp[0] = 0x69; rsp[1] = 0x83; /* Blocked */
                return 2;
            }

            /* Match 6-8 bytes with 0xFF padding (FIPS 201 compliant constant-time) */
            bool match = false;
            uint8_t padded_input[8];
            memset(padded_input, 0xFF, sizeof(padded_input));
            if (lc >= 6 && lc <= 8 && data != NULL) {
                memcpy(padded_input, data, lc);
                if (crypto_consttime_eq(padded_input, s_piv_pin, 8)) {
                    match = true;
                }
            }

            if (match) {
                s_piv_pin_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, s_piv_pin_tries);
                s_piv_pin_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                if (s_piv_pin_tries > 0) s_piv_pin_tries--;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, s_piv_pin_tries);
                s_piv_pin_verified = false;
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_piv_pin_tries);
            }
            return 2;
        }
        rsp[0] = 0x6A; rsp[1] = 0x88;
        return 2;
    }

    /* 3. CHANGE REFERENCE DATA (0x24) */
    if (ins == 0x24 && p2 == 0x80) {
        if (lc >= 16 && data != NULL) {
            /* Old PIN (8) + New PIN (8) */
            uint8_t padded_old[8];
            memset(padded_old, 0xFF, sizeof(padded_old));
            memcpy(padded_old, data, 8);
            if (crypto_consttime_eq(padded_old, s_piv_pin, 8)) {
                memcpy(s_piv_pin, data + 8, 8);
                s_piv_pin_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, 3);
                s_piv_pin_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        }
        rsp[0] = 0x63; rsp[1] = 0xC0;
        return 2;
    }

    /* 4. RESET RETRY COUNTER (0x2C) */
    if (ins == 0x2C && p2 == 0x80) {
        if (lc >= 16 && data != NULL) {
            /* PUK (8) + New PIN (8) */
            uint8_t padded_puk[8];
            memset(padded_puk, 0xFF, sizeof(padded_puk));
            memcpy(padded_puk, data, 8);
            if (crypto_consttime_eq(padded_puk, s_piv_puk, 8)) {
                memcpy(s_piv_pin, data + 8, 8);
                s_piv_pin_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, 3);
                s_piv_puk_tries = 3;
                s_piv_pin_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        }
        if (s_piv_puk_tries > 0) s_piv_puk_tries--;
        rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_piv_puk_tries);
        return 2;
    }

    /* 5. GET DATA (0xCB) */
    if (ins == 0xCB && p1 == 0x3F && p2 == 0xFF) {
        if (lc < 3 || !data || data[0] != 0x5C) {
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        uint8_t tag_len = data[1];
        uint32_t tag = 0;
        for (uint8_t i = 0; i < tag_len && i < 4; i++) {
            tag = (tag << 8) | data[2 + i];
        }

        const uint8_t *payload = NULL;
        uint16_t payload_len = 0;
        uint8_t wrap_buf[600];

        if (tag == PIV_TAG_CHUID) {
            /* Wrap in tag 0x53 */
            wrap_buf[0] = 0x53;
            wrap_buf[1] = (uint8_t)sizeof(s_piv_chuid);
            memcpy(wrap_buf + 2, s_piv_chuid, sizeof(s_piv_chuid));
            payload = wrap_buf;
            payload_len = 2 + sizeof(s_piv_chuid);
        } else if (tag == PIV_TAG_CCC) {
            wrap_buf[0] = 0x53;
            wrap_buf[1] = (uint8_t)sizeof(s_piv_ccc);
            memcpy(wrap_buf + 2, s_piv_ccc, sizeof(s_piv_ccc));
            payload = wrap_buf;
            payload_len = 2 + sizeof(s_piv_ccc);
        } else if (tag == PIV_TAG_CERT_9A || tag == PIV_TAG_CERT_9C ||
                   tag == PIV_TAG_CERT_9D || tag == PIV_TAG_CERT_9E) {
            piv_key_t *k = &s_piv_key_9a;
            if (tag == PIV_TAG_CERT_9C) k = &s_piv_key_9c;
            else if (tag == PIV_TAG_CERT_9D) k = &s_piv_key_9d;
            else if (tag == PIV_TAG_CERT_9E) k = &s_piv_key_9e;

            /* Wrap certificate in Tag 0x70, Tag 0x71 (CertInfo 00), Tag 0xFE */
            uint16_t inner_len = 0;
            uint8_t inner_buf[550];

            /* Tag 0x70 */
            inner_buf[inner_len++] = 0x70;
            if (k->cert_len > 127) {
                inner_buf[inner_len++] = 0x82;
                inner_buf[inner_len++] = (uint8_t)(k->cert_len >> 8);
                inner_buf[inner_len++] = (uint8_t)(k->cert_len & 0xFF);
            } else {
                inner_buf[inner_len++] = (uint8_t)k->cert_len;
            }
            memcpy(inner_buf + inner_len, k->cert, k->cert_len);
            inner_len += k->cert_len;

            /* Tag 0x71: CertInfo */
            inner_buf[inner_len++] = 0x71; inner_buf[inner_len++] = 0x01; inner_buf[inner_len++] = 0x00;
            /* Tag 0xFE: EDC */
            inner_buf[inner_len++] = 0xFE; inner_buf[inner_len++] = 0x00;

            /* Wrap in Tag 0x53 */
            uint16_t w_idx = 0;
            wrap_buf[w_idx++] = 0x53;
            if (inner_len > 127) {
                wrap_buf[w_idx++] = 0x82;
                wrap_buf[w_idx++] = (uint8_t)(inner_len >> 8);
                wrap_buf[w_idx++] = (uint8_t)(inner_len & 0xFF);
            } else {
                wrap_buf[w_idx++] = (uint8_t)inner_len;
            }
            memcpy(wrap_buf + w_idx, inner_buf, inner_len);
            w_idx += inner_len;

            payload = wrap_buf;
            payload_len = w_idx;
        }

        if (payload && payload_len > 0) {
            if (payload_len + 2 > max_rsp_len) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            memcpy(rsp, payload, payload_len);
            rsp[payload_len]     = 0x90;
            rsp[payload_len + 1] = 0x00;
            return payload_len + 2;
        }

        rsp[0] = 0x6A; rsp[1] = 0x82; /* Not found */
        return 2;
    }

    /* 6. GENERAL AUTHENTICATE (0x87) */
    if (ins == 0x87) {
        uint8_t key_ref = p2;
        piv_key_t *k = &s_piv_key_9a;
        if (key_ref == 0x9C) k = &s_piv_key_9c;
        else if (key_ref == 0x9D) k = &s_piv_key_9d;
        else if (key_ref == 0x9E) k = &s_piv_key_9e;

        /* PIN check (9E is card authentication without PIN) */
        if (key_ref != 0x9E && !s_piv_pin_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
            return 2;
        }

        /* Parse Dynamic Auth Template (Tag 0x7C) */
        if (lc >= 4 && data[0] == 0x7C) {
            uint16_t t7c_len = data[1];
            const uint8_t *t7c_data = data + 2;
            if (t7c_len == 0x82) {
                if (lc < 4) { rsp[0] = 0x67; rsp[1] = 0x00; return 2; }
                t7c_len = ((uint16_t)data[2] << 8) | data[3];
                t7c_data = data + 4;
            } else if (t7c_len == 0x81) {
                if (lc < 3) { rsp[0] = 0x67; rsp[1] = 0x00; return 2; }
                t7c_len = data[2];
                t7c_data = data + 3;
            }

            if ((uint16_t)((t7c_data - data) + t7c_len) > lc) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }

            /* Find Tag 0x81 (Challenge to sign) or Tag 0x85 (ECDH peer point) */
            uint16_t offset = 0;
            const uint8_t *challenge = NULL;
            uint16_t chal_len = 0;
            const uint8_t *ecdh_peer = NULL;
            uint16_t ecdh_len = 0;

            while (offset + 1 < t7c_len) {
                uint8_t tag = t7c_data[offset++];
                uint16_t len = t7c_data[offset++];
                if (len == 0x82) {
                    if (offset + 2 > t7c_len) break;
                    len = ((uint16_t)t7c_data[offset] << 8) | t7c_data[offset + 1];
                    offset += 2;
                } else if (len == 0x81) {
                    if (offset >= t7c_len) break;
                    len = t7c_data[offset++];
                }
                if ((uint16_t)(offset + len) > t7c_len) break;

                if (tag == 0x81) {
                    challenge = t7c_data + offset;
                    chal_len = len;
                } else if (tag == 0x85) {
                    ecdh_peer = t7c_data + offset;
                    ecdh_len = len;
                }
                offset += len;
            }

            /* Case 1: Signature on Tag 0x81 */
            if (challenge && chal_len > 0) {
                if (p1 == 0x22) {
                    /* Ed25519 signature: raw 64 bytes */
                    uint8_t pk25519[32], sk25519[64];
                    ed25519_create_keypair(pk25519, sk25519, k->privkey);
                    uint8_t sig64[64];
                    ed25519_sign(sig64, challenge, chal_len, pk25519, sk25519);

                    /* Response: 7C 42 82 40 <sig64> 90 00 */
                    uint16_t total = 0;
                    rsp[total++] = 0x7C;
                    rsp[total++] = 66; /* 64 + 2 */
                    rsp[total++] = 0x82;
                    rsp[total++] = 64;
                    memcpy(rsp + total, sig64, 64);
                    total += 64;
                    rsp[total++] = 0x90;
                    rsp[total++] = 0x00;
                    return total;
                }

                uint8_t digest[32];
                if (chal_len == 32) {
                    memcpy(digest, challenge, 32);
                } else {
                    sha256_ctx_t sha;
                    sha256_init(&sha);
                    sha256_update(&sha, challenge, chal_len);
                    sha256_final(&sha, digest);
                }

                uint8_t raw_sig[64];
                uECC_sign(k->privkey, digest, 32, raw_sig, uECC_secp256r1());

                uint8_t der_sig[80];
                uint16_t der_len = encode_der_signature(der_sig, raw_sig);

                /* Response: 7C <len> 82 <der_len> <der_sig> 90 00 */
                uint16_t total = 0;
                rsp[total++] = 0x7C;
                rsp[total++] = (uint8_t)(der_len + 2);
                rsp[total++] = 0x82;
                rsp[total++] = (uint8_t)der_len;
                memcpy(rsp + total, der_sig, der_len);
                total += der_len;

                rsp[total++] = 0x90;
                rsp[total++] = 0x00;
                return total;
            }

            /* Case 2: ECDH Key Agreement on Tag 0x85 */
            if (ecdh_peer && ecdh_len >= 65 && ecdh_peer[0] == 0x04) {
                uint8_t secret[32];
                uECC_shared_secret(ecdh_peer + 1, k->privkey, secret, uECC_secp256r1());

                /* Response: 7C 22 82 20 <secret 32> 90 00 */
                uint16_t total = 0;
                rsp[total++] = 0x7C;
                rsp[total++] = 34;
                rsp[total++] = 0x82;
                rsp[total++] = 32;
                memcpy(rsp + total, secret, 32);
                total += 32;

                rsp[total++] = 0x90;
                rsp[total++] = 0x00;
                return total;
            }
        }

        rsp[0] = 0x6A; rsp[1] = 0x80;
        return 2;
    }

    /* 7. GENERATE ASYMMETRIC KEY PAIR (0x47) */
    if (ins == 0x47) {
        uint8_t key_ref = p2;
        piv_key_t *k = &s_piv_key_9a;
        if (key_ref == 0x9C) k = &s_piv_key_9c;
        else if (key_ref == 0x9D) k = &s_piv_key_9d;
        else if (key_ref == 0x9E) k = &s_piv_key_9e;

        if (p1 == 0x22) {
            /* Ed25519 public key template (Tag 0x86, 32 bytes) */
            uint8_t pk25519[32], sk25519[64];
            ed25519_create_keypair(pk25519, sk25519, k->privkey);
            uint16_t total = 0;
            rsp[total++] = 0x7F;
            rsp[total++] = 0x49;
            rsp[total++] = 34; /* 32 + 2 */
            rsp[total++] = 0x86;
            rsp[total++] = 32;
            memcpy(rsp + total, pk25519, 32);
            total += 32;
            rsp[total++] = 0x90;
            rsp[total++] = 0x00;
            return total;
        }

        /* Return public key template 0x7F49 containing Tag 0x86 (0x04 || pubkey 64) */
        uint16_t total = 0;
        rsp[total++] = 0x7F;
        rsp[total++] = 0x49;
        rsp[total++] = 67; /* 65 + 2 */
        rsp[total++] = 0x86;
        rsp[total++] = 65;
        rsp[total++] = 0x04;
        memcpy(rsp + total, k->pubkey, 64);
        total += 64;

        rsp[total++] = 0x90;
        rsp[total++] = 0x00;
        return total;
    }

    rsp[0] = 0x6D; rsp[1] = 0x00; /* Instruction not supported */
    return 2;
}

#include "ctap2.h"
#include "mldsa/mldsa.h"
#include "ed25519/ed25519.h"
#include "sha256/sha256.h"
#include "micro_ecc/uECC.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>
#include <stdbool.h>

static const uint8_t HYPRKEY_AAGUID[16] = {
    0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* ==================== CBOR Writer ==================== */
typedef struct {
    uint8_t *buf;
    size_t   max_len;
    size_t   pos;
} cbor_writer_t;

static void cbor_w_init(cbor_writer_t *w, uint8_t *buf, size_t max_len) {
    w->buf = buf;
    w->max_len = max_len;
    w->pos = 0;
}

static void cbor_w_byte(cbor_writer_t *w, uint8_t b) {
    if (w->pos < w->max_len) {
        w->buf[w->pos++] = b;
    }
}

static void cbor_w_header(cbor_writer_t *w, uint8_t major, uint64_t val) {
    uint8_t m = (uint8_t)(major << 5);
    if (val < 24) {
        cbor_w_byte(w, m | (uint8_t)val);
    } else if (val <= 0xFF) {
        cbor_w_byte(w, m | 24);
        cbor_w_byte(w, (uint8_t)val);
    } else if (val <= 0xFFFF) {
        cbor_w_byte(w, m | 25);
        cbor_w_byte(w, (uint8_t)(val >> 8));
        cbor_w_byte(w, (uint8_t)(val & 0xFF));
    } else if (val <= 0xFFFFFFFFULL) {
        cbor_w_byte(w, m | 26);
        cbor_w_byte(w, (uint8_t)(val >> 24));
        cbor_w_byte(w, (uint8_t)(val >> 16));
        cbor_w_byte(w, (uint8_t)(val >> 8));
        cbor_w_byte(w, (uint8_t)(val & 0xFF));
    }
}

static void cbor_w_uint(cbor_writer_t *w, uint64_t val) {
    cbor_w_header(w, 0, val);
}

static void cbor_w_nint(cbor_writer_t *w, uint64_t val) {
    cbor_w_header(w, 1, val);
}

static void cbor_w_int(cbor_writer_t *w, int64_t val) {
    if (val >= 0) {
        cbor_w_uint(w, (uint64_t)val);
    } else {
        cbor_w_nint(w, (uint64_t)(-1 - val));
    }
}

static void cbor_w_bstr(cbor_writer_t *w, const uint8_t *data, size_t len) {
    cbor_w_header(w, 2, len);
    for (size_t i = 0; i < len; i++) {
        cbor_w_byte(w, data[i]);
    }
}

static void cbor_w_tstr(cbor_writer_t *w, const char *str) {
    size_t len = strlen(str);
    cbor_w_header(w, 3, len);
    for (size_t i = 0; i < len; i++) {
        cbor_w_byte(w, (uint8_t)str[i]);
    }
}

static void __attribute__((unused)) cbor_w_array(cbor_writer_t *w, size_t count) {
    cbor_w_header(w, 4, count);
}

static void cbor_w_map(cbor_writer_t *w, size_t count) {
    cbor_w_header(w, 5, count);
}

/* ==================== CBOR Reader ==================== */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} cbor_reader_t;

static void cbor_r_init(cbor_reader_t *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

static bool cbor_r_get_header(cbor_reader_t *r, uint8_t *major, uint64_t *val) {
    if (r->pos >= r->len) return false;
    uint8_t b = r->data[r->pos++];
    *major = b >> 5;
    uint8_t info = b & 0x1F;

    if (info < 24) {
        *val = info;
    } else if (info == 24) {
        if (r->pos >= r->len) return false;
        *val = r->data[r->pos++];
    } else if (info == 25) {
        if (r->pos + 2 > r->len) return false;
        *val = ((uint64_t)r->data[r->pos] << 8) | r->data[r->pos + 1];
        r->pos += 2;
    } else if (info == 26) {
        if (r->pos + 4 > r->len) return false;
        *val = ((uint64_t)r->data[r->pos] << 24) |
               ((uint64_t)r->data[r->pos + 1] << 16) |
               ((uint64_t)r->data[r->pos + 2] << 8) |
               r->data[r->pos + 3];
        r->pos += 4;
    } else {
        return false;
    }
    return true;
}

#define CBOR_MAX_NESTING_DEPTH 6U

static bool cbor_r_skip_bounded(cbor_reader_t *r, uint8_t depth) {
    if (depth > CBOR_MAX_NESTING_DEPTH) {
        return false; /* Prevent recursive stack overflow */
    }
    uint8_t major;
    uint64_t val;
    if (!cbor_r_get_header(r, &major, &val)) return false;

    if (major == 0 || major == 1 || major == 7) {
        return true;
    } else if (major == 2 || major == 3) {
        if (val > (uint64_t)(r->len - r->pos)) return false;
        r->pos += (size_t)val;
        return true;
    } else if (major == 4) {
        if (val > 32) return false;
        for (uint64_t i = 0; i < val; i++) {
            if (!cbor_r_skip_bounded(r, depth + 1)) return false;
        }
        return true;
    } else if (major == 5) {
        if (val > 32) return false;
        for (uint64_t i = 0; i < val; i++) {
            if (!cbor_r_skip_bounded(r, depth + 1)) return false; /* key */
            if (!cbor_r_skip_bounded(r, depth + 1)) return false; /* value */
        }
        return true;
    }
    return false;
}

static inline bool cbor_r_skip(cbor_reader_t *r) {
    return cbor_r_skip_bounded(r, 0);
}

static bool cbor_r_get_bytes(cbor_reader_t *r, uint8_t expected_major, const uint8_t **out_ptr, size_t *out_len) {
    uint8_t major;
    uint64_t val;
    if (!cbor_r_get_header(r, &major, &val) || major != expected_major) return false;
    if (val > (uint64_t)(r->len - r->pos)) return false;
    *out_ptr = r->data + r->pos;
    *out_len = (size_t)val;
    r->pos += (size_t)val;
    return true;
}

/* ==================== Cryptographic Derivation ==================== */

static void derive_cred_seed(const uint8_t rp_id_hash[32], int32_t alg, uint8_t seed_out[32]) {
    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_CTAP2", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    const char tag[] = "CTAP2_CRED_SEED";
    sha256_update(&ctx, (const uint8_t *)tag, sizeof(tag) - 1);
    uint8_t alg_bytes[4] = {
        (uint8_t)(alg >> 24), (uint8_t)(alg >> 16),
        (uint8_t)(alg >> 8),  (uint8_t)(alg & 0xFF)
    };
    sha256_update(&ctx, alg_bytes, 4);
    sha256_update(&ctx, rp_id_hash, 32);
    sha256_final(&ctx, seed_out);
}

static void derive_cred_id(const uint8_t rp_id_hash[32], int32_t alg, uint8_t cred_id_out[32]) {
    /* Format of 32-byte cred_id:
     * [0..3]: alg (big endian)
     * [4..7]: 'H', 'Y', 'P', 'R' (tag)
     * [8..31]: HMAC/SHA256(master_key, tag || alg || rp_id_hash)[0..24]
     */
    cred_id_out[0] = (uint8_t)(alg >> 24);
    cred_id_out[1] = (uint8_t)(alg >> 16);
    cred_id_out[2] = (uint8_t)(alg >> 8);
    cred_id_out[3] = (uint8_t)(alg & 0xFF);
    cred_id_out[4] = 'H';
    cred_id_out[5] = 'Y';
    cred_id_out[6] = 'P';
    cred_id_out[7] = 'R';

    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_CTAP2", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    const char tag[] = "CRED_ID_MAC";
    sha256_update(&ctx, (const uint8_t *)tag, sizeof(tag) - 1);
    sha256_update(&ctx, cred_id_out, 4);
    sha256_update(&ctx, rp_id_hash, 32);
    uint8_t mac[32];
    sha256_final(&ctx, mac);
    memcpy(&cred_id_out[8], mac, 24);
}

static bool verify_cred_id(const uint8_t cred_id[32], const uint8_t rp_id_hash[32], int32_t *alg_out) {
    if (cred_id[4] != 'H' || cred_id[5] != 'Y' || cred_id[6] != 'P' || cred_id[7] != 'R') {
        return false;
    }
    int32_t alg = ((int32_t)cred_id[0] << 24) |
                  ((int32_t)cred_id[1] << 16) |
                  ((int32_t)cred_id[2] << 8)  |
                  ((int32_t)cred_id[3]);

    uint8_t expected[32];
    derive_cred_id(rp_id_hash, alg, expected);
    if (!crypto_consttime_eq(cred_id, expected, 32)) {
        return false;
    }
    *alg_out = alg;
    return true;
}

static uint16_t der_encode_ecdsa(const uint8_t *r, const uint8_t *s, uint8_t *out) {
    int r_start = 0;
    while (r_start < 31 && r[r_start] == 0) r_start++;
    bool r_pad = (r[r_start] & 0x80) != 0;
    uint8_t r_len = (32 - r_start) + (r_pad ? 1 : 0);

    int s_start = 0;
    while (s_start < 31 && s[s_start] == 0) s_start++;
    bool s_pad = (s[s_start] & 0x80) != 0;
    uint8_t s_len = (32 - s_start) + (s_pad ? 1 : 0);

    uint8_t total_seq_len = 2 + r_len + 2 + s_len;
    uint16_t idx = 0;
    out[idx++] = 0x30;
    out[idx++] = total_seq_len;

    out[idx++] = 0x02;
    out[idx++] = r_len;
    if (r_pad) out[idx++] = 0x00;
    memcpy(&out[idx], &r[r_start], 32 - r_start);
    idx += (32 - r_start);

    out[idx++] = 0x02;
    out[idx++] = s_len;
    if (s_pad) out[idx++] = 0x00;
    memcpy(&out[idx], &s[s_start], 32 - s_start);
    idx += (32 - s_start);

    return idx;
}

/* ==================== CTAP2 Command Handlers ==================== */

static uint16_t handle_get_info(uint8_t *rsp, uint16_t max_len) {
    /* Pre-encoded AuthenticatorGetInfo CBOR map (163 bytes) */
    static const uint8_t s_get_info_cbor[] = {
        0xa5,                                           /* map(5) */
        0x01, 0x83, 0x66, 0x55, 0x32, 0x46, 0x5f, 0x56, /* 1: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"] */
        0x32, 0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32,
        0x5f, 0x30, 0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f,
        0x32, 0x5f, 0x31,
        0x03, 0x50,                                     /* 3: aaguid (16 bytes) */
        0x48, 0x59, 0x50, 0x52, 0x4b, 0x45, 0x59, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xa4,                                     /* 4: options: map(4) */
        0x62, 0x72, 0x6b, 0xf5,                         /* "rk": true */
        0x62, 0x75, 0x70, 0xf5,                         /* "up": true */
        0x62, 0x75, 0x76, 0xf4,                         /* "uv": false */
        0x64, 0x70, 0x6c, 0x61, 0x74, 0xf4,             /* "plat": false */
        0x05, 0x19, 0x20, 0x00,                         /* 5: maxMsgSize = 8192 */
        0x0a, 0x85,                                     /* 10: algorithms: array(5) */
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -7} (ES256) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x26,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -8} (EdDSA / Ed25519) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x27,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -48} (ML-DSA-44) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x2f,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -49} (ML-DSA-65) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x30,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -50} (ML-DSA-87) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x31
    };

    if (max_len < sizeof(s_get_info_cbor) + 1) return 0;
    rsp[0] = CTAP1_ERR_SUCCESS;
    memcpy(rsp + 1, s_get_info_cbor, sizeof(s_get_info_cbor));
    return sizeof(s_get_info_cbor) + 1;
}

static uint16_t handle_make_credential(const uint8_t *payload, uint16_t len, uint8_t *rsp, uint16_t max_len) {
    cbor_reader_t r;
    cbor_r_init(&r, payload, len);

    uint8_t major;
    uint64_t map_entries;
    if (!cbor_r_get_header(&r, &major, &map_entries) || major != 5) {
        rsp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    uint8_t client_data_hash[32];
    bool has_cdh = false;
    uint8_t rp_id_hash[32];
    bool has_rp = false;
    int32_t chosen_alg = 0;
    bool has_alg = false;

    for (uint64_t m = 0; m < map_entries; m++) {
        uint8_t k_major;
        uint64_t key_val;
        if (!cbor_r_get_header(&r, &k_major, &key_val)) break;

        if (k_major == 0 && key_val == 1) {
            /* 1: clientDataHash (bstr, 32 bytes) */
            const uint8_t *cdh_ptr;
            size_t cdh_len;
            if (cbor_r_get_bytes(&r, 2, &cdh_ptr, &cdh_len) && cdh_len == 32) {
                memcpy(client_data_hash, cdh_ptr, 32);
                has_cdh = true;
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 2) {
            /* 2: rp (map with "id" text string) */
            uint8_t v_major;
            uint64_t rp_entries;
            if (cbor_r_get_header(&r, &v_major, &rp_entries) && v_major == 5) {
                for (uint64_t i = 0; i < rp_entries; i++) {
                    const uint8_t *k_str;
                    size_t rp_k_len;
                    if (cbor_r_get_bytes(&r, 3, &k_str, &rp_k_len)) {
                        if (rp_k_len == 2 && memcmp(k_str, "id", 2) == 0) {
                            const uint8_t *id_str;
                            size_t id_len;
                            if (cbor_r_get_bytes(&r, 3, &id_str, &id_len)) {
                                sha256_ctx_t sha;
                                sha256_init(&sha);
                                sha256_update(&sha, id_str, id_len);
                                sha256_final(&sha, rp_id_hash);
                                has_rp = true;
                            } else {
                                cbor_r_skip(&r);
                            }
                        } else {
                            cbor_r_skip(&r);
                        }
                    } else {
                        cbor_r_skip(&r);
                    }
                }
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 4) {
            /* 4: pubKeyCredParams (array of {"type": "public-key", "alg": int}) */
            uint8_t v_major;
            uint64_t param_count;
            if (cbor_r_get_header(&r, &v_major, &param_count) && v_major == 4) {
                for (uint64_t i = 0; i < param_count; i++) {
                    uint8_t item_major;
                    uint64_t item_entries;
                    if (cbor_r_get_header(&r, &item_major, &item_entries) && item_major == 5) {
                        int32_t entry_alg = 0;
                        for (uint64_t p = 0; p < item_entries; p++) {
                            uint8_t pk_major;
                            uint64_t pk_len;
                            if (cbor_r_get_header(&r, &pk_major, &pk_len) && pk_major == 3) {
                                const uint8_t *k_str = r.data + r.pos;
                                r.pos += (size_t)pk_len;
                                if (pk_len == 3 && memcmp(k_str, "alg", 3) == 0) {
                                    uint8_t a_major;
                                    uint64_t a_val;
                                    if (cbor_r_get_header(&r, &a_major, &a_val)) {
                                        if (a_major == 0) entry_alg = (int32_t)a_val;
                                        else if (a_major == 1) entry_alg = (int32_t)(-1 - a_val);
                                    }
                                } else {
                                    cbor_r_skip(&r);
                                }
                            } else {
                                cbor_r_skip(&r);
                            }
                        }
                        /* Preference: ML-DSA-44 (-48), ML-DSA-65 (-49), ML-DSA-87 (-50), Ed25519 (-8), ES256 (-7) */
                        if (!has_alg) {
                            if (entry_alg == -48 || entry_alg == -49 || entry_alg == -50 || entry_alg == -8 || entry_alg == -7) {
                                chosen_alg = entry_alg;
                                has_alg = true;
                            }
                        }
                    } else {
                        cbor_r_skip(&r);
                    }
                }
            } else {
                cbor_r_skip(&r);
            }
        } else {
            cbor_r_skip(&r);
        }
    }

    if (!has_cdh || !has_rp) {
        rsp[0] = CTAP1_ERR_INVALID_PAR;
        return 1;
    }
    if (!has_alg) {
        chosen_alg = -48; /* Default to ML-DSA-44 if none explicitly filtered */
    }

    /* 1. Derive credential seed and cred_id */
    uint8_t cred_seed[32];
    derive_cred_seed(rp_id_hash, chosen_alg, cred_seed);
    uint8_t cred_id[32];
    derive_cred_id(rp_id_hash, chosen_alg, cred_id);

    /* 2. Build authData */
    /* authData = rpIdHash (32) || flags 0x41 (1) || signCount (4) || aaguid (16) || credIdLen (2) || credId (32) || cose_key */
    static uint8_t auth_data[4096];
    cbor_writer_t aw;
    cbor_w_init(&aw, auth_data, sizeof(auth_data));

    /* Header: rpIdHash (32) */
    for (int i = 0; i < 32; i++) cbor_w_byte(&aw, rp_id_hash[i]);
    /* Flags: UP (0x01) | AT (0x40) = 0x41 */
    cbor_w_byte(&aw, 0x41);
    /* Sign counter (4 bytes big-endian) */
    uint32_t cnt = storage_increment_sign_counter();
    cbor_w_byte(&aw, (uint8_t)(cnt >> 24));
    cbor_w_byte(&aw, (uint8_t)(cnt >> 16));
    cbor_w_byte(&aw, (uint8_t)(cnt >> 8));
    cbor_w_byte(&aw, (uint8_t)(cnt & 0xFF));

    /* Attested Credential Data */
    /* aaguid (16 bytes) */
    for (int i = 0; i < 16; i++) cbor_w_byte(&aw, HYPRKEY_AAGUID[i]);
    /* credentialIdLength = 32 (0x00, 0x20) */
    cbor_w_byte(&aw, 0x00);
    cbor_w_byte(&aw, 0x20);
    /* credentialId (32 bytes) */
    for (int i = 0; i < 32; i++) cbor_w_byte(&aw, cred_id[i]);

    /* COSE Public Key */
    if (chosen_alg == -48) {
        /* ML-DSA-44: COSE Key (RFC 9964): { 1: 7, 3: -48, -1: pk (1312) } */
        static uint8_t pk44[MLDSA44_PUBLIC_KEY_SIZE];
        mldsa44_keygen(cred_seed, pk44, NULL);

        cbor_w_map(&aw, 3);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 7);   /* kty: AKP (7) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -48); /* alg: ML-DSA-44 (-48) */
        cbor_w_int(&aw, -1); cbor_w_bstr(&aw, pk44, MLDSA44_PUBLIC_KEY_SIZE);
    } else if (chosen_alg == -49) {
        /* ML-DSA-65: COSE Key (RFC 9964): { 1: 7, 3: -49, -1: pk (1952) } */
        static uint8_t pk65[MLDSA65_PUBLIC_KEY_SIZE];
        mldsa65_keygen(cred_seed, pk65, NULL);

        cbor_w_map(&aw, 3);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 7);   /* kty: AKP (7) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -49); /* alg: ML-DSA-65 (-49) */
        cbor_w_int(&aw, -1); cbor_w_bstr(&aw, pk65, MLDSA65_PUBLIC_KEY_SIZE);
    } else if (chosen_alg == -50) {
        /* ML-DSA-87: COSE Key (RFC 9964): { 1: 7, 3: -50, -1: pk (2592) } */
        static uint8_t pk87[MLDSA87_PUBLIC_KEY_SIZE];
        mldsa87_keygen(cred_seed, pk87, NULL);

        cbor_w_map(&aw, 3);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 7);   /* kty: AKP (7) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -50); /* alg: ML-DSA-87 (-50) */
        cbor_w_int(&aw, -1); cbor_w_bstr(&aw, pk87, MLDSA87_PUBLIC_KEY_SIZE);
    } else if (chosen_alg == -8) {
        /* Ed25519: COSE Key (RFC 8152): { 1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x (32) } */
        uint8_t pk25519[32], sk25519[64];
        ed25519_create_keypair(pk25519, sk25519, cred_seed);

        cbor_w_map(&aw, 4);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 1);  /* kty: OKP (1) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -8); /* alg: EdDSA (-8) */
        cbor_w_int(&aw, -1); cbor_w_int(&aw, 6);  /* crv: Ed25519 (6) */
        cbor_w_int(&aw, -2); cbor_w_bstr(&aw, pk25519, 32); /* x */
    } else {
        /* ES256 (-7): COSE Key: { 1: 2, 3: -7, -1: 1, -2: x (32), -3: y (32) } */
        uint8_t raw_pub[64];
        uECC_compute_public_key(cred_seed, raw_pub, uECC_secp256r1());

        cbor_w_map(&aw, 5);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 2);  /* kty: EC2 */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -7); /* alg: ES256 */
        cbor_w_int(&aw, -1); cbor_w_int(&aw, 1);  /* crv: P-256 */
        cbor_w_int(&aw, -2); cbor_w_bstr(&aw, raw_pub, 32);      /* x */
        cbor_w_int(&aw, -3); cbor_w_bstr(&aw, raw_pub + 32, 32); /* y */
    }

    /* 3. Build response: Status 0x00 || CBOR { 1: "none", 2: authData, 3: {} } */
    cbor_writer_t rw;
    cbor_w_init(&rw, rsp + 1, max_len - 1);
    cbor_w_map(&rw, 3);
    cbor_w_int(&rw, 1); cbor_w_tstr(&rw, "none");
    cbor_w_int(&rw, 2); cbor_w_bstr(&rw, auth_data, aw.pos);
    cbor_w_int(&rw, 3); cbor_w_map(&rw, 0);

    rsp[0] = CTAP1_ERR_SUCCESS;
    return (uint16_t)(rw.pos + 1);
}

static uint16_t handle_get_assertion(const uint8_t *payload, uint16_t len, uint8_t *rsp, uint16_t max_len) {
    cbor_reader_t r;
    cbor_r_init(&r, payload, len);

    uint8_t major;
    uint64_t map_entries;
    if (!cbor_r_get_header(&r, &major, &map_entries) || major != 5) {
        rsp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    uint8_t client_data_hash[32];
    bool has_cdh = false;
    uint8_t rp_id_hash[32];
    bool has_rp = false;
    uint8_t target_cred_id[32];
    bool has_cred_id = false;
    int32_t alg = -48; /* Default ML-DSA-44 */

    for (uint64_t m = 0; m < map_entries; m++) {
        uint8_t k_major;
        uint64_t key_val;
        if (!cbor_r_get_header(&r, &k_major, &key_val)) break;

        if (k_major == 0 && key_val == 1) {
            /* 1: rpId (text string) */
            const uint8_t *id_str;
            size_t id_len;
            if (cbor_r_get_bytes(&r, 3, &id_str, &id_len)) {
                sha256_ctx_t sha;
                sha256_init(&sha);
                sha256_update(&sha, id_str, id_len);
                sha256_final(&sha, rp_id_hash);
                has_rp = true;
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 2) {
            /* 2: clientDataHash (bstr, 32 bytes) */
            const uint8_t *cdh_ptr;
            size_t cdh_len;
            if (cbor_r_get_bytes(&r, 2, &cdh_ptr, &cdh_len) && cdh_len == 32) {
                memcpy(client_data_hash, cdh_ptr, 32);
                has_cdh = true;
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 3) {
            /* 3: allowList (array of {"id": bstr, "type": "public-key"}) */
            uint8_t v_major;
            uint64_t list_count;
            if (cbor_r_get_header(&r, &v_major, &list_count) && v_major == 4) {
                for (uint64_t i = 0; i < list_count; i++) {
                    uint8_t d_major;
                    uint64_t d_entries;
                    if (cbor_r_get_header(&r, &d_major, &d_entries) && d_major == 5) {
                        for (uint64_t d = 0; d < d_entries; d++) {
                            const uint8_t *k_str;
                            size_t dk_len;
                            if (cbor_r_get_bytes(&r, 3, &k_str, &dk_len)) {
                                if (dk_len == 2 && memcmp(k_str, "id", 2) == 0) {
                                    const uint8_t *id_bstr;
                                    size_t id_bstr_len;
                                    if (cbor_r_get_bytes(&r, 2, &id_bstr, &id_bstr_len) && id_bstr_len == 32) {
                                        memcpy(target_cred_id, id_bstr, 32);
                                        has_cred_id = true;
                                    } else {
                                        cbor_r_skip(&r);
                                    }
                                } else {
                                    cbor_r_skip(&r);
                                }
                            } else {
                                cbor_r_skip(&r);
                            }
                        }
                    } else {
                        cbor_r_skip(&r);
                    }
                }
            } else {
                cbor_r_skip(&r);
            }
        } else {
            cbor_r_skip(&r);
        }
    }

    if (!has_cdh || !has_rp) {
        rsp[0] = CTAP1_ERR_INVALID_PAR;
        return 1;
    }

    /* Verify or reconstruct credential */
    if (has_cred_id) {
        if (!verify_cred_id(target_cred_id, rp_id_hash, &alg)) {
            rsp[0] = CTAP2_ERR_NO_CREDENTIALS;
            return 1;
        }
    } else {
        /* Default non-resident credential derivation */
        derive_cred_id(rp_id_hash, alg, target_cred_id);
    }

    uint8_t cred_seed[32];
    derive_cred_seed(rp_id_hash, alg, cred_seed);

    /* 1. Build authData (37 bytes) = rpIdHash (32) || flags 0x01 (1) || signCount (4) */
    uint8_t auth_data[37];
    memcpy(auth_data, rp_id_hash, 32);
    auth_data[32] = 0x01; /* UP = 1 */
    uint32_t cnt = storage_increment_sign_counter();
    auth_data[33] = (uint8_t)(cnt >> 24);
    auth_data[34] = (uint8_t)(cnt >> 16);
    auth_data[35] = (uint8_t)(cnt >> 8);
    auth_data[36] = (uint8_t)(cnt & 0xFF);

    /* 2. Message to sign = authData (37) || clientDataHash (32) = 69 bytes */
    uint8_t msg_to_sign[69];
    memcpy(msg_to_sign, auth_data, 37);
    memcpy(msg_to_sign + 37, client_data_hash, 32);

    /* 3. Compute signature */
    static uint8_t sig_buf[5000];
    size_t sig_len = 0;

    if (alg == -48) {
        mldsa44_sign_seed(cred_seed, msg_to_sign, 69, NULL, sig_buf);
        sig_len = MLDSA44_SIGNATURE_SIZE;
    } else if (alg == -49) {
        mldsa65_sign_seed(cred_seed, msg_to_sign, 69, NULL, sig_buf);
        sig_len = MLDSA65_SIGNATURE_SIZE;
    } else if (alg == -50) {
        mldsa87_sign_seed(cred_seed, msg_to_sign, 69, NULL, sig_buf);
        sig_len = MLDSA87_SIGNATURE_SIZE;
    } else if (alg == -8) {
        /* Ed25519 (raw 64-byte signature) */
        uint8_t pk25519[32], sk25519[64];
        ed25519_create_keypair(pk25519, sk25519, cred_seed);
        ed25519_sign(sig_buf, msg_to_sign, 69, pk25519, sk25519);
        sig_len = 64;
    } else {
        /* ES256 (-7) */
        uint8_t hash[32];
        sha256_ctx_t sha;
        sha256_init(&sha);
        sha256_update(&sha, msg_to_sign, 69);
        sha256_final(&sha, hash);

        uint8_t raw_sig[64];
        uECC_sign(cred_seed, hash, 32, raw_sig, uECC_secp256r1());
        sig_len = der_encode_ecdsa(raw_sig, raw_sig + 32, sig_buf);
    }

    /* 4. Build CBOR response: { 1: {"id": target_cred_id, "type": "public-key"}, 2: authData, 3: signature } */
    cbor_writer_t rw;
    cbor_w_init(&rw, rsp + 1, max_len - 1);
    cbor_w_map(&rw, 3);

    /* 1: credential */
    cbor_w_int(&rw, 1);
    cbor_w_map(&rw, 2);
    cbor_w_tstr(&rw, "id");
    cbor_w_bstr(&rw, target_cred_id, 32);
    cbor_w_tstr(&rw, "type");
    cbor_w_tstr(&rw, "public-key");

    /* 2: authData */
    cbor_w_int(&rw, 2);
    cbor_w_bstr(&rw, auth_data, 37);

    /* 3: signature */
    cbor_w_int(&rw, 3);
    cbor_w_bstr(&rw, sig_buf, sig_len);

    rsp[0] = CTAP1_ERR_SUCCESS;
    return (uint16_t)(rw.pos + 1);
}

/* Main CTAP2 dispatcher */
uint16_t ctap2_process_cbor(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (req_len < 1) {
        rsp[0] = CTAP1_ERR_INVALID_LENGTH;
        return 1;
    }

    uint8_t cmd = req[0];
    const uint8_t *payload = req + 1;
    uint16_t payload_len = req_len - 1;

    switch (cmd) {
        case CTAP2_CMD_GET_INFO:
            return handle_get_info(rsp, max_rsp_len);

        case CTAP2_CMD_MAKE_CREDENTIAL:
            return handle_make_credential(payload, payload_len, rsp, max_rsp_len);

        case CTAP2_CMD_GET_ASSERTION:
            return handle_get_assertion(payload, payload_len, rsp, max_rsp_len);

        case CTAP2_CMD_RESET:
            rsp[0] = CTAP1_ERR_SUCCESS;
            return 1;

        default:
            rsp[0] = CTAP1_ERR_INVALID_COMMAND;
            return 1;
    }
}

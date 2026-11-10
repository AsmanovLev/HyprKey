#include "fido_u2f.h"
#include "attestation.h"
#include "sha256.h"
#include "uECC.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>

#define RNG_BASE 0x4000D000UL
#define RNG_TASKS_START   (*(volatile uint32_t *)(RNG_BASE + 0x000))
#define RNG_TASKS_STOP    (*(volatile uint32_t *)(RNG_BASE + 0x004))
#define RNG_EVENTS_VALRDY (*(volatile uint32_t *)(RNG_BASE + 0x100))
#define RNG_VALUE         (*(volatile uint32_t *)(RNG_BASE + 0x508))
#define NRF_RNG_CONFIG    (*(volatile uint32_t *)(RNG_BASE + 0x504))

/* Multi-chunk chaining buffer for ISO 7816-4 GET RESPONSE (61 XX) */
static uint8_t g_pending_rsp[800];
static uint16_t g_pending_len = 0;
static uint16_t g_pending_offset = 0;

static int nrf_trng(uint8_t *dest, unsigned size) {
    NRF_RNG_CONFIG = 1UL; /* Enable Digital Error Correction (Bias elimination) */
    RNG_TASKS_START = 1UL;
    while (size--) {
        RNG_EVENTS_VALRDY = 0UL;
        uint32_t timeout = 100000UL;
        while (!RNG_EVENTS_VALRDY && --timeout);
        if (timeout == 0UL) {
            RNG_TASKS_STOP = 1UL;
            return 0; /* RNG failure */
        }
        *dest++ = (uint8_t)RNG_VALUE;
    }
    RNG_TASKS_STOP = 1UL;
    return 1;
}

void fido_init(void) {
    uECC_set_rng(nrf_trng);
    g_pending_len = 0;
    g_pending_offset = 0;
}

static uint16_t der_encode_sig(const uint8_t *r, const uint8_t *s, uint8_t *out) {
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

static void derive_user_key(const uint8_t app_param[32], uint8_t priv_key[32], uint8_t pub_key_uncomp[65]) {
    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_U2F", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, sizeof(master_key));
    sha256_update(&ctx, app_param, 32);
    sha256_final(&ctx, priv_key);

    uint8_t raw_pub[64];
    uECC_compute_public_key(priv_key, raw_pub, uECC_secp256r1());
    pub_key_uncomp[0] = 0x04;
    memcpy(&pub_key_uncomp[1], raw_pub, 64);
}

static void derive_key_handle(const uint8_t app_param[32], uint8_t key_handle[32]) {
    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_U2F", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    uint8_t tag[] = "HYPRKEY_KEY_HANDLE";
    sha256_update(&ctx, tag, sizeof(tag) - 1);
    sha256_update(&ctx, master_key, sizeof(master_key));
    sha256_update(&ctx, app_param, 32);
    sha256_final(&ctx, key_handle);
}

int fido_process_apdu(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len) {
    (void)max_rsp_len;
    if (req_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    uint8_t cla = req[0];
    uint8_t ins = req[1];
    uint8_t p1  = req[2];
    uint8_t p2  = req[3];
    (void)p2;

    /* Detect Short vs. Extended APDU framing (ISO 7816-4) */
    uint16_t data_offset = 5;
    uint16_t lc = 0;
    if (req_len >= 7 && req[4] == 0x00) {
        /* Extended APDU: Lc is 2 bytes at req[5..6], data starts at req[7] */
        lc = ((uint16_t)req[5] << 8) | req[6];
        data_offset = 7;
    } else if (req_len >= 5) {
        /* Short APDU: Lc is 1 byte at req[4], data starts at req[5] */
        lc = req[4];
        data_offset = 5;
    }

    /* 0. ISO 7816-4 GET RESPONSE (INS = 0xC0) */
    if (cla == 0x00 && ins == 0xC0) {
        if (g_pending_offset >= g_pending_len) {
            rsp[0] = 0x69; rsp[1] = 0x85;
            return 2;
        }

        uint16_t rem = g_pending_len - g_pending_offset;
        uint16_t chunk = (rem > 220) ? 220 : rem;

        memcpy(rsp, &g_pending_rsp[g_pending_offset], chunk);
        g_pending_offset += chunk;

        if (g_pending_offset < g_pending_len) {
            uint16_t next_rem = g_pending_len - g_pending_offset;
            rsp[chunk]     = 0x61; /* More data available */
            rsp[chunk + 1] = (next_rem > 255) ? 0x00 : (uint8_t)next_rem;
            return chunk + 2;
        } else {
            rsp[chunk]     = 0x90; /* Completed */
            rsp[chunk + 1] = 0x00;
            g_pending_len = 0;
            g_pending_offset = 0;
            return chunk + 2;
        }
    }

    /* New non-chaining command -> clear pending buffer */
    g_pending_len = 0;
    g_pending_offset = 0;

    /* 0b. Diagnostic command (INS = 0xFE) */
    if (cla == 0x00 && ins == 0xFE) {
        extern uint32_t g_dbg_ccid_rx_count;
        extern uint32_t g_dbg_ccid_tx_count;
        extern uint32_t g_dbg_last_ccid_cmd;
        extern uint32_t g_dbg_last_ep0_req;
        rsp[0] = (uint8_t)(g_dbg_ccid_rx_count & 0xFF);
        rsp[1] = (uint8_t)((g_dbg_ccid_rx_count >> 8) & 0xFF);
        rsp[2] = (uint8_t)(g_dbg_ccid_tx_count & 0xFF);
        rsp[3] = (uint8_t)((g_dbg_ccid_tx_count >> 8) & 0xFF);
        rsp[4] = (uint8_t)g_dbg_last_ccid_cmd;
        rsp[5] = (uint8_t)g_dbg_last_ep0_req;
        rsp[6] = 0x90;
        rsp[7] = 0x00;
        return 8;
    }

    /* 1. SELECT FIDO AID */
    if (cla == 0x00 && ins == 0xA4 && p1 == 0x04) {
        static const uint8_t FIDO_AID[] = { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 };
        if (req_len >= data_offset + sizeof(FIDO_AID) &&
            memcmp(&req[data_offset], FIDO_AID, sizeof(FIDO_AID)) == 0) {
            static const uint8_t version_str[] = { 'U', '2', 'F', '_', 'V', '2' };
            memcpy(rsp, version_str, sizeof(version_str));
            rsp[sizeof(version_str)]     = 0x90;
            rsp[sizeof(version_str) + 1] = 0x00;
            return sizeof(version_str) + 2;
        }
        rsp[0] = 0x6A; rsp[1] = 0x82;
        return 2;
    }

    /* 2. U2F VERSION (0x03) */
    if (cla == 0x00 && ins == 0x03) {
        static const uint8_t version_str[] = { 'U', '2', 'F', '_', 'V', '2' };
        memcpy(rsp, version_str, sizeof(version_str));
        rsp[sizeof(version_str)]     = 0x90;
        rsp[sizeof(version_str) + 1] = 0x00;
        return sizeof(version_str) + 2;
    }

    /* 3. U2F AUTHENTICATE (0x02) */
    if (cla == 0x00 && ins == 0x02) {
        if (req_len < data_offset + 32 + 32 + 1) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        const uint8_t *challenge = &req[data_offset];
        const uint8_t *app_param = &req[data_offset + 32];
        uint8_t kh_len = req[data_offset + 64];

        if (req_len < (uint16_t)(data_offset + 64 + 1 + kh_len)) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        const uint8_t *key_handle = &req[data_offset + 64 + 1];

        uint8_t expected_kh[32];
        derive_key_handle(app_param, expected_kh);
        if (kh_len != 32 || !crypto_consttime_eq(key_handle, expected_kh, 32)) {
            /* Key handle not recognized */
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        if (p1 == 0x07) {
            /* Check-only: Key recognized! */
            rsp[0] = 0x69; rsp[1] = 0x85;
            return 2;
        }

        /* Enforce user presence & sign (P1 == 0x03 or 0x08) */
        uint8_t user_priv[32], user_pub[65];
        derive_user_key(app_param, user_priv, user_pub);

        uint32_t cur_counter = storage_increment_sign_counter();
        uint8_t up_flags = 0x01;

        sha256_ctx_t s_ctx;
        sha256_init(&s_ctx);
        sha256_update(&s_ctx, app_param, 32);
        sha256_update(&s_ctx, &up_flags, 1);
        uint8_t cnt_bytes[4] = {
            (uint8_t)(cur_counter >> 24),
            (uint8_t)(cur_counter >> 16),
            (uint8_t)(cur_counter >> 8),
            (uint8_t)(cur_counter)
        };
        sha256_update(&s_ctx, cnt_bytes, 4);
        sha256_update(&s_ctx, challenge, 32);
        uint8_t auth_hash[32];
        sha256_final(&s_ctx, auth_hash);

        uint8_t raw_sig[64];
        if (!uECC_sign(user_priv, auth_hash, 32, raw_sig, uECC_secp256r1())) {
            rsp[0] = 0x6F; rsp[1] = 0x00;
            return 2;
        }

        uint16_t out_idx = 0;
        rsp[out_idx++] = up_flags;
        memcpy(&rsp[out_idx], cnt_bytes, 4);
        out_idx += 4;

        uint16_t sig_len = der_encode_sig(raw_sig, &raw_sig[32], &rsp[out_idx]);
        out_idx += sig_len;

        rsp[out_idx++] = 0x90;
        rsp[out_idx++] = 0x00;
        return out_idx;
    }

    /* 4. U2F REGISTER (0x01) */
    if (cla == 0x00 && ins == 0x01) {
        if (req_len < data_offset + 32 + 32) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        const uint8_t *challenge = &req[data_offset];
        const uint8_t *app_param = &req[data_offset + 32];

        uint8_t user_priv[32], user_pub[65];
        derive_user_key(app_param, user_priv, user_pub);

        uint8_t key_handle[32];
        derive_key_handle(app_param, key_handle);

        sha256_ctx_t reg_ctx;
        sha256_init(&reg_ctx);
        uint8_t rfu = 0x00;
        sha256_update(&reg_ctx, &rfu, 1);
        sha256_update(&reg_ctx, app_param, 32);
        sha256_update(&reg_ctx, challenge, 32);
        sha256_update(&reg_ctx, key_handle, 32);
        sha256_update(&reg_ctx, user_pub, 65);
        uint8_t reg_hash[32];
        sha256_final(&reg_ctx, reg_hash);

        uint8_t raw_sig[64];
        if (!uECC_sign(HYPRKEY_ATTEST_PRIVKEY, reg_hash, 32, raw_sig, uECC_secp256r1())) {
            rsp[0] = 0x6F; rsp[1] = 0x00;
            return 2;
        }

        /* Assemble full registration response directly into rsp */
        uint16_t out_idx = 0;
        rsp[out_idx++] = 0x05;
        memcpy(&rsp[out_idx], user_pub, 65);
        out_idx += 65;

        rsp[out_idx++] = 32;
        memcpy(&rsp[out_idx], key_handle, 32);
        out_idx += 32;

        uint16_t cert_len = sizeof(HYPRKEY_ATTEST_CERT);
        memcpy(&rsp[out_idx], HYPRKEY_ATTEST_CERT, cert_len);
        out_idx += cert_len;

        uint16_t sig_len = der_encode_sig(raw_sig, &raw_sig[32], &rsp[out_idx]);
        out_idx += sig_len;

        rsp[out_idx++] = 0x90;
        rsp[out_idx++] = 0x00;
        return out_idx;
    }

    /* 5. CTAP2 Encapsulation (CLA = 0x80, INS = 0x10) */
    if (cla == 0x80 && ins == 0x10) {
        if (req_len >= data_offset && lc >= 1 && req[data_offset] == 0x04) {
            static const uint8_t CTAP2_GETINFO_CBOR[] = {
                0x00,
                0xA5,
                0x01, 0x82, 0x66, 'U', '2', 'F', '_', 'V', '2', 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '0',
                0x02, 0x81, 0x6B, 'c', 'r', 'e', 'd', 'P', 'r', 'o', 't', 'e', 'c', 't',
                0x03, 0x50, 0x48, 0x79, 0x70, 0x72, 0x4B, 0x65, 0x79, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
                0x04, 0xA3, 0x62, 'r', 'k', 0xF5, 0x62, 'u', 'p', 0xF5, 0x62, 'u', 'v', 0xF4,
                0x05, 0x19, 0x04, 0xB0
            };

            memcpy(rsp, CTAP2_GETINFO_CBOR, sizeof(CTAP2_GETINFO_CBOR));
            rsp[sizeof(CTAP2_GETINFO_CBOR)]     = 0x90;
            rsp[sizeof(CTAP2_GETINFO_CBOR) + 1] = 0x00;
            return sizeof(CTAP2_GETINFO_CBOR) + 2;
        }
    }

    rsp[0] = 0x6D;
    rsp[1] = 0x00;
    return 2;
}

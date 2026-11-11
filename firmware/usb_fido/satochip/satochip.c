#include "satochip.h"
#include <string.h>
#include "micro_ecc/uECC.h"
#include "ed25519/ed25519.h"
#include "fips202/fips202.h"
#include "sha512/sha512.h"
#include "sha256/sha256.h"
#include "ripemd160/ripemd160.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include "device_log.h"

/* Satochip Applet AIDs */
const uint8_t SATOCHIP_AID[SATOCHIP_AID_LEN] = { 0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70 }; /* "SatoChip" */
const uint8_t SATOCHIP_AID_ALT[SATOCHIP_AID_ALT_LEN] = { 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01 };

/* Hardware registers for Touch Button (P0.11) and LED (P0.15) */
#define P0_OUTSET (*(volatile uint32_t *)0x50000508UL)
#define P0_OUTCLR (*(volatile uint32_t *)0x5000050CUL)
#define P0_IN     (*(volatile uint32_t *)0x50000510UL)
#define PIN_TOUCH 11
#define PIN_LED   15

/* Wallet State */
static uint8_t  s_master_seed[64] = { 0 };
static bool     s_seed_initialized = false;
static uint8_t  s_wallet_pin[16] = "1234";
static uint8_t  s_wallet_pin_len = 4;
static uint8_t  s_pin_tries_left = 3;
static bool     s_pin_verified = false;

/* Curve secp256k1 order N */
static const uint8_t SECP256K1_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

/* ==================== Cryptographic Primitives ==================== */

static void hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[64]) {
    uint8_t k[128] = {0};
    if (key_len > 128) {
        sha512(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[128], opad[128];
    for (int i = 0; i < 128; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    sha512_ctx_t ctx;
    uint8_t inner[64];
    sha512_init(&ctx);
    sha512_update(&ctx, ipad, 128);
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, inner);

    sha512_init(&ctx);
    sha512_update(&ctx, opad, 128);
    sha512_update(&ctx, inner, 64);
    sha512_final(&ctx, out);

    crypto_zero(k, sizeof(k));
    crypto_zero(ipad, sizeof(ipad));
    crypto_zero(opad, sizeof(opad));
    crypto_zero(inner, sizeof(inner));
}

static void secp256k1_add_mod_n(const uint8_t a[32], const uint8_t b[32], uint8_t res[32]) {
    uint32_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint32_t sum = (uint32_t)a[i] + (uint32_t)b[i] + carry;
        res[i] = (uint8_t)sum;
        carry = sum >> 8;
    }

    bool ge = false;
    if (carry) {
        ge = true;
    } else {
        for (int i = 0; i < 32; i++) {
            if (res[i] > SECP256K1_N[i]) { ge = true; break; }
            if (res[i] < SECP256K1_N[i]) { ge = false; break; }
        }
    }

    if (ge) {
        uint32_t borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int32_t diff = (int32_t)res[i] - (int32_t)SECP256K1_N[i] - (int32_t)borrow;
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            res[i] = (uint8_t)diff;
        }
    }
}

/* ==================== BIP-32 & SLIP-0010 Key Derivation ==================== */

static bool derive_bip32_key(const uint32_t *path, uint8_t depth,
                            uint8_t child_priv[32], uint8_t child_chain[32],
                            bool is_ed25519) {
    if (depth > 10) return false;

    uint8_t cur_priv[32];
    uint8_t cur_chain[32];

    /* Master Key Generation */
    uint8_t master_out[64];
    if (is_ed25519) {
        hmac_sha512((const uint8_t *)"ed25519 seed", 12, s_master_seed, 64, master_out);
    } else {
        hmac_sha512((const uint8_t *)"Bitcoin seed", 12, s_master_seed, 64, master_out);
    }
    memcpy(cur_priv, master_out, 32);
    memcpy(cur_chain, master_out + 32, 32);
    crypto_zero(master_out, sizeof(master_out));

    /* Derive each step along path */
    for (uint8_t d = 0; d < depth; d++) {
        uint32_t index = path[d];
        uint8_t data[37];
        size_t data_len = 0;

        if (is_ed25519) {
            /* SLIP-0010: Ed25519 only supports hardened derivation */
            if ((index & 0x80000000UL) == 0) {
                crypto_zero(cur_priv, sizeof(cur_priv));
                return false;
            }
            data[0] = 0x00;
            memcpy(&data[1], cur_priv, 32);
            data[33] = (uint8_t)(index >> 24);
            data[34] = (uint8_t)(index >> 16);
            data[35] = (uint8_t)(index >> 8);
            data[36] = (uint8_t)index;
            data_len = 37;

            uint8_t I[64];
            hmac_sha512(cur_chain, 32, data, data_len, I);
            memcpy(cur_priv, I, 32);
            memcpy(cur_chain, I + 32, 32);
            crypto_zero(I, sizeof(I));
        } else {
            /* BIP-32 over secp256k1 */
            if (index & 0x80000000UL) {
                /* Hardened derivation */
                data[0] = 0x00;
                memcpy(&data[1], cur_priv, 32);
                data[33] = (uint8_t)(index >> 24);
                data[34] = (uint8_t)(index >> 16);
                data[35] = (uint8_t)(index >> 8);
                data[36] = (uint8_t)index;
                data_len = 37;
            } else {
                /* Normal public derivation */
                uint8_t pub[64];
                uECC_compute_public_key(cur_priv, pub, uECC_secp256k1());
                uECC_compress(pub, data, uECC_secp256k1()); /* 33 bytes compressed */
                data[33] = (uint8_t)(index >> 24);
                data[34] = (uint8_t)(index >> 16);
                data[35] = (uint8_t)(index >> 8);
                data[36] = (uint8_t)index;
                data_len = 37;
            }

            uint8_t I[64];
            hmac_sha512(cur_chain, 32, data, data_len, I);
            secp256k1_add_mod_n(cur_priv, I, cur_priv);
            memcpy(cur_chain, I + 32, 32);
            crypto_zero(I, sizeof(I));
        }
    }

    memcpy(child_priv, cur_priv, 32);
    if (child_chain) memcpy(child_chain, cur_chain, 32);
    crypto_zero(cur_priv, sizeof(cur_priv));
    return true;
}

/* ==================== User Presence Touch Check ==================== */

static bool wait_for_user_touch(uint32_t timeout_ms) {
    if (P0_IN & (1UL << PIN_TOUCH)) return true;

    /* Blink LED while waiting for touch confirmation */
    for (uint32_t ms = 0; ms < timeout_ms; ms += 20) {
        if (P0_IN & (1UL << PIN_TOUCH)) {
            P0_OUTSET = (1UL << PIN_LED);
            return true;
        }
        if ((ms % 200) < 100) {
            P0_OUTCLR = (1UL << PIN_LED);
        } else {
            P0_OUTSET = (1UL << PIN_LED);
        }
        for (volatile int d = 0; d < 12800; d++);
    }
    P0_OUTSET = (1UL << PIN_LED);
    return (P0_IN & (1UL << PIN_TOUCH)) != 0;
}

/* ==================== Public API ==================== */

void satochip_init(void) {
    /* If master seed is not explicitly set, derive default deterministic seed from Nordic FICR */
    if (!s_seed_initialized) {
        storage_get_device_master_key("HYPR_BIP32_WALLET_ROOT", s_master_seed);
        storage_get_device_master_key("HYPR_BIP32_WALLET_ROOT_EXT", s_master_seed + 32);
        s_seed_initialized = true;
    }
    s_pin_tries_left = 3;
    s_pin_verified = false;
}

bool satochip_is_pin_verified(void) {
    return s_pin_verified;
}

/* ==================== Monero Base58 Encoder ==================== */
static const char MONERO_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void monero_b58_encode_block(uint64_t val, int size, char *out) {
    for (int i = size - 1; i >= 0; i--) {
        out[i] = MONERO_ALPHABET[val % 58];
        val /= 58;
    }
}

static void monero_base58_encode(const uint8_t *data, size_t len, char *out) {
    size_t full_blocks = len / 8;
    char *ptr = out;
    for (size_t b = 0; b < full_blocks; b++) {
        uint64_t val = 0;
        for (int i = 0; i < 8; i++) {
            val = (val << 8) | data[b * 8 + i];
        }
        monero_b58_encode_block(val, 11, ptr);
        ptr += 11;
    }
    size_t rem = len % 8;
    if (rem > 0) {
        uint64_t val = 0;
        for (size_t i = 0; i < rem; i++) {
            val = (val << 8) | data[full_blocks * 8 + i];
        }
        int enc_len = (rem == 5) ? 7 : (rem == 4 ? 6 : (rem == 3 ? 5 : (rem == 2 ? 3 : 2)));
        monero_b58_encode_block(val, enc_len, ptr);
        ptr += enc_len;
    }
    *ptr = '\0';
}

/* ==================== Standard Bitcoin / Tron / Litecoin Base58 ==================== */
static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void base58_encode(const uint8_t *data, size_t len, char *out) {
    uint8_t digits[128] = {0};
    size_t digits_len = 1;

    for (size_t i = 0; i < len; i++) {
        uint32_t carry = data[i];
        for (size_t j = 0; j < digits_len; j++) {
            carry += (uint32_t)digits[j] << 8;
            digits[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits[digits_len++] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < len && data[i] == 0; i++) {
        out[out_idx++] = '1';
    }
    for (size_t i = 0; i < digits_len; i++) {
        out[out_idx++] = BASE58_ALPHABET[digits[digits_len - 1 - i]];
    }
    out[out_idx] = '\0';
}

static void base58check_encode(uint8_t version, const uint8_t *payload, size_t payload_len, char *out) {
    uint8_t buf[64];
    buf[0] = version;
    memcpy(buf + 1, payload, payload_len);

    uint8_t h1[32], h2[32];
    sha256_hash(buf, 1 + payload_len, h1);
    sha256_hash(h1, 32, h2);

    memcpy(buf + 1 + payload_len, h2, 4);
    base58_encode(buf, 1 + payload_len + 4, out);
}

uint16_t satochip_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x6E; rsp[1] = 0x00; /* Class not supported */
        return 2;
    }

    uint8_t cla = apdu[0];
    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    uint8_t p2  = apdu[3];
    (void)cla;
    (void)p2;

    /* Extended / ISO APDU Parser */
    const uint8_t *data = NULL;
    uint16_t lc = 0;
    if (!iso7816_parse_apdu(apdu, apdu_len, &data, &lc)) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    /* 1. SELECT APPLET (00 A4 04 ...) */
    if (ins == 0xA4 && p1 == 0x04) {
        s_pin_verified = false; /* Reset auth on new select */
        rsp[0] = 0x00; /* Protocol version major: 0 */
        rsp[1] = 0x0C; /* Protocol version minor: 12 (v0.12) */
        rsp[2] = 0x01; /* Applet version major: 1 */
        rsp[3] = 0x00; /* Applet version minor: 0 */
        rsp[4] = s_pin_tries_left;
        rsp[5] = s_seed_initialized ? 0x01 : 0x00;
        rsp[6] = 0x01; /* Needs 2FA / Touch Confirmation */
        rsp[7] = 0x90;
        rsp[8] = 0x00;
        return 9;
    }

    /* 2. GET STATUS (B0 6D 00 00) */
    if (ins == 0x6D) {
        rsp[0] = s_seed_initialized ? 0x01 : 0x00;
        rsp[1] = s_pin_verified ? 0x01 : 0x00;
        rsp[2] = s_pin_tries_left;
        rsp[3] = 0x01; /* Hardware Touch Enabled */
        rsp[4] = 0x90;
        rsp[5] = 0x00;
        return 6;
    }

    /* 3. VERIFY PIN (B0 20 00 00) */
    if (ins == 0x20) {
        if (s_pin_tries_left == 0) {
            rsp[0] = 0x69; rsp[1] = 0x83; /* Authentication method blocked */
            return 2;
        }
        if (lc == s_wallet_pin_len &&
            crypto_consttime_eq(data, s_wallet_pin, s_wallet_pin_len)) {
            s_pin_verified = true;
            s_pin_tries_left = 3;
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0x5A, 1, 0);
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else {
            s_pin_verified = false;
            s_pin_tries_left--;
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0x5A, 0, s_pin_tries_left);
            rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pin_tries_left);
            return 2;
        }
    }

    /* 4. CHANGE PIN (B0 22 00 00) */
    if (ins == 0x22) {
        if (!s_pin_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
            return 2;
        }
        if (lc < 2) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        uint8_t old_len = data[0];
        if (1 + old_len >= lc) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        uint8_t new_len = data[1 + old_len];
        if (1 + old_len + 1 + new_len > lc || new_len > 16 || new_len < 4) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        const uint8_t *old_pin = &data[1];
        const uint8_t *new_pin = &data[2 + old_len];
        if (old_len == s_wallet_pin_len && crypto_consttime_eq(old_pin, s_wallet_pin, old_len)) {
            memcpy(s_wallet_pin, new_pin, new_len);
            s_wallet_pin_len = new_len;
            s_pin_tries_left = 3;
            rsp[0] = 0x90; rsp[1] = 0x00;
        } else {
            rsp[0] = 0x63; rsp[1] = 0xC0;
        }
        return 2;
    }

    /* 5. IMPORT BIP-39 SEED (B0 69 00 00) */
    if (ins == 0x69) {
        if (!s_pin_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }
        if (lc == 64 || lc == 32) {
            if (lc == 64) {
                memcpy(s_master_seed, data, 64);
            } else {
                memcpy(s_master_seed, data, 32);
                memset(s_master_seed + 32, 0, 32);
            }
            s_seed_initialized = true;
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0x5A, 2, 0);
            rsp[0] = 0x90; rsp[1] = 0x00;
        } else {
            rsp[0] = 0x67; rsp[1] = 0x00;
        }
        return 2;
    }

    /* 6. GET BIP32 PUBLIC KEY / ADDRESS (B0 6C P1 P2)
     * P1 = 0x00: Bitcoin (BTC): Compressed (33B) + Chaincode (32B) + AddrLen(1B) + Legacy Addr (1...)
     * P1 = 0x01: Uncompressed secp256k1 (65B: 04 || X || Y)
     * P1 = 0x02: Ethereum (ETH/BSC/POL): Address (20B)
     * P1 = 0x03: Solana (SOL): Ed25519 Pubkey (32B) + AddrLen(1B) + Base58 Addr
     * P1 = 0x04: TON: Ed25519 Pubkey (32B)
     * P1 = 0x05: Monero (XMR): SpendPub(32) || ViewPub(32) || ViewSec(32) || AddrLen(1) || Addr(95)
     * P1 = 0x06: Tron (TRX / USDT-TRC20): Raw(20B) + AddrLen(1B) + Base58Check Addr (T...)
     * P1 = 0x07: Litecoin (LTC): Compressed (33B) + AddrLen(1B) + Base58Check Addr (L...)
     */
    if (ins == 0x6C) {
        if (lc < 4 || (lc % 4) != 0) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        uint8_t depth = (uint8_t)(lc / 4);
        uint32_t path[10];
        for (uint8_t i = 0; i < depth; i++) {
            path[i] = ((uint32_t)data[i * 4] << 24) |
                      ((uint32_t)data[i * 4 + 1] << 16) |
                      ((uint32_t)data[i * 4 + 2] << 8) |
                      data[i * 4 + 3];
        }

        bool is_monero = (p1 == 0x05) || (depth > 1 && path[1] == 0x80000080UL); /* 128' (Monero) */
        bool is_ed25519 = is_monero || (p1 == 0x03) || (p1 == 0x04) || (depth > 1 && (path[1] == 0x800001F5UL || path[1] == 0x8000018CUL)); /* 501' (Solana) or 396' (TON) */

        uint8_t child_priv[32];
        uint8_t child_chain[32];
        if (!derive_bip32_key(path, depth, child_priv, child_chain, is_ed25519)) {
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        uint16_t out_len = 0;
        if (is_monero) {
            /* Monero (XMR): Spend Pub (32B), View Pub (32B), View Sec (32B), Address (95B) */
            uint8_t spend_sec[32];
            uint8_t view_sec[32];
            uint8_t spend_pub[32];
            uint8_t view_pub[32];

            keccak_256(child_priv, 32, spend_sec);
            ed25519_sc_reduce32(spend_sec);

            keccak_256(spend_sec, 32, view_sec);
            ed25519_sc_reduce32(view_sec);

            ed25519_scalarmult_base(spend_pub, spend_sec);
            ed25519_scalarmult_base(view_pub, view_sec);

            /* Build 69-byte raw buffer: 0x12 (mainnet) || spend_pub || view_pub || checksum */
            uint8_t raw[69];
            raw[0] = 0x12; /* Monero Mainnet */
            memcpy(raw + 1, spend_pub, 32);
            memcpy(raw + 33, view_pub, 32);

            uint8_t chk[32];
            keccak_256(raw, 65, chk);
            memcpy(raw + 65, chk, 4);

            char addr_str[96];
            monero_base58_encode(raw, 69, addr_str);

            /* Export: spend_pub(32) || view_pub(32) || view_sec(32) || addr_len(1) || addr_str(95) */
            memcpy(rsp, spend_pub, 32);
            memcpy(rsp + 32, view_pub, 32);
            memcpy(rsp + 64, view_sec, 32);
            rsp[96] = 95;
            memcpy(rsp + 97, addr_str, 95);
            out_len = 97 + 95;

            /* Zero sensitive keys immediately */
            crypto_zero(spend_sec, sizeof(spend_sec));
            crypto_zero(view_sec, sizeof(view_sec));
        } else if (is_ed25519) {
            uint8_t pk[32];
            uint8_t sk[64];
            ed25519_create_keypair(pk, sk, child_priv);
            memcpy(rsp, pk, 32);
            out_len = 32;
            if (p1 == 0x03 || (depth > 1 && path[1] == 0x800001F5UL)) {
                /* Solana: append Base58 address string */
                char sol_b58[64];
                base58_encode(pk, 32, sol_b58);
                uint8_t slen = (uint8_t)strlen(sol_b58);
                rsp[32] = slen;
                memcpy(rsp + 33, sol_b58, slen);
                out_len = 33 + slen;
            }
            crypto_zero(sk, sizeof(sk));
        } else {
            uint8_t pub[64];
            uECC_compute_public_key(child_priv, pub, uECC_secp256k1());

            if (p1 == 0x06 || (depth > 1 && path[1] == 0x800000C3UL)) {
                /* Tron (TRX / USDT-TRC20): Base58Check(0x41 || Keccak256(pub)[12..31]) */
                uint8_t eth_hash[32];
                keccak_256(pub, 64, eth_hash);
                char trx_addr[64];
                base58check_encode(0x41, eth_hash + 12, 20, trx_addr);
                uint8_t tlen = (uint8_t)strlen(trx_addr);
                memcpy(rsp, eth_hash + 12, 20);
                rsp[20] = tlen;
                memcpy(rsp + 21, trx_addr, tlen);
                out_len = 21 + tlen;
            } else if (p1 == 0x07 || (depth > 1 && path[1] == 0x80000002UL)) {
                /* Litecoin (LTC): Base58Check(0x30 || RIPEMD160(SHA256(compressed_pub))) */
                uint8_t comp_pub[33];
                uECC_compress(pub, comp_pub, uECC_secp256k1());
                uint8_t s256[32], r160[20];
                sha256_hash(comp_pub, 33, s256);
                ripemd160(s256, 32, r160);
                char ltc_addr[64];
                base58check_encode(0x30, r160, 20, ltc_addr);
                uint8_t llen = (uint8_t)strlen(ltc_addr);
                memcpy(rsp, comp_pub, 33);
                rsp[33] = llen;
                memcpy(rsp + 34, ltc_addr, llen);
                out_len = 34 + llen;
            } else if (p1 == 0x00) {
                /* Bitcoin (BTC): Compressed (33B) + Chaincode (32B) + P2PKH Addr */
                uECC_compress(pub, rsp, uECC_secp256k1());
                memcpy(rsp + 33, child_chain, 32);
                out_len = 65;

                uint8_t s256[32], r160[20];
                sha256_hash(rsp, 33, s256);
                ripemd160(s256, 32, r160);
                char btc_addr[64];
                base58check_encode(0x00, r160, 20, btc_addr);
                uint8_t blen = (uint8_t)strlen(btc_addr);
                rsp[out_len++] = blen;
                memcpy(rsp + out_len, btc_addr, blen);
                out_len += blen;
            } else if (p1 == 0x01) {
                /* Uncompressed (65B: 04 || X || Y) */
                rsp[0] = 0x04;
                memcpy(rsp + 1, pub, 64);
                out_len = 65;
            } else if (p1 == 0x02) {
                /* Ethereum Address: last 20 bytes of keccak256(pub[0..63]) */
                uint8_t eth_hash[32];
                keccak_256(pub, 64, eth_hash);
                memcpy(rsp, eth_hash + 12, 20);
                out_len = 20;
            }
        }

        crypto_zero(child_priv, sizeof(child_priv));
        rsp[out_len++] = 0x90;
        rsp[out_len++] = 0x00;
        return out_len;
    }

    /* 7. SIGN TRANSACTION OR MESSAGE (B0 6E P1 P2)
     * Payload: <Path_len: 1B> <Path: 4 * depth> <MsgHash: 32B>
     */
    if (ins == 0x6E) {
        if (!s_pin_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }
        if (lc < 37) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        uint8_t path_bytes = data[0];
        if (path_bytes == 0 || (path_bytes % 4) != 0 || (1 + path_bytes + 32) > lc) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        uint8_t depth = path_bytes / 4;
        uint32_t path[10];
        for (uint8_t i = 0; i < depth; i++) {
            path[i] = ((uint32_t)data[1 + i * 4] << 24) |
                      ((uint32_t)data[1 + i * 4 + 1] << 16) |
                      ((uint32_t)data[1 + i * 4 + 2] << 8) |
                      data[1 + i * 4 + 3];
        }
        const uint8_t *msghash = &data[1 + path_bytes];

        /* Physical Touch Confirmation (User Presence) */
        if (!wait_for_user_touch(3000)) {
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0x5A, 3, 0);
            rsp[0] = 0x69; rsp[1] = 0x85; /* Conditions of use not satisfied (Touch Required) */
            return 2;
        }

        bool is_ed25519 = (depth > 1 && (path[1] == 0x800001F5UL || path[1] == 0x8000018CUL));

        uint8_t child_priv[32];
        if (!derive_bip32_key(path, depth, child_priv, NULL, is_ed25519)) {
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        uint16_t out_len = 0;
        if (is_ed25519) {
            /* Ed25519 Signature (Solana / TON) */
            uint8_t pk[32], sk[64];
            ed25519_create_keypair(pk, sk, child_priv);
            ed25519_sign(rsp, msghash, 32, pk, sk);
            out_len = 64;
            crypto_zero(sk, sizeof(sk));
        } else {
            /* secp256k1 Signature (Bitcoin / Ethereum) */
            uint8_t sig[64];
            uint8_t recid = 0;
            if (!uECC_sign_with_recid(child_priv, msghash, 32, sig, &recid, uECC_secp256k1())) {
                crypto_zero(child_priv, sizeof(child_priv));
                rsp[0] = 0x6F; rsp[1] = 0x00; /* Crypto error */
                return 2;
            }
            /* Format: [r: 32B] [s: 32B] [v: 1B = 27 + recid] */
            memcpy(rsp, sig, 64);
            rsp[64] = (uint8_t)(27 + recid);
            out_len = 65;
        }

        crypto_zero(child_priv, sizeof(child_priv));
        rsp[out_len++] = 0x90;
        rsp[out_len++] = 0x00;
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0x5A, 4, is_ed25519);
        return out_len;
    }

    /* Unsupported Satochip Command */
    rsp[0] = 0x6D; rsp[1] = 0x00; /* Instruction not supported */
    return 2;
}

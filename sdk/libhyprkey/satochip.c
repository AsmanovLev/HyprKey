#include "hyprkey_internal.h"
#include <string.h>
#include <stdio.h>

/* Standard Satochip APDUs implemented in firmware */
#define INS_VERIFY_PIN   0x20
#define INS_CHANGE_PIN   0x21
#define INS_GET_RANDOM   0x84
#define INS_IMPORT_SEED  0x69
#define INS_DERIVE_KEY   0x6C
#define INS_GET_STATUS   0x6D
#define INS_SIGN_MSG     0x6E

hyprkey_status_t hyprkey_get_status(hyprkey_device_t *device, hyprkey_status_info_t *info) {
    if (!device || !info) return HYPRKEY_ERR_INVALID_PARAM;
    memset(info, 0, sizeof(*info));

    uint8_t rx[256];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    hyprkey_status_t st = hyprkey_send_apdu_internal(device, 0xB0, INS_GET_STATUS, 0x00, 0x00, NULL, 0, rx, &rx_len, &sw);
    if (st != HYPRKEY_OK) return st;
    if (sw != 0x9000 || rx_len < 4) return HYPRKEY_ERR_APPLET_FAILED;

    /* Firmware returns: [pin_retries, pin_verified, has_seed, touch_policy] */
    info->protocol_version = 1;
    info->applet_version_major = 0;
    info->applet_version_minor = 12;
    info->pin_retry_count = rx[0];
    info->pin_verified = (rx[1] != 0);
    info->has_seed = (rx[2] != 0);

    return HYPRKEY_OK;
}

hyprkey_status_t hyprkey_verify_pin(hyprkey_device_t *device, const char *pin) {
    if (!device || !pin) return HYPRKEY_ERR_INVALID_PARAM;
    size_t len = strlen(pin);
    if (len == 0 || len > 16) return HYPRKEY_ERR_INVALID_PARAM;

    uint8_t rx[32];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    hyprkey_status_t st = hyprkey_send_apdu_internal(
        device, 0xB0, INS_VERIFY_PIN, 0x00, 0x00,
        (const uint8_t *)pin, len,
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK) return st;
    if (sw == 0x9000) return HYPRKEY_OK;
    if (sw == 0x6983) return HYPRKEY_ERR_PIN_BLOCKED;
    if ((sw & 0xFFF0) == 0x63C0) return HYPRKEY_ERR_PIN_FAILED;

    return HYPRKEY_ERR_PIN_FAILED;
}

hyprkey_status_t hyprkey_change_pin(hyprkey_device_t *device, const char *old_pin, const char *new_pin) {
    if (!device || !old_pin || !new_pin) return HYPRKEY_ERR_INVALID_PARAM;

    hyprkey_status_t st = hyprkey_verify_pin(device, old_pin);
    if (st != HYPRKEY_OK) return st;

    size_t new_len = strlen(new_pin);
    if (new_len < 4 || new_len > 16) return HYPRKEY_ERR_INVALID_PARAM;

    uint8_t rx[32];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    st = hyprkey_send_apdu_internal(
        device, 0xB0, INS_CHANGE_PIN, 0x00, 0x00,
        (const uint8_t *)new_pin, new_len,
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK) return st;
    if (sw != 0x9000) return HYPRKEY_ERR_APPLET_FAILED;

    return HYPRKEY_OK;
}

hyprkey_status_t hyprkey_import_bip39_seed(hyprkey_device_t *device, const uint8_t seed[64]) {
    if (!device || !seed) return HYPRKEY_ERR_INVALID_PARAM;

    uint8_t rx[32];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    hyprkey_status_t st = hyprkey_send_apdu_internal(
        device, 0xB0, INS_IMPORT_SEED, 0x00, 0x00,
        seed, 64,
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK) return st;
    if (sw != 0x9000) return HYPRKEY_ERR_APPLET_FAILED;

    return HYPRKEY_OK;
}

hyprkey_status_t hyprkey_get_random(hyprkey_device_t *device, uint8_t *buffer, size_t len) {
    if (!device || !buffer || len == 0 || len > 255) return HYPRKEY_ERR_INVALID_PARAM;

    uint8_t rx[300];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    hyprkey_status_t st = hyprkey_send_apdu_internal(
        device, 0xB0, INS_GET_RANDOM, 0x00, 0x00,
        NULL, 0,
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK) return st;
    if (sw != 0x9000 || rx_len < len) return HYPRKEY_ERR_APPLET_FAILED;

    memcpy(buffer, rx, len);
    return HYPRKEY_OK;
}

static void put_be32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)(val >> 16);
    buf[2] = (uint8_t)(val >> 8);
    buf[3] = (uint8_t)(val);
}

hyprkey_status_t hyprkey_get_address(
    hyprkey_device_t *device,
    hyprkey_coin_t coin,
    char *address_out,
    size_t max_addr_len,
    uint8_t *pubkey_out,
    size_t *pubkey_len
) {
    if (!device || !address_out || max_addr_len == 0) return HYPRKEY_ERR_INVALID_PARAM;

    uint8_t path_buf[32];
    size_t path_len = 0;
    uint8_t p1 = 0;

    switch (coin) {
        case HYPRKEY_COIN_BTC_LEGACY:
        case HYPRKEY_COIN_BTC_NESTED_SEGWIT:
        case HYPRKEY_COIN_BTC_NATIVE_SEGWIT:
        case HYPRKEY_COIN_BTC_TAPROOT:
            p1 = 0x00;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x80000000);
            put_be32(&path_buf[8], 0x80000000);
            put_be32(&path_buf[12], 0);
            put_be32(&path_buf[16], 0);
            path_len = 20;
            break;

        case HYPRKEY_COIN_EVM:
            p1 = 0x02;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x8000003C);
            put_be32(&path_buf[8], 0x80000000);
            put_be32(&path_buf[12], 0);
            put_be32(&path_buf[16], 0);
            path_len = 20;
            break;

        case HYPRKEY_COIN_SOLANA:
            p1 = 0x03;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x800001F5);
            put_be32(&path_buf[8], 0x80000000);
            put_be32(&path_buf[12], 0x80000000);
            path_len = 16;
            break;

        case HYPRKEY_COIN_TON:
            p1 = 0x04;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x8000018C);
            put_be32(&path_buf[8], 0x80000000);
            put_be32(&path_buf[12], 0x80000000);
            path_len = 16;
            break;

        case HYPRKEY_COIN_TRON:
            p1 = 0x06;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x800000C3);
            put_be32(&path_buf[8], 0x80000000);
            put_be32(&path_buf[12], 0);
            put_be32(&path_buf[16], 0);
            path_len = 20;
            break;

        case HYPRKEY_COIN_LTC_LEGACY:
        case HYPRKEY_COIN_LTC_NESTED:
        case HYPRKEY_COIN_LTC_NATIVE:
            p1 = 0x07;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x80000002);
            put_be32(&path_buf[8], 0x80000000);
            put_be32(&path_buf[12], 0);
            put_be32(&path_buf[16], 0);
            path_len = 20;
            break;

        case HYPRKEY_COIN_MONERO:
            p1 = 0x05;
            put_be32(&path_buf[0], 0x8000002C);
            put_be32(&path_buf[4], 0x80000080);
            put_be32(&path_buf[8], 0x80000000);
            path_len = 12;
            break;

        default:
            return HYPRKEY_ERR_INVALID_PARAM;
    }

    uint8_t rx[512];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    hyprkey_status_t st = hyprkey_send_apdu_internal(
        device, 0xB0, INS_DERIVE_KEY, p1, 0x00,
        path_buf, path_len,
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK) return st;
    if (sw == 0x6985) return HYPRKEY_ERR_NO_SEED;
    if (sw == 0x6982) return HYPRKEY_ERR_PIN_FAILED;
    if (sw != 0x9000 || rx_len < 20) return HYPRKEY_ERR_APPLET_FAILED;

    if (coin == HYPRKEY_COIN_EVM) {
        /* rx: 20 bytes raw address */
        snprintf(address_out, max_addr_len, "0x");
        for (int i = 0; i < 20; ++i) {
            snprintf(address_out + 2 + i * 2, max_addr_len - (2 + i * 2), "%02x", rx[i]);
        }
        if (pubkey_out && pubkey_len) *pubkey_len = 0;
    } else if (coin == HYPRKEY_COIN_SOLANA) {
        /* rx: [32 pubkey] [len:1] [Base58 string] */
        if (rx_len < 33) return HYPRKEY_ERR_APPLET_FAILED;
        if (pubkey_out && pubkey_len && *pubkey_len >= 32) {
            memcpy(pubkey_out, rx, 32);
            *pubkey_len = 32;
        }
        uint8_t slen = rx[32];
        if (rx_len < (size_t)(33 + slen)) return HYPRKEY_ERR_APPLET_FAILED;
        if (slen >= max_addr_len) slen = (uint8_t)(max_addr_len - 1);
        memcpy(address_out, &rx[33], slen);
        address_out[slen] = '\0';
    } else if (coin == HYPRKEY_COIN_TON) {
        /* rx: [32 pubkey] */
        if (rx_len < 32) return HYPRKEY_ERR_APPLET_FAILED;
        if (pubkey_out && pubkey_len && *pubkey_len >= 32) {
            memcpy(pubkey_out, rx, 32);
            *pubkey_len = 32;
        }
        for (int i = 0; i < 32; ++i) {
            snprintf(address_out + i * 2, max_addr_len - (i * 2), "%02x", rx[i]);
        }
    } else if (coin == HYPRKEY_COIN_TRON) {
        /* rx: [20 raw_addr] [len:1] [Base58Check] */
        if (rx_len < 21) return HYPRKEY_ERR_APPLET_FAILED;
        uint8_t slen = rx[20];
        if (rx_len < (size_t)(21 + slen)) return HYPRKEY_ERR_APPLET_FAILED;
        if (slen >= max_addr_len) slen = (uint8_t)(max_addr_len - 1);
        memcpy(address_out, &rx[21], slen);
        address_out[slen] = '\0';
        if (pubkey_out && pubkey_len && *pubkey_len >= 20) {
            memcpy(pubkey_out, rx, 20);
            *pubkey_len = 20;
        }
    } else if (coin >= HYPRKEY_COIN_BTC_LEGACY && coin <= HYPRKEY_COIN_BTC_TAPROOT) {
        /* rx: [33 compressed pubkey] [32 chaincode] [len1][legacy] [len2][nested] [len3][native] [len4][taproot] */
        if (rx_len < 69) return HYPRKEY_ERR_APPLET_FAILED;
        if (pubkey_out && pubkey_len && *pubkey_len >= 33) {
            memcpy(pubkey_out, rx, 33);
            *pubkey_len = 33;
        }
        size_t idx = 65;
        char addrs[4][128];
        for (int k = 0; k < 4; ++k) {
            if (idx >= rx_len) break;
            uint8_t alen = rx[idx++];
            if (idx + alen > rx_len) break;
            memcpy(addrs[k], &rx[idx], alen);
            addrs[k][alen] = '\0';
            idx += alen;
        }
        int sel = (int)coin - (int)HYPRKEY_COIN_BTC_LEGACY;
        if (sel >= 0 && sel < 4) {
            strncpy(address_out, addrs[sel], max_addr_len - 1);
            address_out[max_addr_len - 1] = '\0';
        }
    } else if (coin >= HYPRKEY_COIN_LTC_LEGACY && coin <= HYPRKEY_COIN_LTC_NATIVE) {
        /* rx: [33 pubkey] [len1][legacy] [len2][nested] [len3][native] */
        if (rx_len < 34) return HYPRKEY_ERR_APPLET_FAILED;
        if (pubkey_out && pubkey_len && *pubkey_len >= 33) {
            memcpy(pubkey_out, rx, 33);
            *pubkey_len = 33;
        }
        size_t idx = 33;
        char addrs[3][128];
        for (int k = 0; k < 3; ++k) {
            if (idx >= rx_len) break;
            uint8_t alen = rx[idx++];
            if (idx + alen > rx_len) break;
            memcpy(addrs[k], &rx[idx], alen);
            addrs[k][alen] = '\0';
            idx += alen;
        }
        int sel = (int)coin - (int)HYPRKEY_COIN_LTC_LEGACY;
        if (sel >= 0 && sel < 3) {
            strncpy(address_out, addrs[sel], max_addr_len - 1);
            address_out[max_addr_len - 1] = '\0';
        }
    } else if (coin == HYPRKEY_COIN_MONERO) {
        hyprkey_monero_keys_t xmr;
        st = hyprkey_get_monero_keys(device, &xmr);
        if (st != HYPRKEY_OK) return st;
        strncpy(address_out, xmr.address, max_addr_len - 1);
        address_out[max_addr_len - 1] = '\0';
        if (pubkey_out && pubkey_len && *pubkey_len >= 32) {
            memcpy(pubkey_out, xmr.spend_pub, 32);
            *pubkey_len = 32;
        }
    }

    return HYPRKEY_OK;
}

hyprkey_status_t hyprkey_get_monero_keys(hyprkey_device_t *device, hyprkey_monero_keys_t *keys) {
    if (!device || !keys) return HYPRKEY_ERR_INVALID_PARAM;
    memset(keys, 0, sizeof(*keys));

    /* m/44'/128'/0' */
    uint8_t path_buf[12];
    put_be32(&path_buf[0], 0x8000002C);
    put_be32(&path_buf[4], 0x80000080);
    put_be32(&path_buf[8], 0x80000000);

    uint8_t rx[256];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    /* Monero P1 = 0x05 */
    hyprkey_status_t st = hyprkey_send_apdu_internal(
        device, 0xB0, INS_DERIVE_KEY, 0x05, 0x00,
        path_buf, sizeof(path_buf),
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK) return st;
    if (sw != 0x9000 || rx_len < (32 + 32 + 32 + 1 + 95)) return HYPRKEY_ERR_APPLET_FAILED;

    /* Layout: [SpendPub(32)] [ViewPub(32)] [ViewSec(32)] [len:1] [Address(95)] */
    memcpy(keys->spend_pub, &rx[0], 32);
    memcpy(keys->view_pub, &rx[32], 32);
    memcpy(keys->view_sec, &rx[64], 32);
    uint8_t alen = rx[96];
    if (alen > 95) alen = 95;
    memcpy(keys->address, &rx[97], alen);
    keys->address[alen] = '\0';

    return HYPRKEY_OK;
}

const char *hyprkey_strerror(hyprkey_status_t code) {
    switch (code) {
        case HYPRKEY_OK: return "Success";
        case HYPRKEY_ERR_INVALID_PARAM: return "Invalid parameter";
        case HYPRKEY_ERR_NO_DEVICE: return "No Hyprkey device found in card reader";
        case HYPRKEY_ERR_PCSC_FAILED: return "PC/SC subsystem failure";
        case HYPRKEY_ERR_COMMUNICATION: return "Smartcard transmission error";
        case HYPRKEY_ERR_PIN_FAILED: return "Incorrect PIN or PIN authentication required";
        case HYPRKEY_ERR_PIN_BLOCKED: return "PIN blocked (exceeded retry counter)";
        case HYPRKEY_ERR_NO_SEED: return "No master seed imported on device";
        case HYPRKEY_ERR_TOUCH_TIMEOUT: return "Physical touch button timeout";
        case HYPRKEY_ERR_APPLET_FAILED: return "Hardware wallet applet returned error status";
        case HYPRKEY_ERR_BUFFER_TOO_SMALL: return "Provided buffer is too small";
        default: return "Unknown error";
    }
}

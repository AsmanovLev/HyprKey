#include "oath.h"
#include "sha1/sha1.h"
#include "sha256/sha256.h"
#include <string.h>

static const uint8_t s_oath_aid[7] = {
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
};

static oath_cred_t s_creds[OATH_MAX_CREDENTIALS];

void oath_init(void) {
    memset(s_creds, 0, sizeof(s_creds));

    /* Pre-populate demo credential: "Google:alice@hyprkey.local" */
    /* Secret: 20 bytes "12345678901234567890" */
    const char *demo_name = "Google:alice@hyprkey.local";
    size_t name_len = strlen(demo_name);
    memcpy(s_creds[0].name, demo_name, name_len);
    s_creds[0].name_len = (uint8_t)name_len;
    s_creds[0].type_alg = OATH_TYPE_TOTP | OATH_ALG_SHA1; /* 0x21 */
    s_creds[0].digits = 6;
    memcpy(s_creds[0].secret, "12345678901234567890", 20);
    s_creds[0].secret_len = 20;
    s_creds[0].valid = true;
}

static oath_cred_t *find_cred(const char *name, uint8_t name_len) {
    for (int i = 0; i < OATH_MAX_CREDENTIALS; i++) {
        if (s_creds[i].valid && s_creds[i].name_len == name_len &&
            memcmp(s_creds[i].name, name, name_len) == 0) {
            return &s_creds[i];
        }
    }
    return NULL;
}

static oath_cred_t *alloc_cred(const char *name, uint8_t name_len) {
    oath_cred_t *existing = find_cred(name, name_len);
    if (existing) return existing;

    for (int i = 0; i < OATH_MAX_CREDENTIALS; i++) {
        if (!s_creds[i].valid) {
            return &s_creds[i];
        }
    }
    return NULL;
}

static uint32_t compute_otp_code31(const oath_cred_t *cred, const uint8_t challenge[8]) {
    uint8_t mac[32];
    uint8_t mac_len = 20;

    if ((cred->type_alg & 0x0F) == OATH_ALG_SHA256) {
        hmac_sha256(cred->secret, cred->secret_len, challenge, 8, mac);
        mac_len = 32;
    } else {
        hmac_sha1(cred->secret, cred->secret_len, challenge, 8, mac);
        mac_len = 20;
    }

    uint8_t offset = mac[mac_len - 1] & 0x0F;
    uint32_t code31 = ((uint32_t)(mac[offset] & 0x7F) << 24) |
                      ((uint32_t)(mac[offset + 1] & 0xFF) << 16) |
                      ((uint32_t)(mac[offset + 2] & 0xFF) << 8) |
                      ((uint32_t)(mac[offset + 3] & 0xFF));
    return code31;
}

uint16_t oath_process_apdu(const uint8_t *apdu, uint16_t apdu_len,
                           uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* Wrong length */
        return 2;
    }

    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    (void)p1;

    /* 1. SELECT AID (00 A4 04 00 ...) */
    if (ins == 0xA4 && p1 == 0x04) {
        uint8_t lc = (apdu_len >= 5) ? apdu[4] : 0;
        const uint8_t *aid = apdu + 5;
        if (lc >= sizeof(s_oath_aid) && memcmp(aid, s_oath_aid, sizeof(s_oath_aid)) == 0) {
            /* Response: Tag 0x79 Version (3B), Tag 0x71 ID (12B), 90 00 */
            uint16_t idx = 0;
            rsp[idx++] = 0x79; rsp[idx++] = 0x03;
            rsp[idx++] = 0x05; rsp[idx++] = 0x04; rsp[idx++] = 0x00; /* v5.4.0 */

            const char *dev_id = "HYPRKEY-OATH";
            rsp[idx++] = 0x71; rsp[idx++] = 12;
            memcpy(rsp + idx, dev_id, 12);
            idx += 12;

            rsp[idx++] = 0x90; rsp[idx++] = 0x00;
            return idx;
        }
        rsp[0] = 0x6A; rsp[1] = 0x82; /* Applet not found */
        return 2;
    }

    uint16_t lc = 0;
    const uint8_t *data = NULL;
    if (apdu_len >= 5) {
        lc = apdu[4];
        data = apdu + 5;
    }

    /* 2. PUT (0x01): Store credential */
    if (ins == 0x01) {
        const char *name = NULL;
        uint8_t name_len = 0;
        const uint8_t *secret_blob = NULL;
        uint8_t secret_blob_len = 0;
        uint8_t digits = 6;

        uint16_t pos = 0;
        while (pos + 1 < lc) {
            uint8_t tag = data[pos++];
            uint8_t len = data[pos++];
            if (pos + len > lc) break;

            if (tag == 0x71) {
                name = (const char *)&data[pos];
                name_len = len;
            } else if (tag == 0x73) {
                secret_blob = &data[pos];
                secret_blob_len = len;
            } else if (tag == 0x75) {
                if (len >= 1) digits = data[pos];
            }
            pos += len;
        }

        if (!name || name_len == 0 || !secret_blob || secret_blob_len < 2) {
            rsp[0] = 0x6A; rsp[1] = 0x80; /* Wrong data */
            return 2;
        }

        oath_cred_t *c = alloc_cred(name, name_len);
        if (!c) {
            rsp[0] = 0x6A; rsp[1] = 0x84; /* Not enough memory */
            return 2;
        }

        if (name_len > OATH_MAX_NAME_LEN) name_len = OATH_MAX_NAME_LEN;
        memcpy(c->name, name, name_len);
        c->name_len = name_len;
        c->type_alg = secret_blob[0]; /* e.g. 0x21 */
        if (secret_blob_len >= 2 && (secret_blob[1] == 6 || secret_blob[1] == 8)) {
            c->digits = secret_blob[1];
            uint8_t raw_key_len = secret_blob_len - 2;
            if (raw_key_len > OATH_MAX_SECRET_LEN) raw_key_len = OATH_MAX_SECRET_LEN;
            memcpy(c->secret, &secret_blob[2], raw_key_len);
            c->secret_len = raw_key_len;
        } else {
            c->digits = digits;
            uint8_t raw_key_len = secret_blob_len - 1;
            if (raw_key_len > OATH_MAX_SECRET_LEN) raw_key_len = OATH_MAX_SECRET_LEN;
            memcpy(c->secret, &secret_blob[1], raw_key_len);
            c->secret_len = raw_key_len;
        }
        c->valid = true;

        rsp[0] = 0x90; rsp[1] = 0x00;
        return 2;
    }

    /* 3. DELETE (0x02): Remove credential */
    if (ins == 0x02) {
        if (lc >= 2 && data[0] == 0x71) {
            uint8_t name_len = data[1];
            const char *name = (const char *)&data[2];
            oath_cred_t *c = find_cred(name, name_len);
            if (c) {
                c->valid = false;
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        }
        rsp[0] = 0x6A; rsp[1] = 0x82; /* Credential not found */
        return 2;
    }

    /* 4. RESET (0x04): Wipe all credentials */
    if (ins == 0x04) {
        memset(s_creds, 0, sizeof(s_creds));
        rsp[0] = 0x90; rsp[1] = 0x00;
        return 2;
    }

    /* 5. LIST (0xA1): List all configured credentials */
    if (ins == 0xA1) {
        uint16_t idx = 0;
        for (int i = 0; i < OATH_MAX_CREDENTIALS; i++) {
            if (s_creds[i].valid) {
                if (idx + 2 + s_creds[i].name_len + 3 > max_rsp_len - 2) break;
                rsp[idx++] = 0x71;
                rsp[idx++] = s_creds[i].name_len;
                memcpy(rsp + idx, s_creds[i].name, s_creds[i].name_len);
                idx += s_creds[i].name_len;

                rsp[idx++] = 0x72;
                rsp[idx++] = 0x01;
                rsp[idx++] = s_creds[i].type_alg;
            }
        }
        rsp[idx++] = 0x90; rsp[idx++] = 0x00;
        return idx;
    }

    /* 6. CALCULATE (0xA2): Compute OTP for one credential */
    if (ins == 0xA2) {
        const char *name = NULL;
        uint8_t name_len = 0;
        const uint8_t *challenge = NULL;

        uint16_t pos = 0;
        while (pos + 1 < lc) {
            uint8_t tag = data[pos++];
            uint8_t len = data[pos++];
            if (pos + len > lc) break;

            if (tag == 0x71) {
                name = (const char *)&data[pos];
                name_len = len;
            } else if (tag == 0x74 && len == 8) {
                challenge = &data[pos];
            }
            pos += len;
        }

        if (!name || !challenge) {
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        oath_cred_t *c = find_cred(name, name_len);
        if (!c) {
            rsp[0] = 0x6A; rsp[1] = 0x82; /* Not found */
            return 2;
        }

        uint32_t code31 = compute_otp_code31(c, challenge);

        /* Tag 0x76: digits (1B) || code31 (4B big-endian) */
        rsp[0] = 0x76;
        rsp[1] = 0x05;
        rsp[2] = c->digits;
        rsp[3] = (uint8_t)(code31 >> 24);
        rsp[4] = (uint8_t)(code31 >> 16);
        rsp[5] = (uint8_t)(code31 >> 8);
        rsp[6] = (uint8_t)(code31 & 0xFF);
        rsp[7] = 0x90;
        rsp[8] = 0x00;
        return 9;
    }

    /* 7. CALCULATE ALL (0xA4): Compute OTP for all credentials */
    if (ins == 0xA4) {
        const uint8_t *challenge = NULL;
        if (lc >= 10 && data[0] == 0x74 && data[1] == 8) {
            challenge = &data[2];
        }

        if (!challenge) {
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        uint16_t idx = 0;
        for (int i = 0; i < OATH_MAX_CREDENTIALS; i++) {
            if (s_creds[i].valid) {
                if (idx + 2 + s_creds[i].name_len + 7 > max_rsp_len - 2) break;

                rsp[idx++] = 0x71;
                rsp[idx++] = s_creds[i].name_len;
                memcpy(rsp + idx, s_creds[i].name, s_creds[i].name_len);
                idx += s_creds[i].name_len;

                uint32_t code31 = compute_otp_code31(&s_creds[i], challenge);
                rsp[idx++] = 0x76;
                rsp[idx++] = 0x05;
                rsp[idx++] = s_creds[i].digits;
                rsp[idx++] = (uint8_t)(code31 >> 24);
                rsp[idx++] = (uint8_t)(code31 >> 16);
                rsp[idx++] = (uint8_t)(code31 >> 8);
                rsp[idx++] = (uint8_t)(code31 & 0xFF);
            }
        }

        rsp[idx++] = 0x90; rsp[idx++] = 0x00;
        return idx;
    }

    rsp[0] = 0x6D; rsp[1] = 0x00; /* Instruction not supported */
    return 2;
}

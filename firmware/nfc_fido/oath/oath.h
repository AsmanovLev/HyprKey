#ifndef OATH_H
#define OATH_H

#include <stdint.h>
#include <stdbool.h>

#define OATH_MAX_CREDENTIALS 32
#define OATH_MAX_NAME_LEN    64
#define OATH_MAX_SECRET_LEN  64

#define OATH_TYPE_HOTP 0x10
#define OATH_TYPE_TOTP 0x20

#define OATH_ALG_SHA1   0x01
#define OATH_ALG_SHA256 0x02

typedef struct {
    char     name[OATH_MAX_NAME_LEN];
    uint8_t  name_len;
    uint8_t  type_alg; /* e.g. 0x21 (TOTP SHA1), 0x22 (TOTP SHA256) */
    uint8_t  digits;   /* 6 or 8 */
    uint8_t  secret[OATH_MAX_SECRET_LEN];
    uint8_t  secret_len;
    bool     valid;
} oath_cred_t;

void oath_init(void);

uint16_t oath_process_apdu(const uint8_t *apdu, uint16_t apdu_len,
                           uint8_t *rsp, uint16_t max_rsp_len);

#endif /* OATH_H */

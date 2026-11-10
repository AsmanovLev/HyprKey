#ifndef HYPR_STORAGE_MGR_H
#define HYPR_STORAGE_MGR_H

#include "hypr_storage.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Logical Record IDs */
#define HYPR_ID_DEV_CONFIG          1U
#define HYPR_ID_PGP_CONFIG          10U
#define HYPR_ID_PGP_KEY_SIG         11U
#define HYPR_ID_PGP_KEY_DEC         12U
#define HYPR_ID_PGP_KEY_AUT         13U
#define HYPR_ID_PGP_CERT            14U
#define HYPR_ID_OATH_BASE           100U  /* Slots 0..31 -> 100..131 */
#define HYPR_ID_FIDO_RK_BASE        200U  /* Slots 0..63 -> 200..263 */

/* OpenPGP persistent config payload */
typedef struct __attribute__((packed)) {
    char     pw1[32];
    uint8_t  pw1_len;
    uint8_t  pw1_tries;
    char     pw3[32];
    uint8_t  pw3_len;
    uint8_t  pw3_tries;
    char     name[64];
    uint8_t  name_len;
    char     lang[8];
    uint8_t  lang_len;
    uint8_t  sex;
    char     url[128];
    uint8_t  url_len;
    uint32_t sig_counter;
    uint8_t  magic_init; /* 0xA5 = initialized */
} hypr_pgp_config_record_t;

/* OpenPGP key record */
typedef struct __attribute__((packed)) {
    uint8_t  privkey[32];
    uint8_t  pubkey[64];
    uint8_t  fingerprint[20];
    uint32_t creation_time;
    uint8_t  valid;
} hypr_pgp_key_record_t;

/* OATH credential record payload */
typedef struct __attribute__((packed)) {
    char     name[64];
    uint8_t  name_len;
    uint8_t  type_alg;
    uint8_t  digits;
    uint8_t  secret[64];
    uint8_t  secret_len;
    uint8_t  valid;
} hypr_oath_record_t;

/**
 * @brief Global storage context
 */
extern hypr_storage_ctx_t g_hypr_storage;

/**
 * @brief Initialize HAL, derive FICR Master Key, and mount journaled storage
 * @return HYPR_OK on success
 */
hypr_err_t hypr_storage_mgr_init(void);

/* ==================== OATH Applet Storage ==================== */
hypr_err_t hypr_storage_oath_load(uint8_t slot, hypr_oath_record_t *rec_out);
hypr_err_t hypr_storage_oath_save(uint8_t slot, const hypr_oath_record_t *rec);
hypr_err_t hypr_storage_oath_delete(uint8_t slot);

/* =================== OpenPGP Applet Storage ================== */
hypr_err_t hypr_storage_pgp_load_config(hypr_pgp_config_record_t *cfg_out);
hypr_err_t hypr_storage_pgp_save_config(const hypr_pgp_config_record_t *cfg);

hypr_err_t hypr_storage_pgp_load_key(uint8_t key_slot, hypr_pgp_key_record_t *key_out);
hypr_err_t hypr_storage_pgp_save_key(uint8_t key_slot, const hypr_pgp_key_record_t *key);

hypr_err_t hypr_storage_pgp_load_cert(uint8_t *cert_out, uint16_t max_len, uint16_t *actual_len);
hypr_err_t hypr_storage_pgp_save_cert(const uint8_t *cert, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* HYPR_STORAGE_MGR_H */

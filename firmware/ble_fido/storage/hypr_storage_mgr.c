#include "hypr_storage_mgr.h"
#include "hypr_storage_hal_nrf.h"
#include <string.h>

hypr_storage_ctx_t g_hypr_storage;
static hypr_storage_hal_t s_hal;
static uint8_t s_storage_mk[32];

hypr_err_t hypr_storage_mgr_init(void) {
    hypr_storage_hal_nrf_init(&s_hal);
    hypr_storage_hal_nrf_get_hardware_key(s_storage_mk);
    return hypr_storage_mount(&g_hypr_storage, &s_hal, s_storage_mk);
}

/* ==================== OATH Applet Storage ==================== */

hypr_err_t hypr_storage_oath_load(uint8_t slot, hypr_oath_record_t *rec_out) {
    if (slot >= 32 || !rec_out) return HYPR_ERR_INVALID_ARG;

    uint16_t type, flags, actual_len;
    hypr_err_t err = hypr_storage_read(&g_hypr_storage, HYPR_ID_OATH_BASE + slot,
                                       &type, &flags, (uint8_t *)rec_out,
                                       sizeof(*rec_out), &actual_len);
    if (err == HYPR_OK && type == HYPR_REC_TYPE_OATH && actual_len == sizeof(*rec_out)) {
        return HYPR_OK;
    }
    return HYPR_ERR_NOT_FOUND;
}

hypr_err_t hypr_storage_oath_save(uint8_t slot, const hypr_oath_record_t *rec) {
    if (slot >= 32 || !rec) return HYPR_ERR_INVALID_ARG;

    return hypr_storage_write(&g_hypr_storage, HYPR_ID_OATH_BASE + slot,
                              HYPR_REC_TYPE_OATH, 0,
                              (const uint8_t *)rec, sizeof(*rec));
}

hypr_err_t hypr_storage_oath_delete(uint8_t slot) {
    if (slot >= 32) return HYPR_ERR_INVALID_ARG;
    return hypr_storage_delete(&g_hypr_storage, HYPR_ID_OATH_BASE + slot);
}

/* =================== OpenPGP Applet Storage ================== */

hypr_err_t hypr_storage_pgp_load_config(hypr_pgp_config_record_t *cfg_out) {
    if (!cfg_out) return HYPR_ERR_INVALID_ARG;

    uint16_t type, flags, actual_len;
    hypr_err_t err = hypr_storage_read(&g_hypr_storage, HYPR_ID_PGP_CONFIG,
                                       &type, &flags, (uint8_t *)cfg_out,
                                       sizeof(*cfg_out), &actual_len);
    if (err == HYPR_OK && type == HYPR_REC_TYPE_PGP_DATA &&
        actual_len == sizeof(*cfg_out) && cfg_out->magic_init == 0xA5) {
        return HYPR_OK;
    }
    return HYPR_ERR_NOT_FOUND;
}

hypr_err_t hypr_storage_pgp_save_config(const hypr_pgp_config_record_t *cfg) {
    if (!cfg) return HYPR_ERR_INVALID_ARG;

    return hypr_storage_write(&g_hypr_storage, HYPR_ID_PGP_CONFIG,
                              HYPR_REC_TYPE_PGP_DATA, 0,
                              (const uint8_t *)cfg, sizeof(*cfg));
}

hypr_err_t hypr_storage_pgp_load_key(uint8_t key_slot, hypr_pgp_key_record_t *key_out) {
    if (key_slot > 2 || !key_out) return HYPR_ERR_INVALID_ARG;

    uint16_t rec_id = HYPR_ID_PGP_KEY_SIG + key_slot;
    uint16_t type, flags, actual_len;
    hypr_err_t err = hypr_storage_read(&g_hypr_storage, rec_id,
                                       &type, &flags, (uint8_t *)key_out,
                                       sizeof(*key_out), &actual_len);
    if (err == HYPR_OK && type == HYPR_REC_TYPE_PGP_DATA && actual_len == sizeof(*key_out)) {
        return HYPR_OK;
    }
    return HYPR_ERR_NOT_FOUND;
}

hypr_err_t hypr_storage_pgp_save_key(uint8_t key_slot, const hypr_pgp_key_record_t *key) {
    if (key_slot > 2 || !key) return HYPR_ERR_INVALID_ARG;

    uint16_t rec_id = HYPR_ID_PGP_KEY_SIG + key_slot;
    return hypr_storage_write(&g_hypr_storage, rec_id,
                              HYPR_REC_TYPE_PGP_DATA, 0,
                              (const uint8_t *)key, sizeof(*key));
}

hypr_err_t hypr_storage_pgp_load_cert(uint8_t *cert_out, uint16_t max_len, uint16_t *actual_len) {
    if (!cert_out || !actual_len) return HYPR_ERR_INVALID_ARG;

    uint16_t type, flags;
    hypr_err_t err = hypr_storage_read(&g_hypr_storage, HYPR_ID_PGP_CERT,
                                       &type, &flags, cert_out,
                                       max_len, actual_len);
    if (err == HYPR_OK && type == HYPR_REC_TYPE_PGP_DATA) {
        return HYPR_OK;
    }
    return HYPR_ERR_NOT_FOUND;
}

hypr_err_t hypr_storage_pgp_save_cert(const uint8_t *cert, uint16_t len) {
    if (!cert || len > HYPR_MAX_PAYLOAD_LEN) return HYPR_ERR_INVALID_ARG;

    return hypr_storage_write(&g_hypr_storage, HYPR_ID_PGP_CERT,
                              HYPR_REC_TYPE_PGP_DATA, 0,
                              cert, len);
}

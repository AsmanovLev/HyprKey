#include "hypr_storage_hal_nrf.h"
#include "chacha20poly1305.h"
#include "fips202.h"
#include "nrf_sdm.h"
#include "nrf_soc.h"
#include <string.h>

/* Bare-metal hardware addresses for nRF52840 */
#define NRF_NVMC_BASE           0x4001E000UL
#define NRF_NVMC_READY          (*(volatile uint32_t *)(NRF_NVMC_BASE + 0x400))
#define NRF_NVMC_CONFIG         (*(volatile uint32_t *)(NRF_NVMC_BASE + 0x504))
#define NRF_NVMC_ERASEPAGE      (*(volatile uint32_t *)(NRF_NVMC_BASE + 0x508))

#define NRF_POWER_BASE          0x40000000UL
#define NRF_POWER_EVENTS_POF    (*(volatile uint32_t *)(NRF_POWER_BASE + 0x108))
#define NRF_POWER_POFCON        (*(volatile uint32_t *)(NRF_POWER_BASE + 0x510))

#define NRF_FICR_BASE           0x10000000UL
#define NRF_FICR_DEVICEID0      (*(volatile uint32_t *)(NRF_FICR_BASE + 0x060))
#define NRF_FICR_DEVICEID1      (*(volatile uint32_t *)(NRF_FICR_BASE + 0x064))
#define NRF_FICR_ER(i)          (*(volatile uint32_t *)(NRF_FICR_BASE + 0x080 + ((i)*4)))
#define NRF_FICR_IR(i)          (*(volatile uint32_t *)(NRF_FICR_BASE + 0x090 + ((i)*4)))

static volatile bool s_flash_busy = false;
static volatile bool s_pofwarn_latched = false;
static volatile bool s_sd_active = false;

void hypr_storage_hal_nrf_on_sd_enabled(void) {
    s_sd_active = true;
    sd_power_pof_threshold_set(NRF_POWER_THRESHOLD_V28);
    sd_power_pof_enable(1);
}

static inline bool is_softdevice_enabled(void) {
    return s_sd_active;
}

void hypr_storage_hal_nrf_get_hardware_key(uint8_t mk_out[32]) {
    shake256_ctx sctx;
    shake256_init(&sctx);

    uint32_t dev_id[2] = { NRF_FICR_DEVICEID0, NRF_FICR_DEVICEID1 };
    shake256_absorb(&sctx, (const uint8_t *)dev_id, sizeof(dev_id));

    uint32_t roots[8];
    for (int i = 0; i < 4; i++) {
        roots[i] = NRF_FICR_ER(i);
        roots[4 + i] = NRF_FICR_IR(i);
    }
    shake256_absorb(&sctx, (const uint8_t *)roots, sizeof(roots));

    const char dom[] = "HYPRKEY_HW_STORAGE_KEY_v2";
    shake256_absorb(&sctx, (const uint8_t *)dom, sizeof(dom) - 1);
    shake256_finalize(&sctx);
    shake256_squeeze(&sctx, mk_out, 32);
}

void hypr_storage_hal_nrf_on_soc_evt(uint32_t evt_id) {
    if (evt_id == NRF_EVT_FLASH_OPERATION_SUCCESS || evt_id == NRF_EVT_FLASH_OPERATION_ERROR) {
        s_flash_busy = false;
    } else if (evt_id == NRF_EVT_POWER_FAILURE_WARNING) {
        s_pofwarn_latched = true;
    }
}

static bool hal_pofwarn_is_active(void *user_ctx) {
    (void)user_ctx;
    if (s_pofwarn_latched) {
        return true;
    }
    if (NRF_POWER_EVENTS_POF != 0) {
        return true;
    }
    return false;
}

static void hal_flash_read(void *user_ctx, uint32_t addr, void *dst, uint32_t len) {
    (void)user_ctx;
    const uint8_t *src_ptr = (const uint8_t *)(HYPR_FLASH_ZONE_B_BASE_ADDR + addr);
    memcpy(dst, (const void *)src_ptr, len);
}

static void hal_flash_write_words(void *user_ctx, uint32_t addr, const uint32_t *src, uint32_t words) {
    (void)user_ctx;
    uint32_t phys_addr = HYPR_FLASH_ZONE_B_BASE_ADDR + addr;

    if (is_softdevice_enabled()) {
        s_flash_busy = true;
        uint32_t err = sd_flash_write((uint32_t *)phys_addr, src, words);
        if (err == NRF_SUCCESS) {
            while (s_flash_busy) {
                uint32_t evt_id;
                if (sd_evt_get(&evt_id) == NRF_SUCCESS) {
                    hypr_storage_hal_nrf_on_soc_evt(evt_id);
                }
                __asm volatile("wfe");
            }
        } else {
            s_flash_busy = false;
        }
    } else {
        /* Direct NVMC register write */
        NRF_NVMC_CONFIG = 1U; /* Write enable */
        __asm volatile("dsb");
        __asm volatile("isb");

        volatile uint32_t *dst_ptr = (volatile uint32_t *)phys_addr;
        for (uint32_t i = 0; i < words; i++) {
            dst_ptr[i] = src[i];
            while (NRF_NVMC_READY == 0) {
                /* Busy wait */
            }
        }

        NRF_NVMC_CONFIG = 0U; /* Read-only mode */
        __asm volatile("dsb");
        __asm volatile("isb");
    }
}

static void hal_flash_erase_page(void *user_ctx, uint32_t page_idx) {
    (void)user_ctx;
    uint32_t phys_page = HYPR_FLASH_ZONE_B_START_PAGE + page_idx;

    if (is_softdevice_enabled()) {
        s_flash_busy = true;
        uint32_t err = sd_flash_page_erase(phys_page);
        if (err == NRF_SUCCESS) {
            while (s_flash_busy) {
                uint32_t evt_id;
                if (sd_evt_get(&evt_id) == NRF_SUCCESS) {
                    hypr_storage_hal_nrf_on_soc_evt(evt_id);
                }
                __asm volatile("wfe");
            }
        } else {
            s_flash_busy = false;
        }
    } else {
        /* Direct NVMC register page erase */
        NRF_NVMC_CONFIG = 2U; /* Erase enable */
        __asm volatile("dsb");
        __asm volatile("isb");

        NRF_NVMC_ERASEPAGE = phys_page * HYPR_FLASH_PAGE_SIZE;
        while (NRF_NVMC_READY == 0) {
            /* Busy wait */
        }

        NRF_NVMC_CONFIG = 0U; /* Read-only mode */
        __asm volatile("dsb");
        __asm volatile("isb");
    }
}

static void hal_derive_nonce(const uint8_t mk[32], uint16_t type, uint16_t id, uint32_t ver, uint8_t nonce[12]) {
    shake256_ctx sctx;
    shake256_init(&sctx);
    shake256_absorb(&sctx, mk, 32);

    uint8_t meta[8];
    meta[0] = (uint8_t)type;
    meta[1] = (uint8_t)(type >> 8);
    meta[2] = (uint8_t)id;
    meta[3] = (uint8_t)(id >> 8);
    meta[4] = (uint8_t)ver;
    meta[5] = (uint8_t)(ver >> 8);
    meta[6] = (uint8_t)(ver >> 16);
    meta[7] = (uint8_t)(ver >> 24);
    shake256_absorb(&sctx, meta, sizeof(meta));

    const char dom[] = "HYPR-NONCE-v2";
    shake256_absorb(&sctx, (const uint8_t *)dom, sizeof(dom) - 1);
    shake256_finalize(&sctx);
    shake256_squeeze(&sctx, nonce, 12);
}

static void hal_aead_encrypt(const uint8_t mk[32], const uint8_t nonce[12],
                             const void *aad, uint32_t aad_len,
                             const uint8_t *plain, uint8_t *cipher, uint32_t len,
                             uint8_t tag_out[16]) {
    chacha20_poly1305_encrypt(mk, nonce, aad, aad_len, plain, cipher, len, tag_out);
}

static bool hal_aead_decrypt(const uint8_t mk[32], const uint8_t nonce[12],
                             const void *aad, uint32_t aad_len,
                             const uint8_t *cipher, uint8_t *plain, uint32_t len,
                             const uint8_t tag[16]) {
    return chacha20_poly1305_decrypt(mk, nonce, aad, aad_len, cipher, plain, len, tag);
}

void hypr_storage_hal_nrf_init(hypr_storage_hal_t *hal_out) {
    if (!hal_out) return;

    hal_out->user_ctx          = NULL;
    hal_out->pofwarn_is_active = hal_pofwarn_is_active;
    hal_out->flash_read        = hal_flash_read;
    hal_out->flash_write_words = hal_flash_write_words;
    hal_out->flash_erase_page  = hal_flash_erase_page;
    hal_out->derive_nonce      = hal_derive_nonce;
    hal_out->aead_encrypt      = hal_aead_encrypt;
    hal_out->aead_decrypt      = hal_aead_decrypt;

    /* Enable Power-Fail Comparator if SoftDevice active */
    if (is_softdevice_enabled()) {
        sd_power_pof_threshold_set(NRF_POWER_THRESHOLD_V28);
        sd_power_pof_enable(1);
    } else {
        /* POFCON = POF enabled (bit 0=1) | Threshold 2.8V (value 15 << 1) */
        NRF_POWER_POFCON = (1U << 0) | (15U << 1);
    }
}

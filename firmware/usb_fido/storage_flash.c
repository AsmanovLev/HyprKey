#include "storage_flash.h"
#include "device_log.h"
#include "sha256/sha256.h"
#include "app_header.h"
#include "crypto_consttime.h"
#include "openpgp/openpgp.h"
#include <string.h>

/* ==================== Device Master Key Derivation ==================== */
void storage_get_device_master_key(const char *domain, uint8_t key_out[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);

    /* Read factory-programmed hardware secrets from Nordic FICR */
    const uint32_t *ficr_devid = (const uint32_t *)0x10000060UL; /* 64-bit Device ID */
    const uint32_t *ficr_er    = (const uint32_t *)0x10000080UL; /* 128-bit Encryption Root */
    const uint32_t *ficr_ir    = (const uint32_t *)0x10000090UL; /* 128-bit Identity Root */

    sha256_update(&ctx, (const uint8_t *)ficr_devid, 8);
    sha256_update(&ctx, (const uint8_t *)ficr_er, 16);
    sha256_update(&ctx, (const uint8_t *)ficr_ir, 16);

    const char salt[] = "HyprKey_Hardware_Root_Salt_v2";
    sha256_update(&ctx, (const uint8_t *)salt, sizeof(salt) - 1);
    if (domain) {
        sha256_update(&ctx, (const uint8_t *)domain, strlen(domain));
    }
    sha256_final(&ctx, key_out);
}

#define NVMC_READY          (*(volatile uint32_t *)0x4001E400UL)
#define NVMC_CONFIG         (*(volatile uint32_t *)0x4001E504UL)
#define NVMC_ERASEPAGE      (*(volatile uint32_t *)0x4001E508UL)

#define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0CUL)

/* 4-Byte Append-Only Log Entry Format: [slot: 8 bits | state: 8 bits | version: 16 bits] */
#define OTA_LOG_MAKE_ENTRY(slot, state, ver) (((uint32_t)(slot) & 0xFF) | (((uint32_t)(state) & 0xFF) << 8) | (((uint32_t)(ver) & 0xFFFF) << 16))
#define OTA_LOG_GET_SLOT(entry)              ((uint8_t)((entry) & 0xFF))
#define OTA_LOG_GET_STATE(entry)             ((uint8_t)(((entry) >> 8) & 0xFF))
#define OTA_LOG_GET_VER(entry)               ((uint16_t)(((entry) >> 16) & 0xFFFF))

static inline void nvmc_wait(void) {
    while (NVMC_READY == 0);
}

static void nvmc_raw_erase_page(uint32_t page_addr) {
    nvmc_wait();
    NVMC_CONFIG = 0x02; /* Een */
    NVMC_ERASEPAGE = page_addr;
    nvmc_wait();
    NVMC_CONFIG = 0x00; /* Ren */
}

static void nvmc_raw_write_word(uint32_t addr, uint32_t val) {
    nvmc_wait();
    NVMC_CONFIG = 0x01; /* Wen */
    *(volatile uint32_t *)addr = val;
    nvmc_wait();
    NVMC_CONFIG = 0x00; /* Ren */
}

static uint32_t ota_meta_read_active(uint32_t *next_free_offset) {
    const uint32_t *log = (const uint32_t *)FLASH_OTA_META_BASE;
    uint32_t last_entry = 0xFFFFFFFFUL;
    uint32_t next_idx = 0;

    for (uint32_t i = 0; i < 1024; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            next_idx = i;
            break;
        }
        last_entry = log[i];
        next_idx = i + 1;
    }

    if (next_free_offset) {
        *next_free_offset = next_idx * 4;
    }
    return last_entry;
}

static void ota_meta_append_switch(uint8_t target_slot, uint16_t version) {
    uint32_t next_offset = 0;
    ota_meta_read_active(&next_offset);

    if (next_offset >= 4096) {
        /* Page full after 1024 switches: erase and restart at offset 0 */
        nvmc_raw_erase_page(FLASH_OTA_META_BASE);
        next_offset = 0;
    }

    uint32_t entry = OTA_LOG_MAKE_ENTRY(target_slot, 0x00 /* CONFIRMED */, version);
    nvmc_raw_write_word(FLASH_OTA_META_BASE + next_offset, entry);
}

void storage_flash_init(void) {
    nvmc_wait();
    NVMC_CONFIG = 0x00; /* Ensure read mode */
}

uint32_t storage_flash_get_capacity(void) {
    return FLASH_USERDATA_SIZE;
}

bool storage_flash_erase_page(uint32_t page_index) {
    if (page_index >= FLASH_USERDATA_PAGES) {
        return false;
    }
    uint32_t page_addr = FLASH_USERDATA_BASE + (page_index * FLASH_PAGE_SIZE);
    nvmc_raw_erase_page(page_addr);
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0xE1, page_index, 0);
    return true;
}

bool storage_flash_read(uint32_t byte_offset, void *dst, size_t len) {
    if (byte_offset + len > FLASH_USERDATA_SIZE || dst == NULL) {
        return false;
    }
    const uint8_t *src = (const uint8_t *)(FLASH_USERDATA_BASE + byte_offset);
    memcpy(dst, src, len);
    return true;
}

bool storage_flash_write(uint32_t byte_offset, const void *src, size_t len) {
    if (byte_offset + len > FLASH_USERDATA_SIZE || src == NULL) {
        return false;
    }
    uint32_t target_addr = FLASH_USERDATA_BASE + byte_offset;
    const uint8_t *data = (const uint8_t *)src;

    /* Write 32-bit aligned words */
    size_t i = 0;
    while (i < len) {
        uint32_t word = 0xFFFFFFFFUL;
        size_t chunk = len - i;
        if (chunk > 4) chunk = 4;
        memcpy(&word, data + i, chunk);

        nvmc_raw_write_word(target_addr + i, word);
        i += 4;
    }
    return true;
}

/* ==================== Persistent Monotonic Counter & PIN Tries ==================== */

static uint32_t s_cached_sign_counter = 0;
static bool s_sign_counter_initialized = false;

uint32_t storage_get_sign_counter(void) {
    if (s_sign_counter_initialized) {
        return s_cached_sign_counter;
    }
    const uint32_t *log = (const uint32_t *)FLASH_USERDATA_BASE;
    uint32_t val = 0;
    for (uint32_t i = 0; i < 512; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            break;
        }
        val = log[i];
    }
    if (val == 0) {
        val = 1;
    }
    s_cached_sign_counter = val;
    s_sign_counter_initialized = true;
    return s_cached_sign_counter;
}

uint32_t storage_increment_sign_counter(void) {
    uint32_t cur = storage_get_sign_counter();
    uint32_t next = cur + 1;
    s_cached_sign_counter = next;

    const uint32_t *log = (const uint32_t *)FLASH_USERDATA_BASE;
    uint32_t next_idx = 512;
    for (uint32_t i = 0; i < 512; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            next_idx = i;
            break;
        }
    }

    if (next_idx >= 512) {
        /* Preserve PIN retry second half before page erase */
        uint32_t pin_half[512];
        memcpy(pin_half, (const void *)(FLASH_USERDATA_BASE + 2048), sizeof(pin_half));
        nvmc_raw_erase_page(FLASH_USERDATA_BASE);
        for (uint32_t i = 0; i < 512; i++) {
            if (pin_half[i] != 0xFFFFFFFFUL) {
                nvmc_raw_write_word(FLASH_USERDATA_BASE + 2048 + (i * 4), pin_half[i]);
            }
        }
        next_idx = 0;
    }

    nvmc_raw_write_word(FLASH_USERDATA_BASE + (next_idx * 4), next);
    return next;
}

uint8_t storage_get_pin_retries(uint8_t pin_type) {
    const uint32_t *log = (const uint32_t *)(FLASH_USERDATA_BASE + 2048);
    uint8_t tries = 3; /* default */
    for (uint32_t i = 0; i < 512; i++) {
        uint32_t entry = log[i];
        if (entry == 0xFFFFFFFFUL) {
            break;
        }
        if ((uint8_t)(entry & 0xFF) == pin_type) {
            tries = (uint8_t)((entry >> 8) & 0xFF);
        }
    }
    return tries;
}

void storage_set_pin_retries(uint8_t pin_type, uint8_t retries) {
    const uint32_t *log = (const uint32_t *)(FLASH_USERDATA_BASE + 2048);
    uint32_t next_idx = 512;
    for (uint32_t i = 0; i < 512; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            next_idx = i;
            break;
        }
    }

    if (next_idx >= 512) {
        /* Preserve sign counter first half before page erase */
        uint32_t sign_half[512];
        memcpy(sign_half, (const void *)FLASH_USERDATA_BASE, sizeof(sign_half));
        nvmc_raw_erase_page(FLASH_USERDATA_BASE);
        for (uint32_t i = 0; i < 512; i++) {
            if (sign_half[i] != 0xFFFFFFFFUL) {
                nvmc_raw_write_word(FLASH_USERDATA_BASE + (i * 4), sign_half[i]);
            }
        }
        next_idx = 0;
    }

    uint32_t entry = ((uint32_t)pin_type) | ((uint32_t)retries << 8) | 0xFFFF0000UL;
    nvmc_raw_write_word(FLASH_USERDATA_BASE + 2048 + (next_idx * 4), entry);
}

/* ==================== OTA Staging Helpers ==================== */

bool ota_staging_erase(void) {
    for (uint32_t addr = FLASH_SLOT_B_BASE; addr < (FLASH_SLOT_B_BASE + FLASH_SLOT_B_SIZE); addr += FLASH_PAGE_SIZE) {
        nvmc_raw_erase_page(addr);
    }
    return true;
}

bool ota_staging_write_chunk(uint32_t offset, const void *data, size_t len) {
    if (offset + len > FLASH_SLOT_B_SIZE || data == NULL) {
        return false;
    }
    uint32_t target_addr = FLASH_SLOT_B_BASE + offset;
    const uint8_t *bytes = (const uint8_t *)data;

    size_t i = 0;
    while (i < len) {
        uint32_t word = 0xFFFFFFFFUL;
        size_t chunk = len - i;
        if (chunk > 4) chunk = 4;
        memcpy(&word, bytes + i, chunk);

        nvmc_raw_write_word(target_addr + i, word);
        i += 4;
    }
    return true;
}

volatile uint8_t g_ota_reboot_pending = 0;

uint8_t ota_get_current_slot(void) {
    uint32_t entry = ota_meta_read_active(NULL);
    if (entry != 0xFFFFFFFFUL) {
        return OTA_LOG_GET_SLOT(entry);
    }
    uint32_t vtor = (*(volatile uint32_t *)0xE000ED08UL);
    if (vtor >= FLASH_SLOT_B_BASE && vtor < (FLASH_SLOT_B_BASE + FLASH_SLOT_B_SIZE)) {
        return 1; /* Slot B */
    }
    return 0; /* Slot A */
}

uint8_t ota_get_target_slot(void) {
    return (ota_get_current_slot() == 0) ? 1 : 0;
}

static uint32_t ota_get_target_base(void) {
    return (ota_get_target_slot() == 1) ? FLASH_SLOT_B_BASE : FLASH_SLOT_A_BASE;
}

bool ota_session_begin(uint8_t *cur_slot, uint8_t *tgt_slot) {
    uint8_t cur = ota_get_current_slot();
    uint8_t tgt = ota_get_target_slot();
    if (cur_slot) *cur_slot = cur;
    if (tgt_slot) *tgt_slot = tgt;

    uint32_t tgt_base = ota_get_target_base();
    for (uint32_t addr = tgt_base; addr < (tgt_base + FLASH_SLOT_A_SIZE); addr += FLASH_PAGE_SIZE) {
        nvmc_raw_erase_page(addr);
    }
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0xE0, cur, tgt);
    return true;
}

bool ota_session_write(uint32_t offset, const uint8_t *data, size_t len) {
    if (offset + len > FLASH_SLOT_A_SIZE || data == NULL) {
        return false;
    }
    uint32_t target_addr = ota_get_target_base() + offset;

    size_t i = 0;
    while (i < len) {
        uint32_t word = 0xFFFFFFFFUL;
        size_t chunk = len - i;
        if (chunk > 4) chunk = 4;
        memcpy(&word, data + i, chunk);

        nvmc_raw_write_word(target_addr + i, word);
        i += 4;
    }
    return true;
}

bool ota_session_finalize(uint32_t total_size, const uint8_t expected_hash[32]) {
    if (total_size == 0 || total_size > FLASH_SLOT_A_SIZE || expected_hash == NULL) {
        return false;
    }

    uint32_t tgt_base = ota_get_target_base();
    uint8_t actual_hash[32];
    sha256_hash((const uint8_t *)tgt_base, total_size, actual_hash);

    if (!crypto_consttime_eq(actual_hash, expected_hash, 32)) {
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xE3, 0, 0);
        return false;
    }

    /* Verify Target Slot Application Header Magic */
    const app_header_t *new_hdr = (const app_header_t *)(tgt_base + 0x40);
    if (new_hdr->magic != APP_HEADER_MAGIC) {
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xE5, 0, 0);
        return false;
    }

    /* Verify embedded SHA-256 digest in header */
    if (total_size > 0x80) {
        uint8_t payload_hash[32];
        sha256_hash((const uint8_t *)(tgt_base + 0x80), total_size - 0x80, payload_hash);
        if (!crypto_consttime_eq(payload_hash, new_hdr->sha256, 32)) {
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xE3, 1, 0);
            return false;
        }
    }

    /* Anti-Rollback Check */
    uint32_t cur_base = (ota_get_current_slot() == 1) ? FLASH_SLOT_B_BASE : FLASH_SLOT_A_BASE;
    const app_header_t *cur_hdr = (const app_header_t *)(cur_base + 0x40);
    if (cur_hdr->magic == APP_HEADER_MAGIC) {
        if (new_hdr->security_counter < cur_hdr->security_counter) {
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xE4, new_hdr->security_counter, cur_hdr->security_counter);
            return false; /* Reject downgrade attack */
        }
    }

    /* Determine next version number */
    uint16_t next_ver = (uint16_t)(new_hdr->version & 0xFFFF);
    if (next_ver == 0) {
        uint32_t cur_entry = ota_meta_read_active(NULL);
        if (cur_entry != 0xFFFFFFFFUL) {
            next_ver = OTA_LOG_GET_VER(cur_entry) + 1;
        } else {
            next_ver = 1;
        }
    }

    /* Append single 4-byte switch entry (NO PAGE ERASE, 41 microseconds!) */
    uint8_t target_slot = ota_get_target_slot();
    ota_meta_append_switch(target_slot, next_ver);

    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xE2, total_size, next_ver);
    g_ota_reboot_pending = 1;
    return true;
}

uint16_t ota_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    (void)max_rsp_len;
    if (apdu_len < 4) return 0;
    uint8_t p1 = apdu[2];

    /* Audit Finding 1.2: Mutating OTA operations (Init 0x00, Write 0x01, Finalize 0x02, Swap 0x04)
     * require verified Admin PIN (PW3) authorization. Query (0x03) remains public read-only. */
    if (p1 != 0x03 && !openpgp_is_pw3_verified()) {
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDE, p1, 0);
        rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
        return 2;
    }

    switch (p1) {
        case 0x00: {
            /* Begin OTA Session / Query Slots */
            uint8_t cur, tgt;
            ota_session_begin(&cur, &tgt);
            rsp[0] = cur;
            rsp[1] = tgt;
            rsp[2] = 0x90;
            rsp[3] = 0x00;
            return 4;
        }

        case 0x01: {
            /* Write Chunk: APDU layout: FF FC 01 00 <Len> <Offset:4> <Data> */
            if (apdu_len < 9) {
                rsp[0] = 0x6A; rsp[1] = 0x86;
                return 2;
            }
            uint8_t lc = apdu[4];
            if (lc < 4 || (uint16_t)(5 + lc) > apdu_len) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            uint32_t offset = ((uint32_t)apdu[5] << 24) | ((uint32_t)apdu[6] << 16) |
                              ((uint32_t)apdu[7] << 8)  | apdu[8];
            const uint8_t *chunk = apdu + 9;
            size_t chunk_len = lc - 4;

            if (ota_session_write(offset, chunk, chunk_len)) {
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                rsp[0] = 0x6A; rsp[1] = 0x80;
            }
            return 2;
        }

        case 0x02: {
            /* Finalize: APDU layout: FF FC 02 00 24 <TotalSize:4> <SHA256:32> */
            if (apdu_len < 41 || apdu[4] < 36) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            uint32_t total_size = ((uint32_t)apdu[5] << 24) | ((uint32_t)apdu[6] << 16) |
                                  ((uint32_t)apdu[7] << 8)  | apdu[8];
            const uint8_t *expected_sha256 = apdu + 9;

            if (ota_session_finalize(total_size, expected_sha256)) {
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                rsp[0] = 0x6A; rsp[1] = 0x80;
            }
            return 2;
        }

        case 0x03: {
            /* Query Device Info & Slots: APDU layout: FF FC 03 00 00 */
            extern const app_header_t g_app_header;
            uint8_t cur = ota_get_current_slot();
            uint8_t tgt = ota_get_target_slot();
            rsp[0] = cur;
            rsp[1] = tgt;

            /* Active slot metadata (24 bytes) */
            memcpy(rsp + 2,  &g_app_header.version, 4);
            memcpy(rsp + 6,  &g_app_header.security_counter, 4);
            memcpy(rsp + 10, g_app_header.git_commit, 8);
            memcpy(rsp + 18, g_app_header.build_date, 8);

            /* Target (inactive) slot metadata */
            uint32_t tgt_base = ota_get_target_base();
            const app_header_t *tgt_hdr = (const app_header_t *)(tgt_base + 0x40);
            uint8_t tgt_valid = (tgt_hdr->magic == APP_HEADER_MAGIC) ? 1 : 0;
            rsp[26] = tgt_valid;
            if (tgt_valid) {
                memcpy(rsp + 27, &tgt_hdr->version, 4);
                memcpy(rsp + 31, &tgt_hdr->security_counter, 4);
                memcpy(rsp + 35, tgt_hdr->git_commit, 8);
                memcpy(rsp + 43, tgt_hdr->build_date, 8);
            } else {
                memset(rsp + 27, 0, 24);
            }

            rsp[51] = 0x90;
            rsp[52] = 0x00;
            return 53;
        }

        case 0x04: {
            /* Instant Slot Switch / Rollback: APDU layout: FF FC 04 00 00 */
            uint32_t tgt_base = ota_get_target_base();
            const app_header_t *tgt_hdr = (const app_header_t *)(tgt_base + 0x40);
            if (tgt_hdr->magic != APP_HEADER_MAGIC) {
                /* Target slot does not have a valid firmware image */
                rsp[0] = 0x69; rsp[1] = 0x85;
                return 2;
            }

            /* Anti-Rollback check */
            uint32_t cur_base = (ota_get_current_slot() == 1) ? FLASH_SLOT_B_BASE : FLASH_SLOT_A_BASE;
            const app_header_t *cur_hdr = (const app_header_t *)(cur_base + 0x40);
            if (cur_hdr->magic == APP_HEADER_MAGIC && tgt_hdr->security_counter < cur_hdr->security_counter) {
                rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
                return 2;
            }

            /* Verify target payload digest before switching */
            if (tgt_hdr->image_size > 0x80 && tgt_hdr->image_size <= FLASH_SLOT_A_SIZE) {
                uint8_t p_hash[32];
                sha256_hash((const uint8_t *)(tgt_base + 0x80), tgt_hdr->image_size - 0x80, p_hash);
                if (!crypto_consttime_eq(p_hash, tgt_hdr->sha256, 32)) {
                    rsp[0] = 0x69; rsp[1] = 0x84; /* Data invalid */
                    return 2;
                }
            }

            uint16_t tgt_ver = (uint16_t)(tgt_hdr->version & 0xFFFF);
            ota_meta_append_switch(ota_get_target_slot(), tgt_ver);
            g_ota_reboot_pending = 1;

            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        }

        default:
            rsp[0] = 0x6A; rsp[1] = 0x86;
            return 2;
    }
}

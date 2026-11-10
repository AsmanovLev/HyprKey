#include "storage_flash.h"
#include "device_log.h"
#include "sha256/sha256.h"
#include <string.h>

#define NVMC_READY          (*(volatile uint32_t *)0x4001E400UL)
#define NVMC_CONFIG         (*(volatile uint32_t *)0x4001E504UL)
#define NVMC_ERASEPAGE      (*(volatile uint32_t *)0x4001E508UL)

#define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0CUL)

#define OTA_MAGIC_HEADER    0x48595052UL  /* 'HYPR' */
#define OTA_FLAG_SWAP_REQ   0x00000001UL

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t flags;
    uint32_t image_size;
    uint32_t version;
    uint32_t boot_count;
    uint8_t  sha256[32];
    uint32_t reserved[6];
} ota_meta_record_t;

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

    if (memcmp(actual_hash, expected_hash, 32) != 0) {
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xE3, 0, 0);
        return false;
    }

    /* Write metadata with SHA-256 */
    nvmc_raw_erase_page(FLASH_OTA_META_BASE);

    ota_meta_record_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.magic = OTA_MAGIC_HEADER;
    meta.flags = OTA_FLAG_SWAP_REQ;
    meta.image_size = total_size;
    memcpy(meta.sha256, expected_hash, 32);
    meta.boot_count = 0;

    const uint32_t *words = (const uint32_t *)&meta;
    for (size_t i = 0; i < (sizeof(meta) / 4); i++) {
        nvmc_raw_write_word(FLASH_OTA_META_BASE + (i * 4), words[i]);
    }

    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xE2, total_size, *(const uint32_t *)expected_hash);
    g_ota_reboot_pending = 1;
    return true;
}

uint16_t ota_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    (void)max_rsp_len;
    if (apdu_len < 4) return 0;
    uint8_t p1 = apdu[2];

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

        default:
            rsp[0] = 0x6A; rsp[1] = 0x86;
            return 2;
    }
}

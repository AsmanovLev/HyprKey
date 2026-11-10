#include "storage_flash.h"
#include "device_log.h"
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
    uint32_t crc32;
    uint32_t version;
    uint32_t boot_count;
    uint32_t reserved[10];
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

bool ota_staging_finalize_and_reboot(uint32_t image_size, uint32_t crc32, uint32_t version) {
    if (image_size == 0 || image_size > FLASH_SLOT_B_SIZE) {
        return false;
    }

    /* 1. Write OTA Metadata */
    nvmc_raw_erase_page(FLASH_OTA_META_BASE);

    ota_meta_record_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.magic = OTA_MAGIC_HEADER;
    meta.flags = OTA_FLAG_SWAP_REQ;
    meta.image_size = image_size;
    meta.crc32 = crc32;
    meta.version = version;
    meta.boot_count = 0;

    const uint32_t *words = (const uint32_t *)&meta;
    for (size_t i = 0; i < (sizeof(meta) / 4); i++) {
        nvmc_raw_write_word(FLASH_OTA_META_BASE + (i * 4), words[i]);
    }

    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xE2, image_size, crc32);

    /* 2. Software Reset into Stage-2 Bootloader */
    for (volatile int d = 0; d < 200000; d++);
    SCB_AIRCR = 0x05FA0004UL;
    while (1);

    return true;
}

#ifndef STORAGE_FLASH_H
#define STORAGE_FLASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ==================== Flash Memory Partitioning ==================== */
#define FLASH_PAGE_SIZE         4096UL

/* Stage-2 Bootloader: 0x00026000 - 0x00028000 (8 KB) */
#define FLASH_STAGE2_BASE       0x00026000UL
#define FLASH_STAGE2_SIZE       (8 * 1024UL)

/* Slot A (Active Firmware): 0x00028000 - 0x00040000 (96 KB) */
#define FLASH_SLOT_A_BASE       0x00028000UL
#define FLASH_SLOT_A_SIZE       (96 * 1024UL)

/* Slot B (OTA / Staging): 0x00040000 - 0x00058000 (96 KB) */
#define FLASH_SLOT_B_BASE       0x00040000UL
#define FLASH_SLOT_B_SIZE       (96 * 1024UL)

/* OTA Metadata: 0x00058000 - 0x00059000 (4 KB) */
#define FLASH_OTA_META_BASE     0x00058000UL
#define FLASH_OTA_META_SIZE     4096UL

/* User Data Area: 0x00059000 - 0x000ED000 (592 KB = 148 pages) */
#define FLASH_USERDATA_BASE     0x00059000UL
#define FLASH_USERDATA_SIZE     (592 * 1024UL)
#define FLASH_USERDATA_PAGES    148UL

/* ==================== NVMC Storage Primitives ==================== */
void storage_flash_init(void);
bool storage_flash_erase_page(uint32_t page_index);
bool storage_flash_read(uint32_t byte_offset, void *dst, size_t len);
bool storage_flash_write(uint32_t byte_offset, const void *src, size_t len);
uint32_t storage_flash_get_capacity(void);

/* ==================== OTA Staging Helpers ==================== */
bool ota_staging_erase(void);
bool ota_staging_write_chunk(uint32_t offset, const void *data, size_t len);
bool ota_staging_finalize_and_reboot(uint32_t image_size, uint32_t crc32, uint32_t version);

/* ==================== Cryptographic Hardware Root Secrets ==================== */
void storage_get_device_master_key(const char *domain, uint8_t key_out[32]);

/* ==================== Persistent State & Monotonic Counters ==================== */
uint32_t storage_get_sign_counter(void);
uint32_t storage_increment_sign_counter(void);

#define PIN_TYPE_PGP_PW1    0
#define PIN_TYPE_PGP_PW3    1
#define PIN_TYPE_PIV_PIN    2
#define PIN_TYPE_PIV_PUK    3

uint8_t storage_get_pin_retries(uint8_t pin_type);
void storage_set_pin_retries(uint8_t pin_type, uint8_t retries);

/* ==================== NFC Physical Presence Lock Configuration ==================== */
#define FLASH_NFC_LOCK_PAGE_ADDR (FLASH_USERDATA_BASE + 0x2000UL) /* 0x0005B000 (Page 2) */
#define NFC_LOCK_MAGIC           0x4E4C4B31UL /* 'NLK1' */

#define NFC_LOCK_MODE_DISABLED   0
#define NFC_LOCK_MODE_STATIC_UID 1
#define NFC_LOCK_MODE_EMV_CRYPTO 2

typedef struct {
    uint32_t magic;
    uint8_t  lock_mode;
    uint8_t  enrolled_uid_len;
    uint8_t  enrolled_uid[10];
    uint8_t  enrolled_card_hash[32];
    uint8_t  reserved[16];
} nfc_lock_config_t;

bool storage_get_nfc_lock_config(nfc_lock_config_t *cfg);
bool storage_set_nfc_lock_config(const nfc_lock_config_t *cfg);
void storage_disable_nfc_lock(void);

/* ==================== High-level Autonomous OTA API ==================== */
uint8_t ota_get_current_slot(void);
uint8_t ota_get_target_slot(void);
bool ota_session_begin(uint8_t *cur_slot, uint8_t *tgt_slot);
bool ota_session_write(uint32_t offset, const uint8_t *data, size_t len);
bool ota_session_finalize(uint32_t total_size, const uint8_t expected_hash[32]);
uint16_t ota_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* STORAGE_FLASH_H */

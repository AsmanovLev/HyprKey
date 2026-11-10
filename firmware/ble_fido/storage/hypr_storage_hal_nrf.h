#ifndef HYPR_STORAGE_HAL_NRF_H
#define HYPR_STORAGE_HAL_NRF_H

#include "hypr_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flash Partitioning for nRF52840 (1024 KB Flash) with Adafruit/Nice!Nano UF2 Bootloader:
 * 0x0000_0000 - 0x0002_5FFF : SoftDevice S140 (152 KB)
 * 0x0002_6000 - 0x0004_8FFF : Zone A Application (140 KB, pages 38..72)
 * 0x0004_9000 - 0x000E_CFFF : Zone B Journaled Storage (656 KB, 164 pages * 4 KB, pages 73..236)
 * 0x000E_D000 - 0x000F_FFFF : Adafruit UF2 Bootloader + Settings (76 KB)
 */
#define HYPR_FLASH_ZONE_B_START_PAGE    73U
#define HYPR_FLASH_ZONE_B_BASE_ADDR     (HYPR_FLASH_ZONE_B_START_PAGE * HYPR_FLASH_PAGE_SIZE) /* 0x00049000 */

/**
 * @brief Initialize and retrieve the nRF52840 Hardware Abstraction Layer for hypr_storage
 *
 * @param hal_out Pointer to HAL structure to populate
 */
void hypr_storage_hal_nrf_init(hypr_storage_hal_t *hal_out);

/**
 * @brief Notify HAL that SoftDevice has been enabled and configure SoftDevice POFCON
 */
void hypr_storage_hal_nrf_on_sd_enabled(void);

/**
 * @brief Derive 32-byte Storage Master Key bound to nRF52840 FICR hardware root keys
 *
 * @param mk_out Buffer of at least 32 bytes
 */
void hypr_storage_hal_nrf_get_hardware_key(uint8_t mk_out[32]);

/**
 * @brief Handles SOC Flash events from SoftDevice event dispatcher.
 * Call this from main event loop when sd_evt_get() returns a SOC event.
 */
void hypr_storage_hal_nrf_on_soc_evt(uint32_t evt_id);

#ifdef __cplusplus
}
#endif

#endif /* HYPR_STORAGE_HAL_NRF_H */

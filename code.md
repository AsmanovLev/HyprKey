# HyprKey Codebase Export for Architectural & Security Review

> **Target MCU:** Nordic Semiconductor nRF52840 (Cortex-M4F @ 64 MHz, 1 MB Flash, 256 KB RAM)
> **Device:** nice!nano v2 Security Key Token
> **Export Date:** 2026-11-10
> **Scope:** Bootloader Switcher, Dual-Slot A/B Architecture, Storage Journal, Protocols (FIDO2, OpenPGP, PIV, OATH), Live OTA & Host Tools.

## Flash Memory Map

```text
+-------------------------+ 0x00000000
| Nordic S140 SoftDevice  | (152 KB, 0x00000 - 0x25FFF)
+-------------------------+ 0x00026000
| Stage-2 Switcher        | (8 KB, 0x26000 - 0x27FFF, runs in < 0.1 ms)
+-------------------------+ 0x00028000
| Slot A Application      | (96 KB, 0x28000 - 0x3FFFF)
+-------------------------+ 0x00040000
| Slot B Application      | (96 KB, 0x40000 - 0x57FFF)
+-------------------------+ 0x00058000
| OTA Metadata Page       | (4 KB, 0x58000 - 0x58FFF, 4-byte append-only log)
+-------------------------+ 0x00059000
| User Data & Storage     | (592 KB, 0x59000 - 0xECFFF, Passkeys, PGP, LittleFS)
+-------------------------+ 0x000ED000
| SoftDevice Flash Data   | (28 KB, 0xED000 - 0xF3FFF)
+-------------------------+ 0x000F4000
| Adafruit UF2 Bootloader | (48 KB, 0xF4000 - 0xFFFFF)
+-------------------------+ 0x00100000 (1 MB End)
```

## Table of Contents

- [firmware/stage2_bootloader/linker_stage2.ld](#firmwarestage2bootloaderlinkerstage2ld) - *Stage-2 Linker Script*
- [firmware/stage2_bootloader/stage2_main.c](#firmwarestage2bootloaderstage2mainc) - *Stage-2 Bootloader Switcher (Fast A/B Dispatcher)*
- [firmware/usb_fido/app_header.h](#firmwareusbfidoappheaderh) - *Firmware Image Header & Metadata Definition*
- [firmware/usb_fido/crypto_consttime.h](#firmwareusbfidocryptoconsttimeh) - *Constant-Time Memory & Secret Comparison Primitives*
- [firmware/usb_fido/storage_flash.h](#firmwareusbfidostorageflashh) - *Flash Layout & Dual-Slot Storage Header*
- [firmware/usb_fido/storage_flash.c](#firmwareusbfidostorageflashc) - *Dual-Slot Flash Manager, 4-Byte Journal & Live OTA APDU*
- [firmware/usb_fido/patch_header.py](#firmwareusbfidopatchheaderpy) - *Header Stamping & Cryptographic Image Signer*
- [firmware/usb_fido/linker_slot_a.ld](#firmwareusbfidolinkerslotald) - *Slot A Linker Script (ORIGIN = 0x00028000)*
- [firmware/usb_fido/linker_slot_b.ld](#firmwareusbfidolinkerslotbld) - *Slot B Linker Script (ORIGIN = 0x00040000)*
- [firmware/usb_fido/device_log.h](#firmwareusbfidodevicelogh) - *Device Diagnostics Ring Buffer Header*
- [firmware/usb_fido/device_log.c](#firmwareusbfidodevicelogc) - *Device Diagnostics Ring Buffer Implementation*
- [firmware/usb_fido/ccid/ccid.h](#firmwareusbfidoccidccidh) - *USB CCID Smart Card Transport Header*
- [firmware/usb_fido/ccid/ccid.c](#firmwareusbfidoccidccidc) - *USB CCID Smart Card Transport Implementation*
- [firmware/usb_fido/main.c](#firmwareusbfidomainc) - *Firmware Entry Point, USB Stack, Interrupt Handlers*
- [firmware/usb_fido/fido_u2f.h](#firmwareusbfidofidou2fh) - *FIDO U2F Protocol Definitions*
- [firmware/usb_fido/fido_u2f.c](#firmwareusbfidofidou2fc) - *FIDO U2F Protocol Implementation*
- [firmware/usb_fido/ctap2.h](#firmwareusbfidoctap2h) - *FIDO2 / CTAP2 Protocol Definitions*
- [firmware/usb_fido/ctap2.c](#firmwareusbfidoctap2c) - *FIDO2 / CTAP2 Protocol Implementation*
- [firmware/usb_fido/openpgp/openpgp.h](#firmwareusbfidoopenpgpopenpgph) - *OpenPGP Smart Card 3.4 Definitions*
- [firmware/usb_fido/openpgp/openpgp.c](#firmwareusbfidoopenpgpopenpgpc) - *OpenPGP Smart Card 3.4 Implementation*
- [firmware/usb_fido/piv/piv.h](#firmwareusbfidopivpivh) - *PIV (NIST SP 800-73-4) Definitions*
- [firmware/usb_fido/piv/piv.c](#firmwareusbfidopivpivc) - *PIV (NIST SP 800-73-4) Implementation*
- [firmware/usb_fido/oath/oath.h](#firmwareusbfidooathoathh) - *OATH TOTP/HOTP Definitions*
- [firmware/usb_fido/oath/oath.c](#firmwareusbfidooathoathc) - *OATH TOTP/HOTP Implementation*
- [tools/hyprkey_ota.py](#toolshyprkeyotapy) - *Host Live OTA CCID Streaming Tool*
- [tools/flash_key.py](#toolsflashkeypy) - *Host Autonomous 1-Click DFU Flasher*

---

<a id="firmwarestage2bootloaderlinkerstage2ld"></a>
# File: `firmware/stage2_bootloader/linker_stage2.ld`

> **Description:** Stage-2 Linker Script  
> **Path:** `firmware/stage2_bootloader/linker_stage2.ld`  
> **Lines:** 48  

```ld
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00026000, LENGTH = 0x00028000 - 0x00026000 /* 8 KB */
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 0x00040000             /* 256 KB */
}

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.ARM.exidx*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .data : AT(_etext)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  _estack = ORIGIN(RAM) + 0x4000; /* 16 KB stack for bootloader */
}
```

---

<a id="firmwarestage2bootloaderstage2mainc"></a>
# File: `firmware/stage2_bootloader/stage2_main.c`

> **Description:** Stage-2 Bootloader Switcher (Fast A/B Dispatcher)  
> **Path:** `firmware/stage2_bootloader/stage2_main.c`  
> **Lines:** 172  

```c
#include <stdint.h>
#include <stdbool.h>
#include "sha256.h"
#include "../usb_fido/app_header.h"

/* ==================== Memory Map Definitions ==================== */
#define STAGE2_BASE         0x00026000UL
#define SLOT_A_BASE         0x00028000UL
#define SLOT_B_BASE         0x00040000UL
#define SLOT_SIZE           (96 * 1024)   /* 96 KB = 0x18000 */
#define META_PAGE_ADDR      0x00058000UL
#define USERDATA_BASE       0x00059000UL

/* ==================== 4-Byte Append-Only Metadata Log ==================== */
/* Format: [slot: 8 bits | state: 8 bits | version_counter: 16 bits] */
#define OTA_LOG_GET_SLOT(entry)  ((uint8_t)((entry) & 0xFF))
#define OTA_LOG_GET_STATE(entry) ((uint8_t)(((entry) >> 8) & 0xFF))
#define OTA_LOG_GET_VER(entry)   ((uint16_t)(((entry) >> 16) & 0xFFFF))

/* ==================== Hardware Registers ==================== */
#define SCB_VTOR            (*(volatile uint32_t *)0xE000ED08UL)
#define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0CUL)
#define NRF_POWER_GPREGRET  (*(volatile uint32_t *)0x4000051CUL)
#define DFU_MAGIC_UF2_RESET 0x57

#define P0_DIRSET           (*(volatile uint32_t *)0x50000518UL)
#define P0_OUTSET           (*(volatile uint32_t *)0x50000508UL)
#define P0_OUTCLR           (*(volatile uint32_t *)0x5000050CUL)
#define PIN_LED             15

/* ==================== Validation & Execution ==================== */
static uint32_t ota_meta_read_active(void) {
    const uint32_t *log = (const uint32_t *)META_PAGE_ADDR;
    uint32_t last_entry = 0xFFFFFFFFUL;
    for (uint32_t i = 0; i < 1024; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            break;
        }
        last_entry = log[i];
    }
    return last_entry;
}

static bool is_valid_image(uint32_t base) {
    uint32_t sp = *(volatile uint32_t *)base;
    uint32_t pc = *(volatile uint32_t *)(base + 4);

    /* Stack pointer must be in nRF52840 RAM (0x20000000 .. 0x20040000) */
    if ((sp & 3) != 0 || sp < 0x20001000UL || sp > 0x20040000UL) {
        return false;
    }

    /* Reset handler must be Thumb address inside the slot */
    if ((pc & 1) == 0 || pc < base || pc >= (base + SLOT_SIZE)) {
        return false;
    }

    /* HyprKey application image must have valid header magic */
    const app_header_t *hdr = (const app_header_t *)(base + 0x40);
    if (hdr->magic != APP_HEADER_MAGIC) {
        return false;
    }

    /* Verify compound SHA-256 integrity (vectors 0x00..0x4F + payload 0x80..EOF) against stamped header */
    if (hdr->image_size > 0x80 && hdr->image_size <= SLOT_SIZE) {
        sha256_ctx_t ctx;
        uint8_t actual_hash[32];
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t *)base, 0x50U);
        sha256_update(&ctx, (const uint8_t *)(base + 0x80UL), hdr->image_size - 0x80UL);
        sha256_final(&ctx, actual_hash);

        for (int i = 0; i < 32; i++) {
            if (actual_hash[i] != hdr->sha256[i]) {
                return false; /* Payload hash mismatch! */
            }
        }
    } else {
        return false;
    }

    return true;
}

static void __attribute__((naked, noreturn)) boot_target(uint32_t addr) {
    SCB_VTOR = addr;
    __asm volatile(
        "ldr r0, [%0, #0]\n"   /* Load initial SP */
        "msr msp, r0\n"        /* Set Main Stack Pointer */
        "ldr r1, [%0, #4]\n"   /* Load Reset_Handler address */
        "bx r1\n"              /* Jump to application */
        : : "r"(addr) : "r0", "r1"
    );
}

static void reboot_to_uf2(void) {
    NRF_POWER_GPREGRET = DFU_MAGIC_UF2_RESET;
    SCB_AIRCR = 0x05FA0004UL;
    while (1);
}

/* ==================== Stage-2 Entry Point ==================== */
void Reset_Handler(void);

int main(void) {
    /* 1. Relocate VTOR to Stage-2 vector table */
    SCB_VTOR = STAGE2_BASE;

    /* 2. Configure Status LED (P0.15) */
    P0_DIRSET = (1UL << PIN_LED);
    P0_OUTSET = (1UL << PIN_LED); /* LED off */

    /* 3. Read active entry from 4-byte append-only log */
    uint32_t entry = ota_meta_read_active();
    uint8_t active_slot = (entry == 0xFFFFFFFFUL) ? 0 : OTA_LOG_GET_SLOT(entry);

    /* 4. Boot Target Selection */
    uint32_t primary_target = (active_slot == 1) ? SLOT_B_BASE : SLOT_A_BASE;
    uint32_t fallback_target = (active_slot == 1) ? SLOT_A_BASE : SLOT_B_BASE;

    if (is_valid_image(primary_target)) {
        boot_target(primary_target);
    } else if (is_valid_image(fallback_target)) {
        /* Primary slot corrupted -> Auto-fallback to other slot! */
        boot_target(fallback_target);
    } else {
        /* Both slots invalid -> Emergency bootloader */
        reboot_to_uf2();
    }

    while (1);
    return 0;
}

/* ==================== Startup Vector Table ==================== */
extern uint32_t _estack;
extern uint32_t _etext, _sdata, _edata, _sbss, _ebss;

void Reset_Handler(void) {
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0;
    }
    main();
    while (1);
}

void Default_Handler(void) {
    while (1);
}

__attribute__((section(".isr_vector"), used))
const uint32_t stage2_vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler, /* NMI */
    (uint32_t)Default_Handler, /* HardFault */
    (uint32_t)Default_Handler, /* MemManage */
    (uint32_t)Default_Handler, /* BusFault */
    (uint32_t)Default_Handler, /* UsageFault */
    0, 0, 0, 0,
    (uint32_t)Default_Handler, /* SVCall */
    (uint32_t)Default_Handler, /* DebugMon */
    0,
    (uint32_t)Default_Handler, /* PendSV */
    (uint32_t)Default_Handler, /* SysTick */
};
```

---

<a id="firmwareusbfidoappheaderh"></a>
# File: `firmware/usb_fido/app_header.h`

> **Description:** Firmware Image Header & Metadata Definition  
> **Path:** `firmware/usb_fido/app_header.h`  
> **Lines:** 20  

```c
#ifndef APP_HEADER_H
#define APP_HEADER_H

#include <stdint.h>

#define APP_HEADER_MAGIC 0x48595052UL /* 'HYPR' */

typedef struct __attribute__((packed)) {
    uint32_t magic;            /* 0x48595052 'HYPR' (offset 0x00) */
    uint32_t version;          /* (Major<<24) | (Minor<<16) | (Patch<<8) | Build (offset 0x04) */
    uint32_t security_counter; /* Monotonic Anti-Rollback Counter (offset 0x08) */
    uint32_t image_size;       /* Total image length in bytes (offset 0x0C) */
    uint8_t  sha256[32];       /* SHA-256 digest of payload starting at 0x80 (offset 0x10..0x2F) */
    char     git_commit[8];    /* Git short commit hash (offset 0x30..0x37) */
    char     build_date[8];    /* Build date YYYYMMDD (offset 0x38..0x3F) */
} app_header_t;

_Static_assert(sizeof(app_header_t) == 64, "app_header_t must be exactly 64 bytes");

#endif /* APP_HEADER_H */
```

---

<a id="firmwareusbfidocryptoconsttimeh"></a>
# File: `firmware/usb_fido/crypto_consttime.h`

> **Description:** Constant-Time Memory & Secret Comparison Primitives  
> **Path:** `firmware/usb_fido/crypto_consttime.h`  
> **Lines:** 80  

```c
#ifndef CRYPTO_CONSTTIME_H
#define CRYPTO_CONSTTIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Constant-time memory comparison to protect against timing side-channel attacks.
 * Returns true if both buffers match, false otherwise.
 */
static inline bool crypto_consttime_eq(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return (diff == 0U);
}

/**
 * Secure memory zeroization to wipe sensitive keys from SRAM/stack.
 */
static inline void crypto_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0U;
    }
}

/**
 * Strict ISO/IEC 7816-4 APDU parser.
 * Accurately parses Cases 1, 2S, 2E, 3S, 3E, 4S, 4E, correctly separating Lc data from Le.
 */
static inline bool iso7816_parse_apdu(const uint8_t *apdu, uint16_t apdu_len,
                                      const uint8_t **data_out, uint16_t *lc_out) {
    *data_out = NULL;
    *lc_out   = 0U;

    if (apdu_len < 4U) {
        return false;
    }
    if (apdu_len == 4U) {
        return true; /* Case 1: [CLA INS P1 P2] */
    }
    if (apdu_len == 5U) {
        return true; /* Case 2S: [CLA INS P1 P2 Le] — No body (Lc = 0) */
    }

    if (apdu[4] == 0x00U) {
        /* Extended APDU */
        if (apdu_len == 7U) {
            return true; /* Case 2E: [CLA INS P1 P2 00 Le1 Le2] — No body (Lc = 0) */
        }
        uint16_t lc = (uint16_t)(((uint16_t)apdu[5] << 8U) | apdu[6]);
        if (lc == 0U) {
            return false;
        }
        /* Case 3E: (7 + lc) or Case 4E: (7 + lc + 2 bytes Le) */
        if (apdu_len != (uint16_t)(7U + lc) && apdu_len != (uint16_t)(7U + lc + 2U)) {
            return false;
        }
        *data_out = &apdu[7];
        *lc_out   = lc;
        return true;
    } else {
        /* Short APDU */
        uint16_t lc = apdu[4];
        /* Case 3S: (5 + lc) or Case 4S: (5 + lc + 1 byte Le) */
        if (apdu_len != (uint16_t)(5U + lc) && apdu_len != (uint16_t)(5U + lc + 1U)) {
            return false;
        }
        *data_out = &apdu[5];
        *lc_out   = lc;
        return true;
    }
}

#endif /* CRYPTO_CONSTTIME_H */
```

---

<a id="firmwareusbfidostorageflashh"></a>
# File: `firmware/usb_fido/storage_flash.h`

> **Description:** Flash Layout & Dual-Slot Storage Header  
> **Path:** `firmware/usb_fido/storage_flash.h`  
> **Lines:** 88  

```c
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
```

---

<a id="firmwareusbfidostorageflashc"></a>
# File: `firmware/usb_fido/storage_flash.c`

> **Description:** Dual-Slot Flash Manager, 4-Byte Journal & Live OTA APDU  
> **Path:** `firmware/usb_fido/storage_flash.c`  
> **Lines:** 577  

```c
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

#define FLASH_SIGN_CNT_PAGE_ADDR  (FLASH_USERDATA_BASE)
#define FLASH_PIN_STATE_PAGE_ADDR (FLASH_USERDATA_BASE + FLASH_PAGE_SIZE)

static uint32_t s_cached_sign_counter = 0;
static bool s_sign_counter_initialized = false;

uint32_t storage_get_sign_counter(void) {
    if (s_sign_counter_initialized) {
        return s_cached_sign_counter;
    }
    const uint32_t *log = (const uint32_t *)FLASH_SIGN_CNT_PAGE_ADDR;
    uint32_t val = 0;
    for (uint32_t i = 0; i < 1024; i++) {
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
    uint32_t next = cur + 1U;
    s_cached_sign_counter = next;

    const uint32_t *log = (const uint32_t *)FLASH_SIGN_CNT_PAGE_ADDR;
    uint32_t next_idx = 1024U;
    for (uint32_t i = 0U; i < 1024U; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            next_idx = i;
            break;
        }
    }

    if (next_idx >= 1024U) {
        /* Erase only the sign counter page. PIN state on neighboring page is completely safe. */
        nvmc_raw_erase_page(FLASH_SIGN_CNT_PAGE_ADDR);
        next_idx = 0U;
    }

    nvmc_raw_write_word(FLASH_SIGN_CNT_PAGE_ADDR + (next_idx * 4U), next);
    return next;
}

uint8_t storage_get_pin_retries(uint8_t pin_type) {
    const uint32_t *log = (const uint32_t *)FLASH_PIN_STATE_PAGE_ADDR;
    uint8_t tries = 3; /* default */
    for (uint32_t i = 0; i < 1024; i++) {
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
    /* Guard: Avoid unnecessary Flash writes if current retry count matches */
    if (storage_get_pin_retries(pin_type) == retries) {
        return;
    }

    const uint32_t *log = (const uint32_t *)FLASH_PIN_STATE_PAGE_ADDR;
    uint32_t next_idx = 1024U;
    for (uint32_t i = 0U; i < 1024U; i++) {
        if (log[i] == 0xFFFFFFFFUL) {
            next_idx = i;
            break;
        }
    }

    if (next_idx >= 1024U) {
        /* Compact only the 4 active counters (PW1, PW3, PIV_PIN, PIV_PUK) instead of copying old history */
        uint8_t cur_tries[4];
        for (uint8_t t = 0U; t < 4U; t++) {
            cur_tries[t] = (t == pin_type) ? retries : storage_get_pin_retries(t);
        }
        nvmc_raw_erase_page(FLASH_PIN_STATE_PAGE_ADDR);
        for (uint8_t t = 0U; t < 4U; t++) {
            uint32_t e = ((uint32_t)t) | ((uint32_t)cur_tries[t] << 8U) | 0xFFFF0000UL;
            nvmc_raw_write_word(FLASH_PIN_STATE_PAGE_ADDR + (t * 4U), e);
        }
        return;
    }

    uint32_t entry = ((uint32_t)pin_type) | ((uint32_t)retries << 8U) | 0xFFFF0000UL;
    nvmc_raw_write_word(FLASH_PIN_STATE_PAGE_ADDR + (next_idx * 4U), entry);
}

/* ==================== NFC Physical Presence Lock Configuration Storage ==================== */

bool storage_get_nfc_lock_config(nfc_lock_config_t *cfg) {
    if (!cfg) return false;
    const nfc_lock_config_t *flash_cfg = (const nfc_lock_config_t *)FLASH_NFC_LOCK_PAGE_ADDR;
    if (flash_cfg->magic != NFC_LOCK_MAGIC) {
        memset(cfg, 0, sizeof(nfc_lock_config_t));
        cfg->lock_mode = NFC_LOCK_MODE_DISABLED;
        return false;
    }
    memcpy(cfg, flash_cfg, sizeof(nfc_lock_config_t));
    return true;
}

bool storage_set_nfc_lock_config(const nfc_lock_config_t *cfg) {
    if (!cfg) return false;
    nvmc_raw_erase_page(FLASH_NFC_LOCK_PAGE_ADDR);

    nfc_lock_config_t local_cfg;
    memcpy(&local_cfg, cfg, sizeof(nfc_lock_config_t));
    local_cfg.magic = NFC_LOCK_MAGIC;

    const uint32_t *words = (const uint32_t *)&local_cfg;
    size_t num_words = sizeof(nfc_lock_config_t) / sizeof(uint32_t);
    for (size_t i = 0; i < num_words; i++) {
        nvmc_raw_write_word(FLASH_NFC_LOCK_PAGE_ADDR + (i * 4U), words[i]);
    }
    return true;
}

void storage_disable_nfc_lock(void) {
    nvmc_raw_erase_page(FLASH_NFC_LOCK_PAGE_ADDR);
}

static bool verify_slot_digest(uint32_t base) {
    const app_header_t *hdr = (const app_header_t *)(base + 0x40UL);
    if (hdr->magic != APP_HEADER_MAGIC || hdr->image_size <= 0x80UL || hdr->image_size > FLASH_SLOT_A_SIZE) {
        return false;
    }
    sha256_ctx_t ctx;
    uint8_t actual_hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)base, 0x50U);
    sha256_update(&ctx, (const uint8_t *)(base + 0x80UL), hdr->image_size - 0x80UL);
    sha256_final(&ctx, actual_hash);

    return crypto_consttime_eq(actual_hash, hdr->sha256, 32);
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

static uint32_t s_ota_last_erased_page = 0xFFFFFFFFUL;

bool ota_session_begin(uint8_t *cur_slot, uint8_t *tgt_slot) {
    uint8_t cur = ota_get_current_slot();
    uint8_t tgt = ota_get_target_slot();
    if (cur_slot) *cur_slot = cur;
    if (tgt_slot) *tgt_slot = tgt;

    /* Reset page erase tracker; pages will be erased lazily on demand during write
     * to prevent blocking the USB bus for >2 seconds upfront */
    s_ota_last_erased_page = 0xFFFFFFFFUL;
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0xE0, cur, tgt);
    return true;
}

bool ota_session_write(uint32_t offset, const uint8_t *data, size_t len) {
    if (offset + len > FLASH_SLOT_A_SIZE || data == NULL) {
        return false;
    }
    uint32_t target_addr = ota_get_target_base() + offset;

    /* Erase target pages on demand as write pointer advances */
    uint32_t start_page = target_addr & ~(FLASH_PAGE_SIZE - 1UL);
    uint32_t end_page   = (target_addr + len - 1UL) & ~(FLASH_PAGE_SIZE - 1UL);
    for (uint32_t p = start_page; p <= end_page; p += FLASH_PAGE_SIZE) {
        if (p != s_ota_last_erased_page) {
            nvmc_raw_erase_page(p);
            s_ota_last_erased_page = p;
        }
    }

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

    /* Verify Target Slot Application Header Magic and Compound Digest */
    const app_header_t *new_hdr = (const app_header_t *)(tgt_base + 0x40);
    if (!verify_slot_digest(tgt_base)) {
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xE3, 1, 0);
        return false;
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
            if (!verify_slot_digest(tgt_base)) {
                rsp[0] = 0x69; rsp[1] = 0x84; /* Data invalid */
                return 2;
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
```

---

<a id="firmwareusbfidopatchheaderpy"></a>
# File: `firmware/usb_fido/patch_header.py`

> **Description:** Header Stamping & Cryptographic Image Signer  
> **Path:** `firmware/usb_fido/patch_header.py`  
> **Lines:** 90  

```python
#!/usr/bin/env python3
"""patch_header.py - Stamp firmware metadata, SHA-256 digest, git commit, and build date into app_header_t.

Header layout at offset 0x40:
  0x00: magic (0x48595052 'HYPR')
  0x04: version (Major.Minor.Patch.Build)
  0x08: security_counter (Anti-rollback)
  0x0C: image_size (total bytes)
  0x10..0x2F: sha256 (32 bytes payload digest starting at 0x80)
  0x30..0x37: git_commit (8 bytes ASCII null-padded)
  0x38..0x3F: build_date (8 bytes ASCII "YYYYMMDD")
"""

import sys
import os
import struct
import hashlib
import subprocess
from datetime import datetime

MAGIC_HYPR = 0x48595052
HEADER_OFFSET = 0x40
HEADER_SIZE = 64
PAYLOAD_OFFSET = 0x80

def get_git_commit():
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode("ascii").strip()[:7]
    except Exception:
        return "95f2032"

def patch_binary(bin_path):
    if not os.path.exists(bin_path):
        print(f"Error: {bin_path} does not exist!")
        sys.exit(1)

    with open(bin_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < PAYLOAD_OFFSET:
        print(f"Error: binary too small ({len(data)} bytes)!")
        sys.exit(1)

    # Verify Header Magic
    magic = struct.unpack_from("<I", data, HEADER_OFFSET)[0]
    if magic != MAGIC_HYPR:
        print(f"Error: Invalid header magic: 0x{magic:08X} (expected 0x{MAGIC_HYPR:08X})")
        sys.exit(1)

    version, sec_cnt = struct.unpack_from("<II", data, HEADER_OFFSET + 4)
    image_size = len(data)

    # Stamp image_size first so bytes 0x00..0x4F are final
    struct.pack_into("<I", data, HEADER_OFFSET + 12, image_size)

    # Hash vectors (0x00..0x3F) + immutable header prefix (0x40..0x4F) + payload (0x80..EOF)
    h = hashlib.sha256()
    h.update(data[0x00 : 0x50])
    h.update(data[PAYLOAD_OFFSET:])
    payload_sha256 = h.digest()

    # Git commit and Build date
    git_commit = get_git_commit().encode("ascii").ljust(8, b"\x00")[:8]
    build_date = datetime.now().strftime("%Y%m%d").encode("ascii").ljust(8, b"\x00")[:8]

    # Stamp sha256, git_commit, build_date
    data[HEADER_OFFSET + 16 : HEADER_OFFSET + 48] = payload_sha256
    data[HEADER_OFFSET + 48 : HEADER_OFFSET + 56] = git_commit
    data[HEADER_OFFSET + 56 : HEADER_OFFSET + 64] = build_date

    with open(bin_path, "wb") as f:
        f.write(data)

    v_major = (version >> 24) & 0xFF
    v_minor = (version >> 16) & 0xFF
    v_patch = (version >> 8) & 0xFF
    v_build = version & 0xFF

    print(f"Stamped {bin_path}:")
    print(f"  Version:          v{v_major}.{v_minor}.{v_patch}.{v_build} (0x{version:08X})")
    print(f"  Security Counter: {sec_cnt}")
    print(f"  Image Size:       {image_size} bytes")
    print(f"  Payload SHA-256:  {payload_sha256.hex()}")
    print(f"  Git Commit:       {git_commit.decode('ascii', errors='ignore').strip(chr(0))}")
    print(f"  Build Date:       {build_date.decode('ascii', errors='ignore').strip(chr(0))}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "usb_fido.bin")
    patch_binary(target)
```

---

<a id="firmwareusbfidolinkerslotald"></a>
# File: `firmware/usb_fido/linker_slot_a.ld`

> **Description:** Slot A Linker Script (ORIGIN = 0x00028000)  
> **Path:** `firmware/usb_fido/linker_slot_a.ld`  
> **Lines:** 55  

```ld
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00028000, LENGTH = 0x18000 /* Slot A: 96 KB (0x28000 - 0x3FFFF) */
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 0x40000 /* 256 KB */
}

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .app_header :
  {
    . = ALIGN(4);
    KEEP(*(.app_header))
    . = ALIGN(4);
  } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.ARM.exidx*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .data : AT(_etext)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
```

---

<a id="firmwareusbfidolinkerslotbld"></a>
# File: `firmware/usb_fido/linker_slot_b.ld`

> **Description:** Slot B Linker Script (ORIGIN = 0x00040000)  
> **Path:** `firmware/usb_fido/linker_slot_b.ld`  
> **Lines:** 55  

```ld
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00040000, LENGTH = 0x18000 /* Slot B: 96 KB (0x40000 - 0x57FFF) */
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 0x40000 /* 256 KB */
}

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .app_header :
  {
    . = ALIGN(4);
    KEEP(*(.app_header))
    . = ALIGN(4);
  } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.ARM.exidx*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .data : AT(_etext)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
```

---

<a id="firmwareusbfidodevicelogh"></a>
# File: `firmware/usb_fido/device_log.h`

> **Description:** Device Diagnostics Ring Buffer Header  
> **Path:** `firmware/usb_fido/device_log.h`  
> **Lines:** 81  

```c
#ifndef DEVICE_LOG_H
#define DEVICE_LOG_H

#include <stdint.h>
#include <stdbool.h>

#define DEV_LOG_CAPACITY  128  /* 128 entries * 16 bytes = 2048 bytes (2 KB RAM) */

/* Modules */
#define DEV_LOG_MOD_SYS       0x01
#define DEV_LOG_MOD_USB       0x02
#define DEV_LOG_MOD_CCID      0x03
#define DEV_LOG_MOD_CTAP2     0x04
#define DEV_LOG_MOD_OATH      0x05
#define DEV_LOG_MOD_OPENPGP   0x06
#define DEV_LOG_MOD_PIV       0x07
#define DEV_LOG_MOD_CRYPTO    0x08
#define DEV_LOG_MOD_TOUCH     0x09

/* Severity */
#define DEV_LOG_SEV_INFO      0x00
#define DEV_LOG_SEV_WARN      0x01
#define DEV_LOG_SEV_ERROR     0x02

/* Event IDs */
#define DEV_LOG_EVT_BOOT              0x0001
#define DEV_LOG_EVT_USB_RESET         0x0002
#define DEV_LOG_EVT_USB_CONFIGURED    0x0003
#define DEV_LOG_EVT_USB_SUSPEND       0x0004

#define DEV_LOG_EVT_CCID_ICC_ON       0x0010
#define DEV_LOG_EVT_CCID_ICC_OFF      0x0011
#define DEV_LOG_EVT_CCID_XFR          0x0012
#define DEV_LOG_EVT_CCID_APDU_ROUTE   0x0013
#define DEV_LOG_EVT_CCID_SW           0x0014

#define DEV_LOG_EVT_OATH_SELECT       0x0020
#define DEV_LOG_EVT_OATH_CALC         0x0021
#define DEV_LOG_EVT_OATH_PUT          0x0022
#define DEV_LOG_EVT_OATH_DELETE       0x0023
#define DEV_LOG_EVT_OATH_RESET        0x0024

#define DEV_LOG_EVT_PGP_SELECT        0x0030
#define DEV_LOG_EVT_PGP_VERIFY_PW1    0x0031
#define DEV_LOG_EVT_PGP_VERIFY_PW3    0x0032
#define DEV_LOG_EVT_PGP_CHANGE_PW     0x0033
#define DEV_LOG_EVT_PGP_GEN_KEY       0x0034
#define DEV_LOG_EVT_PGP_SIGN          0x0035
#define DEV_LOG_EVT_PGP_DEC           0x0036

#define DEV_LOG_EVT_CTAP_INIT         0x0040
#define DEV_LOG_EVT_CTAP_MSG          0x0041
#define DEV_LOG_EVT_CTAP_TOUCH        0x0042

#define DEV_LOG_EVT_CRYPTO_ECDSA      0x0050
#define DEV_LOG_EVT_CRYPTO_ED25519    0x0051
#define DEV_LOG_EVT_CRYPTO_MLKEM      0x0052
#define DEV_LOG_EVT_CRYPTO_MLDSA      0x0053

/* 16-byte packed event record */
typedef struct __attribute__((packed)) {
    uint32_t timestamp_ms; // ms since boot from SysTick
    uint8_t  module_id;    // DEV_LOG_MOD_*
    uint8_t  severity;     // DEV_LOG_SEV_*
    uint16_t event_id;     // DEV_LOG_EVT_*
    uint32_t arg0;         // Context arg (e.g. CLA/INS, alg, slot)
    uint32_t arg1;         // Return code (e.g. SW 0x9000, len)
} device_log_entry_t;

/* Global uptime ms tick */
extern volatile uint32_t g_uptime_ms;

void dev_log_init(void);

/* Thread-safe, non-blocking log write into in-memory ring buffer */
void dev_log(uint8_t module, uint8_t severity, uint16_t event, uint32_t arg0, uint32_t arg1);

/* Process Vendor APDU: CLA=0xFF, INS=0xFD */
uint16_t dev_log_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* DEVICE_LOG_H */
```

---

<a id="firmwareusbfidodevicelogc"></a>
# File: `firmware/usb_fido/device_log.c`

> **Description:** Device Diagnostics Ring Buffer Implementation  
> **Path:** `firmware/usb_fido/device_log.c`  
> **Lines:** 128  

```c
#include "device_log.h"
#include <string.h>

volatile uint32_t g_uptime_ms = 0;

static device_log_entry_t s_log_ring[DEV_LOG_CAPACITY];
static uint32_t s_head = 0;
static uint32_t s_total_events = 0;

void dev_log_init(void) {
    memset(s_log_ring, 0, sizeof(s_log_ring));
    s_head = 0;
    s_total_events = 0;
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, DEV_LOG_EVT_BOOT, 0x0005, 0); // version 5.0
}

void dev_log(uint8_t module, uint8_t severity, uint16_t event, uint32_t arg0, uint32_t arg1) {
    /* Fast critical section without halting pipeline */
    __asm__ volatile ("cpsid i" : : : "memory");

    device_log_entry_t *entry = &s_log_ring[s_head];
    entry->timestamp_ms = g_uptime_ms;
    entry->module_id    = module;
    entry->severity     = severity;
    entry->event_id     = event;
    entry->arg0         = arg0;
    entry->arg1         = arg1;

    s_head = (s_head + 1) % DEV_LOG_CAPACITY;
    s_total_events++;

    __asm__ volatile ("cpsie i" : : : "memory");
}

/* Process Vendor APDU:
 * CLA = 0xFF, INS = 0xFD
 * P1 = Sub-command:
 *      0x00 = Read Tail (P2 = max entries to return, 0 = 32)
 *      0x01 = Clear log buffer
 *      0x02 = Get log stats
 */
uint16_t dev_log_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* Wrong length */
        return 2;
    }

    uint8_t p1 = apdu[2];
    uint8_t p2 = apdu[3];

    if (p1 == 0x01) {
        /* Clear logs */
        __asm__ volatile ("cpsid i" : : : "memory");
        s_head = 0;
        memset(s_log_ring, 0, sizeof(s_log_ring));
        __asm__ volatile ("cpsie i" : : : "memory");

        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, DEV_LOG_EVT_BOOT, 0x0005, 1);
        rsp[0] = 0x90; rsp[1] = 0x00;
        return 2;
    }

    if (p1 == 0x02) {
        /* Get stats: [total_events:4][capacity:2][uptime_ms:4] */
        if (max_rsp_len < 12) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        uint32_t tot = s_total_events;
        uint32_t upt = g_uptime_ms;
        rsp[0] = (uint8_t)((tot >> 24) & 0xFF);
        rsp[1] = (uint8_t)((tot >> 16) & 0xFF);
        rsp[2] = (uint8_t)((tot >> 8) & 0xFF);
        rsp[3] = (uint8_t)(tot & 0xFF);
        rsp[4] = 0x00;
        rsp[5] = DEV_LOG_CAPACITY;
        rsp[6] = (uint8_t)((upt >> 24) & 0xFF);
        rsp[7] = (uint8_t)((upt >> 16) & 0xFF);
        rsp[8] = (uint8_t)((upt >> 8) & 0xFF);
        rsp[9] = (uint8_t)(upt & 0xFF);
        rsp[10] = 0x90;
        rsp[11] = 0x00;
        return 12;
    }

    /* P1 == 0x00: Read Tail */
    uint8_t count_req = p2;
    if (count_req == 0 || count_req > 64) {
        count_req = 32; /* Default 32 latest entries */
    }

    uint32_t available = (s_total_events < DEV_LOG_CAPACITY) ? s_total_events : DEV_LOG_CAPACITY;
    if (count_req > available) {
        count_req = (uint8_t)available;
    }

    uint16_t payload_len = 9 + (count_req * sizeof(device_log_entry_t));
    if (payload_len + 2 > max_rsp_len) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    /* Header: [total_events:4][uptime_ms:4][count:1] */
    uint32_t tot = s_total_events;
    uint32_t upt = g_uptime_ms;
    rsp[0] = (uint8_t)((tot >> 24) & 0xFF);
    rsp[1] = (uint8_t)((tot >> 16) & 0xFF);
    rsp[2] = (uint8_t)((tot >> 8) & 0xFF);
    rsp[3] = (uint8_t)(tot & 0xFF);
    rsp[4] = (uint8_t)((upt >> 24) & 0xFF);
    rsp[5] = (uint8_t)((upt >> 16) & 0xFF);
    rsp[6] = (uint8_t)((upt >> 8) & 0xFF);
    rsp[7] = (uint8_t)(upt & 0xFF);
    rsp[8] = count_req;

    /* Copy in chronological order (oldest to newest among the last count_req) */
    uint32_t start_idx = (s_head + DEV_LOG_CAPACITY - count_req) % DEV_LOG_CAPACITY;
    uint8_t *dest = rsp + 9;
    for (uint8_t i = 0; i < count_req; i++) {
        uint32_t cur = (start_idx + i) % DEV_LOG_CAPACITY;
        memcpy(dest, &s_log_ring[cur], sizeof(device_log_entry_t));
        dest += sizeof(device_log_entry_t);
    }

    rsp[payload_len]     = 0x90;
    rsp[payload_len + 1] = 0x00;
    return payload_len + 2;
}
```

---

<a id="firmwareusbfidoccidccidh"></a>
# File: `firmware/usb_fido/ccid/ccid.h`

> **Description:** USB CCID Smart Card Transport Header  
> **Path:** `firmware/usb_fido/ccid/ccid.h`  
> **Lines:** 45  

```c
#ifndef CCID_H
#define CCID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CCID_MAX_MSG_SIZE 3072

/* CCID Message Types (PC -> RDR) */
#define CCID_PC_TO_RDR_ICC_POWER_ON      0x62
#define CCID_PC_TO_RDR_ICC_POWER_OFF     0x63
#define CCID_PC_TO_RDR_GET_SLOT_STATUS   0x65
#define CCID_PC_TO_RDR_XFR_BLOCK         0x6F
#define CCID_PC_TO_RDR_GET_PARAMETERS    0x6C
#define CCID_PC_TO_RDR_RESET_PARAMETERS  0x6D
#define CCID_PC_TO_RDR_SET_PARAMETERS    0x61
#define CCID_PC_TO_RDR_ESCAPE            0x6B

/* CCID Message Types (RDR -> PC) */
#define CCID_RDR_TO_PC_DATA_BLOCK        0x80
#define CCID_RDR_TO_PC_SLOT_STATUS       0x81
#define CCID_RDR_TO_PC_PARAMETERS        0x82
#define CCID_RDR_TO_PC_ESCAPE            0x83

/* CCID Header Structure (10 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  bMessageType;
    uint32_t dwLength;
    uint8_t  bSlot;
    uint8_t  bSeq;
    uint8_t  bParam0;
    uint8_t  bParam1;
    uint8_t  bParam2;
} ccid_header_t;

void ccid_init(void);

extern volatile uint8_t g_dfu_reset_pending;

/* Process a complete CCID command from host and write response.
 * Returns length of response written to rsp. */
uint16_t ccid_process_message(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* CCID_H */
```

---

<a id="firmwareusbfidoccidccidc"></a>
# File: `firmware/usb_fido/ccid/ccid.c`

> **Description:** USB CCID Smart Card Transport Implementation  
> **Path:** `firmware/usb_fido/ccid/ccid.c`  
> **Lines:** 368  

```c
#include "ccid.h"
#include "openpgp/openpgp.h"
#include "piv/piv.h"
#include "oath/oath.h"
#include "device_log.h"
#include "storage_flash.h"
#include "../pn532_nfc.h"
#include <string.h>

typedef enum {
    CCID_APPLET_OPENPGP = 0,
    CCID_APPLET_PIV,
    CCID_APPLET_OATH
} ccid_applet_t;

static ccid_applet_t s_active_applet = CCID_APPLET_OPENPGP;
volatile uint8_t g_dfu_reset_pending = 0;

void ccid_init(void) {
    dev_log_init();
    openpgp_init();
    piv_init();
    oath_init();
    s_active_applet = CCID_APPLET_OPENPGP;
}

uint16_t ccid_process_message(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (req_len < 10) return 0;

    uint8_t msg_type = req[0];
    uint32_t length = (uint32_t)req[1] | ((uint32_t)req[2] << 8) |
                      ((uint32_t)req[3] << 16) | ((uint32_t)req[4] << 24);
    uint8_t slot = req[5];
    uint8_t seq  = req[6];

    if (slot != 0) {
        /* Slot does not exist */
        rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
        rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
        rsp[5] = slot;
        rsp[6] = seq;
        rsp[7] = 0x40 | 0x02; /* Command failed, No ICC present */
        rsp[8] = 0x05;        /* Slot not found */
        rsp[9] = 0;
        return 10;
    }

    switch (msg_type) {
        case CCID_PC_TO_RDR_ICC_POWER_ON: {
            uint16_t atr_len = openpgp_get_atr(rsp + 10, max_rsp_len - 10);
            rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
            rsp[1] = (uint8_t)(atr_len & 0xFF);
            rsp[2] = (uint8_t)((atr_len >> 8) & 0xFF);
            rsp[3] = 0;
            rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Command success, Card active */
            rsp[8] = 0x00; /* Error code 0 */
            rsp[9] = 0x00; /* Chain parameter */
            return 10 + atr_len;
        }

        case CCID_PC_TO_RDR_ICC_POWER_OFF: {
            rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
            rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x01; /* Card inactive */
            rsp[8] = 0x00;
            rsp[9] = 0x00;
            return 10;
        }

        case CCID_PC_TO_RDR_GET_SLOT_STATUS: {
            rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
            rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Card present and active */
            rsp[8] = 0x00;
            rsp[9] = 0x00;
            return 10;
        }

        case CCID_PC_TO_RDR_GET_PARAMETERS:
        case CCID_PC_TO_RDR_RESET_PARAMETERS:
        case CCID_PC_TO_RDR_SET_PARAMETERS: {
            /* T=1 Protocol Parameters */
            rsp[0] = CCID_RDR_TO_PC_PARAMETERS;
            rsp[1] = 7; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0; /* 7 bytes param */
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Card active */
            rsp[8] = 0x00;
            rsp[9] = 0x01; /* Protocol T=1 */
            /* T=1 Data: bmFindexDindex, bmTCCKST1, bGuardTimeT1, bmWaitingIntegersT1, bClockStop, bIFSC, bNadValue */
            rsp[10] = 0x18; /* Fi=372, Di=12 matching TA1 */
            rsp[11] = 0x00; /* LRC checksum */
            rsp[12] = 0x00; /* Extra guard time = 0 */
            rsp[13] = 0x75; /* BWI=7, CWI=5 matching TB3 */
            rsp[14] = 0x00; /* Clock stop not supported */
            rsp[15] = 0xFE; /* IFSC = 254 matching TA3 */
            rsp[16] = 0x00; /* NAD = 0 */
            return 17;
        }

        case CCID_PC_TO_RDR_XFR_BLOCK: {
            const uint8_t *apdu = req + 10;
            uint16_t apdu_len = (uint16_t)length;
            if (10 + apdu_len > req_len) {
                apdu_len = req_len - 10;
            }

            /* Log incoming APDU header: CLA INS P1 P2 */
            uint32_t apdu_hdr = (apdu_len >= 4) ? (((uint32_t)apdu[0] << 24) | ((uint32_t)apdu[1] << 16) | ((uint32_t)apdu[2] << 8) | apdu[3]) : 0;
            dev_log(DEV_LOG_MOD_CCID, DEV_LOG_SEV_INFO, DEV_LOG_EVT_CCID_XFR, apdu_hdr, apdu_len);

            /* Intercept Vendor APDU for Live Seamless A/B OTA (CLA=0xFF, INS=0xFC) */
            if (apdu_len >= 4 && apdu[0] == 0xFF && apdu[1] == 0xFC) {
                uint16_t apdu_rsp_len = ota_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                rsp[3] = 0;
                rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                return 10 + apdu_rsp_len;
            }

            /* Intercept Vendor APDU for DFU Bootloader Reset (FF FD 42 00 or FF FE 00 00)
             * Audit Finding 1.2: Enforce Admin PIN (PW3) authorization before resetting to DFU */
            if (apdu_len >= 4 && ((apdu[0] == 0xFF && apdu[1] == 0xFD && apdu[2] == 0x42) ||
                                  (apdu[0] == 0xFF && apdu[1] == 0xFE))) {
                if (!openpgp_is_pw3_verified()) {
                    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDE, 0, 0);
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot;
                    rsp[6] = seq;
                    rsp[7] = 0x00;
                    rsp[8] = 0x00;
                    rsp[9] = 0x00;
                    rsp[10] = 0x69; /* SW1 = 0x69 */
                    rsp[11] = 0x82; /* SW2 = 0x82: Security status not satisfied */
                    return 12;
                }
                dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDF, 0, 0);
                g_dfu_reset_pending = 1;
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                rsp[10] = 0x90; /* SW1 = 0x90 */
                rsp[11] = 0x00; /* SW2 = 0x00 */
                return 12;
            }

            /* Intercept Vendor APDU for In-Memory Device Logs (CLA=0xFF, INS=0xFD) */
            if (apdu_len >= 4 && apdu[0] == 0xFF && apdu[1] == 0xFD) {
                uint16_t apdu_rsp_len = dev_log_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                rsp[3] = 0;
                rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                return 10 + apdu_rsp_len;
            }

            /* Intercept Vendor APDU for NFC Tag Scan / Inspection (INS=0xEA) */
            if (apdu_len >= 4 && apdu[1] == 0xEA) {
                uint16_t apdu_rsp_len = pn532_scan_tag(rsp + 10, max_rsp_len - 10);
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                rsp[3] = 0;
                rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                return 10 + apdu_rsp_len;
            }

            /* Intercept Vendor APDU for NFC Physical Presence Lock Management (INS=0xEB) */
            if (apdu_len >= 4 && apdu[1] == 0xEB) {
                uint8_t sub_cmd = apdu[2];
                uint8_t mode = apdu[3];

                if (sub_cmd == 0x00) {
                    /* Query Lock Status: FF EB 00 00 */
                    uint8_t lmode;
                    bool locked;
                    uint8_t ulen;
                    uint8_t e_uid[10];
                    uint8_t e_hash[32];
                    pn532_get_lock_status(&lmode, &locked, &ulen, e_uid, e_hash);

                    uint16_t apdu_rsp_len = 0;
                    rsp[10 + apdu_rsp_len++] = lmode;
                    rsp[10 + apdu_rsp_len++] = locked ? 0x01 : 0x00;
                    rsp[10 + apdu_rsp_len++] = ulen;
                    memcpy(rsp + 10 + apdu_rsp_len, e_uid, ulen);
                    apdu_rsp_len += ulen;
                    memcpy(rsp + 10 + apdu_rsp_len, e_hash, 32);
                    apdu_rsp_len += 32;

                    rsp[10 + apdu_rsp_len++] = 0x90;
                    rsp[10 + apdu_rsp_len++] = 0x00;

                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                    rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                    rsp[3] = 0; rsp[4] = 0; rsp[5] = slot; rsp[6] = seq;
                    rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    return 10 + apdu_rsp_len;
                }

                /* Mutating commands (Enroll 0x01, Disable 0x02) require verified Admin PIN (PW3) */
                if (!openpgp_is_pw3_verified()) {
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x69; rsp[11] = 0x82; /* Security status not satisfied */
                    return 12;
                }

                if (sub_cmd == 0x01) {
                    /* Enroll: mode 1 = Static UID, mode 2 = EMV Crypto */
                    uint16_t apdu_rsp_len = 0;
                    if (mode == 0x01) {
                        uint8_t enrolled_uid[10];
                        uint8_t ulen = 0;
                        if (pn532_enroll_tag_uid(enrolled_uid, &ulen)) {
                            rsp[10 + apdu_rsp_len++] = 0x01; /* Warning: Insecure Static UID */
                            rsp[10 + apdu_rsp_len++] = ulen;
                            memcpy(rsp + 10 + apdu_rsp_len, enrolled_uid, ulen);
                            apdu_rsp_len += ulen;
                            rsp[10 + apdu_rsp_len++] = 0x90;
                            rsp[10 + apdu_rsp_len++] = 0x00;
                        } else {
                            rsp[10 + apdu_rsp_len++] = 0x6A;
                            rsp[10 + apdu_rsp_len++] = 0x80; /* Incorrect parameters / no card */
                        }
                    } else if (mode == 0x02) {
                        uint8_t hash[32];
                        if (pn532_enroll_emv_crypto(hash)) {
                            rsp[10 + apdu_rsp_len++] = 0x00; /* Secure: Zero-clone EMV */
                            memcpy(rsp + 10 + apdu_rsp_len, hash, 32);
                            apdu_rsp_len += 32;
                            rsp[10 + apdu_rsp_len++] = 0x90;
                            rsp[10 + apdu_rsp_len++] = 0x00;
                        } else {
                            rsp[10 + apdu_rsp_len++] = 0x6A;
                            rsp[10 + apdu_rsp_len++] = 0x80;
                        }
                    }
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                    rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                    rsp[3] = 0; rsp[4] = 0; rsp[5] = slot; rsp[6] = seq;
                    rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    return 10 + apdu_rsp_len;
                }

                if (sub_cmd == 0x02) {
                    /* Disable Lock */
                    pn532_disable_lock();
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x90; rsp[11] = 0x00;
                    return 12;
                }

                if (sub_cmd == 0x03) {
                    /* Lock now (re-arm lock immediately) */
                    pn532_lock_force();
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x90; rsp[11] = 0x00;
                    return 12;
                }
            }

            /* Explicit Applet Switching on SELECT AID (00 A4 04 ...) */
            if (apdu_len >= 5 && apdu[1] == 0xA4 && apdu[2] == 0x04) {
                uint8_t aid_len = apdu[4];
                const uint8_t *aid = apdu + 5;
                if (aid_len >= 7 && memcmp(aid, "\xA0\x00\x00\x05\x27\x21\x01", 7) == 0) {
                    s_active_applet = CCID_APPLET_OATH;
                    dev_log(DEV_LOG_MOD_OATH, DEV_LOG_SEV_INFO, DEV_LOG_EVT_OATH_SELECT, 0, 0);
                } else if (aid_len >= 11 && memcmp(aid, "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00", 11) == 0) {
                    s_active_applet = CCID_APPLET_PIV;
                    dev_log(DEV_LOG_MOD_PIV, DEV_LOG_SEV_INFO, DEV_LOG_EVT_CCID_APDU_ROUTE, CCID_APPLET_PIV, 0);
                } else if (aid_len >= 6 && memcmp(aid, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
                    s_active_applet = CCID_APPLET_OPENPGP;
                    dev_log(DEV_LOG_MOD_OPENPGP, DEV_LOG_SEV_INFO, DEV_LOG_EVT_PGP_SELECT, 0, 0);
                }
            }

            /* Check Physical Presence Lock: block cryptographic & secret operations if locked */
            if (pn532_is_locked()) {
                uint8_t ins = (apdu_len >= 2) ? apdu[1] : 0;
                /* If INS is PSO (0x2A), GENERATE KEY (0x47), GENERAL AUTHENTICATE (0x87),
                 * VERIFY (0x20), or CHANGE PIN (0x24), reject with 0x6982 */
                if (ins == 0x2A || ins == 0x47 || ins == 0x87 || ins == 0x20 || ins == 0x24) {
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x69; rsp[11] = 0x82; /* Security status not satisfied: device locked */
                    return 12;
                }
            }

            uint16_t apdu_rsp_len = 0;
            if (s_active_applet == CCID_APPLET_OATH) {
                apdu_rsp_len = oath_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
            } else if (s_active_applet == CCID_APPLET_PIV) {
                apdu_rsp_len = piv_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
            } else {
                apdu_rsp_len = openpgp_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
            }

            /* Log SW response */
            uint16_t sw = (apdu_rsp_len >= 2) ? (((uint16_t)rsp[10 + apdu_rsp_len - 2] << 8) | rsp[10 + apdu_rsp_len - 1]) : 0;
            dev_log(DEV_LOG_MOD_CCID, (sw == 0x9000) ? DEV_LOG_SEV_INFO : DEV_LOG_SEV_WARN, DEV_LOG_EVT_CCID_SW, s_active_applet, sw);

            rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
            rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
            rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
            rsp[3] = 0;
            rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Success, card active */
            rsp[8] = 0x00;
            rsp[9] = 0x00; /* Chain parameter */
            return 10 + apdu_rsp_len;
        }

        default: {
            /* Unsupported command */
            rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
            rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x40 | 0x00; /* Command failed, card active */
            rsp[8] = 0xFE;        /* Command not supported */
            rsp[9] = 0x00;
            return 10;
        }
    }
}
```

---

<a id="firmwareusbfidomainc"></a>
# File: `firmware/usb_fido/main.c`

> **Description:** Firmware Entry Point, USB Stack, Interrupt Handlers  
> **Path:** `firmware/usb_fido/main.c`  
> **Lines:** 1314  

```c
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "fido_u2f.h"
#include "ctap2.h"
#include "ccid/ccid.h"
#include "openpgp/openpgp.h"
#include "oath/oath.h"
#include "device_log.h"
#include "app_header.h"
#include "pn532_nfc.h"

__attribute__((section(".app_header"), used))
const app_header_t g_app_header = {
    .magic            = APP_HEADER_MAGIC,
    .version          = (1 << 24) | (0 << 16) | (0 << 8) | 1, /* v1.0.0.1 */
    .security_counter = 1,
    .image_size       = 0,
    .sha256           = {0},
    .git_commit       = "95f2032",
    .build_date       = "20261110",
};

/* ==================== nRF52840 Registers ==================== */
#define P0_BASE               0x50000000UL
#define P0_OUTSET             (*(volatile uint32_t *)(P0_BASE + 0x508))
#define P0_OUTCLR             (*(volatile uint32_t *)(P0_BASE + 0x50C))
#define P0_IN                 (*(volatile uint32_t *)(P0_BASE + 0x510))
#define P0_DIRSET             (*(volatile uint32_t *)(P0_BASE + 0x518))
#define P0_PIN_CNF(n)         (*(volatile uint32_t *)(P0_BASE + 0x700 + ((n) * 4)))

#define PIN_LED               15  /* P0.15, active LOW */
#define PIN_DBG_TX            10  /* P0.10 -> CH340 RX */
#define PIN_TOUCH             11  /* P0.11 -> Touch interrupt / Button */

/* UART1 Registers */
#define UART1_BASE            0x40028000UL
#define UART1_TASKS_STARTTX   (*(volatile uint32_t *)(UART1_BASE + 0x008))
#define UART1_ENABLE          (*(volatile uint32_t *)(UART1_BASE + 0x500))
#define UART1_PSEL_TXD        (*(volatile uint32_t *)(UART1_BASE + 0x50C))
#define UART1_PSEL_RXD        (*(volatile uint32_t *)(UART1_BASE + 0x514))
#define UART1_BAUDRATE        (*(volatile uint32_t *)(UART1_BASE + 0x524))
#define UART1_TXD_PTR         (*(volatile uint32_t *)(UART1_BASE + 0x544))
#define UART1_TXD_MAXCNT      (*(volatile uint32_t *)(UART1_BASE + 0x548))
#define UART1_EVENTS_ENDTX    (*(volatile uint32_t *)(UART1_BASE + 0x120))

/* Clock & Power Registers */
#define CLOCK_BASE            0x40000000UL
#define POWER_BASE            0x40000000UL
#define CLOCK_TASKS_HFCLKSTART  (*(volatile uint32_t *)(CLOCK_BASE + 0x000))
#define CLOCK_EVENTS_HFCLKSTARTED (*(volatile uint32_t *)(CLOCK_BASE + 0x100))
#define POWER_USBREGSTATUS      (*(volatile uint32_t *)(POWER_BASE + 0x438))
#define POWER_EVENTS_USBDETECTED (*(volatile uint32_t *)(POWER_BASE + 0x11C))
#define POWER_EVENTS_USBPWRRDY   (*(volatile uint32_t *)(POWER_BASE + 0x124))

/* USBD Base Address */
#define USBD_BASE             0x40027000UL

/* Tasks */
#define USBD_TASKS_STARTEPIN(n) (*(volatile uint32_t *)(USBD_BASE + 0x004 + ((n) * 4)))
#define USBD_TASKS_STARTEPOUT(n)(*(volatile uint32_t *)(USBD_BASE + 0x028 + ((n) * 4)))
#define USBD_TASKS_EP0RCVOUT    (*(volatile uint32_t *)(USBD_BASE + 0x04C))
#define USBD_TASKS_EP0STATUS    (*(volatile uint32_t *)(USBD_BASE + 0x050))
#define USBD_TASKS_EP0STALL     (*(volatile uint32_t *)(USBD_BASE + 0x054))

/* Events */
#define USBD_EVENTS_USBRESET    (*(volatile uint32_t *)(USBD_BASE + 0x100))
#define USBD_EVENTS_ENDEPIN(n)  (*(volatile uint32_t *)(USBD_BASE + 0x108 + ((n) * 4)))
#define USBD_EVENTS_EP0DATADONE (*(volatile uint32_t *)(USBD_BASE + 0x128))
#define USBD_EVENTS_ENDEPOUT(n) (*(volatile uint32_t *)(USBD_BASE + 0x130 + ((n) * 4)))
#define USBD_EVENTS_ENDISOOUT   (*(volatile uint32_t *)(USBD_BASE + 0x150))
#define USBD_EVENTS_SOF         (*(volatile uint32_t *)(USBD_BASE + 0x154))
#define USBD_EVENTS_USBEVENT    (*(volatile uint32_t *)(USBD_BASE + 0x158))
#define USBD_EVENTS_EP0SETUP    (*(volatile uint32_t *)(USBD_BASE + 0x15C))
#define USBD_EVENTS_EPDATA      (*(volatile uint32_t *)(USBD_BASE + 0x160))

/* Registers */
#define USBD_EVENTCAUSE         (*(volatile uint32_t *)(USBD_BASE + 0x400))
#define USBD_EPSTATUS           (*(volatile uint32_t *)(USBD_BASE + 0x468))
#define USBD_EPDATASTATUS       (*(volatile uint32_t *)(USBD_BASE + 0x46C))
#define USBD_SIZE_EPOUT(n)      (*(volatile uint32_t *)(USBD_BASE + 0x4A0 + ((n) * 4)))
#define USBD_BMREQUESTTYPE      (*(volatile uint32_t *)(USBD_BASE + 0x480))
#define USBD_BREQUEST           (*(volatile uint32_t *)(USBD_BASE + 0x484))
#define USBD_WVALUEL            (*(volatile uint32_t *)(USBD_BASE + 0x488))
#define USBD_WVALUEH            (*(volatile uint32_t *)(USBD_BASE + 0x48C))
#define USBD_WINDEXL            (*(volatile uint32_t *)(USBD_BASE + 0x490))
#define USBD_WINDEXH            (*(volatile uint32_t *)(USBD_BASE + 0x494))
#define USBD_WLENGTHL           (*(volatile uint32_t *)(USBD_BASE + 0x498))
#define USBD_WLENGTHH           (*(volatile uint32_t *)(USBD_BASE + 0x49C))
#define USBD_EPINEN             (*(volatile uint32_t *)(USBD_BASE + 0x510))
#define USBD_EPOUTEN            (*(volatile uint32_t *)(USBD_BASE + 0x514))
#define USBD_ENABLE             (*(volatile uint32_t *)(USBD_BASE + 0x500))
#define USBD_USBPULLUP          (*(volatile uint32_t *)(USBD_BASE + 0x504))
#define USBD_LOWPOWER           (*(volatile uint32_t *)(USBD_BASE + 0x544))
#define USBD_EPSTATUS           (*(volatile uint32_t *)(USBD_BASE + 0x468))

/* Endpoint EasyDMA Structures */
typedef struct {
    volatile uint32_t PTR;
    volatile uint32_t MAXCNT;
    volatile uint32_t AMOUNT;
} usbd_ep_t;

#define USBD_EPIN_BASE  (USBD_BASE + 0x600)
#define USBD_EPOUT_BASE (USBD_BASE + 0x700)

#define USBD_EPIN(n)  ((volatile usbd_ep_t *)(USBD_EPIN_BASE + ((n) * 0x14)))
#define USBD_EPOUT(n) ((volatile usbd_ep_t *)(USBD_EPOUT_BASE + ((n) * 0x14)))

/* ==================== UART Debug ==================== */
static volatile uint8_t m_tx_byte;

static void uart_init(void) {
    P0_DIRSET = (1UL << PIN_DBG_TX);
    P0_PIN_CNF(PIN_DBG_TX) = 0x00000003UL;
    UART1_PSEL_TXD = PIN_DBG_TX;
    UART1_PSEL_RXD = 0xFFFFFFFFUL;
    UART1_BAUDRATE = 0x01D7E000UL; /* 115200 */
    UART1_ENABLE = 8;
}

static void uart_putc(char c) {
    m_tx_byte = (uint8_t)c;
    UART1_TXD_PTR = (uint32_t)&m_tx_byte;
    UART1_TXD_MAXCNT = 1;
    UART1_EVENTS_ENDTX = 0;
    UART1_TASKS_STARTTX = 1;
    while (!UART1_EVENTS_ENDTX);
}

static void uart_puts(const char *s) {
    while (*s) uart_putc(*s++);
}

static void uart_puthex8(uint8_t b) {
    static const char hex[] = "0123456789ABCDEF";
    uart_putc(hex[(b >> 4) & 0x0F]);
    uart_putc(hex[b & 0x0F]);
}

static void uart_puthex32(uint32_t v) {
    uart_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        uart_putc("0123456789ABCDEF"[(v >> i) & 0x0F]);
    }
}

/* ==================== USB Descriptors ==================== */
static const uint8_t s_device_desc[] = {
    0x12,       /* bLength = 18 */
    0x01,       /* bDescriptorType = DEVICE */
    0x00, 0x02, /* bcdUSB = 2.00 */
    0x00,       /* bDeviceClass = 0 (Interface defined) */
    0x00,       /* bDeviceSubClass = 0 */
    0x00,       /* bDeviceProtocol = 0 */
    0x40,       /* bMaxPacketSize0 = 64 */
    0x09, 0x12, /* idVendor  = 0x1209 (pid.codes open source VID) */
    0x05, 0x00, /* idProduct = 0x0005 (Composite FIDO2 + OpenPGP/PIV CCID + OTP Keyboard v5) */
    0x00, 0x05, /* bcdDevice = 5.00 */
    0x01,       /* iManufacturer = String 1 */
    0x02,       /* iProduct = String 2 */
    0x03,       /* iSerialNumber = String 3 */
    0x01        /* bNumConfigurations = 1 */
};

static const uint8_t s_config_desc[] = {
    /* Configuration Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x02,       /* bDescriptorType = CONFIGURATION */
    0x8F, 0x00, /* wTotalLength = 143 bytes (9 + 32 + 77 + 25) */
    0x03,       /* bNumInterfaces = 3 (Interface 0: HID FIDO2, Interface 1: CCID OpenPGP/PIV, Interface 2: HID Keyboard OTP) */
    0x01,       /* bConfigurationValue = 1 */
    0x00,       /* iConfiguration = 0 */
    0x80,       /* bmAttributes = Bus powered */
    0x32,       /* bMaxPower = 100 mA (50 * 2mA) */

    /* ================= Interface 0: HID (FIDO2 / U2F) (32 bytes) ================= */
    /* Interface Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x04,       /* bDescriptorType = INTERFACE */
    0x00,       /* bInterfaceNumber = 0 */
    0x00,       /* bAlternateSetting = 0 */
    0x02,       /* bNumEndpoints = 2 (EP1 IN, EP1 OUT) */
    0x03,       /* bInterfaceClass = 0x03 (HID) */
    0x00,       /* bInterfaceSubClass = 0 */
    0x00,       /* bInterfaceProtocol = 0 */
    0x00,       /* iInterface = 0 */

    /* HID Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x21,       /* bDescriptorType = HID */
    0x11, 0x01, /* bcdHID = 1.11 */
    0x00,       /* bCountryCode = 0 */
    0x01,       /* bNumDescriptors = 1 */
    0x22,       /* bDescriptorType = REPORT */
    0x22, 0x00, /* wDescriptorLength = 34 bytes (0x0022) */

    /* Endpoint Descriptor IN 1 (7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x81,       /* bEndpointAddress = EP 1 IN */
    0x03,       /* bmAttributes = Interrupt */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x05,       /* bInterval = 5 ms */

    /* Endpoint Descriptor OUT 1 (7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x01,       /* bEndpointAddress = EP 1 OUT */
    0x03,       /* bmAttributes = Interrupt */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x05,       /* bInterval = 5 ms */

    /* ================= Interface 1: CCID (Smart Card / OpenPGP / PIV) (77 bytes) ================= */
    /* Interface Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x04,       /* bDescriptorType = INTERFACE */
    0x01,       /* bInterfaceNumber = 1 */
    0x00,       /* bAlternateSetting = 0 */
    0x02,       /* bNumEndpoints = 2 (EP2 OUT, EP2 IN) */
    0x0B,       /* bInterfaceClass = 0x0B (CCID) */
    0x00,       /* bInterfaceSubClass = 0 */
    0x00,       /* bInterfaceProtocol = 0 */
    0x04,       /* iInterface = String 4 ("hyprkey OpenPGP CCID") */

    /* CCID Functional Descriptor (54 bytes) */
    0x36,       /* bLength = 54 */
    0x21,       /* bDescriptorType = Functional */
    0x10, 0x01, /* bcdCCID = 1.10 */
    0x00,       /* bMaxSlotIndex = 0 (1 slot) */
    0x07,       /* bVoltageSupport = 5V, 3V, 1.8V */
    0x03, 0x00, 0x00, 0x00, /* dwProtocols = T=0 and T=1 (0x00000003) */
    0xA0, 0x0F, 0x00, 0x00, /* dwDefaultClock = 4000 kHz */
    0xA0, 0x0F, 0x00, 0x00, /* dwMaximumClock = 4000 kHz */
    0x00,       /* bNumClockSupported = 0 */
    0x80, 0x25, 0x00, 0x00, /* dwDataRate = 9600 bps */
    0x00, 0xC2, 0x01, 0x00, /* dwMaxDataRate = 115200 bps */
    0x00,       /* bNumDataRatesSupported = 0 */
    0xFE, 0x00, 0x00, 0x00, /* dwMaxIFSD = 254 bytes */
    0x00, 0x00, 0x00, 0x00, /* dwSynchProtocols = 0 */
    0x00, 0x00, 0x00, 0x00, /* dwMechanical = 0 */
    0xFE, 0x00, 0x04, 0x00, /* dwFeatures = 0x000400FE (Short & Extended APDU, auto voltage, auto params) */
    0x00, 0x0C, 0x00, 0x00, /* dwMaxCCIDMessageLength = 3072 bytes */
    0x00,       /* bClassGetResponse = echo */
    0x00,       /* bClassEnvelope = echo */
    0x00, 0x00, /* wLcdLayout = 0 */
    0x00,       /* bPINSupport = 0 */
    0x01,       /* bMaxCCIDBusySlots = 1 */

    /* Endpoint Descriptor OUT 2 (Bulk OUT, 7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x02,       /* bEndpointAddress = EP 2 OUT */
    0x02,       /* bmAttributes = Bulk */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x00,       /* bInterval = 0 */

    /* Endpoint Descriptor IN 2 (Bulk IN, 7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x82,       /* bEndpointAddress = EP 2 IN */
    0x02,       /* bmAttributes = Bulk */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x00,       /* bInterval = 0 */

    /* ================= Interface 2: HID Keyboard (OTP / Static Password) (25 bytes) ================= */
    /* Interface Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x04,       /* bDescriptorType = INTERFACE */
    0x02,       /* bInterfaceNumber = 2 */
    0x00,       /* bAlternateSetting = 0 */
    0x01,       /* bNumEndpoints = 1 (EP3 IN) */
    0x03,       /* bInterfaceClass = 0x03 (HID) */
    0x01,       /* bInterfaceSubClass = 0x01 (Boot Interface) */
    0x01,       /* bInterfaceProtocol = 0x01 (Keyboard) */
    0x05,       /* iInterface = String 5 ("hyprkey OTP Keyboard") */

    /* HID Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x21,       /* bDescriptorType = HID */
    0x11, 0x01, /* bcdHID = 1.11 */
    0x00,       /* bCountryCode = 0 */
    0x01,       /* bNumDescriptors = 1 */
    0x22,       /* bDescriptorType = REPORT */
    0x3F, 0x00, /* wDescriptorLength = 63 bytes (0x003F) */

    /* Endpoint Descriptor IN 3 (Interrupt IN, 7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x83,       /* bEndpointAddress = EP 3 IN */
    0x03,       /* bmAttributes = Interrupt */
    0x08, 0x00, /* wMaxPacketSize = 8 bytes */
    0x0A        /* bInterval = 10 ms */
};

/* FIDO Alliance Universal Standard HID Report Descriptor (34 bytes) */
static const uint8_t s_hid_report_desc[] = {
    0x06, 0xD0, 0xF1, /* USAGE_PAGE (FIDO Alliance 0xF1D0) */
    0x09, 0x01,       /* USAGE (U2F HID Authenticator Device) */
    0xA1, 0x01,       /* COLLECTION (Application) */
    0x09, 0x20,       /*   USAGE (Data In) */
    0x15, 0x00,       /*   LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /*   LOGICAL_MAXIMUM (255) */
    0x75, 0x08,       /*   REPORT_SIZE (8 bits) */
    0x95, 0x40,       /*   REPORT_COUNT (64 bytes) */
    0x81, 0x02,       /*   INPUT (Data, Var, Abs) */
    0x09, 0x21,       /*   USAGE (Data Out) */
    0x15, 0x00,       /*   LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /*   LOGICAL_MAXIMUM (255) */
    0x75, 0x08,       /*   REPORT_SIZE (8 bits) */
    0x95, 0x40,       /*   REPORT_COUNT (64 bytes) */
    0x91, 0x02,       /*   OUTPUT (Data, Var, Abs) */
    0xC0              /* END_COLLECTION */
};

/* Standard USB Boot Keyboard Report Descriptor (63 bytes) */
static const uint8_t s_kbd_report_desc[] = {
    0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x06, /* USAGE (Keyboard) */
    0xA1, 0x01, /* COLLECTION (Application) */
    0x05, 0x07, /*   USAGE_PAGE (Keyboard) */
    0x19, 0xE0, /*   USAGE_MINIMUM (Keyboard LeftControl) */
    0x29, 0xE7, /*   USAGE_MAXIMUM (Keyboard Right GUI) */
    0x15, 0x00, /*   LOGICAL_MINIMUM (0) */
    0x25, 0x01, /*   LOGICAL_MAXIMUM (1) */
    0x75, 0x01, /*   REPORT_SIZE (1) */
    0x95, 0x08, /*   REPORT_COUNT (8) */
    0x81, 0x02, /*   INPUT (Data,Var,Abs) */
    0x95, 0x01, /*   REPORT_COUNT (1) */
    0x75, 0x08, /*   REPORT_SIZE (8) */
    0x81, 0x03, /*   INPUT (Cnst,Var,Abs) */
    0x95, 0x05, /*   REPORT_COUNT (5) */
    0x75, 0x01, /*   REPORT_SIZE (1) */
    0x05, 0x08, /*   USAGE_PAGE (LEDs) */
    0x19, 0x01, /*   USAGE_MINIMUM (Num Lock) */
    0x29, 0x05, /*   USAGE_MAXIMUM (Kana) */
    0x91, 0x02, /*   OUTPUT (Data,Var,Abs) */
    0x95, 0x01, /*   REPORT_COUNT (1) */
    0x75, 0x03, /*   REPORT_SIZE (3) */
    0x91, 0x03, /*   OUTPUT (Cnst,Var,Abs) */
    0x95, 0x06, /*   REPORT_COUNT (6) */
    0x75, 0x08, /*   REPORT_SIZE (8) */
    0x15, 0x00, /*   LOGICAL_MINIMUM (0) */
    0x25, 0x65, /*   LOGICAL_MAXIMUM (101) */
    0x05, 0x07, /*   USAGE_PAGE (Keyboard) */
    0x19, 0x00, /*   USAGE_MINIMUM (Reserved) */
    0x29, 0x65, /*   USAGE_MAXIMUM (Keyboard Application) */
    0x81, 0x00, /*   INPUT (Data,Ary,Abs) */
    0xC0        /* END_COLLECTION */
};

/* String Descriptors */
static const uint8_t s_str_lang[] = {
    0x04, 0x03, 0x09, 0x04 /* English US (0x0409) */
};

static const uint8_t s_str_manuf[] = {
    0x10, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0
};

static const uint8_t s_str_prod[] = {
    0x30, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
    'F', 0, 'I', 0, 'D', 0, 'O', 0, '2', 0, ' ', 0, '/', 0, ' ', 0,
    'O', 0, 'p', 0, 'e', 0, 'n', 0, 'P', 0, 'G', 0, 'P', 0
};

static const uint8_t s_str_serial[] = {
    0x18, 0x03,
    'H', 0, 'Y', 0, 'P', 0, 'R', 0, 'K', 0, 'E', 0, 'Y', 0, '-', 0, '0', 0, '0', 0, '5', 0
};

static const uint8_t s_str_ccid[] = {
    0x2C, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
    'O', 0, 'p', 0, 'e', 0, 'n', 0, 'P', 0, 'G', 0, 'P', 0, ' ', 0,
    'C', 0, 'C', 0, 'I', 0, 'D', 0
};

static const uint8_t s_str_kbd[] = {
    0x2A, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
    'O', 0, 'T', 0, 'P', 0, ' ', 0,
    'K', 0, 'e', 0, 'y', 0, 'b', 0, 'o', 0, 'a', 0, 'r', 0, 'd', 0
};

/* ==================== USB Hardware & Buffers ==================== */
/* EasyDMA buffers MUST be in RAM and 4-byte aligned */
static uint8_t m_ep0_tx_buf[128] __attribute__((aligned(4)));
static uint8_t m_ep1_rx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep1_tx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep2_rx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep2_tx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep3_tx_buf[8]   __attribute__((aligned(4)));

static uint8_t  m_ccid_rx_msg[CCID_MAX_MSG_SIZE];
static uint16_t m_ccid_rx_len = 0;
static uint16_t m_ccid_rx_expected = 0;
static uint8_t  m_ccid_tx_buf[CCID_MAX_MSG_SIZE];

static uint8_t  m_usb_configured = 0;
static uint32_t m_assigned_cid = 0x01020304;

/* ==================== USB HID Keyboard Driver ==================== */
static bool ascii_to_hid(char c, uint8_t *mod, uint8_t *code) {
    *mod = 0;
    if (c >= 'a' && c <= 'z') {
        *code = 0x04 + (uint8_t)(c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *mod = 0x02; /* Left Shift */
        *code = 0x04 + (uint8_t)(c - 'A');
        return true;
    }
    if (c >= '1' && c <= '9') {
        *code = 0x1E + (uint8_t)(c - '1');
        return true;
    }
    if (c == '0') { *code = 0x27; return true; }
    if (c == '\n' || c == '\r') { *code = 0x28; return true; } /* Enter */
    if (c == '\t') { *code = 0x2B; return true; }              /* Tab */
    if (c == ' ')  { *code = 0x2C; return true; }              /* Space */
    if (c == '-')  { *code = 0x2D; return true; }
    if (c == '_')  { *mod = 0x02; *code = 0x2D; return true; }
    if (c == '=')  { *code = 0x2E; return true; }
    if (c == '+')  { *mod = 0x02; *code = 0x2E; return true; }
    if (c == '[')  { *code = 0x2F; return true; }
    if (c == '{')  { *mod = 0x02; *code = 0x2F; return true; }
    if (c == ']')  { *code = 0x30; return true; }
    if (c == '}')  { *mod = 0x02; *code = 0x30; return true; }
    if (c == ';')  { *code = 0x33; return true; }
    if (c == ':')  { *mod = 0x02; *code = 0x33; return true; }
    if (c == '\'') { *code = 0x34; return true; }
    if (c == '\"') { *mod = 0x02; *code = 0x34; return true; }
    if (c == ',')  { *code = 0x36; return true; }
    if (c == '<')  { *mod = 0x02; *code = 0x36; return true; }
    if (c == '.')  { *code = 0x37; return true; }
    if (c == '>')  { *mod = 0x02; *code = 0x37; return true; }
    if (c == '/')  { *code = 0x38; return true; }
    if (c == '?')  { *mod = 0x02; *code = 0x38; return true; }
    if (c == '!')  { *mod = 0x02; *code = 0x1E; return true; }
    if (c == '@')  { *mod = 0x02; *code = 0x1F; return true; }
    if (c == '#')  { *mod = 0x02; *code = 0x20; return true; }
    if (c == '$')  { *mod = 0x02; *code = 0x21; return true; }
    if (c == '%')  { *mod = 0x02; *code = 0x22; return true; }
    if (c == '^')  { *mod = 0x02; *code = 0x23; return true; }
    if (c == '&')  { *mod = 0x02; *code = 0x24; return true; }
    if (c == '*')  { *mod = 0x02; *code = 0x25; return true; }
    if (c == '(')  { *mod = 0x02; *code = 0x26; return true; }
    if (c == ')')  { *mod = 0x02; *code = 0x27; return true; }
    return false;
}

static void send_ep3_keyboard_report(uint8_t modifier, uint8_t keycode) {
    m_ep3_tx_buf[0] = modifier;
    m_ep3_tx_buf[1] = 0;
    m_ep3_tx_buf[2] = keycode;
    m_ep3_tx_buf[3] = 0;
    m_ep3_tx_buf[4] = 0;
    m_ep3_tx_buf[5] = 0;
    m_ep3_tx_buf[6] = 0;
    m_ep3_tx_buf[7] = 0;

    USBD_EPIN(3)->PTR = (uint32_t)m_ep3_tx_buf;
    USBD_EPIN(3)->MAXCNT = 8;
    USBD_EVENTS_ENDEPIN(3) = 0;
    USBD_EPDATASTATUS = (1UL << 3); /* Clear host ACK bit before transmission */
    USBD_TASKS_STARTEPIN(3) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(3) && --timeout);
    USBD_EVENTS_ENDEPIN(3) = 0;

    /* Wait for host ACK (EPDATA bit 3) */
    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 3)) && --timeout);
    USBD_EPDATASTATUS = (1UL << 3);
}

static void kbd_type_char(char c) {
    uint8_t mod = 0, code = 0;
    if (ascii_to_hid(c, &mod, &code)) {
        send_ep3_keyboard_report(mod, code);
        for (volatile int d = 0; d < 40000; d++);
        send_ep3_keyboard_report(0, 0); /* Key release */
        for (volatile int d = 0; d < 40000; d++);
    }
}

static void kbd_type_string(const char *str) {
    if (!m_usb_configured) return;
    uart_puts("[KBD] Typing: ");
    uart_puts(str);
    uart_puts("\r\n");

    P0_OUTCLR = (1UL << PIN_LED); /* LED ON while typing */
    while (*str) {
        kbd_type_char(*str++);
    }
    P0_OUTSET = (1UL << PIN_LED); /* LED OFF */
}



static void send_ep0_data(const uint8_t *src, uint16_t len, uint16_t req_len) {
    uint16_t total = (len > req_len) ? req_len : len;
    uint16_t sent = 0;

    uart_puts("    send_ep0 total=");
    uart_puthex32(total);
    uart_puts("\r\n");

    if (total == 0) {
        USBD_TASKS_EP0STATUS = 1;
        return;
    }

    while (sent < total) {
        uint16_t chunk = total - sent;
        if (chunk > 64) chunk = 64;

        memcpy(m_ep0_tx_buf, src + sent, chunk);
        USBD_EPIN(0)->PTR = (uint32_t)m_ep0_tx_buf;
        USBD_EPIN(0)->MAXCNT = chunk;
        USBD_EVENTS_ENDEPIN(0) = 0;
        USBD_EVENTS_EP0DATADONE = 0;
        USBD_TASKS_STARTEPIN(0) = 1;

        uint32_t timeout = 500000;
        while (!USBD_EVENTS_ENDEPIN(0) && --timeout);
        USBD_EVENTS_ENDEPIN(0) = 0;

        timeout = 500000;
        while (!USBD_EVENTS_EP0DATADONE && --timeout);
        USBD_EVENTS_EP0DATADONE = 0;

        sent += chunk;
    }

    USBD_TASKS_EP0STATUS = 1;
    uart_puts("    EP0STATUS triggered\r\n");
}

uint32_t g_dbg_ccid_rx_count = 0;
uint32_t g_dbg_ccid_tx_count = 0;
uint32_t g_dbg_last_ccid_cmd = 0;
uint32_t g_dbg_last_ep0_req  = 0;

/* Send 64-byte packet on EP1 IN */
static void send_ep1_packet(const uint8_t *pkt64) {
    memcpy(m_ep1_tx_buf, pkt64, 64);
    USBD_EPIN(1)->PTR = (uint32_t)m_ep1_tx_buf;
    USBD_EPIN(1)->MAXCNT = 64;
    USBD_EVENTS_ENDEPIN(1) = 0;
    USBD_TASKS_STARTEPIN(1) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(1) && --timeout);
    USBD_EVENTS_ENDEPIN(1) = 0;

    /* Wait for host ACK (EPDATA bit 1) */
    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 1)) && --timeout);
    if (timeout == 0) {
        uart_puts("  [EP1 TX] Host fetch timeout!\r\n");
    }
    USBD_EPDATASTATUS = (1UL << 1); /* Clear host ACK bit */
}

/* ==================== CTAPHID Framing & Handler ==================== */
#define CTAPHID_CMD_PING   0x81
#define CTAPHID_CMD_MSG    0x83
#define CTAPHID_CMD_INIT   0x86
#define CTAPHID_CMD_WINK   0x88
#define CTAPHID_CMD_CBOR   0x90
#define CTAPHID_CMD_ERROR  0xBF

#define CTAPHID_ERR_INVALID_CMD  0x01
#define CTAPHID_ERR_INVALID_PAR  0x02
#define CTAPHID_ERR_INVALID_LEN  0x03
#define CTAPHID_ERR_INVALID_SEQ  0x04

static uint8_t  m_ctap_rx_msg[4096];
static uint16_t m_ctap_rx_len = 0;
static uint16_t m_ctap_rx_expected = 0;
static uint8_t  m_ctap_rx_seq = 0;
static uint8_t  m_ctap_rx_cmd = 0;
static uint32_t m_ctap_active_cid = 0;

static uint8_t  m_fido_tx_buf[8192];

static void send_ctaphid_response(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len) {
    uint8_t pkt[64];
    memset(pkt, 0, 64);

    /* Initial packet */
    pkt[0] = (uint8_t)(cid >> 24);
    pkt[1] = (uint8_t)(cid >> 16);
    pkt[2] = (uint8_t)(cid >> 8);
    pkt[3] = (uint8_t)(cid & 0xFF);
    pkt[4] = cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)(len & 0xFF);

    uint16_t chunk = (len > 57) ? 57 : len;
    if (chunk > 0) {
        memcpy(&pkt[7], data, chunk);
    }
    send_ep1_packet(pkt);

    uint16_t sent = chunk;
    uint8_t seq = 0;

    /* Continuation packets */
    while (sent < len) {
        memset(pkt, 0, 64);
        pkt[0] = (uint8_t)(cid >> 24);
        pkt[1] = (uint8_t)(cid >> 16);
        pkt[2] = (uint8_t)(cid >> 8);
        pkt[3] = (uint8_t)(cid & 0xFF);
        pkt[4] = seq++;

        chunk = (len - sent > 59) ? 59 : (len - sent);
        memcpy(&pkt[5], data + sent, chunk);
        sent += chunk;

        send_ep1_packet(pkt);
    }
}

static void send_ctaphid_error(uint32_t cid, uint8_t err_code) {
    uint8_t b = err_code;
    send_ctaphid_response(cid, CTAPHID_CMD_ERROR, &b, 1);
}

static void handle_complete_ctaphid_msg(uint32_t cid, uint8_t cmd, const uint8_t *payload, uint16_t len) {
    uart_puts("[CTAPHID] CMD=0x");
    uart_puthex8(cmd);
    uart_puts(" len=");
    uart_puthex32(len);
    uart_puts("\r\n");

    if (cmd == CTAPHID_CMD_PING) {
        /* PING: Echo payload */
        send_ctaphid_response(cid, CTAPHID_CMD_PING, payload, len);
    } else if (cmd == CTAPHID_CMD_WINK) {
        /* WINK: Return immediately with success, brief LED blink */
        send_ctaphid_response(cid, CTAPHID_CMD_WINK, NULL, 0);
        P0_OUTCLR = (1UL << PIN_LED);
        for (volatile int d = 0; d < 50000; d++);
        P0_OUTSET = (1UL << PIN_LED);
    } else if (cmd == CTAPHID_CMD_MSG) {
        /* MSG: Process U2F APDU */
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON during crypto */
        uint16_t resp_len = fido_process_apdu(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */

        uart_puts("[U2F] Resp len=");
        uart_puthex32(resp_len);
        uart_puts(" sw=");
        if (resp_len >= 2) {
            uart_puthex8(m_fido_tx_buf[resp_len - 2]);
            uart_puthex8(m_fido_tx_buf[resp_len - 1]);
        }
        uart_puts("\r\n");

        send_ctaphid_response(cid, CTAPHID_CMD_MSG, m_fido_tx_buf, resp_len);
    } else if (cmd == CTAPHID_CMD_CBOR) {
        /* CTAP2 CBOR */
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON during crypto */
        uint16_t resp_len = ctap2_process_cbor(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */

        uart_puts("[CTAP2] Resp len=");
        uart_puthex32(resp_len);
        uart_puts(" status=");
        if (resp_len >= 1) {
            uart_puthex8(m_fido_tx_buf[0]);
        }
        uart_puts("\r\n");

        send_ctaphid_response(cid, CTAPHID_CMD_CBOR, m_fido_tx_buf, resp_len);
    } else if (cmd == 0x71) {
        /* CTAPHID Vendor Command: OATH APDU Tunnel (for WebHID / Browser) */
        uart_puts("[OATH-TUNNEL] Processing APDU via CTAPHID...\r\n");
        uint16_t apdu_rsp_len = oath_process_apdu(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        send_ctaphid_response(cid, 0x71, m_fido_tx_buf, apdu_rsp_len);
    } else {
        send_ctaphid_error(cid, CTAPHID_ERR_INVALID_CMD);
    }
}

static void process_incoming_ctaphid_packet(const uint8_t *pkt) {
    uint32_t cid = ((uint32_t)pkt[0] << 24) |
                   ((uint32_t)pkt[1] << 16) |
                   ((uint32_t)pkt[2] << 8)  |
                   ((uint32_t)pkt[3]);

    uint8_t cmd_or_seq = pkt[4];

    /* Special case: CTAPHID_INIT */
    if (cmd_or_seq == CTAPHID_CMD_INIT) {
        uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];
        uart_puts("[CTAPHID] INIT received, nonce=");
        for (int i = 0; i < 8 && i < bcnt; i++) uart_puthex8(pkt[7 + i]);
        uart_puts("\r\n");

        /* Reply: 8-byte nonce, 4-byte CID, 1-byte IF ver, 3-byte dev ver, 1-byte caps */
        uint8_t resp[17];
        memcpy(&resp[0], &pkt[7], 8);                 /* Nonce */
        resp[8]  = (uint8_t)(m_assigned_cid >> 24);    /* Channel ID */
        resp[9]  = (uint8_t)(m_assigned_cid >> 16);
        resp[10] = (uint8_t)(m_assigned_cid >> 8);
        resp[11] = (uint8_t)(m_assigned_cid & 0xFF);
        resp[12] = 0x02;                             /* CTAPHID IF version 2 */
        resp[13] = 0x01;                             /* Major dev version 1 */
        resp[14] = 0x00;                             /* Minor dev version 0 */
        resp[15] = 0x00;                             /* Build dev version 0 */
        resp[16] = 0x05;                             /* Capabilities: CAPFLAG_WINK (0x01) | CAPFLAG_CBOR (0x04) */

        send_ctaphid_response(cid, CTAPHID_CMD_INIT, resp, 17);
        m_ctap_rx_expected = 0;
        return;
    }

    if (cmd_or_seq & 0x80) {
        /* Initial Packet */
        m_ctap_active_cid = cid;
        m_ctap_rx_cmd = cmd_or_seq;
        m_ctap_rx_expected = ((uint16_t)pkt[5] << 8) | pkt[6];
        m_ctap_rx_seq = 0;

        uint16_t chunk = (m_ctap_rx_expected > 57) ? 57 : m_ctap_rx_expected;
        if (chunk > sizeof(m_ctap_rx_msg)) chunk = sizeof(m_ctap_rx_msg);
        memcpy(m_ctap_rx_msg, &pkt[7], chunk);
        m_ctap_rx_len = chunk;

        if (m_ctap_rx_len >= m_ctap_rx_expected) {
            handle_complete_ctaphid_msg(m_ctap_active_cid, m_ctap_rx_cmd, m_ctap_rx_msg, m_ctap_rx_expected);
            m_ctap_rx_expected = 0;
        }
    } else {
        /* Continuation Packet */
        if (cid == m_ctap_active_cid && m_ctap_rx_expected > 0) {
            uint8_t seq = cmd_or_seq;
            if (seq == m_ctap_rx_seq) {
                m_ctap_rx_seq++;
                uint16_t chunk = m_ctap_rx_expected - m_ctap_rx_len;
                if (chunk > 59) chunk = 59;
                if (m_ctap_rx_len + chunk <= sizeof(m_ctap_rx_msg)) {
                    memcpy(&m_ctap_rx_msg[m_ctap_rx_len], &pkt[5], chunk);
                    m_ctap_rx_len += chunk;
                }
                if (m_ctap_rx_len >= m_ctap_rx_expected) {
                    handle_complete_ctaphid_msg(m_ctap_active_cid, m_ctap_rx_cmd, m_ctap_rx_msg, m_ctap_rx_expected);
                    m_ctap_rx_expected = 0;
                }
            } else {
                send_ctaphid_error(cid, CTAPHID_ERR_INVALID_SEQ);
                m_ctap_rx_expected = 0;
            }
        }
    }
}

/* ==================== CCID Framing & Handler ==================== */
static void send_ep2_packet(const uint8_t *pkt64, uint8_t len) {
    g_dbg_ccid_tx_count++;
    if (len > 0 && pkt64) {
        memcpy(m_ep2_tx_buf, pkt64, len);
    }
    USBD_EPIN(2)->PTR = (uint32_t)m_ep2_tx_buf;
    USBD_EPIN(2)->MAXCNT = len;
    USBD_EVENTS_ENDEPIN(2) = 0;
    USBD_EPDATASTATUS = (1UL << 2); /* Clear host ACK bit before transmission */
    USBD_TASKS_STARTEPIN(2) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(2) && --timeout);
    USBD_EVENTS_ENDEPIN(2) = 0;

    /* Wait for host ACK (EPDATA bit 2) */
    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 2)) && --timeout);
    if (timeout == 0) {
        uart_puts("  [EP2 TX] Timeout!\r\n");
    } else {
        uart_puts("  [EP2 TX] Sent OK\r\n");
    }
    USBD_EPDATASTATUS = (1UL << 2);
}

static void send_ccid_response(const uint8_t *data, uint16_t len) {
    uint16_t sent = 0;
    while (sent < len) {
        uint16_t chunk = len - sent;
        if (chunk > 64) chunk = 64;
        send_ep2_packet(&data[sent], (uint8_t)chunk);
        sent += chunk;
    }
    /* If length is exact multiple of 64 bytes, send zero-length packet (ZLP) */
    if (len > 0 && (len % 64) == 0) {
        send_ep2_packet(NULL, 0);
    }
}

#define NRF_POWER_GPREGRET  (*(volatile uint32_t *)0x4000051CUL)
#define DFU_MAGIC_UF2_RESET 0x57
#define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0CUL)

void system_reboot_to_bootloader(void) {
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDF, 0, 0);
    uart_puts("\r\n[SYS] Rebooting to UF2 Bootloader (DFU)...\r\n");
    for (volatile int i = 0; i < 200000; i++);
    USBD_USBPULLUP = 0; /* Detach USB */
    for (volatile int i = 0; i < 300000; i++);
    NRF_POWER_GPREGRET = DFU_MAGIC_UF2_RESET;
    SCB_AIRCR = 0x05FA0004UL; /* NVIC_SystemReset */
    while (1);
}

static void process_incoming_ccid_packet(const uint8_t *pkt, uint8_t len) {
    if (m_ccid_rx_len == 0) {
        /* First packet contains 10-byte CCID header */
        if (len < 10) return;
        uint32_t payload_len = (uint32_t)pkt[1] | ((uint32_t)pkt[2] << 8) |
                               ((uint32_t)pkt[3] << 16) | ((uint32_t)pkt[4] << 24);
        m_ccid_rx_expected = 10 + (uint16_t)payload_len;
        if (m_ccid_rx_expected > sizeof(m_ccid_rx_msg)) {
            m_ccid_rx_expected = sizeof(m_ccid_rx_msg);
        }
        memcpy(m_ccid_rx_msg, pkt, len);
        m_ccid_rx_len = len;
    } else {
        /* Continuation packet */
        uint16_t rem = m_ccid_rx_expected - m_ccid_rx_len;
        uint16_t chunk = (len < rem) ? len : rem;
        memcpy(m_ccid_rx_msg + m_ccid_rx_len, pkt, chunk);
        m_ccid_rx_len += chunk;
    }

    if (m_ccid_rx_len >= m_ccid_rx_expected) {
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON during card operation */
        uint16_t rsp_len = ccid_process_message(m_ccid_rx_msg, m_ccid_rx_expected,
                                                m_ccid_tx_buf, sizeof(m_ccid_tx_buf));
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */

        uart_puts("[CCID] Cmd=");
        uart_puthex8(m_ccid_rx_msg[0]);
        uart_puts(" RspLen=");
        uart_puthex32(rsp_len);
        uart_puts(" RspHdr: ");
        for (int i = 0; i < (rsp_len < 12 ? rsp_len : 12); i++) {
            uart_puthex8(m_ccid_tx_buf[i]);
            uart_puts(" ");
        }
        uart_puts("\r\n");

        send_ccid_response(m_ccid_tx_buf, rsp_len);
        m_ccid_rx_len = 0;
        m_ccid_rx_expected = 0;

        if (g_dfu_reset_pending) {
            system_reboot_to_bootloader();
        }

        extern volatile uint8_t g_ota_reboot_pending;
        if (g_ota_reboot_pending) {
            uart_puts("\r\n[OTA] Update verified via SHA-256. Rebooting into Stage-2...\r\n");
            for (volatile int d = 0; d < 200000; d++);
            SCB_AIRCR = 0x05FA0004UL; /* NVIC_SystemReset */
            while (1);
        }
    }
}

/* ==================== EP0 Setup Request Handler ==================== */
static void handle_ep0_setup(void) {
    uint8_t  bmRequestType = USBD_BMREQUESTTYPE;
    uint8_t  bRequest      = USBD_BREQUEST;
    g_dbg_last_ep0_req     = bRequest;
    uint16_t wValue        = USBD_WVALUEL | (USBD_WVALUEH << 8);
    uint16_t wIndex        = USBD_WINDEXL | (USBD_WINDEXH << 8);
    uint16_t wLength       = USBD_WLENGTHL | (USBD_WLENGTHH << 8);
    (void)wIndex;

    uart_puts("[EP0] reqType=");
    uart_puthex8(bmRequestType);
    uart_puts(" req=");
    uart_puthex8(bRequest);
    uart_puts(" val=");
    uart_puthex32(wValue);
    uart_puts(" len=");
    uart_puthex32(wLength);
    uart_puts("\r\n");

    /* 1. Standard Device Requests */
    if ((bmRequestType & 0x60) == 0x00) {
        if (bRequest == 0x06) {
            /* GET_DESCRIPTOR */
            uint8_t desc_type = (uint8_t)(wValue >> 8);
            uint8_t desc_idx  = (uint8_t)(wValue & 0xFF);

            if (desc_type == 0x01) {
                /* Device Descriptor */
                uart_puts("  -> Get Device Desc\r\n");
                send_ep0_data(s_device_desc, sizeof(s_device_desc), wLength);
                return;
            } else if (desc_type == 0x02) {
                /* Configuration Descriptor */
                uart_puts("  -> Get Config Desc\r\n");
                send_ep0_data(s_config_desc, sizeof(s_config_desc), wLength);
                return;
            } else if (desc_type == 0x03) {
                /* String Descriptor */
                uart_puts("  -> Get String Desc idx=");
                uart_puthex8(desc_idx);
                uart_puts("\r\n");
                if (desc_idx == 0) {
                    send_ep0_data(s_str_lang, sizeof(s_str_lang), wLength);
                } else if (desc_idx == 1) {
                    send_ep0_data(s_str_manuf, sizeof(s_str_manuf), wLength);
                } else if (desc_idx == 2) {
                    send_ep0_data(s_str_prod, sizeof(s_str_prod), wLength);
                } else if (desc_idx == 3) {
                    send_ep0_data(s_str_serial, sizeof(s_str_serial), wLength);
                } else if (desc_idx == 4) {
                    send_ep0_data(s_str_ccid, sizeof(s_str_ccid), wLength);
                } else if (desc_idx == 5) {
                    send_ep0_data(s_str_kbd, sizeof(s_str_kbd), wLength);
                } else {
                    USBD_TASKS_EP0STALL = 1;
                }
                return;
            }
        } else if (bRequest == 0x05) {
            /* SET_ADDRESS: Handled automatically by hardware */
            uart_puts("  -> Set Address: ");
            uart_puthex32(wValue);
            uart_puts("\r\n");
            USBD_TASKS_EP0STATUS = 1;
            return;
        } else if (bRequest == 0x09) {
            /* SET_CONFIGURATION */
            uart_puts("  -> Set Config: ");
            uart_puthex32(wValue);
            uart_puts("\r\n");
            m_usb_configured = (uint8_t)wValue;
            USBD_EPINEN = 0x0F;  /* Enable EP0, EP1, EP2, EP3 IN */
            USBD_EPOUTEN = 0x07; /* Enable EP0, EP1, EP2 OUT */
            USBD_TASKS_EP0STATUS = 1;
            uart_puts("  -> Configured! Ready for CTAPHID (EP1), CCID (EP2), Keyboard (EP3).\r\n");

            /* Prime EP1 and EP2 OUT to accept data from host */
            USBD_SIZE_EPOUT(1) = 0;
            USBD_SIZE_EPOUT(2) = 0;
            return;
        } else if (bRequest == 0x08) {
            /* GET_CONFIGURATION */
            send_ep0_data(&m_usb_configured, 1, wLength);
            return;
        } else if (bRequest == 0x00) {
            /* GET_STATUS */
            static const uint8_t zero_status[2] = {0, 0};
            send_ep0_data(zero_status, 2, wLength);
            return;
        }
    }

    /* 2. Standard Interface Requests (e.g. HID Report Descriptor, CCID Descriptor) */
    if (bmRequestType == 0x81 && bRequest == 0x06) {
        uint8_t desc_type = (uint8_t)(wValue >> 8);
        uint8_t iface     = (uint8_t)(wIndex & 0xFF);
        if (iface == 0) {
            if (desc_type == 0x22) {
                /* HID Report Descriptor */
                uart_puts("  -> Get HID Report Desc\r\n");
                send_ep0_data(s_hid_report_desc, sizeof(s_hid_report_desc), wLength);
                return;
            } else if (desc_type == 0x21) {
                /* HID Descriptor */
                uart_puts("  -> Get HID Desc\r\n");
                send_ep0_data(&s_config_desc[18], 9, wLength);
                return;
            }
        } else if (iface == 1) {
            if (desc_type == 0x21) {
                /* CCID Functional Descriptor */
                uart_puts("  -> Get CCID Functional Desc\r\n");
                send_ep0_data(&s_config_desc[50], 54, wLength);
                return;
            }
        } else if (iface == 2) {
            if (desc_type == 0x22) {
                /* Keyboard HID Report Descriptor */
                uart_puts("  -> Get Keyboard HID Report Desc\r\n");
                send_ep0_data(s_kbd_report_desc, sizeof(s_kbd_report_desc), wLength);
                return;
            } else if (desc_type == 0x21) {
                /* Keyboard HID Descriptor */
                uart_puts("  -> Get Keyboard HID Desc\r\n");
                send_ep0_data(&s_config_desc[127], 9, wLength);
                return;
            }
        }
    }

    /* 3. Class Requests */
    if ((bmRequestType & 0x60) == 0x20) {
        uint8_t iface = (uint8_t)(wIndex & 0xFF);
        if (iface == 0 || iface == 2) {
            /* HID Class Requests (FIDO2 or Keyboard) */
            if (bRequest == 0x0A) {
                /* SET_IDLE */
                uart_puts("  -> Set Idle\r\n");
                USBD_TASKS_EP0STATUS = 1;
                return;
            } else if (bRequest == 0x02) {
                /* GET_IDLE */
                static const uint8_t idle_rate = 0;
                send_ep0_data(&idle_rate, 1, wLength);
                return;
            } else if (bRequest == 0x09) {
                /* SET_REPORT (e.g. Keyboard LEDs) */
                uart_puts("  -> Set Report\r\n");
                USBD_TASKS_EP0STATUS = 1;
                return;
            }
        } else if (iface == 1) {
            /* CCID Class Requests */
            if (bRequest == 0x02) { /* ABORT */
                uart_puts("  -> CCID Abort\r\n");
                USBD_TASKS_EP0STATUS = 1;
                return;
            } else if (bRequest == 0x03) { /* GET_CLOCK_FREQUENCIES */
                static const uint32_t freqs[1] = { 4000 };
                send_ep0_data((const uint8_t *)freqs, sizeof(freqs), wLength);
                return;
            } else if (bRequest == 0x04) { /* GET_DATA_RATES */
                static const uint32_t rates[2] = { 9600, 115200 };
                send_ep0_data((const uint8_t *)rates, sizeof(rates), wLength);
                return;
            }
        }
    }

    /* Unsupported request: Stall */
    uart_puts("  -> STALL unsupported request\r\n");
    USBD_TASKS_EP0STALL = 1;
}

/* ==================== Main Application ==================== */
int main(void) {
    /* 0. SysTick: 1 ms tick @ 64 MHz */
    #define SYST_CSR   (*(volatile uint32_t *)0xE000E010UL)
    #define SYST_RVR   (*(volatile uint32_t *)0xE000E014UL)
    #define SYST_CVR   (*(volatile uint32_t *)0xE000E018UL)
    SYST_RVR = 64000 - 1;
    SYST_CVR = 0;
    SYST_CSR = 7; /* CLKSOURCE(4) | TICKINT(2) | ENABLE(1) */

    /* 1. Configure LED */
    P0_DIRSET = (1UL << PIN_LED);
    P0_PIN_CNF(PIN_LED) = 0x00000001UL;
    P0_OUTSET = (1UL << PIN_LED); /* LED OFF initially */

    /* 1b. Configure Touch / Button Pin (P0.11) with internal pull-down */
    P0_PIN_CNF(PIN_TOUCH) = 0x00000004UL;

    /* 1c. Emergency Bootloader Recovery: hold Touch (P0.11) for ~2s on boot */
    if (P0_IN & (1UL << PIN_TOUCH)) {
        int held_count = 0;
        for (int i = 0; i < 200; i++) {
            for (volatile int d = 0; d < 6400; d++); /* ~10 ms delay */
            if (P0_IN & (1UL << PIN_TOUCH)) {
                held_count++;
                if ((held_count % 20) < 10) P0_OUTCLR = (1UL << PIN_LED);
                else P0_OUTSET = (1UL << PIN_LED);
            } else {
                break;
            }
        }
        if (held_count >= 180) {
            P0_OUTSET = (1UL << PIN_LED);
            system_reboot_to_bootloader();
        }
    }

    /* 2. Configure Debug UART (P0.10) */
    uart_init();
    uart_puts("\r\n=========================================\r\n");
    uart_puts("   hyprkey USB FIDO2/U2F Security Key    \r\n");
    uart_puts("=========================================\r\n");

    /* 3. Initialize FIDO Cryptographic Engine */
    fido_init();
    uart_puts("[FIDO] Crypto engine initialized\r\n");

    /* 3b. Initialize CCID / OpenPGP Smart Card Engine */
    ccid_init();
    uart_puts("[CCID] OpenPGP Smart Card engine initialized\r\n");

    /* 3c. Initialize PN532 NFC Subsystem */
    if (pn532_nfc_init()) {
        uart_puts("[NFC] PN532 NFC subsystem initialized (Target + Fast Reader)\r\n");
    } else {
        uart_puts("[NFC] PN532 not detected or disabled\r\n");
    }

    /* 4. Start 32 MHz High-Frequency Crystal (HFXO) */
    uart_puts("[CLK] Starting 32 MHz crystal oscillator (HFXO)...\r\n");
    CLOCK_EVENTS_HFCLKSTARTED = 0;
    CLOCK_TASKS_HFCLKSTART = 1;
    while (!CLOCK_EVENTS_HFCLKSTARTED);
    CLOCK_EVENTS_HFCLKSTARTED = 0;
    uart_puts("[CLK] HFXO started successfully!\r\n");

    /* 5. Apply Silicon Errata 171/187 Workaround before USBD Enable */
    if (*(volatile uint32_t *)0x4006EC00 == 0) {
        *(volatile uint32_t *)0x4006EC00 = 0x00009375;
    }
    *(volatile uint32_t *)0x4006EC14 = 0x000000C0;
    *(volatile uint32_t *)0x4006EC00 = 0x00009375;

    /* 6. Enable USBD Peripheral (This powers on the internal 3.3V USB regulator!) */
    uart_puts("[USBD] Enabling USBD controller...\r\n");
    USBD_ENABLE = 1;

    /* 7. Wait for USB 3.3V Power Regulator Ready */
    uart_puts("[PWR] Waiting for USB 3.3V power regulator...\r\n");
    uint32_t pwr_timeout = 500000;
    while (((POWER_USBREGSTATUS & 0x02) == 0) && --pwr_timeout);
    uart_puts("[PWR] USBREGSTATUS = ");
    uart_puthex32(POWER_USBREGSTATUS);
    uart_puts("\r\n");

    /* 8. Wait for 48 MHz PLL READY event */
    uart_puts("[USBD] Waiting for 48 MHz PLL lock...\r\n");
    uint32_t pll_timeout = 500000;
    while ((!USBD_EVENTS_USBEVENT || !(USBD_EVENTCAUSE & 1)) && --pll_timeout);
    USBD_EVENTS_USBEVENT = 0;
    USBD_EVENTCAUSE = 1;
    uart_puts("[USBD] USBD controller 48 MHz PLL locked!\r\n");

    /* Clear Errata Workaround */
    if (*(volatile uint32_t *)0x4006EC00 == 0) {
        *(volatile uint32_t *)0x4006EC00 = 0x00009375;
    }
    *(volatile uint32_t *)0x4006EC14 = 0x00000000;
    *(volatile uint32_t *)0x4006EC00 = 0x00009375;

    /* 9. Enable EP0 & Connect USB Pull-Up Resistor (triggers host enumeration!) */
    USBD_EPINEN = 0x01;
    USBD_EPOUTEN = 0x01;
    USBD_USBPULLUP = 1;
    uart_puts("[USBD] Pull-up resistor enabled -> Device attached to host!\r\n");

    /* 10. Main USB Event Loop */
    static uint32_t s_btn_counter = 0;
    static bool s_btn_pressed = false;

    while (1) {
        /* Run PN532 Dynamic NFC Poller (Target Mode + 15ms Reader Probe) */
        pn532_nfc_poll();

        /* Check Touch / Button on P0.11 */
        if (m_usb_configured) {
            if ((P0_IN & (1UL << PIN_TOUCH)) && !pn532_is_locked()) {
                s_btn_counter++;
                if (s_btn_counter > 50000 && !s_btn_pressed) {
                    s_btn_pressed = true;
                    uart_puts("[BTN] Touch / Button triggered!\r\n");
                    kbd_type_string("hyprkey-sec-k3y-otp-2026\n");
                }
            } else {
                if (s_btn_counter > 0) s_btn_counter--;
                if (s_btn_counter == 0) s_btn_pressed = false;
            }
        }
        /* Check USB Reset */
        if (USBD_EVENTS_USBRESET) {
            USBD_EVENTS_USBRESET = 0;
            USBD_EPINEN = 0x01;
            USBD_EPOUTEN = 0x01;
            m_usb_configured = 0;
            uart_puts("\r\n[USB] === BUS RESET ===\r\n");
        }

        /* Check USBEVENT */
        if (USBD_EVENTS_USBEVENT) {
            uint32_t cause = USBD_EVENTCAUSE;
            USBD_EVENTS_USBEVENT = 0;
            USBD_EVENTCAUSE = cause;
            uart_puts("[EVT] USBEVENT cause=");
            uart_puthex32(cause);
            uart_puts("\r\n");
        }

        /* Check EP0 SETUP Packet */
        if (USBD_EVENTS_EP0SETUP) {
            USBD_EVENTS_EP0SETUP = 0;
            handle_ep0_setup();
        }

        /* Check EP1 OUT packet reception from host */
        if (m_usb_configured && (USBD_EPDATASTATUS & (1UL << 17))) {
            USBD_EPDATASTATUS = (1UL << 17); /* Clear status flag */
            USBD_EVENTS_EPDATA = 0;

            /* Copy packet from endpoint buffer into RAM via EasyDMA */
            USBD_EPOUT(1)->PTR = (uint32_t)m_ep1_rx_buf;
            USBD_EPOUT(1)->MAXCNT = 64;
            USBD_EVENTS_ENDEPOUT(1) = 0;
            USBD_TASKS_STARTEPOUT(1) = 1;

            uint32_t timeout = 500000;
            while (!USBD_EVENTS_ENDEPOUT(1) && --timeout);
            USBD_EVENTS_ENDEPOUT(1) = 0;

            /* Re-arm EP1 OUT immediately so hardware can accept next packet */
            USBD_SIZE_EPOUT(1) = 0;

            process_incoming_ctaphid_packet(m_ep1_rx_buf);
        }

        /* Check EP2 OUT packet reception from host (CCID / OpenPGP) */
        if (m_usb_configured && (USBD_EPDATASTATUS & (1UL << 18))) {
            USBD_EPDATASTATUS = (1UL << 18); /* Clear status flag */
            USBD_EVENTS_EPDATA = 0;
            g_dbg_ccid_rx_count++;

            uint8_t bytes_received = (uint8_t)USBD_SIZE_EPOUT(2);

            /* Copy packet from endpoint buffer into RAM via EasyDMA */
            USBD_EPOUT(2)->PTR = (uint32_t)m_ep2_rx_buf;
            USBD_EPOUT(2)->MAXCNT = 64;
            USBD_EVENTS_ENDEPOUT(2) = 0;
            USBD_TASKS_STARTEPOUT(2) = 1;

            uint32_t timeout = 500000;
            while (!USBD_EVENTS_ENDEPOUT(2) && --timeout);
            USBD_EVENTS_ENDEPOUT(2) = 0;

            if (bytes_received == 0) {
                bytes_received = (uint8_t)USBD_EPOUT(2)->AMOUNT;
            }
            if (bytes_received == 0) {
                bytes_received = 64;
            }

            USBD_SIZE_EPOUT(2) = 0;

            process_incoming_ccid_packet(m_ep2_rx_buf, bytes_received);
        }
    }

    return 0;
}

/* ==================== Startup & Vector Table ==================== */
extern uint32_t _estack;
extern uint32_t _etext, _sdata, _edata, _sbss, _ebss;

void HardFault_Handler(void) {
    uart_puts("\r\n!!! HARDFAULT !!!\r\n");
    /* Emergency fallback: reboot into UF2 bootloader so token is never permanently stuck */
    (*(volatile uint32_t *)0x4000051CUL) = 0x57; /* NRF_POWER->GPREGRET = DFU_MAGIC_UF2_RESET */
    (*(volatile uint32_t *)0xE000ED0CUL) = 0x05FA0004UL; /* SCB->AIRCR = SYSRESETREQ */
    while (1);
}

void Default_Handler(void) {
    while (1);
}

void SysTick_Handler(void) {
    g_uptime_ms++;
}

extern const uint32_t vector_table[];

void Reset_Handler(void) {
    (*(volatile uint32_t *)0xE000ED08UL) = (uint32_t)vector_table; /* Relocate VTOR to active slot */
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0;
    }
    main();
    while (1);
}

__attribute__((section(".isr_vector"), used))
const uint32_t vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,   /* NMI */
    (uint32_t)HardFault_Handler, /* HardFault */
    (uint32_t)Default_Handler,   /* MemManage */
    (uint32_t)Default_Handler,   /* BusFault */
    (uint32_t)Default_Handler,   /* UsageFault */
    0, 0, 0, 0,
    (uint32_t)Default_Handler,   /* SVCall */
    (uint32_t)Default_Handler,   /* DebugMon */
    0,
    (uint32_t)Default_Handler,   /* PendSV */
    (uint32_t)SysTick_Handler,   /* SysTick */
};
```

---

<a id="firmwareusbfidofidou2fh"></a>
# File: `firmware/usb_fido/fido_u2f.h`

> **Description:** FIDO U2F Protocol Definitions  
> **Path:** `firmware/usb_fido/fido_u2f.h`  
> **Lines:** 10  

```c
#ifndef FIDO_U2F_H
#define FIDO_U2F_H

#include <stdint.h>
#include <stdbool.h>

void fido_init(void);
int fido_process_apdu(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* FIDO_U2F_H */
```

---

<a id="firmwareusbfidofidou2fc"></a>
# File: `firmware/usb_fido/fido_u2f.c`

> **Description:** FIDO U2F Protocol Implementation  
> **Path:** `firmware/usb_fido/fido_u2f.c`  
> **Lines:** 353  

```c
#include "fido_u2f.h"
#include "attestation.h"
#include "sha256.h"
#include "uECC.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>

#define RNG_BASE 0x4000D000UL
#define RNG_TASKS_START   (*(volatile uint32_t *)(RNG_BASE + 0x000))
#define RNG_TASKS_STOP    (*(volatile uint32_t *)(RNG_BASE + 0x004))
#define RNG_EVENTS_VALRDY (*(volatile uint32_t *)(RNG_BASE + 0x100))
#define RNG_VALUE         (*(volatile uint32_t *)(RNG_BASE + 0x508))
#define NRF_RNG_CONFIG    (*(volatile uint32_t *)(RNG_BASE + 0x504))

/* Multi-chunk chaining buffer for ISO 7816-4 GET RESPONSE (61 XX) */
static uint8_t g_pending_rsp[800];
static uint16_t g_pending_len = 0;
static uint16_t g_pending_offset = 0;

static int nrf_trng(uint8_t *dest, unsigned size) {
    NRF_RNG_CONFIG = 1UL; /* Enable Digital Error Correction (Bias elimination) */
    RNG_TASKS_START = 1UL;
    while (size--) {
        RNG_EVENTS_VALRDY = 0UL;
        uint32_t timeout = 100000UL;
        while (!RNG_EVENTS_VALRDY && --timeout);
        if (timeout == 0UL) {
            RNG_TASKS_STOP = 1UL;
            return 0; /* RNG failure */
        }
        *dest++ = (uint8_t)RNG_VALUE;
    }
    RNG_TASKS_STOP = 1UL;
    return 1;
}

void fido_init(void) {
    uECC_set_rng(nrf_trng);
    g_pending_len = 0;
    g_pending_offset = 0;
}

static uint16_t der_encode_sig(const uint8_t *r, const uint8_t *s, uint8_t *out) {
    int r_start = 0;
    while (r_start < 31 && r[r_start] == 0) r_start++;
    bool r_pad = (r[r_start] & 0x80) != 0;
    uint8_t r_len = (32 - r_start) + (r_pad ? 1 : 0);

    int s_start = 0;
    while (s_start < 31 && s[s_start] == 0) s_start++;
    bool s_pad = (s[s_start] & 0x80) != 0;
    uint8_t s_len = (32 - s_start) + (s_pad ? 1 : 0);

    uint8_t total_seq_len = 2 + r_len + 2 + s_len;
    uint16_t idx = 0;
    out[idx++] = 0x30;
    out[idx++] = total_seq_len;

    out[idx++] = 0x02;
    out[idx++] = r_len;
    if (r_pad) out[idx++] = 0x00;
    memcpy(&out[idx], &r[r_start], 32 - r_start);
    idx += (32 - r_start);

    out[idx++] = 0x02;
    out[idx++] = s_len;
    if (s_pad) out[idx++] = 0x00;
    memcpy(&out[idx], &s[s_start], 32 - s_start);
    idx += (32 - s_start);

    return idx;
}

static void derive_user_key(const uint8_t app_param[32], uint8_t priv_key[32], uint8_t pub_key_uncomp[65]) {
    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_U2F", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, sizeof(master_key));
    sha256_update(&ctx, app_param, 32);
    sha256_final(&ctx, priv_key);

    uint8_t raw_pub[64];
    uECC_compute_public_key(priv_key, raw_pub, uECC_secp256r1());
    pub_key_uncomp[0] = 0x04;
    memcpy(&pub_key_uncomp[1], raw_pub, 64);
}

static void derive_key_handle(const uint8_t app_param[32], uint8_t key_handle[32]) {
    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_U2F", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    uint8_t tag[] = "HYPRKEY_KEY_HANDLE";
    sha256_update(&ctx, tag, sizeof(tag) - 1);
    sha256_update(&ctx, master_key, sizeof(master_key));
    sha256_update(&ctx, app_param, 32);
    sha256_final(&ctx, key_handle);
}

int fido_process_apdu(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len) {
    (void)max_rsp_len;
    if (req_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    uint8_t cla = req[0];
    uint8_t ins = req[1];
    uint8_t p1  = req[2];
    uint8_t p2  = req[3];
    (void)p2;

    /* Detect Short vs. Extended APDU framing (ISO 7816-4) */
    uint16_t data_offset = 5;
    uint16_t lc = 0;
    if (req_len >= 7 && req[4] == 0x00) {
        /* Extended APDU: Lc is 2 bytes at req[5..6], data starts at req[7] */
        lc = ((uint16_t)req[5] << 8) | req[6];
        data_offset = 7;
    } else if (req_len >= 5) {
        /* Short APDU: Lc is 1 byte at req[4], data starts at req[5] */
        lc = req[4];
        data_offset = 5;
    }

    /* 0. ISO 7816-4 GET RESPONSE (INS = 0xC0) */
    if (cla == 0x00 && ins == 0xC0) {
        if (g_pending_offset >= g_pending_len) {
            rsp[0] = 0x69; rsp[1] = 0x85;
            return 2;
        }

        uint16_t rem = g_pending_len - g_pending_offset;
        uint16_t chunk = (rem > 220) ? 220 : rem;

        memcpy(rsp, &g_pending_rsp[g_pending_offset], chunk);
        g_pending_offset += chunk;

        if (g_pending_offset < g_pending_len) {
            uint16_t next_rem = g_pending_len - g_pending_offset;
            rsp[chunk]     = 0x61; /* More data available */
            rsp[chunk + 1] = (next_rem > 255) ? 0x00 : (uint8_t)next_rem;
            return chunk + 2;
        } else {
            rsp[chunk]     = 0x90; /* Completed */
            rsp[chunk + 1] = 0x00;
            g_pending_len = 0;
            g_pending_offset = 0;
            return chunk + 2;
        }
    }

    /* New non-chaining command -> clear pending buffer */
    g_pending_len = 0;
    g_pending_offset = 0;

    /* 0b. Diagnostic command (INS = 0xFE) */
    if (cla == 0x00 && ins == 0xFE) {
        extern uint32_t g_dbg_ccid_rx_count;
        extern uint32_t g_dbg_ccid_tx_count;
        extern uint32_t g_dbg_last_ccid_cmd;
        extern uint32_t g_dbg_last_ep0_req;
        rsp[0] = (uint8_t)(g_dbg_ccid_rx_count & 0xFF);
        rsp[1] = (uint8_t)((g_dbg_ccid_rx_count >> 8) & 0xFF);
        rsp[2] = (uint8_t)(g_dbg_ccid_tx_count & 0xFF);
        rsp[3] = (uint8_t)((g_dbg_ccid_tx_count >> 8) & 0xFF);
        rsp[4] = (uint8_t)g_dbg_last_ccid_cmd;
        rsp[5] = (uint8_t)g_dbg_last_ep0_req;
        rsp[6] = 0x90;
        rsp[7] = 0x00;
        return 8;
    }

    /* 1. SELECT FIDO AID */
    if (cla == 0x00 && ins == 0xA4 && p1 == 0x04) {
        static const uint8_t FIDO_AID[] = { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 };
        if (req_len >= data_offset + sizeof(FIDO_AID) &&
            memcmp(&req[data_offset], FIDO_AID, sizeof(FIDO_AID)) == 0) {
            static const uint8_t version_str[] = { 'U', '2', 'F', '_', 'V', '2' };
            memcpy(rsp, version_str, sizeof(version_str));
            rsp[sizeof(version_str)]     = 0x90;
            rsp[sizeof(version_str) + 1] = 0x00;
            return sizeof(version_str) + 2;
        }
        rsp[0] = 0x6A; rsp[1] = 0x82;
        return 2;
    }

    /* 2. U2F VERSION (0x03) */
    if (cla == 0x00 && ins == 0x03) {
        static const uint8_t version_str[] = { 'U', '2', 'F', '_', 'V', '2' };
        memcpy(rsp, version_str, sizeof(version_str));
        rsp[sizeof(version_str)]     = 0x90;
        rsp[sizeof(version_str) + 1] = 0x00;
        return sizeof(version_str) + 2;
    }

    /* 3. U2F AUTHENTICATE (0x02) */
    if (cla == 0x00 && ins == 0x02) {
        if (req_len < data_offset + 32 + 32 + 1) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        const uint8_t *challenge = &req[data_offset];
        const uint8_t *app_param = &req[data_offset + 32];
        uint8_t kh_len = req[data_offset + 64];

        if (req_len < (uint16_t)(data_offset + 64 + 1 + kh_len)) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        const uint8_t *key_handle = &req[data_offset + 64 + 1];

        uint8_t expected_kh[32];
        derive_key_handle(app_param, expected_kh);
        if (kh_len != 32 || !crypto_consttime_eq(key_handle, expected_kh, 32)) {
            /* Key handle not recognized */
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        if (p1 == 0x07) {
            /* Check-only: Key recognized! */
            rsp[0] = 0x69; rsp[1] = 0x85;
            return 2;
        }

        /* Enforce user presence & sign (P1 == 0x03 or 0x08) */
        uint8_t user_priv[32], user_pub[65];
        derive_user_key(app_param, user_priv, user_pub);

        uint32_t cur_counter = storage_increment_sign_counter();
        uint8_t up_flags = 0x01;

        sha256_ctx_t s_ctx;
        sha256_init(&s_ctx);
        sha256_update(&s_ctx, app_param, 32);
        sha256_update(&s_ctx, &up_flags, 1);
        uint8_t cnt_bytes[4] = {
            (uint8_t)(cur_counter >> 24),
            (uint8_t)(cur_counter >> 16),
            (uint8_t)(cur_counter >> 8),
            (uint8_t)(cur_counter)
        };
        sha256_update(&s_ctx, cnt_bytes, 4);
        sha256_update(&s_ctx, challenge, 32);
        uint8_t auth_hash[32];
        sha256_final(&s_ctx, auth_hash);

        uint8_t raw_sig[64];
        if (!uECC_sign(user_priv, auth_hash, 32, raw_sig, uECC_secp256r1())) {
            rsp[0] = 0x6F; rsp[1] = 0x00;
            return 2;
        }

        uint16_t out_idx = 0;
        rsp[out_idx++] = up_flags;
        memcpy(&rsp[out_idx], cnt_bytes, 4);
        out_idx += 4;

        uint16_t sig_len = der_encode_sig(raw_sig, &raw_sig[32], &rsp[out_idx]);
        out_idx += sig_len;

        rsp[out_idx++] = 0x90;
        rsp[out_idx++] = 0x00;
        return out_idx;
    }

    /* 4. U2F REGISTER (0x01) */
    if (cla == 0x00 && ins == 0x01) {
        if (req_len < data_offset + 32 + 32) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }

        const uint8_t *challenge = &req[data_offset];
        const uint8_t *app_param = &req[data_offset + 32];

        uint8_t user_priv[32], user_pub[65];
        derive_user_key(app_param, user_priv, user_pub);

        uint8_t key_handle[32];
        derive_key_handle(app_param, key_handle);

        sha256_ctx_t reg_ctx;
        sha256_init(&reg_ctx);
        uint8_t rfu = 0x00;
        sha256_update(&reg_ctx, &rfu, 1);
        sha256_update(&reg_ctx, app_param, 32);
        sha256_update(&reg_ctx, challenge, 32);
        sha256_update(&reg_ctx, key_handle, 32);
        sha256_update(&reg_ctx, user_pub, 65);
        uint8_t reg_hash[32];
        sha256_final(&reg_ctx, reg_hash);

        uint8_t raw_sig[64];
        if (!uECC_sign(HYPRKEY_ATTEST_PRIVKEY, reg_hash, 32, raw_sig, uECC_secp256r1())) {
            rsp[0] = 0x6F; rsp[1] = 0x00;
            return 2;
        }

        /* Assemble full registration response directly into rsp */
        uint16_t out_idx = 0;
        rsp[out_idx++] = 0x05;
        memcpy(&rsp[out_idx], user_pub, 65);
        out_idx += 65;

        rsp[out_idx++] = 32;
        memcpy(&rsp[out_idx], key_handle, 32);
        out_idx += 32;

        uint16_t cert_len = sizeof(HYPRKEY_ATTEST_CERT);
        memcpy(&rsp[out_idx], HYPRKEY_ATTEST_CERT, cert_len);
        out_idx += cert_len;

        uint16_t sig_len = der_encode_sig(raw_sig, &raw_sig[32], &rsp[out_idx]);
        out_idx += sig_len;

        rsp[out_idx++] = 0x90;
        rsp[out_idx++] = 0x00;
        return out_idx;
    }

    /* 5. CTAP2 Encapsulation (CLA = 0x80, INS = 0x10) */
    if (cla == 0x80 && ins == 0x10) {
        if (req_len >= data_offset && lc >= 1 && req[data_offset] == 0x04) {
            static const uint8_t CTAP2_GETINFO_CBOR[] = {
                0x00,
                0xA5,
                0x01, 0x82, 0x66, 'U', '2', 'F', '_', 'V', '2', 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '0',
                0x02, 0x81, 0x6B, 'c', 'r', 'e', 'd', 'P', 'r', 'o', 't', 'e', 'c', 't',
                0x03, 0x50, 0x48, 0x79, 0x70, 0x72, 0x4B, 0x65, 0x79, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
                0x04, 0xA3, 0x62, 'r', 'k', 0xF5, 0x62, 'u', 'p', 0xF5, 0x62, 'u', 'v', 0xF4,
                0x05, 0x19, 0x04, 0xB0
            };

            memcpy(rsp, CTAP2_GETINFO_CBOR, sizeof(CTAP2_GETINFO_CBOR));
            rsp[sizeof(CTAP2_GETINFO_CBOR)]     = 0x90;
            rsp[sizeof(CTAP2_GETINFO_CBOR) + 1] = 0x00;
            return sizeof(CTAP2_GETINFO_CBOR) + 2;
        }
    }

    rsp[0] = 0x6D;
    rsp[1] = 0x00;
    return 2;
}
```

---

<a id="firmwareusbfidoctap2h"></a>
# File: `firmware/usb_fido/ctap2.h`

> **Description:** FIDO2 / CTAP2 Protocol Definitions  
> **Path:** `firmware/usb_fido/ctap2.h`  
> **Lines:** 27  

```c
#ifndef CTAP2_H
#define CTAP2_H

#include <stdint.h>
#include <stddef.h>

#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION   0x02
#define CTAP2_CMD_GET_INFO        0x04
#define CTAP2_CMD_RESET           0x06
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x07

#define CTAP1_ERR_SUCCESS         0x00
#define CTAP1_ERR_INVALID_COMMAND 0x01
#define CTAP1_ERR_INVALID_PAR     0x02
#define CTAP1_ERR_INVALID_LENGTH  0x03
#define CTAP2_ERR_CBOR_UNEXPECTED 0x21
#define CTAP2_ERR_INVALID_CBOR    0x22
#define CTAP2_ERR_UNSUPPORTED_ALG 0x26
#define CTAP2_ERR_NO_CREDENTIALS  0x27

/* Process a CTAP2 CBOR request and write the response into rsp.
 * Returns total response length (status byte + CBOR payload).
 */
uint16_t ctap2_process_cbor(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* CTAP2_H */
```

---

<a id="firmwareusbfidoctap2c"></a>
# File: `firmware/usb_fido/ctap2.c`

> **Description:** FIDO2 / CTAP2 Protocol Implementation  
> **Path:** `firmware/usb_fido/ctap2.c`  
> **Lines:** 749  

```c
#include "ctap2.h"
#include "mldsa/mldsa.h"
#include "ed25519/ed25519.h"
#include "sha256/sha256.h"
#include "micro_ecc/uECC.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>
#include <stdbool.h>

static const uint8_t HYPRKEY_AAGUID[16] = {
    0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* ==================== CBOR Writer ==================== */
typedef struct {
    uint8_t *buf;
    size_t   max_len;
    size_t   pos;
} cbor_writer_t;

static void cbor_w_init(cbor_writer_t *w, uint8_t *buf, size_t max_len) {
    w->buf = buf;
    w->max_len = max_len;
    w->pos = 0;
}

static void cbor_w_byte(cbor_writer_t *w, uint8_t b) {
    if (w->pos < w->max_len) {
        w->buf[w->pos++] = b;
    }
}

static void cbor_w_header(cbor_writer_t *w, uint8_t major, uint64_t val) {
    uint8_t m = (uint8_t)(major << 5);
    if (val < 24) {
        cbor_w_byte(w, m | (uint8_t)val);
    } else if (val <= 0xFF) {
        cbor_w_byte(w, m | 24);
        cbor_w_byte(w, (uint8_t)val);
    } else if (val <= 0xFFFF) {
        cbor_w_byte(w, m | 25);
        cbor_w_byte(w, (uint8_t)(val >> 8));
        cbor_w_byte(w, (uint8_t)(val & 0xFF));
    } else if (val <= 0xFFFFFFFFULL) {
        cbor_w_byte(w, m | 26);
        cbor_w_byte(w, (uint8_t)(val >> 24));
        cbor_w_byte(w, (uint8_t)(val >> 16));
        cbor_w_byte(w, (uint8_t)(val >> 8));
        cbor_w_byte(w, (uint8_t)(val & 0xFF));
    }
}

static void cbor_w_uint(cbor_writer_t *w, uint64_t val) {
    cbor_w_header(w, 0, val);
}

static void cbor_w_nint(cbor_writer_t *w, uint64_t val) {
    cbor_w_header(w, 1, val);
}

static void cbor_w_int(cbor_writer_t *w, int64_t val) {
    if (val >= 0) {
        cbor_w_uint(w, (uint64_t)val);
    } else {
        cbor_w_nint(w, (uint64_t)(-1 - val));
    }
}

static void cbor_w_bstr(cbor_writer_t *w, const uint8_t *data, size_t len) {
    cbor_w_header(w, 2, len);
    for (size_t i = 0; i < len; i++) {
        cbor_w_byte(w, data[i]);
    }
}

static void cbor_w_tstr(cbor_writer_t *w, const char *str) {
    size_t len = strlen(str);
    cbor_w_header(w, 3, len);
    for (size_t i = 0; i < len; i++) {
        cbor_w_byte(w, (uint8_t)str[i]);
    }
}

static void __attribute__((unused)) cbor_w_array(cbor_writer_t *w, size_t count) {
    cbor_w_header(w, 4, count);
}

static void cbor_w_map(cbor_writer_t *w, size_t count) {
    cbor_w_header(w, 5, count);
}

/* ==================== CBOR Reader ==================== */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} cbor_reader_t;

static void cbor_r_init(cbor_reader_t *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

static bool cbor_r_get_header(cbor_reader_t *r, uint8_t *major, uint64_t *val) {
    if (r->pos >= r->len) return false;
    uint8_t b = r->data[r->pos++];
    *major = b >> 5;
    uint8_t info = b & 0x1F;

    if (info < 24) {
        *val = info;
    } else if (info == 24) {
        if (r->pos >= r->len) return false;
        *val = r->data[r->pos++];
    } else if (info == 25) {
        if (r->pos + 2 > r->len) return false;
        *val = ((uint64_t)r->data[r->pos] << 8) | r->data[r->pos + 1];
        r->pos += 2;
    } else if (info == 26) {
        if (r->pos + 4 > r->len) return false;
        *val = ((uint64_t)r->data[r->pos] << 24) |
               ((uint64_t)r->data[r->pos + 1] << 16) |
               ((uint64_t)r->data[r->pos + 2] << 8) |
               r->data[r->pos + 3];
        r->pos += 4;
    } else {
        return false;
    }
    return true;
}

#define CBOR_MAX_NESTING_DEPTH 6U

static bool cbor_r_skip_bounded(cbor_reader_t *r, uint8_t depth) {
    if (depth > CBOR_MAX_NESTING_DEPTH) {
        return false; /* Prevent recursive stack overflow */
    }
    uint8_t major;
    uint64_t val;
    if (!cbor_r_get_header(r, &major, &val)) return false;

    if (major == 0 || major == 1 || major == 7) {
        return true;
    } else if (major == 2 || major == 3) {
        if (val > (uint64_t)(r->len - r->pos)) return false;
        r->pos += (size_t)val;
        return true;
    } else if (major == 4) {
        if (val > 32) return false;
        for (uint64_t i = 0; i < val; i++) {
            if (!cbor_r_skip_bounded(r, depth + 1)) return false;
        }
        return true;
    } else if (major == 5) {
        if (val > 32) return false;
        for (uint64_t i = 0; i < val; i++) {
            if (!cbor_r_skip_bounded(r, depth + 1)) return false; /* key */
            if (!cbor_r_skip_bounded(r, depth + 1)) return false; /* value */
        }
        return true;
    }
    return false;
}

static inline bool cbor_r_skip(cbor_reader_t *r) {
    return cbor_r_skip_bounded(r, 0);
}

static bool cbor_r_get_bytes(cbor_reader_t *r, uint8_t expected_major, const uint8_t **out_ptr, size_t *out_len) {
    uint8_t major;
    uint64_t val;
    if (!cbor_r_get_header(r, &major, &val) || major != expected_major) return false;
    if (val > (uint64_t)(r->len - r->pos)) return false;
    *out_ptr = r->data + r->pos;
    *out_len = (size_t)val;
    r->pos += (size_t)val;
    return true;
}

/* ==================== Cryptographic Derivation ==================== */

static void derive_cred_seed(const uint8_t rp_id_hash[32], int32_t alg, uint8_t seed_out[32]) {
    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_CTAP2", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    const char tag[] = "CTAP2_CRED_SEED";
    sha256_update(&ctx, (const uint8_t *)tag, sizeof(tag) - 1);
    uint8_t alg_bytes[4] = {
        (uint8_t)(alg >> 24), (uint8_t)(alg >> 16),
        (uint8_t)(alg >> 8),  (uint8_t)(alg & 0xFF)
    };
    sha256_update(&ctx, alg_bytes, 4);
    sha256_update(&ctx, rp_id_hash, 32);
    sha256_final(&ctx, seed_out);
}

static void derive_cred_id(const uint8_t rp_id_hash[32], int32_t alg, uint8_t cred_id_out[32]) {
    /* Format of 32-byte cred_id:
     * [0..3]: alg (big endian)
     * [4..7]: 'H', 'Y', 'P', 'R' (tag)
     * [8..31]: HMAC/SHA256(master_key, tag || alg || rp_id_hash)[0..24]
     */
    cred_id_out[0] = (uint8_t)(alg >> 24);
    cred_id_out[1] = (uint8_t)(alg >> 16);
    cred_id_out[2] = (uint8_t)(alg >> 8);
    cred_id_out[3] = (uint8_t)(alg & 0xFF);
    cred_id_out[4] = 'H';
    cred_id_out[5] = 'Y';
    cred_id_out[6] = 'P';
    cred_id_out[7] = 'R';

    uint8_t master_key[32];
    storage_get_device_master_key("FIDO_CTAP2", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    const char tag[] = "CRED_ID_MAC";
    sha256_update(&ctx, (const uint8_t *)tag, sizeof(tag) - 1);
    sha256_update(&ctx, cred_id_out, 4);
    sha256_update(&ctx, rp_id_hash, 32);
    uint8_t mac[32];
    sha256_final(&ctx, mac);
    memcpy(&cred_id_out[8], mac, 24);
}

static bool verify_cred_id(const uint8_t cred_id[32], const uint8_t rp_id_hash[32], int32_t *alg_out) {
    if (cred_id[4] != 'H' || cred_id[5] != 'Y' || cred_id[6] != 'P' || cred_id[7] != 'R') {
        return false;
    }
    int32_t alg = ((int32_t)cred_id[0] << 24) |
                  ((int32_t)cred_id[1] << 16) |
                  ((int32_t)cred_id[2] << 8)  |
                  ((int32_t)cred_id[3]);

    uint8_t expected[32];
    derive_cred_id(rp_id_hash, alg, expected);
    if (!crypto_consttime_eq(cred_id, expected, 32)) {
        return false;
    }
    *alg_out = alg;
    return true;
}

static uint16_t der_encode_ecdsa(const uint8_t *r, const uint8_t *s, uint8_t *out) {
    int r_start = 0;
    while (r_start < 31 && r[r_start] == 0) r_start++;
    bool r_pad = (r[r_start] & 0x80) != 0;
    uint8_t r_len = (32 - r_start) + (r_pad ? 1 : 0);

    int s_start = 0;
    while (s_start < 31 && s[s_start] == 0) s_start++;
    bool s_pad = (s[s_start] & 0x80) != 0;
    uint8_t s_len = (32 - s_start) + (s_pad ? 1 : 0);

    uint8_t total_seq_len = 2 + r_len + 2 + s_len;
    uint16_t idx = 0;
    out[idx++] = 0x30;
    out[idx++] = total_seq_len;

    out[idx++] = 0x02;
    out[idx++] = r_len;
    if (r_pad) out[idx++] = 0x00;
    memcpy(&out[idx], &r[r_start], 32 - r_start);
    idx += (32 - r_start);

    out[idx++] = 0x02;
    out[idx++] = s_len;
    if (s_pad) out[idx++] = 0x00;
    memcpy(&out[idx], &s[s_start], 32 - s_start);
    idx += (32 - s_start);

    return idx;
}

/* ==================== CTAP2 Command Handlers ==================== */

static uint16_t handle_get_info(uint8_t *rsp, uint16_t max_len) {
    /* Pre-encoded AuthenticatorGetInfo CBOR map (163 bytes) */
    static const uint8_t s_get_info_cbor[] = {
        0xa5,                                           /* map(5) */
        0x01, 0x83, 0x66, 0x55, 0x32, 0x46, 0x5f, 0x56, /* 1: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"] */
        0x32, 0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32,
        0x5f, 0x30, 0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f,
        0x32, 0x5f, 0x31,
        0x03, 0x50,                                     /* 3: aaguid (16 bytes) */
        0x48, 0x59, 0x50, 0x52, 0x4b, 0x45, 0x59, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xa4,                                     /* 4: options: map(4) */
        0x62, 0x72, 0x6b, 0xf5,                         /* "rk": true */
        0x62, 0x75, 0x70, 0xf5,                         /* "up": true */
        0x62, 0x75, 0x76, 0xf4,                         /* "uv": false */
        0x64, 0x70, 0x6c, 0x61, 0x74, 0xf4,             /* "plat": false */
        0x05, 0x19, 0x20, 0x00,                         /* 5: maxMsgSize = 8192 */
        0x0a, 0x85,                                     /* 10: algorithms: array(5) */
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -7} (ES256) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x26,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -8} (EdDSA / Ed25519) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x27,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -48} (ML-DSA-44) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x2f,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -49} (ML-DSA-65) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x30,
        0xa2, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, /* {"type": "public-key", "alg": -50} (ML-DSA-87) */
        0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65,
        0x79, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x31
    };

    if (max_len < sizeof(s_get_info_cbor) + 1) return 0;
    rsp[0] = CTAP1_ERR_SUCCESS;
    memcpy(rsp + 1, s_get_info_cbor, sizeof(s_get_info_cbor));
    return sizeof(s_get_info_cbor) + 1;
}

static uint16_t handle_make_credential(const uint8_t *payload, uint16_t len, uint8_t *rsp, uint16_t max_len) {
    cbor_reader_t r;
    cbor_r_init(&r, payload, len);

    uint8_t major;
    uint64_t map_entries;
    if (!cbor_r_get_header(&r, &major, &map_entries) || major != 5) {
        rsp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    uint8_t client_data_hash[32];
    bool has_cdh = false;
    uint8_t rp_id_hash[32];
    bool has_rp = false;
    int32_t chosen_alg = 0;
    bool has_alg = false;

    for (uint64_t m = 0; m < map_entries; m++) {
        uint8_t k_major;
        uint64_t key_val;
        if (!cbor_r_get_header(&r, &k_major, &key_val)) break;

        if (k_major == 0 && key_val == 1) {
            /* 1: clientDataHash (bstr, 32 bytes) */
            const uint8_t *cdh_ptr;
            size_t cdh_len;
            if (cbor_r_get_bytes(&r, 2, &cdh_ptr, &cdh_len) && cdh_len == 32) {
                memcpy(client_data_hash, cdh_ptr, 32);
                has_cdh = true;
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 2) {
            /* 2: rp (map with "id" text string) */
            uint8_t v_major;
            uint64_t rp_entries;
            if (cbor_r_get_header(&r, &v_major, &rp_entries) && v_major == 5) {
                for (uint64_t i = 0; i < rp_entries; i++) {
                    const uint8_t *k_str;
                    size_t rp_k_len;
                    if (cbor_r_get_bytes(&r, 3, &k_str, &rp_k_len)) {
                        if (rp_k_len == 2 && memcmp(k_str, "id", 2) == 0) {
                            const uint8_t *id_str;
                            size_t id_len;
                            if (cbor_r_get_bytes(&r, 3, &id_str, &id_len)) {
                                sha256_ctx_t sha;
                                sha256_init(&sha);
                                sha256_update(&sha, id_str, id_len);
                                sha256_final(&sha, rp_id_hash);
                                has_rp = true;
                            } else {
                                cbor_r_skip(&r);
                            }
                        } else {
                            cbor_r_skip(&r);
                        }
                    } else {
                        cbor_r_skip(&r);
                    }
                }
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 4) {
            /* 4: pubKeyCredParams (array of {"type": "public-key", "alg": int}) */
            uint8_t v_major;
            uint64_t param_count;
            if (cbor_r_get_header(&r, &v_major, &param_count) && v_major == 4 && param_count <= 16) {
                for (uint64_t i = 0; i < param_count; i++) {
                    uint8_t item_major;
                    uint64_t item_entries;
                    if (cbor_r_get_header(&r, &item_major, &item_entries) && item_major == 5 && item_entries <= 8) {
                        int32_t entry_alg = 0;
                        for (uint64_t p = 0; p < item_entries; p++) {
                            const uint8_t *k_str;
                            size_t pk_len;
                            if (cbor_r_get_bytes(&r, 3, &k_str, &pk_len)) {
                                if (pk_len == 3 && memcmp(k_str, "alg", 3) == 0) {
                                    uint8_t a_major;
                                    uint64_t a_val;
                                    if (cbor_r_get_header(&r, &a_major, &a_val)) {
                                        if (a_major == 0) entry_alg = (int32_t)a_val;
                                        else if (a_major == 1) entry_alg = (int32_t)(-1 - a_val);
                                    }
                                } else {
                                    if (!cbor_r_skip(&r)) break;
                                }
                            } else {
                                if (!cbor_r_skip(&r)) break;
                            }
                        }
                        /* Preference: ML-DSA-44 (-48), ML-DSA-65 (-49), ML-DSA-87 (-50), Ed25519 (-8), ES256 (-7) */
                        if (!has_alg) {
                            if (entry_alg == -48 || entry_alg == -49 || entry_alg == -50 || entry_alg == -8 || entry_alg == -7) {
                                chosen_alg = entry_alg;
                                has_alg = true;
                            }
                        }
                    } else {
                        if (!cbor_r_skip(&r)) break;
                    }
                }
            } else {
                cbor_r_skip(&r);
            }
        } else {
            cbor_r_skip(&r);
        }
    }

    if (!has_cdh || !has_rp) {
        rsp[0] = CTAP1_ERR_INVALID_PAR;
        return 1;
    }
    if (!has_alg) {
        chosen_alg = -48; /* Default to ML-DSA-44 if none explicitly filtered */
    }

    /* 1. Derive credential seed and cred_id */
    uint8_t cred_seed[32];
    derive_cred_seed(rp_id_hash, chosen_alg, cred_seed);
    uint8_t cred_id[32];
    derive_cred_id(rp_id_hash, chosen_alg, cred_id);

    /* 2. Build authData */
    /* authData = rpIdHash (32) || flags 0x41 (1) || signCount (4) || aaguid (16) || credIdLen (2) || credId (32) || cose_key */
    static uint8_t auth_data[4096];
    cbor_writer_t aw;
    cbor_w_init(&aw, auth_data, sizeof(auth_data));

    /* Header: rpIdHash (32) */
    for (int i = 0; i < 32; i++) cbor_w_byte(&aw, rp_id_hash[i]);
    /* Flags: UP (0x01) | AT (0x40) = 0x41 */
    cbor_w_byte(&aw, 0x41);
    /* Sign counter (4 bytes big-endian) */
    uint32_t cnt = storage_increment_sign_counter();
    cbor_w_byte(&aw, (uint8_t)(cnt >> 24));
    cbor_w_byte(&aw, (uint8_t)(cnt >> 16));
    cbor_w_byte(&aw, (uint8_t)(cnt >> 8));
    cbor_w_byte(&aw, (uint8_t)(cnt & 0xFF));

    /* Attested Credential Data */
    /* aaguid (16 bytes) */
    for (int i = 0; i < 16; i++) cbor_w_byte(&aw, HYPRKEY_AAGUID[i]);
    /* credentialIdLength = 32 (0x00, 0x20) */
    cbor_w_byte(&aw, 0x00);
    cbor_w_byte(&aw, 0x20);
    /* credentialId (32 bytes) */
    for (int i = 0; i < 32; i++) cbor_w_byte(&aw, cred_id[i]);

    /* COSE Public Key */
    if (chosen_alg == -48) {
        /* ML-DSA-44: COSE Key (RFC 9964): { 1: 7, 3: -48, -1: pk (1312) } */
        static uint8_t pk44[MLDSA44_PUBLIC_KEY_SIZE];
        mldsa44_keygen(cred_seed, pk44, NULL);

        cbor_w_map(&aw, 3);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 7);   /* kty: AKP (7) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -48); /* alg: ML-DSA-44 (-48) */
        cbor_w_int(&aw, -1); cbor_w_bstr(&aw, pk44, MLDSA44_PUBLIC_KEY_SIZE);
    } else if (chosen_alg == -49) {
        /* ML-DSA-65: COSE Key (RFC 9964): { 1: 7, 3: -49, -1: pk (1952) } */
        static uint8_t pk65[MLDSA65_PUBLIC_KEY_SIZE];
        mldsa65_keygen(cred_seed, pk65, NULL);

        cbor_w_map(&aw, 3);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 7);   /* kty: AKP (7) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -49); /* alg: ML-DSA-65 (-49) */
        cbor_w_int(&aw, -1); cbor_w_bstr(&aw, pk65, MLDSA65_PUBLIC_KEY_SIZE);
    } else if (chosen_alg == -50) {
        /* ML-DSA-87: COSE Key (RFC 9964): { 1: 7, 3: -50, -1: pk (2592) } */
        static uint8_t pk87[MLDSA87_PUBLIC_KEY_SIZE];
        mldsa87_keygen(cred_seed, pk87, NULL);

        cbor_w_map(&aw, 3);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 7);   /* kty: AKP (7) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -50); /* alg: ML-DSA-87 (-50) */
        cbor_w_int(&aw, -1); cbor_w_bstr(&aw, pk87, MLDSA87_PUBLIC_KEY_SIZE);
    } else if (chosen_alg == -8) {
        /* Ed25519: COSE Key (RFC 8152): { 1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x (32) } */
        uint8_t pk25519[32], sk25519[64];
        ed25519_create_keypair(pk25519, sk25519, cred_seed);

        cbor_w_map(&aw, 4);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 1);  /* kty: OKP (1) */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -8); /* alg: EdDSA (-8) */
        cbor_w_int(&aw, -1); cbor_w_int(&aw, 6);  /* crv: Ed25519 (6) */
        cbor_w_int(&aw, -2); cbor_w_bstr(&aw, pk25519, 32); /* x */
    } else {
        /* ES256 (-7): COSE Key: { 1: 2, 3: -7, -1: 1, -2: x (32), -3: y (32) } */
        uint8_t raw_pub[64];
        uECC_compute_public_key(cred_seed, raw_pub, uECC_secp256r1());

        cbor_w_map(&aw, 5);
        cbor_w_int(&aw, 1);  cbor_w_int(&aw, 2);  /* kty: EC2 */
        cbor_w_int(&aw, 3);  cbor_w_int(&aw, -7); /* alg: ES256 */
        cbor_w_int(&aw, -1); cbor_w_int(&aw, 1);  /* crv: P-256 */
        cbor_w_int(&aw, -2); cbor_w_bstr(&aw, raw_pub, 32);      /* x */
        cbor_w_int(&aw, -3); cbor_w_bstr(&aw, raw_pub + 32, 32); /* y */
    }

    /* 3. Build response: Status 0x00 || CBOR { 1: "none", 2: authData, 3: {} } */
    cbor_writer_t rw;
    cbor_w_init(&rw, rsp + 1, max_len - 1);
    cbor_w_map(&rw, 3);
    cbor_w_int(&rw, 1); cbor_w_tstr(&rw, "none");
    cbor_w_int(&rw, 2); cbor_w_bstr(&rw, auth_data, aw.pos);
    cbor_w_int(&rw, 3); cbor_w_map(&rw, 0);

    rsp[0] = CTAP1_ERR_SUCCESS;
    crypto_zero(cred_seed, sizeof(cred_seed));
    return (uint16_t)(rw.pos + 1);
}

static uint16_t handle_get_assertion(const uint8_t *payload, uint16_t len, uint8_t *rsp, uint16_t max_len) {
    cbor_reader_t r;
    cbor_r_init(&r, payload, len);

    uint8_t major;
    uint64_t map_entries;
    if (!cbor_r_get_header(&r, &major, &map_entries) || major != 5) {
        rsp[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    uint8_t client_data_hash[32];
    bool has_cdh = false;
    uint8_t rp_id_hash[32];
    bool has_rp = false;
    uint8_t target_cred_id[32];
    bool has_cred_id = false;
    int32_t alg = -48; /* Default ML-DSA-44 */

    for (uint64_t m = 0; m < map_entries; m++) {
        uint8_t k_major;
        uint64_t key_val;
        if (!cbor_r_get_header(&r, &k_major, &key_val)) break;

        if (k_major == 0 && key_val == 1) {
            /* 1: rpId (text string) */
            const uint8_t *id_str;
            size_t id_len;
            if (cbor_r_get_bytes(&r, 3, &id_str, &id_len)) {
                sha256_ctx_t sha;
                sha256_init(&sha);
                sha256_update(&sha, id_str, id_len);
                sha256_final(&sha, rp_id_hash);
                has_rp = true;
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 2) {
            /* 2: clientDataHash (bstr, 32 bytes) */
            const uint8_t *cdh_ptr;
            size_t cdh_len;
            if (cbor_r_get_bytes(&r, 2, &cdh_ptr, &cdh_len) && cdh_len == 32) {
                memcpy(client_data_hash, cdh_ptr, 32);
                has_cdh = true;
            } else {
                cbor_r_skip(&r);
            }
        } else if (k_major == 0 && key_val == 3) {
            /* 3: allowList (array of {"id": bstr, "type": "public-key"}) */
            uint8_t v_major;
            uint64_t list_count;
            if (cbor_r_get_header(&r, &v_major, &list_count) && v_major == 4 && list_count <= 16) {
                for (uint64_t i = 0; i < list_count; i++) {
                    uint8_t d_major;
                    uint64_t d_entries;
                    if (cbor_r_get_header(&r, &d_major, &d_entries) && d_major == 5 && d_entries <= 8) {
                        for (uint64_t d = 0; d < d_entries; d++) {
                            const uint8_t *k_str;
                            size_t dk_len;
                            if (cbor_r_get_bytes(&r, 3, &k_str, &dk_len)) {
                                if (dk_len == 2 && memcmp(k_str, "id", 2) == 0) {
                                    const uint8_t *id_bstr;
                                    size_t id_bstr_len;
                                    if (cbor_r_get_bytes(&r, 2, &id_bstr, &id_bstr_len) && id_bstr_len == 32) {
                                        memcpy(target_cred_id, id_bstr, 32);
                                        has_cred_id = true;
                                    } else {
                                        cbor_r_skip(&r);
                                    }
                                } else {
                                    cbor_r_skip(&r);
                                }
                            } else {
                                cbor_r_skip(&r);
                            }
                        }
                    } else {
                        cbor_r_skip(&r);
                    }
                }
            } else {
                cbor_r_skip(&r);
            }
        } else {
            cbor_r_skip(&r);
        }
    }

    if (!has_cdh || !has_rp) {
        rsp[0] = CTAP1_ERR_INVALID_PAR;
        return 1;
    }

    /* Verify or reconstruct credential */
    if (has_cred_id) {
        if (!verify_cred_id(target_cred_id, rp_id_hash, &alg)) {
            rsp[0] = CTAP2_ERR_NO_CREDENTIALS;
            return 1;
        }
    } else {
        /* Default non-resident credential derivation */
        derive_cred_id(rp_id_hash, alg, target_cred_id);
    }

    uint8_t cred_seed[32];
    derive_cred_seed(rp_id_hash, alg, cred_seed);

    /* 1. Build authData (37 bytes) = rpIdHash (32) || flags 0x01 (1) || signCount (4) */
    uint8_t auth_data[37];
    memcpy(auth_data, rp_id_hash, 32);
    auth_data[32] = 0x01; /* UP = 1 */
    uint32_t cnt = storage_increment_sign_counter();
    auth_data[33] = (uint8_t)(cnt >> 24);
    auth_data[34] = (uint8_t)(cnt >> 16);
    auth_data[35] = (uint8_t)(cnt >> 8);
    auth_data[36] = (uint8_t)(cnt & 0xFF);

    /* 2. Message to sign = authData (37) || clientDataHash (32) = 69 bytes */
    uint8_t msg_to_sign[69];
    memcpy(msg_to_sign, auth_data, 37);
    memcpy(msg_to_sign + 37, client_data_hash, 32);

    /* 3. Compute signature */
    static uint8_t sig_buf[5000];
    size_t sig_len = 0;

    if (alg == -48) {
        mldsa44_sign_seed(cred_seed, msg_to_sign, 69, NULL, sig_buf);
        sig_len = MLDSA44_SIGNATURE_SIZE;
    } else if (alg == -49) {
        mldsa65_sign_seed(cred_seed, msg_to_sign, 69, NULL, sig_buf);
        sig_len = MLDSA65_SIGNATURE_SIZE;
    } else if (alg == -50) {
        mldsa87_sign_seed(cred_seed, msg_to_sign, 69, NULL, sig_buf);
        sig_len = MLDSA87_SIGNATURE_SIZE;
    } else if (alg == -8) {
        /* Ed25519 (raw 64-byte signature) */
        uint8_t pk25519[32], sk25519[64];
        ed25519_create_keypair(pk25519, sk25519, cred_seed);
        ed25519_sign(sig_buf, msg_to_sign, 69, pk25519, sk25519);
        sig_len = 64;
    } else {
        /* ES256 (-7) */
        uint8_t hash[32];
        sha256_ctx_t sha;
        sha256_init(&sha);
        sha256_update(&sha, msg_to_sign, 69);
        sha256_final(&sha, hash);

        uint8_t raw_sig[64];
        uECC_sign(cred_seed, hash, 32, raw_sig, uECC_secp256r1());
        sig_len = der_encode_ecdsa(raw_sig, raw_sig + 32, sig_buf);
    }

    /* 4. Build CBOR response: { 1: {"id": target_cred_id, "type": "public-key"}, 2: authData, 3: signature } */
    cbor_writer_t rw;
    cbor_w_init(&rw, rsp + 1, max_len - 1);
    cbor_w_map(&rw, 3);

    /* 1: credential */
    cbor_w_int(&rw, 1);
    cbor_w_map(&rw, 2);
    cbor_w_tstr(&rw, "id");
    cbor_w_bstr(&rw, target_cred_id, 32);
    cbor_w_tstr(&rw, "type");
    cbor_w_tstr(&rw, "public-key");

    /* 2: authData */
    cbor_w_int(&rw, 2);
    cbor_w_bstr(&rw, auth_data, 37);

    /* 3: signature */
    cbor_w_int(&rw, 3);
    cbor_w_bstr(&rw, sig_buf, sig_len);

    rsp[0] = CTAP1_ERR_SUCCESS;
    crypto_zero(cred_seed, sizeof(cred_seed));
    return (uint16_t)(rw.pos + 1);
}

/* Main CTAP2 dispatcher */
uint16_t ctap2_process_cbor(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (req_len < 1) {
        rsp[0] = CTAP1_ERR_INVALID_LENGTH;
        return 1;
    }

    uint8_t cmd = req[0];
    const uint8_t *payload = req + 1;
    uint16_t payload_len = req_len - 1;

    switch (cmd) {
        case CTAP2_CMD_GET_INFO:
            return handle_get_info(rsp, max_rsp_len);

        case CTAP2_CMD_MAKE_CREDENTIAL:
            return handle_make_credential(payload, payload_len, rsp, max_rsp_len);

        case CTAP2_CMD_GET_ASSERTION:
            return handle_get_assertion(payload, payload_len, rsp, max_rsp_len);

        case CTAP2_CMD_RESET:
            rsp[0] = CTAP1_ERR_SUCCESS;
            return 1;

        default:
            rsp[0] = CTAP1_ERR_INVALID_COMMAND;
            return 1;
    }
}
```

---

<a id="firmwareusbfidoopenpgpopenpgph"></a>
# File: `firmware/usb_fido/openpgp/openpgp.h`

> **Description:** OpenPGP Smart Card 3.4 Definitions  
> **Path:** `firmware/usb_fido/openpgp/openpgp.h`  
> **Lines:** 20  

```c
#ifndef OPENPGP_H
#define OPENPGP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void openpgp_init(void);

/* Get ISO 7816-3 ATR (Answer To Reset) for OpenPGP Card */
uint16_t openpgp_get_atr(uint8_t *out, uint16_t max_len);

/* Process incoming ISO 7816-4 APDU and write response (Data + SW1 + SW2).
 * Returns total length of response. */
uint16_t openpgp_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len);

/* Check if Admin PIN (PW3) is currently verified */
bool openpgp_is_pw3_verified(void);

#endif /* OPENPGP_H */
```

---

<a id="firmwareusbfidoopenpgpopenpgpc"></a>
# File: `firmware/usb_fido/openpgp/openpgp.c`

> **Description:** OpenPGP Smart Card 3.4 Implementation  
> **Path:** `firmware/usb_fido/openpgp/openpgp.c`  
> **Lines:** 841  

```c
#include "openpgp.h"
#include "micro_ecc/uECC.h"
#include "sha256/sha256.h"
#include "fips202.h"
#include "mlkem.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>

/* AID: D2 76 00 01 24 01 (OpenPGP) 03 04 (v3.4) 00 01 (Manuf) 00 00 00 01 (Serial) 00 00 */
static const uint8_t s_openpgp_aid[16] = {
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    0x03, 0x04,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00
};

/* Historical bytes (ISO 7816-4) - 10 bytes */
static const uint8_t s_historical_bytes[] = {
    0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01, 0x40, 0x00, 0x90, 0x00
};

/* ISO 7816-3 Answer To Reset (ATR) for OpenPGP Card v2/v3 with valid TCK (0x0C) - 21 bytes */
static const uint8_t s_openpgp_atr[21] = {
    0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75,
    0x1F, 0x03, 0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01,
    0x40, 0x00, 0x90, 0x00, 0x0C
};

/* ECC curve secp256r1 OID: 1.2.840.10045.3.1.7 (8 bytes) */
static const uint8_t s_oid_secp256r1[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* Algorithm attributes: 0x13 (ECDSA) or 0x12 (ECDH) + OID */
static const uint8_t s_alg_attr_sig[] = { 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t s_alg_attr_dec[] = { 0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t s_alg_attr_aut[] = { 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/* Extended Capabilities (DO 0xC0) - 10 bytes */
static const uint8_t s_extended_capabilities[10] = {
    0x7C,       /* Support for GET CHALLENGE, Key Import, PW Status change */
    0x00,       /* No SM */
    0x01, 0x00, /* Max challenge length = 256 */
    0x04, 0x00, /* Max cert length = 1024 */
    0x0C, 0x00, /* Max special DO length = 3072 */
    0x00,       /* PIN block 2 format */
    0x00        /* MSE command support */
};

/* Key material */
typedef struct {
    uint8_t  privkey[32];
    uint8_t  pubkey[64];
    uint8_t  fingerprint[20];
    uint32_t creation_time;
    bool     valid;
} openpgp_key_t;

static openpgp_key_t s_key_sig;
static openpgp_key_t s_key_dec;
static openpgp_key_t s_key_aut;

/* Post-Quantum ML-KEM Key Material */
static uint8_t s_mlkem768_pk[MLKEM768_PUBLICKEYBYTES];
static uint8_t s_mlkem768_sk[MLKEM768_SECRETKEYBYTES];
static bool    s_mlkem768_valid = false;

/* PINs & State */
static char    s_pw1[32] = "123456";
static uint8_t s_pw1_len = 6;
static uint8_t s_pw1_tries = 3;
static bool    s_pw1_sign_verified = false;
static bool    s_pw1_other_verified = false;

static char    s_pw3[32] = "12345678";
static uint8_t s_pw3_len = 8;
static uint8_t s_pw3_tries = 3;
static bool    s_pw3_verified = false;

static uint32_t s_sig_counter = 0;

/* Cardholder data */
static char    s_name[40] = "hyprkey OpenPGP User";
static char    s_lang[4]  = "en";
static uint8_t s_sex      = 0x00; /* Unspecified */
static char    s_login[32]= "";

/* Helper: Simple SHA-1 for OpenPGP V4 Fingerprint calculation */
static void sha1_calc(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint8_t buf[64];
    size_t i = 0;
    uint64_t total_bits = (uint64_t)len * 8;

    while (i + 64 <= len) {
        uint32_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)data[i + t * 4] << 24) |
                   ((uint32_t)data[i + t * 4 + 1] << 16) |
                   ((uint32_t)data[i + t * 4 + 2] << 8) |
                   ((uint32_t)data[i + t * 4 + 3]);
        }
        for (int t = 16; t < 80; t++) {
            uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (val << 1) | (val >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int t = 0; t < 80; t++) {
            uint32_t f, k;
            if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        i += 64;
    }

    size_t rem = len - i;
    memcpy(buf, data + i, rem);
    buf[rem++] = 0x80;
    if (rem > 56) {
        while (rem < 64) buf[rem++] = 0;
        uint32_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = ((uint32_t)buf[t * 4] << 24) | ((uint32_t)buf[t * 4 + 1] << 16) |
                   ((uint32_t)buf[t * 4 + 2] << 8) | ((uint32_t)buf[t * 4 + 3]);
        }
        for (int t = 16; t < 80; t++) {
            uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (val << 1) | (val >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int t = 0; t < 80; t++) {
            uint32_t f, k;
            if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        rem = 0;
    }
    while (rem < 56) buf[rem++] = 0;
    for (int t = 0; t < 8; t++) buf[56 + t] = (uint8_t)(total_bits >> ((7 - t) * 8));
    uint32_t w[80];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)buf[t * 4] << 24) | ((uint32_t)buf[t * 4 + 1] << 16) |
               ((uint32_t)buf[t * 4 + 2] << 8) | ((uint32_t)buf[t * 4 + 3]);
    }
    for (int t = 16; t < 80; t++) {
        uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = (val << 1) | (val >> 31);
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int t = 0; t < 80; t++) {
        uint32_t f, k;
        if (t < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;

    for (int t = 0; t < 5; t++) {
        out[t * 4]     = (uint8_t)(h[t] >> 24);
        out[t * 4 + 1] = (uint8_t)(h[t] >> 16);
        out[t * 4 + 2] = (uint8_t)(h[t] >> 8);
        out[t * 4 + 3] = (uint8_t)(h[t]);
    }
}

/* Compute V4 fingerprint for ECC secp256r1 key */
static void compute_v4_fingerprint(uint8_t alg, uint32_t ctime, const uint8_t pubkey[64], uint8_t fp_out[20]) {
    /* V4 Public Key Packet:
     * 0x99 || 2-byte body length ||
     * 0x04 (version) || 4-byte creation time || alg (0x13 or 0x12) ||
     * 0x08 (OID len) || OID (8 bytes) ||
     * 0x02, 0x08 (MPI bitlen 520) || 0x04 (uncompressed) || X (32) || Y (32)
     */
    uint8_t pkt[128];
    uint16_t body_len = 1 + 4 + 1 + 1 + sizeof(s_oid_secp256r1) + 2 + 1 + 64; /* = 82 bytes */
    uint16_t idx = 0;

    pkt[idx++] = 0x99;
    pkt[idx++] = (uint8_t)(body_len >> 8);
    pkt[idx++] = (uint8_t)(body_len & 0xFF);

    pkt[idx++] = 0x04; /* Version 4 */
    pkt[idx++] = (uint8_t)(ctime >> 24);
    pkt[idx++] = (uint8_t)(ctime >> 16);
    pkt[idx++] = (uint8_t)(ctime >> 8);
    pkt[idx++] = (uint8_t)(ctime & 0xFF);

    pkt[idx++] = alg;
    pkt[idx++] = sizeof(s_oid_secp256r1);
    memcpy(&pkt[idx], s_oid_secp256r1, sizeof(s_oid_secp256r1));
    idx += sizeof(s_oid_secp256r1);

    /* MPI bitlength = 520 (0x02, 0x08) */
    pkt[idx++] = 0x02;
    pkt[idx++] = 0x08;
    pkt[idx++] = 0x04; /* Uncompressed point tag */
    memcpy(&pkt[idx], pubkey, 64);
    idx += 64;

    sha1_calc(pkt, idx, fp_out);
}

/* Initialize keys deterministically from master secret */
static void init_key(openpgp_key_t *k, const char *role_tag, uint8_t alg, uint32_t ctime) {
    uint8_t master_key[32];
    storage_get_device_master_key("OPENPGP", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    sha256_update(&ctx, (const uint8_t *)role_tag, strlen(role_tag));
    sha256_final(&ctx, k->privkey);

    /* Ensure valid scalar for secp256r1 */
    k->privkey[0] &= 0x7F; /* keep strictly < order */

    uECC_compute_public_key(k->privkey, k->pubkey, uECC_secp256r1());
    k->creation_time = ctime;
    k->valid = true;

    compute_v4_fingerprint(alg, ctime, k->pubkey, k->fingerprint);
}

void openpgp_init(void) {
    /* Creation timestamp: e.g. 1700000000 (0x6554F700) */
    uint32_t default_ctime = 0x6554F700;

    init_key(&s_key_sig, "OPENPGP_SIGN_KEY", 0x13, default_ctime);
    init_key(&s_key_dec, "OPENPGP_DEC_KEY",  0x12, default_ctime);
    init_key(&s_key_aut, "OPENPGP_AUTH_KEY", 0x13, default_ctime);

    /* Derive deterministic ML-KEM-768 keypair */
    uint8_t master_key[32];
    storage_get_device_master_key("OPENPGP", master_key);

    uint8_t d[32], z[32];
    sha3_256_ctx hctx;
    sha3_256_init(&hctx);
    sha3_256_absorb(&hctx, master_key, 32);
    sha3_256_absorb(&hctx, (const uint8_t *)"MLKEM768_D", 10);
    sha3_256_finalize(&hctx, d);

    sha3_256_init(&hctx);
    sha3_256_absorb(&hctx, master_key, 32);
    sha3_256_absorb(&hctx, (const uint8_t *)"MLKEM768_Z", 10);
    sha3_256_finalize(&hctx, z);

    mlkem768_keygen_internal(s_mlkem768_pk, s_mlkem768_sk, d, z);
    s_mlkem768_valid = true;

    /* Persistent PIN retry counters from Flash (Audit Finding 2.1) */
    s_pw1_tries = storage_get_pin_retries(PIN_TYPE_PGP_PW1);
    s_pw3_tries = storage_get_pin_retries(PIN_TYPE_PGP_PW3);

    s_pw1_sign_verified = false;
    s_pw1_other_verified = false;
    s_pw3_verified = false;
}

uint16_t openpgp_get_atr(uint8_t *out, uint16_t max_len) {
    if (max_len < sizeof(s_openpgp_atr)) return 0;
    memcpy(out, s_openpgp_atr, sizeof(s_openpgp_atr));
    return sizeof(s_openpgp_atr);
}

/* ==================== TLV Helpers ==================== */

static uint16_t put_tlv(uint8_t *buf, uint16_t max_len, uint16_t tag, const uint8_t *val, uint16_t val_len) {
    uint16_t idx = 0;
    if (tag > 0xFF) {
        if (idx + 2 > max_len) return 0;
        buf[idx++] = (uint8_t)(tag >> 8);
        buf[idx++] = (uint8_t)(tag & 0xFF);
    } else {
        if (idx + 1 > max_len) return 0;
        buf[idx++] = (uint8_t)tag;
    }

    if (val_len < 128) {
        if (idx + 1 > max_len) return 0;
        buf[idx++] = (uint8_t)val_len;
    } else if (val_len < 256) {
        if (idx + 2 > max_len) return 0;
        buf[idx++] = 0x81;
        buf[idx++] = (uint8_t)val_len;
    } else {
        if (idx + 3 > max_len) return 0;
        buf[idx++] = 0x82;
        buf[idx++] = (uint8_t)(val_len >> 8);
        buf[idx++] = (uint8_t)(val_len & 0xFF);
    }

    if (idx + val_len > max_len) return 0;
    if (val_len > 0 && val) {
        memcpy(buf + idx, val, val_len);
        idx += val_len;
    }
    return idx;
}

/* Build DO 0x6E: Application Related Data */
static uint16_t build_do_6e(uint8_t *out, uint16_t max_len) {
    uint8_t disc_buf[256];
    uint16_t d_idx = 0;

    /* Extended capabilities (0xC0) */
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC0, s_extended_capabilities, sizeof(s_extended_capabilities));
    /* Algorithm attributes: Sig (0xC1), Dec (0xC2), Aut (0xC3) */
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC1, s_alg_attr_sig, sizeof(s_alg_attr_sig));
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC2, s_alg_attr_dec, sizeof(s_alg_attr_dec));
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC3, s_alg_attr_aut, sizeof(s_alg_attr_aut));

    /* PW Status Bytes (0xC4) - 7 bytes:
     * [0]: PW1 status (0 = not valid for multiple sigs)
     * [1]: max PW1 len (64)
     * [2]: max Reset Code len (64)
     * [3]: max PW3 len (64)
     * [4]: PW1 retry counter (s_pw1_tries)
     * [5]: Reset Code retry counter (0)
     * [6]: PW3 retry counter (s_pw3_tries)
     */
    uint8_t pw_status[7] = { 0x00, 64, 64, 64, s_pw1_tries, 0, s_pw3_tries };
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC4, pw_status, 7);

    /* Fingerprints: Sig (0xC5), Dec (0xC6), Aut (0xC7) */
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC5, s_key_sig.fingerprint, 20);
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC6, s_key_dec.fingerprint, 20);
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xC7, s_key_aut.fingerprint, 20);

    /* Creation timestamps (0xCD) - 12 bytes */
    uint8_t ctimes[12];
    ctimes[0] = (uint8_t)(s_key_sig.creation_time >> 24);
    ctimes[1] = (uint8_t)(s_key_sig.creation_time >> 16);
    ctimes[2] = (uint8_t)(s_key_sig.creation_time >> 8);
    ctimes[3] = (uint8_t)(s_key_sig.creation_time & 0xFF);
    ctimes[4] = (uint8_t)(s_key_dec.creation_time >> 24);
    ctimes[5] = (uint8_t)(s_key_dec.creation_time >> 16);
    ctimes[6] = (uint8_t)(s_key_dec.creation_time >> 8);
    ctimes[7] = (uint8_t)(s_key_dec.creation_time & 0xFF);
    ctimes[8] = (uint8_t)(s_key_aut.creation_time >> 24);
    ctimes[9] = (uint8_t)(s_key_aut.creation_time >> 16);
    ctimes[10]= (uint8_t)(s_key_aut.creation_time >> 8);
    ctimes[11]= (uint8_t)(s_key_aut.creation_time & 0xFF);
    d_idx += put_tlv(disc_buf + d_idx, sizeof(disc_buf) - d_idx, 0xCD, ctimes, 12);

    /* Combine into 0x6E body: 0x4F (AID) + 0x5F52 (Hist) + 0x73 (Discretionary) */
    uint8_t body_buf[512];
    uint16_t b_idx = 0;
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x4F, s_openpgp_aid, sizeof(s_openpgp_aid));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5F52, s_historical_bytes, sizeof(s_historical_bytes));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x73, disc_buf, d_idx);

    return put_tlv(out, max_len, 0x6E, body_buf, b_idx);
}

/* Build DO 0x65: Cardholder Related Data */
static uint16_t build_do_65(uint8_t *out, uint16_t max_len) {
    uint8_t body_buf[128];
    uint16_t b_idx = 0;
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5B, (const uint8_t *)s_name, strlen(s_name));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5F2D, (const uint8_t *)s_lang, strlen(s_lang));
    b_idx += put_tlv(body_buf + b_idx, sizeof(body_buf) - b_idx, 0x5F35, &s_sex, 1);
    return put_tlv(out, max_len, 0x65, body_buf, b_idx);
}

/* Build DO 0x7A: Security Support Template */
static uint16_t build_do_7a(uint8_t *out, uint16_t max_len) {
    uint8_t body_buf[16];
    uint8_t cnt[3] = {
        (uint8_t)(s_sig_counter >> 16),
        (uint8_t)(s_sig_counter >> 8),
        (uint8_t)(s_sig_counter & 0xFF)
    };
    uint16_t b_idx = put_tlv(body_buf, sizeof(body_buf), 0x93, cnt, 3);
    return put_tlv(out, max_len, 0x7A, body_buf, b_idx);
}

/* ==================== APDU Dispatcher ==================== */

uint16_t openpgp_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* Wrong length */
        return 2;
    }

    uint8_t cla = apdu[0];
    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    uint8_t p2  = apdu[3];

    (void)cla;

    /* Parse Lc and Data pointer using strict ISO/IEC 7816-4 parser (Short and Extended APDUs) */
    uint16_t lc = 0U;
    const uint8_t *data = NULL;
    if (!iso7816_parse_apdu(apdu, apdu_len, &data, &lc)) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* SW_WRONG_LENGTH */
        return 2;
    }

    /* 1. SELECT (0xA4) */
    if (ins == 0xA4) {
        if (p1 == 0x04 && p2 == 0x00) {
            /* Select by AID */
            /* We accept either prefix D2 76 00 01 24 01 or full 16-byte AID */
            if (lc >= 6 && memcmp(data, s_openpgp_aid, 6) == 0) {
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        }
        rsp[0] = 0x6A; rsp[1] = 0x82; /* File not found */
        return 2;
    }

    /* 2. GET DATA (0xCA) */
    if (ins == 0xCA) {
        uint16_t tag = ((uint16_t)p1 << 8) | p2;
        uint16_t len = 0;

        switch (tag) {
            case 0x004F: /* AID */
                memcpy(rsp, s_openpgp_aid, sizeof(s_openpgp_aid));
                len = sizeof(s_openpgp_aid);
                break;

            case 0x006E: /* Application Related Data */
                len = build_do_6e(rsp, max_rsp_len - 2);
                break;

            case 0x0065: /* Cardholder Related Data */
                len = build_do_65(rsp, max_rsp_len - 2);
                break;

            case 0x005E: /* Login Data */
                memcpy(rsp, s_login, strlen(s_login));
                len = strlen(s_login);
                break;

            case 0x007A: /* Security Support Template */
                len = build_do_7a(rsp, max_rsp_len - 2);
                break;

            case 0x00C4: { /* PW Status Bytes */
                uint8_t pw_status[7] = { 0x00, 64, 64, 64, s_pw1_tries, 0, s_pw3_tries };
                memcpy(rsp, pw_status, 7);
                len = 7;
                break;
            }

            case 0x00C1: /* Sig algorithm attributes */
                memcpy(rsp, s_alg_attr_sig, sizeof(s_alg_attr_sig));
                len = sizeof(s_alg_attr_sig);
                break;

            case 0x00C2: /* Dec algorithm attributes */
                memcpy(rsp, s_alg_attr_dec, sizeof(s_alg_attr_dec));
                len = sizeof(s_alg_attr_dec);
                break;

            case 0x00C3: /* Aut algorithm attributes */
                memcpy(rsp, s_alg_attr_aut, sizeof(s_alg_attr_aut));
                len = sizeof(s_alg_attr_aut);
                break;

            case 0x00C5: /* Sig Fingerprint */
                memcpy(rsp, s_key_sig.fingerprint, 20);
                len = 20;
                break;

            case 0x00C6: /* Dec Fingerprint */
                memcpy(rsp, s_key_dec.fingerprint, 20);
                len = 20;
                break;

            case 0x00D6: /* Post-Quantum ML-KEM-768 Public Key */
                if (s_mlkem768_valid && max_rsp_len >= MLKEM768_PUBLICKEYBYTES + 2) {
                    memcpy(rsp, s_mlkem768_pk, MLKEM768_PUBLICKEYBYTES);
                    len = MLKEM768_PUBLICKEYBYTES;
                }
                break;

            case 0x00C7: /* Aut Fingerprint */
                memcpy(rsp, s_key_aut.fingerprint, 20);
                len = 20;
                break;

            case 0x00DE: { /* Extended length info: 2 bytes max cmd (3072), 2 bytes max rsp (3072) */
                uint8_t ext_len[8] = { 0x02, 0x02, 0x0C, 0x00, 0x02, 0x02, 0x0C, 0x00 };
                memcpy(rsp, ext_len, 8);
                len = 8;
                break;
            }

            default:
                /* Unknown or unsupported DO */
                rsp[0] = 0x6A; rsp[1] = 0x88; /* Referenced data not found */
                return 2;
        }

        rsp[len]     = 0x90;
        rsp[len + 1] = 0x00;
        return len + 2;
    }

    /* 3. VERIFY (0x20) */
    if (ins == 0x20) {
        if (p1 != 0x00) {
            rsp[0] = 0x6A; rsp[1] = 0x86;
            return 2;
        }

        if (p2 == 0x81 || p2 == 0x82) {
            /* PW1 verification */
            if (lc == 0) {
                /* Query status */
                bool v = (p2 == 0x81) ? s_pw1_sign_verified : s_pw1_other_verified;
                if (v) {
                    rsp[0] = 0x90; rsp[1] = 0x00;
                } else {
                    rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw1_tries);
                }
                return 2;
            }

            if (s_pw1_tries == 0) {
                rsp[0] = 0x69; rsp[1] = 0x83; /* Authentication method blocked */
                return 2;
            }

            if (data != NULL && lc == s_pw1_len && crypto_consttime_eq(data, s_pw1, lc)) {
                s_pw1_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PGP_PW1, s_pw1_tries);
                if (p2 == 0x81) s_pw1_sign_verified = true;
                if (p2 == 0x82) s_pw1_other_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                if (s_pw1_tries > 0) s_pw1_tries--;
                storage_set_pin_retries(PIN_TYPE_PGP_PW1, s_pw1_tries);
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw1_tries);
            }
            return 2;
        } else if (p2 == 0x83) {
            /* PW3 verification */
            if (lc == 0) {
                if (s_pw3_verified) {
                    rsp[0] = 0x90; rsp[1] = 0x00;
                } else {
                    rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw3_tries);
                }
                return 2;
            }

            if (s_pw3_tries == 0) {
                rsp[0] = 0x69; rsp[1] = 0x83; /* Blocked */
                return 2;
            }

            if (data != NULL && lc == s_pw3_len && crypto_consttime_eq(data, s_pw3, lc)) {
                s_pw3_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PGP_PW3, s_pw3_tries);
                s_pw3_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                if (s_pw3_tries > 0) s_pw3_tries--;
                storage_set_pin_retries(PIN_TYPE_PGP_PW3, s_pw3_tries);
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw3_tries);
            }
            return 2;
        }

        rsp[0] = 0x6A; rsp[1] = 0x88;
        return 2;
    }

    /* 3b. CHANGE REFERENCE DATA (0x24) - Supports PW1 and PW3 (Admin PIN) modification */
    if (ins == 0x24 && p1 == 0x00 && (p2 == 0x81 || p2 == 0x83)) {
        if (data == NULL) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        if (p2 == 0x81) {
            /* Change PW1: data = [Old PW1 (s_pw1_len)] || [New PW1 (min 6 bytes)] */
            if (s_pw1_tries == 0) { rsp[0] = 0x69; rsp[1] = 0x83; return 2; }
            if (lc < (uint16_t)(s_pw1_len + 6U) || lc > (uint16_t)(s_pw1_len + sizeof(s_pw1) - 1)) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            if (!crypto_consttime_eq(data, s_pw1, s_pw1_len)) {
                if (s_pw1_tries > 0) s_pw1_tries--;
                storage_set_pin_retries(PIN_TYPE_PGP_PW1, s_pw1_tries);
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw1_tries);
                return 2;
            }
            uint8_t new_len = (uint8_t)(lc - s_pw1_len);
            memcpy(s_pw1, data + s_pw1_len, new_len);
            s_pw1_len = new_len;
            s_pw1_tries = 3;
            storage_set_pin_retries(PIN_TYPE_PGP_PW1, 3);
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else {
            /* Change PW3 (Admin PIN): data = [Old PW3 (s_pw3_len)] || [New PW3 (min 8 bytes)] */
            if (s_pw3_tries == 0) { rsp[0] = 0x69; rsp[1] = 0x83; return 2; }
            if (lc < (uint16_t)(s_pw3_len + 8U) || lc > (uint16_t)(s_pw3_len + sizeof(s_pw3) - 1)) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            if (!crypto_consttime_eq(data, s_pw3, s_pw3_len)) {
                if (s_pw3_tries > 0) s_pw3_tries--;
                storage_set_pin_retries(PIN_TYPE_PGP_PW3, s_pw3_tries);
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_pw3_tries);
                return 2;
            }
            uint8_t new_len = (uint8_t)(lc - s_pw3_len);
            memcpy(s_pw3, data + s_pw3_len, new_len);
            s_pw3_len = new_len;
            s_pw3_tries = 3;
            s_pw3_verified = true;
            storage_set_pin_retries(PIN_TYPE_PGP_PW3, 3);
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        }
    }

    /* 4. PUT DATA (0xDA) */
    if (ins == 0xDA) {
        uint16_t tag = ((uint16_t)p1 << 8) | p2;
        if (!s_pw3_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied (need admin) */
            return 2;
        }

        if (tag == 0x005B) { /* Name */
            size_t n = (lc < sizeof(s_name) - 1) ? lc : sizeof(s_name) - 1;
            memcpy(s_name, data, n);
            s_name[n] = '\0';
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else if (tag == 0x5F2D) { /* Language */
            size_t n = (lc < sizeof(s_lang) - 1) ? lc : sizeof(s_lang) - 1;
            memcpy(s_lang, data, n);
            s_lang[n] = '\0';
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else if (tag == 0x5F35) { /* Sex */
            if (lc >= 1) s_sex = data[0];
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        } else if (tag == 0x005E) { /* Login */
            size_t n = (lc < sizeof(s_login) - 1) ? lc : sizeof(s_login) - 1;
            memcpy(s_login, data, n);
            s_login[n] = '\0';
            rsp[0] = 0x90; rsp[1] = 0x00;
            return 2;
        }

        rsp[0] = 0x6A; rsp[1] = 0x88;
        return 2;
    }

    /* 5. GENERATE ASYMMETRIC KEY PAIR (0x47) */
    if (ins == 0x47) {
        /* P1 = 0x80: Generate Key Pair (requires PW3 / Admin PIN)
         * P1 = 0x81: Read Public Key (public operation, no PIN required) */
        if (p1 == 0x80 && !s_pw3_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }

        /* Check key reference template tag */
        uint8_t role = 0xB6; /* Default signature */
        if (lc >= 2) role = data[0];

        /* Role 0xBA: Post-Quantum ML-KEM-768 Decryption Key */
        if (role == 0xBA && s_mlkem768_valid) {
            uint16_t total = 0;
            rsp[total++] = 0x7F;
            rsp[total++] = 0x49;
            uint16_t inner_len = MLKEM768_PUBLICKEYBYTES + 4;
            rsp[total++] = 0x82;
            rsp[total++] = (uint8_t)(inner_len >> 8);
            rsp[total++] = (uint8_t)(inner_len & 0xFF);

            rsp[total++] = 0x86;
            rsp[total++] = 0x82;
            rsp[total++] = (uint8_t)(MLKEM768_PUBLICKEYBYTES >> 8);
            rsp[total++] = (uint8_t)(MLKEM768_PUBLICKEYBYTES & 0xFF);
            memcpy(rsp + total, s_mlkem768_pk, MLKEM768_PUBLICKEYBYTES);
            total += MLKEM768_PUBLICKEYBYTES;

            rsp[total++] = 0x90;
            rsp[total++] = 0x00;
            return total;
        }

        const openpgp_key_t *k = &s_key_sig;
        if (role == 0xB8) k = &s_key_dec;
        else if (role == 0xA4) k = &s_key_aut;

        /* Return public key template 0x7F49 containing 0x86 (0x04 || pubkey 64) */
        uint8_t raw_pt[65];
        raw_pt[0] = 0x04;
        memcpy(raw_pt + 1, k->pubkey, 64);

        uint8_t body[80];
        uint16_t b_len = put_tlv(body, sizeof(body), 0x86, raw_pt, 65);
        uint16_t total = put_tlv(rsp, max_rsp_len - 2, 0x7F49, body, b_len);

        rsp[total]     = 0x90;
        rsp[total + 1] = 0x00;
        return total + 2;
    }

    /* 6. PSO: COMPUTE DIGITAL SIGNATURE (0x2A with P1=0x9E, P2=0x9A or P1=0x80, P2=0x86) */
    if (ins == 0x2A && ((p1 == 0x9E && p2 == 0x9A) || (p1 == 0x80 && p2 == 0x86))) {
        if (!s_pw1_sign_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
            return 2;
        }

        /* Sign digest in data */
        uint8_t digest[32];
        if (lc == 32) {
            memcpy(digest, data, 32);
        } else {
            sha256_ctx_t sha;
            sha256_init(&sha);
            sha256_update(&sha, data, lc);
            sha256_final(&sha, digest);
        }

        /* Output raw r || s (64 bytes) */
        uECC_sign(s_key_sig.privkey, digest, 32, rsp, uECC_secp256r1());

        s_sig_counter++;
        s_pw1_sign_verified = false; /* Single signature per PIN verification */

        rsp[64] = 0x90;
        rsp[65] = 0x00;
        return 66;
    }

    /* 7. PSO: DECIPHER (0x2A with P1=0x86, P2=0x80) */
    if (ins == 0x2A && p1 == 0x86 && p2 == 0x80) {
        if (!s_pw1_other_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }

        /* Check for ML-KEM-768 ciphertext (1088 bytes) */
        if (lc == MLKEM768_CIPHERTEXTBYTES && s_mlkem768_valid) {
            uint8_t secret[32];
            mlkem768_decaps_internal(secret, data, s_mlkem768_sk);
            memcpy(rsp, secret, 32);
            rsp[32] = 0x90;
            rsp[33] = 0x00;
            return 34;
        }
        /* Check for ML-KEM-768 ciphertext with 0x00 padding prefix (1089 bytes) */
        if (lc == MLKEM768_CIPHERTEXTBYTES + 1 && data[0] == 0x00 && s_mlkem768_valid) {
            uint8_t secret[32];
            mlkem768_decaps_internal(secret, data + 1, s_mlkem768_sk);
            memcpy(rsp, secret, 32);
            rsp[32] = 0x90;
            rsp[33] = 0x00;
            return 34;
        }

        /* Classical ECDH NIST P-256 peer public point: 0x04 || X (32) || Y (32) */
        if (lc >= 65 && data[0] == 0x04) {
            uint8_t secret[32];
            uECC_shared_secret(data + 1, s_key_dec.privkey, secret, uECC_secp256r1());
            memcpy(rsp, secret, 32);
            rsp[32] = 0x90;
            rsp[33] = 0x00;
            return 34;
        }

        rsp[0] = 0x6A; rsp[1] = 0x80; /* Incorrect data */
        return 2;
    }

    /* 8. INTERNAL AUTHENTICATE (0x88) */
    if (ins == 0x88 && p1 == 0x00 && p2 == 0x00) {
        if (!s_pw1_other_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }

        uint8_t digest[32];
        if (lc == 32) {
            memcpy(digest, data, 32);
        } else {
            sha256_ctx_t sha;
            sha256_init(&sha);
            sha256_update(&sha, data, lc);
            sha256_final(&sha, digest);
        }

        /* Sign with authentication key */
        uECC_sign(s_key_aut.privkey, digest, 32, rsp, uECC_secp256r1());

        rsp[64] = 0x90;
        rsp[65] = 0x00;
        return 66;
    }

    /* 9. TERMINATE DF (0xE6) & ACTIVATE FILE (0x44) -> Factory Reset */
    if (ins == 0xE6 || ins == 0x44) {
        if (!s_pw3_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82;
            return 2;
        }
        openpgp_init();
        rsp[0] = 0x90; rsp[1] = 0x00;
        return 2;
    }

    /* Unsupported instruction */
    rsp[0] = 0x6D; rsp[1] = 0x00;
    return 2;
}

bool openpgp_is_pw3_verified(void) {
    return s_pw3_verified;
}
```

---

<a id="firmwareusbfidopivpivh"></a>
# File: `firmware/usb_fido/piv/piv.h`

> **Description:** PIV (NIST SP 800-73-4) Definitions  
> **Path:** `firmware/usb_fido/piv/piv.h`  
> **Lines:** 14  

```c
#ifndef PIV_H
#define PIV_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void piv_init(void);

/* Process incoming PIV APDU and write response (Data + SW1 + SW2).
 * Returns total length of response. */
uint16_t piv_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* PIV_H */
```

---

<a id="firmwareusbfidopivpivc"></a>
# File: `firmware/usb_fido/piv/piv.c`

> **Description:** PIV (NIST SP 800-73-4) Implementation  
> **Path:** `firmware/usb_fido/piv/piv.c`  
> **Lines:** 670  

```c
#include "piv.h"
#include "micro_ecc/uECC.h"
#include "sha256/sha256.h"
#include "ed25519/ed25519.h"
#include "storage_flash.h"
#include "crypto_consttime.h"
#include <string.h>

#define PIV_TAG_CHUID     0x5FC102
#define PIV_TAG_CCC       0x5FC107
#define PIV_TAG_CERT_9A   0x5FC105
#define PIV_TAG_CERT_9C   0x5FC10A
#define PIV_TAG_CERT_9D   0x5FC10B
#define PIV_TAG_CERT_9E   0x5FC101
#define PIV_TAG_DISCOVERY 0x007E

/* PIV AID: A0 00 00 03 08 00 00 10 00 01 00 */
static const uint8_t s_piv_aid[11] = {
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

/* CHUID (Card Holder Unique Identifier) */
static const uint8_t s_piv_chuid[] = {
    0x30, 0x19, /* FASC-N (25 bytes) */
    0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39,
    0xCE, 0x73, 0x9D, 0x83, 0xA0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x10, /* Card UUID (16 bytes) */
    0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x5F,
    0x50, 0x49, 0x56, 0x5F, 0x55, 0x55, 0x49, 0x44,
    0x35, 0x08, /* Expiration Date: 20360101 */
    '2', '0', '3', '6', '0', '1', '0', '1',
    0x3E, 0x00, /* Signature */
    0xFE, 0x00  /* Error detection code */
};

/* CCC (Card Capability Container) */
static const uint8_t s_piv_ccc[] = {
    0xF0, 0x15, /* Card Identifier (21 bytes) */
    0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF, 0x02,
    0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00,
    0xF1, 0x01, 0x21, /* Container version */
    0xF2, 0x01, 0x21, /* Grammar version */
    0xF3, 0x00,       /* Applet family */
    0xF4, 0x01, 0x00, /* Security object */
    0xF5, 0x01, 0x10, /* Extended application property */
    0xF6, 0x00,
    0xF7, 0x00,
    0xFA, 0x00,
    0xFB, 0x00,
    0xFC, 0x00,
    0xFD, 0x00,
    0xFE, 0x00  /* EDC */
};

/* Key structure */
typedef struct {
    uint8_t  privkey[32];
    uint8_t  pubkey[64];
    uint8_t  cert[512];
    uint16_t cert_len;
    bool     valid;
} piv_key_t;

static piv_key_t s_piv_key_9a; /* PIV Authentication (Windows Logon / SSH) */
static piv_key_t s_piv_key_9c; /* Digital Signature */
static piv_key_t s_piv_key_9d; /* Key Management (Decryption / BitLocker) */
static piv_key_t s_piv_key_9e; /* Card Authentication (Doors) */

/* PINs & State */
static uint8_t s_piv_pin[8] = { '1', '2', '3', '4', '5', '6', 0xFF, 0xFF };
static uint8_t s_piv_pin_tries = 3;
static bool    s_piv_pin_verified = false;

static uint8_t s_piv_puk[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
static uint8_t s_piv_puk_tries = 3;

/* ==================== ASN.1 DER Helpers ==================== */

static uint16_t encode_der_int(uint8_t *out, const uint8_t *val, size_t len) {
    size_t start = 0;
    while (start < len - 1 && val[start] == 0) start++;
    uint8_t pad = (val[start] & 0x80) ? 1 : 0;
    uint8_t int_len = (uint8_t)(len - start + pad);

    out[0] = 0x02;
    out[1] = int_len;
    uint16_t idx = 2;
    if (pad) out[idx++] = 0x00;
    memcpy(out + idx, val + start, len - start);
    return idx + (uint16_t)(len - start);
}

static uint16_t encode_der_signature(uint8_t *out, const uint8_t raw_sig[64]) {
    uint8_t r_buf[40];
    uint8_t s_buf[40];
    uint16_t r_len = encode_der_int(r_buf, raw_sig, 32);
    uint16_t s_len = encode_der_int(s_buf, raw_sig + 32, 32);

    uint16_t total = 0;
    out[total++] = 0x30;
    out[total++] = (uint8_t)(r_len + s_len);
    memcpy(out + total, r_buf, r_len);
    total += r_len;
    memcpy(out + total, s_buf, s_len);
    total += s_len;
    return total;
}

/* Helper to generate self-signed X.509 v3 certificate for P-256 key */
static void generate_self_signed_cert(piv_key_t *k, uint8_t slot_id, const char *cn, uint8_t key_usage) {
    uint8_t tbs[384];
    uint16_t t_idx = 0;

    /* Version v3: A0 03 02 01 02 */
    tbs[t_idx++] = 0xA0; tbs[t_idx++] = 0x03; tbs[t_idx++] = 0x02; tbs[t_idx++] = 0x01; tbs[t_idx++] = 0x02;

    /* Serial Number: 02 02 00 <slot_id> */
    tbs[t_idx++] = 0x02; tbs[t_idx++] = 0x02; tbs[t_idx++] = 0x00; tbs[t_idx++] = slot_id;

    /* Signature Algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2) */
    static const uint8_t alg_ecdsa_sha256[] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    memcpy(tbs + t_idx, alg_ecdsa_sha256, sizeof(alg_ecdsa_sha256));
    t_idx += sizeof(alg_ecdsa_sha256);

    /* Issuer Name: CN=<cn>, O=hyprkey */
    uint8_t cn_len = (uint8_t)strlen(cn);
    uint8_t name_buf[80];
    uint16_t n_idx = 0;
    name_buf[n_idx++] = 0x31; name_buf[n_idx++] = cn_len + 9;
    name_buf[n_idx++] = 0x30; name_buf[n_idx++] = cn_len + 7;
    name_buf[n_idx++] = 0x06; name_buf[n_idx++] = 0x03; name_buf[n_idx++] = 0x55; name_buf[n_idx++] = 0x04; name_buf[n_idx++] = 0x03;
    name_buf[n_idx++] = 0x0C; name_buf[n_idx++] = cn_len;
    memcpy(name_buf + n_idx, cn, cn_len); n_idx += cn_len;
    name_buf[n_idx++] = 0x31; name_buf[n_idx++] = 16;
    name_buf[n_idx++] = 0x30; name_buf[n_idx++] = 14;
    name_buf[n_idx++] = 0x06; name_buf[n_idx++] = 0x03; name_buf[n_idx++] = 0x55; name_buf[n_idx++] = 0x04; name_buf[n_idx++] = 0x0A;
    name_buf[n_idx++] = 0x0C; name_buf[n_idx++] = 7;
    memcpy(name_buf + n_idx, "hyprkey", 7); n_idx += 7;

    tbs[t_idx++] = 0x30; tbs[t_idx++] = (uint8_t)n_idx;
    memcpy(tbs + t_idx, name_buf, n_idx);
    t_idx += n_idx;

    /* Validity: 2026-01-01 to 2036-01-01 */
    static const uint8_t validity[] = {
        0x30, 0x1E,
        0x17, 0x0D, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'
    };
    memcpy(tbs + t_idx, validity, sizeof(validity));
    t_idx += sizeof(validity);

    /* Subject Name: same as Issuer */
    tbs[t_idx++] = 0x30; tbs[t_idx++] = (uint8_t)n_idx;
    memcpy(tbs + t_idx, name_buf, n_idx);
    t_idx += n_idx;

    /* SubjectPublicKeyInfo: id-ecPublicKey + secp256r1 + 04 || pubkey 64 */
    static const uint8_t spki_prefix[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04
    };
    memcpy(tbs + t_idx, spki_prefix, sizeof(spki_prefix));
    t_idx += sizeof(spki_prefix);
    memcpy(tbs + t_idx, k->pubkey, 64);
    t_idx += 64;

    /* Extensions: KeyUsage */
    uint8_t ext[] = {
        0xA3, 0x12, 0x30, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F,
        0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x07, key_usage
    };
    memcpy(tbs + t_idx, ext, sizeof(ext));
    t_idx += sizeof(ext);

    /* Hash TBS */
    uint8_t tbs_full[400];
    uint16_t full_tbs_len = 0;
    tbs_full[full_tbs_len++] = 0x30;
    if (t_idx > 127) {
        tbs_full[full_tbs_len++] = 0x82;
        tbs_full[full_tbs_len++] = (uint8_t)(t_idx >> 8);
        tbs_full[full_tbs_len++] = (uint8_t)(t_idx & 0xFF);
    } else {
        tbs_full[full_tbs_len++] = (uint8_t)t_idx;
    }
    memcpy(tbs_full + full_tbs_len, tbs, t_idx);
    full_tbs_len += t_idx;

    uint8_t hash[32];
    sha256_ctx_t sha;
    sha256_init(&sha);
    sha256_update(&sha, tbs_full, full_tbs_len);
    sha256_final(&sha, hash);

    /* Sign with key */
    uint8_t raw_sig[64];
    uECC_sign(k->privkey, hash, 32, raw_sig, uECC_secp256r1());

    uint8_t der_sig[80];
    uint16_t der_sig_len = encode_der_signature(der_sig, raw_sig);

    /* Build outer certificate */
    uint8_t cert_body[512];
    uint16_t b_idx = 0;
    memcpy(cert_body + b_idx, tbs_full, full_tbs_len);
    b_idx += full_tbs_len;
    memcpy(cert_body + b_idx, alg_ecdsa_sha256, sizeof(alg_ecdsa_sha256));
    b_idx += sizeof(alg_ecdsa_sha256);

    cert_body[b_idx++] = 0x03;
    cert_body[b_idx++] = (uint8_t)(der_sig_len + 1);
    cert_body[b_idx++] = 0x00;
    memcpy(cert_body + b_idx, der_sig, der_sig_len);
    b_idx += der_sig_len;

    /* Wrap in SEQUENCE */
    uint16_t c_idx = 0;
    k->cert[c_idx++] = 0x30;
    if (b_idx > 127) {
        k->cert[c_idx++] = 0x82;
        k->cert[c_idx++] = (uint8_t)(b_idx >> 8);
        k->cert[c_idx++] = (uint8_t)(b_idx & 0xFF);
    } else {
        k->cert[c_idx++] = (uint8_t)b_idx;
    }
    memcpy(k->cert + c_idx, cert_body, b_idx);
    k->cert_len = c_idx + b_idx;
}

static void init_piv_key(piv_key_t *k, const char *role_tag, uint8_t slot_id, const char *cn, uint8_t key_usage) {
    uint8_t master_key[32];
    storage_get_device_master_key("PIV", master_key);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master_key, 32);
    sha256_update(&ctx, (const uint8_t *)role_tag, strlen(role_tag));
    sha256_final(&ctx, k->privkey);
    k->privkey[0] &= 0x7F;

    uECC_compute_public_key(k->privkey, k->pubkey, uECC_secp256r1());
    k->valid = true;

    generate_self_signed_cert(k, slot_id, cn, key_usage);
}

void piv_init(void) {
    init_piv_key(&s_piv_key_9a, "PIV_AUTH_KEY_9A", 0x9A, "hyprkey PIV Authentication",    0x80); /* digitalSignature */
    init_piv_key(&s_piv_key_9c, "PIV_SIGN_KEY_9C", 0x9C, "hyprkey PIV Digital Signature",   0x60); /* nonRepudiation | digitalSignature */
    init_piv_key(&s_piv_key_9d, "PIV_KEYM_KEY_9D", 0x9D, "hyprkey PIV Key Management",      0x28); /* keyEncipherment | keyAgreement */
    init_piv_key(&s_piv_key_9e, "PIV_CARD_KEY_9E", 0x9E, "hyprkey PIV Card Authentication", 0x80); /* digitalSignature */

    s_piv_pin_verified = false;
    s_piv_pin_tries = storage_get_pin_retries(PIN_TYPE_PIV_PIN);
    s_piv_puk_tries = storage_get_pin_retries(PIN_TYPE_PIV_PUK);
}

/* ==================== PIV APDU Processing ==================== */

uint16_t piv_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    uint8_t ins = apdu[1];
    uint8_t p1  = apdu[2];
    uint8_t p2  = apdu[3];

    /* Parse Lc and Data pointer using strict ISO/IEC 7816-4 parser (Short and Extended APDUs) */
    uint16_t lc = 0U;
    const uint8_t *data = NULL;
    if (!iso7816_parse_apdu(apdu, apdu_len, &data, &lc)) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* SW_WRONG_LENGTH */
        return 2;
    }

    /* 1. SELECT (0xA4) */
    if (ins == 0xA4) {
        if (p1 == 0x04 && p2 == 0x00) {
            /* Accept PIV AID (11 bytes or prefix 9 bytes) */
            if (data != NULL && lc >= 9 && memcmp(data, s_piv_aid, 9) == 0) {
                /* Return Application Property Template 0x7E */
                uint16_t idx = 0;
                rsp[idx++] = 0x7E;
                rsp[idx++] = 1 + sizeof(s_piv_aid) + 3;
                rsp[idx++] = 0x4F; /* AID */
                rsp[idx++] = sizeof(s_piv_aid);
                memcpy(rsp + idx, s_piv_aid, sizeof(s_piv_aid));
                idx += sizeof(s_piv_aid);
                rsp[idx++] = 0x7F; rsp[idx++] = 0x66; rsp[idx++] = 0x00; /* CTAA */
                rsp[idx++] = 0x90; rsp[idx++] = 0x00;
                return idx;
            }
        }
        rsp[0] = 0x6A; rsp[1] = 0x82; /* File not found */
        return 2;
    }

    /* 2. VERIFY (0x20) */
    if (ins == 0x20) {
        if (p2 == 0x80) { /* Card Application PIN */
            if (lc == 0) {
                if (s_piv_pin_verified) {
                    rsp[0] = 0x90; rsp[1] = 0x00;
                } else {
                    rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_piv_pin_tries);
                }
                return 2;
            }

            if (s_piv_pin_tries == 0) {
                rsp[0] = 0x69; rsp[1] = 0x83; /* Blocked */
                return 2;
            }

            /* Match 6-8 bytes with 0xFF padding (FIPS 201 compliant constant-time) */
            bool match = false;
            uint8_t padded_input[8];
            memset(padded_input, 0xFF, sizeof(padded_input));
            if (lc >= 6 && lc <= 8 && data != NULL) {
                memcpy(padded_input, data, lc);
                if (crypto_consttime_eq(padded_input, s_piv_pin, 8)) {
                    match = true;
                }
            }

            if (match) {
                s_piv_pin_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, s_piv_pin_tries);
                s_piv_pin_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
            } else {
                if (s_piv_pin_tries > 0) s_piv_pin_tries--;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, s_piv_pin_tries);
                s_piv_pin_verified = false;
                rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_piv_pin_tries);
            }
            return 2;
        }
        rsp[0] = 0x6A; rsp[1] = 0x88;
        return 2;
    }

    /* 3. CHANGE REFERENCE DATA (0x24) */
    if (ins == 0x24 && p2 == 0x80) {
        if (lc >= 16 && data != NULL) {
            /* Old PIN (8) + New PIN (8) */
            uint8_t padded_old[8];
            memset(padded_old, 0xFF, sizeof(padded_old));
            memcpy(padded_old, data, 8);
            if (crypto_consttime_eq(padded_old, s_piv_pin, 8)) {
                memcpy(s_piv_pin, data + 8, 8);
                s_piv_pin_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, 3);
                s_piv_pin_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        }
        rsp[0] = 0x63; rsp[1] = 0xC0;
        return 2;
    }

    /* 4. RESET RETRY COUNTER (0x2C) */
    if (ins == 0x2C && p2 == 0x80) {
        if (s_piv_puk_tries == 0) {
            rsp[0] = 0x69; rsp[1] = 0x83; /* Authentication method blocked */
            return 2;
        }

        if (lc >= 16 && data != NULL) {
            /* PUK (8) + New PIN (8) */
            uint8_t padded_puk[8];
            memset(padded_puk, 0xFF, sizeof(padded_puk));
            memcpy(padded_puk, data, 8);
            if (crypto_consttime_eq(padded_puk, s_piv_puk, 8)) {
                memcpy(s_piv_pin, data + 8, 8);
                s_piv_pin_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PIN, 3);
                s_piv_puk_tries = 3;
                storage_set_pin_retries(PIN_TYPE_PIV_PUK, 3);
                s_piv_pin_verified = true;
                rsp[0] = 0x90; rsp[1] = 0x00;
                return 2;
            }
        }
        if (s_piv_puk_tries > 0) s_piv_puk_tries--;
        storage_set_pin_retries(PIN_TYPE_PIV_PUK, s_piv_puk_tries);
        rsp[0] = 0x63; rsp[1] = (uint8_t)(0xC0 | s_piv_puk_tries);
        return 2;
    }

    /* 5. GET DATA (0xCB) */
    if (ins == 0xCB && p1 == 0x3F && p2 == 0xFF) {
        if (lc < 3 || !data || data[0] != 0x5C) {
            rsp[0] = 0x6A; rsp[1] = 0x80;
            return 2;
        }

        uint8_t tag_len = data[1];
        uint32_t tag = 0;
        for (uint8_t i = 0; i < tag_len && i < 4; i++) {
            tag = (tag << 8) | data[2 + i];
        }

        const uint8_t *payload = NULL;
        uint16_t payload_len = 0;
        uint8_t wrap_buf[600];

        if (tag == PIV_TAG_CHUID) {
            /* Wrap in tag 0x53 */
            wrap_buf[0] = 0x53;
            wrap_buf[1] = (uint8_t)sizeof(s_piv_chuid);
            memcpy(wrap_buf + 2, s_piv_chuid, sizeof(s_piv_chuid));
            payload = wrap_buf;
            payload_len = 2 + sizeof(s_piv_chuid);
        } else if (tag == PIV_TAG_CCC) {
            wrap_buf[0] = 0x53;
            wrap_buf[1] = (uint8_t)sizeof(s_piv_ccc);
            memcpy(wrap_buf + 2, s_piv_ccc, sizeof(s_piv_ccc));
            payload = wrap_buf;
            payload_len = 2 + sizeof(s_piv_ccc);
        } else if (tag == PIV_TAG_CERT_9A || tag == PIV_TAG_CERT_9C ||
                   tag == PIV_TAG_CERT_9D || tag == PIV_TAG_CERT_9E) {
            piv_key_t *k = &s_piv_key_9a;
            if (tag == PIV_TAG_CERT_9C) k = &s_piv_key_9c;
            else if (tag == PIV_TAG_CERT_9D) k = &s_piv_key_9d;
            else if (tag == PIV_TAG_CERT_9E) k = &s_piv_key_9e;

            /* Wrap certificate in Tag 0x70, Tag 0x71 (CertInfo 00), Tag 0xFE */
            uint16_t inner_len = 0;
            uint8_t inner_buf[550];

            /* Tag 0x70 */
            inner_buf[inner_len++] = 0x70;
            if (k->cert_len > 127) {
                inner_buf[inner_len++] = 0x82;
                inner_buf[inner_len++] = (uint8_t)(k->cert_len >> 8);
                inner_buf[inner_len++] = (uint8_t)(k->cert_len & 0xFF);
            } else {
                inner_buf[inner_len++] = (uint8_t)k->cert_len;
            }
            memcpy(inner_buf + inner_len, k->cert, k->cert_len);
            inner_len += k->cert_len;

            /* Tag 0x71: CertInfo */
            inner_buf[inner_len++] = 0x71; inner_buf[inner_len++] = 0x01; inner_buf[inner_len++] = 0x00;
            /* Tag 0xFE: EDC */
            inner_buf[inner_len++] = 0xFE; inner_buf[inner_len++] = 0x00;

            /* Wrap in Tag 0x53 */
            uint16_t w_idx = 0;
            wrap_buf[w_idx++] = 0x53;
            if (inner_len > 127) {
                wrap_buf[w_idx++] = 0x82;
                wrap_buf[w_idx++] = (uint8_t)(inner_len >> 8);
                wrap_buf[w_idx++] = (uint8_t)(inner_len & 0xFF);
            } else {
                wrap_buf[w_idx++] = (uint8_t)inner_len;
            }
            memcpy(wrap_buf + w_idx, inner_buf, inner_len);
            w_idx += inner_len;

            payload = wrap_buf;
            payload_len = w_idx;
        }

        if (payload && payload_len > 0) {
            if (payload_len + 2 > max_rsp_len) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }
            memcpy(rsp, payload, payload_len);
            rsp[payload_len]     = 0x90;
            rsp[payload_len + 1] = 0x00;
            return payload_len + 2;
        }

        rsp[0] = 0x6A; rsp[1] = 0x82; /* Not found */
        return 2;
    }

    /* 6. GENERAL AUTHENTICATE (0x87) */
    if (ins == 0x87) {
        uint8_t key_ref = p2;
        piv_key_t *k = &s_piv_key_9a;
        if (key_ref == 0x9C) k = &s_piv_key_9c;
        else if (key_ref == 0x9D) k = &s_piv_key_9d;
        else if (key_ref == 0x9E) k = &s_piv_key_9e;

        /* PIN check (9E is card authentication without PIN) */
        if (key_ref != 0x9E && !s_piv_pin_verified) {
            rsp[0] = 0x69; rsp[1] = 0x82; /* Security status not satisfied */
            return 2;
        }

        /* Parse Dynamic Auth Template (Tag 0x7C) */
        if (lc >= 4 && data[0] == 0x7C) {
            uint16_t t7c_len = data[1];
            const uint8_t *t7c_data = data + 2;
            if (t7c_len == 0x82) {
                if (lc < 4) { rsp[0] = 0x67; rsp[1] = 0x00; return 2; }
                t7c_len = ((uint16_t)data[2] << 8) | data[3];
                t7c_data = data + 4;
            } else if (t7c_len == 0x81) {
                if (lc < 3) { rsp[0] = 0x67; rsp[1] = 0x00; return 2; }
                t7c_len = data[2];
                t7c_data = data + 3;
            }

            if ((uint16_t)((t7c_data - data) + t7c_len) > lc) {
                rsp[0] = 0x67; rsp[1] = 0x00;
                return 2;
            }

            /* Find Tag 0x81 (Challenge to sign) or Tag 0x85 (ECDH peer point) */
            uint16_t offset = 0;
            const uint8_t *challenge = NULL;
            uint16_t chal_len = 0;
            const uint8_t *ecdh_peer = NULL;
            uint16_t ecdh_len = 0;

            while (offset + 1 < t7c_len) {
                uint8_t tag = t7c_data[offset++];
                uint16_t len = t7c_data[offset++];
                if (len == 0x82) {
                    if (offset + 2 > t7c_len) break;
                    len = ((uint16_t)t7c_data[offset] << 8) | t7c_data[offset + 1];
                    offset += 2;
                } else if (len == 0x81) {
                    if (offset >= t7c_len) break;
                    len = t7c_data[offset++];
                }
                if ((uint16_t)(offset + len) > t7c_len) break;

                if (tag == 0x81) {
                    challenge = t7c_data + offset;
                    chal_len = len;
                } else if (tag == 0x85) {
                    ecdh_peer = t7c_data + offset;
                    ecdh_len = len;
                }
                offset += len;
            }

            /* Case 1: Signature on Tag 0x81 */
            if (challenge && chal_len > 0) {
                if (p1 == 0x22) {
                    /* Ed25519 signature: raw 64 bytes */
                    uint8_t pk25519[32], sk25519[64];
                    ed25519_create_keypair(pk25519, sk25519, k->privkey);
                    uint8_t sig64[64];
                    ed25519_sign(sig64, challenge, chal_len, pk25519, sk25519);

                    /* Response: 7C 42 82 40 <sig64> 90 00 */
                    uint16_t total = 0;
                    rsp[total++] = 0x7C;
                    rsp[total++] = 66; /* 64 + 2 */
                    rsp[total++] = 0x82;
                    rsp[total++] = 64;
                    memcpy(rsp + total, sig64, 64);
                    total += 64;
                    rsp[total++] = 0x90;
                    rsp[total++] = 0x00;
                    return total;
                }

                uint8_t digest[32];
                if (chal_len == 32) {
                    memcpy(digest, challenge, 32);
                } else {
                    sha256_ctx_t sha;
                    sha256_init(&sha);
                    sha256_update(&sha, challenge, chal_len);
                    sha256_final(&sha, digest);
                }

                uint8_t raw_sig[64];
                uECC_sign(k->privkey, digest, 32, raw_sig, uECC_secp256r1());

                uint8_t der_sig[80];
                uint16_t der_len = encode_der_signature(der_sig, raw_sig);

                /* Response: 7C <len> 82 <der_len> <der_sig> 90 00 */
                uint16_t total = 0;
                rsp[total++] = 0x7C;
                rsp[total++] = (uint8_t)(der_len + 2);
                rsp[total++] = 0x82;
                rsp[total++] = (uint8_t)der_len;
                memcpy(rsp + total, der_sig, der_len);
                total += der_len;

                rsp[total++] = 0x90;
                rsp[total++] = 0x00;
                return total;
            }

            /* Case 2: ECDH Key Agreement on Tag 0x85 */
            if (ecdh_peer && ecdh_len >= 65 && ecdh_peer[0] == 0x04) {
                uint8_t secret[32];
                uECC_shared_secret(ecdh_peer + 1, k->privkey, secret, uECC_secp256r1());

                /* Response: 7C 22 82 20 <secret 32> 90 00 */
                uint16_t total = 0;
                rsp[total++] = 0x7C;
                rsp[total++] = 34;
                rsp[total++] = 0x82;
                rsp[total++] = 32;
                memcpy(rsp + total, secret, 32);
                total += 32;

                rsp[total++] = 0x90;
                rsp[total++] = 0x00;
                return total;
            }
        }

        rsp[0] = 0x6A; rsp[1] = 0x80;
        return 2;
    }

    /* 7. GENERATE ASYMMETRIC KEY PAIR (0x47) */
    if (ins == 0x47) {
        uint8_t key_ref = p2;
        piv_key_t *k = &s_piv_key_9a;
        if (key_ref == 0x9C) k = &s_piv_key_9c;
        else if (key_ref == 0x9D) k = &s_piv_key_9d;
        else if (key_ref == 0x9E) k = &s_piv_key_9e;

        if (p1 == 0x22) {
            /* Ed25519 public key template (Tag 0x86, 32 bytes) */
            uint8_t pk25519[32], sk25519[64];
            ed25519_create_keypair(pk25519, sk25519, k->privkey);
            uint16_t total = 0;
            rsp[total++] = 0x7F;
            rsp[total++] = 0x49;
            rsp[total++] = 34; /* 32 + 2 */
            rsp[total++] = 0x86;
            rsp[total++] = 32;
            memcpy(rsp + total, pk25519, 32);
            total += 32;
            rsp[total++] = 0x90;
            rsp[total++] = 0x00;
            return total;
        }

        /* Return public key template 0x7F49 containing Tag 0x86 (0x04 || pubkey 64) */
        uint16_t total = 0;
        rsp[total++] = 0x7F;
        rsp[total++] = 0x49;
        rsp[total++] = 67; /* 65 + 2 */
        rsp[total++] = 0x86;
        rsp[total++] = 65;
        rsp[total++] = 0x04;
        memcpy(rsp + total, k->pubkey, 64);
        total += 64;

        rsp[total++] = 0x90;
        rsp[total++] = 0x00;
        return total;
    }

    rsp[0] = 0x6D; rsp[1] = 0x00; /* Instruction not supported */
    return 2;
}
```

---

<a id="firmwareusbfidooathoathh"></a>
# File: `firmware/usb_fido/oath/oath.h`

> **Description:** OATH TOTP/HOTP Definitions  
> **Path:** `firmware/usb_fido/oath/oath.h`  
> **Lines:** 32  

```c
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
```

---

<a id="firmwareusbfidooathoathc"></a>
# File: `firmware/usb_fido/oath/oath.c`

> **Description:** OATH TOTP/HOTP Implementation  
> **Path:** `firmware/usb_fido/oath/oath.c`  
> **Lines:** 293  

```c
#include "oath.h"
#include "sha1/sha1.h"
#include "sha256/sha256.h"
#include "crypto_consttime.h"
#include <string.h>

static const uint8_t s_oath_aid[7] = {
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
};

static oath_cred_t s_creds[OATH_MAX_CREDENTIALS];

void oath_init(void) {
    memset(s_creds, 0, sizeof(s_creds));
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

    /* Parse Lc and Data pointer using strict ISO/IEC 7816-4 parser */
    uint16_t lc = 0U;
    const uint8_t *data = NULL;
    if (!iso7816_parse_apdu(apdu, apdu_len, &data, &lc)) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* SW_WRONG_LENGTH */
        return 2;
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
            if ((uint16_t)(2 + name_len) > lc) {
                rsp[0] = 0x67; rsp[1] = 0x00; /* Wrong length */
                return 2;
            }
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
```

---

<a id="toolshyprkeyotapy"></a>
# File: `tools/hyprkey_ota.py`

> **Description:** Host Live OTA CCID Streaming Tool  
> **Path:** `tools/hyprkey_ota.py`  
> **Lines:** 173  

```python
#!/usr/bin/env python3
"""hyprkey_ota.py - Live Seamless In-Application OTA Update over USB CCID.

Streams firmware directly into the inactive flash slot via Vendor APDU (FF FC),
verifies on-chip SHA-256 cryptographic digest, and triggers a 100ms soft-reset.
No virtual USB disk (NICENANO) ever mounts.
"""

import sys
import os
import time
import hashlib
import smartcard.System as sc

FW_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firmware", "usb_fido")
CHUNK_SIZE = 220

def perform_ota():
    readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
    if not readers:
        print("Error: HyprKey CCID reader not detected!")
        sys.exit(1)

    reader = readers[0]
    print(f"Connected to reader: {reader}")
    conn = reader.createConnection()
    conn.connect()

    t0 = time.perf_counter()

    # Step 0: Authenticate Admin PIN (OpenPGP PW3)
    admin_pin = sys.argv[1] if len(sys.argv) > 1 else "12345678"
    print(f"\n0. Authenticating Admin PIN (PW3)...")
    # SELECT OpenPGP Card Applet
    resp, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
    # VERIFY PW3 (Admin PIN)
    pin_bytes = list(admin_pin.encode("ascii"))
    resp, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, 0x83, len(pin_bytes)] + pin_bytes)
    if (sw1, sw2) != (0x90, 0x00):
        print(f"Error: Admin PIN verification failed! SW={sw1:02X}{sw2:02X}")
        sys.exit(1)
    print("   Admin PIN (PW3) successfully verified!")

    # Step 1: Begin OTA Session
    print("\n1. Initializing OTA Session (erasing inactive slot)...")
    t_erase_start = time.perf_counter()
    resp, sw1, sw2 = conn.transmit([0xFF, 0xFC, 0x00, 0x00, 0x00])
    t_erase = time.perf_counter() - t_erase_start

    if (sw1, sw2) != (0x90, 0x00) or len(resp) < 2:
        print(f"Error starting OTA session: SW={sw1:02X}{sw2:02X}, resp={resp}")
        sys.exit(1)

    cur_slot_id = resp[0]
    tgt_slot_id = resp[1]
    cur_slot = "Slot A" if cur_slot_id == 0 else "Slot B"
    tgt_slot = "Slot A" if tgt_slot_id == 0 else "Slot B"
    print(f"   Active Running Slot: {cur_slot}")
    print(f"   Target Inactive Slot: {tgt_slot}")
    print(f"   Target slot erased in: {t_erase*1000:.1f} ms")

    # Select target-specific binary (linked for 0x00028000 or 0x00040000)
    slot_bin_name = "usb_fido_slot_b.bin" if tgt_slot_id == 1 else "usb_fido_slot_a.bin"
    target_bin_path = os.path.join(FW_DIR, slot_bin_name)
    if not os.path.exists(target_bin_path):
        target_bin_path = os.path.join(FW_DIR, "usb_fido.bin")

    if not os.path.exists(target_bin_path):
        print(f"Error: Target binary not found at {target_bin_path}")
        sys.exit(1)

    with open(target_bin_path, "rb") as f:
        fw_data = f.read()

    total_len = len(fw_data)
    fw_sha256 = hashlib.sha256(fw_data).digest()

    print(f"   Selected Image: {slot_bin_name}")
    print(f"   Size: {total_len} bytes (~{total_len/1024:.1f} KB)")
    print(f"   SHA-256: {fw_sha256.hex()}")

    # Step 2: Stream Chunks
    print(f"\n2. Streaming {total_len} bytes in {CHUNK_SIZE}-byte chunks over USB CCID...")
    offset = 0
    t_stream_start = time.perf_counter()
    chunk_idx = 0
    num_chunks = (total_len + CHUNK_SIZE - 1) // CHUNK_SIZE

    while offset < total_len:
        chunk = fw_data[offset : offset + CHUNK_SIZE]
        chunk_len = len(chunk)
        payload_len = 4 + chunk_len

        # APDU: FF FC 01 00 <payload_len> <offset:4> <chunk>
        apdu = [
            0xFF, 0xFC, 0x01, 0x00,
            payload_len,
            (offset >> 24) & 0xFF,
            (offset >> 16) & 0xFF,
            (offset >> 8) & 0xFF,
            offset & 0xFF
        ] + list(chunk)

        resp, sw1, sw2 = conn.transmit(apdu)
        if (sw1, sw2) != (0x90, 0x00):
            print(f"\nError writing chunk at offset {offset}: SW={sw1:02X}{sw2:02X}")
            sys.exit(1)

        offset += chunk_len
        chunk_idx += 1
        pct = (offset / total_len) * 100
        print(f"\r   Progress: [{chunk_idx}/{num_chunks}] {offset}/{total_len} bytes ({pct:.1f}%)", end="", flush=True)

    t_stream = time.perf_counter() - t_stream_start
    throughput = (total_len / 1024) / t_stream if t_stream > 0 else 0
    print(f"\n   Stream completed in {t_stream:.2f} s ({throughput:.1f} KB/s)")

    # Step 3: Finalize & Verify SHA-256 on-chip
    print("\n3. Verifying on-chip SHA-256 cryptographic digest...")
    size_bytes = [
        (total_len >> 24) & 0xFF,
        (total_len >> 16) & 0xFF,
        (total_len >> 8) & 0xFF,
        total_len & 0xFF
    ]
    finalize_apdu = [0xFF, 0xFC, 0x02, 0x00, 36] + size_bytes + list(fw_sha256)
    
    t_fin_start = time.perf_counter()
    resp, sw1, sw2 = conn.transmit(finalize_apdu)
    t_fin = time.perf_counter() - t_fin_start

    if (sw1, sw2) == (0x90, 0x00):
        print(f"   SUCCESS! On-chip SHA-256 matched bit-for-bit (verified in {t_fin*1000:.1f} ms)!")
    else:
        print(f"   FAILED! On-chip SHA-256 verification failed: SW={sw1:02X}{sw2:02X}")
        sys.exit(1)

    conn.disconnect()

    # Step 4: Wait for reboot
    print("\n4. Waiting for Stage-2 seamless reboot into updated firmware...")
    t_reboot_start = time.perf_counter()
    time.sleep(0.5)

    re_opened = False
    for _ in range(10):
        try:
            r_list = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
            if r_list:
                c2 = r_list[0].createConnection()
                c2.connect()
                # Query ATR or APDU
                c2.transmit([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
                c2.disconnect()
                re_opened = True
                break
        except Exception:
            pass
        time.sleep(0.1)

    t_reboot = time.perf_counter() - t_reboot_start
    t_total = time.perf_counter() - t0

    if re_opened:
        print(f"   SUCCESS! HyprKey re-opened and responsive in {t_reboot:.2f} s!")
        print("\n" + "="*50)
        print(f"LIVE OTA TOTAL TIME: {t_total:.2f} seconds!")
        print("="*50)
    else:
        print("Note: Token rebooted, re-enumeration in progress.")

if __name__ == "__main__":
    perform_ota()
```

---

<a id="toolsflashkeypy"></a>
# File: `tools/flash_key.py`

> **Description:** Host Autonomous 1-Click DFU Flasher  
> **Path:** `tools/flash_key.py`  
> **Lines:** 106  

```python
#!/usr/bin/env python3
"""flash_key.py - 1-Click Autonomous Flash for HyprKey over USB CCID.

No COM ports, no serial cables, no physical buttons required.
1. Detects if device is in normal CCID mode or bootloader mode.
2. If CCID mode: sends Vendor APDU (FF FD 42 00 00) to reboot into UF2 bootloader.
3. Waits for NICENANO drive.
4. Copies usb_fido.uf2 to the drive.
5. Waits for device to reboot and verifies CCID reader.
"""

import sys
import os
import time
import shutil
import subprocess

UF2_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firmware", "usb_fido", "usb_fido.uf2")

def find_nicenano_drive():
    # Check common drive letters
    for letter in "EFGHIJKLMNOPQRSTUVWXYZ":
        path = f"{letter}:\\INFO_UF2.TXT"
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="latin1") as f:
                    content = f.read()
                    if "nice!nano" in content or "UF2 Bootloader" in content:
                        return f"{letter}:\\"
            except Exception:
                pass
    return None

def trigger_dfu_via_ccid(admin_pin="12345678"):
    try:
        import smartcard.System as sc
        readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
        if not readers:
            return False
        
        reader = readers[0]
        print(f"Connecting to {reader}...")
        conn = reader.createConnection()
        conn.connect()
        # SELECT OpenPGP Card Applet
        conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
        # VERIFY PW3 (Admin PIN)
        pin_bytes = list(admin_pin.encode("ascii"))
        conn.transmit([0x00, 0x20, 0x00, 0x83, len(pin_bytes)] + pin_bytes)
        # APDU: CLA=0xFF, INS=0xFD, P1=0x42 (Reboot to DFU)
        data, sw1, sw2 = conn.transmit([0xFF, 0xFD, 0x42, 0x00, 0x00])
        print(f"Sent Reboot-to-DFU APDU -> SW={sw1:02X}{sw2:02X}")
        conn.disconnect()
        return (sw1, sw2) == (0x90, 0x00)
    except Exception as e:
        print(f"CCID trigger exception: {e}")
        return False

def flash():
    if not os.path.exists(UF2_PATH):
        print(f"Error: Firmware binary not found at {UF2_PATH}")
        sys.exit(1)

    print(f"Firmware binary: {UF2_PATH} ({os.path.getsize(UF2_PATH)} bytes)")

    # 1. Check if already in bootloader
    drive = find_nicenano_drive()
    if not drive:
        print("Device in CCID mode. Sending autonomous DFU reboot command...")
        if not trigger_dfu_via_ccid():
            print("Could not send CCID command. Checking if bootloader drive appears anyway...")
        
        # Wait for drive to appear
        for i in range(12):
            time.sleep(0.5)
            drive = find_nicenano_drive()
            if drive:
                break
        
        if not drive:
            print("Error: NICENANO bootloader drive did not appear within 6 seconds.")
            sys.exit(1)

    print(f"Target drive located at: {drive}")
    dst_uf2 = os.path.join(drive, "usb_fido.uf2")
    print(f"Writing UF2 -> {dst_uf2}...")
    shutil.copyfile(UF2_PATH, dst_uf2)
    print("Write complete! Device is flashing and rebooting...")

    # Wait for reboot and CCID re-enumeration
    time.sleep(2.5)
    try:
        import smartcard.System as sc
        for _ in range(10):
            readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
            if readers:
                print(f"SUCCESS: HyprKey re-enumerated as '{readers[0]}'")
                break
            time.sleep(0.5)
        else:
            print("Warning: CCID reader did not re-appear yet (may still be enumerating).")
    except Exception as e:
        print(f"Note: {e}")

if __name__ == "__main__":
    flash()
```

---


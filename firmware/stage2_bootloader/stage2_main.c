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

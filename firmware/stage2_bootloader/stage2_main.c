#include <stdint.h>
#include <stdbool.h>

/* ==================== Memory Map Definitions ==================== */
#define STAGE2_BASE         0x00026000UL
#define SLOT_A_BASE         0x00028000UL
#define SLOT_B_BASE         0x00040000UL
#define SLOT_SIZE           (96 * 1024)   /* 96 KB = 0x18000 */
#define META_PAGE_ADDR      0x00058000UL
#define USERDATA_BASE       0x00059000UL

/* ==================== Metadata Structure ==================== */
#define OTA_MAGIC_HEADER    0x48595052UL  /* 'HYPR' */
#define OTA_FLAG_SWAP_REQ   0x00000001UL
#define OTA_FLAG_CONFIRMED  0x00000002UL

typedef struct __attribute__((packed)) {
    uint32_t magic;         /* 'HYPR' */
    uint32_t flags;         /* OTA_FLAG_* */
    uint32_t image_size;    /* payload size in bytes */
    uint32_t crc32;         /* image CRC32 */
    uint32_t version;       /* semantic version / build number */
    uint32_t boot_count;    /* trial boot attempts */
    uint32_t reserved[10];
} ota_meta_t;

/* ==================== Hardware Registers ==================== */
#define SCB_VTOR            (*(volatile uint32_t *)0xE000ED08UL)
#define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0CUL)
#define NRF_POWER_GPREGRET  (*(volatile uint32_t *)0x4000051CUL)
#define DFU_MAGIC_UF2_RESET 0x57

#define NVMC_READY          (*(volatile uint32_t *)0x4001E400UL)
#define NVMC_CONFIG         (*(volatile uint32_t *)0x4001E504UL)
#define NVMC_ERASEPAGE      (*(volatile uint32_t *)0x4001E508UL)

#define P0_DIRSET           (*(volatile uint32_t *)0x50000518UL)
#define P0_OUTSET           (*(volatile uint32_t *)0x50000508UL)
#define P0_OUTCLR           (*(volatile uint32_t *)0x5000050CUL)
#define PIN_LED             15

/* ==================== Flash Controller Primitives ==================== */
static inline void nvmc_wait(void) {
    while (NVMC_READY == 0);
}

static void nvmc_erase_page(uint32_t addr) {
    nvmc_wait();
    NVMC_CONFIG = 0x02; /* Een = Erase enable */
    NVMC_ERASEPAGE = addr;
    nvmc_wait();
    NVMC_CONFIG = 0x00; /* Ren = Read-only */
}

static void nvmc_write_word(uint32_t addr, uint32_t data) {
    nvmc_wait();
    NVMC_CONFIG = 0x01; /* Wen = Write enable */
    *(volatile uint32_t *)addr = data;
    nvmc_wait();
    NVMC_CONFIG = 0x00; /* Ren = Read-only */
}

/* ==================== Validation & Execution ==================== */
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

    /* 3. Check OTA Metadata */
    const ota_meta_t *meta = (const ota_meta_t *)META_PAGE_ADDR;

    if (meta->magic == OTA_MAGIC_HEADER && (meta->flags & OTA_FLAG_SWAP_REQ)) {
        /* Slot B has a verified update waiting to be applied */
        if (is_valid_image(SLOT_B_BASE)) {
            /* Quick blink to indicate stage-2 firmware swap */
            P0_OUTCLR = (1UL << PIN_LED);

            /* Erase Slot A (24 pages of 4 KB = 96 KB) */
            uint32_t copy_size = meta->image_size;
            if (copy_size == 0 || copy_size > SLOT_SIZE) {
                copy_size = SLOT_SIZE;
            }

            for (uint32_t p = 0; p < copy_size; p += 4096) {
                nvmc_erase_page(SLOT_A_BASE + p);
            }

            /* Copy Slot B -> Slot A in 32-bit words */
            uint32_t words = (copy_size + 3) / 4;
            const uint32_t *src = (const uint32_t *)SLOT_B_BASE;
            for (uint32_t i = 0; i < words; i++) {
                nvmc_write_word(SLOT_A_BASE + (i * 4), src[i]);
            }

            /* Update Metadata: mark confirmed */
            nvmc_erase_page(META_PAGE_ADDR);
            ota_meta_t updated_meta = *meta;
            updated_meta.flags = OTA_FLAG_CONFIRMED;
            updated_meta.boot_count = 0;

            const uint32_t *mwords = (const uint32_t *)&updated_meta;
            for (uint32_t i = 0; i < (sizeof(ota_meta_t) / 4); i++) {
                nvmc_write_word(META_PAGE_ADDR + (i * 4), mwords[i]);
            }

            P0_OUTSET = (1UL << PIN_LED);
        }
    }

    /* 4. Boot Selection */
    if (is_valid_image(SLOT_A_BASE)) {
        boot_target(SLOT_A_BASE);
    } else if (is_valid_image(SLOT_B_BASE)) {
        boot_target(SLOT_B_BASE);
    } else {
        /* No valid application found: emergency fallback to UF2 bootloader */
        reboot_to_uf2();
    }

    while (1);
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

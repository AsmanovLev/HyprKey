#include <stdint.h>

/* nRF52840 Memory Map */
#define CLOCK_BASE      0x40000000UL
#define RADIO_BASE      0x40001000UL
#define P0_BASE         0x50000000UL

/* CLOCK Registers */
#define CLOCK_TASKS_HFCLKSTART  (*(volatile uint32_t *)(CLOCK_BASE + 0x000))
#define CLOCK_EVENTS_HFCLKSTARTED (*(volatile uint32_t *)(CLOCK_BASE + 0x100))

/* GPIO P0 Registers */
#define P0_OUT                  (*(volatile uint32_t *)(P0_BASE + 0x504))
#define P0_OUTSET               (*(volatile uint32_t *)(P0_BASE + 0x508))
#define P0_OUTCLR               (*(volatile uint32_t *)(P0_BASE + 0x50C))
#define P0_DIRSET               (*(volatile uint32_t *)(P0_BASE + 0x518))
#define P0_PIN_CNF(n)           (*(volatile uint32_t *)(P0_BASE + 0x700 + ((n) * 4)))

/* RADIO Registers */
#define RADIO_TASKS_TXEN        (*(volatile uint32_t *)(RADIO_BASE + 0x000))
#define RADIO_TASKS_START       (*(volatile uint32_t *)(RADIO_BASE + 0x008))
#define RADIO_TASKS_STOP        (*(volatile uint32_t *)(RADIO_BASE + 0x00C))
#define RADIO_TASKS_DISABLE     (*(volatile uint32_t *)(RADIO_BASE + 0x010))
#define RADIO_EVENTS_READY      (*(volatile uint32_t *)(RADIO_BASE + 0x100))
#define RADIO_EVENTS_END        (*(volatile uint32_t *)(RADIO_BASE + 0x10C))
#define RADIO_EVENTS_DISABLED   (*(volatile uint32_t *)(RADIO_BASE + 0x110))
#define RADIO_SHORTS            (*(volatile uint32_t *)(RADIO_BASE + 0x200))
#define RADIO_PACKETPTR         (*(volatile uint32_t *)(RADIO_BASE + 0x504))
#define RADIO_FREQUENCY         (*(volatile uint32_t *)(RADIO_BASE + 0x508))
#define RADIO_TXPOWER           (*(volatile uint32_t *)(RADIO_BASE + 0x50C))
#define RADIO_MODE              (*(volatile uint32_t *)(RADIO_BASE + 0x510))
#define RADIO_PCNF0             (*(volatile uint32_t *)(RADIO_BASE + 0x514))
#define RADIO_PCNF1             (*(volatile uint32_t *)(RADIO_BASE + 0x518))
#define RADIO_BASE0             (*(volatile uint32_t *)(RADIO_BASE + 0x51C))
#define RADIO_PREFIX0           (*(volatile uint32_t *)(RADIO_BASE + 0x524))
#define RADIO_TXADDRESS         (*(volatile uint32_t *)(RADIO_BASE + 0x52C))
#define RADIO_CRCCNF            (*(volatile uint32_t *)(RADIO_BASE + 0x534))
#define RADIO_CRCPOLY           (*(volatile uint32_t *)(RADIO_BASE + 0x538))
#define RADIO_CRCINIT           (*(volatile uint32_t *)(RADIO_BASE + 0x53C))
#define RADIO_DATAWHITEIV       (*(volatile uint32_t *)(RADIO_BASE + 0x554))

/* On-board Red LED on HW-954 / SuperMini is P0.15 (Active LOW) */
#define LED_PIN 15

/* Delay helper */
static void delay_cycles(volatile uint32_t count) {
    while (count--) {
        __asm__ volatile ("nop");
    }
}

/* BLE Advertising Packet Buffer */
static uint8_t adv_packet[64];

static void radio_init(void) {
    /* Set TX Power to +8 dBm (Maximum power for nRF52840) */
    RADIO_TXPOWER = 0x08;

    /* BLE 1Mbit mode */
    RADIO_MODE = 3;

    /* PCNF0: S0=1 byte (ADV header), Length=8 bits, S1=0 */
    RADIO_PCNF0 = (1UL << 8) | (8UL << 0);

    /* PCNF1: Max length 37 bytes, Base addr length 3, Data whitening enabled */
    RADIO_PCNF1 = (37UL << 0) | (3UL << 16) | (1UL << 25);

    /* BLE Advertising Access Address = 0x8E89BED6 */
    RADIO_BASE0 = 0x89BED600UL;
    RADIO_PREFIX0 = 0x8E;
    RADIO_TXADDRESS = 0;

    /* CRC: 3 bytes, Polynomial 0x00065B, Initial 0x555555, skip address */
    RADIO_CRCCNF = (1UL << 8) | 3UL;
    RADIO_CRCPOLY = 0x0000065BUL;
    RADIO_CRCINIT = 0x00555555UL;

    /* Shortcut: START when READY, DISABLE when END */
    RADIO_SHORTS = (1UL << 0) | (1UL << 1);

    RADIO_PACKETPTR = (uint32_t)adv_packet;
}

static void radio_send(uint8_t channel, uint8_t freq) {
    RADIO_FREQUENCY = freq;
    RADIO_DATAWHITEIV = channel;

    RADIO_EVENTS_READY = 0;
    RADIO_EVENTS_END = 0;
    RADIO_EVENTS_DISABLED = 0;

    RADIO_TASKS_TXEN = 1;
    while (!RADIO_EVENTS_DISABLED);
}

int main(void) {
    /* 1. Start External High-Frequency Crystal (32MHz external OSC for BLE) */
    CLOCK_TASKS_HFCLKSTART = 1;
    while (!CLOCK_EVENTS_HFCLKSTARTED);

    /* 2. Configure LED Pin P0.15 as Output */
    P0_DIRSET = (1UL << LED_PIN);
    P0_PIN_CNF(LED_PIN) = 0x00000001UL;
    P0_OUTCLR = (1UL << LED_PIN); /* Turn LED ON */

    /* 3. Prepare BLE Advertisement Packet:
       PDU Header: ADV_NONCONN_IND (0x02) | TxAdd Random (0x40) = 0x42
       Length: 6 (MAC) + 3 (Flags) + 9 (Complete Name 'hyprkey') = 18 bytes
    */
    adv_packet[0] = 0x42;
    adv_packet[1] = 18;

    /* Static Random MAC: F4:CE:36:01:23:45 (Top 2 bits must be 11 for static random address) */
    adv_packet[2] = 0x45;
    adv_packet[3] = 0x23;
    adv_packet[4] = 0x01;
    adv_packet[5] = 0x36;
    adv_packet[6] = 0xCE;
    adv_packet[7] = 0xF4;

    /* AD Element 1: Flags */
    adv_packet[8]  = 2;    /* Length */
    adv_packet[9]  = 0x01; /* GAP AD TYPE FLAGS */
    adv_packet[10] = 0x06; /* LE General Discoverable, BR/EDR Not Supported */

    /* AD Element 2: Complete Local Name "hyprkey" */
    adv_packet[11] = 8;    /* Length */
    adv_packet[12] = 0x09; /* GAP AD TYPE COMPLETE LOCAL NAME */
    adv_packet[13] = 'h';
    adv_packet[14] = 'y';
    adv_packet[15] = 'p';
    adv_packet[16] = 'r';
    adv_packet[17] = 'k';
    adv_packet[18] = 'e';
    adv_packet[19] = 'y';

    radio_init();

    while (1) {
        /* Blink LED: ON */
        P0_OUTCLR = (1UL << LED_PIN);

        /* Broadcast on 3 standard advertising channels */
        radio_send(37, 2);   /* Channel 37 = 2402 MHz */
        radio_send(38, 26);  /* Channel 38 = 2426 MHz */
        radio_send(39, 80);  /* Channel 39 = 2480 MHz */

        /* LED OFF */
        P0_OUTSET = (1UL << LED_PIN);

        /* Sleep ~150ms before next advertising burst */
        delay_cycles(1500000);
    }

    return 0;
}

/* Reset Handler and Vector Table */
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
const uint32_t vector_table[] = {
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

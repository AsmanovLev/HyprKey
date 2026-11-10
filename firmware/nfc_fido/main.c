#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "fido_u2f.h"
#include "openpgp/openpgp.h"
#include "oath/oath.h"

typedef enum {
    NFC_APPLET_NONE = 0,
    NFC_APPLET_FIDO,
    NFC_APPLET_OPENPGP,
    NFC_APPLET_OATH
} nfc_applet_t;

static nfc_applet_t s_active_nfc_applet = NFC_APPLET_NONE;

/* ==================== nRF52840 Memory Map ==================== */
#define CLOCK_BASE 0x40000000UL
#define UART1_BASE 0x40028000UL
#define P0_BASE    0x50000000UL
#define P1_BASE    0x50000300UL

#define CLOCK_TASKS_HFCLKSTART    (*(volatile uint32_t *)(CLOCK_BASE + 0x000))
#define CLOCK_EVENTS_HFCLKSTARTED (*(volatile uint32_t *)(CLOCK_BASE + 0x100))

#define P0_OUTSET       (*(volatile uint32_t *)(P0_BASE + 0x508))
#define P0_OUTCLR       (*(volatile uint32_t *)(P0_BASE + 0x50C))
#define P0_IN           (*(volatile uint32_t *)(P0_BASE + 0x510))
#define P0_DIRSET       (*(volatile uint32_t *)(P0_BASE + 0x518))
#define P0_PIN_CNF(n)   (*(volatile uint32_t *)(P0_BASE + 0x700 + ((n) * 4)))

#define P1_OUTSET       (*(volatile uint32_t *)(P1_BASE + 0x508))
#define P1_OUTCLR       (*(volatile uint32_t *)(P1_BASE + 0x50C))
#define P1_IN           (*(volatile uint32_t *)(P1_BASE + 0x510))
#define P1_DIRSET       (*(volatile uint32_t *)(P1_BASE + 0x518))
#define P1_PIN_CNF(n)   (*(volatile uint32_t *)(P1_BASE + 0x700 + ((n) * 4)))

/* UARTE1 - CH340 debug, 115200 on P0.10 */
#define UART1_TASKS_STARTTX   (*(volatile uint32_t *)(UART1_BASE + 0x008))
#define UART1_ENABLE          (*(volatile uint32_t *)(UART1_BASE + 0x500))
#define UART1_PSEL_TXD        (*(volatile uint32_t *)(UART1_BASE + 0x50C))
#define UART1_PSEL_RXD        (*(volatile uint32_t *)(UART1_BASE + 0x514))
#define UART1_BAUDRATE        (*(volatile uint32_t *)(UART1_BASE + 0x524))
#define UART1_TXD_PTR         (*(volatile uint32_t *)(UART1_BASE + 0x544))
#define UART1_TXD_MAXCNT      (*(volatile uint32_t *)(UART1_BASE + 0x548))
#define UART1_EVENTS_ENDTX    (*(volatile uint32_t *)(UART1_BASE + 0x120))

#define CNF_OUT     0x00000003UL
#define CNF_IN_PU   0x00000018UL

#define PIN_LED       15   /* P0.15, active LOW */
#define PIN_DBG_TX    10   /* P0.10 -> CH340 RX */

#define PIN_SPI_SCK   17   /* P0.17 */
#define PIN_SPI_MISO  20   /* P0.20 */
#define PIN_SPI_MOSI  22   /* P0.22 */
#define PIN_SPI_CS    24   /* P0.24, active LOW */

#define PIN_NFC_RST   6    /* P1.06 */
#define PIN_NFC_IRQ   4    /* P1.04 */

#define PIN_CS_HI()  (P0_OUTSET = (1UL << PIN_SPI_CS))
#define PIN_CS_LO()  (P0_OUTCLR = (1UL << PIN_SPI_CS))

static void delay_cycles(volatile uint32_t n) { while (n--) __asm__ volatile ("nop"); }
static void delay_us(uint32_t us) { delay_cycles(us * 16); }
static void delay_ms(uint32_t ms) { while (ms--) delay_us(1000); }

static inline void led_on(void)  { P0_OUTCLR = (1UL << PIN_LED); }
static inline void led_off(void) { P0_OUTSET = (1UL << PIN_LED); }

/* ==================== UART1 Output ==================== */
static uint8_t g_dbg_buf[128] __attribute__((aligned(4)));

static void o_str(const char *s) {
    uint8_t len = 0;
    while (s[len] && len < 120) {
        g_dbg_buf[len] = (uint8_t)s[len];
        len++;
    }
    UART1_TXD_PTR    = (uint32_t)g_dbg_buf;
    UART1_TXD_MAXCNT = len;
    UART1_EVENTS_ENDTX = 0;
    UART1_TASKS_STARTTX = 1;
    while (!UART1_EVENTS_ENDTX);
}

static void o_hex(uint8_t b) {
    static const char h[] = "0123456789ABCDEF";
    char s[3] = { h[b >> 4], h[b & 0xF], 0 };
    o_str(s);
}

static void o_hexsp(uint8_t b) {
    o_hex(b);
    o_str(" ");
}

static void o_dec(uint16_t v) {
    char b[6]; int i = 5; b[i] = 0;
    if (v == 0) { o_str("0"); return; }
    while (v && i > 0) { b[--i] = (char)('0' + (v % 10)); v /= 10; }
    o_str(&b[i]);
}

/* ==================== PN532 SPI Core ==================== */
static inline uint8_t spi_xfer(uint8_t b) {
    uint8_t rx = 0;
    for (int i = 0; i < 8; i++) {
        if (b & (1 << i)) P0_OUTSET = (1UL << PIN_SPI_MOSI);
        else             P0_OUTCLR = (1UL << PIN_SPI_MOSI);
        delay_us(4);
        P0_OUTSET = (1UL << PIN_SPI_SCK);
        delay_us(4);
        if (P0_IN & (1UL << PIN_SPI_MISO)) rx |= (uint8_t)(1 << i);
        P0_OUTCLR = (1UL << PIN_SPI_SCK);
        delay_us(4);
    }
    return rx;
}

static void pn532_wakeup(void) {
    PIN_CS_LO(); delay_ms(3); PIN_CS_HI(); delay_ms(3);
}

static bool pn532_wait_irq(uint32_t ms) {
    while (ms--) {
        if ((P1_IN & (1UL << PIN_NFC_IRQ)) == 0) return true;
        delay_ms(1);
    }
    return false;
}

static void pn532_write_frame(const uint8_t *cmd, uint16_t len) {
    uint8_t dcs = 0xD4;
    for (uint16_t i = 0; i < len; i++) dcs += cmd[i];
    dcs = (uint8_t)(0x100 - dcs);

    PIN_CS_LO(); delay_us(20);
    spi_xfer(0x01); /* DATAWRITE */
    spi_xfer(0x00);
    spi_xfer(0x00);
    spi_xfer(0xFF);
    spi_xfer((uint8_t)(len + 1));
    spi_xfer((uint8_t)(0x100 - (len + 1)));
    spi_xfer(0xD4);
    for (uint16_t i = 0; i < len; i++) spi_xfer(cmd[i]);
    spi_xfer(dcs);
    spi_xfer(0x00);
    PIN_CS_HI(); delay_us(40);
}

static bool pn532_consume_ack(void) {
    if (!pn532_wait_irq(150)) {
        o_str("[ACK TIMEOUT] ");
        return false;
    }

    PIN_CS_LO(); delay_us(20);
    spi_xfer(0x03); /* DATAREAD */

    uint8_t ack_buf[6] = {0};
    for (int i = 0; i < 6; i++) ack_buf[i] = spi_xfer(0x00);
    PIN_CS_HI(); delay_us(40);

    o_str("[ACK_RAW: ");
    for (int i = 0; i < 6; i++) o_hexsp(ack_buf[i]);
    o_str("] ");

    return (ack_buf[2] == 0xFF && ack_buf[3] == 0x00 && ack_buf[4] == 0xFF);
}

static int pn532_read_frame(uint8_t *buf, uint16_t maxlen, uint32_t timeout_ms) {
    if (!pn532_wait_irq(timeout_ms)) return -1;

    PIN_CS_LO(); delay_us(20);
    spi_xfer(0x03); /* DATAREAD */

    /* Find start of frame: 0x00 followed immediately by 0xFF */
    bool saw_zero = false;
    bool synced = false;
    for (int i = 0; i < 40; i++) {
        uint8_t b = spi_xfer(0x00);
        if (saw_zero && b == 0xFF) {
            synced = true;
            break;
        }
        saw_zero = (b == 0x00);
    }

    if (!synced) {
        PIN_CS_HI(); delay_us(40);
        return -2;
    }

    uint8_t len = spi_xfer(0x00);
    uint8_t lcs = spi_xfer(0x00);
    if ((uint8_t)(len + lcs) != 0x00) {
        PIN_CS_HI(); delay_us(40);
        return -3; /* Length checksum fail */
    }

    (void)spi_xfer(0x00); /* TFI (0xD5) */

    uint16_t n = (len > 1) ? (len - 1) : 0;
    if (n > maxlen) n = maxlen;

    for (uint16_t i = 0; i < n; i++) buf[i] = spi_xfer(0x00);
    (void)spi_xfer(0x00); /* DCS */
    (void)spi_xfer(0x00); /* Postamble */

    PIN_CS_HI(); delay_us(40);
    return (int)n;
}

static int pn532_exec(const uint8_t *cmd, uint16_t len, uint8_t *rsp, uint16_t maxlen, uint32_t timeout_ms) {
    pn532_write_frame(cmd, len);
    (void)pn532_consume_ack();
    return pn532_read_frame(rsp, maxlen, timeout_ms);
}

/* ==================== NFC Target & FIDO APDU ==================== */

/* Exact Seeed/NXP payload for ISO 14443-4 PICC Target Mode:
 * Mode: 0x05 (PICC only 0x04 | Passive only 0x01)
 * Total bytes = 1 (CMD) + 1 (Mode) + 6 (Mifare) + 18 (FeliCa) + 10 (NFCID3t) + 1 (Lgt) + 1 (Lht) = 38 bytes
 */
static const uint8_t TG_INIT_EXACT_38B[] = {
    0x8C,       /* CMD: TgInitAsTarget */
    0x05,       /* Mode: 0x05 = PICC only + Passive only */
    
    /* MifareParams (exactly 6 bytes): */
    0x04, 0x00,             /* SENS_RES: ATQA (2 bytes) */
    0x79, 0xCC, 0xDD,       /* NFCID1t: 3 bytes UID */
    0x20,                   /* SEL_RES: 0x20 = ISO 14443-4 PICC */

    /* FeliCaParams (exactly 18 bytes): */
    0x01, 0xFE, 0x05, 0x01, 0x86, 0x04, 0x02, 0x02,
    0x03, 0x00, 0x4B, 0x02, 0x4F, 0x49, 0x8A, 0x00,
    0xFF, 0xFF,

    /* NFCID3t (exactly 10 bytes): */
    0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,

    /* General / Historical lengths: */
    0x00,       /* Lgt: Length of General Bytes = 0 */
    0x00        /* Lht: Length of Historical Bytes = 0 */
};

static void pn532_cancel_target(void) {
    PIN_CS_LO(); delay_us(20);
    spi_xfer(0x01);
    spi_xfer(0x00); spi_xfer(0x00); spi_xfer(0xFF);
    spi_xfer(0x00); spi_xfer(0xFF); spi_xfer(0x00);
    PIN_CS_HI(); delay_ms(15);
    pn532_wakeup();
    delay_ms(10);
}

static bool pn532_send_target_data(const uint8_t *data, uint16_t len) {
    if (len > 260) len = 260;
    uint8_t cmd[300];
    cmd[0] = 0x8E; /* TgSetData */
    memcpy(&cmd[1], data, len);

    uint8_t tx_rsp[16];
    int n = pn532_exec(cmd, (uint16_t)(1 + len), tx_rsp, sizeof(tx_rsp), 500);
    return (n >= 2 && tx_rsp[0] == 0x8F && tx_rsp[1] == 0x00);
}

static bool start_target_mode(void) {
    pn532_write_frame(TG_INIT_EXACT_38B, sizeof(TG_INIT_EXACT_38B));
    return pn532_consume_ack();
}

int main(void) {
    CLOCK_TASKS_HFCLKSTART = 1;
    while (!CLOCK_EVENTS_HFCLKSTARTED);

    P0_DIRSET = (1UL << PIN_LED);
    P0_PIN_CNF(PIN_LED) = CNF_OUT;
    led_off();

    P0_DIRSET = (1UL << PIN_DBG_TX);
    P0_OUTSET = (1UL << PIN_DBG_TX);
    P0_PIN_CNF(PIN_DBG_TX) = CNF_OUT;

    P0_DIRSET = (1UL << PIN_SPI_CS) | (1UL << PIN_SPI_SCK) | (1UL << PIN_SPI_MOSI);
    P0_PIN_CNF(PIN_SPI_CS)   = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_SCK)  = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_MOSI) = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_MISO) = CNF_IN_PU;
    PIN_CS_HI();
    P0_OUTCLR = (1UL << PIN_SPI_SCK);

    P1_DIRSET = (1UL << PIN_NFC_RST);
    P1_PIN_CNF(PIN_NFC_RST) = CNF_OUT;
    P1_PIN_CNF(PIN_NFC_IRQ) = CNF_IN_PU;

    UART1_PSEL_TXD   = PIN_DBG_TX;
    UART1_PSEL_RXD   = 0xFFFFFFFFUL;
    UART1_BAUDRATE   = 0x01D7E000UL;
    UART1_ENABLE     = 8;

    o_str("\r\n========================================\r\n");
    o_str("   HyprKey NFC FIDO2 Target Emulation v1.4\r\n");
    o_str("   Exact NXP 38-byte TgInitAsTarget\r\n");
    o_str("========================================\r\n");

    /* Reset PN532 */
    P1_OUTCLR = (1UL << PIN_NFC_RST); delay_ms(20);
    P1_OUTSET = (1UL << PIN_NFC_RST); delay_ms(50);
    pn532_wakeup();

    /* Verify FW */
    static const uint8_t fw_cmd[] = { 0x02 };
    uint8_t rsp[300];
    int n = pn532_exec(fw_cmd, sizeof(fw_cmd), rsp, sizeof(rsp), 200);
    if (n >= 4 && rsp[0] == 0x03) {
        o_str("[NFC] PN532 Ready! Ver: 0x");
        o_hex(rsp[2]);
        o_str(" Rev: 0x");
        o_hex(rsp[3]);
        o_str("\r\n");
    } else {
        o_str("[NFC] FW Check replied n="); o_dec((uint16_t)n);
        if (n > 0) { o_str(" [0]=0x"); o_hex(rsp[0]); }
        o_str("\r\n");
    }

    /* Configure SAM */
    static const uint8_t sam_cmd[] = { 0x14, 0x01, 0x14, 0x01 };
    pn532_exec(sam_cmd, sizeof(sam_cmd), rsp, sizeof(rsp), 200);

    /* SetParameters:
     * 0x20 = fISO14443-4_PICC (enable ISO 14443-4 target emulation and automatic ATS answer)
     * 0x10 = fAutomaticRATS
     * 0x04 = fAutomaticATR_RES
     * Total = 0x34
     */
    static const uint8_t set_params_cmd[] = { 0x12, 0x34 };
    n = pn532_exec(set_params_cmd, sizeof(set_params_cmd), rsp, sizeof(rsp), 200);
    if (n >= 1 && rsp[0] == 0x13) {
        o_str("[NFC] SetParameters OK (fISO14443-4_PICC enabled)!\r\n");
    } else {
        o_str("[NFC] SetParameters replied code: 0x");
        if (n >= 1) o_hex(rsp[0]);
        o_str("\r\n");
    }

    /* Maximize RxGain: CIU_RFCfg (0x6316) -> 0x78 (48 dB) */
    static const uint8_t rxgain_cmd[] = { 0x08, 0x63, 0x16, 0x78 };
    n = pn532_exec(rxgain_cmd, sizeof(rxgain_cmd), rsp, sizeof(rsp), 200);
    if (n >= 1 && rsp[0] == 0x09) {
        o_str("[NFC] CIU_RFCfg RxGain set to 48dB (0x78) OK!\r\n");
    } else {
        o_str("[NFC] CIU_RFCfg WriteRegister replied code: 0x");
        if (n >= 1) o_hex(rsp[0]);
        o_str("\r\n");
    }

    /* Explicitly ensure PN532 RF field transmitter is OFF in Target Mode */
    static const uint8_t rf_off_cmd[] = { 0x32, 0x01, 0x00 };
    pn532_exec(rf_off_cmd, sizeof(rf_off_cmd), rsp, sizeof(rsp), 200);
    o_str("[NFC] RF Transmitter Field set to OFF (Passive PICC)\r\n");

    fido_init();
    openpgp_init();
    oath_init();
    o_str("[CRYPTO] FIDO, OpenPGP Card 3.4 & YubiKey OATH Initialized\r\n");

    while (1) {
        o_str("[NFC] Arming Target (38B)... ");
        led_off();

        if (!start_target_mode()) {
            o_str("ACK FAIL! Canceling target...\r\n");
            pn532_cancel_target();
            delay_ms(50);
            continue;
        }

        o_str("ACK OK! Listening...\r\n");

        /* Wait up to 1200ms for phone field */
        n = pn532_read_frame(rsp, sizeof(rsp), 1200);

        if (n < 0) {
            pn532_cancel_target();
            continue;
        }

        /* 0x8D = Response to TgInitAsTarget */
        if (n >= 1 && rsp[0] == 0x8D) {
            led_on();
            o_str("\r\n[PHONE] >>> PHONE ACTIVATED TARGET (0x8D)! <<<\r\n");
            if (n >= 2) {
                o_str("[PHONE] Mode byte: 0x"); o_hex(rsp[1]); o_str("\r\n");
            }
            if (n > 2) {
                o_str("[PHONE] Initiator frame ("); o_dec((uint16_t)(n - 2)); o_str("B): ");
                for (int i = 2; i < n; i++) o_hexsp(rsp[i]);
                o_str("\r\n");
            }

            /* APDU exchange loop */
            while (1) {
                static const uint8_t tg_get_data[] = { 0x86 };
                n = pn532_exec(tg_get_data, sizeof(tg_get_data), rsp, sizeof(rsp), 2000);

                if (n < 2 || rsp[0] != 0x87) {
                    o_str("[PHONE] Session closed / link lost.\r\n");
                    break;
                }

                uint8_t status_byte = rsp[1];
                if (status_byte != 0x00) {
                    o_str("[PHONE] Status error: 0x"); o_hex(status_byte); o_str("\r\n");
                    break;
                }

                uint16_t apdu_len = (uint16_t)(n - 2);
                uint8_t *apdu = &rsp[2];

                o_str("[APDU] RECV ("); o_dec(apdu_len); o_str("B): ");
                for (uint16_t i = 0; i < (apdu_len < 16 ? apdu_len : 16); i++) o_hexsp(apdu[i]);
                if (apdu_len > 16) o_str("...");
                o_str("\r\n");

                /* Detect applet on SELECT AID (00 A4 04 ...) */
                if (apdu_len >= 5 && apdu[1] == 0xA4 && apdu[2] == 0x04) {
                    uint16_t aid_len = apdu[4];
                    const uint8_t *aid = apdu + 5;
                    if (aid_len == 0 && apdu_len >= 7) {
                        aid_len = ((uint16_t)apdu[5] << 8) | apdu[6];
                        aid = apdu + 7;
                    }
                    if (aid_len >= 6 && memcmp(aid, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
                        s_active_nfc_applet = NFC_APPLET_OPENPGP;
                        o_str("[NFC] Applet selected: OpenPGP\r\n");
                    } else if (aid_len >= 7 && memcmp(aid, "\xA0\x00\x00\x05\x27\x21\x01", 7) == 0) {
                        s_active_nfc_applet = NFC_APPLET_OATH;
                        o_str("[NFC] Applet selected: Yubico OATH\r\n");
                    } else if (aid_len >= 8 && memcmp(aid, "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8) == 0) {
                        s_active_nfc_applet = NFC_APPLET_FIDO;
                        o_str("[NFC] Applet selected: FIDO2/U2F\r\n");
                    }
                }

                static uint8_t applet_rsp_buf[700];
                int rsp_len = 0;
                if (s_active_nfc_applet == NFC_APPLET_OPENPGP) {
                    rsp_len = openpgp_process_apdu(apdu, apdu_len, applet_rsp_buf, sizeof(applet_rsp_buf));
                } else if (s_active_nfc_applet == NFC_APPLET_OATH) {
                    rsp_len = oath_process_apdu(apdu, apdu_len, applet_rsp_buf, sizeof(applet_rsp_buf));
                } else {
                    rsp_len = fido_process_apdu(apdu, apdu_len, applet_rsp_buf, sizeof(applet_rsp_buf));
                }

                if (rsp_len > 0) {
                    o_str("[NFC] Replied ("); o_dec((uint16_t)rsp_len); o_str("B): ");
                    for (int i = 0; i < (rsp_len < 6 ? rsp_len : 6); i++) o_hexsp(applet_rsp_buf[i]);
                    o_str("\r\n");
                    if (!pn532_send_target_data(applet_rsp_buf, (uint16_t)rsp_len)) {
                        o_str("[NFC] Send target data error!\r\n");
                        break;
                    }
                }
            }

            led_off();
            delay_ms(300);
        }
    }

    return 0;
}

/* Startup Vector Table */
extern uint32_t _estack, _etext, _sdata, _edata, _sbss, _ebss;

void Reset_Handler(void) {
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0;
    main();
    while (1);
}

void Default_Handler(void) { while (1); }

__attribute__((section(".isr_vector"), used))
const uint32_t vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0, 0, 0, 0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

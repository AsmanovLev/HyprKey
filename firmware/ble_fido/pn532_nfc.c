#include "pn532_nfc.h"
#include <string.h>
#include "fido_u2f.h"
#include "openpgp/openpgp.h"
#include "oath/oath.h"
#include "piv/piv.h"

extern void uart_puts(const char *s);
extern void uart_puthex8(uint8_t b);

/* ==================== nRF52840 Pin Definitions ==================== */
#define P0_BASE    0x50000000UL
#define P1_BASE    0x50000300UL

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

#define CNF_OUT     0x00000003UL
#define CNF_IN_PU   0x00000018UL

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

/* ==================== Low-Level SPI ==================== */

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
    spi_xfer(0x00); spi_xfer(0x00); spi_xfer(0xFF);
    uint8_t flen = (uint8_t)(len + 1);
    spi_xfer(flen);
    spi_xfer((uint8_t)(0x100 - flen));
    spi_xfer(0xD4);
    for (uint16_t i = 0; i < len; i++) spi_xfer(cmd[i]);
    spi_xfer(dcs);
    spi_xfer(0x00);
    PIN_CS_HI();
}

static bool pn532_consume_ack(void) {
    if (!pn532_wait_irq(150)) return false;
    PIN_CS_LO(); delay_us(20);
    spi_xfer(0x03); /* DATAREAD */
    uint8_t ack[6];
    for (int i = 0; i < 6; i++) ack[i] = spi_xfer(0x00);
    PIN_CS_HI();
    return (ack[0] == 0x00 && ack[1] == 0x00 && ack[2] == 0xFF &&
            ack[3] == 0x00 && ack[4] == 0xFF && ack[5] == 0x00);
}

static int pn532_read_frame(uint8_t *buf, uint16_t maxlen, uint32_t timeout_ms) {
    if (!pn532_wait_irq(timeout_ms)) return -1;
    PIN_CS_LO(); delay_us(20);
    spi_xfer(0x03); /* DATAREAD */
    for (int i = 0; i < 3; i++) spi_xfer(0x00); /* 00 00 FF */
    uint8_t len = spi_xfer(0x00);
    spi_xfer(0x00); /* LCS */
    uint8_t tfi = spi_xfer(0x00);
    if (tfi != 0xD5) { PIN_CS_HI(); return -2; }
    uint8_t dlen = (uint8_t)(len - 1);
    int read_bytes = (dlen < maxlen) ? dlen : maxlen;
    for (int i = 0; i < read_bytes; i++) buf[i] = spi_xfer(0x00);
    for (int i = read_bytes; i < dlen; i++) spi_xfer(0x00);
    spi_xfer(0x00); /* DCS */
    spi_xfer(0x00); /* Postamble */
    PIN_CS_HI();
    return read_bytes;
}

static int pn532_exec(const uint8_t *cmd, uint16_t len, uint8_t *rsp, uint16_t maxlen, uint32_t timeout_ms) {
    pn532_write_frame(cmd, len);
    (void)pn532_consume_ack();
    return pn532_read_frame(rsp, maxlen, timeout_ms);
}

/* ==================== ISO 14443-4 Target Configuration ==================== */

static const uint8_t TG_INIT_EXACT_38B[] = {
    0x8C,       /* CMD: TgInitAsTarget */
    0x05,       /* Mode: 0x05 = PICC only + Passive only */
    
    /* MifareParams (6 bytes): */
    0x04, 0x00,             /* SENS_RES: ATQA */
    0x79, 0xCC, 0xDD,       /* NFCID1t: 3 bytes UID */
    0x20,                   /* SEL_RES: 0x20 = ISO 14443-4 PICC */

    /* FeliCaParams (18 bytes): */
    0x01, 0xFE, 0x05, 0x01, 0x86, 0x04, 0x02, 0x02,
    0x03, 0x00, 0x4B, 0x02, 0x4F, 0x49, 0x8A, 0x00,
    0xFF, 0xFF,

    /* NFCID3t (10 bytes): */
    0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,

    /* Length of General / Historical Bytes: */
    0x00, 0x00
};

static bool pn532_start_target_mode(void) {
    pn532_write_frame(TG_INIT_EXACT_38B, sizeof(TG_INIT_EXACT_38B));
    return pn532_consume_ack();
}

static bool pn532_send_target_data(const uint8_t *data, uint16_t len) {
    if (len > 260) len = 260;
    static uint8_t cmd[300];
    cmd[0] = 0x8E; /* TgSetData */
    memcpy(&cmd[1], data, len);

    uint8_t tx_rsp[16];
    int n = pn532_exec(cmd, (uint16_t)(1 + len), tx_rsp, sizeof(tx_rsp), 500);
    return (n >= 2 && tx_rsp[0] == 0x8F && tx_rsp[1] == 0x00);
}

/* ==================== State Machine & Multi-Applet Router ==================== */

typedef enum {
    NFC_STATE_UNINIT = 0,
    NFC_STATE_ARMED_WAIT_INITIATOR,
    NFC_STATE_CONNECTED_WAIT_APDU
} nfc_state_t;

typedef enum {
    NFC_APPLET_NONE = 0,
    NFC_APPLET_FIDO,
    NFC_APPLET_OPENPGP,
    NFC_APPLET_OATH,
    NFC_APPLET_PIV
} nfc_applet_t;

static nfc_state_t  s_nfc_state = NFC_STATE_UNINIT;
static nfc_applet_t s_nfc_applet = NFC_APPLET_NONE;
static uint8_t      s_nfc_buf[350];
static uint8_t      s_applet_rsp[700];

bool pn532_nfc_init(void) {
    /* Setup GPIO directions */
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

    /* Hardware reset PN532 */
    P1_OUTCLR = (1UL << PIN_NFC_RST);
    delay_ms(20);
    P1_OUTSET = (1UL << PIN_NFC_RST);
    delay_ms(25);

    pn532_wakeup();

    /* Probe GetFirmwareVersion (0x02) */
    static const uint8_t get_fw_cmd[] = { 0x02 };
    uint8_t fw_rsp[16];
    int n = pn532_exec(get_fw_cmd, sizeof(get_fw_cmd), fw_rsp, sizeof(fw_rsp), 200);
    if (n < 4 || fw_rsp[0] != 0x03) {
        uart_puts("[NFC] PN532 not detected on SPI!\r\n");
        s_nfc_state = NFC_STATE_UNINIT;
        return false;
    }

    uart_puts("[NFC] PN532 detected! Firmware: IC 0x");
    uart_puthex8(fw_rsp[1]);
    uart_puts(" Ver 0x");
    uart_puthex8(fw_rsp[2]);
    uart_puts("\r\n");

    /* Arm ISO 14443-4 Target Mode */
    if (!pn532_start_target_mode()) {
        uart_puts("[NFC] Failed to arm Target Mode ACK\r\n");
        s_nfc_state = NFC_STATE_UNINIT;
        return false;
    }

    uart_puts("[NFC] Arming Target Mode: OK! Listening for NFC initiator...\r\n");
    s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
    s_nfc_applet = NFC_APPLET_NONE;
    return true;
}

bool pn532_nfc_is_active(void) {
    return (s_nfc_state != NFC_STATE_UNINIT);
}

void pn532_nfc_poll(void) {
    if (s_nfc_state == NFC_STATE_UNINIT) return;

    /* Non-blocking: If IRQ is HIGH (1), PN532 is idle/waiting. Return immediately! */
    if (P1_IN & (1UL << PIN_NFC_IRQ)) return;

    /* IRQ is LOW (0): PN532 has finished a command or detected an initiator! */
    if (s_nfc_state == NFC_STATE_ARMED_WAIT_INITIATOR) {
        int n = pn532_read_frame(s_nfc_buf, sizeof(s_nfc_buf), 50);
        if (n >= 2 && s_nfc_buf[0] == 0x8D) {
            uart_puts("[NFC] Phone/Initiator tapped! Mode: 0x");
            uart_puthex8(s_nfc_buf[1]);
            uart_puts("\r\n");

            /* Arm TgGetData to receive the first APDU */
            static const uint8_t tg_get_data[] = { 0x86 };
            pn532_write_frame(tg_get_data, sizeof(tg_get_data));
            pn532_consume_ack();

            s_nfc_state = NFC_STATE_CONNECTED_WAIT_APDU;
        } else {
            /* False alarm or timeout -> Re-arm Target Mode */
            pn532_start_target_mode();
        }
        return;
    }

    if (s_nfc_state == NFC_STATE_CONNECTED_WAIT_APDU) {
        int n = pn532_read_frame(s_nfc_buf, sizeof(s_nfc_buf), 50);
        if (n < 2 || s_nfc_buf[0] != 0x87 || s_nfc_buf[1] != 0x00) {
            uart_puts("[NFC] Link lost / transaction closed. Re-arming Target...\r\n");
            pn532_start_target_mode();
            s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
            s_nfc_applet = NFC_APPLET_NONE;
            return;
        }

        uint16_t apdu_len = (uint16_t)(n - 2);
        const uint8_t *apdu = &s_nfc_buf[2];

        uart_puts("[NFC] IN: ");
        for (uint16_t i = 0; i < (apdu_len > 12 ? 12 : apdu_len); i++) uart_puthex8(apdu[i]);
        uart_puts("\r\n");

        /* Inspect SELECT AID APDU (00 A4 04 ...) */
        if (apdu_len >= 5 && apdu[1] == 0xA4 && apdu[2] == 0x04) {
            uint16_t aid_len = apdu[4];
            const uint8_t *aid = apdu + 5;
            if (aid_len == 0 && apdu_len >= 7) {
                aid_len = ((uint16_t)apdu[5] << 8) | apdu[6];
                aid = apdu + 7;
            }

            if (aid_len >= 6 && memcmp(aid, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
                s_nfc_applet = NFC_APPLET_OPENPGP;
                uart_puts("[NFC] Active Applet -> OpenPGP Card 3.4\r\n");
            } else if (aid_len >= 7 && memcmp(aid, "\xA0\x00\x00\x05\x27\x21\x01", 7) == 0) {
                s_nfc_applet = NFC_APPLET_OATH;
                uart_puts("[NFC] Active Applet -> Yubico OATH\r\n");
            } else if (aid_len >= 11 && memcmp(aid, "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00", 11) == 0) {
                s_nfc_applet = NFC_APPLET_PIV;
                uart_puts("[NFC] Active Applet -> NIST PIV\r\n");
            } else if (aid_len >= 8 && memcmp(aid, "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8) == 0) {
                s_nfc_applet = NFC_APPLET_FIDO;
                uart_puts("[NFC] Active Applet -> FIDO2 / U2F\r\n");
            }
        }

        /* Dispatch APDU to selected applet */
        int rsp_len = 0;
        if (apdu_len >= 2 && apdu[1] == 0xC0) {
            /* ISO 7816-4 GET RESPONSE chaining */
            if (s_nfc_applet == NFC_APPLET_OPENPGP) {
                rsp_len = openpgp_process_apdu(apdu, apdu_len, s_applet_rsp, 240);
            } else {
                rsp_len = fido_process_apdu(apdu, apdu_len, s_applet_rsp, 240);
            }
        } else if (s_nfc_applet == NFC_APPLET_OPENPGP) {
            rsp_len = openpgp_process_apdu(apdu, apdu_len, s_applet_rsp, 240);
        } else if (s_nfc_applet == NFC_APPLET_OATH) {
            rsp_len = oath_process_apdu(apdu, apdu_len, s_applet_rsp, 240);
        } else if (s_nfc_applet == NFC_APPLET_PIV) {
            rsp_len = piv_process_apdu(apdu, apdu_len, s_applet_rsp, 240);
        } else {
            rsp_len = fido_process_apdu(apdu, apdu_len, s_applet_rsp, 240);
        }

        uart_puts("[NFC] OUT: len=");
        uart_puthex8((uint8_t)rsp_len);
        if (rsp_len >= 2) {
            uart_puts(" SW=");
            uart_puthex8(s_applet_rsp[rsp_len - 2]);
            uart_puthex8(s_applet_rsp[rsp_len - 1]);
        }
        uart_puts("\r\n");

        if (rsp_len > 0) {
            if (!pn532_send_target_data(s_applet_rsp, (uint16_t)rsp_len)) {
                uart_puts("[NFC] Send target data error!\r\n");
                pn532_start_target_mode();
                s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
                s_nfc_applet = NFC_APPLET_NONE;
                return;
            }

            /* Arm TgGetData for next incoming APDU */
            static const uint8_t tg_get_data[] = { 0x86 };
            pn532_write_frame(tg_get_data, sizeof(tg_get_data));
            pn532_consume_ack();
        }
    }
}

uint16_t pn532_scan_tag(uint8_t *out, uint16_t max_out) {
    if (max_out < 64) return 0;

    uart_puts("[NFC] Scanning for passive tag (Reader Mode)...\r\n");

    /* 1. Hardware reset PN532 to cleanly exit Target Mode */
    P1_OUTCLR = (1UL << PIN_NFC_RST);
    delay_ms(10);
    P1_OUTSET = (1UL << PIN_NFC_RST);
    delay_ms(25);
    pn532_wakeup();

    /* 2. Configure SAM (Normal mode) */
    static const uint8_t sam_cmd[] = { 0x14, 0x01, 0x14, 0x01 };
    uint8_t tmp_rsp[64];
    pn532_exec(sam_cmd, sizeof(sam_cmd), tmp_rsp, sizeof(tmp_rsp), 100);

    /* 3. InListPassiveTarget (0x4A, 0x01, 0x00) */
    static const uint8_t in_list_cmd[] = { 0x4A, 0x01, 0x00 };
    int n = pn532_exec(in_list_cmd, sizeof(in_list_cmd), tmp_rsp, sizeof(tmp_rsp), 300);

    uint16_t out_len = 0;
    if (n >= 7 && tmp_rsp[0] == 0x4B && tmp_rsp[1] > 0) {
        /* Target found! */
        uint8_t atqa_hi = tmp_rsp[3];
        uint8_t atqa_lo = tmp_rsp[4];
        uint8_t sak     = tmp_rsp[5];
        uint8_t uid_len = tmp_rsp[6];
        if (uid_len > 10) uid_len = 10;

        uart_puts("[NFC] Tag Found! SAK=0x");
        uart_puthex8(sak);
        uart_puts(" UID len=");
        uart_puthex8(uid_len);
        uart_puts(" UID=");
        for (int i = 0; i < uid_len; i++) uart_puthex8(tmp_rsp[7 + i]);
        uart_puts("\r\n");

        out[out_len++] = 0x01; /* Found tag */
        out[out_len++] = atqa_hi;
        out[out_len++] = atqa_lo;
        out[out_len++] = sak;
        out[out_len++] = uid_len;
        memcpy(&out[out_len], &tmp_rsp[7], uid_len);
        out_len += uid_len;

        /* Check ATS if present */
        if (n > 7 + uid_len) {
            uint8_t ats_len = tmp_rsp[7 + uid_len];
            if (ats_len > 0 && n >= 8 + uid_len + ats_len) {
                out[out_len++] = ats_len;
                memcpy(&out[out_len], &tmp_rsp[8 + uid_len], ats_len);
                out_len += ats_len;
            } else {
                out[out_len++] = 0;
            }
        } else {
            out[out_len++] = 0;
        }

        /* If NTAG / Ultralight (sak == 0x00), try reading page 4 (NDEF header) */
        if (sak == 0x00) {
            static const uint8_t read_p4[] = { 0x40, 0x01, 0x30, 0x04 };
            uint8_t p4_rsp[32];
            int p4_n = pn532_exec(read_p4, sizeof(read_p4), p4_rsp, sizeof(p4_rsp), 200);
            if (p4_n >= 18 && p4_rsp[0] == 0x41 && p4_rsp[1] == 0x00) {
                out[out_len++] = 16; /* 16 bytes user data */
                memcpy(&out[out_len], &p4_rsp[2], 16);
                out_len += 16;
            } else {
                out[out_len++] = 0;
            }
        } else {
            out[out_len++] = 0;
        }
    } else {
        uart_puts("[NFC] No tag in RF field\r\n");
        out[out_len++] = 0x00; /* No tag found */
    }

    /* 4. Re-arm Target Mode so key continues emulating OpenPGP/FIDO */
    pn532_start_target_mode();
    s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
    s_nfc_applet = NFC_APPLET_NONE;

    out[out_len++] = 0x90;
    out[out_len++] = 0x00;
    return out_len;
}

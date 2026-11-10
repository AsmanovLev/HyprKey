#include "pn532_nfc.h"
#include <string.h>
#include "fido_u2f.h"
#include "openpgp/openpgp.h"
#include "oath/oath.h"
#include "piv/piv.h"
#include "device_log.h"
#include "storage_flash.h"
#include "sha256/sha256.h"
#include "crypto_consttime.h"

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

#define PIN_LED 15

static void led_blink(int count, int delay_ms_val) {
    for (int i = 0; i < count; i++) {
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON */
        delay_ms(delay_ms_val);
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */
        delay_ms(delay_ms_val);
    }
}

/* ==================== State Machine & Multi-Applet Router ==================== */

typedef enum {
    NFC_STATE_UNINIT = 0,
    NFC_STATE_ARMED_WAIT_INITIATOR,
    NFC_STATE_CONNECTED_WAIT_APDU,
    NFC_STATE_LOCKED_WAIT_KEY
} nfc_state_t;

typedef enum {
    NFC_APPLET_NONE = 0,
    NFC_APPLET_FIDO,
    NFC_APPLET_OPENPGP,
    NFC_APPLET_OATH,
    NFC_APPLET_PIV
} nfc_applet_t;

static nfc_state_t       s_nfc_state = NFC_STATE_UNINIT;
static nfc_applet_t      s_nfc_applet = NFC_APPLET_NONE;
static uint8_t           s_nfc_buf[300];

/* Physical Presence Lock State */
static nfc_lock_config_t s_lock_cfg = { 0 };
static bool              s_is_locked = false;

/* Variant 3: Time-Sharing Poller State */
static pn532_tag_info_t  s_last_detected_tag = { 0 };
static uint32_t          s_last_probe_ms = 0;
#define NFC_PROBE_INTERVAL_MS 500U

/* ==================== Low-Level InDataExchange (ISO 14443-4 APDU) ==================== */

static int pn532_in_data_exchange(uint8_t tg, const uint8_t *cmd, uint16_t cmd_len, uint8_t *rsp, uint16_t max_rsp, uint32_t timeout_ms) {
    static uint8_t frame[260];
    if (cmd_len + 2 > sizeof(frame)) return -1;
    frame[0] = 0x40; /* InDataExchange */
    frame[1] = tg;   /* Target number (1) */
    memcpy(&frame[2], cmd, cmd_len);

    uint8_t raw_rsp[300];
    int n = pn532_exec(frame, (uint16_t)(2 + cmd_len), raw_rsp, sizeof(raw_rsp), timeout_ms);
    if (n < 2 || raw_rsp[0] != 0x41 || raw_rsp[1] != 0x00) {
        return -2; /* Exchange failed or card returned error */
    }
    int data_len = n - 2;
    if (data_len > (int)max_rsp) data_len = (int)max_rsp;
    memcpy(rsp, &raw_rsp[2], data_len);
    return data_len;
}

/* Query EMV Contactless Card (PPSE / Mir / Visa / Mastercard) and compute response SHA-256 */
static bool pn532_query_emv_card(uint8_t hash_out[32]) {
    uint8_t card_rsp[256];

    /* 1. PPSE (2PAY.SYS.DDF01) */
    static const uint8_t ppse_select[] = {
        0x00, 0xA4, 0x04, 0x00, 0x0E,
        0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00
    };
    int n = pn532_in_data_exchange(1, ppse_select, sizeof(ppse_select), card_rsp, sizeof(card_rsp), 150);

    /* 2. Direct Mir AID: A0 00 00 06 58 01 01 */
    if (n < 2 || card_rsp[n - 2] != 0x90 || card_rsp[n - 1] != 0x00) {
        static const uint8_t mir_select[] = {
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x06, 0x58, 0x01, 0x01, 0x00
        };
        n = pn532_in_data_exchange(1, mir_select, sizeof(mir_select), card_rsp, sizeof(card_rsp), 150);
    }

    /* 3. Direct Visa AID: A0 00 00 00 03 10 10 */
    if (n < 2 || card_rsp[n - 2] != 0x90 || card_rsp[n - 1] != 0x00) {
        static const uint8_t visa_select[] = {
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00
        };
        n = pn532_in_data_exchange(1, visa_select, sizeof(visa_select), card_rsp, sizeof(card_rsp), 150);
    }

    /* 4. Direct Mastercard AID: A0 00 00 00 04 10 10 */
    if (n < 2 || card_rsp[n - 2] != 0x90 || card_rsp[n - 1] != 0x00) {
        static const uint8_t mc_select[] = {
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x00
        };
        n = pn532_in_data_exchange(1, mc_select, sizeof(mc_select), card_rsp, sizeof(card_rsp), 150);
    }

    if (n >= 2 && card_rsp[n - 2] == 0x90 && card_rsp[n - 1] == 0x00) {
        sha256_hash(card_rsp, (size_t)n, hash_out);
        return true;
    }
    return false;
}

bool pn532_nfc_init(void) {
    P0_PIN_CNF(PIN_SPI_SCK)  = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_MOSI) = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_CS)   = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_MISO) = CNF_IN_PU;

    P1_PIN_CNF(PIN_NFC_RST)  = CNF_OUT;
    P1_PIN_CNF(PIN_NFC_IRQ)  = CNF_IN_PU;

    PIN_CS_HI();
    P0_OUTCLR = (1UL << PIN_SPI_SCK);

    /* Hardware reset pulse */
    P1_OUTCLR = (1UL << PIN_NFC_RST);
    delay_ms(10);
    P1_OUTSET = (1UL << PIN_NFC_RST);
    delay_ms(20);

    pn532_wakeup();

    /* Probe firmware version */
    static const uint8_t get_fw[] = { 0x02 };
    uint8_t rsp[16];
    int n = pn532_exec(get_fw, sizeof(get_fw), rsp, sizeof(rsp), 100);
    if (n < 4 || rsp[0] != 0x03) {
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xEA, 0, 0);
        return false;
    }

    /* Configure SAM (Normal Mode) */
    static const uint8_t sam_cfg[] = { 0x14, 0x01, 0x14, 0x01 };
    pn532_exec(sam_cfg, sizeof(sam_cfg), rsp, sizeof(rsp), 100);

    /* Configure MaxRetries: MxRtyPassiveActivation = 1 (try once, fast non-blocking poll) */
    static const uint8_t rty_cfg[] = { 0x32, 0x05, 0x00, 0x01, 0x01 };
    pn532_exec(rty_cfg, sizeof(rty_cfg), rsp, sizeof(rsp), 100);

    /* Load Physical Presence Lock Configuration */
    storage_get_nfc_lock_config(&s_lock_cfg);
    if (s_lock_cfg.lock_mode != NFC_LOCK_MODE_DISABLED) {
        s_is_locked = true;
        s_nfc_state = NFC_STATE_LOCKED_WAIT_KEY;
        /* Reader RF ON: keep reader active continuously awaiting the unlock key/card */
        static const uint8_t rf_cfg[] = { 0x32, 0x01, 0x01 };
        pn532_exec(rf_cfg, sizeof(rf_cfg), rsp, sizeof(rsp), 50);
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xEB, s_lock_cfg.lock_mode, 1);
    } else {
        s_is_locked = false;
        /* Arm ISO 14443-4 Target Mode */
        if (!pn532_start_target_mode()) {
            dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_ERROR, 0xEA, 1, 0);
            return false;
        }
        s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, 0xEA, 2, 0);
    }

    s_nfc_applet = NFC_APPLET_NONE;
    return true;
}

bool pn532_is_locked(void) {
    return s_is_locked;
}

void pn532_lock_force(void) {
    if (s_lock_cfg.lock_mode != NFC_LOCK_MODE_DISABLED) {
        s_is_locked = true;
        s_nfc_state = NFC_STATE_LOCKED_WAIT_KEY;
        static const uint8_t rf_cfg[] = { 0x32, 0x01, 0x01 };
        uint8_t tmp[16];
        pn532_exec(rf_cfg, sizeof(rf_cfg), tmp, sizeof(tmp), 50);
    }
}

bool pn532_enroll_tag_uid(uint8_t *uid_out, uint8_t *uid_len_out) {
    pn532_wakeup();
    static const uint8_t sam_cfg[] = { 0x14, 0x01, 0x14, 0x01 };
    uint8_t tmp[32];
    pn532_exec(sam_cfg, sizeof(sam_cfg), tmp, sizeof(tmp), 50);

    static const uint8_t rf_cfg[] = { 0x32, 0x01, 0x01 };
    pn532_exec(rf_cfg, sizeof(rf_cfg), tmp, sizeof(tmp), 50);

    static const uint8_t in_list_1[] = { 0x4A, 0x01, 0x00 };
    int n = pn532_exec(in_list_1, sizeof(in_list_1), tmp, sizeof(tmp), 150);
    if (n >= 7 && tmp[0] == 0x4B && tmp[1] > 0) {
        uint8_t ulen = tmp[6];
        if (ulen > 10) ulen = 10;
        s_lock_cfg.lock_mode = NFC_LOCK_MODE_STATIC_UID;
        s_lock_cfg.enrolled_uid_len = ulen;
        memcpy(s_lock_cfg.enrolled_uid, &tmp[7], ulen);
        memset(s_lock_cfg.enrolled_card_hash, 0, 32);

        storage_set_nfc_lock_config(&s_lock_cfg);
        s_is_locked = false;

        if (uid_out) memcpy(uid_out, s_lock_cfg.enrolled_uid, ulen);
        if (uid_len_out) *uid_len_out = ulen;

        pn532_start_target_mode();
        s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
        return true;
    }

    pn532_start_target_mode();
    s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
    return false;
}

bool pn532_enroll_emv_crypto(uint8_t card_hash_out[32]) {
    pn532_wakeup();
    static const uint8_t sam_cfg[] = { 0x14, 0x01, 0x14, 0x01 };
    uint8_t tmp[32];
    pn532_exec(sam_cfg, sizeof(sam_cfg), tmp, sizeof(tmp), 50);

    static const uint8_t rf_cfg[] = { 0x32, 0x01, 0x01 };
    pn532_exec(rf_cfg, sizeof(rf_cfg), tmp, sizeof(tmp), 50);

    static const uint8_t in_list_1[] = { 0x4A, 0x01, 0x00 };
    int n = pn532_exec(in_list_1, sizeof(in_list_1), tmp, sizeof(tmp), 150);
    if (n >= 7 && tmp[0] == 0x4B && tmp[1] > 0) {
        uint8_t hash[32];
        if (pn532_query_emv_card(hash)) {
            s_lock_cfg.lock_mode = NFC_LOCK_MODE_EMV_CRYPTO;
            s_lock_cfg.enrolled_uid_len = tmp[6] > 10 ? 10 : tmp[6];
            memcpy(s_lock_cfg.enrolled_uid, &tmp[7], s_lock_cfg.enrolled_uid_len);
            memcpy(s_lock_cfg.enrolled_card_hash, hash, 32);

            storage_set_nfc_lock_config(&s_lock_cfg);
            s_is_locked = false;

            if (card_hash_out) memcpy(card_hash_out, hash, 32);

            pn532_start_target_mode();
            s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
            return true;
        }
    }

    pn532_start_target_mode();
    s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
    return false;
}

bool pn532_disable_lock(void) {
    memset(&s_lock_cfg, 0, sizeof(s_lock_cfg));
    s_lock_cfg.lock_mode = NFC_LOCK_MODE_DISABLED;
    storage_disable_nfc_lock();
    s_is_locked = false;
    pn532_start_target_mode();
    s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
    return true;
}

void pn532_get_lock_status(uint8_t *lock_mode, bool *is_locked, uint8_t *uid_len, uint8_t *uid, uint8_t *card_hash) {
    if (lock_mode) *lock_mode = s_lock_cfg.lock_mode;
    if (is_locked) *is_locked = s_is_locked;
    if (uid_len) *uid_len = s_lock_cfg.enrolled_uid_len;
    if (uid) memcpy(uid, s_lock_cfg.enrolled_uid, 10);
    if (card_hash) memcpy(card_hash, s_lock_cfg.enrolled_card_hash, 32);
}

bool pn532_nfc_is_active(void) {
    return (s_nfc_state != NFC_STATE_UNINIT);
}

bool pn532_get_last_tag(pn532_tag_info_t *info) {
    if (!info) return false;
    memcpy(info, &s_last_detected_tag, sizeof(pn532_tag_info_t));
    return s_last_detected_tag.detected;
}

/* ==================== Variant 3: Time-Sharing Poller ==================== */

void pn532_nfc_poll(void) {
    if (s_nfc_state == NFC_STATE_UNINIT) return;

    if (s_nfc_state == NFC_STATE_LOCKED_WAIT_KEY) {
        /* Reader remains continuously active polling every 80 ms */
        if (g_uptime_ms - s_last_probe_ms >= 80U) {
            s_last_probe_ms = g_uptime_ms;

            /* Gentle heartbeat LED pulse while awaiting key */
            if (((g_uptime_ms / 400U) % 2) == 0) {
                P0_OUTCLR = (1UL << PIN_LED);
            } else {
                P0_OUTSET = (1UL << PIN_LED);
            }

            static const uint8_t in_list_1[] = { 0x4A, 0x01, 0x00 };
            uint8_t probe_rsp[32];
            int n = pn532_exec(in_list_1, sizeof(in_list_1), probe_rsp, sizeof(probe_rsp), 20);

            if (n >= 7 && probe_rsp[0] == 0x4B && probe_rsp[1] > 0) {
                uint8_t ulen = probe_rsp[6];
                if (ulen > 10) ulen = 10;
                uint8_t sak  = probe_rsp[5];

                if (s_lock_cfg.lock_mode == NFC_LOCK_MODE_STATIC_UID) {
                    if (ulen == s_lock_cfg.enrolled_uid_len &&
                        crypto_consttime_eq(&probe_rsp[7], s_lock_cfg.enrolled_uid, ulen)) {
                        /* Match! Unlock token */
                        s_is_locked = false;
                        led_blink(3, 40);
                        pn532_start_target_mode();
                        s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
                    }
                } else if (s_lock_cfg.lock_mode == NFC_LOCK_MODE_EMV_CRYPTO) {
                    if (sak & 0x20) {
                        uint8_t hash[32];
                        if (pn532_query_emv_card(hash) &&
                            crypto_consttime_eq(hash, s_lock_cfg.enrolled_card_hash, 32)) {
                            /* Match! Unlock token */
                            s_is_locked = false;
                            led_blink(3, 40);
                            pn532_start_target_mode();
                            s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
                        }
                    }
                }
            }
        }
        return;
    }

    bool irq_low = ((P1_IN & (1UL << PIN_NFC_IRQ)) == 0);

    if (s_nfc_state == NFC_STATE_ARMED_WAIT_INITIATOR) {
        if (!irq_low) {
            /* No external phone talking right now. Check if 500 ms probe interval elapsed */
            if (g_uptime_ms - s_last_probe_ms >= NFC_PROBE_INTERVAL_MS) {
                s_last_probe_ms = g_uptime_ms;

                /* Fast Probe in Reader Mode: InListPassiveTarget(1) with 15ms timeout */
                static const uint8_t in_list_1[] = { 0x4A, 0x01, 0x00 };
                uint8_t probe_rsp[32];
                int n = pn532_exec(in_list_1, sizeof(in_list_1), probe_rsp, sizeof(probe_rsp), 15);

                if (n >= 7 && probe_rsp[0] == 0x4B && probe_rsp[1] > 0) {
                    /* Passive card detected on antenna! */
                    s_last_detected_tag.detected = true;
                    s_last_detected_tag.timestamp_ms = g_uptime_ms;
                    s_last_detected_tag.atqa = ((uint16_t)probe_rsp[3] << 8) | probe_rsp[4];
                    s_last_detected_tag.sak  = probe_rsp[5];
                    uint8_t ulen = probe_rsp[6];
                    if (ulen > 10) ulen = 10;
                    s_last_detected_tag.uid_len = ulen;
                    memcpy(s_last_detected_tag.uid, &probe_rsp[7], ulen);
                } else {
                    s_last_detected_tag.detected = false;
                }

                /* Immediately re-arm Target Mode (Card Emulation for phone tap) */
                pn532_start_target_mode();
            }
            return;
        }

        /* IRQ is LOW: External phone/reader field detected */
        int n = pn532_read_frame(s_nfc_buf, sizeof(s_nfc_buf), 50);
        if (n >= 2 && s_nfc_buf[0] == 0x8D) {
            /* Arm TgGetData to receive the first APDU from phone */
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
        if (!irq_low) return;
        int n = pn532_read_frame(s_nfc_buf, sizeof(s_nfc_buf), 50);
        if (n < 2 || s_nfc_buf[0] != 0x87 || s_nfc_buf[1] != 0x00) {
            pn532_start_target_mode();
            s_nfc_state = NFC_STATE_ARMED_WAIT_INITIATOR;
            s_nfc_applet = NFC_APPLET_NONE;
            return;
        }

        uint16_t apdu_len = (uint16_t)(n - 2);
        const uint8_t *apdu = &s_nfc_buf[2];

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
            } else if (aid_len >= 7 && memcmp(aid, "\xA0\x00\x00\x05\x27\x21\x01", 7) == 0) {
                s_nfc_applet = NFC_APPLET_OATH;
            } else if (aid_len >= 11 && memcmp(aid, "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00", 11) == 0) {
                s_nfc_applet = NFC_APPLET_PIV;
            } else if (aid_len >= 8 && memcmp(aid, "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8) == 0) {
                s_nfc_applet = NFC_APPLET_FIDO;
            }
        }

        /* Dispatch APDU to appropriate applet */
        uint8_t rsp_buf[300];
        uint16_t rsp_len = 0;

        if (s_nfc_applet == NFC_APPLET_OPENPGP) {
            rsp_len = openpgp_process_apdu(apdu, apdu_len, rsp_buf, sizeof(rsp_buf));
        } else if (s_nfc_applet == NFC_APPLET_OATH) {
            rsp_len = oath_process_apdu(apdu, apdu_len, rsp_buf, sizeof(rsp_buf));
        } else if (s_nfc_applet == NFC_APPLET_PIV) {
            rsp_len = piv_process_apdu(apdu, apdu_len, rsp_buf, sizeof(rsp_buf));
        } else if (s_nfc_applet == NFC_APPLET_FIDO) {
            rsp_len = (uint16_t)fido_process_apdu(apdu, apdu_len, rsp_buf, sizeof(rsp_buf));
        } else {
            rsp_buf[0] = 0x6A; rsp_buf[1] = 0x82; /* File/Application not found */
            rsp_len = 2;
        }

        /* Send response back via TgSetData */
        pn532_send_target_data(rsp_buf, rsp_len);

        /* Re-arm TgGetData for subsequent APDUs in this session */
        static const uint8_t tg_get_data[] = { 0x86 };
        pn532_write_frame(tg_get_data, sizeof(tg_get_data));
        pn532_consume_ack();
    }
}

/* ==================== On-Demand Physical Tag Scanner (APDU 00 EA) ==================== */

uint16_t pn532_scan_tag(uint8_t *out, uint16_t max_out) {
    if (max_out < 32) return 0;
    uint16_t out_len = 0;

    /* 1. Wakeup & Configure SAM */
    pn532_wakeup();
    static const uint8_t sam_cfg[] = { 0x14, 0x01, 0x14, 0x01 };
    uint8_t tmp_rsp[64];
    pn532_exec(sam_cfg, sizeof(sam_cfg), tmp_rsp, sizeof(tmp_rsp), 50);

    /* 2. RF Field ON */
    static const uint8_t rf_cfg[] = { 0x32, 0x01, 0x01 };
    pn532_exec(rf_cfg, sizeof(rf_cfg), tmp_rsp, sizeof(tmp_rsp), 50);

    /* 3. InListPassiveTarget (Max 1 card, 106 kbps Type A) */
    static const uint8_t in_list_1[] = { 0x4A, 0x01, 0x00 };
    int n = pn532_exec(in_list_1, sizeof(in_list_1), tmp_rsp, sizeof(tmp_rsp), 150);

    if (n >= 7 && tmp_rsp[0] == 0x4B && tmp_rsp[1] > 0) {
        uint8_t atqa_hi = tmp_rsp[3];
        uint8_t atqa_lo = tmp_rsp[4];
        uint8_t sak     = tmp_rsp[5];
        uint8_t uid_len = tmp_rsp[6];
        if (uid_len > 10) uid_len = 10;

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
            int p4_n = pn532_exec(read_p4, sizeof(read_p4), p4_rsp, sizeof(p4_rsp), 100);
            if (p4_n >= 18 && p4_rsp[0] == 0x41 && p4_rsp[1] == 0x00) {
                out[out_len++] = 16;
                memcpy(&out[out_len], &p4_rsp[2], 16);
                out_len += 16;
            } else {
                out[out_len++] = 0;
            }
        } else {
            out[out_len++] = 0;
        }
    } else {
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

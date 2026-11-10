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

#ifndef PN532_NFC_H
#define PN532_NFC_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool     detected;
    uint32_t timestamp_ms;
    uint16_t atqa;
    uint8_t  sak;
    uint8_t  uid_len;
    uint8_t  uid[10];
} pn532_tag_info_t;

/* Initialize PN532 GPIO pins, probe PN532 over SPI, and arm ISO 14443-4 target mode.
 * Returns true if PN532 hardware was detected and armed, false if not detected. */
bool pn532_nfc_init(void);

/* Check if PN532 NFC subsystem is detected and active */
bool pn532_nfc_is_active(void);

/* Dynamic time-sharing poll routine (Variant 3) to be called inside main loop:
 * Alternates between Target Mode (Card Emulation for phone tap, 97% of time)
 * and periodic fast probe (Reader Mode, 15ms every 500ms). */
void pn532_nfc_poll(void);

/* Scan for physical passive NFC tag (Reader mode), then restore Target mode.
 * Returns length written to out. */
uint16_t pn532_scan_tag(uint8_t *out, uint16_t max_out);

/* Get last detected tag info from periodic background scanner */
bool pn532_get_last_tag(pn532_tag_info_t *info);

/* ==================== Physical Presence Lock API ==================== */
/* Check whether the token is currently locked awaiting its physical NFC tag/card */
bool pn532_is_locked(void);

/* Force the token back into locked state (until physical card is tapped again) */
void pn532_lock_force(void);

/* Enroll the tag currently on the antenna as a Static UID physical lock (Mode 1) */
bool pn532_enroll_tag_uid(uint8_t *uid_out, uint8_t *uid_len_out);

/* Enroll the EMV crypto smart card currently on the antenna (Mode 2) */
bool pn532_enroll_emv_crypto(uint8_t card_hash_out[32]);

/* Disable the physical NFC lock feature */
bool pn532_disable_lock(void);

/* Get current physical lock status & enrolled credentials */
void pn532_get_lock_status(uint8_t *lock_mode, bool *is_locked, uint8_t *uid_len, uint8_t *uid, uint8_t *card_hash);

#endif /* PN532_NFC_H */

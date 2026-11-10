#ifndef PN532_NFC_H
#define PN532_NFC_H

#include <stdint.h>
#include <stdbool.h>

/* Initialize PN532 GPIO pins, probe PN532 over SPI, and arm ISO 14443-4 target mode.
 * Returns true if PN532 hardware was detected and armed, false if not detected. */
bool pn532_nfc_init(void);

/* Check if PN532 NFC subsystem is detected and active */
bool pn532_nfc_is_active(void);

/* Non-blocking poll routine to be called inside main loop */
void pn532_nfc_poll(void);

/* Scan for physical passive NFC tag (Reader mode), then restore Target mode.
 * Returns length written to out. */
uint16_t pn532_scan_tag(uint8_t *out, uint16_t max_out);

#endif /* PN532_NFC_H */

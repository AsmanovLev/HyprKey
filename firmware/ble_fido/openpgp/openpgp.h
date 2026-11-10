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

#endif /* OPENPGP_H */

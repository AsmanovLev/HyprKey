#ifndef PIV_H
#define PIV_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void piv_init(void);

/* Process incoming PIV APDU and write response (Data + SW1 + SW2).
 * Returns total length of response. */
uint16_t piv_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* PIV_H */

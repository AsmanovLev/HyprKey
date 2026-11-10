#ifndef SATOCHIP_H
#define SATOCHIP_H

#include <stdint.h>
#include <stdbool.h>

/* Satochip Card Applet AID: "SatoChip" (8 bytes: 0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70) */
#define SATOCHIP_AID_LEN 8
extern const uint8_t SATOCHIP_AID[SATOCHIP_AID_LEN];

/* Alternative standard Satochip AID: A0 00 00 08 04 00 01 01 */
#define SATOCHIP_AID_ALT_LEN 8
extern const uint8_t SATOCHIP_AID_ALT[SATOCHIP_AID_ALT_LEN];

/* Initialize Satochip hardware wallet state */
void satochip_init(void);

/* Process APDU targeted at Satochip Hardware Wallet Applet */
uint16_t satochip_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len);

/* Check if Satochip PIN has been verified in current session */
bool satochip_is_pin_verified(void);

#endif /* SATOCHIP_H */

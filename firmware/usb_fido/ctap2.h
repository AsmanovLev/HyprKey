#ifndef CTAP2_H
#define CTAP2_H

#include <stdint.h>
#include <stddef.h>

#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION   0x02
#define CTAP2_CMD_GET_INFO        0x04
#define CTAP2_CMD_RESET           0x06
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x07

#define CTAP1_ERR_SUCCESS         0x00
#define CTAP1_ERR_INVALID_COMMAND 0x01
#define CTAP1_ERR_INVALID_PAR     0x02
#define CTAP1_ERR_INVALID_LENGTH  0x03
#define CTAP2_ERR_CBOR_UNEXPECTED 0x21
#define CTAP2_ERR_INVALID_CBOR    0x22
#define CTAP2_ERR_UNSUPPORTED_ALG 0x26
#define CTAP2_ERR_NO_CREDENTIALS  0x27

/* Process a CTAP2 CBOR request and write the response into rsp.
 * Returns total response length (status byte + CBOR payload).
 */
uint16_t ctap2_process_cbor(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* CTAP2_H */

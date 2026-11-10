#ifndef CCID_H
#define CCID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CCID_MAX_MSG_SIZE 3072

/* CCID Message Types (PC -> RDR) */
#define CCID_PC_TO_RDR_ICC_POWER_ON      0x62
#define CCID_PC_TO_RDR_ICC_POWER_OFF     0x63
#define CCID_PC_TO_RDR_GET_SLOT_STATUS   0x65
#define CCID_PC_TO_RDR_XFR_BLOCK         0x6F
#define CCID_PC_TO_RDR_GET_PARAMETERS    0x6C
#define CCID_PC_TO_RDR_RESET_PARAMETERS  0x6D
#define CCID_PC_TO_RDR_SET_PARAMETERS    0x61
#define CCID_PC_TO_RDR_ESCAPE            0x6B

/* CCID Message Types (RDR -> PC) */
#define CCID_RDR_TO_PC_DATA_BLOCK        0x80
#define CCID_RDR_TO_PC_SLOT_STATUS       0x81
#define CCID_RDR_TO_PC_PARAMETERS        0x82
#define CCID_RDR_TO_PC_ESCAPE            0x83

/* CCID Header Structure (10 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  bMessageType;
    uint32_t dwLength;
    uint8_t  bSlot;
    uint8_t  bSeq;
    uint8_t  bParam0;
    uint8_t  bParam1;
    uint8_t  bParam2;
} ccid_header_t;

void ccid_init(void);

/* Process a complete CCID command from host and write response.
 * Returns length of response written to rsp. */
uint16_t ccid_process_message(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* CCID_H */

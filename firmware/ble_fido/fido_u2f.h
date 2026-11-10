#ifndef FIDO_U2F_H
#define FIDO_U2F_H

#include <stdint.h>
#include <stdbool.h>

void fido_init(void);
int fido_process_apdu(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len);

#endif /* FIDO_U2F_H */

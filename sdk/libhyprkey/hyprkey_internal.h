#ifndef HYPRKEY_INTERNAL_H
#define HYPRKEY_INTERNAL_H

#include "../include/hyprkey.h"

#if defined(_WIN32)
  #include <windows.h>
  #include <winscard.h>
#else
  #include <winscard.h>
  #include <reader.h>
#endif

struct hyprkey_device {
    SCARDCONTEXT hContext;
    SCARDHANDLE hCard;
    DWORD dwActiveProtocol;
    char reader_name[256];
    bool is_connected;
};

/* Internal APDU helper */
hyprkey_status_t hyprkey_send_apdu_internal(
    hyprkey_device_t *device,
    uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
    const uint8_t *data, size_t data_len,
    uint8_t *rx_buf, size_t *rx_len,
    uint16_t *sw_out
);

#endif /* HYPRKEY_INTERNAL_H */

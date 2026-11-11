#include "hyprkey_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

hyprkey_status_t hyprkey_connect(hyprkey_device_t **device_out, const char *reader_filter) {
    if (!device_out) return HYPRKEY_ERR_INVALID_PARAM;
    *device_out = NULL;

    hyprkey_device_t *dev = (hyprkey_device_t *)calloc(1, sizeof(hyprkey_device_t));
    if (!dev) return HYPRKEY_ERR_INVALID_PARAM;

    LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &dev->hContext);
    if (rv != SCARD_S_SUCCESS) {
        free(dev);
        return HYPRKEY_ERR_PCSC_FAILED;
    }

    DWORD dwReaders = 0;
    rv = SCardListReadersA(dev->hContext, NULL, NULL, &dwReaders);
    if (rv != SCARD_S_SUCCESS || dwReaders == 0) {
        SCardReleaseContext(dev->hContext);
        free(dev);
        return HYPRKEY_ERR_NO_DEVICE;
    }

    char *mszReaders = (char *)malloc(dwReaders);
    if (!mszReaders) {
        SCardReleaseContext(dev->hContext);
        free(dev);
        return HYPRKEY_ERR_INVALID_PARAM;
    }

    rv = SCardListReadersA(dev->hContext, NULL, mszReaders, &dwReaders);
    if (rv != SCARD_S_SUCCESS) {
        free(mszReaders);
        SCardReleaseContext(dev->hContext);
        free(dev);
        return HYPRKEY_ERR_PCSC_FAILED;
    }

    /* Find matching reader */
    char *p = mszReaders;
    const char *target_reader = NULL;
    while (*p != '\0') {
        if (reader_filter) {
            if (strstr(p, reader_filter) != NULL) {
                target_reader = p;
                break;
            }
        } else {
            /* Default: find Hyprkey or OpenPGP reader */
            if (strstr(p, "hyprkey") != NULL || strstr(p, "Hyprkey") != NULL ||
                strstr(p, "OpenPGP") != NULL || strstr(p, "FIDO") != NULL) {
                target_reader = p;
                break;
            }
            /* Fallback to first available reader if no exact match found yet */
            if (!target_reader) {
                target_reader = p;
            }
        }
        p += strlen(p) + 1;
    }

    if (!target_reader) {
        free(mszReaders);
        SCardReleaseContext(dev->hContext);
        free(dev);
        return HYPRKEY_ERR_NO_DEVICE;
    }

    strncpy(dev->reader_name, target_reader, sizeof(dev->reader_name) - 1);
    free(mszReaders);

    rv = SCardConnectA(
        dev->hContext,
        dev->reader_name,
        SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T1 | SCARD_PROTOCOL_T0,
        &dev->hCard,
        &dev->dwActiveProtocol
    );

    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(dev->hContext);
        free(dev);
        return HYPRKEY_ERR_COMMUNICATION;
    }

    dev->is_connected = true;

    /* Select Satochip Applet: 00 A4 04 00 08 53 61 74 6F 43 68 69 70 00 */
    const uint8_t satochip_aid[] = { 0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70 };
    uint8_t rx[256];
    size_t rx_len = sizeof(rx);
    uint16_t sw = 0;

    hyprkey_status_t st = hyprkey_send_apdu_internal(
        dev, 0x00, 0xA4, 0x04, 0x00,
        satochip_aid, sizeof(satochip_aid),
        rx, &rx_len, &sw
    );

    if (st != HYPRKEY_OK || sw != 0x9000) {
        hyprkey_disconnect(dev);
        return HYPRKEY_ERR_APPLET_FAILED;
    }

    *device_out = dev;
    return HYPRKEY_OK;
}

void hyprkey_disconnect(hyprkey_device_t *device) {
    if (!device) return;
    if (device->hCard) {
        SCardDisconnect(device->hCard, SCARD_LEAVE_CARD);
        device->hCard = 0;
    }
    if (device->hContext) {
        SCardReleaseContext(device->hContext);
        device->hContext = 0;
    }
    device->is_connected = false;
    free(device);
}

const char *hyprkey_get_reader_name(hyprkey_device_t *device) {
    if (!device) return "";
    return device->reader_name;
}

hyprkey_status_t hyprkey_transmit_apdu(
    hyprkey_device_t *device,
    const uint8_t *apdu,
    size_t apdu_len,
    uint8_t *rx_buf,
    size_t *rx_len,
    uint16_t *sw_out
) {
    if (!device || !device->is_connected || !apdu || !rx_buf || !rx_len) {
        return HYPRKEY_ERR_INVALID_PARAM;
    }

    SCARD_IO_REQUEST pioSendPci;
    pioSendPci.dwProtocol = device->dwActiveProtocol;
    pioSendPci.cbPciLength = sizeof(SCARD_IO_REQUEST);

    DWORD recv_len = (DWORD)*rx_len;
    LONG rv = SCardTransmit(
        device->hCard,
        &pioSendPci,
        apdu,
        (DWORD)apdu_len,
        NULL,
        rx_buf,
        &recv_len
    );

    if (rv != SCARD_S_SUCCESS) {
        return HYPRKEY_ERR_COMMUNICATION;
    }

    if (recv_len < 2) {
        return HYPRKEY_ERR_COMMUNICATION;
    }

    uint16_t sw = ((uint16_t)rx_buf[recv_len - 2] << 8) | rx_buf[recv_len - 1];
    if (sw_out) *sw_out = sw;
    *rx_len = recv_len - 2; /* Strip SW */

    return HYPRKEY_OK;
}

hyprkey_status_t hyprkey_send_apdu_internal(
    hyprkey_device_t *device,
    uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
    const uint8_t *data, size_t data_len,
    uint8_t *rx_buf, size_t *rx_len,
    uint16_t *sw_out
) {
    uint8_t tx[300];
    tx[0] = cla;
    tx[1] = ins;
    tx[2] = p1;
    tx[3] = p2;

    size_t tx_len = 4;
    if (data && data_len > 0) {
        tx[4] = (uint8_t)data_len;
        memcpy(&tx[5], data, data_len);
        tx[5 + data_len] = 0x00; /* Le */
        tx_len = 6 + data_len;
    } else {
        tx[4] = 0x00; /* Le = 0 / 256 */
        tx_len = 5;
    }

    return hyprkey_transmit_apdu(device, tx, tx_len, rx_buf, rx_len, sw_out);
}

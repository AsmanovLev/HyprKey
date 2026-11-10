#include "usb_composite.h"
#include "nrf_soc.h"
#include "ctap2.h"
#include "fido_u2f.h"
#include "ccid/ccid.h"
#include "oath/oath.h"
#include <string.h>

#ifndef HYPRKEY_TEST_MODE
#define HYPRKEY_TEST_MODE 1
#endif

#if HYPRKEY_TEST_MODE
extern void uart_puts(const char *s);
extern void uart_puthex8(uint8_t b);
extern void uart_puthex32(uint32_t v);
#else
#define uart_puts(s) ((void)0)
#define uart_puthex8(b) ((void)0)
#define uart_puthex32(v) ((void)0)
#endif

#define PIN_LED 15

/* ==================== Register Definitions ==================== */
#define POWER_BASE            0x40000000UL
#define POWER_USBREGSTATUS    (*(volatile uint32_t *)(POWER_BASE + 0x438))

#define USBD_BASE             0x40027000UL

/* Tasks */
#define USBD_TASKS_STARTEPIN(n)  (*(volatile uint32_t *)(USBD_BASE + 0x004 + ((n) * 4)))
#define USBD_TASKS_STARTEPOUT(n) (*(volatile uint32_t *)(USBD_BASE + 0x028 + ((n) * 4)))
#define USBD_TASKS_EP0RCVOUT     (*(volatile uint32_t *)(USBD_BASE + 0x04C))
#define USBD_TASKS_EP0STATUS     (*(volatile uint32_t *)(USBD_BASE + 0x050))
#define USBD_TASKS_EP0STALL      (*(volatile uint32_t *)(USBD_BASE + 0x054))

/* Events */
#define USBD_EVENTS_USBRESET     (*(volatile uint32_t *)(USBD_BASE + 0x100))
#define USBD_EVENTS_ENDEPIN(n)   (*(volatile uint32_t *)(USBD_BASE + 0x108 + ((n) * 4)))
#define USBD_EVENTS_EP0DATADONE  (*(volatile uint32_t *)(USBD_BASE + 0x128))
#define USBD_EVENTS_ENDEPOUT(n)  (*(volatile uint32_t *)(USBD_BASE + 0x130 + ((n) * 4)))
#define USBD_EVENTS_ENDISOOUT    (*(volatile uint32_t *)(USBD_BASE + 0x150))
#define USBD_EVENTS_SOF          (*(volatile uint32_t *)(USBD_BASE + 0x154))
#define USBD_EVENTS_USBEVENT     (*(volatile uint32_t *)(USBD_BASE + 0x158))
#define USBD_EVENTS_EP0SETUP     (*(volatile uint32_t *)(USBD_BASE + 0x15C))
#define USBD_EVENTS_EPDATA       (*(volatile uint32_t *)(USBD_BASE + 0x160))

/* Registers */
#define USBD_EVENTCAUSE          (*(volatile uint32_t *)(USBD_BASE + 0x400))
#define USBD_EPSTATUS            (*(volatile uint32_t *)(USBD_BASE + 0x468))
#define USBD_EPDATASTATUS        (*(volatile uint32_t *)(USBD_BASE + 0x46C))
#define USBD_SIZE_EPOUT(n)       (*(volatile uint32_t *)(USBD_BASE + 0x4A0 + ((n) * 4)))
#define USBD_BMREQUESTTYPE       (*(volatile uint32_t *)(USBD_BASE + 0x480))
#define USBD_BREQUEST            (*(volatile uint32_t *)(USBD_BASE + 0x484))
#define USBD_WVALUEL             (*(volatile uint32_t *)(USBD_BASE + 0x488))
#define USBD_WVALUEH             (*(volatile uint32_t *)(USBD_BASE + 0x48C))
#define USBD_WINDEXL             (*(volatile uint32_t *)(USBD_BASE + 0x490))
#define USBD_WINDEXH             (*(volatile uint32_t *)(USBD_BASE + 0x494))
#define USBD_WLENGTHL            (*(volatile uint32_t *)(USBD_BASE + 0x498))
#define USBD_WLENGTHH            (*(volatile uint32_t *)(USBD_BASE + 0x49C))
#define USBD_EPINEN              (*(volatile uint32_t *)(USBD_BASE + 0x510))
#define USBD_EPOUTEN             (*(volatile uint32_t *)(USBD_BASE + 0x514))
#define USBD_ENABLE              (*(volatile uint32_t *)(USBD_BASE + 0x500))
#define USBD_USBPULLUP           (*(volatile uint32_t *)(USBD_BASE + 0x504))
#define USBD_LOWPOWER            (*(volatile uint32_t *)(USBD_BASE + 0x544))

/* Endpoint EasyDMA Structures */
typedef struct {
    volatile uint32_t PTR;
    volatile uint32_t MAXCNT;
    volatile uint32_t AMOUNT;
} usbd_dma_t;

#define USBD_EPIN_BASE  (USBD_BASE + 0x600)
#define USBD_EPOUT_BASE (USBD_BASE + 0x700)

#define USBD_EPIN(n)  ((volatile usbd_dma_t *)(USBD_EPIN_BASE + ((n) * 0x14)))
#define USBD_EPOUT(n) ((volatile usbd_dma_t *)(USBD_EPOUT_BASE + ((n) * 0x14)))

#define NRF_P0_BASE 0x50000000UL
#define P0_OUTSET   (*(volatile uint32_t *)(NRF_P0_BASE + 0x508))
#define P0_OUTCLR   (*(volatile uint32_t *)(NRF_P0_BASE + 0x50C))

/* ==================== USB Descriptors ==================== */
static const uint8_t s_device_desc[] = {
    0x12,       /* bLength = 18 */
    0x01,       /* bDescriptorType = DEVICE */
    0x00, 0x02, /* bcdUSB = 2.00 */
    0x00,       /* bDeviceClass = 0 (Interface defined) */
    0x00,       /* bDeviceSubClass = 0 */
    0x00,       /* bDeviceProtocol = 0 */
    0x40,       /* bMaxPacketSize0 = 64 */
    0x09, 0x12, /* idVendor  = 0x1209 (pid.codes open source VID) */
    0x05, 0x00, /* idProduct = 0x0005 (Composite FIDO2 + CCID + Keyboard OTP) */
    0x00, 0x05, /* bcdDevice = 5.00 */
    0x01,       /* iManufacturer = String 1 */
    0x02,       /* iProduct = String 2 */
    0x03,       /* iSerialNumber = String 3 */
    0x01        /* bNumConfigurations = 1 */
};

static const uint8_t s_config_desc[] = {
    /* Configuration Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x02,       /* bDescriptorType = CONFIGURATION */
    0x8F, 0x00, /* wTotalLength = 143 bytes (9 + 32 + 77 + 25) */
    0x03,       /* bNumInterfaces = 3 (Interface 0: HID FIDO2, Interface 1: CCID OATH/PIV, Interface 2: HID Keyboard OTP) */
    0x01,       /* bConfigurationValue = 1 */
    0x00,       /* iConfiguration = 0 */
    0x80,       /* bmAttributes = Bus powered */
    0x32,       /* bMaxPower = 100 mA (50 * 2mA) */

    /* ================= Interface 0: HID (FIDO2 / U2F) (32 bytes) ================= */
    0x09, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
    /* HID Descriptor (9 bytes) */
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x22, 0x00,
    /* Endpoint Descriptor IN 1 (7 bytes) */
    0x07, 0x05, 0x81, 0x03, 0x40, 0x00, 0x05,
    /* Endpoint Descriptor OUT 1 (7 bytes) */
    0x07, 0x05, 0x01, 0x03, 0x40, 0x00, 0x05,

    /* ================= Interface 1: CCID (Smart Card / OATH / PIV) (77 bytes) ================= */
    0x09, 0x04, 0x01, 0x00, 0x02, 0x0B, 0x00, 0x00, 0x04,
    /* CCID Functional Descriptor (54 bytes) */
    0x36, 0x21, 0x10, 0x01, 0x00, 0x07, 0x03, 0x00, 0x00, 0x00,
    0xA0, 0x0F, 0x00, 0x00, 0xA0, 0x0F, 0x00, 0x00, 0x00,
    0x80, 0x25, 0x00, 0x00, 0x00, 0xC2, 0x01, 0x00, 0x00,
    0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFE, 0x00, 0x04, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01,
    /* Endpoint Descriptor OUT 2 (Bulk OUT, 7 bytes) */
    0x07, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00,
    /* Endpoint Descriptor IN 2 (Bulk IN, 7 bytes) */
    0x07, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00,

    /* ================= Interface 2: HID Keyboard (OTP) (25 bytes) ================= */
    0x09, 0x04, 0x02, 0x00, 0x01, 0x03, 0x01, 0x01, 0x05,
    /* HID Descriptor (9 bytes) */
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3F, 0x00,
    /* Endpoint Descriptor IN 3 (Interrupt IN, 7 bytes) */
    0x07, 0x05, 0x83, 0x03, 0x08, 0x00, 0x0A
};

/* FIDO Alliance Universal Standard HID Report Descriptor (34 bytes) */
static const uint8_t s_hid_report_desc[] = {
    0x06, 0xD0, 0xF1, /* USAGE_PAGE (FIDO Alliance 0xF1D0) */
    0x09, 0x01,       /* USAGE (U2F HID Authenticator Device) */
    0xA1, 0x01,       /* COLLECTION (Application) */
    0x09, 0x20,       /*   USAGE (Data In) */
    0x15, 0x00,       /*   LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /*   LOGICAL_MAXIMUM (255) */
    0x75, 0x08,       /*   REPORT_SIZE (8 bits) */
    0x95, 0x40,       /*   REPORT_COUNT (64 bytes) */
    0x81, 0x02,       /*   INPUT (Data, Var, Abs) */
    0x09, 0x21,       /*   USAGE (Data Out) */
    0x15, 0x00,       /*   LOGICAL_MINIMUM (0) */
    0x26, 0xFF, 0x00, /*   LOGICAL_MAXIMUM (255) */
    0x75, 0x08,       /*   REPORT_SIZE (8 bits) */
    0x95, 0x40,       /*   REPORT_COUNT (64 bytes) */
    0x91, 0x02,       /*   OUTPUT (Data, Var, Abs) */
    0xC0              /* END_COLLECTION */
};

/* Standard USB Boot Keyboard Report Descriptor (63 bytes) */
static const uint8_t s_kbd_report_desc[] = {
    0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x06, /* USAGE (Keyboard) */
    0xA1, 0x01, /* COLLECTION (Application) */
    0x05, 0x07, /*   USAGE_PAGE (Keyboard) */
    0x19, 0xE0, /*   USAGE_MINIMUM (Keyboard LeftControl) */
    0x29, 0xE7, /*   USAGE_MAXIMUM (Keyboard Right GUI) */
    0x15, 0x00, /*   LOGICAL_MINIMUM (0) */
    0x25, 0x01, /*   LOGICAL_MAXIMUM (1) */
    0x75, 0x01, /*   REPORT_SIZE (1) */
    0x95, 0x08, /*   REPORT_COUNT (8) */
    0x81, 0x02, /*   INPUT (Data,Var,Abs) */
    0x95, 0x01, /*   REPORT_COUNT (1) */
    0x75, 0x08, /*   REPORT_SIZE (8) */
    0x81, 0x03, /*   INPUT (Cnst,Var,Abs) */
    0x95, 0x05, /*   REPORT_COUNT (5) */
    0x75, 0x01, /*   REPORT_SIZE (1) */
    0x05, 0x08, /*   USAGE_PAGE (LEDs) */
    0x19, 0x01, /*   USAGE_MINIMUM (Num Lock) */
    0x29, 0x05, /*   USAGE_MAXIMUM (Kana) */
    0x91, 0x02, /*   OUTPUT (Data,Var,Abs) */
    0x95, 0x01, /*   REPORT_COUNT (1) */
    0x75, 0x03, /*   REPORT_SIZE (3) */
    0x91, 0x03, /*   OUTPUT (Cnst,Var,Abs) */
    0x95, 0x06, /*   REPORT_COUNT (6) */
    0x75, 0x08, /*   REPORT_SIZE (8) */
    0x15, 0x00, /*   LOGICAL_MINIMUM (0) */
    0x25, 0x65, /*   LOGICAL_MAXIMUM (101) */
    0x05, 0x07, /*   USAGE_PAGE (Keyboard) */
    0x19, 0x00, /*   USAGE_MINIMUM (Reserved) */
    0x29, 0x65, /*   USAGE_MAXIMUM (Keyboard Application) */
    0x81, 0x00, /*   INPUT (Data,Ary,Abs) */
    0xC0        /* END_COLLECTION */
};

/* String Descriptors */
static const uint8_t s_str_lang[]   = { 0x04, 0x03, 0x09, 0x04 };
static const uint8_t s_str_manuf[]  = { 0x10, 0x03, 'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0 };
static const uint8_t s_str_prod[]   = { 0x2A, 0x03, 'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
                                        'F', 0, 'I', 0, 'D', 0, 'O', 0, '2', 0, ' ', 0, '/', 0, ' ', 0,
                                        'C', 0, 'C', 0, 'I', 0, 'D', 0 };
static const uint8_t s_str_serial[] = { 0x18, 0x03, 'H', 0, 'Y', 0, 'P', 0, 'R', 0, 'K', 0, 'E', 0, 'Y', 0, '-', 0, '0', 0, '0', 0, '5', 0 };
static const uint8_t s_str_ccid[]   = { 0x26, 0x03, 'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
                                        'S', 0, 'm', 0, 'a', 0, 'r', 0, 't', 0, ' ', 0, 'C', 0, 'a', 0, 'r', 0, 'd', 0 };
static const uint8_t s_str_kbd[]    = { 0x2A, 0x03, 'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
                                        'O', 0, 'T', 0, 'P', 0, ' ', 0,
                                        'K', 0, 'e', 0, 'y', 0, 'b', 0, 'o', 0, 'a', 0, 'r', 0, 'd', 0 };

/* ==================== DMA Buffers (RAM) ==================== */
static uint8_t m_ep0_tx_buf[128] __attribute__((aligned(4)));
static uint8_t m_ep1_rx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep1_tx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep2_rx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep2_tx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep3_tx_buf[8]   __attribute__((aligned(4)));

static uint8_t  m_ctap_rx_msg[4096];
static uint16_t m_ctap_rx_len = 0;
static uint16_t m_ctap_rx_expected = 0;
static uint8_t  m_ctap_rx_seq = 0;
static uint8_t  m_ctap_rx_cmd = 0;
static uint32_t m_ctap_active_cid = 0;
static uint8_t  m_fido_tx_buf[4096];

static uint8_t  m_ccid_rx_msg[CCID_MAX_MSG_SIZE];
static uint16_t m_ccid_rx_len = 0;
static uint16_t m_ccid_rx_expected = 0;
static uint8_t  m_ccid_tx_buf[CCID_MAX_MSG_SIZE];

static uint8_t  m_usb_configured = 0;
static uint32_t m_assigned_cid = 0x01020304;

bool usb_composite_is_configured(void) {
    return (m_usb_configured != 0);
}

/* ==================== EP0 Control Transfers ==================== */
static void send_ep0_data(const uint8_t *src, uint16_t len, uint16_t req_len) {
    uint16_t total = (len > req_len) ? req_len : len;
    uint16_t sent = 0;

    if (total == 0) {
        USBD_TASKS_EP0STATUS = 1;
        return;
    }

    while (sent < total) {
        uint16_t chunk = total - sent;
        if (chunk > 64) chunk = 64;

        memcpy(m_ep0_tx_buf, src + sent, chunk);
        USBD_EPIN(0)->PTR = (uint32_t)m_ep0_tx_buf;
        USBD_EPIN(0)->MAXCNT = chunk;
        USBD_EVENTS_ENDEPIN(0) = 0;
        USBD_EVENTS_EP0DATADONE = 0;
        USBD_TASKS_STARTEPIN(0) = 1;

        uint32_t timeout = 500000;
        while (!USBD_EVENTS_ENDEPIN(0) && --timeout);
        USBD_EVENTS_ENDEPIN(0) = 0;

        timeout = 500000;
        while (!USBD_EVENTS_EP0DATADONE && --timeout);
        USBD_EVENTS_EP0DATADONE = 0;

        sent += chunk;
    }

    USBD_TASKS_EP0STATUS = 1;
}

static void handle_ep0_setup(void) {
    uint8_t  bmRequestType = USBD_BMREQUESTTYPE;
    uint8_t  bRequest      = USBD_BREQUEST;
    uint16_t wValue        = USBD_WVALUEL | (USBD_WVALUEH << 8);
    uint16_t wIndex        = USBD_WINDEXL | (USBD_WINDEXH << 8);
    uint16_t wLength       = USBD_WLENGTHL | (USBD_WLENGTHH << 8);
    (void)wIndex;

#if HYPRKEY_TEST_MODE
    uart_puts("[EP0] reqType=");
    uart_puthex8(bmRequestType);
    uart_puts(" req=");
    uart_puthex8(bRequest);
    uart_puts(" val=");
    uart_puthex32(wValue);
    uart_puts(" len=");
    uart_puthex32(wLength);
    uart_puts("\r\n");
#endif

    /* 1. Standard Device Requests */
    if ((bmRequestType & 0x60) == 0x00) {
        if (bRequest == 0x06) {
            /* GET_DESCRIPTOR */
            uint8_t desc_type = (uint8_t)(wValue >> 8);
            uint8_t desc_idx  = (uint8_t)(wValue & 0xFF);

            if (desc_type == 0x01) {
                send_ep0_data(s_device_desc, sizeof(s_device_desc), wLength);
                return;
            } else if (desc_type == 0x02) {
                send_ep0_data(s_config_desc, sizeof(s_config_desc), wLength);
                return;
            } else if (desc_type == 0x03) {
                if (desc_idx == 0)      send_ep0_data(s_str_lang, sizeof(s_str_lang), wLength);
                else if (desc_idx == 1) send_ep0_data(s_str_manuf, sizeof(s_str_manuf), wLength);
                else if (desc_idx == 2) send_ep0_data(s_str_prod, sizeof(s_str_prod), wLength);
                else if (desc_idx == 3) send_ep0_data(s_str_serial, sizeof(s_str_serial), wLength);
                else if (desc_idx == 4) send_ep0_data(s_str_ccid, sizeof(s_str_ccid), wLength);
                else if (desc_idx == 5) send_ep0_data(s_str_kbd, sizeof(s_str_kbd), wLength);
                else USBD_TASKS_EP0STALL = 1;
                return;
            }
        } else if (bRequest == 0x05) {
            /* SET_ADDRESS */
            USBD_TASKS_EP0STATUS = 1;
            return;
        } else if (bRequest == 0x09) {
            /* SET_CONFIGURATION */
            m_usb_configured = (uint8_t)wValue;
            USBD_EPINEN = 0x0F;  /* EP0, EP1, EP2, EP3 IN */
            USBD_EPOUTEN = 0x07; /* EP0, EP1, EP2 OUT */
            USBD_TASKS_EP0STATUS = 1;
            USBD_SIZE_EPOUT(1) = 0;
            USBD_SIZE_EPOUT(2) = 0;
            return;
        } else if (bRequest == 0x08) {
            send_ep0_data(&m_usb_configured, 1, wLength);
            return;
        } else if (bRequest == 0x00) {
            static const uint8_t zero_status[2] = {0, 0};
            send_ep0_data(zero_status, 2, wLength);
            return;
        }
    }

    /* 2. Standard Interface Requests */
    if (bmRequestType == 0x81 && bRequest == 0x06) {
        uint8_t desc_type = (uint8_t)(wValue >> 8);
        uint8_t iface     = (uint8_t)(wIndex & 0xFF);
        if (iface == 0) {
            if (desc_type == 0x22) {
                send_ep0_data(s_hid_report_desc, sizeof(s_hid_report_desc), wLength);
                return;
            } else if (desc_type == 0x21) {
                send_ep0_data(&s_config_desc[18], 9, wLength);
                return;
            }
        } else if (iface == 1) {
            if (desc_type == 0x21) {
                send_ep0_data(&s_config_desc[50], 54, wLength);
                return;
            }
        } else if (iface == 2) {
            if (desc_type == 0x22) {
                send_ep0_data(s_kbd_report_desc, sizeof(s_kbd_report_desc), wLength);
                return;
            } else if (desc_type == 0x21) {
                send_ep0_data(&s_config_desc[127], 9, wLength);
                return;
            }
        }
    }

    /* 3. Class Requests */
    if ((bmRequestType & 0x60) == 0x20) {
        uint8_t iface = (uint8_t)(wIndex & 0xFF);
        if (iface == 0 || iface == 2) {
            if (bRequest == 0x0A || bRequest == 0x09) {
                USBD_TASKS_EP0STATUS = 1;
                return;
            } else if (bRequest == 0x02) {
                static const uint8_t idle_rate = 0;
                send_ep0_data(&idle_rate, 1, wLength);
                return;
            }
        } else if (iface == 1) {
            if (bRequest == 0x02) { /* ABORT */
                USBD_TASKS_EP0STATUS = 1;
                return;
            } else if (bRequest == 0x03) { /* GET_CLOCK_FREQUENCIES */
                static const uint32_t freqs[1] = { 4000 };
                send_ep0_data((const uint8_t *)freqs, sizeof(freqs), wLength);
                return;
            } else if (bRequest == 0x04) { /* GET_DATA_RATES */
                static const uint32_t rates[2] = { 9600, 115200 };
                send_ep0_data((const uint8_t *)rates, sizeof(rates), wLength);
                return;
            }
        }
    }

    /* Unsupported: Stall */
    USBD_TASKS_EP0STALL = 1;
}

/* ==================== EP1 CTAPHID Engine ==================== */
static void send_ep1_packet(const uint8_t *pkt64) {
    memcpy(m_ep1_tx_buf, pkt64, 64);
    USBD_EPIN(1)->PTR = (uint32_t)m_ep1_tx_buf;
    USBD_EPIN(1)->MAXCNT = 64;
    USBD_EVENTS_ENDEPIN(1) = 0;
    USBD_TASKS_STARTEPIN(1) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(1) && --timeout);
    USBD_EVENTS_ENDEPIN(1) = 0;

    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 1)) && --timeout);
    USBD_EPDATASTATUS = (1UL << 1);
}

static void send_ctaphid_response(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len) {
    uint8_t pkt[64];
    memset(pkt, 0, 64);

    pkt[0] = (uint8_t)(cid >> 24);
    pkt[1] = (uint8_t)(cid >> 16);
    pkt[2] = (uint8_t)(cid >> 8);
    pkt[3] = (uint8_t)(cid & 0xFF);
    pkt[4] = cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)(len & 0xFF);

    uint16_t chunk = (len > 57) ? 57 : len;
    if (chunk > 0) memcpy(&pkt[7], data, chunk);
    send_ep1_packet(pkt);

    uint16_t sent = chunk;
    uint8_t seq = 0;

    while (sent < len) {
        memset(pkt, 0, 64);
        pkt[0] = (uint8_t)(cid >> 24);
        pkt[1] = (uint8_t)(cid >> 16);
        pkt[2] = (uint8_t)(cid >> 8);
        pkt[3] = (uint8_t)(cid & 0xFF);
        pkt[4] = seq++;

        chunk = (len - sent > 59) ? 59 : (len - sent);
        memcpy(&pkt[5], data + sent, chunk);
        sent += chunk;
        send_ep1_packet(pkt);
    }
}

static void handle_complete_ctaphid_msg(uint32_t cid, uint8_t cmd, const uint8_t *payload, uint16_t len) {
    if (cmd == 0x81) {
        /* CTAPHID PING */
        send_ctaphid_response(cid, 0x81, payload, len);
    } else if (cmd == 0x88) {
        /* WINK */
        send_ctaphid_response(cid, 0x88, NULL, 0);
    } else if (cmd == 0x83) {
        /* U2F APDU MSG */
        P0_OUTCLR = (1UL << PIN_LED);
        uint16_t resp_len = fido_process_apdu(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        P0_OUTSET = (1UL << PIN_LED);
        send_ctaphid_response(cid, 0x83, m_fido_tx_buf, resp_len);
    } else if (cmd == 0x90) {
        /* CTAP2 CBOR */
        P0_OUTCLR = (1UL << PIN_LED);
        uint16_t resp_len = ctap2_process_cbor(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        P0_OUTSET = (1UL << PIN_LED);
        send_ctaphid_response(cid, 0x90, m_fido_tx_buf, resp_len);
    } else if (cmd == 0x70) {
        /* Vendor Command: Keyboard OTP Typing */
        usb_composite_type_string("hyprkey-sec-k3y-otp-2026\n");
        uint8_t ack = 0x00;
        send_ctaphid_response(cid, 0x70, &ack, 1);
    } else if (cmd == 0x71) {
        /* Vendor Command: OATH APDU Tunnel for Browser WebHID */
        uint16_t apdu_rsp_len = oath_process_apdu(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        send_ctaphid_response(cid, 0x71, m_fido_tx_buf, apdu_rsp_len);
    } else {
        uint8_t err = 0x01; /* Invalid command */
        send_ctaphid_response(cid, 0xBF, &err, 1);
    }
}

static void process_incoming_ctaphid_packet(const uint8_t *pkt) {
    uint32_t cid = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16) |
                   ((uint32_t)pkt[2] << 8)  | ((uint32_t)pkt[3]);
    uint8_t cmd_or_seq = pkt[4];

    if (cmd_or_seq == 0x86) {
        /* CTAPHID_INIT */
        uint8_t resp[17];
        memcpy(&resp[0], &pkt[7], 8); /* Nonce */
        resp[8]  = (uint8_t)(m_assigned_cid >> 24);
        resp[9]  = (uint8_t)(m_assigned_cid >> 16);
        resp[10] = (uint8_t)(m_assigned_cid >> 8);
        resp[11] = (uint8_t)(m_assigned_cid & 0xFF);
        resp[12] = 0x02; /* CTAPHID v2 */
        resp[13] = 0x01; /* Dev ver */
        resp[14] = 0x00;
        resp[15] = 0x00;
        resp[16] = 0x05; /* WINK | CBOR */
        send_ctaphid_response(cid, 0x86, resp, 17);
        m_ctap_rx_expected = 0;
        return;
    }

    if (cmd_or_seq & 0x80) {
        /* Initial Packet */
        m_ctap_active_cid = cid;
        m_ctap_rx_cmd = cmd_or_seq;
        m_ctap_rx_expected = ((uint16_t)pkt[5] << 8) | pkt[6];
        m_ctap_rx_seq = 0;

        uint16_t chunk = (m_ctap_rx_expected > 57) ? 57 : m_ctap_rx_expected;
        if (chunk > sizeof(m_ctap_rx_msg)) chunk = sizeof(m_ctap_rx_msg);
        memcpy(m_ctap_rx_msg, &pkt[7], chunk);
        m_ctap_rx_len = chunk;

        if (m_ctap_rx_len >= m_ctap_rx_expected) {
            handle_complete_ctaphid_msg(m_ctap_active_cid, m_ctap_rx_cmd, m_ctap_rx_msg, m_ctap_rx_expected);
            m_ctap_rx_expected = 0;
        }
    } else {
        /* Continuation Packet */
        if (cid == m_ctap_active_cid && m_ctap_rx_expected > 0) {
            if (cmd_or_seq == m_ctap_rx_seq) {
                m_ctap_rx_seq++;
                uint16_t chunk = m_ctap_rx_expected - m_ctap_rx_len;
                if (chunk > 59) chunk = 59;
                if (m_ctap_rx_len + chunk <= sizeof(m_ctap_rx_msg)) {
                    memcpy(&m_ctap_rx_msg[m_ctap_rx_len], &pkt[5], chunk);
                    m_ctap_rx_len += chunk;
                }
                if (m_ctap_rx_len >= m_ctap_rx_expected) {
                    handle_complete_ctaphid_msg(m_ctap_active_cid, m_ctap_rx_cmd, m_ctap_rx_msg, m_ctap_rx_expected);
                    m_ctap_rx_expected = 0;
                }
            } else {
                uint8_t err = 0x04; /* Invalid sequence */
                send_ctaphid_response(cid, 0xBF, &err, 1);
                m_ctap_rx_expected = 0;
            }
        }
    }
}

/* ==================== EP2 CCID Engine ==================== */
static void send_ep2_packet(const uint8_t *pkt64, uint8_t len) {
    if (len > 0 && pkt64) {
        memcpy(m_ep2_tx_buf, pkt64, len);
    }
    USBD_EPIN(2)->PTR = (uint32_t)m_ep2_tx_buf;
    USBD_EPIN(2)->MAXCNT = len;
    USBD_EVENTS_ENDEPIN(2) = 0;
    USBD_EPDATASTATUS = (1UL << 2);
    USBD_TASKS_STARTEPIN(2) = 1;

    uint32_t timeout = 10000000;
    while (!USBD_EVENTS_ENDEPIN(2) && --timeout);
    USBD_EVENTS_ENDEPIN(2) = 0;

    timeout = 10000000;
    while (!(USBD_EPDATASTATUS & (1UL << 2)) && --timeout);
    USBD_EPDATASTATUS = (1UL << 2);
}

static void send_ccid_response(const uint8_t *data, uint16_t len) {
    uint16_t sent = 0;
    while (sent < len) {
        uint16_t chunk = len - sent;
        if (chunk > 64) chunk = 64;
        send_ep2_packet(&data[sent], (uint8_t)chunk);
        sent += chunk;
    }
    if (len > 0 && (len % 64) == 0) {
        send_ep2_packet(NULL, 0);
    }
}

static void process_incoming_ccid_packet(const uint8_t *pkt, uint8_t len) {
    if (m_ccid_rx_len == 0) {
        if (len < 10) return;
        uint32_t payload_len = (uint32_t)pkt[1] | ((uint32_t)pkt[2] << 8) |
                               ((uint32_t)pkt[3] << 16) | ((uint32_t)pkt[4] << 24);
        m_ccid_rx_expected = 10 + (uint16_t)payload_len;
        if (m_ccid_rx_expected > sizeof(m_ccid_rx_msg)) {
            m_ccid_rx_expected = sizeof(m_ccid_rx_msg);
        }
        memcpy(m_ccid_rx_msg, pkt, len);
        m_ccid_rx_len = len;
    } else {
        uint16_t rem = m_ccid_rx_expected - m_ccid_rx_len;
        uint16_t chunk = (len < rem) ? len : rem;
        memcpy(m_ccid_rx_msg + m_ccid_rx_len, pkt, chunk);
        m_ccid_rx_len += chunk;
    }

    if (m_ccid_rx_len >= m_ccid_rx_expected) {
        uint16_t rsp_len = ccid_process_message(m_ccid_rx_msg, m_ccid_rx_expected,
                                                m_ccid_tx_buf, sizeof(m_ccid_tx_buf));
        send_ccid_response(m_ccid_tx_buf, rsp_len);
        m_ccid_rx_len = 0;
        m_ccid_rx_expected = 0;
    }
}

/* ==================== EP3 Keyboard OTP Typing ==================== */
static bool ascii_to_hid(char c, uint8_t *mod, uint8_t *code) {
    *mod = 0;
    if (c >= 'a' && c <= 'z') { *code = 0x04 + (uint8_t)(c - 'a'); return true; }
    if (c >= 'A' && c <= 'Z') { *mod = 0x02; *code = 0x04 + (uint8_t)(c - 'A'); return true; }
    if (c >= '1' && c <= '9') { *code = 0x1E + (uint8_t)(c - '1'); return true; }
    if (c == '0') { *code = 0x27; return true; }
    if (c == '\n' || c == '\r') { *code = 0x28; return true; }
    if (c == ' ') { *code = 0x2C; return true; }
    if (c == '-') { *code = 0x2D; return true; }
    return false;
}

static void send_ep3_keyboard_report(uint8_t modifier, uint8_t keycode) {
    m_ep3_tx_buf[0] = modifier;
    m_ep3_tx_buf[1] = 0;
    m_ep3_tx_buf[2] = keycode;
    m_ep3_tx_buf[3] = 0;
    m_ep3_tx_buf[4] = 0;
    m_ep3_tx_buf[5] = 0;
    m_ep3_tx_buf[6] = 0;
    m_ep3_tx_buf[7] = 0;

    USBD_EPIN(3)->PTR = (uint32_t)m_ep3_tx_buf;
    USBD_EPIN(3)->MAXCNT = 8;
    USBD_EVENTS_ENDEPIN(3) = 0;
    USBD_EPDATASTATUS = (1UL << 3);
    USBD_TASKS_STARTEPIN(3) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(3) && --timeout);
    USBD_EVENTS_ENDEPIN(3) = 0;

    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 3)) && --timeout);
    USBD_EPDATASTATUS = (1UL << 3);
}

void usb_composite_type_string(const char *str) {
    if (!m_usb_configured) return;
    while (*str) {
        uint8_t mod = 0, code = 0;
        if (ascii_to_hid(*str, &mod, &code)) {
            send_ep3_keyboard_report(mod, code);
            for (volatile int d = 0; d < 40000; d++);
            send_ep3_keyboard_report(0, 0);
            for (volatile int d = 0; d < 40000; d++);
        }
        str++;
    }
}

/* ==================== Public Init & Poll ==================== */
void usb_composite_init(void) {
    /* 1. Request 32MHz HFXO crystal clock via SoftDevice API */
    sd_clock_hfclk_request();
    uint32_t is_running = 0;
    uint32_t timeout = 500000;
    while (--timeout) {
        sd_clock_hfclk_is_running(&is_running);
        if (is_running) break;
    }

    /* 2. Silicon Errata 171/187 Workaround before USBD Enable */
    if (*(volatile uint32_t *)0x4006EC00 == 0) {
        *(volatile uint32_t *)0x4006EC00 = 0x00009375;
    }
    *(volatile uint32_t *)0x4006EC14 = 0x000000C0;
    *(volatile uint32_t *)0x4006EC00 = 0x00009375;

    /* 3. Enable USBD Controller */
    USBD_ENABLE = 1;

    /* 4. Wait for USB 3.3V power regulator ready */
    uint32_t usbreg = 0;
    timeout = 500000;
    while (--timeout) {
        sd_power_usbregstatus_get(&usbreg);
        if (usbreg & 0x02) break; /* Bit 1: OUTPUTRDY */
    }

    /* 5. Wait for 48 MHz PLL lock (READY bit is bit 11 = 0x800) */
    timeout = 5000000;
    while ((!USBD_EVENTS_USBEVENT || !(USBD_EVENTCAUSE & (1UL << 11))) && --timeout);
    uint32_t cause = USBD_EVENTCAUSE;
    USBD_EVENTS_USBEVENT = 0;
    USBD_EVENTCAUSE = cause;

#if HYPRKEY_TEST_MODE
    uart_puts("[USBD] PWR: ");
    uart_puthex32(usbreg);
    uart_puts(" PLL timeout: ");
    uart_puthex32(timeout);
    uart_puts(" cause: ");
    uart_puthex32(cause);
    uart_puts("\r\n");
#endif

    /* Clear Errata Workaround */
    if (*(volatile uint32_t *)0x4006EC00 == 0) {
        *(volatile uint32_t *)0x4006EC00 = 0x00009375;
    }
    *(volatile uint32_t *)0x4006EC14 = 0x00000000;
    *(volatile uint32_t *)0x4006EC00 = 0x00009375;

    /* 6. Initialize CCID Multi-Applet Engine (OpenPGP + PIV + OATH) */
    ccid_init();

    /* 7. Enable EP0 & Connect Pull-Up Resistor */
    USBD_EPINEN = 0x01;
    USBD_EPOUTEN = 0x01;
    USBD_USBPULLUP = 1;

#if HYPRKEY_TEST_MODE
    uart_puts("[USBD] Composite USB controller initialized & pull-up attached!\r\n");
#endif
}

void usb_composite_stop(void) {
    USBD_USBPULLUP = 0;
    USBD_ENABLE = 0;
    m_usb_configured = 0;
}

void usb_composite_poll(void) {
    /* Check USB Bus Reset */
    if (USBD_EVENTS_USBRESET) {
        USBD_EVENTS_USBRESET = 0;
#if HYPRKEY_TEST_MODE
        uart_puts("\r\n[USB] === BUS RESET ===\r\n");
#endif
        USBD_EPINEN = 0x01;
        USBD_EPOUTEN = 0x01;
        m_usb_configured = 0;
    }

    /* Check USBEVENT */
    if (USBD_EVENTS_USBEVENT) {
        uint32_t cause = USBD_EVENTCAUSE;
        USBD_EVENTS_USBEVENT = 0;
        USBD_EVENTCAUSE = cause;
#if HYPRKEY_TEST_MODE
        uart_puts("[USB] USBEVENT cause=");
        uart_puthex32(cause);
        uart_puts("\r\n");
#endif
    }

    /* Check EP0 SETUP Packet */
    if (USBD_EVENTS_EP0SETUP) {
        USBD_EVENTS_EP0SETUP = 0;
#if HYPRKEY_TEST_MODE
        uart_puts("[USB] EP0 SETUP!\r\n");
#endif
        handle_ep0_setup();
    }

    /* Check EP1 OUT packet (FIDO / WebHID) */
    if (m_usb_configured && (USBD_EPDATASTATUS & (1UL << 17))) {
        USBD_EPDATASTATUS = (1UL << 17);
        USBD_EVENTS_EPDATA = 0;

        USBD_EPOUT(1)->PTR = (uint32_t)m_ep1_rx_buf;
        USBD_EPOUT(1)->MAXCNT = 64;
        USBD_EVENTS_ENDEPOUT(1) = 0;
        USBD_TASKS_STARTEPOUT(1) = 1;

        uint32_t timeout = 500000;
        while (!USBD_EVENTS_ENDEPOUT(1) && --timeout);
        USBD_EVENTS_ENDEPOUT(1) = 0;

        USBD_SIZE_EPOUT(1) = 0;
        process_incoming_ctaphid_packet(m_ep1_rx_buf);
    }

    /* Check EP2 OUT packet (CCID Smart Card) */
    if (m_usb_configured && (USBD_EPDATASTATUS & (1UL << 18))) {
        USBD_EPDATASTATUS = (1UL << 18);
        USBD_EVENTS_EPDATA = 0;

        USBD_EPOUT(2)->PTR = (uint32_t)m_ep2_rx_buf;
        USBD_EPOUT(2)->MAXCNT = 64;
        USBD_EVENTS_ENDEPOUT(2) = 0;
        USBD_TASKS_STARTEPOUT(2) = 1;

        uint32_t timeout = 500000;
        while (!USBD_EVENTS_ENDEPOUT(2) && --timeout);
        USBD_EVENTS_ENDEPOUT(2) = 0;

        uint32_t bytes_received = USBD_EPOUT(2)->AMOUNT;
        USBD_SIZE_EPOUT(2) = 0;
        process_incoming_ccid_packet(m_ep2_rx_buf, (uint8_t)bytes_received);
    }
}

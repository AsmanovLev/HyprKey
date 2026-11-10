#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "fido_u2f.h"
#include "ctap2.h"
#include "ccid/ccid.h"
#include "openpgp/openpgp.h"
#include "oath/oath.h"
#include "device_log.h"

/* ==================== nRF52840 Registers ==================== */
#define P0_BASE               0x50000000UL
#define P0_OUTSET             (*(volatile uint32_t *)(P0_BASE + 0x508))
#define P0_OUTCLR             (*(volatile uint32_t *)(P0_BASE + 0x50C))
#define P0_IN                 (*(volatile uint32_t *)(P0_BASE + 0x510))
#define P0_DIRSET             (*(volatile uint32_t *)(P0_BASE + 0x518))
#define P0_PIN_CNF(n)         (*(volatile uint32_t *)(P0_BASE + 0x700 + ((n) * 4)))

#define PIN_LED               15  /* P0.15, active LOW */
#define PIN_DBG_TX            10  /* P0.10 -> CH340 RX */
#define PIN_TOUCH             11  /* P0.11 -> Touch interrupt / Button */

/* UART1 Registers */
#define UART1_BASE            0x40028000UL
#define UART1_TASKS_STARTTX   (*(volatile uint32_t *)(UART1_BASE + 0x008))
#define UART1_ENABLE          (*(volatile uint32_t *)(UART1_BASE + 0x500))
#define UART1_PSEL_TXD        (*(volatile uint32_t *)(UART1_BASE + 0x50C))
#define UART1_PSEL_RXD        (*(volatile uint32_t *)(UART1_BASE + 0x514))
#define UART1_BAUDRATE        (*(volatile uint32_t *)(UART1_BASE + 0x524))
#define UART1_TXD_PTR         (*(volatile uint32_t *)(UART1_BASE + 0x544))
#define UART1_TXD_MAXCNT      (*(volatile uint32_t *)(UART1_BASE + 0x548))
#define UART1_EVENTS_ENDTX    (*(volatile uint32_t *)(UART1_BASE + 0x120))

/* Clock & Power Registers */
#define CLOCK_BASE            0x40000000UL
#define POWER_BASE            0x40000000UL
#define CLOCK_TASKS_HFCLKSTART  (*(volatile uint32_t *)(CLOCK_BASE + 0x000))
#define CLOCK_EVENTS_HFCLKSTARTED (*(volatile uint32_t *)(CLOCK_BASE + 0x100))
#define POWER_USBREGSTATUS      (*(volatile uint32_t *)(POWER_BASE + 0x438))
#define POWER_EVENTS_USBDETECTED (*(volatile uint32_t *)(POWER_BASE + 0x11C))
#define POWER_EVENTS_USBPWRRDY   (*(volatile uint32_t *)(POWER_BASE + 0x124))

/* USBD Base Address */
#define USBD_BASE             0x40027000UL

/* Tasks */
#define USBD_TASKS_STARTEPIN(n) (*(volatile uint32_t *)(USBD_BASE + 0x004 + ((n) * 4)))
#define USBD_TASKS_STARTEPOUT(n)(*(volatile uint32_t *)(USBD_BASE + 0x028 + ((n) * 4)))
#define USBD_TASKS_EP0RCVOUT    (*(volatile uint32_t *)(USBD_BASE + 0x04C))
#define USBD_TASKS_EP0STATUS    (*(volatile uint32_t *)(USBD_BASE + 0x050))
#define USBD_TASKS_EP0STALL     (*(volatile uint32_t *)(USBD_BASE + 0x054))

/* Events */
#define USBD_EVENTS_USBRESET    (*(volatile uint32_t *)(USBD_BASE + 0x100))
#define USBD_EVENTS_ENDEPIN(n)  (*(volatile uint32_t *)(USBD_BASE + 0x108 + ((n) * 4)))
#define USBD_EVENTS_EP0DATADONE (*(volatile uint32_t *)(USBD_BASE + 0x128))
#define USBD_EVENTS_ENDEPOUT(n) (*(volatile uint32_t *)(USBD_BASE + 0x130 + ((n) * 4)))
#define USBD_EVENTS_ENDISOOUT   (*(volatile uint32_t *)(USBD_BASE + 0x150))
#define USBD_EVENTS_SOF         (*(volatile uint32_t *)(USBD_BASE + 0x154))
#define USBD_EVENTS_USBEVENT    (*(volatile uint32_t *)(USBD_BASE + 0x158))
#define USBD_EVENTS_EP0SETUP    (*(volatile uint32_t *)(USBD_BASE + 0x15C))
#define USBD_EVENTS_EPDATA      (*(volatile uint32_t *)(USBD_BASE + 0x160))

/* Registers */
#define USBD_EVENTCAUSE         (*(volatile uint32_t *)(USBD_BASE + 0x400))
#define USBD_EPSTATUS           (*(volatile uint32_t *)(USBD_BASE + 0x468))
#define USBD_EPDATASTATUS       (*(volatile uint32_t *)(USBD_BASE + 0x46C))
#define USBD_SIZE_EPOUT(n)      (*(volatile uint32_t *)(USBD_BASE + 0x4A0 + ((n) * 4)))
#define USBD_BMREQUESTTYPE      (*(volatile uint32_t *)(USBD_BASE + 0x480))
#define USBD_BREQUEST           (*(volatile uint32_t *)(USBD_BASE + 0x484))
#define USBD_WVALUEL            (*(volatile uint32_t *)(USBD_BASE + 0x488))
#define USBD_WVALUEH            (*(volatile uint32_t *)(USBD_BASE + 0x48C))
#define USBD_WINDEXL            (*(volatile uint32_t *)(USBD_BASE + 0x490))
#define USBD_WINDEXH            (*(volatile uint32_t *)(USBD_BASE + 0x494))
#define USBD_WLENGTHL           (*(volatile uint32_t *)(USBD_BASE + 0x498))
#define USBD_WLENGTHH           (*(volatile uint32_t *)(USBD_BASE + 0x49C))
#define USBD_EPINEN             (*(volatile uint32_t *)(USBD_BASE + 0x510))
#define USBD_EPOUTEN            (*(volatile uint32_t *)(USBD_BASE + 0x514))
#define USBD_ENABLE             (*(volatile uint32_t *)(USBD_BASE + 0x500))
#define USBD_USBPULLUP          (*(volatile uint32_t *)(USBD_BASE + 0x504))
#define USBD_LOWPOWER           (*(volatile uint32_t *)(USBD_BASE + 0x544))
#define USBD_EPSTATUS           (*(volatile uint32_t *)(USBD_BASE + 0x468))

/* Endpoint EasyDMA Structures */
typedef struct {
    volatile uint32_t PTR;
    volatile uint32_t MAXCNT;
    volatile uint32_t AMOUNT;
} usbd_ep_t;

#define USBD_EPIN_BASE  (USBD_BASE + 0x600)
#define USBD_EPOUT_BASE (USBD_BASE + 0x700)

#define USBD_EPIN(n)  ((volatile usbd_ep_t *)(USBD_EPIN_BASE + ((n) * 0x14)))
#define USBD_EPOUT(n) ((volatile usbd_ep_t *)(USBD_EPOUT_BASE + ((n) * 0x14)))

/* ==================== UART Debug ==================== */
static volatile uint8_t m_tx_byte;

static void uart_init(void) {
    P0_DIRSET = (1UL << PIN_DBG_TX);
    P0_PIN_CNF(PIN_DBG_TX) = 0x00000003UL;
    UART1_PSEL_TXD = PIN_DBG_TX;
    UART1_PSEL_RXD = 0xFFFFFFFFUL;
    UART1_BAUDRATE = 0x01D7E000UL; /* 115200 */
    UART1_ENABLE = 8;
}

static void uart_putc(char c) {
    m_tx_byte = (uint8_t)c;
    UART1_TXD_PTR = (uint32_t)&m_tx_byte;
    UART1_TXD_MAXCNT = 1;
    UART1_EVENTS_ENDTX = 0;
    UART1_TASKS_STARTTX = 1;
    while (!UART1_EVENTS_ENDTX);
}

static void uart_puts(const char *s) {
    while (*s) uart_putc(*s++);
}

static void uart_puthex8(uint8_t b) {
    static const char hex[] = "0123456789ABCDEF";
    uart_putc(hex[(b >> 4) & 0x0F]);
    uart_putc(hex[b & 0x0F]);
}

static void uart_puthex32(uint32_t v) {
    uart_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        uart_putc("0123456789ABCDEF"[(v >> i) & 0x0F]);
    }
}

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
    0x05, 0x00, /* idProduct = 0x0005 (Composite FIDO2 + OpenPGP/PIV CCID + OTP Keyboard v5) */
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
    0x03,       /* bNumInterfaces = 3 (Interface 0: HID FIDO2, Interface 1: CCID OpenPGP/PIV, Interface 2: HID Keyboard OTP) */
    0x01,       /* bConfigurationValue = 1 */
    0x00,       /* iConfiguration = 0 */
    0x80,       /* bmAttributes = Bus powered */
    0x32,       /* bMaxPower = 100 mA (50 * 2mA) */

    /* ================= Interface 0: HID (FIDO2 / U2F) (32 bytes) ================= */
    /* Interface Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x04,       /* bDescriptorType = INTERFACE */
    0x00,       /* bInterfaceNumber = 0 */
    0x00,       /* bAlternateSetting = 0 */
    0x02,       /* bNumEndpoints = 2 (EP1 IN, EP1 OUT) */
    0x03,       /* bInterfaceClass = 0x03 (HID) */
    0x00,       /* bInterfaceSubClass = 0 */
    0x00,       /* bInterfaceProtocol = 0 */
    0x00,       /* iInterface = 0 */

    /* HID Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x21,       /* bDescriptorType = HID */
    0x11, 0x01, /* bcdHID = 1.11 */
    0x00,       /* bCountryCode = 0 */
    0x01,       /* bNumDescriptors = 1 */
    0x22,       /* bDescriptorType = REPORT */
    0x22, 0x00, /* wDescriptorLength = 34 bytes (0x0022) */

    /* Endpoint Descriptor IN 1 (7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x81,       /* bEndpointAddress = EP 1 IN */
    0x03,       /* bmAttributes = Interrupt */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x05,       /* bInterval = 5 ms */

    /* Endpoint Descriptor OUT 1 (7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x01,       /* bEndpointAddress = EP 1 OUT */
    0x03,       /* bmAttributes = Interrupt */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x05,       /* bInterval = 5 ms */

    /* ================= Interface 1: CCID (Smart Card / OpenPGP / PIV) (77 bytes) ================= */
    /* Interface Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x04,       /* bDescriptorType = INTERFACE */
    0x01,       /* bInterfaceNumber = 1 */
    0x00,       /* bAlternateSetting = 0 */
    0x02,       /* bNumEndpoints = 2 (EP2 OUT, EP2 IN) */
    0x0B,       /* bInterfaceClass = 0x0B (CCID) */
    0x00,       /* bInterfaceSubClass = 0 */
    0x00,       /* bInterfaceProtocol = 0 */
    0x04,       /* iInterface = String 4 ("hyprkey OpenPGP CCID") */

    /* CCID Functional Descriptor (54 bytes) */
    0x36,       /* bLength = 54 */
    0x21,       /* bDescriptorType = Functional */
    0x10, 0x01, /* bcdCCID = 1.10 */
    0x00,       /* bMaxSlotIndex = 0 (1 slot) */
    0x07,       /* bVoltageSupport = 5V, 3V, 1.8V */
    0x03, 0x00, 0x00, 0x00, /* dwProtocols = T=0 and T=1 (0x00000003) */
    0xA0, 0x0F, 0x00, 0x00, /* dwDefaultClock = 4000 kHz */
    0xA0, 0x0F, 0x00, 0x00, /* dwMaximumClock = 4000 kHz */
    0x00,       /* bNumClockSupported = 0 */
    0x80, 0x25, 0x00, 0x00, /* dwDataRate = 9600 bps */
    0x00, 0xC2, 0x01, 0x00, /* dwMaxDataRate = 115200 bps */
    0x00,       /* bNumDataRatesSupported = 0 */
    0xFE, 0x00, 0x00, 0x00, /* dwMaxIFSD = 254 bytes */
    0x00, 0x00, 0x00, 0x00, /* dwSynchProtocols = 0 */
    0x00, 0x00, 0x00, 0x00, /* dwMechanical = 0 */
    0xFE, 0x00, 0x04, 0x00, /* dwFeatures = 0x000400FE (Short & Extended APDU, auto voltage, auto params) */
    0x00, 0x0C, 0x00, 0x00, /* dwMaxCCIDMessageLength = 3072 bytes */
    0x00,       /* bClassGetResponse = echo */
    0x00,       /* bClassEnvelope = echo */
    0x00, 0x00, /* wLcdLayout = 0 */
    0x00,       /* bPINSupport = 0 */
    0x01,       /* bMaxCCIDBusySlots = 1 */

    /* Endpoint Descriptor OUT 2 (Bulk OUT, 7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x02,       /* bEndpointAddress = EP 2 OUT */
    0x02,       /* bmAttributes = Bulk */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x00,       /* bInterval = 0 */

    /* Endpoint Descriptor IN 2 (Bulk IN, 7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x82,       /* bEndpointAddress = EP 2 IN */
    0x02,       /* bmAttributes = Bulk */
    0x40, 0x00, /* wMaxPacketSize = 64 bytes */
    0x00,       /* bInterval = 0 */

    /* ================= Interface 2: HID Keyboard (OTP / Static Password) (25 bytes) ================= */
    /* Interface Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x04,       /* bDescriptorType = INTERFACE */
    0x02,       /* bInterfaceNumber = 2 */
    0x00,       /* bAlternateSetting = 0 */
    0x01,       /* bNumEndpoints = 1 (EP3 IN) */
    0x03,       /* bInterfaceClass = 0x03 (HID) */
    0x01,       /* bInterfaceSubClass = 0x01 (Boot Interface) */
    0x01,       /* bInterfaceProtocol = 0x01 (Keyboard) */
    0x05,       /* iInterface = String 5 ("hyprkey OTP Keyboard") */

    /* HID Descriptor (9 bytes) */
    0x09,       /* bLength = 9 */
    0x21,       /* bDescriptorType = HID */
    0x11, 0x01, /* bcdHID = 1.11 */
    0x00,       /* bCountryCode = 0 */
    0x01,       /* bNumDescriptors = 1 */
    0x22,       /* bDescriptorType = REPORT */
    0x3F, 0x00, /* wDescriptorLength = 63 bytes (0x003F) */

    /* Endpoint Descriptor IN 3 (Interrupt IN, 7 bytes) */
    0x07,       /* bLength = 7 */
    0x05,       /* bDescriptorType = ENDPOINT */
    0x83,       /* bEndpointAddress = EP 3 IN */
    0x03,       /* bmAttributes = Interrupt */
    0x08, 0x00, /* wMaxPacketSize = 8 bytes */
    0x0A        /* bInterval = 10 ms */
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
static const uint8_t s_str_lang[] = {
    0x04, 0x03, 0x09, 0x04 /* English US (0x0409) */
};

static const uint8_t s_str_manuf[] = {
    0x10, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0
};

static const uint8_t s_str_prod[] = {
    0x30, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
    'F', 0, 'I', 0, 'D', 0, 'O', 0, '2', 0, ' ', 0, '/', 0, ' ', 0,
    'O', 0, 'p', 0, 'e', 0, 'n', 0, 'P', 0, 'G', 0, 'P', 0
};

static const uint8_t s_str_serial[] = {
    0x18, 0x03,
    'H', 0, 'Y', 0, 'P', 0, 'R', 0, 'K', 0, 'E', 0, 'Y', 0, '-', 0, '0', 0, '0', 0, '5', 0
};

static const uint8_t s_str_ccid[] = {
    0x2C, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
    'O', 0, 'p', 0, 'e', 0, 'n', 0, 'P', 0, 'G', 0, 'P', 0, ' ', 0,
    'C', 0, 'C', 0, 'I', 0, 'D', 0
};

static const uint8_t s_str_kbd[] = {
    0x2A, 0x03,
    'h', 0, 'y', 0, 'p', 0, 'r', 0, 'k', 0, 'e', 0, 'y', 0, ' ', 0,
    'O', 0, 'T', 0, 'P', 0, ' ', 0,
    'K', 0, 'e', 0, 'y', 0, 'b', 0, 'o', 0, 'a', 0, 'r', 0, 'd', 0
};

/* ==================== USB Hardware & Buffers ==================== */
/* EasyDMA buffers MUST be in RAM and 4-byte aligned */
static uint8_t m_ep0_tx_buf[128] __attribute__((aligned(4)));
static uint8_t m_ep1_rx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep1_tx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep2_rx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep2_tx_buf[64]  __attribute__((aligned(4)));
static uint8_t m_ep3_tx_buf[8]   __attribute__((aligned(4)));

static uint8_t  m_ccid_rx_msg[CCID_MAX_MSG_SIZE];
static uint16_t m_ccid_rx_len = 0;
static uint16_t m_ccid_rx_expected = 0;
static uint8_t  m_ccid_tx_buf[CCID_MAX_MSG_SIZE];

static uint8_t  m_usb_configured = 0;
static uint32_t m_assigned_cid = 0x01020304;

/* ==================== USB HID Keyboard Driver ==================== */
static bool ascii_to_hid(char c, uint8_t *mod, uint8_t *code) {
    *mod = 0;
    if (c >= 'a' && c <= 'z') {
        *code = 0x04 + (uint8_t)(c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *mod = 0x02; /* Left Shift */
        *code = 0x04 + (uint8_t)(c - 'A');
        return true;
    }
    if (c >= '1' && c <= '9') {
        *code = 0x1E + (uint8_t)(c - '1');
        return true;
    }
    if (c == '0') { *code = 0x27; return true; }
    if (c == '\n' || c == '\r') { *code = 0x28; return true; } /* Enter */
    if (c == '\t') { *code = 0x2B; return true; }              /* Tab */
    if (c == ' ')  { *code = 0x2C; return true; }              /* Space */
    if (c == '-')  { *code = 0x2D; return true; }
    if (c == '_')  { *mod = 0x02; *code = 0x2D; return true; }
    if (c == '=')  { *code = 0x2E; return true; }
    if (c == '+')  { *mod = 0x02; *code = 0x2E; return true; }
    if (c == '[')  { *code = 0x2F; return true; }
    if (c == '{')  { *mod = 0x02; *code = 0x2F; return true; }
    if (c == ']')  { *code = 0x30; return true; }
    if (c == '}')  { *mod = 0x02; *code = 0x30; return true; }
    if (c == ';')  { *code = 0x33; return true; }
    if (c == ':')  { *mod = 0x02; *code = 0x33; return true; }
    if (c == '\'') { *code = 0x34; return true; }
    if (c == '\"') { *mod = 0x02; *code = 0x34; return true; }
    if (c == ',')  { *code = 0x36; return true; }
    if (c == '<')  { *mod = 0x02; *code = 0x36; return true; }
    if (c == '.')  { *code = 0x37; return true; }
    if (c == '>')  { *mod = 0x02; *code = 0x37; return true; }
    if (c == '/')  { *code = 0x38; return true; }
    if (c == '?')  { *mod = 0x02; *code = 0x38; return true; }
    if (c == '!')  { *mod = 0x02; *code = 0x1E; return true; }
    if (c == '@')  { *mod = 0x02; *code = 0x1F; return true; }
    if (c == '#')  { *mod = 0x02; *code = 0x20; return true; }
    if (c == '$')  { *mod = 0x02; *code = 0x21; return true; }
    if (c == '%')  { *mod = 0x02; *code = 0x22; return true; }
    if (c == '^')  { *mod = 0x02; *code = 0x23; return true; }
    if (c == '&')  { *mod = 0x02; *code = 0x24; return true; }
    if (c == '*')  { *mod = 0x02; *code = 0x25; return true; }
    if (c == '(')  { *mod = 0x02; *code = 0x26; return true; }
    if (c == ')')  { *mod = 0x02; *code = 0x27; return true; }
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
    USBD_EPDATASTATUS = (1UL << 3); /* Clear host ACK bit before transmission */
    USBD_TASKS_STARTEPIN(3) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(3) && --timeout);
    USBD_EVENTS_ENDEPIN(3) = 0;

    /* Wait for host ACK (EPDATA bit 3) */
    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 3)) && --timeout);
    USBD_EPDATASTATUS = (1UL << 3);
}

static void kbd_type_char(char c) {
    uint8_t mod = 0, code = 0;
    if (ascii_to_hid(c, &mod, &code)) {
        send_ep3_keyboard_report(mod, code);
        for (volatile int d = 0; d < 40000; d++);
        send_ep3_keyboard_report(0, 0); /* Key release */
        for (volatile int d = 0; d < 40000; d++);
    }
}

static void kbd_type_string(const char *str) {
    if (!m_usb_configured) return;
    uart_puts("[KBD] Typing: ");
    uart_puts(str);
    uart_puts("\r\n");

    P0_OUTCLR = (1UL << PIN_LED); /* LED ON while typing */
    while (*str) {
        kbd_type_char(*str++);
    }
    P0_OUTSET = (1UL << PIN_LED); /* LED OFF */
}



static void send_ep0_data(const uint8_t *src, uint16_t len, uint16_t req_len) {
    uint16_t total = (len > req_len) ? req_len : len;
    uint16_t sent = 0;

    uart_puts("    send_ep0 total=");
    uart_puthex32(total);
    uart_puts("\r\n");

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
    uart_puts("    EP0STATUS triggered\r\n");
}

uint32_t g_dbg_ccid_rx_count = 0;
uint32_t g_dbg_ccid_tx_count = 0;
uint32_t g_dbg_last_ccid_cmd = 0;
uint32_t g_dbg_last_ep0_req  = 0;

/* Send 64-byte packet on EP1 IN */
static void send_ep1_packet(const uint8_t *pkt64) {
    memcpy(m_ep1_tx_buf, pkt64, 64);
    USBD_EPIN(1)->PTR = (uint32_t)m_ep1_tx_buf;
    USBD_EPIN(1)->MAXCNT = 64;
    USBD_EVENTS_ENDEPIN(1) = 0;
    USBD_TASKS_STARTEPIN(1) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(1) && --timeout);
    USBD_EVENTS_ENDEPIN(1) = 0;

    /* Wait for host ACK (EPDATA bit 1) */
    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 1)) && --timeout);
    if (timeout == 0) {
        uart_puts("  [EP1 TX] Host fetch timeout!\r\n");
    }
    USBD_EPDATASTATUS = (1UL << 1); /* Clear host ACK bit */
}

/* ==================== CTAPHID Framing & Handler ==================== */
#define CTAPHID_CMD_PING   0x81
#define CTAPHID_CMD_MSG    0x83
#define CTAPHID_CMD_INIT   0x86
#define CTAPHID_CMD_WINK   0x88
#define CTAPHID_CMD_CBOR   0x90
#define CTAPHID_CMD_ERROR  0xBF

#define CTAPHID_ERR_INVALID_CMD  0x01
#define CTAPHID_ERR_INVALID_PAR  0x02
#define CTAPHID_ERR_INVALID_LEN  0x03
#define CTAPHID_ERR_INVALID_SEQ  0x04

static uint8_t  m_ctap_rx_msg[4096];
static uint16_t m_ctap_rx_len = 0;
static uint16_t m_ctap_rx_expected = 0;
static uint8_t  m_ctap_rx_seq = 0;
static uint8_t  m_ctap_rx_cmd = 0;
static uint32_t m_ctap_active_cid = 0;

static uint8_t  m_fido_tx_buf[8192];

static void send_ctaphid_response(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len) {
    uint8_t pkt[64];
    memset(pkt, 0, 64);

    /* Initial packet */
    pkt[0] = (uint8_t)(cid >> 24);
    pkt[1] = (uint8_t)(cid >> 16);
    pkt[2] = (uint8_t)(cid >> 8);
    pkt[3] = (uint8_t)(cid & 0xFF);
    pkt[4] = cmd;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)(len & 0xFF);

    uint16_t chunk = (len > 57) ? 57 : len;
    if (chunk > 0) {
        memcpy(&pkt[7], data, chunk);
    }
    send_ep1_packet(pkt);

    uint16_t sent = chunk;
    uint8_t seq = 0;

    /* Continuation packets */
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

static void send_ctaphid_error(uint32_t cid, uint8_t err_code) {
    uint8_t b = err_code;
    send_ctaphid_response(cid, CTAPHID_CMD_ERROR, &b, 1);
}

static void handle_complete_ctaphid_msg(uint32_t cid, uint8_t cmd, const uint8_t *payload, uint16_t len) {
    uart_puts("[CTAPHID] CMD=0x");
    uart_puthex8(cmd);
    uart_puts(" len=");
    uart_puthex32(len);
    uart_puts("\r\n");

    if (cmd == CTAPHID_CMD_PING) {
        /* PING: Echo payload */
        send_ctaphid_response(cid, CTAPHID_CMD_PING, payload, len);
    } else if (cmd == CTAPHID_CMD_WINK) {
        /* WINK: Return immediately with success, brief LED blink */
        send_ctaphid_response(cid, CTAPHID_CMD_WINK, NULL, 0);
        P0_OUTCLR = (1UL << PIN_LED);
        for (volatile int d = 0; d < 50000; d++);
        P0_OUTSET = (1UL << PIN_LED);
    } else if (cmd == CTAPHID_CMD_MSG) {
        /* MSG: Process U2F APDU */
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON during crypto */
        uint16_t resp_len = fido_process_apdu(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */

        uart_puts("[U2F] Resp len=");
        uart_puthex32(resp_len);
        uart_puts(" sw=");
        if (resp_len >= 2) {
            uart_puthex8(m_fido_tx_buf[resp_len - 2]);
            uart_puthex8(m_fido_tx_buf[resp_len - 1]);
        }
        uart_puts("\r\n");

        send_ctaphid_response(cid, CTAPHID_CMD_MSG, m_fido_tx_buf, resp_len);
    } else if (cmd == CTAPHID_CMD_CBOR) {
        /* CTAP2 CBOR */
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON during crypto */
        uint16_t resp_len = ctap2_process_cbor(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */

        uart_puts("[CTAP2] Resp len=");
        uart_puthex32(resp_len);
        uart_puts(" status=");
        if (resp_len >= 1) {
            uart_puthex8(m_fido_tx_buf[0]);
        }
        uart_puts("\r\n");

        send_ctaphid_response(cid, CTAPHID_CMD_CBOR, m_fido_tx_buf, resp_len);
    } else if (cmd == 0x70) {
        /* CTAPHID Vendor Command: Trigger Keyboard Typing */
        uart_puts("[VENDOR] Triggering Keyboard OTP typing...\r\n");
        kbd_type_string("hyprkey-sec-k3y-otp-2026\n");
        uint8_t ack = 0x00;
        send_ctaphid_response(cid, 0x70, &ack, 1);
    } else if (cmd == 0x71) {
        /* CTAPHID Vendor Command: OATH APDU Tunnel (for WebHID / Browser) */
        uart_puts("[OATH-TUNNEL] Processing APDU via CTAPHID...\r\n");
        uint16_t apdu_rsp_len = oath_process_apdu(payload, len, m_fido_tx_buf, sizeof(m_fido_tx_buf));
        send_ctaphid_response(cid, 0x71, m_fido_tx_buf, apdu_rsp_len);
    } else {
        send_ctaphid_error(cid, CTAPHID_ERR_INVALID_CMD);
    }
}

static void process_incoming_ctaphid_packet(const uint8_t *pkt) {
    uint32_t cid = ((uint32_t)pkt[0] << 24) |
                   ((uint32_t)pkt[1] << 16) |
                   ((uint32_t)pkt[2] << 8)  |
                   ((uint32_t)pkt[3]);

    uint8_t cmd_or_seq = pkt[4];

    /* Special case: CTAPHID_INIT */
    if (cmd_or_seq == CTAPHID_CMD_INIT) {
        uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];
        uart_puts("[CTAPHID] INIT received, nonce=");
        for (int i = 0; i < 8 && i < bcnt; i++) uart_puthex8(pkt[7 + i]);
        uart_puts("\r\n");

        /* Reply: 8-byte nonce, 4-byte CID, 1-byte IF ver, 3-byte dev ver, 1-byte caps */
        uint8_t resp[17];
        memcpy(&resp[0], &pkt[7], 8);                 /* Nonce */
        resp[8]  = (uint8_t)(m_assigned_cid >> 24);    /* Channel ID */
        resp[9]  = (uint8_t)(m_assigned_cid >> 16);
        resp[10] = (uint8_t)(m_assigned_cid >> 8);
        resp[11] = (uint8_t)(m_assigned_cid & 0xFF);
        resp[12] = 0x02;                             /* CTAPHID IF version 2 */
        resp[13] = 0x01;                             /* Major dev version 1 */
        resp[14] = 0x00;                             /* Minor dev version 0 */
        resp[15] = 0x00;                             /* Build dev version 0 */
        resp[16] = 0x05;                             /* Capabilities: CAPFLAG_WINK (0x01) | CAPFLAG_CBOR (0x04) */

        send_ctaphid_response(cid, CTAPHID_CMD_INIT, resp, 17);
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
            uint8_t seq = cmd_or_seq;
            if (seq == m_ctap_rx_seq) {
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
                send_ctaphid_error(cid, CTAPHID_ERR_INVALID_SEQ);
                m_ctap_rx_expected = 0;
            }
        }
    }
}

/* ==================== CCID Framing & Handler ==================== */
static void send_ep2_packet(const uint8_t *pkt64, uint8_t len) {
    g_dbg_ccid_tx_count++;
    if (len > 0 && pkt64) {
        memcpy(m_ep2_tx_buf, pkt64, len);
    }
    USBD_EPIN(2)->PTR = (uint32_t)m_ep2_tx_buf;
    USBD_EPIN(2)->MAXCNT = len;
    USBD_EVENTS_ENDEPIN(2) = 0;
    USBD_EPDATASTATUS = (1UL << 2); /* Clear host ACK bit before transmission */
    USBD_TASKS_STARTEPIN(2) = 1;

    uint32_t timeout = 2000000;
    while (!USBD_EVENTS_ENDEPIN(2) && --timeout);
    USBD_EVENTS_ENDEPIN(2) = 0;

    /* Wait for host ACK (EPDATA bit 2) */
    timeout = 2000000;
    while (!(USBD_EPDATASTATUS & (1UL << 2)) && --timeout);
    if (timeout == 0) {
        uart_puts("  [EP2 TX] Timeout!\r\n");
    } else {
        uart_puts("  [EP2 TX] Sent OK\r\n");
    }
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
    /* If length is exact multiple of 64 bytes, send zero-length packet (ZLP) */
    if (len > 0 && (len % 64) == 0) {
        send_ep2_packet(NULL, 0);
    }
}

#define NRF_POWER_GPREGRET  (*(volatile uint32_t *)0x4000051CUL)
#define DFU_MAGIC_UF2_RESET 0x57
#define SCB_AIRCR           (*(volatile uint32_t *)0xE000ED0CUL)

void system_reboot_to_bootloader(void) {
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDF, 0, 0);
    uart_puts("\r\n[SYS] Rebooting to UF2 Bootloader (DFU)...\r\n");
    for (volatile int i = 0; i < 200000; i++);
    USBD_USBPULLUP = 0; /* Detach USB */
    for (volatile int i = 0; i < 300000; i++);
    NRF_POWER_GPREGRET = DFU_MAGIC_UF2_RESET;
    SCB_AIRCR = 0x05FA0004UL; /* NVIC_SystemReset */
    while (1);
}

static void process_incoming_ccid_packet(const uint8_t *pkt, uint8_t len) {
    if (m_ccid_rx_len == 0) {
        /* First packet contains 10-byte CCID header */
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
        /* Continuation packet */
        uint16_t rem = m_ccid_rx_expected - m_ccid_rx_len;
        uint16_t chunk = (len < rem) ? len : rem;
        memcpy(m_ccid_rx_msg + m_ccid_rx_len, pkt, chunk);
        m_ccid_rx_len += chunk;
    }

    if (m_ccid_rx_len >= m_ccid_rx_expected) {
        P0_OUTCLR = (1UL << PIN_LED); /* LED ON during card operation */
        uint16_t rsp_len = ccid_process_message(m_ccid_rx_msg, m_ccid_rx_expected,
                                                m_ccid_tx_buf, sizeof(m_ccid_tx_buf));
        P0_OUTSET = (1UL << PIN_LED); /* LED OFF */

        uart_puts("[CCID] Cmd=");
        uart_puthex8(m_ccid_rx_msg[0]);
        uart_puts(" RspLen=");
        uart_puthex32(rsp_len);
        uart_puts(" RspHdr: ");
        for (int i = 0; i < (rsp_len < 12 ? rsp_len : 12); i++) {
            uart_puthex8(m_ccid_tx_buf[i]);
            uart_puts(" ");
        }
        uart_puts("\r\n");

        send_ccid_response(m_ccid_tx_buf, rsp_len);
        m_ccid_rx_len = 0;
        m_ccid_rx_expected = 0;

        if (g_dfu_reset_pending) {
            system_reboot_to_bootloader();
        }
    }
}

/* ==================== EP0 Setup Request Handler ==================== */
static void handle_ep0_setup(void) {
    uint8_t  bmRequestType = USBD_BMREQUESTTYPE;
    uint8_t  bRequest      = USBD_BREQUEST;
    g_dbg_last_ep0_req     = bRequest;
    uint16_t wValue        = USBD_WVALUEL | (USBD_WVALUEH << 8);
    uint16_t wIndex        = USBD_WINDEXL | (USBD_WINDEXH << 8);
    uint16_t wLength       = USBD_WLENGTHL | (USBD_WLENGTHH << 8);
    (void)wIndex;

    uart_puts("[EP0] reqType=");
    uart_puthex8(bmRequestType);
    uart_puts(" req=");
    uart_puthex8(bRequest);
    uart_puts(" val=");
    uart_puthex32(wValue);
    uart_puts(" len=");
    uart_puthex32(wLength);
    uart_puts("\r\n");

    /* 1. Standard Device Requests */
    if ((bmRequestType & 0x60) == 0x00) {
        if (bRequest == 0x06) {
            /* GET_DESCRIPTOR */
            uint8_t desc_type = (uint8_t)(wValue >> 8);
            uint8_t desc_idx  = (uint8_t)(wValue & 0xFF);

            if (desc_type == 0x01) {
                /* Device Descriptor */
                uart_puts("  -> Get Device Desc\r\n");
                send_ep0_data(s_device_desc, sizeof(s_device_desc), wLength);
                return;
            } else if (desc_type == 0x02) {
                /* Configuration Descriptor */
                uart_puts("  -> Get Config Desc\r\n");
                send_ep0_data(s_config_desc, sizeof(s_config_desc), wLength);
                return;
            } else if (desc_type == 0x03) {
                /* String Descriptor */
                uart_puts("  -> Get String Desc idx=");
                uart_puthex8(desc_idx);
                uart_puts("\r\n");
                if (desc_idx == 0) {
                    send_ep0_data(s_str_lang, sizeof(s_str_lang), wLength);
                } else if (desc_idx == 1) {
                    send_ep0_data(s_str_manuf, sizeof(s_str_manuf), wLength);
                } else if (desc_idx == 2) {
                    send_ep0_data(s_str_prod, sizeof(s_str_prod), wLength);
                } else if (desc_idx == 3) {
                    send_ep0_data(s_str_serial, sizeof(s_str_serial), wLength);
                } else if (desc_idx == 4) {
                    send_ep0_data(s_str_ccid, sizeof(s_str_ccid), wLength);
                } else if (desc_idx == 5) {
                    send_ep0_data(s_str_kbd, sizeof(s_str_kbd), wLength);
                } else {
                    USBD_TASKS_EP0STALL = 1;
                }
                return;
            }
        } else if (bRequest == 0x05) {
            /* SET_ADDRESS: Handled automatically by hardware */
            uart_puts("  -> Set Address: ");
            uart_puthex32(wValue);
            uart_puts("\r\n");
            USBD_TASKS_EP0STATUS = 1;
            return;
        } else if (bRequest == 0x09) {
            /* SET_CONFIGURATION */
            uart_puts("  -> Set Config: ");
            uart_puthex32(wValue);
            uart_puts("\r\n");
            m_usb_configured = (uint8_t)wValue;
            USBD_EPINEN = 0x0F;  /* Enable EP0, EP1, EP2, EP3 IN */
            USBD_EPOUTEN = 0x07; /* Enable EP0, EP1, EP2 OUT */
            USBD_TASKS_EP0STATUS = 1;
            uart_puts("  -> Configured! Ready for CTAPHID (EP1), CCID (EP2), Keyboard (EP3).\r\n");

            /* Prime EP1 and EP2 OUT to accept data from host */
            USBD_SIZE_EPOUT(1) = 0;
            USBD_SIZE_EPOUT(2) = 0;
            return;
        } else if (bRequest == 0x08) {
            /* GET_CONFIGURATION */
            send_ep0_data(&m_usb_configured, 1, wLength);
            return;
        } else if (bRequest == 0x00) {
            /* GET_STATUS */
            static const uint8_t zero_status[2] = {0, 0};
            send_ep0_data(zero_status, 2, wLength);
            return;
        }
    }

    /* 2. Standard Interface Requests (e.g. HID Report Descriptor, CCID Descriptor) */
    if (bmRequestType == 0x81 && bRequest == 0x06) {
        uint8_t desc_type = (uint8_t)(wValue >> 8);
        uint8_t iface     = (uint8_t)(wIndex & 0xFF);
        if (iface == 0) {
            if (desc_type == 0x22) {
                /* HID Report Descriptor */
                uart_puts("  -> Get HID Report Desc\r\n");
                send_ep0_data(s_hid_report_desc, sizeof(s_hid_report_desc), wLength);
                return;
            } else if (desc_type == 0x21) {
                /* HID Descriptor */
                uart_puts("  -> Get HID Desc\r\n");
                send_ep0_data(&s_config_desc[18], 9, wLength);
                return;
            }
        } else if (iface == 1) {
            if (desc_type == 0x21) {
                /* CCID Functional Descriptor */
                uart_puts("  -> Get CCID Functional Desc\r\n");
                send_ep0_data(&s_config_desc[50], 54, wLength);
                return;
            }
        } else if (iface == 2) {
            if (desc_type == 0x22) {
                /* Keyboard HID Report Descriptor */
                uart_puts("  -> Get Keyboard HID Report Desc\r\n");
                send_ep0_data(s_kbd_report_desc, sizeof(s_kbd_report_desc), wLength);
                return;
            } else if (desc_type == 0x21) {
                /* Keyboard HID Descriptor */
                uart_puts("  -> Get Keyboard HID Desc\r\n");
                send_ep0_data(&s_config_desc[127], 9, wLength);
                return;
            }
        }
    }

    /* 3. Class Requests */
    if ((bmRequestType & 0x60) == 0x20) {
        uint8_t iface = (uint8_t)(wIndex & 0xFF);
        if (iface == 0 || iface == 2) {
            /* HID Class Requests (FIDO2 or Keyboard) */
            if (bRequest == 0x0A) {
                /* SET_IDLE */
                uart_puts("  -> Set Idle\r\n");
                USBD_TASKS_EP0STATUS = 1;
                return;
            } else if (bRequest == 0x02) {
                /* GET_IDLE */
                static const uint8_t idle_rate = 0;
                send_ep0_data(&idle_rate, 1, wLength);
                return;
            } else if (bRequest == 0x09) {
                /* SET_REPORT (e.g. Keyboard LEDs) */
                uart_puts("  -> Set Report\r\n");
                USBD_TASKS_EP0STATUS = 1;
                return;
            }
        } else if (iface == 1) {
            /* CCID Class Requests */
            if (bRequest == 0x02) { /* ABORT */
                uart_puts("  -> CCID Abort\r\n");
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

    /* Unsupported request: Stall */
    uart_puts("  -> STALL unsupported request\r\n");
    USBD_TASKS_EP0STALL = 1;
}

/* ==================== Main Application ==================== */
int main(void) {
    /* 0. SysTick: 1 ms tick @ 64 MHz */
    #define SYST_CSR   (*(volatile uint32_t *)0xE000E010UL)
    #define SYST_RVR   (*(volatile uint32_t *)0xE000E014UL)
    #define SYST_CVR   (*(volatile uint32_t *)0xE000E018UL)
    SYST_RVR = 64000 - 1;
    SYST_CVR = 0;
    SYST_CSR = 7; /* CLKSOURCE(4) | TICKINT(2) | ENABLE(1) */

    /* 1. Configure LED */
    P0_DIRSET = (1UL << PIN_LED);
    P0_PIN_CNF(PIN_LED) = 0x00000001UL;
    P0_OUTSET = (1UL << PIN_LED); /* LED OFF initially */

    /* 1b. Configure Touch / Button Pin (P0.11) with internal pull-down */
    P0_PIN_CNF(PIN_TOUCH) = 0x00000004UL;

    /* 1c. Emergency Bootloader Recovery: hold Touch (P0.11) for ~2s on boot */
    if (P0_IN & (1UL << PIN_TOUCH)) {
        int held_count = 0;
        for (int i = 0; i < 200; i++) {
            for (volatile int d = 0; d < 6400; d++); /* ~10 ms delay */
            if (P0_IN & (1UL << PIN_TOUCH)) {
                held_count++;
                if ((held_count % 20) < 10) P0_OUTCLR = (1UL << PIN_LED);
                else P0_OUTSET = (1UL << PIN_LED);
            } else {
                break;
            }
        }
        if (held_count >= 180) {
            P0_OUTSET = (1UL << PIN_LED);
            system_reboot_to_bootloader();
        }
    }

    /* 2. Configure Debug UART (P0.10) */
    uart_init();
    uart_puts("\r\n=========================================\r\n");
    uart_puts("   hyprkey USB FIDO2/U2F Security Key    \r\n");
    uart_puts("=========================================\r\n");

    /* 3. Initialize FIDO Cryptographic Engine */
    fido_init();
    uart_puts("[FIDO] Crypto engine initialized\r\n");

    /* 3b. Initialize CCID / OpenPGP Smart Card Engine */
    ccid_init();
    uart_puts("[CCID] OpenPGP Smart Card engine initialized\r\n");

    /* 4. Start 32 MHz High-Frequency Crystal (HFXO) */
    uart_puts("[CLK] Starting 32 MHz crystal oscillator (HFXO)...\r\n");
    CLOCK_EVENTS_HFCLKSTARTED = 0;
    CLOCK_TASKS_HFCLKSTART = 1;
    while (!CLOCK_EVENTS_HFCLKSTARTED);
    CLOCK_EVENTS_HFCLKSTARTED = 0;
    uart_puts("[CLK] HFXO started successfully!\r\n");

    /* 5. Apply Silicon Errata 171/187 Workaround before USBD Enable */
    if (*(volatile uint32_t *)0x4006EC00 == 0) {
        *(volatile uint32_t *)0x4006EC00 = 0x00009375;
    }
    *(volatile uint32_t *)0x4006EC14 = 0x000000C0;
    *(volatile uint32_t *)0x4006EC00 = 0x00009375;

    /* 6. Enable USBD Peripheral (This powers on the internal 3.3V USB regulator!) */
    uart_puts("[USBD] Enabling USBD controller...\r\n");
    USBD_ENABLE = 1;

    /* 7. Wait for USB 3.3V Power Regulator Ready */
    uart_puts("[PWR] Waiting for USB 3.3V power regulator...\r\n");
    uint32_t pwr_timeout = 500000;
    while (((POWER_USBREGSTATUS & 0x02) == 0) && --pwr_timeout);
    uart_puts("[PWR] USBREGSTATUS = ");
    uart_puthex32(POWER_USBREGSTATUS);
    uart_puts("\r\n");

    /* 8. Wait for 48 MHz PLL READY event */
    uart_puts("[USBD] Waiting for 48 MHz PLL lock...\r\n");
    uint32_t pll_timeout = 500000;
    while ((!USBD_EVENTS_USBEVENT || !(USBD_EVENTCAUSE & 1)) && --pll_timeout);
    USBD_EVENTS_USBEVENT = 0;
    USBD_EVENTCAUSE = 1;
    uart_puts("[USBD] USBD controller 48 MHz PLL locked!\r\n");

    /* Clear Errata Workaround */
    if (*(volatile uint32_t *)0x4006EC00 == 0) {
        *(volatile uint32_t *)0x4006EC00 = 0x00009375;
    }
    *(volatile uint32_t *)0x4006EC14 = 0x00000000;
    *(volatile uint32_t *)0x4006EC00 = 0x00009375;

    /* 9. Enable EP0 & Connect USB Pull-Up Resistor (triggers host enumeration!) */
    USBD_EPINEN = 0x01;
    USBD_EPOUTEN = 0x01;
    USBD_USBPULLUP = 1;
    uart_puts("[USBD] Pull-up resistor enabled -> Device attached to host!\r\n");

    /* 10. Main USB Event Loop */
    static uint32_t s_btn_counter = 0;
    static bool s_btn_pressed = false;

    while (1) {
        /* Check Touch / Button on P0.11 */
        if (m_usb_configured) {
            if (P0_IN & (1UL << PIN_TOUCH)) {
                s_btn_counter++;
                if (s_btn_counter > 50000 && !s_btn_pressed) {
                    s_btn_pressed = true;
                    uart_puts("[BTN] Touch / Button triggered!\r\n");
                    kbd_type_string("hyprkey-sec-k3y-otp-2026\n");
                }
            } else {
                if (s_btn_counter > 0) s_btn_counter--;
                if (s_btn_counter == 0) s_btn_pressed = false;
            }
        }
        /* Check USB Reset */
        if (USBD_EVENTS_USBRESET) {
            USBD_EVENTS_USBRESET = 0;
            USBD_EPINEN = 0x01;
            USBD_EPOUTEN = 0x01;
            m_usb_configured = 0;
            uart_puts("\r\n[USB] === BUS RESET ===\r\n");
        }

        /* Check USBEVENT */
        if (USBD_EVENTS_USBEVENT) {
            uint32_t cause = USBD_EVENTCAUSE;
            USBD_EVENTS_USBEVENT = 0;
            USBD_EVENTCAUSE = cause;
            uart_puts("[EVT] USBEVENT cause=");
            uart_puthex32(cause);
            uart_puts("\r\n");
        }

        /* Check EP0 SETUP Packet */
        if (USBD_EVENTS_EP0SETUP) {
            USBD_EVENTS_EP0SETUP = 0;
            handle_ep0_setup();
        }

        /* Check EP1 OUT packet reception from host */
        if (m_usb_configured && (USBD_EPDATASTATUS & (1UL << 17))) {
            USBD_EPDATASTATUS = (1UL << 17); /* Clear status flag */
            USBD_EVENTS_EPDATA = 0;

            /* Copy packet from endpoint buffer into RAM via EasyDMA */
            USBD_EPOUT(1)->PTR = (uint32_t)m_ep1_rx_buf;
            USBD_EPOUT(1)->MAXCNT = 64;
            USBD_EVENTS_ENDEPOUT(1) = 0;
            USBD_TASKS_STARTEPOUT(1) = 1;

            uint32_t timeout = 500000;
            while (!USBD_EVENTS_ENDEPOUT(1) && --timeout);
            USBD_EVENTS_ENDEPOUT(1) = 0;

            /* Re-arm EP1 OUT immediately so hardware can accept next packet */
            USBD_SIZE_EPOUT(1) = 0;

            process_incoming_ctaphid_packet(m_ep1_rx_buf);
        }

        /* Check EP2 OUT packet reception from host (CCID / OpenPGP) */
        if (m_usb_configured && (USBD_EPDATASTATUS & (1UL << 18))) {
            USBD_EPDATASTATUS = (1UL << 18); /* Clear status flag */
            USBD_EVENTS_EPDATA = 0;
            g_dbg_ccid_rx_count++;

            uint8_t bytes_received = (uint8_t)USBD_SIZE_EPOUT(2);

            /* Copy packet from endpoint buffer into RAM via EasyDMA */
            USBD_EPOUT(2)->PTR = (uint32_t)m_ep2_rx_buf;
            USBD_EPOUT(2)->MAXCNT = 64;
            USBD_EVENTS_ENDEPOUT(2) = 0;
            USBD_TASKS_STARTEPOUT(2) = 1;

            uint32_t timeout = 500000;
            while (!USBD_EVENTS_ENDEPOUT(2) && --timeout);
            USBD_EVENTS_ENDEPOUT(2) = 0;

            if (bytes_received == 0) {
                bytes_received = (uint8_t)USBD_EPOUT(2)->AMOUNT;
            }
            if (bytes_received == 0) {
                bytes_received = 64;
            }

            USBD_SIZE_EPOUT(2) = 0;

            process_incoming_ccid_packet(m_ep2_rx_buf, bytes_received);
        }
    }

    return 0;
}

/* ==================== Startup & Vector Table ==================== */
extern uint32_t _estack;
extern uint32_t _etext, _sdata, _edata, _sbss, _ebss;

void HardFault_Handler(void) {
    uart_puts("\r\n!!! HARDFAULT !!!\r\n");
    while (1);
}

void Default_Handler(void) {
    while (1);
}

void SysTick_Handler(void) {
    g_uptime_ms++;
}

void Reset_Handler(void) {
    (*(volatile uint32_t *)0xE000ED08UL) = 0x00026000UL; /* Relocate VTOR */
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst++ = 0;
    }
    main();
    while (1);
}

__attribute__((section(".isr_vector"), used))
const uint32_t vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,   /* NMI */
    (uint32_t)HardFault_Handler, /* HardFault */
    (uint32_t)Default_Handler,   /* MemManage */
    (uint32_t)Default_Handler,   /* BusFault */
    (uint32_t)Default_Handler,   /* UsageFault */
    0, 0, 0, 0,
    (uint32_t)Default_Handler,   /* SVCall */
    (uint32_t)Default_Handler,   /* DebugMon */
    0,
    (uint32_t)Default_Handler,   /* PendSV */
    (uint32_t)SysTick_Handler,   /* SysTick */
};

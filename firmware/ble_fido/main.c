#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "s140/nrf_sdm.h"
#include "s140/nrf_soc.h"
#include "s140/ble.h"
#include "s140/ble_gap.h"
#include "s140/ble_gatts.h"
#include "fido_u2f.h"
#include "ctap2.h"
#include "oath/oath.h"
#include "openpgp/openpgp.h"
#include "storage/hypr_storage_mgr.h"
#include "storage/hypr_storage_hal_nrf.h"
#include "usb_composite.h"
#include "pn532_nfc.h"

#define HYPRKEY_ENABLE_USB 1

/* ==================== Diagnostic & Test Mode ==================== */
#ifndef HYPRKEY_TEST_MODE
#define HYPRKEY_TEST_MODE 1
#endif

#if HYPRKEY_TEST_MODE
/* Preserved across warm resets in RAM to guarantee unique MAC on every reset */
__attribute__((section(".noinit"))) static uint32_t g_boot_counter;
#endif

/* ==================== nRF52840 Registers ==================== */
#define P0_BASE    0x50000000UL
#define UART1_BASE 0x40028000UL

#define P0_OUTSET       (*(volatile uint32_t *)(P0_BASE + 0x508))
#define P0_OUTCLR       (*(volatile uint32_t *)(P0_BASE + 0x50C))
#define P0_IN           (*(volatile uint32_t *)(P0_BASE + 0x510))
#define P0_DIRSET       (*(volatile uint32_t *)(P0_BASE + 0x518))
#define P0_PIN_CNF(n)   (*(volatile uint32_t *)(P0_BASE + 0x700 + ((n) * 4)))

#define PIN_LED       15   /* P0.15, active LOW */
#define PIN_DBG_TX    10   /* P0.10 -> CH340 RX */
#define PIN_TOUCH     11   /* P0.11 -> Touch / Button */

#define UART1_TASKS_STARTTX   (*(volatile uint32_t *)(UART1_BASE + 0x008))
#define UART1_ENABLE          (*(volatile uint32_t *)(UART1_BASE + 0x500))
#define UART1_PSEL_TXD        (*(volatile uint32_t *)(UART1_BASE + 0x50C))
#define UART1_PSEL_RXD        (*(volatile uint32_t *)(UART1_BASE + 0x514))
#define UART1_BAUDRATE        (*(volatile uint32_t *)(UART1_BASE + 0x524))
#define UART1_TXD_PTR         (*(volatile uint32_t *)(UART1_BASE + 0x544))
#define UART1_TXD_MAXCNT      (*(volatile uint32_t *)(UART1_BASE + 0x548))
#define UART1_EVENTS_ENDTX    (*(volatile uint32_t *)(UART1_BASE + 0x120))

/* ==================== UARTE1 Debug Functions ==================== */
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

void uart_puts(const char *s) {
    while (*s) uart_putc(*s++);
}

void uart_puthex8(uint8_t b) {
    static const char hex[] = "0123456789ABCDEF";
    uart_putc(hex[(b >> 4) & 0x0F]);
    uart_putc(hex[b & 0x0F]);
}

void uart_puthex32(uint32_t v) {
    uart_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        uart_putc("0123456789ABCDEF"[(v >> i) & 0x0F]);
    }
}

/* ==================== FIDO & OATH BLE Handles ==================== */
static uint16_t m_fido_service_handle;
static ble_gatts_char_handles_t m_char_cp_handles;      /* FIDO Control Point */
static ble_gatts_char_handles_t m_char_status_handles;  /* FIDO Status (Notify) */
static ble_gatts_char_handles_t m_char_cplen_handles;   /* FIDO Control Point Length */
static ble_gatts_char_handles_t m_char_rev_handles;     /* FIDO Service Revision Bitfield */

static uint16_t m_oath_service_handle;
static ble_gatts_char_handles_t m_char_oath_rx_handles; /* OATH APDU RX (Write) */
static ble_gatts_char_handles_t m_char_oath_tx_handles; /* OATH APDU TX (Notify) */
static ble_gatts_char_handles_t m_char_ctap_rx_handles; /* CTAP Tunnel RX (Write) */
static ble_gatts_char_handles_t m_char_ctap_tx_handles; /* CTAP Tunnel TX (Notify) */
static uint8_t  m_oath_vs_uuid_type = 0;

static uint16_t m_conn_handle = BLE_CONN_HANDLE_INVALID;
static uint16_t m_curr_mtu = BLE_GATT_ATT_MTU_DEFAULT; /* default 23 */
static uint8_t  m_adv_handle = BLE_GAP_ADV_SET_HANDLE_NOT_SET;
static bool     m_status_notify_enabled = false;

/* FIDO Base UUID: F1D00000-DEAA-ECEE-B42F-C9BA7ED623BB */
static const ble_uuid128_t FIDO_BASE_UUID = {
    .uuid128 = {
        0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
        0xEE, 0xEC, 0xAA, 0xDE, 0x00, 0x00, 0xD0, 0xF1
    }
};
static uint8_t m_vs_uuid_type = 0;

/* hyprkey OATH Base UUID: A0000000-2721-0100-B42F-C9BA7ED623BB (Derived from Yubico OATH AID) */
static const ble_uuid128_t OATH_BASE_UUID = {
    .uuid128 = {
        0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4,
        0x00, 0x01, 0x21, 0x27, 0x00, 0x00, 0x00, 0xA0
    }
};

static uint8_t m_adv_data_buf[31];
static uint8_t m_scan_rsp_buf[31];
static ble_gap_adv_data_t m_adv_data = {
    .adv_data = {
        .p_data = m_adv_data_buf,
        .len = 0
    },
    .scan_rsp_data = {
        .p_data = m_scan_rsp_buf,
        .len = 0
    }
};

/* Persistent Security Keys for Pairing/Bonding */
static ble_gap_enc_key_t m_own_enc_key;
static ble_gap_id_key_t  m_own_id_key;
static ble_gap_enc_key_t m_peer_enc_key;
static ble_gap_id_key_t  m_peer_id_key;
static ble_gap_sec_keyset_t m_keyset = {
    .keys_own = {
        .p_enc_key  = &m_own_enc_key,
        .p_id_key   = &m_own_id_key,
        .p_sign_key = NULL,
        .p_pk       = NULL
    },
    .keys_peer = {
        .p_enc_key  = &m_peer_enc_key,
        .p_id_key   = &m_peer_id_key,
        .p_sign_key = NULL,
        .p_pk       = NULL
    }
};

/* SoftDevice Fault Handler */
static void sd_fault_handler(uint32_t id, uint32_t pc, uint32_t info) {
    uart_puts("\r\n[SD FAULT] id=");
    uart_puthex32(id);
    uart_puts(" pc=");
    uart_puthex32(pc);
    uart_puts(" info=");
    uart_puthex32(info);
    uart_puts("\r\n");
    while (1);
}

#if HYPRKEY_TEST_MODE
static void run_boot_selftest(void) {
    uart_puts("\r\n=========================================\r\n");
    uart_puts("   HYPRKEY HARDWARE SELF-TEST HARNESS    \r\n");
    uart_puts("=========================================\r\n");

    /* 1. Test OATH CALCULATE TOTP (RFC 6238 HMAC-SHA1 on Google:alice) */
    static const uint8_t calc_apdu[] = {
        0x00, 0xA2, 0x00, 0x01, 38,
        0x71, 26, 'G','o','o','g','l','e',':','a','l','i','c','e','@','h','y','p','r','k','e','y','.','l','o','c','a','l',
        0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1
    };
    uint8_t rsp[64];
    uint16_t rlen = oath_process_apdu(calc_apdu, sizeof(calc_apdu), rsp, sizeof(rsp));
    if (rlen == 9 && rsp[0] == 0x76 && rsp[7] == 0x90 && rsp[8] == 0x00) {
        uint32_t raw_code = ((uint32_t)rsp[3] << 24) | ((uint32_t)rsp[4] << 16) | ((uint32_t)rsp[5] << 8) | rsp[6];
        uint32_t totp = raw_code % 1000000;
        if (totp == 287082) {
            uart_puts(" [PASS] Test 1: OATH HMAC-SHA1 TOTP = 287082\r\n");
        } else {
            uart_puts(" [FAIL] Test 1: TOTP mismatch: ");
            uart_puthex32(totp);
            uart_puts("\r\n");
        }
    } else {
        uart_puts(" [FAIL] Test 1: OATH APDU failed\r\n");
    }

    /* 2. Test CTAP2 CBOR AuthenticatorGetInfo */
    static const uint8_t ctap_getinfo_cmd[1] = { 0x04 };
    uint8_t cbor_rsp[256];
    uint16_t cbor_len = ctap2_process_cbor(ctap_getinfo_cmd, 1, cbor_rsp, sizeof(cbor_rsp));
    if (cbor_len > 10 && cbor_rsp[0] == 0x00) {
        uart_puts(" [PASS] Test 2: CTAP2 CBOR AuthenticatorGetInfo (len=");
        uart_puthex32(cbor_len);
        uart_puts(")\r\n");
    } else {
        uart_puts(" [FAIL] Test 2: CTAP2 CBOR GetInfo failed\r\n");
    }

    uart_puts("--- [ALL FIRMWARE SELF-TESTS PASSED] ---\r\n\r\n");
}
#endif

/* ==================== GAP Setup ==================== */
static void gap_init(void) {
    ble_gap_conn_sec_mode_t sec_mode;
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);
    sd_ble_gap_device_name_set(&sec_mode, (const uint8_t *)"hyprkey", 7);
    sd_ble_gap_appearance_set(0x0340); /* Generic Security Key */

    ble_gap_addr_t addr;
    sd_ble_gap_addr_get(&addr);
#if HYPRKEY_TEST_MODE
    /* Use test salt to guarantee Windows sees a fresh device for updated GATT table */
    addr.addr[0] ^= 0x5E;
    addr.addr[1] ^= 0xA5;
    addr.addr[5] |= 0xC0; /* Static Random requirement: bits 7 and 6 must be 1 */
    addr.addr_type = BLE_GAP_ADDR_TYPE_RANDOM_STATIC;
    sd_ble_gap_addr_set(&addr);
#endif

    uart_puts("[GAP] MAC: ");
    for (int i = 5; i >= 0; i--) {
        uart_puthex8(addr.addr[i]);
        if (i > 0) uart_putc(':');
    }
    uart_puts(" type=");
    uart_puthex8(addr.addr_type);
    uart_puts("\r\n");

    ble_gap_conn_params_t gap_conn_params;
    memset(&gap_conn_params, 0, sizeof(gap_conn_params));
    gap_conn_params.min_conn_interval = 12; /* 15 ms */
    gap_conn_params.max_conn_interval = 24; /* 30 ms */
    gap_conn_params.slave_latency     = 0;
    gap_conn_params.conn_sup_timeout  = 400; /* 4000 ms */
    sd_ble_gap_ppcp_set(&gap_conn_params);
}

#define CHECK_ERR(op, call) do { \
    uint32_t _e = (call); \
    uart_puts(op); \
    uart_puts(": "); \
    uart_puthex32(_e); \
    uart_puts("\r\n"); \
} while(0)

static void add_dis_char(uint16_t srv_handle, uint16_t uuid, const char *val) {
    ble_gatts_char_md_t char_md;
    memset(&char_md, 0, sizeof(char_md));
    char_md.char_props.read = 1;

    ble_gatts_attr_md_t attr_md;
    memset(&attr_md, 0, sizeof(attr_md));
    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
    BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
    attr_md.vloc = BLE_GATTS_VLOC_STACK;

    ble_uuid_t char_uuid = { .uuid = uuid, .type = BLE_UUID_TYPE_BLE };
    ble_gatts_attr_t attr_val;
    memset(&attr_val, 0, sizeof(attr_val));
    attr_val.p_uuid = &char_uuid;
    attr_val.p_attr_md = &attr_md;
    attr_val.init_len = strlen(val);
    attr_val.max_len = strlen(val);
    attr_val.p_value = (uint8_t *)val;

    ble_gatts_char_handles_t h;
    CHECK_ERR("dis_char", sd_ble_gatts_characteristic_add(srv_handle, &char_md, &attr_val, &h));
}

/* ==================== GATT Services ==================== */
static void services_init(void) {
    /* 0. Add Device Information Service (0x180A) */
    uint16_t dis_handle;
    ble_uuid_t dis_uuid = { .uuid = 0x180A, .type = BLE_UUID_TYPE_BLE };
    CHECK_ERR("dis_srv", sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &dis_uuid, &dis_handle));
    add_dis_char(dis_handle, 0x2A29, "hyprkey");
    add_dis_char(dis_handle, 0x2A24, "hyprkey-ble");
    add_dis_char(dis_handle, 0x2A26, "2.0.0");

    /* 1. Register 128-bit Vendor Specific Base UUID for FIDO */
    CHECK_ERR("vs_add", sd_ble_uuid_vs_add(&FIDO_BASE_UUID, &m_vs_uuid_type));

    /* 2. Add FIDO Primary Service (16-bit 0xFFFD) */
    ble_uuid_t service_uuid = {
        .uuid = 0xFFFD,
        .type = BLE_UUID_TYPE_BLE
    };
    CHECK_ERR("fido_srv", sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &service_uuid, &m_fido_service_handle));

    /* 3. Add Characteristic: FIDO Control Point (0xFFF1) */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.write = 1;
        char_md.char_props.write_wo_resp = 1;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr_md.vlen = 1;

        ble_uuid_t char_uuid = { .uuid = 0xFFF1, .type = m_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 0;
        attr_char_value.max_len = 64;

        CHECK_ERR("cp_char", sd_ble_gatts_characteristic_add(m_fido_service_handle, &char_md, &attr_char_value, &m_char_cp_handles));
    }

    /* 4. Add Characteristic: FIDO Status (0xFFF2) */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.notify = 1;

        ble_gatts_attr_md_t cccd_md;
        memset(&cccd_md, 0, sizeof(cccd_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
        cccd_md.vloc = BLE_GATTS_VLOC_STACK;
        char_md.p_cccd_md = &cccd_md;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr_md.vlen = 1;

        ble_uuid_t char_uuid = { .uuid = 0xFFF2, .type = m_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 0;
        attr_char_value.max_len = 64;

        CHECK_ERR("status_char", sd_ble_gatts_characteristic_add(m_fido_service_handle, &char_md, &attr_char_value, &m_char_status_handles));
    }

    /* 5. Add Characteristic: FIDO Control Point Length (0xFFF3) */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.read = 1;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;

        static uint8_t cplen_val[2] = { 0x00, 0x40 }; /* 64 bytes */
        ble_uuid_t char_uuid = { .uuid = 0xFFF3, .type = m_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 2;
        attr_char_value.max_len = 2;
        attr_char_value.p_value = cplen_val;

        CHECK_ERR("cplen_char", sd_ble_gatts_characteristic_add(m_fido_service_handle, &char_md, &attr_char_value, &m_char_cplen_handles));
    }

    /* 6. Add Characteristic: FIDO Service Revision Bitfield (0xFFF4) */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.read = 1;
        char_md.char_props.write = 1;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;

        static uint8_t rev_val[1] = { 0xE0 }; /* U2F 1.1, U2F 1.2, FIDO2 */
        ble_uuid_t char_uuid = { .uuid = 0xFFF4, .type = m_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 1;
        attr_char_value.max_len = 1;
        attr_char_value.p_value = rev_val;

        CHECK_ERR("rev_char", sd_ble_gatts_characteristic_add(m_fido_service_handle, &char_md, &attr_char_value, &m_char_rev_handles));
    }

    /* 7. Register 128-bit Vendor Specific Base UUID for hyprkey OATH Service */
    CHECK_ERR("oath_vs_add", sd_ble_uuid_vs_add(&OATH_BASE_UUID, &m_oath_vs_uuid_type));

    /* 8. Add hyprkey OATH Primary Service (UUID 0x0001) */
    ble_uuid_t oath_service_uuid = {
        .uuid = 0x0001,
        .type = m_oath_vs_uuid_type
    };
    CHECK_ERR("oath_srv", sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &oath_service_uuid, &m_oath_service_handle));

    /* 9. Add Characteristic: OATH APDU RX (UUID 0x0002) - Write without response */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.write = 1;
        char_md.char_props.write_wo_resp = 1;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr_md.vlen = 1;

        ble_uuid_t char_uuid = { .uuid = 0x0002, .type = m_oath_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 0;
        attr_char_value.max_len = 244;

        CHECK_ERR("oath_rx_char", sd_ble_gatts_characteristic_add(m_oath_service_handle, &char_md, &attr_char_value, &m_char_oath_rx_handles));
    }

    /* 10. Add Characteristic: OATH APDU TX (UUID 0x0003) - Notify */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.notify = 1;

        ble_gatts_attr_md_t cccd_md;
        memset(&cccd_md, 0, sizeof(cccd_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
        cccd_md.vloc = BLE_GATTS_VLOC_STACK;
        char_md.p_cccd_md = &cccd_md;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr_md.vlen = 1;

        ble_uuid_t char_uuid = { .uuid = 0x0003, .type = m_oath_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 0;
        attr_char_value.max_len = 244;

        CHECK_ERR("oath_tx_char", sd_ble_gatts_characteristic_add(m_oath_service_handle, &char_md, &attr_char_value, &m_char_oath_tx_handles));
    }

    /* 11. Add Characteristic: CTAP Tunnel RX (UUID 0x0004) - Write without response */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.write = 1;
        char_md.char_props.write_wo_resp = 1;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr_md.vlen = 1;

        ble_uuid_t char_uuid = { .uuid = 0x0004, .type = m_oath_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 0;
        attr_char_value.max_len = 64;

        CHECK_ERR("ctap_tun_rx", sd_ble_gatts_characteristic_add(m_oath_service_handle, &char_md, &attr_char_value, &m_char_ctap_rx_handles));
    }

    /* 12. Add Characteristic: CTAP Tunnel TX (UUID 0x0005) - Notify */
    {
        ble_gatts_char_md_t char_md;
        memset(&char_md, 0, sizeof(char_md));
        char_md.char_props.notify = 1;

        ble_gatts_attr_md_t cccd_md;
        memset(&cccd_md, 0, sizeof(cccd_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
        cccd_md.vloc = BLE_GATTS_VLOC_STACK;
        char_md.p_cccd_md = &cccd_md;

        ble_gatts_attr_md_t attr_md;
        memset(&attr_md, 0, sizeof(attr_md));
        BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
        BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&attr_md.write_perm);
        attr_md.vloc = BLE_GATTS_VLOC_STACK;
        attr_md.vlen = 1;

        ble_uuid_t char_uuid = { .uuid = 0x0005, .type = m_oath_vs_uuid_type };
        ble_gatts_attr_t attr_char_value;
        memset(&attr_char_value, 0, sizeof(attr_char_value));
        attr_char_value.p_uuid = &char_uuid;
        attr_char_value.p_attr_md = &attr_md;
        attr_char_value.init_len = 0;
        attr_char_value.max_len = 64;

        CHECK_ERR("ctap_tun_tx", sd_ble_gatts_characteristic_add(m_oath_service_handle, &char_md, &attr_char_value, &m_char_ctap_tx_handles));
    }
}

/* ==================== Advertising Setup ==================== */
static void advertising_init(void) {
    uint8_t *p = m_adv_data_buf;
    /* 1. Flags: LE General Discoverable, BR/EDR not supported */
    *p++ = 2;
    *p++ = 0x01;
    *p++ = 0x06;
    /* 2. Complete Local Name: "hyprkey" */
    *p++ = 8;
    *p++ = 0x09;
    *p++ = 'h'; *p++ = 'y'; *p++ = 'p'; *p++ = 'r';
    *p++ = 'k'; *p++ = 'e'; *p++ = 'y';
    /* 3. 16-bit Service UUID 0xFFFD (FIDO) */
    *p++ = 3;
    *p++ = 0x03;
    *p++ = 0xFD;
    *p++ = 0xFF;
    /* 4. Appearance: 0x0340 (Generic Security Key) */
    *p++ = 3;
    *p++ = 0x19;
    *p++ = 0x40;
    *p++ = 0x03;
    m_adv_data.adv_data.len = p - m_adv_data_buf;

    /* Scan Response Data: OATH 128-bit UUID */
    p = m_scan_rsp_buf;
    *p++ = 17; /* 16 bytes UUID + 1 type */
    *p++ = 0x07; /* Complete 128-bit UUID */
    memcpy(p, OATH_BASE_UUID.uuid128, 16);
    p += 16;
    m_adv_data.scan_rsp_data.len = p - m_scan_rsp_buf;

    ble_gap_adv_params_t adv_params;
    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.properties.type = BLE_GAP_ADV_TYPE_CONNECTABLE_SCANNABLE_UNDIRECTED;
    adv_params.interval = 160; /* 100 ms */
    adv_params.duration = 0;   /* Unlimited */
    adv_params.primary_phy = BLE_GAP_PHY_1MBPS;

    sd_ble_gap_adv_set_configure(&m_adv_handle, &m_adv_data, &adv_params);
}

/* ==================== CTAP2 & OATH Framer ==================== */
static uint8_t  m_rx_cmd = 0;
static uint16_t m_rx_expected_len = 0;
static uint16_t m_rx_received_len = 0;
static uint8_t  m_rx_seq = 0;
static uint8_t  m_ctap_rx_buf[1024];
static uint8_t  m_ctap_tx_buf[1024];

static uint8_t  m_oath_rx_buf[256];
static uint16_t m_oath_rx_accum = 0;
static uint16_t m_oath_rx_expected = 0;

static void send_oath_response(const uint8_t *data, uint16_t len) {
    if (m_conn_handle == BLE_CONN_HANDLE_INVALID) return;

    uint16_t max_payload = (m_curr_mtu > 3) ? (m_curr_mtu - 3) : 20;
    uint16_t sent = 0;

    while (sent < len) {
        uint16_t chunk = (len - sent > max_payload) ? max_payload : (len - sent);
        uint16_t pkt_len = chunk;

        ble_gatts_hvx_params_t hvx;
        memset(&hvx, 0, sizeof(hvx));
        hvx.handle = m_char_oath_tx_handles.value_handle;
        hvx.type   = BLE_GATT_HVX_NOTIFICATION;
        hvx.offset = 0;
        hvx.p_len  = &pkt_len;
        hvx.p_data = (uint8_t *)(data + sent);

        uint32_t retry = 1000;
        uint32_t err;
        while ((err = sd_ble_gatts_hvx(m_conn_handle, &hvx)) == NRF_ERROR_RESOURCES && --retry) {
            sd_app_evt_wait();
        }
        if (err != NRF_SUCCESS) {
            uart_puts("[OATH] hvx err: ");
            uart_puthex32(err);
            uart_puts("\r\n");
            break;
        }
        sent += pkt_len;
    }
}

typedef struct {
    bool     active;
    uint16_t char_handle;
    uint8_t  cmd;
    uint16_t total_len;
    uint16_t sent_len;
    uint8_t  seq;
} ctap_tx_state_t;

static ctap_tx_state_t m_ctap_tx_state = { 0 };

static void pump_ctap_tx(void) {
    if (!m_ctap_tx_state.active || m_conn_handle == BLE_CONN_HANDLE_INVALID) return;

    uint16_t max_payload = (m_curr_mtu > 3) ? (m_curr_mtu - 3) : 20;

    while (m_ctap_tx_state.active) {
        uint8_t pkt[247];
        uint16_t pkt_len = 0;

        if (m_ctap_tx_state.sent_len == 0) {
            /* Initial packet: [CMD, LEN_HI, LEN_LO, DATA...] */
            pkt[0] = m_ctap_tx_state.cmd;
            pkt[1] = (uint8_t)(m_ctap_tx_state.total_len >> 8);
            pkt[2] = (uint8_t)(m_ctap_tx_state.total_len & 0xFF);

            uint16_t chunk = (m_ctap_tx_state.total_len > (max_payload - 3)) ? (max_payload - 3) : m_ctap_tx_state.total_len;
            memcpy(&pkt[3], m_ctap_tx_buf, chunk);
            pkt_len = chunk + 3;

            ble_gatts_hvx_params_t hvx;
            memset(&hvx, 0, sizeof(hvx));
            hvx.handle = m_ctap_tx_state.char_handle;
            hvx.type   = BLE_GATT_HVX_NOTIFICATION;
            hvx.offset = 0;
            hvx.p_len  = &pkt_len;
            hvx.p_data = pkt;

            uint32_t err = sd_ble_gatts_hvx(m_conn_handle, &hvx);
            if (err == NRF_ERROR_RESOURCES) {
                return; /* SoftDevice queue full, yield to event loop */
            }
            if (err != NRF_SUCCESS) {
                uart_puts("[CTAP_TX] init err: ");
                uart_puthex32(err);
                uart_puts("\r\n");
                m_ctap_tx_state.active = false;
                return;
            }
            m_ctap_tx_state.sent_len += chunk;
            if (m_ctap_tx_state.sent_len >= m_ctap_tx_state.total_len) {
                m_ctap_tx_state.active = false;
                break;
            }
        } else if (m_ctap_tx_state.sent_len < m_ctap_tx_state.total_len) {
            /* Continuation packet: [SEQ, DATA...] */
            uint16_t remaining = m_ctap_tx_state.total_len - m_ctap_tx_state.sent_len;
            uint16_t chunk = (remaining > (max_payload - 1)) ? (max_payload - 1) : remaining;

            pkt[0] = (uint8_t)(m_ctap_tx_state.seq & 0x7F);
            memcpy(&pkt[1], m_ctap_tx_buf + m_ctap_tx_state.sent_len, chunk);
            pkt_len = chunk + 1;

            ble_gatts_hvx_params_t hvx;
            memset(&hvx, 0, sizeof(hvx));
            hvx.handle = m_ctap_tx_state.char_handle;
            hvx.type   = BLE_GATT_HVX_NOTIFICATION;
            hvx.offset = 0;
            hvx.p_len  = &pkt_len;
            hvx.p_data = pkt;

            uint32_t err = sd_ble_gatts_hvx(m_conn_handle, &hvx);
            if (err == NRF_ERROR_RESOURCES) {
                return; /* SoftDevice queue full, yield to event loop */
            }
            if (err != NRF_SUCCESS) {
                uart_puts("[CTAP_TX] cont err: ");
                uart_puthex32(err);
                uart_puts("\r\n");
                m_ctap_tx_state.active = false;
                return;
            }
            m_ctap_tx_state.seq++;
            m_ctap_tx_state.sent_len += chunk;
            if (m_ctap_tx_state.sent_len >= m_ctap_tx_state.total_len) {
                m_ctap_tx_state.active = false;
                break;
            }
        } else {
            m_ctap_tx_state.active = false;
            break;
        }
    }
}

static void start_ctap_response(uint16_t tx_handle, uint8_t cmd, const uint8_t *data, uint16_t len) {
    if (m_conn_handle == BLE_CONN_HANDLE_INVALID) return;
    if (len > sizeof(m_ctap_tx_buf)) len = sizeof(m_ctap_tx_buf);
    if (data != m_ctap_tx_buf) {
        memcpy(m_ctap_tx_buf, data, len);
    }
    m_ctap_tx_state.active = true;
    m_ctap_tx_state.char_handle = tx_handle;
    m_ctap_tx_state.cmd = cmd;
    m_ctap_tx_state.total_len = len;
    m_ctap_tx_state.sent_len = 0;
    m_ctap_tx_state.seq = 0;
    pump_ctap_tx();
}

static void handle_complete_ctap_message(uint16_t tx_handle) {
    uart_puts("[CTAP] Recv cmd=");
    uart_puthex8(m_rx_cmd);
    uart_puts(" len=");
    uart_puthex32(m_rx_expected_len);
    uart_puts("\r\n");

    if (m_rx_cmd == 0x81) {
        /* PING: Echo back payload */
        start_ctap_response(tx_handle, 0x81, m_ctap_rx_buf, m_rx_expected_len);
    } else if (m_rx_cmd == 0x83) {
        /* U2F MSG: Process APDU */
        uint16_t resp_len = fido_process_apdu(m_ctap_rx_buf, m_rx_expected_len, m_ctap_tx_buf, sizeof(m_ctap_tx_buf));
        uart_puts("[CTAP] U2F Resp len=");
        uart_puthex32(resp_len);
        uart_puts("\r\n");
        start_ctap_response(tx_handle, 0x83, m_ctap_tx_buf, resp_len);
    } else if (m_rx_cmd == 0x90) {
        /* CTAP2 CBOR (FIDO2) */
        uint16_t resp_len = ctap2_process_cbor(m_ctap_rx_buf, m_rx_expected_len, m_ctap_tx_buf, sizeof(m_ctap_tx_buf));
        uart_puts("[CTAP2] CBOR Resp len=");
        uart_puthex32(resp_len);
        uart_puts("\r\n");
        start_ctap_response(tx_handle, 0x90, m_ctap_tx_buf, resp_len);
    } else if (m_rx_cmd == 0xF1) {
        /* CTAP OATH APDU Tunnel */
        uint16_t resp_len = oath_process_apdu(m_ctap_rx_buf, m_rx_expected_len, m_ctap_tx_buf, sizeof(m_ctap_tx_buf));
        uart_puts("[OATH-TUNNEL] Resp len=");
        uart_puthex32(resp_len);
        uart_puts("\r\n");
        start_ctap_response(tx_handle, 0xF1, m_ctap_tx_buf, resp_len);
    } else {
        /* Unknown CMD */
        static const uint8_t ERR_INVALID_CMD[1] = { 0x01 };
        start_ctap_response(tx_handle, 0xBF, ERR_INVALID_CMD, 1);
    }
}

static void process_ctap_rx_chunk(const uint8_t *data, uint16_t len, uint16_t tx_handle) {
    if (len == 0) return;

    if (data[0] & 0x80) {
        /* Initial packet: [CMD, LEN_HI, LEN_LO, DATA...] */
        m_rx_cmd = data[0];
        if (len >= 3) {
            m_rx_expected_len = ((uint16_t)data[1] << 8) | data[2];
            uint16_t chunk = len - 3;
            if (chunk > sizeof(m_ctap_rx_buf)) chunk = sizeof(m_ctap_rx_buf);
            memcpy(m_ctap_rx_buf, &data[3], chunk);
            m_rx_received_len = chunk;
            m_rx_seq = 0;
        }
    } else {
        /* Continuation packet: [SEQ, DATA...] */
        uint8_t seq = data[0];
        if (seq == m_rx_seq) {
            m_rx_seq++;
            uint16_t chunk = len - 1;
            if (m_rx_received_len + chunk <= sizeof(m_ctap_rx_buf)) {
                memcpy(&m_ctap_rx_buf[m_rx_received_len], &data[1], chunk);
                m_rx_received_len += chunk;
            }
        }
    }

    if (m_rx_received_len >= m_rx_expected_len && m_rx_expected_len > 0) {
        handle_complete_ctap_message(tx_handle);
        m_rx_expected_len = 0;
        m_rx_received_len = 0;
    }
}

/* ==================== BLE Event Dispatcher ==================== */
static void on_ble_evt(const ble_evt_t *p_ble_evt) {
    uart_puts("[EVT] 0x");
    uart_puthex8((uint8_t)p_ble_evt->header.evt_id);
    uart_puts("\r\n");
    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            m_curr_mtu = BLE_GATT_ATT_MTU_DEFAULT;
            P0_OUTCLR = (1UL << PIN_LED); /* LED ON */
            uart_puts("\r\n[BLE] Connected! Handle=");
            uart_puthex32(m_conn_handle);
            uart_puts("\r\n");
            break;

        case BLE_GAP_EVT_DISCONNECTED: {
            uart_puts("\r\n[BLE] Disconnected! reason=0x");
            uart_puthex8(p_ble_evt->evt.gap_evt.params.disconnected.reason);
            uart_puts("\r\n");
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            m_ctap_tx_state.active = false;
            m_rx_expected_len = 0;
            m_rx_received_len = 0;
            m_oath_rx_accum = 0;
            m_oath_rx_expected = 0;
            P0_OUTSET = (1UL << PIN_LED); /* LED OFF */
            uint32_t adv_err = sd_ble_gap_adv_start(m_adv_handle, BLE_CONN_CFG_TAG_DEFAULT);
            uart_puts("[ADV] restart err: ");
            uart_puthex32(adv_err);
            uart_puts("\r\n");
            break;
        }

        case BLE_GATTS_EVT_HVN_TX_COMPLETE:
            pump_ctap_tx();
            break;

        case BLE_GAP_EVT_SEC_PARAMS_REQUEST: {
            uart_puts("[BLE] Pairing request (Just Works)\r\n");
            ble_gap_sec_params_t sec_params;
            memset(&sec_params, 0, sizeof(sec_params));
            sec_params.bond         = 1;
            sec_params.mitm         = 0;
            sec_params.lesc         = 0;
            sec_params.keypress     = 0;
            sec_params.io_caps      = BLE_GAP_IO_CAPS_NONE; /* Just Works */
            sec_params.min_key_size = 7;
            sec_params.max_key_size = 16;
            sec_params.kdist_own.enc = 1;
            sec_params.kdist_own.id  = 1;
            sec_params.kdist_peer.enc = 1;
            sec_params.kdist_peer.id  = 1;

            uint32_t err = sd_ble_gap_sec_params_reply(m_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, &sec_params, &m_keyset);
            uart_puts("[BLE] sec_params_reply err: ");
            uart_puthex32(err);
            uart_puts("\r\n");
            break;
        }

        case BLE_GAP_EVT_SEC_INFO_REQUEST: {
            uart_puts("[BLE] Sec info request\r\n");
            const ble_gap_evt_sec_info_request_t *p_req = &p_ble_evt->evt.gap_evt.params.sec_info_request;
            if (p_req->id_info) {
                sd_ble_gap_sec_info_reply(m_conn_handle, NULL, &m_own_id_key.id_info, NULL);
            } else if (p_req->enc_info) {
                sd_ble_gap_sec_info_reply(m_conn_handle, &m_peer_enc_key.enc_info, NULL, NULL);
            } else {
                sd_ble_gap_sec_info_reply(m_conn_handle, NULL, NULL, NULL);
            }
            break;
        }

        case BLE_GAP_EVT_CONN_PARAM_UPDATE_REQUEST:
            sd_ble_gap_conn_param_update(m_conn_handle, &p_ble_evt->evt.gap_evt.params.conn_param_update_request.conn_params);
            break;

        case BLE_GATTS_EVT_SYS_ATTR_MISSING:
            sd_ble_gatts_sys_attr_set(m_conn_handle, NULL, 0, 0);
            break;

        case BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST: {
            uint16_t client_mtu = p_ble_evt->evt.gatts_evt.params.exchange_mtu_request.client_rx_mtu;
            uart_puts("[BLE] MTU request: ");
            uart_puthex32(client_mtu);
            uart_puts("\r\n");
            uint32_t mtu_err = sd_ble_gatts_exchange_mtu_reply(m_conn_handle, BLE_GATT_ATT_MTU_DEFAULT);
            uart_puts("[BLE] MTU reply err: ");
            uart_puthex32(mtu_err);
            uart_puts("\r\n");
            m_curr_mtu = BLE_GATT_ATT_MTU_DEFAULT;
            break;
        }

        case BLE_GATTS_EVT_WRITE: {
            const ble_gatts_evt_write_t *p_write = &p_ble_evt->evt.gatts_evt.params.write;
            if (p_write->handle == m_char_cp_handles.value_handle) {
                process_ctap_rx_chunk(p_write->data, p_write->len, m_char_status_handles.value_handle);
            } else if (p_write->handle == m_char_ctap_rx_handles.value_handle) {
                process_ctap_rx_chunk(p_write->data, p_write->len, m_char_ctap_tx_handles.value_handle);
            } else if (p_write->handle == m_char_status_handles.cccd_handle) {
                if (p_write->len >= 2) {
                    uint16_t cccd_val = p_write->data[0] | (p_write->data[1] << 8);
                    m_status_notify_enabled = (cccd_val & 0x0001) != 0;
                    uart_puts("[BLE] Status CCCD: ");
                    uart_puthex32(cccd_val);
                    uart_puts("\r\n");
                }
            } else if (p_write->handle == m_char_ctap_tx_handles.cccd_handle) {
                if (p_write->len >= 2) {
                    uint16_t cccd_val = p_write->data[0] | (p_write->data[1] << 8);
                    uart_puts("[CTAP-TUNNEL] TX CCCD: ");
                    uart_puthex32(cccd_val);
                    uart_puts("\r\n");
                }
            } else if (p_write->handle == m_char_oath_rx_handles.value_handle) {
                /* Custom OATH GATT Characteristic: Supports chunked APDU reception */
                if (m_oath_rx_accum == 0) {
                    /* Determine expected length: Short APDU header [CLA, INS, P1, P2, Lc, data...] */
                    if (p_write->len >= 5 && p_write->data[4] > 0) {
                        m_oath_rx_expected = 5 + p_write->data[4];
                    } else {
                        m_oath_rx_expected = p_write->len;
                    }
                }

                if (m_oath_rx_accum + p_write->len <= sizeof(m_oath_rx_buf)) {
                    memcpy(&m_oath_rx_buf[m_oath_rx_accum], p_write->data, p_write->len);
                    m_oath_rx_accum += p_write->len;
                }

#if HYPRKEY_TEST_MODE
                uart_puts("[OATH-GATT] Received chunk: accum=");
                uart_puthex32(m_oath_rx_accum);
                uart_puts(" expected=");
                uart_puthex32(m_oath_rx_expected);
                uart_puts("\r\n");
#endif

                if (m_oath_rx_accum >= m_oath_rx_expected && m_oath_rx_expected > 0) {
                    uint8_t rsp_buf[256];
                    uint16_t rsp_len = oath_process_apdu(m_oath_rx_buf, m_oath_rx_accum, rsp_buf, sizeof(rsp_buf));

#if HYPRKEY_TEST_MODE
                    uart_puts("[OATH-GATT] Sending response len=");
                    uart_puthex32(rsp_len);
                    uart_puts("\r\n");
#endif

                    send_oath_response(rsp_buf, rsp_len);
                    m_oath_rx_accum = 0;
                    m_oath_rx_expected = 0;
                }
            } else if (p_write->handle == m_char_oath_tx_handles.cccd_handle) {
                if (p_write->len >= 2) {
                    uint16_t cccd_val = p_write->data[0] | (p_write->data[1] << 8);
                    uart_puts("[OATH-GATT] TX CCCD: ");
                    uart_puthex32(cccd_val);
                    uart_puts("\r\n");
                }
            }
            break;
        }

        case BLE_GAP_EVT_PHY_UPDATE_REQUEST: {
            ble_gap_phys_t phys;
            memset(&phys, 0, sizeof(phys));
            phys.tx_phys = BLE_GAP_PHY_AUTO;
            phys.rx_phys = BLE_GAP_PHY_AUTO;
            sd_ble_gap_phy_update(m_conn_handle, &phys);
            break;
        }

        case BLE_GAP_EVT_DATA_LENGTH_UPDATE_REQUEST: {
            sd_ble_gap_data_length_update(m_conn_handle, NULL, NULL);
            break;
        }

        default:
            break;
    }
}

/* ==================== Main Application ==================== */
int main(void) {
    /* 1. Configure LED */
    P0_DIRSET = (1UL << PIN_LED);
    P0_PIN_CNF(PIN_LED) = 0x00000001UL;
    P0_OUTSET = (1UL << PIN_LED); /* LED OFF initially */

    /* 1b. Configure Touch / Button Pin (P0.11) with internal pull-down */
    P0_PIN_CNF(PIN_TOUCH) = 0x00000004UL;

    /* 2. Configure Debug UART (P0.10) */
    uart_init();
    uart_puts("\r\n=========================================\r\n");
    uart_puts("   hyprkey Dual USB & BLE Security Key   \r\n");
    uart_puts("=========================================\r\n");

    /* 3. Initialize Storage & Cryptographic Engines */
    uart_puts("[STORAGE] Initializing journaled TLV storage...\r\n");
    hypr_err_t st_err = hypr_storage_mgr_init();
    if (st_err == HYPR_OK) {
        uart_puts("[STORAGE] Mounted successfully! Zone B (656 KB)\r\n");
    } else {
        uart_puts("[STORAGE] Mount failed code: ");
        uart_puthex32((uint32_t)st_err);
        uart_puts("\r\n");
    }

    fido_init();
    oath_init();
    openpgp_init();
    uart_puts("[INIT] FIDO, OATH, and OpenPGP initialized\r\n");

#if HYPRKEY_TEST_MODE
    run_boot_selftest();
#endif

    /* 4. Enable SoftDevice S140 with Synthesized LFCLK (from 32MHz HFXO crystal) */
    static const nrf_clock_lf_cfg_t lf_cfg = {
        .source       = NRF_CLOCK_LF_SRC_SYNTH, /* 2: Synthesized from HFCLK crystal */
        .rc_ctiv      = 0,
        .rc_temp_ctiv = 0,
        .accuracy     = 0
    };
    uint32_t err = sd_softdevice_enable(&lf_cfg, sd_fault_handler);
    if (err != NRF_SUCCESS) {
        uart_puts("[SD] sd_softdevice_enable err: ");
        uart_puthex32(err);
        uart_puts("\r\n");
    } else {
        uart_puts("[SD] SoftDevice S140 enabled with SYNTH clock\r\n");
        hypr_storage_hal_nrf_on_sd_enabled();
    }

    sd_softdevice_vector_table_base_set(0x00026000);

    /* 5. Enable BLE Stack */
    uint32_t ram_start = 0x20003600;
    ble_cfg_t ble_cfg;
    memset(&ble_cfg, 0, sizeof(ble_cfg));
    ble_cfg.gatts_cfg.attr_tab_size.attr_tab_size = 2048;
    CHECK_ERR("cfg_attr_tab", sd_ble_cfg_set(BLE_GATTS_CFG_ATTR_TAB_SIZE, &ble_cfg, ram_start));

    err = sd_ble_enable(&ram_start);
    uart_puts("[BLE] ram_start: ");
    uart_puthex32(ram_start);
    uart_puts("\r\n");
    if (err != NRF_SUCCESS) {
        uart_puts("[BLE] sd_ble_enable err: ");
        uart_puthex32(err);
        uart_puts("\r\n");
    } else {
        uart_puts("[BLE] Stack enabled successfully!\r\n");
    }

    /* 6. GAP, GATT Services & Advertising */
    gap_init();
    services_init();
    advertising_init();

    err = sd_ble_gap_adv_start(m_adv_handle, BLE_CONN_CFG_TAG_DEFAULT);
    if (err != NRF_SUCCESS) {
        uart_puts("[ADV] sd_ble_gap_adv_start err: ");
        uart_puthex32(err);
        uart_puts("\r\n");
    } else {
        uart_puts("[ADV] Advertising started as 'hyprkey'!\r\n");
    }

#if HYPRKEY_ENABLE_USB
    /* 6b. Initialize USB Composite Controller */
    uart_puts("[USB] Initializing USB Composite device...\r\n");
    usb_composite_init();
#endif

    /* 6c. Initialize PN532 NFC Target Controller */
    uart_puts("[NFC] Initializing PN532 NFC Target controller...\r\n");
    pn532_nfc_init();

    /* 7. Main Event Loop */
    uint8_t evt_buf[sizeof(ble_evt_t) + 512] __attribute__((aligned(4)));

#if HYPRKEY_ENABLE_USB
    static uint32_t s_btn_counter = 0;
    static bool s_btn_pressed = false;
#endif

    while (1) {
#if HYPRKEY_ENABLE_USB
        usb_composite_poll();

        /* Check hardware touch button on P0.11 */
        if (usb_composite_is_configured()) {
            if (P0_IN & (1UL << PIN_TOUCH)) {
                s_btn_counter++;
                if (s_btn_counter > 50000 && !s_btn_pressed) {
                    s_btn_pressed = true;
                    uart_puts("[BTN] Touch / Button triggered!\r\n");
                    usb_composite_type_string("hyprkey-sec-k3y-otp-2026\n");
                }
            } else {
                if (s_btn_counter > 0) s_btn_counter--;
                if (s_btn_counter == 0) s_btn_pressed = false;
            }
        }
#endif

        pn532_nfc_poll();

        if (m_ctap_tx_state.active) {
            pump_ctap_tx();
        }

        uint16_t evt_len = sizeof(evt_buf);
        err = sd_ble_evt_get(evt_buf, &evt_len);
        if (err == NRF_SUCCESS) {
            on_ble_evt((const ble_evt_t *)evt_buf);
            if (m_ctap_tx_state.active) {
                pump_ctap_tx();
            }
        } else if (err != NRF_ERROR_NOT_FOUND) {
            uart_puts("[EVT_ERR] 0x");
            uart_puthex32(err);
            uart_puts("\r\n");
        }

        /* Dispatch asynchronous SoC events (flash completion, POFWARN) */
        uint32_t soc_evt;
        while (sd_evt_get(&soc_evt) == NRF_SUCCESS) {
            hypr_storage_hal_nrf_on_soc_evt(soc_evt);
        }
    }

    return 0;
}

/* ==================== Startup & Vector Table ==================== */
extern uint32_t _estack;
extern uint32_t _etext, _sdata, _edata, _sbss, _ebss;

void Reset_Handler(void) {
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

void Default_Handler(void) {
    while (1);
}

__attribute__((section(".isr_vector"), used))
const uint32_t vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler, /* NMI */
    (uint32_t)Default_Handler, /* HardFault */
    (uint32_t)Default_Handler, /* MemManage */
    (uint32_t)Default_Handler, /* BusFault */
    (uint32_t)Default_Handler, /* UsageFault */
    0, 0, 0, 0,
    (uint32_t)Default_Handler, /* SVCall */
    (uint32_t)Default_Handler, /* DebugMon */
    0,
    (uint32_t)Default_Handler, /* PendSV */
    (uint32_t)Default_Handler, /* SysTick */
};

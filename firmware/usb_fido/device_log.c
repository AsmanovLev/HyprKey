#include "device_log.h"
#include <string.h>

volatile uint32_t g_uptime_ms = 0;

static device_log_entry_t s_log_ring[DEV_LOG_CAPACITY];
static uint32_t s_head = 0;
static uint32_t s_total_events = 0;

void dev_log_init(void) {
    memset(s_log_ring, 0, sizeof(s_log_ring));
    s_head = 0;
    s_total_events = 0;
    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, DEV_LOG_EVT_BOOT, 0x0005, 0); // version 5.0
}

void dev_log(uint8_t module, uint8_t severity, uint16_t event, uint32_t arg0, uint32_t arg1) {
    /* Fast critical section without halting pipeline */
    __asm__ volatile ("cpsid i" : : : "memory");

    device_log_entry_t *entry = &s_log_ring[s_head];
    entry->timestamp_ms = g_uptime_ms;
    entry->module_id    = module;
    entry->severity     = severity;
    entry->event_id     = event;
    entry->arg0         = arg0;
    entry->arg1         = arg1;

    s_head = (s_head + 1) % DEV_LOG_CAPACITY;
    s_total_events++;

    __asm__ volatile ("cpsie i" : : : "memory");
}

/* Process Vendor APDU:
 * CLA = 0xFF, INS = 0xFD
 * P1 = Sub-command:
 *      0x00 = Read Tail (P2 = max entries to return, 0 = 32)
 *      0x01 = Clear log buffer
 *      0x02 = Get log stats
 */
uint16_t dev_log_process_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (apdu_len < 4) {
        rsp[0] = 0x67; rsp[1] = 0x00; /* Wrong length */
        return 2;
    }

    uint8_t p1 = apdu[2];
    uint8_t p2 = apdu[3];

    if (p1 == 0x01) {
        /* Clear logs */
        __asm__ volatile ("cpsid i" : : : "memory");
        s_head = 0;
        memset(s_log_ring, 0, sizeof(s_log_ring));
        __asm__ volatile ("cpsie i" : : : "memory");

        dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_INFO, DEV_LOG_EVT_BOOT, 0x0005, 1);
        rsp[0] = 0x90; rsp[1] = 0x00;
        return 2;
    }

    if (p1 == 0x02) {
        /* Get stats: [total_events:4][capacity:2][uptime_ms:4] */
        if (max_rsp_len < 12) {
            rsp[0] = 0x67; rsp[1] = 0x00;
            return 2;
        }
        uint32_t tot = s_total_events;
        uint32_t upt = g_uptime_ms;
        rsp[0] = (uint8_t)((tot >> 24) & 0xFF);
        rsp[1] = (uint8_t)((tot >> 16) & 0xFF);
        rsp[2] = (uint8_t)((tot >> 8) & 0xFF);
        rsp[3] = (uint8_t)(tot & 0xFF);
        rsp[4] = 0x00;
        rsp[5] = DEV_LOG_CAPACITY;
        rsp[6] = (uint8_t)((upt >> 24) & 0xFF);
        rsp[7] = (uint8_t)((upt >> 16) & 0xFF);
        rsp[8] = (uint8_t)((upt >> 8) & 0xFF);
        rsp[9] = (uint8_t)(upt & 0xFF);
        rsp[10] = 0x90;
        rsp[11] = 0x00;
        return 12;
    }

    /* P1 == 0x00: Read Tail */
    uint8_t count_req = p2;
    if (count_req == 0 || count_req > 64) {
        count_req = 32; /* Default 32 latest entries */
    }

    uint32_t available = (s_total_events < DEV_LOG_CAPACITY) ? s_total_events : DEV_LOG_CAPACITY;
    if (count_req > available) {
        count_req = (uint8_t)available;
    }

    uint16_t payload_len = 9 + (count_req * sizeof(device_log_entry_t));
    if (payload_len + 2 > max_rsp_len) {
        rsp[0] = 0x67; rsp[1] = 0x00;
        return 2;
    }

    /* Header: [total_events:4][uptime_ms:4][count:1] */
    uint32_t tot = s_total_events;
    uint32_t upt = g_uptime_ms;
    rsp[0] = (uint8_t)((tot >> 24) & 0xFF);
    rsp[1] = (uint8_t)((tot >> 16) & 0xFF);
    rsp[2] = (uint8_t)((tot >> 8) & 0xFF);
    rsp[3] = (uint8_t)(tot & 0xFF);
    rsp[4] = (uint8_t)((upt >> 24) & 0xFF);
    rsp[5] = (uint8_t)((upt >> 16) & 0xFF);
    rsp[6] = (uint8_t)((upt >> 8) & 0xFF);
    rsp[7] = (uint8_t)(upt & 0xFF);
    rsp[8] = count_req;

    /* Copy in chronological order (oldest to newest among the last count_req) */
    uint32_t start_idx = (s_head + DEV_LOG_CAPACITY - count_req) % DEV_LOG_CAPACITY;
    uint8_t *dest = rsp + 9;
    for (uint8_t i = 0; i < count_req; i++) {
        uint32_t cur = (start_idx + i) % DEV_LOG_CAPACITY;
        memcpy(dest, &s_log_ring[cur], sizeof(device_log_entry_t));
        dest += sizeof(device_log_entry_t);
    }

    rsp[payload_len]     = 0x90;
    rsp[payload_len + 1] = 0x00;
    return payload_len + 2;
}

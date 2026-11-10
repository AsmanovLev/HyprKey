#include "ccid.h"
#include "openpgp/openpgp.h"
#include "piv/piv.h"
#include "oath/oath.h"
#include "device_log.h"
#include "storage_flash.h"
#include "../pn532_nfc.h"
#include <string.h>

typedef enum {
    CCID_APPLET_OPENPGP = 0,
    CCID_APPLET_PIV,
    CCID_APPLET_OATH
} ccid_applet_t;

static ccid_applet_t s_active_applet = CCID_APPLET_OPENPGP;
volatile uint8_t g_dfu_reset_pending = 0;

void ccid_init(void) {
    dev_log_init();
    openpgp_init();
    piv_init();
    oath_init();
    s_active_applet = CCID_APPLET_OPENPGP;
}

uint16_t ccid_process_message(const uint8_t *req, uint16_t req_len, uint8_t *rsp, uint16_t max_rsp_len) {
    if (req_len < 10) return 0;

    uint8_t msg_type = req[0];
    uint32_t length = (uint32_t)req[1] | ((uint32_t)req[2] << 8) |
                      ((uint32_t)req[3] << 16) | ((uint32_t)req[4] << 24);
    uint8_t slot = req[5];
    uint8_t seq  = req[6];

    if (slot != 0) {
        /* Slot does not exist */
        rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
        rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
        rsp[5] = slot;
        rsp[6] = seq;
        rsp[7] = 0x40 | 0x02; /* Command failed, No ICC present */
        rsp[8] = 0x05;        /* Slot not found */
        rsp[9] = 0;
        return 10;
    }

    switch (msg_type) {
        case CCID_PC_TO_RDR_ICC_POWER_ON: {
            uint16_t atr_len = openpgp_get_atr(rsp + 10, max_rsp_len - 10);
            rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
            rsp[1] = (uint8_t)(atr_len & 0xFF);
            rsp[2] = (uint8_t)((atr_len >> 8) & 0xFF);
            rsp[3] = 0;
            rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Command success, Card active */
            rsp[8] = 0x00; /* Error code 0 */
            rsp[9] = 0x00; /* Chain parameter */
            return 10 + atr_len;
        }

        case CCID_PC_TO_RDR_ICC_POWER_OFF: {
            rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
            rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x01; /* Card inactive */
            rsp[8] = 0x00;
            rsp[9] = 0x00;
            return 10;
        }

        case CCID_PC_TO_RDR_GET_SLOT_STATUS: {
            rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
            rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Card present and active */
            rsp[8] = 0x00;
            rsp[9] = 0x00;
            return 10;
        }

        case CCID_PC_TO_RDR_GET_PARAMETERS:
        case CCID_PC_TO_RDR_RESET_PARAMETERS:
        case CCID_PC_TO_RDR_SET_PARAMETERS: {
            /* T=1 Protocol Parameters */
            rsp[0] = CCID_RDR_TO_PC_PARAMETERS;
            rsp[1] = 7; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0; /* 7 bytes param */
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Card active */
            rsp[8] = 0x00;
            rsp[9] = 0x01; /* Protocol T=1 */
            /* T=1 Data: bmFindexDindex, bmTCCKST1, bGuardTimeT1, bmWaitingIntegersT1, bClockStop, bIFSC, bNadValue */
            rsp[10] = 0x18; /* Fi=372, Di=12 matching TA1 */
            rsp[11] = 0x00; /* LRC checksum */
            rsp[12] = 0x00; /* Extra guard time = 0 */
            rsp[13] = 0x75; /* BWI=7, CWI=5 matching TB3 */
            rsp[14] = 0x00; /* Clock stop not supported */
            rsp[15] = 0xFE; /* IFSC = 254 matching TA3 */
            rsp[16] = 0x00; /* NAD = 0 */
            return 17;
        }

        case CCID_PC_TO_RDR_XFR_BLOCK: {
            const uint8_t *apdu = req + 10;
            uint16_t apdu_len = (uint16_t)length;
            if (10 + apdu_len > req_len) {
                apdu_len = req_len - 10;
            }

            /* Log incoming APDU header: CLA INS P1 P2 */
            uint32_t apdu_hdr = (apdu_len >= 4) ? (((uint32_t)apdu[0] << 24) | ((uint32_t)apdu[1] << 16) | ((uint32_t)apdu[2] << 8) | apdu[3]) : 0;
            dev_log(DEV_LOG_MOD_CCID, DEV_LOG_SEV_INFO, DEV_LOG_EVT_CCID_XFR, apdu_hdr, apdu_len);

            /* Intercept Vendor APDU for Live Seamless A/B OTA (CLA=0xFF, INS=0xFC) */
            if (apdu_len >= 4 && apdu[0] == 0xFF && apdu[1] == 0xFC) {
                uint16_t apdu_rsp_len = ota_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                rsp[3] = 0;
                rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                return 10 + apdu_rsp_len;
            }

            /* Intercept Vendor APDU for DFU Bootloader Reset (FF FD 42 00 or FF FE 00 00)
             * Audit Finding 1.2: Enforce Admin PIN (PW3) authorization before resetting to DFU */
            if (apdu_len >= 4 && ((apdu[0] == 0xFF && apdu[1] == 0xFD && apdu[2] == 0x42) ||
                                  (apdu[0] == 0xFF && apdu[1] == 0xFE))) {
                if (!openpgp_is_pw3_verified()) {
                    dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDE, 0, 0);
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot;
                    rsp[6] = seq;
                    rsp[7] = 0x00;
                    rsp[8] = 0x00;
                    rsp[9] = 0x00;
                    rsp[10] = 0x69; /* SW1 = 0x69 */
                    rsp[11] = 0x82; /* SW2 = 0x82: Security status not satisfied */
                    return 12;
                }
                dev_log(DEV_LOG_MOD_SYS, DEV_LOG_SEV_WARN, 0xDF, 0, 0);
                g_dfu_reset_pending = 1;
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                rsp[10] = 0x90; /* SW1 = 0x90 */
                rsp[11] = 0x00; /* SW2 = 0x00 */
                return 12;
            }

            /* Intercept Vendor APDU for In-Memory Device Logs (CLA=0xFF, INS=0xFD) */
            if (apdu_len >= 4 && apdu[0] == 0xFF && apdu[1] == 0xFD) {
                uint16_t apdu_rsp_len = dev_log_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                rsp[3] = 0;
                rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                return 10 + apdu_rsp_len;
            }

            /* Intercept Vendor APDU for NFC Tag Scan / Inspection (INS=0xEA) */
            if (apdu_len >= 4 && apdu[1] == 0xEA) {
                uint16_t apdu_rsp_len = pn532_scan_tag(rsp + 10, max_rsp_len - 10);
                rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                rsp[3] = 0;
                rsp[4] = 0;
                rsp[5] = slot;
                rsp[6] = seq;
                rsp[7] = 0x00; /* Success, card active */
                rsp[8] = 0x00;
                rsp[9] = 0x00;
                return 10 + apdu_rsp_len;
            }

            /* Intercept Vendor APDU for NFC Physical Presence Lock Management (INS=0xEB) */
            if (apdu_len >= 4 && apdu[1] == 0xEB) {
                uint8_t sub_cmd = apdu[2];
                uint8_t mode = apdu[3];

                if (sub_cmd == 0x00) {
                    /* Query Lock Status: FF EB 00 00 */
                    uint8_t lmode;
                    bool locked;
                    uint8_t ulen;
                    uint8_t e_uid[10];
                    uint8_t e_hash[32];
                    pn532_get_lock_status(&lmode, &locked, &ulen, e_uid, e_hash);

                    uint16_t apdu_rsp_len = 0;
                    rsp[10 + apdu_rsp_len++] = lmode;
                    rsp[10 + apdu_rsp_len++] = locked ? 0x01 : 0x00;
                    rsp[10 + apdu_rsp_len++] = ulen;
                    memcpy(rsp + 10 + apdu_rsp_len, e_uid, ulen);
                    apdu_rsp_len += ulen;
                    memcpy(rsp + 10 + apdu_rsp_len, e_hash, 32);
                    apdu_rsp_len += 32;

                    rsp[10 + apdu_rsp_len++] = 0x90;
                    rsp[10 + apdu_rsp_len++] = 0x00;

                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                    rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                    rsp[3] = 0; rsp[4] = 0; rsp[5] = slot; rsp[6] = seq;
                    rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    return 10 + apdu_rsp_len;
                }

                /* Mutating commands (Enroll 0x01, Disable 0x02) require verified Admin PIN (PW3) */
                if (!openpgp_is_pw3_verified()) {
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x69; rsp[11] = 0x82; /* Security status not satisfied */
                    return 12;
                }

                if (sub_cmd == 0x01) {
                    /* Enroll: mode 1 = Static UID, mode 2 = EMV Crypto */
                    uint16_t apdu_rsp_len = 0;
                    if (mode == 0x01) {
                        uint8_t enrolled_uid[10];
                        uint8_t ulen = 0;
                        if (pn532_enroll_tag_uid(enrolled_uid, &ulen)) {
                            rsp[10 + apdu_rsp_len++] = 0x01; /* Warning: Insecure Static UID */
                            rsp[10 + apdu_rsp_len++] = ulen;
                            memcpy(rsp + 10 + apdu_rsp_len, enrolled_uid, ulen);
                            apdu_rsp_len += ulen;
                            rsp[10 + apdu_rsp_len++] = 0x90;
                            rsp[10 + apdu_rsp_len++] = 0x00;
                        } else {
                            rsp[10 + apdu_rsp_len++] = 0x6A;
                            rsp[10 + apdu_rsp_len++] = 0x80; /* Incorrect parameters / no card */
                        }
                    } else if (mode == 0x02) {
                        uint8_t hash[32];
                        if (pn532_enroll_emv_crypto(hash)) {
                            rsp[10 + apdu_rsp_len++] = 0x00; /* Secure: Zero-clone EMV */
                            memcpy(rsp + 10 + apdu_rsp_len, hash, 32);
                            apdu_rsp_len += 32;
                            rsp[10 + apdu_rsp_len++] = 0x90;
                            rsp[10 + apdu_rsp_len++] = 0x00;
                        } else {
                            rsp[10 + apdu_rsp_len++] = 0x6A;
                            rsp[10 + apdu_rsp_len++] = 0x80;
                        }
                    }
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
                    rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
                    rsp[3] = 0; rsp[4] = 0; rsp[5] = slot; rsp[6] = seq;
                    rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    return 10 + apdu_rsp_len;
                }

                if (sub_cmd == 0x02) {
                    /* Disable Lock */
                    pn532_disable_lock();
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x90; rsp[11] = 0x00;
                    return 12;
                }

                if (sub_cmd == 0x03) {
                    /* Lock now (re-arm lock immediately) */
                    pn532_lock_force();
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x90; rsp[11] = 0x00;
                    return 12;
                }
            }

            /* Explicit Applet Switching on SELECT AID (00 A4 04 ...) */
            if (apdu_len >= 5 && apdu[1] == 0xA4 && apdu[2] == 0x04) {
                uint8_t aid_len = apdu[4];
                const uint8_t *aid = apdu + 5;
                if (aid_len >= 7 && memcmp(aid, "\xA0\x00\x00\x05\x27\x21\x01", 7) == 0) {
                    s_active_applet = CCID_APPLET_OATH;
                    dev_log(DEV_LOG_MOD_OATH, DEV_LOG_SEV_INFO, DEV_LOG_EVT_OATH_SELECT, 0, 0);
                } else if (aid_len >= 11 && memcmp(aid, "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00", 11) == 0) {
                    s_active_applet = CCID_APPLET_PIV;
                    dev_log(DEV_LOG_MOD_PIV, DEV_LOG_SEV_INFO, DEV_LOG_EVT_CCID_APDU_ROUTE, CCID_APPLET_PIV, 0);
                } else if (aid_len >= 6 && memcmp(aid, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
                    s_active_applet = CCID_APPLET_OPENPGP;
                    dev_log(DEV_LOG_MOD_OPENPGP, DEV_LOG_SEV_INFO, DEV_LOG_EVT_PGP_SELECT, 0, 0);
                }
            }

            /* Check Physical Presence Lock: block cryptographic & secret operations if locked */
            if (pn532_is_locked()) {
                uint8_t ins = (apdu_len >= 2) ? apdu[1] : 0;
                /* If INS is PSO (0x2A), GENERATE KEY (0x47), GENERAL AUTHENTICATE (0x87),
                 * VERIFY (0x20), or CHANGE PIN (0x24), reject with 0x6982 */
                if (ins == 0x2A || ins == 0x47 || ins == 0x87 || ins == 0x20 || ins == 0x24) {
                    rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
                    rsp[1] = 2; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
                    rsp[5] = slot; rsp[6] = seq; rsp[7] = 0x00; rsp[8] = 0x00; rsp[9] = 0x00;
                    rsp[10] = 0x69; rsp[11] = 0x82; /* Security status not satisfied: device locked */
                    return 12;
                }
            }

            uint16_t apdu_rsp_len = 0;
            if (s_active_applet == CCID_APPLET_OATH) {
                apdu_rsp_len = oath_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
            } else if (s_active_applet == CCID_APPLET_PIV) {
                apdu_rsp_len = piv_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
            } else {
                apdu_rsp_len = openpgp_process_apdu(apdu, apdu_len, rsp + 10, max_rsp_len - 10);
            }

            /* Log SW response */
            uint16_t sw = (apdu_rsp_len >= 2) ? (((uint16_t)rsp[10 + apdu_rsp_len - 2] << 8) | rsp[10 + apdu_rsp_len - 1]) : 0;
            dev_log(DEV_LOG_MOD_CCID, (sw == 0x9000) ? DEV_LOG_SEV_INFO : DEV_LOG_SEV_WARN, DEV_LOG_EVT_CCID_SW, s_active_applet, sw);

            rsp[0] = CCID_RDR_TO_PC_DATA_BLOCK;
            rsp[1] = (uint8_t)(apdu_rsp_len & 0xFF);
            rsp[2] = (uint8_t)((apdu_rsp_len >> 8) & 0xFF);
            rsp[3] = 0;
            rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x00; /* Success, card active */
            rsp[8] = 0x00;
            rsp[9] = 0x00; /* Chain parameter */
            return 10 + apdu_rsp_len;
        }

        default: {
            /* Unsupported command */
            rsp[0] = CCID_RDR_TO_PC_SLOT_STATUS;
            rsp[1] = 0; rsp[2] = 0; rsp[3] = 0; rsp[4] = 0;
            rsp[5] = slot;
            rsp[6] = seq;
            rsp[7] = 0x40 | 0x00; /* Command failed, card active */
            rsp[8] = 0xFE;        /* Command not supported */
            rsp[9] = 0x00;
            return 10;
        }
    }
}

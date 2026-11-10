#include "scard_client.h"
#include <stdio.h>
#include <time.h>
#include <algorithm>

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string s;
    char buf[4];
    for (size_t i = 0; i < len; i++) {
        snprintf(buf, sizeof(buf), "%02X ", data[i]);
        s += buf;
    }
    return s;
}

static std::string current_timestamp() {
    time_t now = time(NULL);
    struct tm t;
    localtime_s(&t, &now);
    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", t.tm_hour, t.tm_min, t.tm_sec);
    return buf;
}

SCardClient::SCardClient()
    : m_hContext(NULL), m_hCard(NULL), m_dwActiveProtocol(0), m_connected(false) {
    SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
}

SCardClient::~SCardClient() {
    disconnect();
    if (m_hContext) {
        SCardReleaseContext(m_hContext);
        m_hContext = NULL;
    }
}

bool SCardClient::connect() {
    if (m_connected) return true;
    if (!m_hContext) {
        LONG res = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
        if (res != SCARD_S_SUCCESS) return false;
    }

    DWORD dwReaders = SCARD_AUTOALLOCATE;
    LPSTR mszReaders = NULL;
    LONG res = SCardListReadersA(m_hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
    if (res != SCARD_S_SUCCESS || !mszReaders) {
        return false;
    }

    std::string target_reader = "";
    LPCSTR pReader = mszReaders;
    while (*pReader != '\0') {
        std::string rname = pReader;
        if (rname.find("hyprkey") != std::string::npos || target_reader.empty()) {
            target_reader = rname;
            if (rname.find("hyprkey") != std::string::npos) break;
        }
        pReader += strlen(pReader) + 1;
    }

    if (target_reader.empty()) {
        SCardFreeMemory(m_hContext, mszReaders);
        return false;
    }

    res = SCardConnectA(m_hContext, target_reader.c_str(), SCARD_SHARE_SHARED,
                        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &m_hCard, &m_dwActiveProtocol);
    SCardFreeMemory(m_hContext, mszReaders);

    if (res == SCARD_S_SUCCESS) {
        m_connected = true;
        m_reader_name = target_reader;
        return true;
    }

    m_connected = false;
    return false;
}

void SCardClient::disconnect() {
    if (m_connected && m_hCard) {
        SCardDisconnect(m_hCard, SCARD_LEAVE_CARD);
        m_hCard = NULL;
    }
    m_connected = false;
}

void SCardClient::add_log(bool is_tx, const uint8_t* data, size_t len, uint16_t sw, const std::string& desc) {
    std::lock_guard<std::mutex> lock(m_log_mutex);
    ApduLogEntry e;
    e.time_str = current_timestamp();
    e.is_tx = is_tx;
    e.hex_data = bytes_to_hex(data, (len > 32) ? 32 : len);
    if (len > 32) e.hex_data += "...";
    e.sw = sw;
    e.desc = desc;

    m_logs.push_back(e);
    if (m_logs.size() > 200) {
        m_logs.erase(m_logs.begin());
    }
}

std::vector<ApduLogEntry> SCardClient::get_logs() {
    std::lock_guard<std::mutex> lock(m_log_mutex);
    return m_logs;
}

void SCardClient::clear_logs() {
    std::lock_guard<std::mutex> lock(m_log_mutex);
    m_logs.clear();
}

bool SCardClient::transmit(const std::vector<uint8_t>& apdu, std::vector<uint8_t>& rsp, uint16_t& sw, const std::string& desc) {
    if (!connect()) return false;

    add_log(true, apdu.data(), apdu.size(), 0, desc);

    const SCARD_IO_REQUEST* pio = (m_dwActiveProtocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;
    uint8_t rx_buf[2048];
    DWORD rx_len = sizeof(rx_buf);

    LONG res = SCardTransmit(m_hCard, pio, apdu.data(), (DWORD)apdu.size(), NULL, rx_buf, &rx_len);
    if (res != SCARD_S_SUCCESS) {
        disconnect();
        return false;
    }

    if (rx_len < 2) return false;

    sw = (uint16_t)((rx_buf[rx_len - 2] << 8) | rx_buf[rx_len - 1]);
    rsp.assign(rx_buf, rx_buf + rx_len - 2);

    add_log(false, rsp.data(), rsp.size(), sw, desc);
    return true;
}

/* ==================== OATH Applet ==================== */

bool SCardClient::oath_select() {
    // 00 A4 04 00 07 A0 00 00 05 27 21 01
    std::vector<uint8_t> apdu = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01 };
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OATH: SELECT") && (sw == 0x9000);
}

bool SCardClient::oath_list_and_calc(std::vector<OathAccount>& accounts) {
    if (!oath_select()) return false;

    // 1. LIST: 00 A1 00 00
    std::vector<uint8_t> apdu = { 0x00, 0xA1, 0x00, 0x00 };
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    if (!transmit(apdu, rsp, sw, "OATH: LIST") || sw != 0x9000) return false;

    accounts.clear();
    size_t pos = 0;
    while (pos + 1 < rsp.size()) {
        uint8_t tag = rsp[pos++];
        uint8_t len = rsp[pos++];
        if (pos + len > rsp.size()) break;

        if (tag == 0x71) { // Name
            OathAccount acc;
            acc.name = std::string((char*)&rsp[pos], len);
            acc.digits = 6;
            acc.type_alg = 0x21;
            pos += len;

            if (pos + 2 <= rsp.size() && rsp[pos] == 0x72 && rsp[pos + 1] == 0x01) {
                acc.type_alg = rsp[pos + 2];
                pos += 3;
            }
            accounts.push_back(acc);
        } else {
            pos += len;
        }
    }

    // 2. Compute current 30s challenge
    time_t now = time(NULL);
    uint64_t epoch_step = (uint64_t)now / 30;
    int remaining = 30 - (now % 30);
    uint8_t chal[8];
    for (int i = 7; i >= 0; i--) {
        chal[i] = (uint8_t)(epoch_step & 0xFF);
        epoch_step >>= 8;
    }

    // 3. Calculate OTP for each account
    for (auto& acc : accounts) {
        acc.valid_until_sec = remaining;
        std::vector<uint8_t> calc_apdu = { 0x00, 0xA2, 0x00, 0x00 };
        uint8_t payload_len = (uint8_t)(2 + acc.name.size() + 2 + 8);
        calc_apdu.push_back(payload_len);
        calc_apdu.push_back(0x71);
        calc_apdu.push_back((uint8_t)acc.name.size());
        calc_apdu.insert(calc_apdu.end(), acc.name.begin(), acc.name.end());
        calc_apdu.push_back(0x74);
        calc_apdu.push_back(8);
        calc_apdu.insert(calc_apdu.end(), chal, chal + 8);
        calc_apdu.push_back(0x00);

        std::vector<uint8_t> c_rsp;
        if (transmit(calc_apdu, c_rsp, sw, "OATH: CALC " + acc.name) && sw == 0x9000 && c_rsp.size() >= 7) {
            // Tag 0x76, len 5, digits (1B), code31 (4B BE)
            acc.digits = c_rsp[2];
            uint32_t c31 = ((uint32_t)c_rsp[3] << 24) | ((uint32_t)c_rsp[4] << 16) |
                           ((uint32_t)c_rsp[5] << 8)  | (uint32_t)c_rsp[6];
            uint32_t mod = (acc.digits == 8) ? 100000000 : 1000000;
            uint32_t pin = c31 % mod;

            char code_str[16];
            if (acc.digits == 8) {
                snprintf(code_str, sizeof(code_str), "%04u %04u", pin / 10000, pin % 10000);
            } else {
                snprintf(code_str, sizeof(code_str), "%03u %03u", pin / 1000, pin % 1000);
            }
            acc.current_code = code_str;
        } else {
            acc.current_code = "------";
        }
    }

    return true;
}

bool SCardClient::oath_put(const std::string& name, const std::vector<uint8_t>& secret, uint8_t type_alg, uint8_t digits) {
    if (!oath_select()) return false;

    // 00 01 00 00 Lc 71 nameLen [name] 73 secretBlobLen [type_alg] [digits] [secret]
    std::vector<uint8_t> apdu = { 0x00, 0x01, 0x00, 0x00 };
    uint8_t sec_blob_len = (uint8_t)(2 + secret.size());
    uint8_t lc = (uint8_t)(2 + name.size() + 2 + sec_blob_len);

    apdu.push_back(lc);
    apdu.push_back(0x71);
    apdu.push_back((uint8_t)name.size());
    apdu.insert(apdu.end(), name.begin(), name.end());
    apdu.push_back(0x73);
    apdu.push_back(sec_blob_len);
    apdu.push_back(type_alg);
    apdu.push_back(digits);
    apdu.insert(apdu.end(), secret.begin(), secret.end());

    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OATH: PUT " + name) && (sw == 0x9000);
}

bool SCardClient::oath_delete(const std::string& name) {
    if (!oath_select()) return false;

    std::vector<uint8_t> apdu = { 0x00, 0x02, 0x00, 0x00 };
    uint8_t lc = (uint8_t)(2 + name.size());
    apdu.push_back(lc);
    apdu.push_back(0x71);
    apdu.push_back((uint8_t)name.size());
    apdu.insert(apdu.end(), name.begin(), name.end());

    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OATH: DELETE " + name) && (sw == 0x9000);
}

bool SCardClient::oath_reset() {
    if (!oath_select()) return false;
    std::vector<uint8_t> apdu = { 0x00, 0x04, 0x00, 0x00 };
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OATH: RESET") && (sw == 0x9000);
}

/* ==================== OpenPGP Applet ==================== */

bool SCardClient::openpgp_select() {
    // 00 A4 04 00 06 D2 76 00 01 24 01
    std::vector<uint8_t> apdu = { 0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OpenPGP: SELECT") && (sw == 0x9000);
}

bool SCardClient::openpgp_get_status(OpenPgpStatus& status) {
    if (!openpgp_select()) return false;

    // GET DO 0x006E (Application Related Data)
    std::vector<uint8_t> apdu = { 0x00, 0xCA, 0x00, 0x6E, 0x00 };
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    if (!transmit(apdu, rsp, sw, "OpenPGP: GET DO 6E") || sw != 0x9000) return false;

    status = OpenPgpStatus();
    status.serial = "00000001";
    status.pw1_tries = 3;
    status.pw3_tries = 3;

    // Parse sub-TLVs in 0x006E
    size_t i = 0;
    while (i + 1 < rsp.size()) {
        uint16_t tag = rsp[i++];
        if ((tag & 0x1F) == 0x1F) {
            tag = (tag << 8) | rsp[i++];
        }
        if (i >= rsp.size()) break;

        size_t len = rsp[i++];
        if (len == 0x81) {
            len = rsp[i++];
        } else if (len == 0x82) {
            len = (rsp[i] << 8) | rsp[i + 1];
            i += 2;
        }
        if (i + len > rsp.size()) break;

        const uint8_t* val = &rsp[i];
        if (tag == 0x005B) { // Cardholder Name
            status.cardholder_name = std::string((char*)val, len);
        } else if (tag == 0x5F2D) { // Language
            status.lang = std::string((char*)val, len);
        } else if (tag == 0x5F35) { // Sex
            if (len >= 1) status.sex = val[0];
        } else if (tag == 0x00C4 && len >= 7) { // PW Status
            status.pw1_tries = val[4];
            status.pw3_tries = val[6];
        } else if (tag == 0x00C5 && len == 60) { // Fingerprints (20B Sig, 20B Dec, 20B Aut)
            status.fp_sig = bytes_to_hex(val, 20);
            status.fp_dec = bytes_to_hex(val + 20, 20);
            status.fp_aut = bytes_to_hex(val + 40, 20);
        } else if (tag == 0x0093 && len == 3) { // Sig Counter
            status.sig_counter = ((uint32_t)val[0] << 16) | ((uint32_t)val[1] << 8) | (uint32_t)val[2];
        }
        i += len;
    }

    // Read DO 0x5F50 (URL)
    std::vector<uint8_t> u_apdu = { 0x00, 0xCA, 0x5F, 0x50, 0x00 };
    std::vector<uint8_t> u_rsp;
    if (transmit(u_apdu, u_rsp, sw, "OpenPGP: GET URL") && sw == 0x9000) {
        status.cardholder_url = std::string((char*)u_rsp.data(), u_rsp.size());
    }

    return true;
}

bool SCardClient::openpgp_verify_pw1(const std::string& pin) {
    if (!openpgp_select()) return false;
    std::vector<uint8_t> apdu = { 0x00, 0x20, 0x00, 0x82, (uint8_t)pin.size() };
    apdu.insert(apdu.end(), pin.begin(), pin.end());
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OpenPGP: VERIFY PW1") && (sw == 0x9000);
}

bool SCardClient::openpgp_verify_pw3(const std::string& pin) {
    if (!openpgp_select()) return false;
    std::vector<uint8_t> apdu = { 0x00, 0x20, 0x00, 0x83, (uint8_t)pin.size() };
    apdu.insert(apdu.end(), pin.begin(), pin.end());
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OpenPGP: VERIFY PW3") && (sw == 0x9000);
}

bool SCardClient::openpgp_change_pw1(const std::string& new_pin) {
    if (!openpgp_select()) return false;
    std::vector<uint8_t> apdu = { 0x00, 0x24, 0x00, 0x81, (uint8_t)new_pin.size() };
    apdu.insert(apdu.end(), new_pin.begin(), new_pin.end());
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OpenPGP: CHANGE PW1") && (sw == 0x9000);
}

bool SCardClient::openpgp_change_pw3(const std::string& new_pin) {
    if (!openpgp_select()) return false;
    std::vector<uint8_t> apdu = { 0x00, 0x24, 0x00, 0x83, (uint8_t)new_pin.size() };
    apdu.insert(apdu.end(), new_pin.begin(), new_pin.end());
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OpenPGP: CHANGE PW3") && (sw == 0x9000);
}

bool SCardClient::openpgp_set_url(const std::string& url) {
    if (!openpgp_select()) return false;
    std::vector<uint8_t> apdu = { 0x00, 0xDA, 0x5F, 0x50, (uint8_t)url.size() };
    apdu.insert(apdu.end(), url.begin(), url.end());
    std::vector<uint8_t> rsp;
    uint16_t sw = 0;
    return transmit(apdu, rsp, sw, "OpenPGP: PUT URL") && (sw == 0x9000);
}

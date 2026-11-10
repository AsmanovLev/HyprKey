#pragma once

#include <windows.h>
#include <winscard.h>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

struct OathAccount {
    std::string name;
    uint8_t     type_alg;  // 0x21 = TOTP SHA1, 0x22 = TOTP SHA256
    uint8_t     digits;    // 6 or 8
    std::string current_code;
    int         valid_until_sec; // seconds remaining in 30s window
};

struct OpenPgpStatus {
    std::string cardholder_name;
    std::string cardholder_url;
    std::string lang;
    std::string serial;
    uint8_t     sex;
    uint32_t    sig_counter;
    uint8_t     pw1_tries;
    uint8_t     pw3_tries;
    std::string fp_sig;
    std::string fp_dec;
    std::string fp_aut;
};

struct ApduLogEntry {
    std::string time_str;
    bool        is_tx; // true = PC -> Key, false = Key -> PC
    std::string hex_data;
    uint16_t    sw;
    std::string desc;
};

class SCardClient {
public:
    SCardClient();
    ~SCardClient();

    bool connect();
    void disconnect();
    bool is_connected() const { return m_connected; }
    const std::string& get_reader_name() const { return m_reader_name; }

    bool transmit(const std::vector<uint8_t>& apdu, std::vector<uint8_t>& rsp, uint16_t& sw, const std::string& desc = "");

    // OATH Applet
    bool oath_select();
    bool oath_list_and_calc(std::vector<OathAccount>& accounts);
    bool oath_put(const std::string& name, const std::vector<uint8_t>& secret, uint8_t type_alg, uint8_t digits);
    bool oath_delete(const std::string& name);
    bool oath_reset();

    // OpenPGP Applet
    bool openpgp_select();
    bool openpgp_get_status(OpenPgpStatus& status);
    bool openpgp_verify_pw1(const std::string& pin);
    bool openpgp_verify_pw3(const std::string& pin);
    bool openpgp_change_pw1(const std::string& new_pin);
    bool openpgp_change_pw3(const std::string& new_pin);
    bool openpgp_set_url(const std::string& url);

    // Logs
    std::vector<ApduLogEntry> get_logs();
    void clear_logs();

private:
    SCARDCONTEXT m_hContext;
    SCARDHANDLE  m_hCard;
    DWORD        m_dwActiveProtocol;
    bool         m_connected;
    std::string  m_reader_name;

    std::mutex                m_log_mutex;
    std::vector<ApduLogEntry> m_logs;

    void add_log(bool is_tx, const uint8_t* data, size_t len, uint16_t sw, const std::string& desc);
};

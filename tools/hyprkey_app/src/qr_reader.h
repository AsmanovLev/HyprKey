#pragma once

#include <string>

struct OtpAuthData {
    std::string label;
    std::string secret;
    std::string issuer;
    std::string algorithm = "SHA1";
    int digits = 6;
    int period = 30;
};

// Reads image from Windows Clipboard, locates and decodes QR code.
// Returns true on success and populates qr_raw_text.
bool QrScanFromClipboard(std::string& qr_raw_text, std::string& error_msg);

// Parses an otpauth://totp/ URI into OtpAuthData.
bool ParseOtpAuthUri(const std::string& uri, OtpAuthData& out);

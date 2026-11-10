#include "qr_reader.h"
#include <windows.h>
#include <vector>
#include <algorithm>
#include <sstream>

extern "C" {
#include "../quirc/quirc.h"
}

static std::string url_decode(const std::string& in) {
    std::string out;
    out.reserve(in.length());
    for (size_t i = 0; i < in.length(); i++) {
        if (in[i] == '%' && i + 2 < in.length()) {
            char hex[3] = { in[i + 1], in[i + 2], 0 };
            char* end = nullptr;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2) {
                out += (char)val;
                i += 2;
                continue;
            }
        } else if (in[i] == '+') {
            out += ' ';
            continue;
        }
        out += in[i];
    }
    return out;
}

bool QrScanFromClipboard(std::string& qr_raw_text, std::string& error_msg) {
    if (!OpenClipboard(NULL)) {
        error_msg = "Failed to open Windows Clipboard";
        return false;
    }

    HANDLE hData = GetClipboardData(CF_DIB);
    if (!hData) {
        CloseClipboard();
        error_msg = "Clipboard does not contain an image. Use Win+Shift+S to capture a QR code!";
        return false;
    }

    void* pMem = GlobalLock(hData);
    if (!pMem) {
        CloseClipboard();
        error_msg = "Failed to lock clipboard memory";
        return false;
    }

    BITMAPINFOHEADER* bih = (BITMAPINFOHEADER*)pMem;
    int width = bih->biWidth;
    int height = abs(bih->biHeight);
    bool top_down = (bih->biHeight < 0);
    int bit_count = bih->biBitCount;

    if (bit_count != 24 && bit_count != 32) {
        GlobalUnlock(hData);
        CloseClipboard();
        error_msg = "Unsupported image bit depth (only 24bpp or 32bpp supported)";
        return false;
    }

    // Offset to raw pixel data
    const uint8_t* pPixels = (const uint8_t*)pMem + bih->biSize;
    if (bih->biCompression == BI_BITFIELDS) {
        pPixels += 12; // 3 DWORD color masks
    }

    int bytes_per_pixel = bit_count / 8;
    int row_stride = ((width * bit_count + 31) / 32) * 4;

    std::vector<uint8_t> gray_pixels(width * height);
    for (int y = 0; y < height; y++) {
        int src_y = top_down ? y : (height - 1 - y);
        const uint8_t* row = pPixels + src_y * row_stride;
        for (int x = 0; x < width; x++) {
            uint8_t b = row[x * bytes_per_pixel + 0];
            uint8_t g = row[x * bytes_per_pixel + 1];
            uint8_t r = row[x * bytes_per_pixel + 2];
            // Standard perceptual luminance: 0.299*R + 0.587*G + 0.114*B
            uint8_t gray = (uint8_t)((r * 77 + g * 150 + b * 29) >> 8);
            gray_pixels[y * width + x] = gray;
        }
    }

    GlobalUnlock(hData);
    CloseClipboard();

    // Run quirc QR detection
    struct quirc* q = quirc_new();
    if (!q) {
        error_msg = "Failed to initialize QR detector";
        return false;
    }

    if (quirc_resize(q, width, height) < 0) {
        quirc_destroy(q);
        error_msg = "Failed to allocate memory for QR scanner";
        return false;
    }

    int qw, qh;
    uint8_t* qimage = quirc_begin(q, &qw, &qh);
    memcpy(qimage, gray_pixels.data(), width * height);
    quirc_end(q);

    int count = quirc_count(q);
    if (count == 0) {
        quirc_destroy(q);
        error_msg = "No QR code detected in the screenshot. Try cropping closer to the QR code.";
        return false;
    }

    bool success = false;
    for (int i = 0; i < count; i++) {
        struct quirc_code code;
        struct quirc_data data;
        quirc_extract(q, i, &code);
        if (quirc_decode(&code, &data) == QUIRC_SUCCESS) {
            qr_raw_text = std::string((const char*)data.payload, data.payload_len);
            success = true;
            break;
        }
    }

    quirc_destroy(q);

    if (!success) {
        error_msg = "QR code detected but damaged or corrupted";
        return false;
    }

    return true;
}

bool ParseOtpAuthUri(const std::string& uri, OtpAuthData& out) {
    // Expected format: otpauth://totp/Label?secret=...&issuer=...
    if (uri.rfind("otpauth://", 0) != 0) {
        return false;
    }

    size_t qpos = uri.find('?');
    if (qpos == std::string::npos) return false;

    // Type and Label
    std::string path = uri.substr(10, qpos - 10); // e.g. "totp/Example:alice@gmail.com"
    size_t slash = path.find('/');
    if (slash != std::string::npos) {
        out.label = url_decode(path.substr(slash + 1));
    } else {
        out.label = url_decode(path);
    }

    // Default parameters
    out.algorithm = "SHA1";
    out.digits = 6;
    out.period = 30;
    out.secret = "";
    out.issuer = "";

    // Query string parameters
    std::string query = uri.substr(qpos + 1);
    std::istringstream iss(query);
    std::string pair;
    while (std::getline(iss, pair, '&')) {
        size_t eq = pair.find('=');
        if (eq == std::string::npos) continue;
        std::string key = pair.substr(0, eq);
        std::string val = url_decode(pair.substr(eq + 1));

        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (key == "secret") {
            // Strip any spaces or dashes from base32 secret
            std::string clean_sec;
            for (char c : val) {
                if (c != ' ' && c != '-') clean_sec += (char)::toupper(c);
            }
            out.secret = clean_sec;
        } else if (key == "issuer") {
            out.issuer = val;
        } else if (key == "algorithm") {
            std::string alg = val;
            std::transform(alg.begin(), alg.end(), alg.begin(), ::toupper);
            out.algorithm = alg;
        } else if (key == "digits") {
            out.digits = atoi(val.c_str());
            if (out.digits != 8) out.digits = 6;
        } else if (key == "period") {
            out.period = atoi(val.c_str());
            if (out.period <= 0) out.period = 30;
        }
    }

    if (out.secret.empty()) return false;

    // Prepend issuer to label if not already present
    if (!out.issuer.empty()) {
        if (out.label.find(out.issuer) == std::string::npos) {
            out.label = out.issuer + ": " + out.label;
        }
    }

    return true;
}

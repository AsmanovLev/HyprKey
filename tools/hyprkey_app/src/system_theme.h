#pragma once

#include "imgui.h"
#include <windows.h>
#include <dwmapi.h>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

struct Material3Palette {
    ImVec4 Primary;
    ImVec4 OnPrimary;
    ImVec4 PrimaryContainer;
    ImVec4 OnPrimaryContainer;
    ImVec4 Secondary;
    ImVec4 SecondaryContainer;
    ImVec4 OnSecondaryContainer;
    ImVec4 Surface;
    ImVec4 SurfaceContainer;
    ImVec4 SurfaceContainerHigh;
    ImVec4 Outline;
    ImVec4 OutlineVariant;
    ImVec4 OnSurface;
    ImVec4 OnSurfaceVariant;
};

// Pure math RGB <-> HSL conversion (0.0f - 1.0f)
inline void M3_RgbToHsl(float r, float g, float b, float& h, float& s, float& l) {
    float max_c = (std::max)({r, g, b});
    float min_c = (std::min)({r, g, b});
    float delta = max_c - min_c;

    l = (max_c + min_c) * 0.5f;

    if (delta < 0.00001f) {
        h = 0.0f;
        s = 0.0f;
        return;
    }

    if (l < 0.5f) {
        s = delta / (max_c + min_c);
    } else {
        s = delta / (2.0f - max_c - min_c);
    }

    if (max_c == r) {
        h = (g - b) / delta + (g < b ? 6.0f : 0.0f);
    } else if (max_c == g) {
        h = (b - r) / delta + 2.0f;
    } else {
        h = (r - g) / delta + 4.0f;
    }
    h /= 6.0f;
}

inline float M3_HueToRgb(float p, float q, float t) {
    if (t < 0.0f) t += 1.0f;
    if (t > 1.0f) t -= 1.0f;
    if (t < 1.0f / 6.0f) return p + (q - p) * 6.0f * t;
    if (t < 1.0f / 2.0f) return q;
    if (t < 2.0f / 3.0f) return p + (q - p) * (2.0f / 3.0f - t) * 6.0f;
    return p;
}

inline ImVec4 M3_HslToRgb(float h, float s, float l, float a = 1.0f) {
    if (s < 0.00001f) {
        return ImVec4(l, l, l, a);
    }
    float q = (l < 0.5f) ? (l * (1.0f + s)) : (l + s - l * s);
    float p = 2.0f * l - q;
    float r = M3_HueToRgb(p, q, h + 1.0f / 3.0f);
    float g = M3_HueToRgb(p, q, h);
    float b = M3_HueToRgb(p, q, h - 1.0f / 3.0f);
    return ImVec4(r, g, b, a);
}

// Generate authentic Material Design 3 Dynamic Palette from seed color
inline Material3Palette M3_GeneratePalette(ImVec4 seed, bool dark) {
    float h, s, l;
    M3_RgbToHsl(seed.x, seed.y, seed.z, h, s, l);

    Material3Palette pal;
    if (dark) {
        // Dark Theme (Material You Dark)
        pal.Primary              = M3_HslToRgb(h, (std::min)(s * 0.95f, 0.85f), 0.78f);
        pal.OnPrimary            = M3_HslToRgb(h, (std::min)(s, 0.40f), 0.16f);
        pal.PrimaryContainer     = M3_HslToRgb(h, (std::min)(s * 0.65f, 0.50f), 0.30f);
        pal.OnPrimaryContainer   = M3_HslToRgb(h, (std::min)(s * 0.90f, 0.75f), 0.92f);

        pal.Secondary            = M3_HslToRgb(h, (std::min)(s * 0.40f, 0.35f), 0.76f);
        pal.SecondaryContainer   = M3_HslToRgb(h, (std::min)(s * 0.40f, 0.35f), 0.28f);
        pal.OnSecondaryContainer = M3_HslToRgb(h, (std::min)(s * 0.40f, 0.35f), 0.88f);

        pal.Surface              = M3_HslToRgb(h, 0.08f, 0.075f);
        pal.SurfaceContainer     = M3_HslToRgb(h, 0.08f, 0.13f);
        pal.SurfaceContainerHigh = M3_HslToRgb(h, 0.08f, 0.17f);
        pal.Outline              = M3_HslToRgb(h, 0.06f, 0.45f);
        pal.OutlineVariant       = M3_HslToRgb(h, 0.06f, 0.28f);

        pal.OnSurface            = ImVec4(0.91f, 0.89f, 0.94f, 1.0f);
        pal.OnSurfaceVariant     = ImVec4(0.60f, 0.58f, 0.64f, 1.0f);
    } else {
        // Light Theme (Material You Light)
        pal.Primary              = M3_HslToRgb(h, (std::max)(s, 0.55f), 0.38f);
        pal.OnPrimary            = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        pal.PrimaryContainer     = M3_HslToRgb(h, (std::min)(s * 0.70f, 0.60f), 0.90f);
        pal.OnPrimaryContainer   = M3_HslToRgb(h, (std::max)(s, 0.60f), 0.15f);

        pal.Secondary            = M3_HslToRgb(h, (std::min)(s * 0.40f, 0.35f), 0.42f);
        pal.SecondaryContainer   = M3_HslToRgb(h, (std::min)(s * 0.35f, 0.30f), 0.90f);
        pal.OnSecondaryContainer = M3_HslToRgb(h, (std::min)(s * 0.45f, 0.40f), 0.18f);

        pal.Surface              = M3_HslToRgb(h, 0.06f, 0.98f);
        pal.SurfaceContainer     = M3_HslToRgb(h, 0.06f, 0.93f);
        pal.SurfaceContainerHigh = M3_HslToRgb(h, 0.06f, 0.89f);
        pal.Outline              = M3_HslToRgb(h, 0.05f, 0.55f);
        pal.OutlineVariant       = M3_HslToRgb(h, 0.05f, 0.78f);

        pal.OnSurface            = ImVec4(0.12f, 0.11f, 0.14f, 1.0f);
        pal.OnSurfaceVariant     = ImVec4(0.35f, 0.33f, 0.38f, 1.0f);
    }
    return pal;
}

// Windows System Personalization Queries
inline bool M3_QueryWindowsDarkTheme() {
    DWORD appsLight = 0;
    DWORD size = sizeof(appsLight);
    if (RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            L"AppsUseLightTheme",
            RRF_RT_REG_DWORD, nullptr, &appsLight, &size) == ERROR_SUCCESS) {
        return (appsLight == 0); // 0 = dark mode, 1 = light mode
    }
    return true; // Default dark
}

inline ImVec4 M3_QueryWindowsAccentColor() {
    // 1. Try DWM colorization
    DWORD colorization = 0;
    BOOL opaque = FALSE;
    if (SUCCEEDED(DwmGetColorizationColor(&colorization, &opaque))) {
        // Format: 0xAARRGGBB
        float r = ((colorization >> 16) & 0xFF) / 255.0f;
        float g = ((colorization >> 8) & 0xFF) / 255.0f;
        float b = (colorization & 0xFF) / 255.0f;
        return ImVec4(r, g, b, 1.0f);
    }

    // 2. Fallback to DWM registry AccentColor
    DWORD regAccent = 0;
    DWORD regSize = sizeof(regAccent);
    if (RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\DWM",
            L"AccentColor",
            RRF_RT_REG_DWORD, nullptr, &regAccent, &regSize) == ERROR_SUCCESS) {
        // DWM AccentColor is ABGR: 0xAABBGGRR
        float r = (regAccent & 0xFF) / 255.0f;
        float g = ((regAccent >> 8) & 0xFF) / 255.0f;
        float b = ((regAccent >> 16) & 0xFF) / 255.0f;
        return ImVec4(r, g, b, 1.0f);
    }

    // Default Material 3 seed: Lavender #6750A4
    return ImVec4(0.40f, 0.31f, 0.64f, 1.0f);
}

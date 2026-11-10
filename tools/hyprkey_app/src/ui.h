#pragma once

#include "scard_client.h"
#include "imgui.h"
#include <windows.h>

enum AppTheme {
    THEME_MD3_SYSTEM = 0, // Material You (Windows System Accent Dynamic)
    THEME_MD3_LAVENDER,   // Material 3 Lavender (Default M3 Seed #6750A4)
    THEME_MD3_BLUE,       // Material 3 Google Pixel Blue (#1A73E8)
    THEME_NOTHING,        // Nothing OS Glyph Monochrome
    THEME_CIRCUIT,        // Cyber Circuit PCB Matrix
    THEME_LINEAR,         // Linear Stealth
    THEME_COUNT
};

extern AppTheme g_CurrentTheme;
extern bool     g_IsDarkTheme;
extern HWND     g_MainHWnd;

// Fonts
extern ImFont* g_FontUI;
extern ImFont* g_FontMono;
extern ImFont* g_FontTitle;
extern ImFont* g_FontTotpCode;

void ApplyTheme(AppTheme theme, int force_mode = -1); // force_mode: -1=auto/current, 0=light, 1=dark
void RenderHyprKeyUI(SCardClient& client);
const char* GetThemeName(AppTheme theme);
ImVec4 GetThemeClearColor(AppTheme theme);

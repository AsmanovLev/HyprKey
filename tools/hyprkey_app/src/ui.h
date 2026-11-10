#pragma once

#include "scard_client.h"
#include "imgui.h"

enum AppTheme {
    THEME_MD3 = 0,        // Material Design 3 (Material You Lavender)
    THEME_MD3_BLUE,       // Material Design 3 (Pixel Google Blue)
    THEME_NOTHING,        // Nothing OS Glyph
    THEME_CIRCUIT,        // Cyber Circuit PCB
    THEME_LINEAR,         // Linear Stealth
    THEME_COUNT
};

extern AppTheme g_CurrentTheme;

// Fonts
extern ImFont* g_FontUI;
extern ImFont* g_FontMono;
extern ImFont* g_FontTitle;
extern ImFont* g_FontTotpCode;

void ApplyTheme(AppTheme theme);
void RenderHyprKeyUI(SCardClient& client);
const char* GetThemeName(AppTheme theme);
ImVec4 GetThemeClearColor(AppTheme theme);

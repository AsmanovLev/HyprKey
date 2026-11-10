#pragma once

#include "scard_client.h"
#include "imgui.h"

enum AppTheme {
    THEME_NOTHING = 0,    // Nothing OS Glyph Bento (Pitch Black + Nothing Red)
    THEME_CIRCUIT,        // Cyber Circuit / Silicon PCB (Matte Solder Mask + Emerald/Copper Traces)
    THEME_LINEAR,         // Linear Stealth (Minimalist Obsidian + Mint)
    THEME_CATPPUCCIN,     // Catppuccin Mocha (Soft Pastel Dark)
    THEME_INDUSTRIAL,     // Industrial Amber (Teenage Engineering Carbon)
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

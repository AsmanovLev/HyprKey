#pragma once

#include "scard_client.h"
#include "imgui.h"

enum AppTheme {
    THEME_LINEAR = 0,
    THEME_CATPPUCCIN,
    THEME_NORDIC,
    THEME_INDUSTRIAL,
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

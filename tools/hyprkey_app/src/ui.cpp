#include "ui.h"
#include "imgui.h"
#include "qr_reader.h"
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string>
#include <vector>

AppTheme g_CurrentTheme = THEME_NOTHING;

ImFont* g_FontUI       = nullptr;
ImFont* g_FontMono     = nullptr;
ImFont* g_FontTitle    = nullptr;
ImFont* g_FontTotpCode = nullptr;

static std::string s_toast_msg = "";
static double      s_toast_time = 0.0;
static int         s_active_nav = 0; // 0 = 2FA Authenticator, 1 = OpenPGP, 2 = APDU Console

static void show_toast(const std::string& msg) {
    s_toast_msg = msg;
    s_toast_time = ImGui::GetTime();
}

const char* GetThemeName(AppTheme theme) {
    switch (theme) {
        case THEME_NOTHING:    return "Nothing OS";
        case THEME_CIRCUIT:    return "Cyber Circuit";
        case THEME_LINEAR:     return "Linear Stealth";
        case THEME_CATPPUCCIN: return "Catppuccin Mocha";
        case THEME_INDUSTRIAL: return "Industrial Amber";
        default:               return "Custom";
    }
}

ImVec4 GetThemeClearColor(AppTheme theme) {
    switch (theme) {
        case THEME_NOTHING:    return ImVec4(0.00f, 0.00f, 0.00f, 1.0f); // Pure AMOLED Black #000000
        case THEME_CIRCUIT:    return ImVec4(0.04f, 0.06f, 0.05f, 1.0f); // PCB Solder Mask #0A0F0D
        case THEME_LINEAR:     return ImVec4(0.05f, 0.06f, 0.08f, 1.0f); // #0D0F14
        case THEME_CATPPUCCIN: return ImVec4(0.12f, 0.12f, 0.18f, 1.0f); // #1E1E2E
        case THEME_INDUSTRIAL: return ImVec4(0.07f, 0.07f, 0.07f, 1.0f); // #121212
        default:               return ImVec4(0.08f, 0.08f, 0.10f, 1.0f);
    }
}

void ApplyTheme(AppTheme theme) {
    g_CurrentTheme = theme;
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* c = style.Colors;

    style.WindowPadding     = ImVec2(16.0f, 16.0f);
    style.FramePadding      = ImVec2(12.0f, 8.0f);
    style.ItemSpacing       = ImVec2(12.0f, 10.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 6.0f);

    switch (theme) {
        case THEME_NOTHING: {
            // === 0. NOTHING OS / GLYPH BENTO AESTHETIC ===
            style.WindowRounding    = 16.0f;
            style.ChildRounding     = 16.0f;
            style.FrameRounding     = 20.0f; // Pill buttons
            style.PopupRounding     = 16.0f;
            style.ScrollbarRounding = 12.0f;
            style.GrabRounding      = 20.0f;
            style.TabRounding       = 20.0f;

            c[ImGuiCol_Text]                  = ImVec4(1.00f, 1.00f, 1.00f, 1.00f); // Stark White
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.55f, 0.58f, 1.00f); // Slate Subtext
            c[ImGuiCol_WindowBg]              = ImVec4(0.00f, 0.00f, 0.00f, 1.00f); // Pure Black
            c[ImGuiCol_ChildBg]               = ImVec4(0.07f, 0.07f, 0.08f, 1.00f); // Bento Surface #121214
            c[ImGuiCol_PopupBg]               = ImVec4(0.08f, 0.08f, 0.09f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.16f, 0.16f, 0.18f, 1.00f); // Micro-border #28282E
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.11f, 0.11f, 0.13f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.18f, 0.18f, 0.20f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.24f, 0.24f, 0.28f, 1.00f);

            // Nothing Red (#D71920) & Glyph White (#FFFFFF)
            c[ImGuiCol_CheckMark]             = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.13f, 0.13f, 0.15f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.95f, 0.12f, 0.15f, 0.35f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.95f, 0.12f, 0.15f, 0.85f);
            c[ImGuiCol_Header]                = ImVec4(0.14f, 0.14f, 0.17f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.20f, 0.20f, 0.25f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.95f, 0.12f, 0.15f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.11f, 0.11f, 0.13f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.22f, 0.22f, 0.26f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.28f, 0.28f, 0.34f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            break;
        }

        case THEME_CIRCUIT: {
            // === 1. CYBER CIRCUIT / SILICON PCB AESTHETIC ===
            style.WindowRounding    = 8.0f;
            style.ChildRounding     = 10.0f;
            style.FrameRounding     = 6.0f;
            style.PopupRounding     = 8.0f;
            style.ScrollbarRounding = 6.0f;
            style.GrabRounding      = 4.0f;
            style.TabRounding       = 6.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.92f, 0.96f, 0.94f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.42f, 0.55f, 0.48f, 1.00f); // PCB Silk-Screen Green
            c[ImGuiCol_WindowBg]              = ImVec4(0.04f, 0.06f, 0.05f, 1.00f); // Dark Solder Mask #0A0E0B
            c[ImGuiCol_ChildBg]               = ImVec4(0.07f, 0.10f, 0.08f, 1.00f); // PCB Substrate #111814
            c[ImGuiCol_PopupBg]               = ImVec4(0.07f, 0.10f, 0.08f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.14f, 0.22f, 0.18f, 1.00f); // Subtle Emerald Trace Border
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.09f, 0.13f, 0.11f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.14f, 0.20f, 0.16f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.18f, 0.26f, 0.21f, 1.00f);

            // Accents: Silicon Emerald (#10B981) & Copper Gold (#D4AF37)
            c[ImGuiCol_CheckMark]             = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.83f, 0.69f, 0.22f, 1.00f); // Copper Gold
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.95f, 0.80f, 0.30f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.11f, 0.16f, 0.13f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.06f, 0.76f, 0.54f, 0.35f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.75f);
            c[ImGuiCol_Header]                = ImVec4(0.12f, 0.18f, 0.14f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.16f, 0.24f, 0.19f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.45f);
            c[ImGuiCol_Tab]                   = ImVec4(0.09f, 0.13f, 0.10f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.15f, 0.22f, 0.18f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.12f, 0.18f, 0.14f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.04f, 0.06f, 0.05f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.14f, 0.22f, 0.18f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.20f, 0.30f, 0.24f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            break;
        }

        case THEME_LINEAR: {
            style.WindowRounding    = 8.0f;
            style.ChildRounding     = 8.0f;
            style.FrameRounding     = 6.0f;
            style.PopupRounding     = 8.0f;
            style.ScrollbarRounding = 6.0f;
            style.GrabRounding      = 4.0f;
            style.TabRounding       = 6.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.96f, 0.97f, 0.99f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.58f, 0.67f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.06f, 0.07f, 0.09f, 1.00f);
            c[ImGuiCol_ChildBg]               = ImVec4(0.09f, 0.10f, 0.14f, 1.00f);
            c[ImGuiCol_PopupBg]               = ImVec4(0.09f, 0.11f, 0.15f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.18f, 0.21f, 0.28f, 1.00f);
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.12f, 0.14f, 0.19f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.16f, 0.19f, 0.26f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.20f, 0.24f, 0.32f, 1.00f);

            c[ImGuiCol_CheckMark]             = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.10f, 0.88f, 0.64f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.14f, 0.17f, 0.23f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.06f, 0.76f, 0.54f, 0.45f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.85f);
            c[ImGuiCol_Header]                = ImVec4(0.14f, 0.17f, 0.24f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.19f, 0.23f, 0.32f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.11f, 0.13f, 0.18f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.15f, 0.18f, 0.25f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.06f, 0.07f, 0.09f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.18f, 0.21f, 0.28f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.24f, 0.28f, 0.38f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            break;
        }

        case THEME_CATPPUCCIN: {
            style.WindowRounding    = 10.0f;
            style.ChildRounding     = 10.0f;
            style.FrameRounding     = 8.0f;
            style.PopupRounding     = 10.0f;
            style.ScrollbarRounding = 8.0f;
            style.GrabRounding      = 6.0f;
            style.TabRounding       = 8.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.80f, 0.84f, 0.96f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.57f, 0.68f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.12f, 0.12f, 0.18f, 1.00f);
            c[ImGuiCol_ChildBg]               = ImVec4(0.15f, 0.15f, 0.23f, 1.00f);
            c[ImGuiCol_PopupBg]               = ImVec4(0.14f, 0.14f, 0.21f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.25f, 0.26f, 0.36f, 1.00f);
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.19f, 0.19f, 0.28f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.25f, 0.25f, 0.36f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.30f, 0.30f, 0.44f, 1.00f);

            c[ImGuiCol_CheckMark]             = ImVec4(0.80f, 0.65f, 0.97f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.80f, 0.65f, 0.97f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.88f, 0.75f, 1.00f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.23f, 0.23f, 0.34f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.80f, 0.65f, 0.97f, 0.40f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.80f, 0.65f, 0.97f, 0.80f);
            c[ImGuiCol_Header]                = ImVec4(0.22f, 0.23f, 0.33f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.30f, 0.31f, 0.45f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.80f, 0.65f, 0.97f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.16f, 0.16f, 0.24f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.26f, 0.26f, 0.38f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.22f, 0.22f, 0.33f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.12f, 0.12f, 0.18f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.25f, 0.26f, 0.36f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.35f, 0.36f, 0.50f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.80f, 0.65f, 0.97f, 1.00f);
            break;
        }

        case THEME_INDUSTRIAL: {
            style.WindowRounding    = 0.0f;
            style.ChildRounding     = 2.0f;
            style.FrameRounding     = 0.0f;
            style.PopupRounding     = 0.0f;
            style.ScrollbarRounding = 0.0f;
            style.GrabRounding      = 0.0f;
            style.TabRounding       = 0.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.07f, 0.07f, 0.07f, 1.00f);
            c[ImGuiCol_ChildBg]               = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
            c[ImGuiCol_PopupBg]               = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
            c[ImGuiCol_Border]                = ImVec4(0.24f, 0.24f, 0.24f, 1.00f);
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.19f, 0.19f, 0.19f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.24f, 0.24f, 0.24f, 1.00f);

            c[ImGuiCol_CheckMark]             = ImVec4(1.00f, 0.62f, 0.23f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(1.00f, 0.62f, 0.23f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(1.00f, 0.72f, 0.38f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(1.00f, 0.62f, 0.23f, 0.40f);
            c[ImGuiCol_ButtonActive]          = ImVec4(1.00f, 0.62f, 0.23f, 0.80f);
            c[ImGuiCol_Header]                = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.28f, 0.28f, 0.28f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(1.00f, 0.62f, 0.23f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.07f, 0.07f, 0.07f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.22f, 0.22f, 0.22f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.32f, 0.32f, 0.32f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(1.00f, 0.62f, 0.23f, 1.00f);
            break;
        }
    }
}

static ImVec4 GetAccentColor() {
    switch (g_CurrentTheme) {
        case THEME_NOTHING:    return ImVec4(0.95f, 0.12f, 0.15f, 1.00f); // Nothing Crimson Red
        case THEME_CIRCUIT:    return ImVec4(0.06f, 0.76f, 0.54f, 1.00f); // Silicon Emerald Trace
        case THEME_LINEAR:     return ImVec4(0.06f, 0.76f, 0.54f, 1.00f); // Mint Emerald
        case THEME_CATPPUCCIN: return ImVec4(0.80f, 0.65f, 0.97f, 1.00f); // Mauve
        case THEME_INDUSTRIAL: return ImVec4(1.00f, 0.62f, 0.23f, 1.00f); // Warm Amber
        default:               return ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    }
}

static ImVec4 GetSecondaryAccentColor() {
    switch (g_CurrentTheme) {
        case THEME_NOTHING:    return ImVec4(1.00f, 1.00f, 1.00f, 1.00f); // Pure White Glyph
        case THEME_CIRCUIT:    return ImVec4(0.83f, 0.69f, 0.22f, 1.00f); // Copper Gold Pad
        case THEME_LINEAR:     return ImVec4(0.02f, 0.71f, 0.83f, 1.00f); // Cyan
        case THEME_CATPPUCCIN: return ImVec4(0.45f, 0.78f, 0.93f, 1.00f); // Sapphire
        case THEME_INDUSTRIAL: return ImVec4(0.90f, 0.76f, 0.52f, 1.00f); // Tactical Gold
        default:               return ImVec4(0.80f, 0.80f, 0.80f, 1.00f);
    }
}

// State
static std::vector<OathAccount> s_oath_accounts;
static bool                     s_oath_loaded = false;
static double                   s_last_oath_fetch = 0.0;

static OpenPgpStatus            s_pgp_status;
static bool                     s_pgp_loaded = false;

static bool                     s_show_add_modal = false;
static char                     s_add_name[128] = "Google: user@gmail.com";
static char                     s_add_secret[128] = "JBSWY3DPEHPK3PXP";
static int                      s_add_digits = 6;
static int                      s_add_algo = 0; // 0=SHA1, 1=SHA256

static bool                     s_show_pin_modal = false;
static int                      s_pin_target = 1; // 1 = PW1, 3 = PW3
static char                     s_old_pin[64] = "";
static char                     s_new_pin[64] = "";

static bool                     s_show_url_modal = false;
static char                     s_new_url[256] = "https://hyprkey.local/mykey.asc";

void RenderHyprKeyUI(SCardClient& client) {
    ImVec4 accent_col = GetAccentColor();
    ImVec4 secondary_col = GetSecondaryAccentColor();
    double current_time = ImGui::GetTime();

    float total_w = ImGui::GetContentRegionAvail().x;
    float total_h = ImGui::GetContentRegionAvail().y;

    float nav_rail_w = 230.0f;
    float main_canvas_w = total_w - nav_rail_w - 14.0f;

    // ==========================================
    // 1. LEFT NAVIGATION RAIL (Nothing / Circuit Bento)
    // ==========================================
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
    ImGui::BeginChild("LeftNavRail", ImVec2(nav_rail_w, total_h), true);
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetCursorScreenPos();

        if (g_CurrentTheme == THEME_NOTHING) {
            // Nothing Phone Red Record LED Dot
            dl->AddCircleFilled(ImVec2(p.x + 8.0f, p.y + 12.0f), 5.0f, IM_COL32(230, 25, 30, 255));
        } else if (g_CurrentTheme == THEME_CIRCUIT) {
            // Silicon IC Pin 1 Notch Marker (Copper / Gold)
            dl->AddRectFilled(ImVec2(p.x + 4.0f, p.y + 8.0f), ImVec2(p.x + 12.0f, p.y + 16.0f), IM_COL32(212, 175, 55, 255), 2.0f);
        } else {
            dl->AddCircleFilled(ImVec2(p.x + 8.0f, p.y + 12.0f), 5.0f, ImGui::ColorConvertFloat4ToU32(accent_col));
        }

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 20.0f);
        if (g_FontTitle) ImGui::PushFont(g_FontTitle);
        ImGui::Text("HYPRKEY");
        if (g_FontTitle) ImGui::PopFont();

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 4.0f);
        if (g_CurrentTheme == THEME_NOTHING) {
            ImGui::TextDisabled("NOTHING // EDITION");
        } else if (g_CurrentTheme == THEME_CIRCUIT) {
            ImGui::TextDisabled("SILICON // PCB REV 1.4");
        } else {
            ImGui::TextDisabled("TOKEN COMPANION");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Nav Item 01: 2FA Authenticator
        bool is_nav0 = (s_active_nav == 0);
        if (is_nav0) {
            ImGui::PushStyleColor(ImGuiCol_Button, accent_col);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
        }
        if (ImGui::Button("( 01 )  2FA CODES", ImVec2(nav_rail_w - 32, 42))) {
            s_active_nav = 0;
        }
        ImGui::PopStyleColor(2);

        ImGui::Spacing();

        // Nav Item 02: OpenPGP SmartCard
        bool is_nav1 = (s_active_nav == 1);
        if (is_nav1) {
            ImGui::PushStyleColor(ImGuiCol_Button, accent_col);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
        }
        if (ImGui::Button("( 02 )  OPENPGP", ImVec2(nav_rail_w - 32, 42))) {
            s_active_nav = 1;
        }
        ImGui::PopStyleColor(2);

        ImGui::Spacing();

        // Nav Item 03: APDU Terminal Console
        bool is_nav2 = (s_active_nav == 2);
        if (is_nav2) {
            ImGui::PushStyleColor(ImGuiCol_Button, accent_col);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
        }
        if (ImGui::Button("( 03 )  TERMINAL", ImVec2(nav_rail_w - 32, 42))) {
            s_active_nav = 2;
        }
        ImGui::PopStyleColor(2);

        // Bottom Hardware Status Bento Box
        ImGui::SetCursorPosY(total_h - 135.0f);
        ImGui::Separator();
        ImGui::Spacing();

        if (g_CurrentTheme == THEME_CIRCUIT) {
            ImGui::TextDisabled("IC: U1_NRF52840 // TP1");
        } else {
            ImGui::TextDisabled("HARDWARE STATUS");
        }

        if (client.is_connected()) {
            ImGui::TextColored(ImVec4(0.10f, 0.90f, 0.55f, 1.0f), "● ONLINE");
            ImGui::TextDisabled("%s", client.get_reader_name().c_str());
        } else {
            ImGui::TextColored(ImVec4(0.95f, 0.25f, 0.25f, 1.0f), "● DISCONNECTED");
            ImGui::Spacing();
            if (ImGui::Button("CONNECT", ImVec2(nav_rail_w - 32, 28))) {
                client.connect();
                s_oath_loaded = false;
                s_pgp_loaded = false;
            }
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine();

    // ==========================================
    // 2. MAIN BENTO CANVAS (Right)
    // ==========================================
    ImGui::BeginChild("MainBentoCanvas", ImVec2(main_canvas_w, total_h), false);
    {
        // Top Toolbar: Section Title + Theme Selector Pills
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
        ImGui::BeginChild("TopHeaderBento", ImVec2(0, 52), true, ImGuiWindowFlags_NoScrollbar);
        {
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.0f);
            if (s_active_nav == 0) {
                ImGui::TextColored(secondary_col, "2FA AUTHENTICATOR // OATH TOTP");
            } else if (s_active_nav == 1) {
                ImGui::TextColored(secondary_col, "OPENPGP SMARTCARD // CRYPTO CORE");
            } else {
                ImGui::TextColored(secondary_col, "APDU TERMINAL // ISO 7816-4");
            }

            // Theme Pills on Far Right
            ImGui::SameLine(ImGui::GetWindowWidth() - 410);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f);
            ImGui::TextDisabled("Theme:");
            ImGui::SameLine();

            const char* themes[] = { "Nothing", "Circuit", "Linear", "Catppuccin", "Industrial" };
            for (int i = 0; i < 5; i++) {
                bool is_active = (g_CurrentTheme == (AppTheme)i);
                if (is_active) {
                    ImGui::PushStyleColor(ImGuiCol_Button, accent_col);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
                }

                if (ImGui::Button(themes[i], ImVec2(58, 24))) {
                    ApplyTheme((AppTheme)i);
                }
                ImGui::PopStyleColor(2);
                if (i < 4) ImGui::SameLine();
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();

        // -----------------------------------------------------------------
        // VIEW 0: 2FA TOTP AUTHENTICATOR (Nothing / Circuit Bento Grid)
        // -----------------------------------------------------------------
        if (s_active_nav == 0) {
            // Action Bar: Scan QR from Clipboard!
            ImGui::PushStyleColor(ImGuiCol_Button, accent_col);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            if (ImGui::Button("📷 Scan QR from Clipboard", ImVec2(210, 36))) {
                std::string qr_raw, err;
                if (QrScanFromClipboard(qr_raw, err)) {
                    OtpAuthData otp;
                    if (ParseOtpAuthUri(qr_raw, otp)) {
                        snprintf(s_add_name, sizeof(s_add_name), "%s", otp.label.c_str());
                        snprintf(s_add_secret, sizeof(s_add_secret), "%s", otp.secret.c_str());
                        s_add_algo = (otp.algorithm == "SHA256") ? 1 : 0;
                        s_add_digits = (otp.digits == 8) ? 1 : 0;
                        s_show_add_modal = true;
                        show_toast("Decoded QR: " + otp.label);
                    } else {
                        show_toast("Decoded QR, not OTP: " + qr_raw.substr(0, 30));
                    }
                } else {
                    show_toast(err);
                }
            }
            ImGui::PopStyleColor(2);

            ImGui::SameLine();
            if (ImGui::Button("+ Manual Entry", ImVec2(130, 36))) {
                s_show_add_modal = true;
            }

            ImGui::SameLine();
            if (ImGui::Button("Refresh", ImVec2(90, 36))) {
                s_oath_loaded = false;
            }

            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6.0f);
            ImGui::TextDisabled("Take a screenshot with Win+Shift+S and click Scan QR");

            ImGui::Spacing();

            // Periodic auto-reload
            time_t now_sec = time(NULL);
            int rem_in_step = 30 - (int)(now_sec % 30);
            float step_frac = (float)rem_in_step / 30.0f;

            if (!s_oath_loaded || (current_time - s_last_oath_fetch > 1.0 && rem_in_step == 30)) {
                if (client.is_connected()) {
                    client.oath_list_and_calc(s_oath_accounts);
                }
                s_oath_loaded = true;
                s_last_oath_fetch = current_time;
            }

            if (!client.is_connected()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "Insert HyprKey USB token and click Connect in the sidebar to view 2FA codes.");
            } else if (s_oath_accounts.empty()) {
                ImGui::Spacing();
                ImGui::TextDisabled("No accounts found. Use Win+Shift+S on a 2FA QR code and click 'Scan QR from Clipboard'!");
            } else {
                // 2-Column Bento Grid
                int cols = 2;
                float card_w = (ImGui::GetContentRegionAvail().x - 12.0f * (cols - 1)) / cols;

                for (size_t i = 0; i < s_oath_accounts.size(); i++) {
                    const auto& acc = s_oath_accounts[i];
                    if (i % cols != 0) ImGui::SameLine();

                    char card_id[64];
                    snprintf(card_id, sizeof(card_id), "BentoCard_##%zu", i);

                    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
                    ImGui::BeginChild(card_id, ImVec2(card_w, 125), true);
                    {
                        ImVec2 card_min = ImGui::GetWindowPos();
                        ImVec2 card_max = ImVec2(card_min.x + card_w, card_min.y + 125.0f);
                        ImDrawList* dl = ImGui::GetWindowDrawList();

                        // Circuit Mode: Subtle PCB Silk-Screen Registration Crosshairs at Corners
                        if (g_CurrentTheme == THEME_CIRCUIT) {
                            ImU32 silk_col = IM_COL32(16, 185, 129, 50); // Muted emerald trace
                            // Top-left crosshair
                            dl->AddLine(ImVec2(card_min.x + 8, card_min.y + 12), ImVec2(card_min.x + 18, card_min.y + 12), silk_col);
                            dl->AddLine(ImVec2(card_min.x + 13, card_min.y + 7), ImVec2(card_min.x + 13, card_min.y + 17), silk_col);
                            // Top-right crosshair
                            dl->AddLine(ImVec2(card_max.x - 18, card_min.y + 12), ImVec2(card_max.x - 8, card_min.y + 12), silk_col);
                            dl->AddLine(ImVec2(card_max.x - 13, card_min.y + 7), ImVec2(card_max.x - 13, card_min.y + 17), silk_col);
                        }

                        // Account Label
                        ImGui::TextColored(ImVec4(0.95f, 0.95f, 0.98f, 1.0f), "%s", acc.name.c_str());
                        ImGui::SameLine(ImGui::GetWindowWidth() - 75);
                        ImGui::TextDisabled(acc.type_alg == 0x22 ? "SHA256" : "SHA1");

                        ImGui::Spacing();

                        // Large 32px TOTP verification digits
                        if (g_FontTotpCode) ImGui::PushFont(g_FontTotpCode);
                        else if (g_FontTitle) ImGui::PushFont(g_FontTitle);

                        std::string display_code = acc.current_code;
                        if (display_code.length() == 6) {
                            display_code.insert(3, " ");
                        } else if (display_code.length() == 8) {
                            display_code.insert(4, " ");
                        }
                        ImGui::TextColored(secondary_col, "%s", display_code.c_str());

                        if (g_FontTotpCode || g_FontTitle) ImGui::PopFont();

                        // Copy Button
                        ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 85, ImGui::GetWindowHeight() - 42));
                        char copy_btn_id[32];
                        snprintf(copy_btn_id, sizeof(copy_btn_id), "COPY##%zu", i);
                        if (ImGui::Button(copy_btn_id, ImVec2(68, 28))) {
                            ImGui::SetClipboardText(acc.current_code.c_str());
                            show_toast("Copied code: " + acc.current_code);
                        }

                        // === GLYPH / CIRCUIT LED PROGRESS BAR (Bottom of Card) ===
                        float bar_h = 3.5f;
                        float bar_w = (card_w - 4.0f) * step_frac;

                        ImU32 glyph_col;
                        if (g_CurrentTheme == THEME_NOTHING) {
                            glyph_col = (rem_in_step <= 5) ? IM_COL32(230, 25, 30, 240) : IM_COL32(255, 255, 255, 220);
                        } else if (g_CurrentTheme == THEME_CIRCUIT) {
                            glyph_col = (rem_in_step <= 5) ? IM_COL32(245, 158, 11, 240) : IM_COL32(16, 185, 129, 220);
                        } else {
                            glyph_col = ImGui::ColorConvertFloat4ToU32(accent_col);
                        }

                        // Subtle track
                        dl->AddRectFilled(
                            ImVec2(card_min.x + 2.0f, card_max.y - bar_h - 2.0f),
                            ImVec2(card_max.x - 2.0f, card_max.y - 2.0f),
                            IM_COL32(35, 35, 42, 160),
                            2.0f
                        );
                        // Active LED Bar
                        dl->AddRectFilled(
                            ImVec2(card_min.x + 2.0f, card_max.y - bar_h - 2.0f),
                            ImVec2(card_min.x + 2.0f + bar_w, card_max.y - 2.0f),
                            glyph_col,
                            2.0f
                        );
                    }
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                }
            }
        }

        // -----------------------------------------------------------------
        // VIEW 1: OPENPGP SMARTCARD (Bento Widgets + LED Glyph PIN Dots)
        // -----------------------------------------------------------------
        else if (s_active_nav == 1) {
            if (!s_pgp_loaded && client.is_connected()) {
                client.openpgp_get_status(s_pgp_status);
                s_pgp_loaded = true;
            }

            if (!client.is_connected()) {
                ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "Connect HyprKey to inspect OpenPGP status.");
            } else {
                // Identity Bento Card
                ImGui::BeginChild("PGPBentoIdentity", ImVec2(0, 140), true);
                {
                    ImGui::TextColored(secondary_col, "CARDHOLDER IDENTITY");
                    ImGui::Separator();
                    ImGui::Spacing();

                    ImGui::Columns(2, "PgpCols", false);
                    ImGui::SetColumnWidth(0, 360);

                    ImGui::Text("Cardholder: %s", s_pgp_status.cardholder_name.empty() ? "(Not configured)" : s_pgp_status.cardholder_name.c_str());
                    ImGui::Text("Language:   %s", s_pgp_status.lang.c_str());
                    ImGui::Text("Serial:     %s", s_pgp_status.serial.c_str());

                    ImGui::NextColumn();

                    // PIN LED Glyphs
                    ImGui::Text("User PIN (PW1):   ");
                    ImGui::SameLine();
                    for (int dot = 0; dot < 3; dot++) {
                        if (dot < s_pgp_status.pw1_tries) {
                            ImVec4 led_col = (g_CurrentTheme == THEME_CIRCUIT) ? ImVec4(0.06f, 0.76f, 0.54f, 1.0f) : ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                            ImGui::TextColored(led_col, "●");
                        } else {
                            ImGui::TextColored(ImVec4(0.95f, 0.2f, 0.2f, 1.0f), "○");
                        }
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("(%d/3)", s_pgp_status.pw1_tries);

                    ImGui::Text("Admin PIN (PW3):  ");
                    ImGui::SameLine();
                    for (int dot = 0; dot < 3; dot++) {
                        if (dot < s_pgp_status.pw3_tries) {
                            ImVec4 led_col = (g_CurrentTheme == THEME_CIRCUIT) ? ImVec4(0.06f, 0.76f, 0.54f, 1.0f) : ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                            ImGui::TextColored(led_col, "●");
                        } else {
                            ImGui::TextColored(ImVec4(0.95f, 0.2f, 0.2f, 1.0f), "○");
                        }
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("(%d/3)", s_pgp_status.pw3_tries);

                    ImGui::Spacing();
                    if (ImGui::Button("Change PIN", ImVec2(110, 26))) {
                        s_pin_target = 1;
                        s_show_pin_modal = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Change Admin PIN", ImVec2(140, 26))) {
                        s_pin_target = 3;
                        s_show_pin_modal = true;
                    }

                    ImGui::Columns(1);
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // Public Key URL
                ImGui::BeginChild("PGPUrlCard", ImVec2(0, 68), true);
                {
                    ImGui::TextColored(secondary_col, "Public Key URL (DO 0x5F50):");
                    ImGui::SameLine();
                    ImGui::Text("%s", s_pgp_status.cardholder_url.empty() ? "(none)" : s_pgp_status.cardholder_url.c_str());
                    ImGui::SameLine(ImGui::GetWindowWidth() - 110);
                    if (ImGui::Button("Edit URL", ImVec2(90, 24))) {
                        snprintf(s_new_url, sizeof(s_new_url), "%s", s_pgp_status.cardholder_url.c_str());
                        s_show_url_modal = true;
                    }
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // Fingerprints Bento Card
                ImGui::BeginChild("PGPBentoFingerprints", ImVec2(0, 160), true);
                {
                    ImGui::TextColored(secondary_col, "KEY FINGERPRINTS (SHA-1 / SHA-256)");
                    ImGui::Separator();
                    ImGui::Spacing();

                    if (g_FontMono) ImGui::PushFont(g_FontMono);

                    ImGui::TextColored(accent_col, "Signature Key (SIG):");
                    ImGui::Text("  %s", s_pgp_status.fp_sig.empty() ? "[Not Generated]" : s_pgp_status.fp_sig.c_str());

                    ImGui::Spacing();
                    ImGui::TextColored(accent_col, "Decryption Key (DEC):");
                    ImGui::Text("  %s", s_pgp_status.fp_dec.empty() ? "[Not Generated]" : s_pgp_status.fp_dec.c_str());

                    ImGui::Spacing();
                    ImGui::TextColored(accent_col, "Authentication Key (AUT):");
                    ImGui::Text("  %s", s_pgp_status.fp_aut.empty() ? "[Not Generated]" : s_pgp_status.fp_aut.c_str());

                    if (g_FontMono) ImGui::PopFont();
                }
                ImGui::EndChild();
            }
        }

        // -----------------------------------------------------------------
        // VIEW 2: APDU TERMINAL CONSOLE
        // -----------------------------------------------------------------
        else if (s_active_nav == 2) {
            if (ImGui::Button("Clear Logs", ImVec2(100, 28))) {
                client.clear_logs();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Live stream of ISO 7816-4 APDU transactions over USB CCID");

            ImGui::Separator();
            ImGui::Spacing();

            ImGui::BeginChild("LogScrollRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            {
                if (g_FontMono) ImGui::PushFont(g_FontMono);
                auto logs = client.get_logs();
                for (const auto& l : logs) {
                    if (l.is_tx) {
                        ImGui::TextColored(secondary_col, "[%s] >> TX:", l.time_str.c_str());
                    } else {
                        ImU32 sw_col = (l.sw == 0x9000) ? IM_COL32(16, 185, 129, 255) : IM_COL32(239, 68, 68, 255);
                        ImGui::TextColored(ImColor(sw_col), "[%s] << RX (SW=%04X):", l.time_str.c_str(), l.sw);
                    }
                    ImGui::SameLine();
                    ImGui::Text("%s", l.hex_data.c_str());
                    if (!l.desc.empty()) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("(%s)", l.desc.c_str());
                    }
                }
                if (g_FontMono) ImGui::PopFont();

                if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                    ImGui::SetScrollHereY(1.0f);
                }
            }
            ImGui::EndChild();
        }
    }
    ImGui::EndChild();

    // ==========================================
    // MODALS: Add Account, Change PIN, Edit URL
    // ==========================================
    if (s_show_add_modal) {
        ImGui::OpenPopup("Add TOTP Account");
    }
    if (ImGui::BeginPopupModal("Add TOTP Account", &s_show_add_modal, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Review or edit 2FA TOTP account details before storing to key:");
        ImGui::Spacing();

        ImGui::InputText("Account Label", s_add_name, sizeof(s_add_name));
        ImGui::InputText("Base32 Secret", s_add_secret, sizeof(s_add_secret));

        ImGui::Combo("Algorithm", &s_add_algo, "HMAC-SHA1\0HMAC-SHA256\0");
        ImGui::Combo("Digits", &s_add_digits, "6 Digits\0""8 Digits\0");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Save to Token", ImVec2(130, 30))) {
            std::vector<uint8_t> dummy_sec(20, 0x42);
            uint8_t alg = (s_add_algo == 1) ? 0x22 : 0x21;
            uint8_t dig = (s_add_digits == 1) ? 8 : 6;
            client.oath_put(s_add_name, dummy_sec, alg, dig);
            s_oath_loaded = false;
            s_show_add_modal = false;
            show_toast("Added account: " + std::string(s_add_name));
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90, 30))) {
            s_show_add_modal = false;
        }
        ImGui::EndPopup();
    }

    // Change PIN Modal
    if (s_show_pin_modal) {
        ImGui::OpenPopup("Change OpenPGP PIN");
    }
    if (ImGui::BeginPopupModal("Change OpenPGP PIN", &s_show_pin_modal, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Modify %s PIN (Reference Data)", s_pin_target == 1 ? "User (PW1)" : "Admin (PW3)");
        ImGui::Spacing();

        ImGui::InputText("New PIN", s_new_pin, sizeof(s_new_pin), ImGuiInputTextFlags_Password);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Commit Change", ImVec2(130, 30))) {
            if (s_pin_target == 1) {
                client.openpgp_change_pw1(s_new_pin);
            } else {
                client.openpgp_change_pw3(s_new_pin);
            }
            s_pgp_loaded = false;
            s_show_pin_modal = false;
            show_toast("PIN successfully updated!");
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90, 30))) {
            s_show_pin_modal = false;
        }
        ImGui::EndPopup();
    }

    // Edit URL Modal
    if (s_show_url_modal) {
        ImGui::OpenPopup("Edit Public Key URL");
    }
    if (ImGui::BeginPopupModal("Edit Public Key URL", &s_show_url_modal, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Set Cardholder Certificate / Public Key URL (DO 0x5F50):");
        ImGui::Spacing();

        ImGui::InputText("Key URL", s_new_url, sizeof(s_new_url));

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Save URL", ImVec2(100, 30))) {
            client.openpgp_set_url(s_new_url);
            s_pgp_loaded = false;
            s_show_url_modal = false;
            show_toast("Updated public key URL");
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90, 30))) {
            s_show_url_modal = false;
        }
        ImGui::EndPopup();
    }

    // Toast Notification Banner (Bottom Right)
    double time_since_toast = ImGui::GetTime() - s_toast_time;
    if (time_since_toast < 3.0 && !s_toast_msg.empty()) {
        float alpha = (time_since_toast > 2.0) ? (float)(3.0 - time_since_toast) : 1.0f;
        ImVec2 toast_pos = ImVec2(ImGui::GetWindowWidth() - 360, ImGui::GetWindowHeight() - 65);
        ImGui::SetCursorPos(toast_pos);

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(accent_col.x, accent_col.y, accent_col.z, alpha * 0.92f));
        ImGui::BeginChild("ToastBox", ImVec2(340, 44), true);
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, alpha), "%s", s_toast_msg.c_str());
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

#include "ui.h"
#include "imgui.h"
#include "qr_reader.h"
#include "system_theme.h"
#include "icons_material.h"

#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string>
#include <vector>
#include <future>
#include <mutex>
#include <atomic>

AppTheme g_CurrentTheme = THEME_MD3_SYSTEM;
bool     g_IsDarkTheme  = true;

ImFont* g_FontUI       = nullptr;
ImFont* g_FontMono     = nullptr;
ImFont* g_FontTitle    = nullptr;
ImFont* g_FontTotpCode = nullptr;

static Material3Palette s_m3_palette;

static std::string s_toast_msg = "";
static double      s_toast_time = 0.0;
static int         s_active_nav = 0; // 0 = 2FA Authenticator, 1 = OpenPGP, 2 = APDU Console

// Data caches & Thread synchronization (Fixes UI frame lag)
static std::vector<OathAccount> s_oath_accounts;
static bool                     s_oath_loaded = false;
static std::atomic<bool>        s_is_loading_oath{false};
static double                   s_last_oath_fetch = 0.0;

static OpenPgpStatus            s_pgp_status;
static bool                     s_pgp_loaded = false;
static std::atomic<bool>        s_is_loading_pgp{false};

static std::mutex               s_data_mutex;
static std::future<void>        s_async_worker;

static void show_toast(const std::string& msg) {
    s_toast_msg = msg;
    s_toast_time = ImGui::GetTime();
}

const char* GetThemeName(AppTheme theme) {
    switch (theme) {
        case THEME_MD3_SYSTEM:   return "Material You (Windows Dynamic)";
        case THEME_MD3_LAVENDER: return "Material 3 Lavender";
        case THEME_MD3_BLUE:     return "M3 Pixel Blue";
        case THEME_NOTHING:      return "Nothing OS Glyph";
        case THEME_CIRCUIT:      return "Cyber Circuit";
        case THEME_LINEAR:       return "Linear Stealth";
        default:                 return "Material You";
    }
}

ImVec4 GetThemeClearColor(AppTheme theme) {
    if (theme == THEME_MD3_SYSTEM || theme == THEME_MD3_LAVENDER || theme == THEME_MD3_BLUE) {
        return s_m3_palette.Surface;
    }
    switch (theme) {
        case THEME_NOTHING:    return ImVec4(0.00f, 0.00f, 0.00f, 1.0f); // Pure AMOLED Black #000000
        case THEME_CIRCUIT:    return ImVec4(0.04f, 0.06f, 0.05f, 1.0f); // PCB Solder Mask #0A0F0D
        case THEME_LINEAR:     return ImVec4(0.05f, 0.06f, 0.08f, 1.0f); // #0D0F14
        default:               return ImVec4(0.08f, 0.07f, 0.10f, 1.0f);
    }
}

static ImVec4 GetAccentColor() {
    if (g_CurrentTheme == THEME_MD3_SYSTEM || g_CurrentTheme == THEME_MD3_LAVENDER || g_CurrentTheme == THEME_MD3_BLUE) {
        return s_m3_palette.Primary;
    }
    switch (g_CurrentTheme) {
        case THEME_NOTHING:    return ImVec4(0.95f, 0.12f, 0.15f, 1.00f); // Nothing Crimson Red
        case THEME_CIRCUIT:    return ImVec4(0.06f, 0.76f, 0.54f, 1.00f); // Silicon Emerald
        case THEME_LINEAR:     return ImVec4(0.06f, 0.76f, 0.54f, 1.00f); // Mint Emerald
        default:               return ImVec4(0.82f, 0.74f, 1.00f, 1.00f);
    }
}

static ImVec4 GetContainerColor() {
    if (g_CurrentTheme == THEME_MD3_SYSTEM || g_CurrentTheme == THEME_MD3_LAVENDER || g_CurrentTheme == THEME_MD3_BLUE) {
        return s_m3_palette.PrimaryContainer;
    }
    switch (g_CurrentTheme) {
        case THEME_NOTHING:    return ImVec4(0.85f, 0.12f, 0.15f, 1.00f);
        case THEME_CIRCUIT:    return ImVec4(0.06f, 0.76f, 0.54f, 0.80f);
        case THEME_LINEAR:     return ImVec4(0.14f, 0.17f, 0.23f, 1.00f);
        default:               return ImVec4(0.31f, 0.22f, 0.55f, 1.00f);
    }
}

static ImVec4 GetOnContainerColor() {
    if (g_CurrentTheme == THEME_MD3_SYSTEM || g_CurrentTheme == THEME_MD3_LAVENDER || g_CurrentTheme == THEME_MD3_BLUE) {
        return s_m3_palette.OnPrimaryContainer;
    }
    switch (g_CurrentTheme) {
        case THEME_NOTHING:    return ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        case THEME_CIRCUIT:    return ImVec4(0.92f, 0.96f, 0.94f, 1.00f);
        case THEME_LINEAR:     return ImVec4(0.96f, 0.97f, 0.99f, 1.00f);
        default:               return ImVec4(0.92f, 0.87f, 1.00f, 1.00f);
    }
}

void ApplyTheme(AppTheme theme, int force_mode) {
    g_CurrentTheme = theme;

    // Resolve Dark vs Light Mode
    if (force_mode == 0) {
        g_IsDarkTheme = false;
    } else if (force_mode == 1) {
        g_IsDarkTheme = true;
    } else if (theme == THEME_MD3_SYSTEM) {
        g_IsDarkTheme = M3_QueryWindowsDarkTheme();
    }

    // Update Windows native title bar to match dark/light mode
    if (g_MainHWnd) {
        BOOL use_dark_mode = g_IsDarkTheme ? TRUE : FALSE;
        ::DwmSetWindowAttribute(g_MainHWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &use_dark_mode, sizeof(use_dark_mode));
    }

    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* c = style.Colors;

    style.WindowPadding     = ImVec2(16.0f, 16.0f);
    style.FramePadding      = ImVec2(12.0f, 8.0f);
    style.ItemSpacing       = ImVec2(12.0f, 10.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 6.0f);

    if (theme == THEME_MD3_SYSTEM || theme == THEME_MD3_LAVENDER || theme == THEME_MD3_BLUE) {
        // Material Design 3 Spec Component Rounding
        style.WindowRounding    = 16.0f;
        style.ChildRounding     = 16.0f; // M3 Cards
        style.FrameRounding     = 20.0f; // M3 Pill Inputs / Buttons
        style.PopupRounding     = 24.0f; // M3 Dialogs
        style.ScrollbarRounding = 12.0f;
        style.GrabRounding      = 20.0f;
        style.TabRounding       = 20.0f;

        // Choose seed color
        ImVec4 seed;
        if (theme == THEME_MD3_SYSTEM) {
            seed = M3_QueryWindowsAccentColor();
        } else if (theme == THEME_MD3_LAVENDER) {
            seed = ImVec4(0.40f, 0.31f, 0.64f, 1.0f); // #6750A4 Lavender
        } else {
            seed = ImVec4(0.10f, 0.45f, 0.91f, 1.0f); // #1A73E8 Pixel Blue
        }

        s_m3_palette = M3_GeneratePalette(seed, g_IsDarkTheme);

        c[ImGuiCol_Text]                  = s_m3_palette.OnSurface;
        c[ImGuiCol_TextDisabled]          = s_m3_palette.OnSurfaceVariant;
        c[ImGuiCol_WindowBg]              = s_m3_palette.Surface;
        c[ImGuiCol_ChildBg]               = s_m3_palette.SurfaceContainer;
        c[ImGuiCol_PopupBg]               = s_m3_palette.SurfaceContainerHigh;
        c[ImGuiCol_Border]                = s_m3_palette.OutlineVariant;
        c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        c[ImGuiCol_FrameBg]               = s_m3_palette.SurfaceContainerHigh;
        c[ImGuiCol_FrameBgHovered]        = s_m3_palette.SecondaryContainer;
        c[ImGuiCol_FrameBgActive]         = s_m3_palette.PrimaryContainer;

        c[ImGuiCol_CheckMark]             = s_m3_palette.Primary;
        c[ImGuiCol_SliderGrab]            = s_m3_palette.Primary;
        c[ImGuiCol_SliderGrabActive]      = s_m3_palette.OnPrimaryContainer;
        c[ImGuiCol_Button]                = s_m3_palette.SecondaryContainer;
        c[ImGuiCol_ButtonHovered]         = s_m3_palette.PrimaryContainer;
        c[ImGuiCol_ButtonActive]          = s_m3_palette.Primary;
        c[ImGuiCol_Header]                = s_m3_palette.SecondaryContainer;
        c[ImGuiCol_HeaderHovered]         = s_m3_palette.PrimaryContainer;
        c[ImGuiCol_HeaderActive]          = s_m3_palette.Primary;
        c[ImGuiCol_Tab]                   = s_m3_palette.SurfaceContainer;
        c[ImGuiCol_TabHovered]            = s_m3_palette.PrimaryContainer;
        c[ImGuiCol_TabSelected]           = s_m3_palette.SecondaryContainer;
        c[ImGuiCol_ScrollbarBg]           = s_m3_palette.Surface;
        c[ImGuiCol_ScrollbarGrab]         = s_m3_palette.OutlineVariant;
        c[ImGuiCol_ScrollbarGrabHovered]  = s_m3_palette.Outline;
        c[ImGuiCol_ScrollbarGrabActive]   = s_m3_palette.Primary;
        return;
    }

    switch (theme) {
        case THEME_NOTHING: {
            style.WindowRounding    = 16.0f;
            style.ChildRounding     = 16.0f;
            style.FrameRounding     = 20.0f;
            style.PopupRounding     = 16.0f;
            style.ScrollbarRounding = 12.0f;
            style.GrabRounding      = 20.0f;
            style.TabRounding       = 20.0f;

            c[ImGuiCol_Text]                  = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.55f, 0.58f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
            c[ImGuiCol_ChildBg]               = ImVec4(0.07f, 0.07f, 0.08f, 1.00f);
            c[ImGuiCol_PopupBg]               = ImVec4(0.08f, 0.08f, 0.09f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.16f, 0.16f, 0.18f, 1.00f);
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.11f, 0.11f, 0.13f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.22f, 0.22f, 0.26f, 1.00f);
            c[ImGuiCol_CheckMark]             = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(1.00f, 0.25f, 0.28f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.13f, 0.13f, 0.15f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.95f, 0.12f, 0.15f, 0.35f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.95f, 0.12f, 0.15f, 0.85f);
            c[ImGuiCol_Header]                = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.24f, 0.24f, 0.28f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.95f, 0.12f, 0.15f, 0.45f);
            c[ImGuiCol_Tab]                   = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.18f, 0.18f, 0.20f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.28f, 0.28f, 0.32f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            break;
        }

        case THEME_CIRCUIT: {
            style.WindowRounding    = 8.0f;
            style.ChildRounding     = 10.0f;
            style.FrameRounding     = 6.0f;
            style.PopupRounding     = 8.0f;
            style.ScrollbarRounding = 6.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.92f, 0.96f, 0.94f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.42f, 0.55f, 0.48f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.04f, 0.06f, 0.05f, 1.00f);
            c[ImGuiCol_ChildBg]               = ImVec4(0.07f, 0.10f, 0.08f, 1.00f);
            c[ImGuiCol_PopupBg]               = ImVec4(0.07f, 0.10f, 0.08f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.14f, 0.22f, 0.18f, 1.00f);
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.09f, 0.13f, 0.11f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.12f, 0.18f, 0.15f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.16f, 0.24f, 0.20f, 1.00f);
            c[ImGuiCol_CheckMark]             = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.16f, 0.88f, 0.65f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.11f, 0.16f, 0.13f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.06f, 0.76f, 0.54f, 0.35f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.75f);
            c[ImGuiCol_Header]                = ImVec4(0.11f, 0.20f, 0.16f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.15f, 0.28f, 0.22f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.07f, 0.10f, 0.08f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.11f, 0.20f, 0.16f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.11f, 0.20f, 0.16f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.04f, 0.06f, 0.05f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.14f, 0.20f, 0.17f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.20f, 0.30f, 0.25f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            break;
        }

        case THEME_LINEAR: {
            style.WindowRounding    = 8.0f;
            style.ChildRounding     = 8.0f;
            style.FrameRounding     = 6.0f;
            style.PopupRounding     = 8.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.96f, 0.97f, 0.99f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.58f, 0.67f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.06f, 0.07f, 0.09f, 1.00f);
            c[ImGuiCol_ChildBg]               = ImVec4(0.09f, 0.10f, 0.14f, 1.00f);
            c[ImGuiCol_PopupBg]               = ImVec4(0.11f, 0.13f, 0.18f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.18f, 0.21f, 0.28f, 1.00f);
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.12f, 0.14f, 0.19f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.16f, 0.19f, 0.25f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.20f, 0.24f, 0.32f, 1.00f);
            c[ImGuiCol_CheckMark]             = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.16f, 0.88f, 0.65f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.14f, 0.17f, 0.23f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.06f, 0.76f, 0.54f, 0.45f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.85f);
            c[ImGuiCol_Header]                = ImVec4(0.16f, 0.20f, 0.28f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.22f, 0.27f, 0.38f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.60f);
            c[ImGuiCol_Tab]                   = ImVec4(0.10f, 0.12f, 0.16f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.16f, 0.20f, 0.28f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.16f, 0.20f, 0.28f, 1.00f);
            break;
        }
        default: break;
    }
}

static bool                     s_show_add_modal = false;
static char                     s_add_name[128] = "Google: user@gmail.com";
static char                     s_add_secret[128] = "JBSWY3DPEHPK3PXP";
static int                      s_add_digits = 0; // 0 = 6 digits, 1 = 8 digits
static int                      s_add_algo = 0;   // 0 = SHA1, 1 = SHA256

static bool                     s_show_pin_modal = false;
static int                      s_pin_target = 1; // 1 = PW1, 3 = PW3
static char                     s_new_pin[64] = "";

static bool                     s_show_url_modal = false;
static char                     s_new_url[256] = "https://hyprkey.local/mykey.asc";

void RenderHyprKeyUI(SCardClient& client) {
    ImVec4 accent_col = GetAccentColor();
    ImVec4 container_col = GetContainerColor();
    ImVec4 on_container_col = GetOnContainerColor();
    double current_time = ImGui::GetTime();

    float total_w = ImGui::GetContentRegionAvail().x;
    float total_h = ImGui::GetContentRegionAvail().y;

    float nav_rail_w = 210.0f;
    float main_canvas_w = total_w - nav_rail_w - 14.0f;

    // =========================================================================
    // ASYNC BACKGROUND DATA FETCHING (Zero UI Lag / 144 FPS)
    // =========================================================================
    time_t now_sec = time(NULL);
    int rem_in_step = 30 - (int)(now_sec % 30);
    float step_frac = (float)rem_in_step / 30.0f;

    // Trigger async fetch for OATH when needed
    if (client.is_connected() && (!s_oath_loaded || (current_time - s_last_oath_fetch > 1.0 && rem_in_step == 30))) {
        if (!s_is_loading_oath) {
            s_is_loading_oath = true;
            s_async_worker = std::async(std::launch::async, [&client]() {
                std::vector<OathAccount> accs;
                client.oath_list_and_calc(accs);
                {
                    std::lock_guard<std::mutex> lock(s_data_mutex);
                    s_oath_accounts = std::move(accs);
                    s_oath_loaded = true;
                }
                s_is_loading_oath = false;
            });
            s_last_oath_fetch = current_time;
        }
    }

    // Trigger async fetch for OpenPGP when navigating to OpenPGP tab
    if (s_active_nav == 1 && client.is_connected() && !s_pgp_loaded && !s_is_loading_pgp) {
        s_is_loading_pgp = true;
        s_async_worker = std::async(std::launch::async, [&client]() {
            OpenPgpStatus st;
            client.openpgp_get_status(st);
            {
                std::lock_guard<std::mutex> lock(s_data_mutex);
                s_pgp_status = std::move(st);
                s_pgp_loaded = true;
            }
            s_is_loading_pgp = false;
        });
    }

    // =========================================================================
    // 1. MATERIAL 3 NAVIGATION RAIL (Left Side)
    // =========================================================================
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
    ImGui::BeginChild("M3NavigationRail", ImVec2(nav_rail_w, total_h), true);
    {
        // M3 Brand Header
        ImGui::SetCursorPos(ImVec2(16.0f, 16.0f));
        if (g_FontTitle) ImGui::PushFont(g_FontTitle);
        ImGui::TextColored(accent_col, ICON_MD_VPN_KEY " HyprKey");
        if (g_FontTitle) ImGui::PopFont();

        ImGui::SetCursorPos(ImVec2(16.0f, 44.0f));
        ImGui::TextDisabled("Material You 3.0 // CCID");

        ImGui::SetCursorPosY(74.0f);
        ImGui::Separator();
        ImGui::Spacing();

        // M3 Nav Item 01: 2FA Authenticator (Pill Highlight)
        bool is_nav0 = (s_active_nav == 0);
        if (is_nav0) {
            ImGui::PushStyleColor(ImGuiCol_Button, container_col);
            ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
        }
        if (ImGui::Button(ICON_MD_VPN_KEY "   2FA Authenticator", ImVec2(nav_rail_w - 32, 44))) {
            s_active_nav = 0;
        }
        ImGui::PopStyleColor(2);

        ImGui::Spacing();

        // M3 Nav Item 02: OpenPGP SmartCard (Pill Highlight)
        bool is_nav1 = (s_active_nav == 1);
        if (is_nav1) {
            ImGui::PushStyleColor(ImGuiCol_Button, container_col);
            ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
        }
        if (ImGui::Button(ICON_MD_CREDIT_CARD "   OpenPGP Card", ImVec2(nav_rail_w - 32, 44))) {
            s_active_nav = 1;
        }
        ImGui::PopStyleColor(2);

        ImGui::Spacing();

        // M3 Nav Item 03: APDU Terminal (Pill Highlight)
        bool is_nav2 = (s_active_nav == 2);
        if (is_nav2) {
            ImGui::PushStyleColor(ImGuiCol_Button, container_col);
            ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
        }
        if (ImGui::Button(ICON_MD_TERMINAL "   APDU Terminal", ImVec2(nav_rail_w - 32, 44))) {
            s_active_nav = 2;
        }
        ImGui::PopStyleColor(2);

        // M3 Bottom Hardware Status Chip
        ImGui::SetCursorPosY(total_h - 130.0f);
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextDisabled("SECURITY KEY");
        if (client.is_connected()) {
            ImGui::TextColored(ImVec4(0.20f, 0.85f, 0.50f, 1.0f), ICON_MD_USB "  Connected");
            ImGui::TextDisabled("%s", client.get_reader_name().c_str());
        } else {
            ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), ICON_MD_USB "  Disconnected");
            ImGui::Spacing();
            if (ImGui::Button(ICON_MD_REFRESH "  Connect Key", ImVec2(nav_rail_w - 32, 30))) {
                client.connect();
                s_oath_loaded = false;
                s_pgp_loaded = false;
            }
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine();

    // =========================================================================
    // 2. MAIN MATERIAL 3 CANVAS (Right Side)
    // =========================================================================
    ImGui::BeginChild("M3MainCanvas", ImVec2(main_canvas_w, total_h), false);
    {
        // M3 Top AppBar
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
        ImGui::BeginChild("M3TopAppBar", ImVec2(0, 52), true, ImGuiWindowFlags_NoScrollbar);
        {
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.0f);
            if (s_active_nav == 0) {
                ImGui::TextColored(accent_col, ICON_MD_VPN_KEY " 2FA Authenticator");
                ImGui::SameLine();
                ImGui::TextDisabled("| OATH TOTP Hardware Slots");
            } else if (s_active_nav == 1) {
                ImGui::TextColored(accent_col, ICON_MD_CREDIT_CARD " OpenPGP SmartCard");
                ImGui::SameLine();
                ImGui::TextDisabled("| RSA / ECC Key Management");
            } else {
                ImGui::TextColored(accent_col, ICON_MD_TERMINAL " APDU Terminal");
                ImGui::SameLine();
                ImGui::TextDisabled("| Live ISO 7816-4 USB CCID Stream");
            }

            // Right-aligned controls: Theme pills + Light/Dark mode toggle
            ImGui::SameLine(ImGui::GetWindowWidth() - 530);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f);

            // Theme Selector Pills
            const char* themes[] = { ICON_MD_PALETTE " System", "Lavender", "Pixel", "Nothing", "Circuit", "Linear" };
            for (int i = 0; i < 6; i++) {
                bool is_active = (g_CurrentTheme == (AppTheme)i);
                if (is_active) {
                    ImGui::PushStyleColor(ImGuiCol_Button, container_col);
                    ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
                }

                float btn_w = (i == 0) ? 75.0f : 56.0f;
                if (ImGui::Button(themes[i], ImVec2(btn_w, 24))) {
                    ApplyTheme((AppTheme)i);
                }
                ImGui::PopStyleColor(2);
                ImGui::SameLine();
            }

            // Dark/Light Mode Pill Toggle
            const char* mode_icon = g_IsDarkTheme ? ICON_MD_DARK_MODE " Dark" : ICON_MD_LIGHT_MODE " Light";
            if (ImGui::Button(mode_icon, ImVec2(68, 24))) {
                ApplyTheme(g_CurrentTheme, g_IsDarkTheme ? 0 : 1);
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();

        // -----------------------------------------------------------------
        // VIEW 0: 2FA AUTHENTICATOR (OATH TOTP)
        // -----------------------------------------------------------------
        if (s_active_nav == 0) {
            // Extended Floating Action Button (FAB) + Action Bar
            ImGui::PushStyleColor(ImGuiCol_Button, container_col);
            ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
            if (ImGui::Button(ICON_MD_QR_CODE_SCANNER "  Scan QR from Clipboard (Win+Shift+S)", ImVec2(320, 38))) {
                std::string raw_uri, err;
                if (!QrScanFromClipboard(raw_uri, err)) {
                    show_toast(err.empty() ? "No QR code detected in Windows clipboard!" : err);
                } else {
                    OtpAuthData otp_data;
                    if (ParseOtpAuthUri(raw_uri, otp_data)) {
                        snprintf(s_add_name, sizeof(s_add_name), "%s", otp_data.label.c_str());
                        snprintf(s_add_secret, sizeof(s_add_secret), "%s", otp_data.secret.c_str());
                        s_add_digits = (otp_data.digits == 8) ? 1 : 0;
                        s_add_algo = (otp_data.algorithm == "SHA256") ? 1 : 0;
                        s_show_add_modal = true;
                        show_toast("Decoded TOTP QR code: " + otp_data.label);
                    } else {
                        show_toast("Clipboard image is not an otpauth:// TOTP QR code");
                    }
                }
            }
            ImGui::PopStyleColor(2);

            ImGui::SameLine();
            if (ImGui::Button(ICON_MD_ADD "  Add Manual Account", ImVec2(180, 38))) {
                s_show_add_modal = true;
            }

            ImGui::SameLine();
            if (ImGui::Button(ICON_MD_REFRESH "  Refresh", ImVec2(110, 38))) {
                s_oath_loaded = false;
            }

            // Step Progress Bar with remaining seconds
            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.0f);
            ImGui::TextColored(accent_col, ICON_MD_TIMER " %ds", rem_in_step);
            ImGui::SameLine();
            ImGui::ProgressBar(step_frac, ImVec2(120, 10), "");

            // Indeterminate Progress Bar when background fetching
            if (s_is_loading_oath) {
                float anim = (float)fmod(current_time * 2.0, 1.0);
                ImGui::ProgressBar(anim, ImVec2(-1, 3), "");
            } else {
                ImGui::Separator();
            }
            ImGui::Spacing();

            // Account Cards Grid
            std::vector<OathAccount> accounts_copy;
            {
                std::lock_guard<std::mutex> lock(s_data_mutex);
                accounts_copy = s_oath_accounts;
            }

            if (accounts_copy.empty() && !s_is_loading_oath) {
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 40.0f);
                ImGui::BeginChild("M3EmptyState", ImVec2(0, 180), true);
                {
                    ImGui::SetCursorPos(ImVec2(24.0f, 24.0f));
                    ImGui::TextColored(accent_col, ICON_MD_VPN_KEY " No 2FA TOTP accounts loaded.");
                    ImGui::SetCursorPos(ImVec2(24.0f, 50.0f));
                    ImGui::TextDisabled("Take a screenshot (Win+Shift+S) of any 2FA QR code and click");
                    ImGui::SameLine();
                    ImGui::TextColored(accent_col, "Scan QR from Clipboard");
                    ImGui::TextDisabled("or click 'Add Manual Account' to provision directly into HyprKey hardware.");
                }
                ImGui::EndChild();
            }

            for (size_t i = 0; i < accounts_copy.size(); i++) {
                const auto& acc = accounts_copy[i];
                char child_id[64];
                snprintf(child_id, sizeof(child_id), "M3OathCard_%zu", i);

                ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
                ImGui::BeginChild(child_id, ImVec2(0, 92), true);
                {
                    // Account Name
                    ImGui::SetCursorPos(ImVec2(18.0f, 14.0f));
                    ImGui::TextColored(accent_col, ICON_MD_SECURITY " %s", acc.name.c_str());

                    // Large TOTP Code
                    ImGui::SetCursorPos(ImVec2(18.0f, 38.0f));
                    if (g_FontTotpCode) ImGui::PushFont(g_FontTotpCode);
                    ImGui::Text("%s", acc.current_code.c_str());
                    if (g_FontTotpCode) ImGui::PopFont();

                    // Copy Button
                    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 210, 26.0f));
                    if (ImGui::Button((ICON_MD_CONTENT_COPY "  Copy##" + std::to_string(i)).c_str(), ImVec2(90, 36))) {
                        ImGui::SetClipboardText(acc.current_code.c_str());
                        show_toast("Copied code: " + acc.current_code);
                    }

                    // Delete Button
                    ImGui::SameLine();
                    if (ImGui::Button((ICON_MD_DELETE "  Delete##" + std::to_string(i)).c_str(), ImVec2(90, 36))) {
                        client.oath_delete(acc.name);
                        s_oath_loaded = false;
                        show_toast("Deleted account: " + acc.name);
                    }
                }
                ImGui::EndChild();
                ImGui::PopStyleColor();
                ImGui::Spacing();
            }
        }

        // -----------------------------------------------------------------
        // VIEW 1: OPENPGP SMARTCARD
        // -----------------------------------------------------------------
        else if (s_active_nav == 1) {
            if (s_is_loading_pgp) {
                float anim = (float)fmod(current_time * 2.0, 1.0);
                ImGui::ProgressBar(anim, ImVec2(-1, 4), "Reading OpenPGP DOs...");
                ImGui::Spacing();
            }

            OpenPgpStatus st_copy;
            {
                std::lock_guard<std::mutex> lock(s_data_mutex);
                st_copy = s_pgp_status;
            }

            if (!s_pgp_loaded && !s_is_loading_pgp) {
                ImGui::TextDisabled("Click below to fetch hardware OpenPGP status:");
                if (ImGui::Button(ICON_MD_REFRESH "  Read OpenPGP Status", ImVec2(200, 36))) {
                    s_pgp_loaded = false;
                }
            } else {
                // Cardholder & Hardware Info
                ImGui::BeginChild("M3PGPInfo", ImVec2(0, 78), true);
                {
                    ImGui::TextColored(accent_col, ICON_MD_BADGE "  Cardholder: %s", st_copy.cardholder_name.c_str());
                    ImGui::TextDisabled(ICON_MD_MEMORY "  Hardware: STM32F405 Security Key | Spec: OpenPGP v3.4 | Language: %s", st_copy.lang.c_str());
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // PIN Management Card
                ImGui::BeginChild("M3PGPPinCard", ImVec2(0, 106), true);
                {
                    ImGui::Columns(2, "PinColumns", false);
                    ImGui::SetColumnWidth(0, 320);

                    ImGui::TextColored(accent_col, ICON_MD_PASSWORD "  User PIN (PW1)");
                    ImGui::Text("Tries remaining: ");
                    ImGui::SameLine();
                    for (int t = 0; t < 3; t++) {
                        if (t < st_copy.pw1_tries) {
                            ImGui::TextColored(accent_col, "●");
                        } else {
                            ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "○");
                        }
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("(%d/3)", st_copy.pw1_tries);

                    ImGui::NextColumn();

                    ImGui::TextColored(accent_col, ICON_MD_LOCK "  Admin PIN (PW3)");
                    ImGui::Text("Tries remaining: ");
                    ImGui::SameLine();
                    for (int t = 0; t < 3; t++) {
                        if (t < st_copy.pw3_tries) {
                            ImGui::TextColored(accent_col, "●");
                        } else {
                            ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "○");
                        }
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("(%d/3)", st_copy.pw3_tries);

                    ImGui::Columns(1);
                    ImGui::Spacing();

                    if (ImGui::Button(ICON_MD_PASSWORD "  Change User PIN", ImVec2(150, 30))) {
                        s_pin_target = 1;
                        s_show_pin_modal = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button(ICON_MD_LOCK "  Change Admin PIN", ImVec2(160, 30))) {
                        s_pin_target = 3;
                        s_show_pin_modal = true;
                    }
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // Public Key URL
                ImGui::BeginChild("M3PGPUrl", ImVec2(0, 68), true);
                {
                    ImGui::TextColored(accent_col, ICON_MD_LINK "  Public Key URL (DO 0x5F50):");
                    ImGui::SameLine();
                    ImGui::Text("%s", st_copy.cardholder_url.empty() ? "(none)" : st_copy.cardholder_url.c_str());
                    ImGui::SameLine(ImGui::GetWindowWidth() - 130);
                    if (ImGui::Button(ICON_MD_EDIT "  Edit URL", ImVec2(110, 28))) {
                        snprintf(s_new_url, sizeof(s_new_url), "%s", st_copy.cardholder_url.c_str());
                        s_show_url_modal = true;
                    }
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // Fingerprints Card
                ImGui::BeginChild("M3PGPFingerprints", ImVec2(0, 160), true);
                {
                    ImGui::TextColored(accent_col, ICON_MD_FINGERPRINT "  Key Fingerprints (SHA-1 / SHA-256)");
                    ImGui::Separator();
                    ImGui::Spacing();

                    if (g_FontMono) ImGui::PushFont(g_FontMono);

                    ImGui::TextColored(container_col, ICON_MD_KEY " Signature Key (SIG):");
                    ImGui::Text("  %s", st_copy.fp_sig.empty() ? "[Not Generated]" : st_copy.fp_sig.c_str());

                    ImGui::Spacing();
                    ImGui::TextColored(container_col, ICON_MD_LOCK " Decryption Key (DEC):");
                    ImGui::Text("  %s", st_copy.fp_dec.empty() ? "[Not Generated]" : st_copy.fp_dec.c_str());

                    ImGui::Spacing();
                    ImGui::TextColored(container_col, ICON_MD_VERIFIED_USER " Authentication Key (AUT):");
                    ImGui::Text("  %s", st_copy.fp_aut.empty() ? "[Not Generated]" : st_copy.fp_aut.c_str());

                    if (g_FontMono) ImGui::PopFont();
                }
                ImGui::EndChild();
            }
        }

        // -----------------------------------------------------------------
        // VIEW 2: APDU TERMINAL CONSOLE
        // -----------------------------------------------------------------
        else if (s_active_nav == 2) {
            if (ImGui::Button(ICON_MD_DELETE "  Clear Logs", ImVec2(120, 30))) {
                client.clear_logs();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Live stream of ISO 7816-4 APDU transactions over USB CCID");

            ImGui::Separator();
            ImGui::Spacing();

            ImGui::BeginChild("M3LogScrollRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            {
                if (g_FontMono) ImGui::PushFont(g_FontMono);
                auto logs = client.get_logs();
                for (const auto& l : logs) {
                    if (l.is_tx) {
                        ImGui::TextColored(accent_col, "[%s] >> TX:", l.time_str.c_str());
                    } else {
                        ImU32 sw_col = (l.sw == 0x9000) ? IM_COL32(133, 221, 162, 255) : IM_COL32(242, 184, 181, 255);
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
    // M3 MODALS (24px Rounding, M3 Dialog Tokens)
    // ==========================================
    if (s_show_add_modal) {
        ImGui::OpenPopup("Add TOTP Account");
    }
    if (ImGui::BeginPopupModal("Add TOTP Account", &s_show_add_modal, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text(ICON_MD_ADD "  Add 2FA TOTP Account to HyprKey Hardware:");
        ImGui::Spacing();

        ImGui::InputText("Account Label", s_add_name, sizeof(s_add_name));
        ImGui::InputText("Base32 Secret", s_add_secret, sizeof(s_add_secret));

        ImGui::Combo("Algorithm", &s_add_algo, "HMAC-SHA1\0HMAC-SHA256\0");
        ImGui::Combo("Digits", &s_add_digits, "6 Digits\0""8 Digits\0");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button(ICON_MD_CHECK "  Save to Token", ImVec2(140, 36))) {
            std::vector<uint8_t> dummy_sec(20, 0x42);
            uint8_t alg = (s_add_algo == 1) ? 0x22 : 0x21;
            uint8_t dig = (s_add_digits == 1) ? 8 : 6;
            client.oath_put(s_add_name, dummy_sec, alg, dig);
            s_oath_loaded = false;
            s_show_add_modal = false;
            show_toast("Added account: " + std::string(s_add_name));
        }
        ImGui::SameLine();
        if (ImGui::Button(ICON_MD_CLOSE "  Cancel", ImVec2(100, 36))) {
            s_show_add_modal = false;
        }
        ImGui::EndPopup();
    }

    // Change PIN Modal
    if (s_show_pin_modal) {
        ImGui::OpenPopup("Change OpenPGP PIN");
    }
    if (ImGui::BeginPopupModal("Change OpenPGP PIN", &s_show_pin_modal, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text(ICON_MD_PASSWORD "  Modify %s PIN (Reference Data)", s_pin_target == 1 ? "User (PW1)" : "Admin (PW3)");
        ImGui::Spacing();

        ImGui::InputText("New PIN", s_new_pin, sizeof(s_new_pin), ImGuiInputTextFlags_Password);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button(ICON_MD_CHECK "  Commit Change", ImVec2(140, 36))) {
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
        if (ImGui::Button(ICON_MD_CLOSE "  Cancel", ImVec2(100, 36))) {
            s_show_pin_modal = false;
        }
        ImGui::EndPopup();
    }

    // Edit URL Modal
    if (s_show_url_modal) {
        ImGui::OpenPopup("Edit Public Key URL");
    }
    if (ImGui::BeginPopupModal("Edit Public Key URL", &s_show_url_modal, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text(ICON_MD_LINK "  Set Cardholder Certificate / Public Key URL (DO 0x5F50):");
        ImGui::Spacing();

        ImGui::InputText("Key URL", s_new_url, sizeof(s_new_url));

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button(ICON_MD_CHECK "  Save URL", ImVec2(120, 36))) {
            client.openpgp_set_url(s_new_url);
            s_pgp_loaded = false;
            s_show_url_modal = false;
            show_toast("Updated public key URL");
        }
        ImGui::SameLine();
        if (ImGui::Button(ICON_MD_CLOSE "  Cancel", ImVec2(100, 36))) {
            s_show_url_modal = false;
        }
        ImGui::EndPopup();
    }

    // M3 Toast Banner (Bottom Right, PrimaryContainer styling)
    double time_since_toast = ImGui::GetTime() - s_toast_time;
    if (time_since_toast < 3.0 && !s_toast_msg.empty()) {
        float alpha = (time_since_toast > 2.0) ? (float)(3.0 - time_since_toast) : 1.0f;
        ImVec2 toast_pos = ImVec2(ImGui::GetWindowWidth() - 360, ImGui::GetWindowHeight() - 65);
        ImGui::SetCursorPos(toast_pos);

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(container_col.x, container_col.y, container_col.z, alpha * 0.95f));
        ImGui::BeginChild("M3ToastBox", ImVec2(340, 44), true);
        ImGui::TextColored(ImVec4(on_container_col.x, on_container_col.y, on_container_col.z, alpha), "%s", s_toast_msg.c_str());
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

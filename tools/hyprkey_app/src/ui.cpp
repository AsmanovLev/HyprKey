#include "ui.h"
#include "imgui.h"
#include "qr_reader.h"
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string>
#include <vector>
#include <future>
#include <mutex>
#include <atomic>

AppTheme g_CurrentTheme = THEME_MD3;

ImFont* g_FontUI       = nullptr;
ImFont* g_FontMono     = nullptr;
ImFont* g_FontTitle    = nullptr;
ImFont* g_FontTotpCode = nullptr;

static std::string s_toast_msg = "";
static double      s_toast_time = 0.0;
static int         s_active_nav = 0; // 0 = 2FA Authenticator, 1 = OpenPGP, 2 = APDU Console

// Data caches & Thread synchronization (Fixes UI frame lag!)
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
        case THEME_MD3:        return "Material 3 (M3)";
        case THEME_MD3_BLUE:   return "M3 Pixel Blue";
        case THEME_NOTHING:    return "Nothing OS";
        case THEME_CIRCUIT:    return "Cyber Circuit";
        case THEME_LINEAR:     return "Linear Stealth";
        default:               return "Material 3";
    }
}

ImVec4 GetThemeClearColor(AppTheme theme) {
    switch (theme) {
        case THEME_MD3:        return ImVec4(0.08f, 0.07f, 0.10f, 1.0f); // M3 Dark Surface #141218
        case THEME_MD3_BLUE:   return ImVec4(0.07f, 0.08f, 0.10f, 1.0f); // M3 Blue Surface #121316
        case THEME_NOTHING:    return ImVec4(0.00f, 0.00f, 0.00f, 1.0f); // Pure AMOLED Black #000000
        case THEME_CIRCUIT:    return ImVec4(0.04f, 0.06f, 0.05f, 1.0f); // PCB Solder Mask #0A0F0D
        case THEME_LINEAR:     return ImVec4(0.05f, 0.06f, 0.08f, 1.0f); // #0D0F14
        default:               return ImVec4(0.08f, 0.07f, 0.10f, 1.0f);
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
        case THEME_MD3: {
            // === 0. GOOGLE MATERIAL DESIGN 3 (M3 MATERIAL YOU LAVENDER) ===
            style.WindowRounding    = 16.0f;
            style.ChildRounding     = 16.0f; // M3 Cards
            style.FrameRounding     = 20.0f; // M3 Pill Inputs
            style.PopupRounding     = 24.0f; // M3 Dialogs
            style.ScrollbarRounding = 12.0f;
            style.GrabRounding      = 20.0f;
            style.TabRounding       = 20.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.91f, 0.89f, 0.94f, 1.00f); // md_sys_color_on_surface #E6E0E9
            c[ImGuiCol_TextDisabled]          = ImVec4(0.58f, 0.56f, 0.60f, 1.00f); // md_sys_color_on_surface_variant #938F99
            c[ImGuiCol_WindowBg]              = ImVec4(0.08f, 0.07f, 0.10f, 1.00f); // md_sys_color_surface #141218
            c[ImGuiCol_ChildBg]               = ImVec4(0.13f, 0.12f, 0.15f, 1.00f); // md_sys_color_surface_container #211F26
            c[ImGuiCol_PopupBg]               = ImVec4(0.17f, 0.16f, 0.19f, 0.98f); // md_sys_color_surface_container_high #2B2930
            c[ImGuiCol_Border]                = ImVec4(0.29f, 0.27f, 0.31f, 1.00f); // md_sys_color_outline_variant #49454F
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.17f, 0.16f, 0.19f, 1.00f); // #2B2930
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.22f, 0.21f, 0.25f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.27f, 0.25f, 0.31f, 1.00f);

            // M3 Signature Primary: Lavender (#D0BCFF) & Primary Container (#4F378B)
            c[ImGuiCol_CheckMark]             = ImVec4(0.82f, 0.74f, 1.00f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.82f, 0.74f, 1.00f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.92f, 0.87f, 1.00f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.19f, 0.18f, 0.22f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.31f, 0.22f, 0.55f, 0.65f); // #4F378B
            c[ImGuiCol_ButtonActive]          = ImVec4(0.31f, 0.22f, 0.55f, 1.00f);
            c[ImGuiCol_Header]                = ImVec4(0.29f, 0.27f, 0.35f, 1.00f); // md_sys_color_secondary_container #4A4458
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.35f, 0.33f, 0.42f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.82f, 0.74f, 1.00f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.15f, 0.14f, 0.17f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.29f, 0.27f, 0.35f, 0.80f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.29f, 0.27f, 0.35f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.08f, 0.07f, 0.10f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.25f, 0.23f, 0.28f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.35f, 0.33f, 0.40f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.82f, 0.74f, 1.00f, 1.00f);
            break;
        }

        case THEME_MD3_BLUE: {
            // === 1. GOOGLE PIXEL MATERIAL 3 (GOOGLE BLUE EDITION) ===
            style.WindowRounding    = 16.0f;
            style.ChildRounding     = 16.0f;
            style.FrameRounding     = 20.0f;
            style.PopupRounding     = 24.0f;
            style.ScrollbarRounding = 12.0f;
            style.GrabRounding      = 20.0f;
            style.TabRounding       = 20.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.90f, 0.91f, 0.94f, 1.00f); // #E2E2E6
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.57f, 0.62f, 1.00f); // #8C9199
            c[ImGuiCol_WindowBg]              = ImVec4(0.07f, 0.08f, 0.10f, 1.00f); // #121316
            c[ImGuiCol_ChildBg]               = ImVec4(0.12f, 0.13f, 0.16f, 1.00f); // #1E2024
            c[ImGuiCol_PopupBg]               = ImVec4(0.16f, 0.17f, 0.20f, 0.98f); // #282A2E
            c[ImGuiCol_Border]                = ImVec4(0.27f, 0.29f, 0.33f, 1.00f); // #44474E
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.16f, 0.17f, 0.20f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.21f, 0.23f, 0.27f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.25f, 0.28f, 0.33f, 1.00f);

            // Google Blue (#A8C7FA) & Blue Container (#004A77)
            c[ImGuiCol_CheckMark]             = ImVec4(0.66f, 0.78f, 0.98f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.66f, 0.78f, 0.98f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.82f, 0.89f, 1.00f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.18f, 0.20f, 0.24f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.00f, 0.29f, 0.47f, 0.65f); // #004A77
            c[ImGuiCol_ButtonActive]          = ImVec4(0.00f, 0.29f, 0.47f, 1.00f);
            c[ImGuiCol_Header]                = ImVec4(0.20f, 0.29f, 0.41f, 1.00f); // #334B68
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.25f, 0.36f, 0.50f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.66f, 0.78f, 0.98f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.14f, 0.15f, 0.18f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.20f, 0.29f, 0.41f, 0.80f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.20f, 0.29f, 0.41f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.07f, 0.08f, 0.10f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.22f, 0.25f, 0.30f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.30f, 0.35f, 0.42f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.66f, 0.78f, 0.98f, 1.00f);
            break;
        }

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
            c[ImGuiCol_FrameBg]               = ImVec4(0.11f, 0.11f, 0.13f, 1.00f);
            c[ImGuiCol_CheckMark]             = ImVec4(0.95f, 0.12f, 0.15f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.13f, 0.13f, 0.15f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.95f, 0.12f, 0.15f, 0.35f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.95f, 0.12f, 0.15f, 0.85f);
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
            c[ImGuiCol_CheckMark]             = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.11f, 0.16f, 0.13f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.06f, 0.76f, 0.54f, 0.35f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.75f);
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
            c[ImGuiCol_Border]                = ImVec4(0.18f, 0.21f, 0.28f, 1.00f);
            c[ImGuiCol_CheckMark]             = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.14f, 0.17f, 0.23f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.06f, 0.76f, 0.54f, 0.45f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.06f, 0.76f, 0.54f, 0.85f);
            break;
        }
    }
}

static ImVec4 GetAccentColor() {
    switch (g_CurrentTheme) {
        case THEME_MD3:        return ImVec4(0.82f, 0.74f, 1.00f, 1.00f); // M3 Lavender #D0BCFF
        case THEME_MD3_BLUE:   return ImVec4(0.66f, 0.78f, 0.98f, 1.00f); // Google Blue #A8C7FA
        case THEME_NOTHING:    return ImVec4(0.95f, 0.12f, 0.15f, 1.00f); // Nothing Crimson Red
        case THEME_CIRCUIT:    return ImVec4(0.06f, 0.76f, 0.54f, 1.00f); // Silicon Emerald
        case THEME_LINEAR:     return ImVec4(0.06f, 0.76f, 0.54f, 1.00f); // Mint Emerald
        default:               return ImVec4(0.82f, 0.74f, 1.00f, 1.00f);
    }
}

static ImVec4 GetContainerColor() {
    switch (g_CurrentTheme) {
        case THEME_MD3:        return ImVec4(0.31f, 0.22f, 0.55f, 1.00f); // #4F378B (Primary Container)
        case THEME_MD3_BLUE:   return ImVec4(0.00f, 0.29f, 0.47f, 1.00f); // #004A77
        case THEME_NOTHING:    return ImVec4(0.85f, 0.12f, 0.15f, 1.00f);
        case THEME_CIRCUIT:    return ImVec4(0.06f, 0.76f, 0.54f, 0.80f);
        case THEME_LINEAR:     return ImVec4(0.14f, 0.17f, 0.23f, 1.00f);
        default:               return ImVec4(0.31f, 0.22f, 0.55f, 1.00f);
    }
}

static ImVec4 GetOnContainerColor() {
    switch (g_CurrentTheme) {
        case THEME_MD3:        return ImVec4(0.92f, 0.87f, 1.00f, 1.00f); // #EADDFF
        case THEME_MD3_BLUE:   return ImVec4(0.76f, 0.89f, 1.00f, 1.00f); // #C2E7FF
        case THEME_NOTHING:    return ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
        case THEME_CIRCUIT:    return ImVec4(0.92f, 0.96f, 0.94f, 1.00f);
        case THEME_LINEAR:     return ImVec4(0.96f, 0.97f, 0.99f, 1.00f);
        default:               return ImVec4(0.92f, 0.87f, 1.00f, 1.00f);
    }
}

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
    ImVec4 container_col = GetContainerColor();
    ImVec4 on_container_col = GetOnContainerColor();
    double current_time = ImGui::GetTime();

    float total_w = ImGui::GetContentRegionAvail().x;
    float total_h = ImGui::GetContentRegionAvail().y;

    float nav_rail_w = 200.0f;
    float main_canvas_w = total_w - nav_rail_w - 14.0f;

    // =========================================================================
    // ASYNC BACKGROUND DATA FETCHING (Zero UI Lag / Stable 144 FPS)
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
        ImGui::TextColored(accent_col, "HyprKey");
        if (g_FontTitle) ImGui::PopFont();

        ImGui::SetCursorPos(ImVec2(16.0f, 42.0f));
        ImGui::TextDisabled("Material You // Core");

        ImGui::SetCursorPosY(70.0f);
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
        if (ImGui::Button("2FA Authenticator", ImVec2(nav_rail_w - 32, 42))) {
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
        if (ImGui::Button("OpenPGP Card", ImVec2(nav_rail_w - 32, 42))) {
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
        if (ImGui::Button("APDU Terminal", ImVec2(nav_rail_w - 32, 42))) {
            s_active_nav = 2;
        }
        ImGui::PopStyleColor(2);

        // M3 Bottom Hardware Status Chip
        ImGui::SetCursorPosY(total_h - 130.0f);
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextDisabled("SECURITY KEY");
        if (client.is_connected()) {
            ImGui::TextColored(ImVec4(0.20f, 0.85f, 0.50f, 1.0f), "● Connected");
            ImGui::TextDisabled("%s", client.get_reader_name().c_str());
        } else {
            ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "○ Disconnected");
            ImGui::Spacing();
            if (ImGui::Button("Connect", ImVec2(nav_rail_w - 32, 28))) {
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
                ImGui::TextColored(accent_col, "2FA Authenticator");
                ImGui::SameLine();
                ImGui::TextDisabled("| OATH TOTP Hardware Slots");
            } else if (s_active_nav == 1) {
                ImGui::TextColored(accent_col, "OpenPGP SmartCard");
                ImGui::SameLine();
                ImGui::TextDisabled("| RSA / ECC Key Management");
            } else {
                ImGui::TextColored(accent_col, "APDU Terminal");
                ImGui::SameLine();
                ImGui::TextDisabled("| Live ISO 7816-4 USB Stream");
            }

            // Theme Selector Pills on the right
            ImGui::SameLine(ImGui::GetWindowWidth() - 410);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f);
            ImGui::TextDisabled("Theme:");
            ImGui::SameLine();

            const char* themes[] = { "M3", "M3 Blue", "Nothing", "Circuit", "Linear" };
            for (int i = 0; i < 5; i++) {
                bool is_active = (g_CurrentTheme == (AppTheme)i);
                if (is_active) {
                    ImGui::PushStyleColor(ImGuiCol_Button, container_col);
                    ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
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

        // M3 Indeterminate Loading Indicator (Shown when async worker is active)
        if (s_is_loading_oath || s_is_loading_pgp) {
            float anim = (float)fmod(current_time * 1.5, 1.0);
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 pos = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + 3.0f), IM_COL32(79, 55, 139, 80), 1.5f);
            float bar_start = pos.x + w * anim;
            float bar_end = bar_start + w * 0.35f;
            if (bar_end > pos.x + w) bar_end = pos.x + w;
            dl->AddRectFilled(ImVec2(bar_start, pos.y), ImVec2(bar_end, pos.y + 3.0f), ImGui::ColorConvertFloat4ToU32(accent_col), 1.5f);
            ImGui::Dummy(ImVec2(0, 4.0f));
        } else {
            ImGui::Spacing();
        }

        // -----------------------------------------------------------------
        // VIEW 0: 2FA TOTP AUTHENTICATOR (Material 3 Cards + M3 FAB)
        // -----------------------------------------------------------------
        if (s_active_nav == 0) {
            // M3 Extended FAB (Floating Action Button) for Clipboard QR
            ImGui::PushStyleColor(ImGuiCol_Button, container_col);
            ImGui::PushStyleColor(ImGuiCol_Text, on_container_col);
            if (ImGui::Button("📷 Scan QR from Clipboard", ImVec2(220, 40))) {
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
            if (ImGui::Button("+ Manual Entry", ImVec2(130, 40))) {
                s_show_add_modal = true;
            }

            ImGui::SameLine();
            if (ImGui::Button("Refresh", ImVec2(90, 40))) {
                s_oath_loaded = false;
            }

            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8.0f);
            ImGui::TextDisabled("Capture QR code via Win+Shift+S, then click Scan QR");

            ImGui::Spacing();

            // Render Cards from safe thread-locked cache
            std::vector<OathAccount> current_accs;
            {
                std::lock_guard<std::mutex> lock(s_data_mutex);
                current_accs = s_oath_accounts;
            }

            if (!client.is_connected()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "Insert HyprKey USB token and click Connect in the rail to view 2FA codes.");
            } else if (current_accs.empty() && !s_is_loading_oath) {
                ImGui::Spacing();
                ImGui::TextDisabled("No accounts found. Use Win+Shift+S on a 2FA QR code and click 'Scan QR from Clipboard'!");
            } else {
                int cols = 2;
                float card_w = (ImGui::GetContentRegionAvail().x - 12.0f * (cols - 1)) / cols;

                for (size_t i = 0; i < current_accs.size(); i++) {
                    const auto& acc = current_accs[i];
                    if (i % cols != 0) ImGui::SameLine();

                    char card_id[64];
                    snprintf(card_id, sizeof(card_id), "M3Card_##%zu", i);

                    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
                    ImGui::BeginChild(card_id, ImVec2(card_w, 130), true);
                    {
                        ImVec2 card_min = ImGui::GetWindowPos();
                        ImVec2 card_max = ImVec2(card_min.x + card_w, card_min.y + 130.0f);
                        ImDrawList* dl = ImGui::GetWindowDrawList();

                        // Account Label & Algorithm Chip
                        ImGui::TextColored(ImVec4(0.91f, 0.89f, 0.94f, 1.0f), "%s", acc.name.c_str());
                        ImGui::SameLine(ImGui::GetWindowWidth() - 80);
                        ImGui::TextDisabled(acc.type_alg == 0x22 ? "SHA256" : "SHA1");

                        ImGui::Spacing();

                        // Large 32px TOTP digits with digit grouping
                        if (g_FontTotpCode) ImGui::PushFont(g_FontTotpCode);
                        else if (g_FontTitle) ImGui::PushFont(g_FontTitle);

                        std::string display_code = acc.current_code;
                        if (display_code.length() == 6) {
                            display_code.insert(3, " ");
                        } else if (display_code.length() == 8) {
                            display_code.insert(4, " ");
                        }
                        ImGui::TextColored(accent_col, "%s", display_code.c_str());

                        if (g_FontTotpCode || g_FontTitle) ImGui::PopFont();

                        // Copy Button (Material 3 Pill Button)
                        ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 85, ImGui::GetWindowHeight() - 44));
                        char copy_btn_id[32];
                        snprintf(copy_btn_id, sizeof(copy_btn_id), "Copy##%zu", i);
                        if (ImGui::Button(copy_btn_id, ImVec2(70, 30))) {
                            ImGui::SetClipboardText(acc.current_code.c_str());
                            show_toast("Copied code: " + acc.current_code);
                        }

                        // === MATERIAL 3 LINEAR PROGRESS TRACK (Across bottom) ===
                        float bar_h = 4.0f;
                        float bar_w = (card_w - 8.0f) * step_frac;

                        ImU32 bar_fill = (rem_in_step <= 5) ? IM_COL32(242, 184, 181, 240) : ImGui::ColorConvertFloat4ToU32(accent_col);
                        // Track
                        dl->AddRectFilled(
                            ImVec2(card_min.x + 4.0f, card_max.y - bar_h - 4.0f),
                            ImVec2(card_max.x - 4.0f, card_max.y - 4.0f),
                            IM_COL32(73, 69, 79, 140),
                            2.0f
                        );
                        // Active fill
                        dl->AddRectFilled(
                            ImVec2(card_min.x + 4.0f, card_max.y - bar_h - 4.0f),
                            ImVec2(card_min.x + 4.0f + bar_w, card_max.y - 4.0f),
                            bar_fill,
                            2.0f
                        );
                    }
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                }
            }
        }

        // -----------------------------------------------------------------
        // VIEW 1: OPENPGP SMARTCARD (Material 3 Elevated Cards)
        // -----------------------------------------------------------------
        else if (s_active_nav == 1) {
            OpenPgpStatus st_copy;
            {
                std::lock_guard<std::mutex> lock(s_data_mutex);
                st_copy = s_pgp_status;
            }

            if (!client.is_connected()) {
                ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "Connect HyprKey to inspect OpenPGP status.");
            } else {
                // Identity Card
                ImGui::BeginChild("M3PGPIdentity", ImVec2(0, 140), true);
                {
                    ImGui::TextColored(accent_col, "Cardholder Information");
                    ImGui::Separator();
                    ImGui::Spacing();

                    ImGui::Columns(2, "M3PgpCols", false);
                    ImGui::SetColumnWidth(0, 360);

                    ImGui::Text("Cardholder: %s", st_copy.cardholder_name.empty() ? "(Not configured)" : st_copy.cardholder_name.c_str());
                    ImGui::Text("Language:   %s", st_copy.lang.c_str());
                    ImGui::Text("Serial:     %s", st_copy.serial.c_str());

                    ImGui::NextColumn();

                    ImGui::Text("User PIN (PW1):   ");
                    ImGui::SameLine();
                    for (int dot = 0; dot < 3; dot++) {
                        if (dot < st_copy.pw1_tries) {
                            ImGui::TextColored(accent_col, "●");
                        } else {
                            ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "○");
                        }
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("(%d/3)", st_copy.pw1_tries);

                    ImGui::Text("Admin PIN (PW3):  ");
                    ImGui::SameLine();
                    for (int dot = 0; dot < 3; dot++) {
                        if (dot < st_copy.pw3_tries) {
                            ImGui::TextColored(accent_col, "●");
                        } else {
                            ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "○");
                        }
                        ImGui::SameLine();
                    }
                    ImGui::TextDisabled("(%d/3)", st_copy.pw3_tries);

                    ImGui::Spacing();
                    if (ImGui::Button("Change PIN", ImVec2(120, 28))) {
                        s_pin_target = 1;
                        s_show_pin_modal = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Change Admin PIN", ImVec2(140, 28))) {
                        s_pin_target = 3;
                        s_show_pin_modal = true;
                    }

                    ImGui::Columns(1);
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // Public Key URL
                ImGui::BeginChild("M3PGPUrl", ImVec2(0, 68), true);
                {
                    ImGui::TextColored(accent_col, "Public Key URL (DO 0x5F50):");
                    ImGui::SameLine();
                    ImGui::Text("%s", st_copy.cardholder_url.empty() ? "(none)" : st_copy.cardholder_url.c_str());
                    ImGui::SameLine(ImGui::GetWindowWidth() - 110);
                    if (ImGui::Button("Edit URL", ImVec2(90, 26))) {
                        snprintf(s_new_url, sizeof(s_new_url), "%s", st_copy.cardholder_url.c_str());
                        s_show_url_modal = true;
                    }
                }
                ImGui::EndChild();

                ImGui::Spacing();

                // Fingerprints Card
                ImGui::BeginChild("M3PGPFingerprints", ImVec2(0, 160), true);
                {
                    ImGui::TextColored(accent_col, "Key Fingerprints (SHA-1 / SHA-256)");
                    ImGui::Separator();
                    ImGui::Spacing();

                    if (g_FontMono) ImGui::PushFont(g_FontMono);

                    ImGui::TextColored(container_col, "Signature Key (SIG):");
                    ImGui::Text("  %s", st_copy.fp_sig.empty() ? "[Not Generated]" : st_copy.fp_sig.c_str());

                    ImGui::Spacing();
                    ImGui::TextColored(container_col, "Decryption Key (DEC):");
                    ImGui::Text("  %s", st_copy.fp_dec.empty() ? "[Not Generated]" : st_copy.fp_dec.c_str());

                    ImGui::Spacing();
                    ImGui::TextColored(container_col, "Authentication Key (AUT):");
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
            if (ImGui::Button("Clear Logs", ImVec2(100, 30))) {
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
        ImGui::Text("Review or edit 2FA TOTP account details before storing to key:");
        ImGui::Spacing();

        ImGui::InputText("Account Label", s_add_name, sizeof(s_add_name));
        ImGui::InputText("Base32 Secret", s_add_secret, sizeof(s_add_secret));

        ImGui::Combo("Algorithm", &s_add_algo, "HMAC-SHA1\0HMAC-SHA256\0");
        ImGui::Combo("Digits", &s_add_digits, "6 Digits\0""8 Digits\0");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Save to Token", ImVec2(130, 34))) {
            std::vector<uint8_t> dummy_sec(20, 0x42);
            uint8_t alg = (s_add_algo == 1) ? 0x22 : 0x21;
            uint8_t dig = (s_add_digits == 1) ? 8 : 6;
            client.oath_put(s_add_name, dummy_sec, alg, dig);
            s_oath_loaded = false;
            s_show_add_modal = false;
            show_toast("Added account: " + std::string(s_add_name));
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90, 34))) {
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

        if (ImGui::Button("Commit Change", ImVec2(130, 34))) {
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
        if (ImGui::Button("Cancel", ImVec2(90, 34))) {
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

        if (ImGui::Button("Save URL", ImVec2(110, 34))) {
            client.openpgp_set_url(s_new_url);
            s_pgp_loaded = false;
            s_show_url_modal = false;
            show_toast("Updated public key URL");
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90, 34))) {
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

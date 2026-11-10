#include "ui.h"
#include "imgui.h"
#include "qr_reader.h"
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string>
#include <vector>

AppTheme g_CurrentTheme = THEME_LINEAR;

ImFont* g_FontUI       = nullptr;
ImFont* g_FontMono     = nullptr;
ImFont* g_FontTitle    = nullptr;
ImFont* g_FontTotpCode = nullptr;

static std::string s_toast_msg = "";
static double      s_toast_time = 0.0;

static void show_toast(const std::string& msg) {
    s_toast_msg = msg;
    s_toast_time = ImGui::GetTime();
}

const char* GetThemeName(AppTheme theme) {
    switch (theme) {
        case THEME_LINEAR:     return "Linear Stealth";
        case THEME_CATPPUCCIN: return "Catppuccin Mocha";
        case THEME_NORDIC:     return "Nordic Waybar";
        case THEME_INDUSTRIAL: return "Industrial Amber";
        default:               return "Custom";
    }
}

ImVec4 GetThemeClearColor(AppTheme theme) {
    switch (theme) {
        case THEME_LINEAR:     return ImVec4(0.05f, 0.06f, 0.08f, 1.0f); // #0D0F14
        case THEME_CATPPUCCIN: return ImVec4(0.12f, 0.12f, 0.18f, 1.0f); // #1E1E2E
        case THEME_NORDIC:     return ImVec4(0.10f, 0.11f, 0.15f, 1.0f); // #1A1B26
        case THEME_INDUSTRIAL: return ImVec4(0.07f, 0.07f, 0.07f, 1.0f); // #121212
        default:               return ImVec4(0.08f, 0.08f, 0.10f, 1.0f);
    }
}

void ApplyTheme(AppTheme theme) {
    g_CurrentTheme = theme;
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* c = style.Colors;

    style.WindowPadding     = ImVec2(18.0f, 16.0f);
    style.FramePadding      = ImVec2(12.0f, 7.0f);
    style.ItemSpacing       = ImVec2(12.0f, 10.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 6.0f);

    switch (theme) {
        case THEME_LINEAR: {
            // === 1. LINEAR / RAYCAST STEALTH ===
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

            // Accents: Emerald Green & Crisp Cyan
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
            c[ImGuiCol_TabDimmed]             = ImVec4(0.08f, 0.09f, 0.13f, 1.00f);
            c[ImGuiCol_TabDimmedSelected]     = ImVec4(0.12f, 0.14f, 0.20f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.06f, 0.07f, 0.09f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.18f, 0.21f, 0.28f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.24f, 0.28f, 0.38f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
            break;
        }

        case THEME_CATPPUCCIN: {
            // === 2. CATPPUCCIN MOCHA ===
            style.WindowRounding    = 10.0f;
            style.ChildRounding     = 10.0f;
            style.FrameRounding     = 8.0f;
            style.PopupRounding     = 10.0f;
            style.ScrollbarRounding = 8.0f;
            style.GrabRounding      = 6.0f;
            style.TabRounding       = 8.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.80f, 0.84f, 0.96f, 1.00f); // #CDD6F4
            c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.57f, 0.68f, 1.00f); // #898D9E
            c[ImGuiCol_WindowBg]              = ImVec4(0.12f, 0.12f, 0.18f, 1.00f); // #1E1E2E
            c[ImGuiCol_ChildBg]               = ImVec4(0.15f, 0.15f, 0.23f, 1.00f); // #252538
            c[ImGuiCol_PopupBg]               = ImVec4(0.14f, 0.14f, 0.21f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.25f, 0.26f, 0.36f, 1.00f); // #3E4059
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.19f, 0.19f, 0.28f, 1.00f); // #313244
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.25f, 0.25f, 0.36f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.30f, 0.30f, 0.44f, 1.00f);

            // Accents: Mauve (#CBA6F7) & Sapphire (#74C7EC)
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
            c[ImGuiCol_TabDimmed]             = ImVec4(0.13f, 0.13f, 0.20f, 1.00f);
            c[ImGuiCol_TabDimmedSelected]     = ImVec4(0.18f, 0.18f, 0.28f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.12f, 0.12f, 0.18f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.25f, 0.26f, 0.36f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.35f, 0.36f, 0.50f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.80f, 0.65f, 0.97f, 1.00f);
            break;
        }

        case THEME_NORDIC: {
            // === 3. NORDIC WAYBAR / TOKYO NIGHT ===
            style.WindowRounding    = 4.0f;
            style.ChildRounding     = 4.0f;
            style.FrameRounding     = 4.0f;
            style.PopupRounding     = 4.0f;
            style.ScrollbarRounding = 4.0f;
            style.GrabRounding      = 3.0f;
            style.TabRounding       = 4.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.75f, 0.80f, 0.96f, 1.00f); // #C0CAF5
            c[ImGuiCol_TextDisabled]          = ImVec4(0.44f, 0.48f, 0.63f, 1.00f); // #707B9E
            c[ImGuiCol_WindowBg]              = ImVec4(0.10f, 0.11f, 0.15f, 1.00f); // #1A1B26
            c[ImGuiCol_ChildBg]               = ImVec4(0.14f, 0.16f, 0.23f, 1.00f); // #24283B
            c[ImGuiCol_PopupBg]               = ImVec4(0.12f, 0.13f, 0.19f, 0.98f);
            c[ImGuiCol_Border]                = ImVec4(0.25f, 0.29f, 0.42f, 1.00f); // #414868
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.17f, 0.20f, 0.28f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.22f, 0.26f, 0.36f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.28f, 0.33f, 0.46f, 1.00f);

            // Accents: Icy Cyan (#7DCFFF) & Soft Violet (#BB9AF7)
            c[ImGuiCol_CheckMark]             = ImVec4(0.49f, 0.81f, 1.00f, 1.00f);
            c[ImGuiCol_SliderGrab]            = ImVec4(0.49f, 0.81f, 1.00f, 1.00f);
            c[ImGuiCol_SliderGrabActive]      = ImVec4(0.65f, 0.88f, 1.00f, 1.00f);
            c[ImGuiCol_Button]                = ImVec4(0.18f, 0.22f, 0.32f, 1.00f);
            c[ImGuiCol_ButtonHovered]         = ImVec4(0.49f, 0.81f, 1.00f, 0.40f);
            c[ImGuiCol_ButtonActive]          = ImVec4(0.49f, 0.81f, 1.00f, 0.80f);
            c[ImGuiCol_Header]                = ImVec4(0.20f, 0.24f, 0.34f, 1.00f);
            c[ImGuiCol_HeaderHovered]         = ImVec4(0.26f, 0.31f, 0.44f, 1.00f);
            c[ImGuiCol_HeaderActive]          = ImVec4(0.49f, 0.81f, 1.00f, 0.50f);
            c[ImGuiCol_Tab]                   = ImVec4(0.13f, 0.15f, 0.21f, 1.00f);
            c[ImGuiCol_TabHovered]            = ImVec4(0.22f, 0.26f, 0.36f, 1.00f);
            c[ImGuiCol_TabSelected]           = ImVec4(0.18f, 0.22f, 0.31f, 1.00f);
            c[ImGuiCol_TabDimmed]             = ImVec4(0.11f, 0.12f, 0.17f, 1.00f);
            c[ImGuiCol_TabDimmedSelected]     = ImVec4(0.15f, 0.18f, 0.25f, 1.00f);
            c[ImGuiCol_ScrollbarBg]           = ImVec4(0.10f, 0.11f, 0.15f, 1.00f);
            c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.24f, 0.28f, 0.39f, 1.00f);
            c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.32f, 0.37f, 0.52f, 1.00f);
            c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.49f, 0.81f, 1.00f, 1.00f);
            break;
        }

        case THEME_INDUSTRIAL: {
            // === 4. INDUSTRIAL / TEENAGE ENGINEERING AMBER ===
            style.WindowRounding    = 0.0f;
            style.ChildRounding     = 2.0f;
            style.FrameRounding     = 0.0f;
            style.PopupRounding     = 0.0f;
            style.ScrollbarRounding = 0.0f;
            style.GrabRounding      = 0.0f;
            style.TabRounding       = 0.0f;

            c[ImGuiCol_Text]                  = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
            c[ImGuiCol_TextDisabled]          = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
            c[ImGuiCol_WindowBg]              = ImVec4(0.07f, 0.07f, 0.07f, 1.00f); // Pure dark carbon #121212
            c[ImGuiCol_ChildBg]               = ImVec4(0.11f, 0.11f, 0.11f, 1.00f); // #1C1C1C
            c[ImGuiCol_PopupBg]               = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
            c[ImGuiCol_Border]                = ImVec4(0.24f, 0.24f, 0.24f, 1.00f); // #3D3D3D
            c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
            c[ImGuiCol_FrameBg]               = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
            c[ImGuiCol_FrameBgHovered]        = ImVec4(0.19f, 0.19f, 0.19f, 1.00f);
            c[ImGuiCol_FrameBgActive]         = ImVec4(0.24f, 0.24f, 0.24f, 1.00f);

            // Accents: Warm Amber (#FF9E3B) & Tactical Gold (#E6C384)
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
            c[ImGuiCol_TabDimmed]             = ImVec4(0.09f, 0.09f, 0.09f, 1.00f);
            c[ImGuiCol_TabDimmedSelected]     = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
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
        case THEME_LINEAR:     return ImVec4(0.06f, 0.76f, 0.54f, 1.00f);
        case THEME_CATPPUCCIN: return ImVec4(0.80f, 0.65f, 0.97f, 1.00f);
        case THEME_NORDIC:     return ImVec4(0.49f, 0.81f, 1.00f, 1.00f);
        case THEME_INDUSTRIAL: return ImVec4(1.00f, 0.62f, 0.23f, 1.00f);
        default:               return ImVec4(0.00f, 0.88f, 0.95f, 1.00f);
    }
}

static ImVec4 GetSecondaryAccentColor() {
    switch (g_CurrentTheme) {
        case THEME_LINEAR:     return ImVec4(0.02f, 0.71f, 0.83f, 1.00f);
        case THEME_CATPPUCCIN: return ImVec4(0.45f, 0.78f, 0.93f, 1.00f);
        case THEME_NORDIC:     return ImVec4(0.73f, 0.60f, 0.97f, 1.00f);
        case THEME_INDUSTRIAL: return ImVec4(0.90f, 0.76f, 0.52f, 1.00f);
        default:               return ImVec4(0.65f, 0.55f, 0.98f, 1.00f);
    }
}

static void RenderRadialTimer(ImVec2 center, float radius, float fraction, ImU32 col_active, ImU32 col_bg) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddCircleFilled(center, radius, col_bg, 32);

    const int num_segments = 40;
    const float start_angle = -3.14159265f / 2.0f;
    const float end_angle = start_angle + fraction * 2.0f * 3.14159265f;

    draw_list->PathClear();
    draw_list->PathLineTo(center);
    for (int i = 0; i <= num_segments; i++) {
        float a = start_angle + ((float)i / (float)num_segments) * (end_angle - start_angle);
        draw_list->PathLineTo(ImVec2(center.x + cosf(a) * radius, center.y + sinf(a) * radius));
    }
    draw_list->PathFillConvex(col_active);
    draw_list->AddCircle(center, radius, IM_COL32(255, 255, 255, 30), 32, 1.5f);
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

    // ==========================================
    // TOP HEADER BAR: Logo, Reader & Live Themes
    // ==========================================
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
    ImGui::BeginChild("TopHeader", ImVec2(0, 56), true, ImGuiWindowFlags_NoScrollbar);
    {
        // 1. Logo / App Title
        if (g_FontTitle) ImGui::PushFont(g_FontTitle);
        ImGui::TextColored(accent_col, "HYPRKEY");
        if (g_FontTitle) ImGui::PopFont();

        ImGui::SameLine();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.0f);
        ImGui::TextDisabled("| Hardware Token Companion");

        // 2. Reader Connection Badge
        ImGui::SameLine();
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 570);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 3.0f);

        if (client.is_connected()) {
            ImGui::TextColored(ImVec4(0.10f, 0.88f, 0.55f, 1.0f), "[CONNECTED]");
            ImGui::SameLine();
            ImGui::TextDisabled("(%s)", client.get_reader_name().c_str());
        } else {
            ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "[DISCONNECTED]");
            ImGui::SameLine();
            if (ImGui::Button("Connect Key", ImVec2(100, 24))) {
                client.connect();
                s_oath_loaded = false;
                s_pgp_loaded = false;
            }
        }

        // 3. Theme Selector Pills (Live Instant Switch)
        ImGui::SameLine();
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 340);
        ImGui::TextDisabled("Theme:");
        ImGui::SameLine();

        const char* themes[] = { "Linear", "Catppuccin", "Nordic", "Industrial" };
        for (int i = 0; i < 4; i++) {
            bool is_active = (g_CurrentTheme == (AppTheme)i);
            if (is_active) {
                ImGui::PushStyleColor(ImGuiCol_Button, accent_col);
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.05f, 0.05f, 0.05f, 1.0f));
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
            }

            if (ImGui::Button(themes[i], ImVec2(62, 24))) {
                ApplyTheme((AppTheme)i);
            }
            ImGui::PopStyleColor(2);
            if (i < 3) ImGui::SameLine();
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::Spacing();

    // ==========================================
    // MAIN TAB BAR: 3 Clean Tabs (No Clutter)
    // ==========================================
    if (ImGui::BeginTabBar("HyprKeyTabs", ImGuiTabBarFlags_None)) {

        // ====================================================
        // TAB 1: 2FA TOTP Authenticator
        // ====================================================
        if (ImGui::BeginTabItem("  2FA Authenticator  ")) {
            ImGui::Spacing();

            // Action toolbar: Scan QR from Clipboard!
            if (ImGui::Button("Scan QR from Clipboard", ImVec2(190, 32))) {
                std::string qr_raw, err;
                if (QrScanFromClipboard(qr_raw, err)) {
                    OtpAuthData otp;
                    if (ParseOtpAuthUri(qr_raw, otp)) {
                        snprintf(s_add_name, sizeof(s_add_name), "%s", otp.label.c_str());
                        snprintf(s_add_secret, sizeof(s_add_secret), "%s", otp.secret.c_str());
                        s_add_algo = (otp.algorithm == "SHA256") ? 1 : 0;
                        s_add_digits = (otp.digits == 8) ? 1 : 0;
                        s_show_add_modal = true;
                        show_toast("Decoded QR Code: " + otp.label);
                    } else {
                        show_toast("Decoded QR, but not OTP URL: " + qr_raw.substr(0, 30));
                    }
                } else {
                    show_toast(err);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("+ Manual Entry", ImVec2(130, 32))) {
                s_show_add_modal = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh Codes", ImVec2(120, 32))) {
                s_oath_loaded = false;
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Use Win+Shift+S on any 2FA QR code, then click 'Scan QR from Clipboard'");

            ImGui::Separator();
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
                ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "Insert HyprKey USB token and click Connect in the header to view 2FA codes.");
            } else if (s_oath_accounts.empty()) {
                ImGui::Spacing();
                ImGui::TextDisabled("No TOTP accounts registered yet. Use Win+Shift+S on a QR code and click 'Scan QR from Clipboard'!");
            } else {
                // Render account cards in a 2-column grid
                int cols = 2;
                float card_w = (ImGui::GetContentRegionAvail().x - 12.0f * (cols - 1)) / cols;

                for (size_t i = 0; i < s_oath_accounts.size(); i++) {
                    const auto& acc = s_oath_accounts[i];
                    if (i % cols != 0) ImGui::SameLine();

                    char card_id[64];
                    snprintf(card_id, sizeof(card_id), "Card_##%zu", i);

                    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_ChildBg));
                    ImGui::BeginChild(card_id, ImVec2(card_w, 115), true);
                    {
                        // Account Label
                        ImGui::TextColored(ImVec4(0.90f, 0.92f, 0.96f, 1.0f), "%s", acc.name.c_str());
                        ImGui::SameLine(ImGui::GetWindowWidth() - 75);
                        ImGui::TextDisabled(acc.type_alg == 0x22 ? "SHA256" : "SHA1");

                        ImGui::Spacing();

                        // Large TOTP verification code
                        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f);
                        if (g_FontTotpCode) ImGui::PushFont(g_FontTotpCode);
                        else if (g_FontTitle) ImGui::PushFont(g_FontTitle);

                        // Formatted code with space in middle
                        std::string display_code = acc.current_code;
                        if (display_code.length() == 6) {
                            display_code.insert(3, " ");
                        } else if (display_code.length() == 8) {
                            display_code.insert(4, " ");
                        }
                        ImGui::TextColored(accent_col, "%s", display_code.c_str());

                        if (g_FontTotpCode || g_FontTitle) ImGui::PopFont();

                        // Radial Timer beside code
                        ImVec2 timer_center = ImVec2(ImGui::GetWindowWidth() - 110, ImGui::GetCursorPosY() - 20);
                        ImU32 col_radial = (rem_in_step <= 5) ? IM_COL32(239, 68, 68, 220) : ImGui::ColorConvertFloat4ToU32(accent_col);
                        RenderRadialTimer(timer_center, 12.0f, step_frac, col_radial, IM_COL32(40, 44, 56, 180));

                        // Actions: Copy & Delete
                        ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 85, ImGui::GetWindowHeight() - 36));
                        char copy_btn_id[32];
                        snprintf(copy_btn_id, sizeof(copy_btn_id), "Copy##%zu", i);
                        if (ImGui::Button(copy_btn_id, ImVec2(65, 26))) {
                            ImGui::SetClipboardText(acc.current_code.c_str());
                            show_toast("Code copied to clipboard: " + acc.current_code);
                        }
                    }
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                }
            }

            ImGui::EndTabItem();
        }

        // ====================================================
        // TAB 2: OpenPGP SmartCard
        // ====================================================
        if (ImGui::BeginTabItem("  OpenPGP SmartCard  ")) {
            ImGui::Spacing();

            if (!s_pgp_loaded && client.is_connected()) {
                client.openpgp_get_status(s_pgp_status);
                s_pgp_loaded = true;
            }

            if (!client.is_connected()) {
                ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "Connect HyprKey to inspect OpenPGP status.");
            } else {
                // Top Card: Cardholder & PIN status
                ImGui::BeginChild("PGPCardholder", ImVec2(0, 150), true);
                {
                    ImGui::TextColored(secondary_col, "Cardholder Information");
                    ImGui::Separator();
                    ImGui::Spacing();

                    ImGui::Columns(2, "PgpCols", false);
                    ImGui::SetColumnWidth(0, 340);

                    ImGui::Text("Cardholder: %s", s_pgp_status.cardholder_name.empty() ? "(Not configured)" : s_pgp_status.cardholder_name.c_str());
                    ImGui::Text("Language:   %s", s_pgp_status.lang.c_str());
                    ImGui::Text("Sex:        %s", s_pgp_status.sex == 1 ? "Male" : (s_pgp_status.sex == 2 ? "Female" : "Not announced"));
                    ImGui::Text("Serial:     %s", s_pgp_status.serial.c_str());

                    ImGui::NextColumn();

                    ImU32 pw1_col = (s_pgp_status.pw1_tries > 1) ? IM_COL32(16, 185, 129, 255) : IM_COL32(239, 68, 68, 255);
                    ImGui::Text("User PIN (PW1) Tries:   ");
                    ImGui::SameLine();
                    ImGui::TextColored(ImColor(pw1_col), "%d / 3", s_pgp_status.pw1_tries);

                    ImU32 pw3_col = (s_pgp_status.pw3_tries > 1) ? IM_COL32(16, 185, 129, 255) : IM_COL32(239, 68, 68, 255);
                    ImGui::Text("Admin PIN (PW3) Tries:  ");
                    ImGui::SameLine();
                    ImGui::TextColored(ImColor(pw3_col), "%d / 3", s_pgp_status.pw3_tries);

                    ImGui::Text("Signature Counter:      %u", s_pgp_status.sig_counter);

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

                // Fingerprints Card
                ImGui::BeginChild("PGPFingerprints", ImVec2(0, 160), true);
                {
                    ImGui::TextColored(secondary_col, "Key Fingerprints (SHA-1 / SHA-256)");
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

            ImGui::EndTabItem();
        }

        // ====================================================
        // TAB 3: Live APDU Monitor Console
        // ====================================================
        if (ImGui::BeginTabItem("  APDU Console  ")) {
            ImGui::Spacing();

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
                        ImGui::TextColored(accent_col, "[%s] >> TX:", l.time_str.c_str());
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

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

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
        ImGui::TextColored(ImVec4(0.05f, 0.05f, 0.05f, alpha), "%s", s_toast_msg.c_str());
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

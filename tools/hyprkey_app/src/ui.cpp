#include "ui.h"
#include "imgui.h"
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string>
#include <vector>

static std::string s_toast_msg = "";
static double      s_toast_time = 0.0;

static void show_toast(const std::string& msg) {
    s_toast_msg = msg;
    s_toast_time = ImGui::GetTime();
}

void ApplyHyprTheme() {
    ImGuiStyle& style = ImGui::GetStyle();

    style.WindowRounding    = 10.0f;
    style.ChildRounding     = 8.0f;
    style.FrameRounding     = 6.0f;
    style.PopupRounding     = 8.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding      = 6.0f;
    style.TabRounding       = 6.0f;

    style.WindowPadding     = ImVec2(16.0f, 16.0f);
    style.FramePadding      = ImVec2(10.0f, 6.0f);
    style.ItemSpacing       = ImVec2(10.0f, 10.0f);
    style.ItemInnerSpacing  = ImVec2(6.0f, 6.0f);

    ImVec4* colors = style.Colors;

    // Hyprland / Tokyo Night Palette
    colors[ImGuiCol_Text]                  = ImVec4(0.92f, 0.93f, 0.96f, 1.00f);
    colors[ImGuiCol_TextDisabled]          = ImVec4(0.48f, 0.52f, 0.64f, 1.00f);
    colors[ImGuiCol_WindowBg]              = ImVec4(0.09f, 0.10f, 0.13f, 1.00f);
    colors[ImGuiCol_ChildBg]               = ImVec4(0.12f, 0.14f, 0.18f, 1.00f);
    colors[ImGuiCol_PopupBg]               = ImVec4(0.11f, 0.12f, 0.16f, 0.98f);
    colors[ImGuiCol_Border]                = ImVec4(0.20f, 0.23f, 0.32f, 1.00f);
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);

    colors[ImGuiCol_FrameBg]               = ImVec4(0.15f, 0.17f, 0.22f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.20f, 0.23f, 0.30f, 1.00f);
    colors[ImGuiCol_FrameBgActive]         = ImVec4(0.24f, 0.28f, 0.36f, 1.00f);

    colors[ImGuiCol_TitleBg]               = ImVec4(0.09f, 0.10f, 0.13f, 1.00f);
    colors[ImGuiCol_TitleBgActive]         = ImVec4(0.12f, 0.14f, 0.18f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.09f, 0.10f, 0.13f, 1.00f);

    colors[ImGuiCol_MenuBarBg]             = ImVec4(0.12f, 0.14f, 0.18f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]           = ImVec4(0.09f, 0.10f, 0.13f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]         = ImVec4(0.22f, 0.26f, 0.34f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.28f, 0.32f, 0.42f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.00f, 0.88f, 0.95f, 1.00f);

    colors[ImGuiCol_CheckMark]             = ImVec4(0.00f, 0.88f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrab]            = ImVec4(0.00f, 0.88f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]      = ImVec4(0.20f, 0.95f, 1.00f, 1.00f);

    // Buttons: Electric Cyan / Violet
    colors[ImGuiCol_Button]                = ImVec4(0.16f, 0.20f, 0.28f, 1.00f);
    colors[ImGuiCol_ButtonHovered]         = ImVec4(0.00f, 0.72f, 0.85f, 0.80f);
    colors[ImGuiCol_ButtonActive]          = ImVec4(0.00f, 0.88f, 0.95f, 1.00f);

    // Headers & Tabs
    colors[ImGuiCol_Header]                = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);
    colors[ImGuiCol_HeaderHovered]         = ImVec4(0.24f, 0.28f, 0.38f, 1.00f);
    colors[ImGuiCol_HeaderActive]          = ImVec4(0.00f, 0.88f, 0.95f, 0.50f);

    colors[ImGuiCol_Tab]                   = ImVec4(0.12f, 0.14f, 0.18f, 1.00f);
    colors[ImGuiCol_TabHovered]            = ImVec4(0.00f, 0.88f, 0.95f, 0.60f);
    colors[ImGuiCol_TabSelected]           = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);
    colors[ImGuiCol_TabDimmed]             = ImVec4(0.09f, 0.10f, 0.13f, 1.00f);
    colors[ImGuiCol_TabDimmedSelected]     = ImVec4(0.14f, 0.16f, 0.22f, 1.00f);
}

static void draw_radial_timer(ImVec2 center, float radius, float progress, int seconds_left) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();

    // Background track
    draw_list->AddCircle(center, radius, IM_COL32(50, 60, 80, 200), 48, 4.0f);

    // Color based on urgency
    ImU32 arc_col;
    if (seconds_left > 10) {
        arc_col = IM_COL32(16, 185, 129, 255); // Green
    } else if (seconds_left > 5) {
        arc_col = IM_COL32(245, 158, 11, 255); // Amber
    } else {
        arc_col = IM_COL32(239, 68, 68, 255);   // Red
    }

    // Arc
    float start_angle = -1.5707963f; // Top (-PI/2)
    float end_angle = start_angle + progress * 6.2831853f;
    draw_list->PathArcTo(center, radius, start_angle, end_angle, 48);
    draw_list->PathStroke(arc_col, 0, 4.0f);

    // Number text
    char sec_buf[8];
    snprintf(sec_buf, sizeof(sec_buf), "%d", seconds_left);
    ImVec2 t_size = ImGui::CalcTextSize(sec_buf);
    draw_list->AddText(ImVec2(center.x - t_size.x * 0.5f, center.y - t_size.y * 0.5f), arc_col, sec_buf);
}

// Simple Base32 decode for OTP secrets
static std::vector<uint8_t> base32_decode(const std::string& input) {
    std::vector<uint8_t> out;
    int buffer = 0;
    int bits_left = 0;

    for (char c : input) {
        if (c == ' ' || c == '-' || c == '=') continue;
        int val = -1;
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;

        if (val < 0) continue;

        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            bits_left -= 8;
            out.push_back((uint8_t)((buffer >> bits_left) & 0xFF));
        }
    }
    return out;
}

void RenderHyprKeyUI(SCardClient& client) {
    // Top Bar: Device Status
    bool connected = client.is_connected();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.14f, 0.19f, 1.0f));
    ImGui::BeginChild("TopBar", ImVec2(0, 54), true, ImGuiWindowFlags_NoScrollbar);
    {
        ImGui::TextColored(ImVec4(0.00f, 0.88f, 0.95f, 1.0f), "HYPRKEY");
        ImGui::SameLine();
        ImGui::TextDisabled("| Post-Quantum Security Enclave");

        ImGui::SameLine(ImGui::GetWindowWidth() - 280);
        if (connected) {
            ImGui::TextColored(ImVec4(0.10f, 0.85f, 0.50f, 1.0f), "● CONNECTED");
            ImGui::SameLine();
            if (ImGui::Button("Disconnect")) {
                client.disconnect();
            }
        } else {
            ImGui::TextColored(ImVec4(0.90f, 0.30f, 0.30f, 1.0f), "○ DISCONNECTED");
            ImGui::SameLine();
            if (ImGui::Button("Connect")) {
                client.connect();
            }
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::Spacing();

    // Main Tab Bar
    if (ImGui::BeginTabBar("MainTabs", ImGuiTabBarFlags_None)) {

        // ==================== TAB 1: OATH Authenticator ====================
        if (ImGui::BeginTabItem("  2FA Authenticator  ")) {
            static std::vector<OathAccount> accounts;
            static double last_fetch_time = 0.0;
            double cur_time = ImGui::GetTime();

            time_t now = time(NULL);
            int seconds_left = 30 - (now % 30);
            float progress = (float)seconds_left / 30.0f;

            // Auto-refresh when seconds roll over or on first open
            if (connected && (cur_time - last_fetch_time > 1.0 || accounts.empty())) {
                client.oath_list_and_calc(accounts);
                last_fetch_time = cur_time;
            }

            // Top action row with Countdown Timer
            ImGui::BeginGroup();
            {
                if (ImGui::Button("+ Add Account", ImVec2(130, 36))) {
                    ImGui::OpenPopup("AddAccountModal");
                }
                ImGui::SameLine();
                if (ImGui::Button("Refresh Now", ImVec2(110, 36))) {
                    client.oath_list_and_calc(accounts);
                }

                // Draw radial timer on the far right
                ImGui::SameLine(ImGui::GetWindowWidth() - 60);
                ImVec2 timer_center = ImGui::GetCursorScreenPos();
                timer_center.x += 18;
                timer_center.y += 18;
                draw_radial_timer(timer_center, 16.0f, progress, seconds_left);
            }
            ImGui::EndGroup();

            ImGui::Separator();
            ImGui::Spacing();

            // Accounts List Cards
            if (accounts.empty()) {
                if (connected) {
                    ImGui::TextDisabled("No OATH accounts configured on HyprKey. Click '+ Add Account' above.");
                } else {
                    ImGui::TextDisabled("Connect your HyprKey token via USB to view 2FA codes.");
                }
            } else {
                for (size_t i = 0; i < accounts.size(); i++) {
                    const auto& acc = accounts[i];
                    char card_id[32];
                    snprintf(card_id, sizeof(card_id), "acc_card_%zu", i);

                    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.14f, 0.16f, 0.22f, 1.0f));
                    ImGui::BeginChild(card_id, ImVec2(0, 72), true);
                    {
                        // Left column: Name & Algorithm
                        ImGui::BeginGroup();
                        {
                            ImGui::TextUnformatted(acc.name.c_str());
                            const char* alg_str = (acc.type_alg == 0x22) ? "TOTP SHA-256" : "TOTP SHA-1";
                            ImGui::TextColored(ImVec4(0.48f, 0.52f, 0.64f, 1.00f), "%s • %d digits", alg_str, acc.digits);
                        }
                        ImGui::EndGroup();

                        // Right column: Code & Actions
                        ImGui::SameLine(ImGui::GetWindowWidth() - 240);
                        ImGui::BeginGroup();
                        {
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.00f, 0.88f, 0.95f, 1.0f));
                            ImGui::SetWindowFontScale(1.4f);
                            ImGui::Text("%s", acc.current_code.c_str());
                            ImGui::SetWindowFontScale(1.0f);
                            ImGui::PopStyleColor();

                            ImGui::SameLine();
                            char copy_btn[32];
                            snprintf(copy_btn, sizeof(copy_btn), "Copy##%zu", i);
                            if (ImGui::Button(copy_btn, ImVec2(60, 28))) {
                                std::string clean_code = acc.current_code;
                                clean_code.erase(remove(clean_code.begin(), clean_code.end(), ' '), clean_code.end());
                                ImGui::SetClipboardText(clean_code.c_str());
                                show_toast("Copied " + acc.name + " code!");
                            }

                            ImGui::SameLine();
                            char del_btn[32];
                            snprintf(del_btn, sizeof(del_btn), "X##%zu", i);
                            if (ImGui::Button(del_btn, ImVec2(28, 28))) {
                                client.oath_delete(acc.name);
                                client.oath_list_and_calc(accounts);
                                show_toast("Deleted " + acc.name);
                            }
                        }
                        ImGui::EndGroup();
                    }
                    ImGui::EndChild();
                    ImGui::PopStyleColor();
                    ImGui::Spacing();
                }
            }

            // Modal: Add New Account
            if (ImGui::BeginPopupModal("AddAccountModal", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                static char name_buf[64] = "";
                static char sec_buf[128] = "";
                static int  digits_choice = 0; // 0=6 digits, 1=8 digits
                static int  alg_choice = 0;    // 0=SHA1, 1=SHA256

                ImGui::TextColored(ImVec4(0.00f, 0.88f, 0.95f, 1.0f), "Add OATH TOTP Account");
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::Text("Account Name / Issuer:");
                ImGui::InputText("##acc_name", name_buf, sizeof(name_buf));

                ImGui::Text("Secret Key (Base32 or Plain):");
                ImGui::InputText("##acc_sec", sec_buf, sizeof(sec_buf));

                ImGui::Text("Digits:");
                ImGui::RadioButton("6 digits", &digits_choice, 0); ImGui::SameLine();
                ImGui::RadioButton("8 digits", &digits_choice, 1);

                ImGui::Text("Algorithm:");
                ImGui::RadioButton("SHA-1", &alg_choice, 0); ImGui::SameLine();
                ImGui::RadioButton("SHA-256", &alg_choice, 1);

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (ImGui::Button("Save to HyprKey", ImVec2(150, 32))) {
                    if (strlen(name_buf) > 0 && strlen(sec_buf) > 0) {
                        std::vector<uint8_t> dec_sec = base32_decode(sec_buf);
                        if (dec_sec.empty()) {
                            dec_sec.assign((uint8_t*)sec_buf, (uint8_t*)sec_buf + strlen(sec_buf));
                        }
                        uint8_t alg = (alg_choice == 1) ? 0x22 : 0x21;
                        uint8_t dig = (digits_choice == 1) ? 8 : 6;
                        if (client.oath_put(name_buf, dec_sec, alg, dig)) {
                            client.oath_list_and_calc(accounts);
                            show_toast("Account saved to token!");
                            name_buf[0] = '\0';
                            sec_buf[0] = '\0';
                            ImGui::CloseCurrentPopup();
                        }
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel", ImVec2(100, 32))) {
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }

            ImGui::EndTabItem();
        }

        // ==================== TAB 2: OpenPGP Smart Card ====================
        if (ImGui::BeginTabItem("  OpenPGP Card  ")) {
            static OpenPgpStatus pgp_stat;
            static bool pgp_loaded = false;

            if (ImGui::Button("Refresh Status", ImVec2(130, 32)) || (!pgp_loaded && connected)) {
                if (client.openpgp_get_status(pgp_stat)) {
                    pgp_loaded = true;
                }
            }

            ImGui::Separator();
            ImGui::Spacing();

            if (pgp_loaded) {
                ImGui::Columns(2, "PgpCols", false);
                ImGui::SetColumnWidth(0, 340);

                // Column 1: Cardholder info & PINs
                ImGui::TextColored(ImVec4(0.65f, 0.55f, 0.98f, 1.0f), "Cardholder Metadata");
                ImGui::Spacing();
                ImGui::Text("Cardholder Name:");
                ImGui::TextColored(ImVec4(0.00f, 0.88f, 0.95f, 1.0f), "%s", pgp_stat.cardholder_name.c_str());

                ImGui::Text("Language / Sex:");
                ImGui::Text("%s / %d", pgp_stat.lang.c_str(), pgp_stat.sex);

                ImGui::Text("Serial Number:");
                ImGui::Text("%s", pgp_stat.serial.c_str());

                ImGui::Text("Signature Counter:");
                ImGui::TextColored(ImVec4(0.10f, 0.85f, 0.50f, 1.0f), "%u signatures", pgp_stat.sig_counter);

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::TextColored(ImVec4(0.65f, 0.55f, 0.98f, 1.0f), "PIN Retry Counters");
                ImGui::Text("PW1 (User PIN):  %d / 3 tries", pgp_stat.pw1_tries);
                ImGui::Text("PW3 (Admin PIN): %d / 3 tries", pgp_stat.pw3_tries);

                ImGui::Spacing();
                if (ImGui::Button("Change PINs...", ImVec2(140, 30))) {
                    ImGui::OpenPopup("ChangePinModal");
                }

                ImGui::NextColumn();

                // Column 2: Public Key URL & Fingerprints
                ImGui::TextColored(ImVec4(0.65f, 0.55f, 0.98f, 1.0f), "Public Key URL (DO 0x5F50)");
                static char url_input[128] = "";
                if (url_input[0] == '\0') {
                    snprintf(url_input, sizeof(url_input), "%s", pgp_stat.cardholder_url.c_str());
                }
                ImGui::InputText("##url_in", url_input, sizeof(url_input));
                ImGui::SameLine();
                if (ImGui::Button("Update URL")) {
                    if (client.openpgp_set_url(url_input)) {
                        show_toast("URL updated in storage!");
                        client.openpgp_get_status(pgp_stat);
                    }
                }

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::TextColored(ImVec4(0.65f, 0.55f, 0.98f, 1.0f), "Key Fingerprints (DO 0x00C5)");
                ImGui::Spacing();

                ImGui::Text("Signature Key (SIG):");
                ImGui::TextColored(ImVec4(0.85f, 0.88f, 0.95f, 1.0f), "%s", pgp_stat.fp_sig.c_str());

                ImGui::Text("Decryption Key (DEC):");
                ImGui::TextColored(ImVec4(0.85f, 0.88f, 0.95f, 1.0f), "%s", pgp_stat.fp_dec.c_str());

                ImGui::Text("Authentication Key (AUT):");
                ImGui::TextColored(ImVec4(0.85f, 0.88f, 0.95f, 1.0f), "%s", pgp_stat.fp_aut.c_str());

                ImGui::Columns(1);
            } else {
                ImGui::TextDisabled("Card not loaded or token disconnected.");
            }

            // Modal: Change PIN
            if (ImGui::BeginPopupModal("ChangePinModal", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                static char cur_pw3[32] = "";
                static char new_pin[32] = "";
                static int  pin_target = 0; // 0=PW1, 1=PW3

                ImGui::Text("Verify Admin PIN (PW3):");
                ImGui::InputText("##cur_pw3", cur_pw3, sizeof(cur_pw3), ImGuiInputTextFlags_Password);

                ImGui::Text("Select PIN to change:");
                ImGui::RadioButton("User PIN (PW1)", &pin_target, 0); ImGui::SameLine();
                ImGui::RadioButton("Admin PIN (PW3)", &pin_target, 1);

                ImGui::Text("New PIN:");
                ImGui::InputText("##new_pin", new_pin, sizeof(new_pin), ImGuiInputTextFlags_Password);

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (ImGui::Button("Apply Change", ImVec2(130, 32))) {
                    if (client.openpgp_verify_pw3(cur_pw3)) {
                        bool ok = (pin_target == 0) ? client.openpgp_change_pw1(new_pin) : client.openpgp_change_pw3(new_pin);
                        if (ok) {
                            show_toast("PIN changed successfully!");
                            cur_pw3[0] = '\0';
                            new_pin[0] = '\0';
                            ImGui::CloseCurrentPopup();
                        }
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel", ImVec2(80, 32))) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            ImGui::EndTabItem();
        }

        // ==================== TAB 3: Device & Storage ====================
        if (ImGui::BeginTabItem("  Hardware & Storage  ")) {
            ImGui::TextColored(ImVec4(0.00f, 0.88f, 0.95f, 1.0f), "HyprKey Hardware Specs");
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::BulletText("Microcontroller: Nordic nRF52840 (ARM Cortex-M4F @ 64 MHz)");
            ImGui::BulletText("NFC Controller: NXP PN532 (Active SPI @ 13.56 MHz)");
            ImGui::BulletText("Flash Storage: 1024 KB Total (656 KB Journaled Zone B, 164 pages * 4 KB)");
            ImGui::BulletText("Master Key: Hardware-bound Silicon Root (FICR->ER || FICR->IR)");
            ImGui::BulletText("Storage Cipher: ChaCha20-Poly1305 (RFC 8439) with 1->0 NOR flash bit burning");
            ImGui::BulletText("Post-Quantum Algorithms: ML-KEM-1024 (Kyber) & ML-DSA-87 (Dilithium)");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::TextColored(ImVec4(0.65f, 0.55f, 0.98f, 1.0f), "Storage Partition Map");
            ImGui::ProgressBar(0.08f, ImVec2(0, 24), "Zone B: 656 KB Allocated (164 Pages)");

            ImGui::EndTabItem();
        }

        // ==================== TAB 4: Live APDU Monitor ====================
        if (ImGui::BeginTabItem("  APDU Console  ")) {
            if (ImGui::Button("Clear Logs", ImVec2(100, 28))) {
                client.clear_logs();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Live stream of ISO 7816-4 APDU transactions over USB CCID");

            ImGui::Separator();

            ImGui::BeginChild("LogScrollRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            {
                auto logs = client.get_logs();
                for (const auto& l : logs) {
                    if (l.is_tx) {
                        ImGui::TextColored(ImVec4(0.00f, 0.88f, 0.95f, 1.0f), "[%s] >> TX:", l.time_str.c_str());
                    } else {
                        ImU32 sw_col = (l.sw == 0x9000) ? IM_COL32(16, 185, 129, 255) : IM_COL32(239, 68, 68, 255);
                        ImGui::TextColored(ImVec4(0.65f, 0.55f, 0.98f, 1.0f), "[%s] << RX (SW=%04X):", l.time_str.c_str(), l.sw);
                    }
                    ImGui::SameLine();
                    ImGui::Text("%s", l.hex_data.c_str());
                    if (!l.desc.empty()) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("(%s)", l.desc.c_str());
                    }
                }
                if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                    ImGui::SetScrollHereY(1.0f);
                }
            }
            ImGui::EndChild();

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    // Toast Notification Banner (Bottom Right)
    double time_since_toast = ImGui::GetTime() - s_toast_time;
    if (time_since_toast < 3.0 && !s_toast_msg.empty()) {
        float alpha = (time_since_toast > 2.0) ? (float)(3.0 - time_since_toast) : 1.0f;
        ImVec2 toast_pos = ImVec2(ImGui::GetWindowWidth() - 320, ImGui::GetWindowHeight() - 60);
        ImGui::SetCursorPos(toast_pos);

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.00f, 0.72f, 0.85f, alpha * 0.9f));
        ImGui::BeginChild("ToastBox", ImVec2(300, 40), true);
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, alpha), "%s", s_toast_msg.c_str());
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
}

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "scard_client.h"
#include "ui.h"
#include "system_theme.h"

#include <d3d11.h>
#include <tchar.h>
#include <dwmapi.h>
#include <stdio.h>

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

// Data
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
HWND                            g_MainHWnd = nullptr;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Helper to check file existence
static bool FileExists(const char* path) {
    if (!path || !path[0]) return false;
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

// Main code
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrevInstance; (void)pCmdLine; (void)nCmdShow;

    // Enable DPI awareness
    ImGui_ImplWin32_EnableDpiAwareness();

    // Detect theme from executable filename
    WCHAR exeFullPath[MAX_PATH];
    GetModuleFileNameW(NULL, exeFullPath, MAX_PATH);

    WCHAR exeDir[MAX_PATH];
    wcscpy_s(exeDir, exeFullPath);
    WCHAR* lastSlash = wcsrchr(exeDir, L'\\');
    if (lastSlash) *lastSlash = L'\0';

    WCHAR exeNameLower[MAX_PATH];
    wcscpy_s(exeNameLower, exeFullPath);
    _wcslwr_s(exeNameLower);

    AppTheme initTheme = THEME_MD3_SYSTEM;
    const wchar_t* titleName = L"HyprKey [Material You Dynamic Edition]";

    if (wcsstr(exeNameLower, L"blue") || wcsstr(exeNameLower, L"pixel")) {
        initTheme = THEME_MD3_BLUE;
        titleName = L"HyprKey [Material 3 Pixel Blue Edition]";
    } else if (wcsstr(exeNameLower, L"lavender")) {
        initTheme = THEME_MD3_LAVENDER;
        titleName = L"HyprKey [Material 3 Lavender Edition]";
    } else if (wcsstr(exeNameLower, L"nothing")) {
        initTheme = THEME_NOTHING;
        titleName = L"HyprKey [Nothing OS Glyph Edition]";
    } else if (wcsstr(exeNameLower, L"circuit")) {
        initTheme = THEME_CIRCUIT;
        titleName = L"HyprKey [Cyber Circuit PCB Edition]";
    } else if (wcsstr(exeNameLower, L"linear")) {
        initTheme = THEME_LINEAR;
        titleName = L"HyprKey [Linear Stealth Edition]";
    }

    // Create application window
    WNDCLASSEXW wc = {
        sizeof(wc),
        CS_CLASSDC,
        WndProc,
        0L, 0L,
        GetModuleHandle(nullptr),
        nullptr, nullptr, nullptr, nullptr,
        L"HyprKeyAppClass",
        nullptr
    };
    ::RegisterClassExW(&wc);

    int window_width = 1140;
    int window_height = 740;

    // Center window on primary monitor
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    int pos_x = (screen_w - window_width) / 2;
    int pos_y = (screen_h - window_height) / 2;

    HWND hwnd = ::CreateWindowW(
        wc.lpszClassName,
        titleName,
        WS_OVERLAPPEDWINDOW,
        pos_x, pos_y, window_width, window_height,
        nullptr, nullptr, wc.hInstance, nullptr
    );
    g_MainHWnd = hwnd;

    // Query initial Windows dark mode
    bool is_win_dark = M3_QueryWindowsDarkTheme();
    BOOL use_dark_mode = is_win_dark ? TRUE : FALSE;
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &use_dark_mode, sizeof(use_dark_mode));

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Setup High-DPI Cyrillic + Latin Fonts with Material Design 3 Spec
    ImFontConfig font_cfg;
    font_cfg.OversampleH = 2;
    font_cfg.OversampleV = 2;
    static const ImWchar glyph_ranges[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x0400, 0x052F, // Cyrillic + Cyrillic Supplement
        0x2DE0, 0x2DFF, // Cyrillic Extended-A
        0xA640, 0xA69F, // Cyrillic Extended-B
        0,
    };

    // Construct candidate paths for Roboto and Material Icons
    char roboto_reg[MAX_PATH];
    char roboto_bold[MAX_PATH];
    char mat_icons[MAX_PATH];
    sprintf_s(roboto_reg, "%ls\\Roboto-Regular.ttf", exeDir);
    sprintf_s(roboto_bold, "%ls\\Roboto-Bold.ttf", exeDir);
    sprintf_s(mat_icons, "%ls\\MaterialIcons-Regular.ttf", exeDir);

    const char* f_ui = FileExists(roboto_reg) ? roboto_reg : (FileExists("Roboto-Regular.ttf") ? "Roboto-Regular.ttf" : "C:\\Windows\\Fonts\\segoeui.ttf");
    const char* f_title = FileExists(roboto_bold) ? roboto_bold : (FileExists("Roboto-Bold.ttf") ? "Roboto-Bold.ttf" : "C:\\Windows\\Fonts\\segoeuib.ttf");
    const char* f_icons = FileExists(mat_icons) ? mat_icons : (FileExists("MaterialIcons-Regular.ttf") ? "MaterialIcons-Regular.ttf" : nullptr);

    // 1. Primary UI Font (Roboto-Regular or Segoe UI)
    g_FontUI = io.Fonts->AddFontFromFileTTF(f_ui, 17.5f, &font_cfg, glyph_ranges);
    if (!g_FontUI) {
        g_FontUI = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 18.0f, &font_cfg, glyph_ranges);
    }

    // 2. Merge Google Material Icons into g_FontUI
    if (f_icons) {
        ImFontConfig icon_cfg;
        icon_cfg.MergeMode = true;
        icon_cfg.PixelSnapH = true;
        icon_cfg.GlyphOffset = ImVec2(0.0f, 2.5f);
        static const ImWchar icon_ranges[] = {
            0xE000, 0xF8FF, // Material Icons Private Use Area
            0,
        };
        io.Fonts->AddFontFromFileTTF(f_icons, 19.0f, &icon_cfg, icon_ranges);
    }

    // 3. Title Font (Roboto-Bold or Segoe UI Bold)
    g_FontTitle = io.Fonts->AddFontFromFileTTF(f_title, 22.0f, &font_cfg, glyph_ranges);
    if (!g_FontTitle) {
        g_FontTitle = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", 22.0f, &font_cfg, glyph_ranges);
    }
    if (f_icons) {
        ImFontConfig title_icon_cfg;
        title_icon_cfg.MergeMode = true;
        title_icon_cfg.PixelSnapH = true;
        title_icon_cfg.GlyphOffset = ImVec2(0.0f, 3.0f);
        static const ImWchar icon_ranges[] = {
            0xE000, 0xF8FF,
            0,
        };
        io.Fonts->AddFontFromFileTTF(f_icons, 22.0f, &title_icon_cfg, icon_ranges);
    }

    // 4. Monospace Font for APDU Console and Hex Dumps
    g_FontMono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\CascadiaCode.ttf", 16.5f, &font_cfg, glyph_ranges);
    if (!g_FontMono) {
        g_FontMono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", 16.5f, &font_cfg, glyph_ranges);
    }

    // 5. Giant TOTP Display Font
    g_FontTotpCode = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\CascadiaCode.ttf", 32.0f, &font_cfg, glyph_ranges);
    if (!g_FontTotpCode && g_FontMono) {
        g_FontTotpCode = g_FontMono;
    }

    // Apply Initial Theme
    ApplyTheme(initTheme);

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // SCard Client (Hardware Interface)
    SCardClient scard_client;
    scard_client.connect();

    // Main loop
    bool done = false;
    while (!done)
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (g_FontUI) ImGui::PushFont(g_FontUI);

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGuiWindowFlags main_win_flags = ImGuiWindowFlags_NoTitleBar
                                        | ImGuiWindowFlags_NoResize
                                        | ImGuiWindowFlags_NoMove
                                        | ImGuiWindowFlags_NoCollapse
                                        | ImGuiWindowFlags_NoBringToFrontOnFocus;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        if (ImGui::Begin("##HyprKeyCanvas", nullptr, main_win_flags))
        {
            RenderHyprKeyUI(scard_client);
        }
        ImGui::End();
        ImGui::PopStyleVar(2);

        if (g_FontUI) ImGui::PopFont();

        ImGui::Render();
        ImVec4 cc = GetThemeClearColor(g_CurrentTheme);
        const float clear_color[4] = { cc.x, cc.y, cc.z, cc.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    scard_client.disconnect();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// Helper functions
bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        createDeviceFlags,
        featureLevelArray,
        2,
        D3D11_SDK_VERSION,
        &sd,
        &g_pSwapChain,
        &g_pd3dDevice,
        &featureLevel,
        &g_pd3dDeviceContext
    );
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

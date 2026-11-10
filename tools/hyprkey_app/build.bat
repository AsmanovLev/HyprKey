@echo off
setlocal enabledelayedexpansion

echo [HyprKey Build] Setting up MSVC environment...
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cd /d "%~dp0"

if not exist bin mkdir bin
if not exist obj mkdir obj

echo [HyprKey Build] Compiling C++20 Dear ImGui Companion App...

set CFLAGS=/std:c++20 /O2 /EHsc /MD /W3 /DUNICODE /D_UNICODE /DNDEBUG /I"imgui" /I"src" /Fo"obj\\" /c
set LFLAGS=/OUT:"bin\hyprkey.exe" /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup d3d11.lib d3dcompiler.lib dxgi.lib winscard.lib dwmapi.lib user32.lib gdi32.lib shell32.lib

cl.exe %CFLAGS% ^
    imgui\imgui.cpp ^
    imgui\imgui_draw.cpp ^
    imgui\imgui_tables.cpp ^
    imgui\imgui_widgets.cpp ^
    imgui\imgui_impl_win32.cpp ^
    imgui\imgui_impl_dx11.cpp ^
    src\main.cpp ^
    src\scard_client.cpp ^
    src\ui.cpp

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed!
    exit /b %ERRORLEVEL%
)

echo [HyprKey Build] Linking hyprkey.exe...
link.exe obj\*.obj %LFLAGS%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Linking failed!
    exit /b %ERRORLEVEL%
)

echo [HyprKey Build] SUCCESS: bin\hyprkey.exe created successfully!
dir bin\hyprkey.exe

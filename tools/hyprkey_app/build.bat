@echo off
setlocal enabledelayedexpansion

echo [HyprKey Build] Setting up MSVC environment...
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cd /d "%~dp0"

if not exist bin mkdir bin
if not exist obj mkdir obj

echo [HyprKey Build] Compiling C/C++ sources (ImGui + Quirc QR + M3 HyprKey App)...

set CFLAGS=/std:c++20 /O2 /EHsc /MD /W3 /DUNICODE /D_UNICODE /DNDEBUG /I"imgui" /I"quirc" /I"src" /Fo"obj\\" /c
set C_FLAGS=/O2 /MD /W3 /DNDEBUG /I"quirc" /Fo"obj\\" /c
set LFLAGS=/OUT:"bin\hyprkey.exe" /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup d3d11.lib d3dcompiler.lib dxgi.lib winscard.lib dwmapi.lib advapi32.lib user32.lib gdi32.lib shell32.lib

:: 1. Compile C sources (quirc QR scanner)
cl.exe %C_FLAGS% ^
    quirc\quirc.c ^
    quirc\decode.c ^
    quirc\identify.c ^
    quirc\version_db.c
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Quirc compilation failed!
    exit /b %ERRORLEVEL%
)

:: 2. Compile C++ sources (ImGui + App)
cl.exe %CFLAGS% ^
    imgui\imgui.cpp ^
    imgui\imgui_draw.cpp ^
    imgui\imgui_tables.cpp ^
    imgui\imgui_widgets.cpp ^
    imgui\imgui_impl_win32.cpp ^
    imgui\imgui_impl_dx11.cpp ^
    src\main.cpp ^
    src\scard_client.cpp ^
    src\ui.cpp ^
    src\qr_reader.cpp
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Application compilation failed!
    exit /b %ERRORLEVEL%
)

echo [HyprKey Build] Linking main executable bin\hyprkey.exe...
link.exe obj\*.obj %LFLAGS%
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Linking failed!
    exit /b %ERRORLEVEL%
)

echo [HyprKey Build] Generating Material 3 and theme editions...
copy /Y "bin\hyprkey.exe" "bin\hyprkey_md3.exe" >nul
copy /Y "bin\hyprkey.exe" "bin\hyprkey_md3_blue.exe" >nul
copy /Y "bin\hyprkey.exe" "bin\hyprkey_nothing.exe" >nul
copy /Y "bin\hyprkey.exe" "bin\hyprkey_circuit.exe" >nul
copy /Y "bin\hyprkey.exe" "bin\hyprkey_linear.exe" >nul

echo [HyprKey Build] Copying Material fonts to bin\...
copy /Y "Roboto-Regular.ttf" "bin\" >nul
copy /Y "Roboto-Bold.ttf" "bin\" >nul
copy /Y "MaterialIcons-Regular.ttf" "bin\" >nul

echo [HyprKey Build] SUCCESS: All Material 3 editions created in bin\
dir /b bin\*.exe

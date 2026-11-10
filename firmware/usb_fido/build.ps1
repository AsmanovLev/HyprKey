$gcc = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
$objcopy = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"

Set-Location "S:\hyprkey\firmware\usb_fido"

$c_sources = "main.c device_log.c storage_flash.c fido_u2f.c ctap2.c ccid/ccid.c openpgp/openpgp.c piv/piv.c mldsa/mldsa.c mlkem/mlkem.c fips202/fips202.c micro_ecc/uECC.c sha256/sha256.c sha512/sha512.c ed25519/ed25519.c sha1/sha1.c oath/oath.c pn532_nfc.c"
$common_flags = "-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -O2 -g -Wall -Wextra -Wno-unused-parameter -ffunction-sections -fdata-sections -nostartfiles -Wl,--gc-sections -DuECC_CURVE=uECC_secp256r1 -DuECC_OPTIMIZATION_LEVEL=3 -DuECC_SQUARE_FUNC=1 -I. -Imicro_ecc -Isha256 -Imldsa -Imlkem -Ifips202 -Iccid -Iopenpgp -Ipiv -Isha512 -Ied25519 -Ioath -Isha1"

Write-Host ">>> Compiling Slot A Firmware (0x00028000)..."
$args_a = ($common_flags -split ' ') + @("-T", "linker_slot_a.ld") + ($c_sources -split ' ') + @("-lgcc", "-o", "usb_fido_slot_a.elf")
& $gcc $args_a
if ($LASTEXITCODE -ne 0) { Write-Error "GCC build failed for Slot A"; exit 1 }

& $objcopy -O binary "usb_fido_slot_a.elf" "usb_fido_slot_a.bin"
Copy-Item "usb_fido_slot_a.bin" "usb_fido.bin" -Force

Write-Host ">>> Compiling Slot B Firmware (0x00040000)..."
$args_b = ($common_flags -split ' ') + @("-T", "linker_slot_b.ld") + ($c_sources -split ' ') + @("-lgcc", "-o", "usb_fido_slot_b.elf")
& $gcc $args_b
if ($LASTEXITCODE -ne 0) { Write-Error "GCC build failed for Slot B"; exit 1 }

& $objcopy -O binary "usb_fido_slot_b.elf" "usb_fido_slot_b.bin"

Write-Host ">>> Stamping application headers (app_header_t)..."
python "S:\hyprkey\firmware\usb_fido\patch_header.py" "S:\hyprkey\firmware\usb_fido\usb_fido_slot_a.bin"
python "S:\hyprkey\firmware\usb_fido\patch_header.py" "S:\hyprkey\firmware\usb_fido\usb_fido_slot_b.bin"
Copy-Item "usb_fido_slot_a.bin" "usb_fido.bin" -Force

Write-Host ">>> Building Stage-2 Bootloader..."
powershell -ExecutionPolicy Bypass -File "S:\hyprkey\firmware\stage2_bootloader\build_stage2.ps1"

Write-Host ">>> Packaging Combined Stage-2 + Slot A UF2 image..."
python "S:\hyprkey\firmware\pack_combined_uf2.py"

Write-Host "Build complete: Dual-Slot A/B binaries and combined UF2 generated successfully!"

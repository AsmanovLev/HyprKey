$gcc = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
$objcopy = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"

Set-Location "S:\hyprkey\firmware\usb_fido"

& $gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -O2 -g -Wall -Wextra -Wno-unused-parameter `
    -ffunction-sections -fdata-sections -T "linker.ld" -nostartfiles "-Wl,--gc-sections" `
    -DuECC_CURVE=uECC_secp256r1 -DuECC_OPTIMIZATION_LEVEL=3 -DuECC_SQUARE_FUNC=1 `
    -I. -Imicro_ecc -Isha256 -Imldsa -Imlkem -Ifips202 -Iccid -Iopenpgp -Ipiv -Isha512 -Ied25519 -Ioath -Isha1 `
    main.c fido_u2f.c ctap2.c ccid/ccid.c openpgp/openpgp.c piv/piv.c mldsa/mldsa.c mlkem/mlkem.c fips202/fips202.c micro_ecc/uECC.c sha256/sha256.c sha512/sha512.c ed25519/ed25519.c sha1/sha1.c oath/oath.c -lgcc -o "usb_fido.elf"

if ($LASTEXITCODE -ne 0) {
    Write-Error "GCC build failed"
    exit 1
}

& $objcopy -O binary "usb_fido.elf" "usb_fido.bin"
python "bin2uf2.py" "usb_fido.bin" "usb_fido.uf2" 0x26000

Write-Host "Build complete: usb_fido.uf2 generated!"

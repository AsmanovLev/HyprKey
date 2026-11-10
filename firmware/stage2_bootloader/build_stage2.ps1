$gcc = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
$objcopy = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"

Set-Location "S:\hyprkey\firmware\stage2_bootloader"

& $gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -Os -Wall -Wextra `
    -ffunction-sections -fdata-sections -T "linker_stage2.ld" -nostartfiles "-Wl,--gc-sections" `
    -I. -I../usb_fido -I../usb_fido/sha256 `
    stage2_main.c ../usb_fido/sha256/sha256.c -lgcc -o "stage2.elf"

if ($LASTEXITCODE -ne 0) {
    Write-Error "GCC build failed for Stage-2 Bootloader"
    exit 1
}

& $objcopy -O binary "stage2.elf" "stage2.bin"

Write-Host "Stage-2 Bootloader built successfully!"

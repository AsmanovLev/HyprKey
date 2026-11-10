$gcc = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
$objcopy = "D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"

Set-Location "S:\hyprkey\firmware\test_hw"

& $gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -O2 -g -Wall -Wextra -ffunction-sections -fdata-sections -T "linker.ld" -nostartfiles "-Wl,--gc-sections" "main.c" -o "test_hw.elf"

if ($LASTEXITCODE -ne 0) {
    Write-Error "GCC build failed"
    exit 1
}

& $objcopy -O binary "test_hw.elf" "test_hw.bin"
python "bin2uf2.py" "test_hw.bin" "test_hw.uf2" 0x26000

Write-Host "Build complete: test_hw.uf2 generated!"

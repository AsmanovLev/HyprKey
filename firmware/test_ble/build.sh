#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== 1. Compiling Bare-Metal BLE Beacon for nRF52840 ==="
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 \
  -O2 -Wall -Wextra -T linker.ld -nostartfiles -Wl,--gc-sections \
  main.c -o test_ble.elf

echo "=== 2. Creating Raw Binary ==="
arm-none-eabi-objcopy -O binary test_ble.elf test_ble.bin
ls -lh test_ble.bin

echo "=== 3. Packaging into nice!nano UF2 ==="
python3 bin2uf2.py test_ble.bin test_ble.uf2
ls -lh test_ble.uf2

echo "=== Build Complete! ==="

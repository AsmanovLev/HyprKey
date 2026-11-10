#!/bin/sh
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== 1. Compiling HW Test Firmware (NFC + Fingerprint + BLE) ==="
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 \
  -O2 -Wall -Wextra -T linker.ld -nostartfiles -Wl,--gc-sections \
  main.c -o test_hw.elf

echo "=== 2. Creating Raw Binary ==="
arm-none-eabi-objcopy -O binary test_hw.elf test_hw.bin
ls -lh test_hw.bin

echo "=== 3. Packaging into nice!nano UF2 ==="
python3 bin2uf2.py test_hw.bin test_hw.uf2
ls -lh test_hw.uf2

echo "=== Build Complete! ==="

import unicorn, unicorn.arm_const as ac
import subprocess, os, struct, hashlib

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"

runner_c = """
#include "fips202.h"

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int val, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)val;
    return dst;
}

uint8_t in_buf[256];
uint8_t out_buf[256];

void run_shake128(size_t inlen, size_t outlen) {
    shake128(in_buf, inlen, out_buf, outlen);
}

void run_shake256(size_t inlen, size_t outlen) {
    shake256(in_buf, inlen, out_buf, outlen);
}
"""

with open("s:/hyprkey/firmware/usb_fido/fips202/runner.c", "w") as f:
    f.write(runner_c)

# Compile
cmd = f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 -I s:/hyprkey/firmware/usb_fido/fips202 s:/hyprkey/firmware/usb_fido/fips202/runner.c s:/hyprkey/firmware/usb_fido/fips202/fips202.c -o s:/hyprkey/firmware/usb_fido/fips202/test.elf'
subprocess.check_call(cmd, shell=True)

# Get symbol addresses
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"
syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/fips202/test.elf', shell=True).decode()
symbols = {}
for line in syms.splitlines():
    parts = line.split()
    if len(parts) == 3:
        symbols[parts[2]] = int(parts[0], 16)

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/fips202/test.elf s:/hyprkey/firmware/usb_fido/fips202/test.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/fips202/test.bin", "rb") as f:
    code = f.read()

# Setup Unicorn
uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x20000) # 128KB
uc.mem_write(0x1000, code)

# Test vectors
msg = b"FIPS 202 test vector for Post-Quantum FIDO2 on HyprKey!"
uc.mem_write(symbols['in_buf'], msg)

# Run SHAKE-128 (32 bytes out)
uc.reg_write(ac.UC_ARM_REG_R0, len(msg))
uc.reg_write(ac.UC_ARM_REG_R1, 32)
uc.reg_write(ac.UC_ARM_REG_SP, 0x1F000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x10000 | 1)
uc.emu_start(symbols['run_shake128'] | 1, 0x10000)

out128 = uc.mem_read(symbols['out_buf'], 32)
ref128 = hashlib.shake_128(msg).digest(32)
print("SHAKE128 match:", bytes(out128) == ref128)
assert bytes(out128) == ref128

# Run SHAKE-256 (64 bytes out)
uc.reg_write(ac.UC_ARM_REG_R0, len(msg))
uc.reg_write(ac.UC_ARM_REG_R1, 64)
uc.reg_write(ac.UC_ARM_REG_SP, 0x1F000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x10000 | 1)
uc.emu_start(symbols['run_shake256'] | 1, 0x10000)

out256 = uc.mem_read(symbols['out_buf'], 64)
ref256 = hashlib.shake_256(msg).digest(64)
print("SHAKE256 match:", bytes(out256) == ref256)
assert bytes(out256) == ref256

print("ALL FIPS-202 TESTS PASSED PERFECTLY!")

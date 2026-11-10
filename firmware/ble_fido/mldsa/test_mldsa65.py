import unicorn, unicorn.arm_const as ac
import subprocess, hashlib
from cryptography.hazmat.primitives.asymmetric import mldsa

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

runner_c = """
#include "mldsa.h"

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

uint8_t g_seed[32];
uint8_t g_pk[2000];
uint8_t g_sig[3500];
uint8_t g_msg[128];

void run_keygen65(void) {
    mldsa65_keygen(g_seed, g_pk, 0);
}

void run_sign65(size_t msglen) {
    mldsa65_sign_seed(g_seed, g_msg, msglen, 0, g_sig);
}
"""

with open("s:/hyprkey/firmware/usb_fido/mldsa/runner.c", "w") as f:
    f.write(runner_c)

cmd = f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 -I s:/hyprkey/firmware/usb_fido/mldsa -I s:/hyprkey/firmware/usb_fido/fips202 s:/hyprkey/firmware/usb_fido/mldsa/runner.c s:/hyprkey/firmware/usb_fido/mldsa/mldsa.c s:/hyprkey/firmware/usb_fido/fips202/fips202.c -lgcc -o s:/hyprkey/firmware/usb_fido/mldsa/test.elf'
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/mldsa/test.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/mldsa/test.elf s:/hyprkey/firmware/usb_fido/mldsa/test.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/mldsa/test.bin", "rb") as f:
    code = f.read()

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

seed = bytes([i for i in range(32)])
uc.mem_write(symbols['g_seed'], seed)
uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)

print("Running mldsa65_keygen in Unicorn...")
uc.emu_start(symbols['run_keygen65'] | 1, 0x80000)

pk_c = bytes(uc.mem_read(symbols['g_pk'], 1952))
print("pk_c length:", len(pk_c))

sk_ref = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
pk_ref = sk_ref.public_key().public_bytes_raw()
print("PK match with cryptography:", pk_c == pk_ref)
assert pk_c == pk_ref
print("ML-DSA-65 KEYGEN MATCHES NIST FIPS 204 EXACTLY!")

msg = b"HyprKey FIDO2 CTAP2 ML-DSA-65 Assertion Data"
uc.mem_write(symbols['g_msg'], msg)
uc.reg_write(ac.UC_ARM_REG_R0, len(msg))
uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)

print("Running mldsa65_sign_seed in Unicorn...")
uc.emu_start(symbols['run_sign65'] | 1, 0x80000)

sig_c = bytes(uc.mem_read(symbols['g_sig'], 3309))
print("sig_c length:", len(sig_c))

pk_obj = mldsa.MLDSA65PublicKey.from_public_bytes(pk_c)
pk_obj.verify(sig_c, msg)
print("PYTHON CRYPTOGRAPHY VERIFIED HYPRKEY ML-DSA-65 SIGNATURE: 100% SUCCESS!")

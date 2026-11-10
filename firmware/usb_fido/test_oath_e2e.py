import unicorn, unicorn.arm_const as ac
import subprocess, struct, hmac, hashlib

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

runner_c = """
#include "oath/oath.h"
#include <string.h>

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

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

uint8_t g_apdu_req[512];
uint8_t g_apdu_rsp[512];
uint16_t g_apdu_rsp_len = 0;

void test_init(void) {
    oath_init();
}

void run_apdu(uint16_t req_len) {
    g_apdu_rsp_len = oath_process_apdu(g_apdu_req, req_len, g_apdu_rsp, sizeof(g_apdu_rsp));
}
"""

with open("s:/hyprkey/firmware/usb_fido/runner_oath.c", "w") as f:
    f.write(runner_c)

print("Compiling test_oath.elf...")
cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f'-I s:/hyprkey/firmware/usb_fido '
       f'-I s:/hyprkey/firmware/usb_fido/oath '
       f'-I s:/hyprkey/firmware/usb_fido/sha1 '
       f'-I s:/hyprkey/firmware/usb_fido/sha256 '
       f's:/hyprkey/firmware/usb_fido/runner_oath.c '
       f's:/hyprkey/firmware/usb_fido/oath/oath.c '
       f's:/hyprkey/firmware/usb_fido/sha1/sha1.c '
       f's:/hyprkey/firmware/usb_fido/sha256/sha256.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_oath.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_oath.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_oath.elf s:/hyprkey/firmware/usb_fido/test_oath.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_oath.bin", "rb") as f: code = f.read()

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

# Init
uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
uc.emu_start(symbols['test_init'] | 1, 0x80000)

def send_apdu(apdu):
    uc.mem_write(symbols['g_apdu_req'], apdu)
    uc.reg_write(ac.UC_ARM_REG_R0, len(apdu))
    uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
    uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
    uc.emu_start(symbols['run_apdu'] | 1, 0x80000)
    rsp_len = int.from_bytes(uc.mem_read(symbols['g_apdu_rsp_len'], 2), 'little')
    return bytes(uc.mem_read(symbols['g_apdu_rsp'], rsp_len))

# 1. SELECT AID
print("1. Testing SELECT OATH AID (A0 00 00 05 27 21 01)...")
sel_oath = bytes.fromhex("00A4040007A0000005272101")
rsp = send_apdu(sel_oath)
print("  Response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"
assert rsp.startswith(b"\x79\x03\x05\x04\x00") # Version 5.4.0
print("  [PASS] SELECT OATH AID verified!\n")

# 2. LIST credentials
print("2. Testing LIST (0xA1)...")
list_cmd = bytes.fromhex("00A1000000")
rsp = send_apdu(list_cmd)
print("  Response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"
assert b"Google:alice@hyprkey.local" in rsp
print("  [PASS] LIST returned configured credentials!\n")

# 3. CALCULATE for demo account (RFC 6238 TOTP test vector)
# Demo secret is "12345678901234567890" (20 bytes)
# For challenge = 1 (T=1, e.g. timestamp 30-59 sec):
challenge = struct.pack(">Q", 1)
calc_data = bytes([0x71, len("Google:alice@hyprkey.local")]) + b"Google:alice@hyprkey.local" + bytes([0x74, 8]) + challenge
calc_cmd = bytes([0x00, 0xA2, 0x00, 0x00, len(calc_data)]) + calc_data

print("3. Testing CALCULATE (0xA2) for demo TOTP...")
rsp = send_apdu(calc_cmd)
print("  Response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"
assert rsp[0] == 0x76 and rsp[1] == 0x05 and rsp[2] == 6 # 6 digits
code31 = int.from_bytes(rsp[3:7], 'big')
otp_code = code31 % 1000000
print(f"  Calculated OTP: {otp_code:06d}")

# Verify against Python's HMAC-SHA1 calculation
py_mac = hmac.new(b"12345678901234567890", challenge, hashlib.sha1).digest()
offset = py_mac[-1] & 0x0F
py_code31 = ((py_mac[offset] & 0x7F) << 24) | (py_mac[offset+1] << 16) | (py_mac[offset+2] << 8) | py_mac[offset+3]
py_otp = py_code31 % 1000000
assert otp_code == py_otp
print(f"  Python expected OTP: {py_otp:06d}")
print("  [PASS] CALCULATE OTP bit-for-bit matches RFC 6238 standard!\n")

# 4. PUT (0x01): Add new credential "GitHub:alice" with SHA-256
print("4. Testing PUT (0x01) for SHA-256 TOTP...")
new_name = b"GitHub:alice"
# Tag 73 secret: 0x22 (TOTP SHA-256), digits=6, key="supersecretkey32byteslong1234567"
new_key = b"supersecretkey32byteslong1234567" # 32 bytes
secret_blob = bytes([0x22, 6]) + new_key
put_data = bytes([0x71, len(new_name)]) + new_name + bytes([0x73, len(secret_blob)]) + secret_blob
put_cmd = bytes([0x00, 0x01, 0x00, 0x00, len(put_data)]) + put_data
rsp = send_apdu(put_cmd)
assert rsp == b"\x90\x00"
print("  [PASS] PUT credential succeeded!")

# Verify in LIST
rsp = send_apdu(list_cmd)
assert b"GitHub:alice" in rsp
print("  [PASS] New credential present in LIST!\n")

# 5. CALCULATE for the new SHA-256 credential
print("5. Testing CALCULATE for SHA-256 credential...")
calc_data_gh = bytes([0x71, len(new_name)]) + new_name + bytes([0x74, 8]) + challenge
calc_cmd_gh = bytes([0x00, 0xA2, 0x00, 0x00, len(calc_data_gh)]) + calc_data_gh
rsp = send_apdu(calc_cmd_gh)
assert rsp[-2:] == b"\x90\x00"
code31_gh = int.from_bytes(rsp[3:7], 'big')
otp_gh = code31_gh % 1000000
print(f"  Calculated SHA-256 OTP: {otp_gh:06d}")

py_mac_gh = hmac.new(new_key, challenge, hashlib.sha256).digest()
offset_gh = py_mac_gh[-1] & 0x0F
py_code31_gh = ((py_mac_gh[offset_gh] & 0x7F) << 24) | (py_mac_gh[offset_gh+1] << 16) | (py_mac_gh[offset_gh+2] << 8) | py_mac_gh[offset_gh+3]
py_otp_gh = py_code31_gh % 1000000
assert otp_gh == py_otp_gh
print(f"  Python expected SHA-256 OTP: {py_otp_gh:06d}")
print("  [PASS] SHA-256 TOTP verified 100% against Python!\n")

# 6. CALCULATE ALL (0xA4)
print("6. Testing CALCULATE ALL (0xA4)...")
calc_all_cmd = bytes([0x00, 0xA4, 0x00, 0x00, 10, 0x74, 8]) + challenge
rsp = send_apdu(calc_all_cmd)
assert rsp[-2:] == b"\x90\x00"
assert b"Google:alice@hyprkey.local" in rsp
assert b"GitHub:alice" in rsp
print("  [PASS] CALCULATE ALL returned codes for all accounts!\n")

# 7. DELETE (0x02)
print("7. Testing DELETE (0x02)...")
del_data = bytes([0x71, len(new_name)]) + new_name
del_cmd = bytes([0x00, 0x02, 0x00, 0x00, len(del_data)]) + del_data
rsp = send_apdu(del_cmd)
assert rsp == b"\x90\x00"

rsp = send_apdu(list_cmd)
assert b"GitHub:alice" not in rsp
print("  [PASS] DELETE verified!\n")

print("=" * 60)
print("   ALL YUBICO OATH E2E PROTOCOL TESTS PASSED 100%!")
print("=" * 60)

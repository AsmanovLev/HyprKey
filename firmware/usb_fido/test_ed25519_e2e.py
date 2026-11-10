import unicorn, unicorn.arm_const as ac
import subprocess
from cryptography.hazmat.primitives.asymmetric import ed25519

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

print("Compiling test_ed25519.elf...")
cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f'-I s:/hyprkey/firmware/usb_fido '
       f'-I s:/hyprkey/firmware/usb_fido/ed25519 '
       f'-I s:/hyprkey/firmware/usb_fido/sha512 '
       f's:/hyprkey/firmware/usb_fido/runner_ed25519.c '
       f's:/hyprkey/firmware/usb_fido/ed25519/ed25519.c '
       f's:/hyprkey/firmware/usb_fido/sha512/sha512.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_ed25519.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_ed25519.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_ed25519.elf s:/hyprkey/firmware/usb_fido/test_ed25519.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_ed25519.bin", "rb") as f: code = f.read()

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

def run_function(func_name):
    addr = symbols[func_name]
    uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
    uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
    uc.emu_start(addr | 1, 0x80000)

seed = bytes([i for i in range(32)])
priv_py = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
pub_py = priv_py.public_key().public_bytes_raw()

uc.mem_write(symbols['g_seed'], seed)
run_function('run_ed25519_keygen')
pk_c = bytes(uc.mem_read(symbols['g_pk'], 32))

print("C pk: ", pk_c.hex())
print("Py pk:", pub_py.hex())
assert pk_c == pub_py, "Ed25519 Public Key mismatch!"
print("[PASS] Ed25519 Keygen matches Python 100%!")

msg = b"hyprkey post-quantum and classical Ed25519 signature test 2026"
uc.mem_write(symbols['g_msg'], msg)
uc.mem_write(symbols['g_msg_len'], len(msg).to_bytes(4, 'little'))
run_function('run_ed25519_sign')
sig_c = bytes(uc.mem_read(symbols['g_sig'], 64))

sig_py = priv_py.sign(msg)
print("C   R:", sig_c[:32].hex())
print("Py  R:", sig_py[:32].hex())
print("C   S:", sig_c[32:].hex())
print("Py  S:", sig_py[32:].hex())

priv_py.public_key().verify(sig_c, msg)
print("[PASS] Ed25519 Signature generated in C verified with Python cryptography 100%!")

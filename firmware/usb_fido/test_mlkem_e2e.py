import unicorn, unicorn.arm_const as ac
import subprocess, os
from cryptography.hazmat.primitives.asymmetric import mlkem

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

print("Compiling test_mlkem.elf...")
cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f'-I s:/hyprkey/firmware/usb_fido '
       f'-I s:/hyprkey/firmware/usb_fido/fips202 '
       f'-I s:/hyprkey/firmware/usb_fido/mlkem '
       f's:/hyprkey/firmware/usb_fido/runner_mlkem.c '
       f's:/hyprkey/firmware/usb_fido/mlkem/mlkem.c '
       f's:/hyprkey/firmware/usb_fido/fips202/fips202.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_mlkem.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_mlkem.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_mlkem.elf s:/hyprkey/firmware/usb_fido/test_mlkem.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_mlkem.bin", "rb") as f: code = f.read()

print(f"Code size: {len(code)} bytes")

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

def run_function(func_name):
    addr = symbols[func_name]
    uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
    uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
    uc.emu_start(addr | 1, 0x80000)

print("\n=== Testing ML-KEM-768 ===")
seed = bytes([i % 256 for i in range(64)])
d = seed[:32]
z = seed[32:]

# Python reference key
sk_py = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
pk_py = sk_py.public_key().public_bytes_raw()

# Keygen in Unicorn
uc.mem_write(symbols['g_d'], d)
uc.mem_write(symbols['g_z'], z)
run_function('run_mlkem768_keygen')
pk_c = bytes(uc.mem_read(symbols['g_pk'], 1184))
sk_c = bytes(uc.mem_read(symbols['g_sk'], 2400))

print("C pk length: ", len(pk_c))
print("Py pk length:", len(pk_py))
assert pk_c == pk_py, f"ML-KEM-768 Keygen public key mismatch!\nC:  {pk_c[:32].hex()}\nPy: {pk_py[:32].hex()}"
print("[PASS] ML-KEM-768 Keygen public key matches Python cryptography 100%!")

# Decapsulation: Python encapsulates, C decapsulates
ss_py, ct_py = sk_py.public_key().encapsulate()
uc.mem_write(symbols['g_ct'], ct_py)
run_function('run_mlkem768_decaps')
ss_c = bytes(uc.mem_read(symbols['g_ss'], 32))

assert ss_c == ss_py, f"ML-KEM-768 Decaps mismatch!\nC:  {ss_c.hex()}\nPy: {ss_py.hex()}"
print("[PASS] ML-KEM-768 Decapsulation of Python ciphertext matches shared secret 100%!")

# Encapsulation: C encapsulates, Python decapsulates
m_rand = bytes([(i * 17 + 3) & 0xFF for i in range(32)])
uc.mem_write(symbols['g_m'], m_rand)
run_function('run_mlkem768_encaps')
ct_from_c = bytes(uc.mem_read(symbols['g_ct'], 1088))
ss_from_c = bytes(uc.mem_read(symbols['g_ss'], 32))

ss_py_decaps = sk_py.decapsulate(ct_from_c)
assert ss_py_decaps == ss_from_c, f"ML-KEM-768 C-encaps/Py-decaps mismatch!\nC ss:  {ss_from_c.hex()}\nPy ss: {ss_py_decaps.hex()}"
print("[PASS] ML-KEM-768 Encapsulation in C successfully decapsulated by Python cryptography!")

# Implicit rejection test (tampered ciphertext)
ct_tampered = bytearray(ct_py)
ct_tampered[42] ^= 0x01
uc.mem_write(symbols['g_ct'], bytes(ct_tampered))
run_function('run_mlkem768_decaps')
ss_c_rej = bytes(uc.mem_read(symbols['g_ss'], 32))
assert ss_c_rej != ss_py, "Implicit rejection failed to change shared secret!"
print("[PASS] ML-KEM-768 Implicit rejection verified on tampered ciphertext!")

print("\n=== Testing ML-KEM-1024 ===")
sk1024_py = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)
pk1024_py = sk1024_py.public_key().public_bytes_raw()

uc.mem_write(symbols['g_d'], d)
uc.mem_write(symbols['g_z'], z)
run_function('run_mlkem1024_keygen')
pk1024_c = bytes(uc.mem_read(symbols['g_pk'], 1568))
sk1024_c = bytes(uc.mem_read(symbols['g_sk'], 3168))

assert pk1024_c == pk1024_py, "ML-KEM-1024 Keygen public key mismatch!"
print("[PASS] ML-KEM-1024 Keygen public key matches Python cryptography 100%!")

ss1024_py, ct1024_py = sk1024_py.public_key().encapsulate()
uc.mem_write(symbols['g_ct'], ct1024_py)
run_function('run_mlkem1024_decaps')
ss1024_c = bytes(uc.mem_read(symbols['g_ss'], 32))

assert ss1024_c == ss1024_py, f"ML-KEM-1024 Decaps mismatch!\nC:  {ss1024_c.hex()}\nPy: {ss1024_py.hex()}"
print("[PASS] ML-KEM-1024 Decapsulation of Python ciphertext matches shared secret 100%!")

uc.mem_write(symbols['g_m'], m_rand)
run_function('run_mlkem1024_encaps')
ct1024_from_c = bytes(uc.mem_read(symbols['g_ct'], 1568))
ss1024_from_c = bytes(uc.mem_read(symbols['g_ss'], 32))

ss1024_py_decaps = sk1024_py.decapsulate(ct1024_from_c)
assert ss1024_py_decaps == ss1024_from_c, "ML-KEM-1024 C-encaps/Py-decaps mismatch!"
print("[PASS] ML-KEM-1024 Encapsulation in C successfully decapsulated by Python cryptography!")

print("\nALL POST-QUANTUM ML-KEM TESTS PASSED WITH 100% ACCURACY!")

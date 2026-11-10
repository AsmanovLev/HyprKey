import unicorn, unicorn.arm_const as ac
import subprocess, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils, ed25519

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

runner_c = """
#include "ccid/ccid.h"
#include "openpgp/openpgp.h"
#include "piv/piv.h"
#include "micro_ecc/uECC.h"

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

static int test_rng(uint8_t *dest, unsigned size) {
    static uint32_t s_seed = 0x12345678;
    while (size--) {
        s_seed = s_seed * 1103515245 + 12345;
        *dest++ = (uint8_t)(s_seed >> 16);
    }
    return 1;
}

uint8_t g_ccid_req[2048];
uint8_t g_ccid_rsp[2048];
uint16_t g_ccid_rsp_len = 0;

void test_init(void) {
    uECC_set_rng(test_rng);
    ccid_init();
}

void run_ccid(uint16_t req_len) {
    g_ccid_rsp_len = ccid_process_message(g_ccid_req, req_len, g_ccid_rsp, sizeof(g_ccid_rsp));
}
"""

with open("s:/hyprkey/firmware/usb_fido/runner_piv.c", "w") as f:
    f.write(runner_c)

print("Compiling test_piv.elf...")
cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f'-I s:/hyprkey/firmware/usb_fido '
       f'-I s:/hyprkey/firmware/usb_fido/ccid '
       f'-I s:/hyprkey/firmware/usb_fido/openpgp '
       f'-I s:/hyprkey/firmware/usb_fido/piv '
       f'-I s:/hyprkey/firmware/usb_fido/sha256 '
       f'-I s:/hyprkey/firmware/usb_fido/sha512 '
       f'-I s:/hyprkey/firmware/usb_fido/ed25519 '
       f'-I s:/hyprkey/firmware/usb_fido/micro_ecc '
       f'-I s:/hyprkey/firmware/usb_fido/fips202 '
       f'-I s:/hyprkey/firmware/usb_fido/mlkem '
       f'-DuECC_CURVE=uECC_secp256r1 '
       f's:/hyprkey/firmware/usb_fido/runner_piv.c '
       f's:/hyprkey/firmware/usb_fido/ccid/ccid.c '
       f's:/hyprkey/firmware/usb_fido/openpgp/openpgp.c '
       f's:/hyprkey/firmware/usb_fido/piv/piv.c '
       f's:/hyprkey/firmware/usb_fido/sha256/sha256.c '
       f's:/hyprkey/firmware/usb_fido/sha512/sha512.c '
       f's:/hyprkey/firmware/usb_fido/ed25519/ed25519.c '
       f's:/hyprkey/firmware/usb_fido/micro_ecc/uECC.c '
       f's:/hyprkey/firmware/usb_fido/fips202/fips202.c '
       f's:/hyprkey/firmware/usb_fido/mlkem/mlkem.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_piv.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_piv.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_piv.elf s:/hyprkey/firmware/usb_fido/test_piv.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_piv.bin", "rb") as f: code = f.read()

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

# Init
uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
uc.emu_start(symbols['test_init'] | 1, 0x80000)

seq = 0
def send_ccid(msg_type, param0=0, param1=0, param2=0, data=b''):
    global seq
    header = bytearray(10)
    header[0] = msg_type
    l = len(data)
    header[1] = l & 0xFF
    header[2] = (l >> 8) & 0xFF
    header[3] = (l >> 16) & 0xFF
    header[4] = (l >> 24) & 0xFF
    header[5] = 0 # slot
    header[6] = seq
    seq = (seq + 1) & 0xFF
    header[7] = param0
    header[8] = param1
    header[9] = param2
    msg = bytes(header) + data

    uc.mem_write(symbols['g_ccid_req'], msg)
    uc.reg_write(ac.UC_ARM_REG_R0, len(msg))
    uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
    uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
    uc.emu_start(symbols['run_ccid'] | 1, 0x80000)

    rsp_len = uc.mem_read(symbols['g_ccid_rsp_len'], 2)
    rsp_len = int.from_bytes(rsp_len, 'little')
    rsp_buf = bytes(uc.mem_read(symbols['g_ccid_rsp'], rsp_len))
    r_type = rsp_buf[0]
    r_data_len = int.from_bytes(rsp_buf[1:5], 'little')
    r_slot = rsp_buf[5]
    r_seq = rsp_buf[6]
    r_status = rsp_buf[7]
    r_error = rsp_buf[8]
    r_data = rsp_buf[10:10+r_data_len]
    return r_type, r_status, r_error, r_data

# 1. Power on
_, _, _, atr = send_ccid(0x62)
print("ATR:", atr.hex())

# 2. SELECT PIV AID: A0 00 00 03 08 00 00 10 00 01 00
piv_aid = bytes.fromhex("A000000308000010000100")
sel_apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(piv_aid)]) + piv_aid
_, _, _, sel_rsp = send_ccid(0x6F, data=sel_apdu)
print("SELECT PIV AID response:", sel_rsp.hex())
assert sel_rsp[-2:] == b"\x90\x00"
assert sel_rsp[0] == 0x7E

# 3. GET DATA for CHUID (5FC102)
get_chuid_apdu = bytes.fromhex("00CB3FFF055C035FC10200")
_, _, _, chuid_rsp = send_ccid(0x6F, data=get_chuid_apdu)
assert chuid_rsp[-2:] == b"\x90\x00"
print("CHUID retrieved:", len(chuid_rsp), "bytes, SW:", chuid_rsp[-2:].hex())

# 4. GET DATA for CCC (5FC107)
get_ccc_apdu = bytes.fromhex("00CB3FFF055C035FC10700")
_, _, _, ccc_rsp = send_ccid(0x6F, data=get_ccc_apdu)
assert ccc_rsp[-2:] == b"\x90\x00"
print("CCC retrieved:", len(ccc_rsp), "bytes, SW:", ccc_rsp[-2:].hex())

# 5. GET DATA for Certificate in Slot 9A (5FC105)
get_cert_apdu = bytes.fromhex("00CB3FFF055C035FC10500")
_, _, _, cert_rsp = send_ccid(0x6F, data=get_cert_apdu)
assert cert_rsp[-2:] == b"\x90\x00"
print("Cert 9A container len:", len(cert_rsp), "bytes")

# Unpack Tag 0x53 and Tag 0x70
container = cert_rsp[:-2]
assert container[0] == 0x53
# Find tag 0x70
idx_70 = container.find(b"\x70")
assert idx_70 != -1
# parse length of tag 0x70
if container[idx_70+1] == 0x82:
    cert_len = (container[idx_70+2] << 8) | container[idx_70+3]
    cert_der = container[idx_70+4 : idx_70+4+cert_len]
else:
    cert_len = container[idx_70+1]
    cert_der = container[idx_70+2 : idx_70+2+cert_len]

cert = x509.load_der_x509_certificate(cert_der)
print(f"Loaded X.509 Certificate: Subject = '{cert.subject.rfc4514_string()}', Serial = {hex(cert.serial_number)}")
assert "hyprkey PIV Authentication" in cert.subject.rfc4514_string()

# Cryptographically verify self-signature of certificate!
cert_pub = cert.public_key()
# Verification: self-signed
cert_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
print("[PASS] PIV Slot 9A Self-Signed X.509 Certificate is Cryptographically VALID!")

# 6. VERIFY PIN
# Default PIN "123456"
verify_pin = bytes.fromhex("0020008008313233343536FFFF")
_, _, _, pin_rsp = send_ccid(0x6F, data=verify_pin)
assert pin_rsp == b"\x90\x00"
print("[PASS] PIV PIN Verified successfully!")

# 7. GENERAL AUTHENTICATE on Slot 9A (Digital Signature)
# Challenge data: 32 bytes SHA-256 hash
test_chal = hashlib.sha256(b"HYPRKEY-WINDOWS-SMARTCARD-LOGON-CHALLENGE").digest()
# Dynamic Auth Template 7C with Tag 81 (challenge) and Tag 82 (empty)
t7c = bytes([0x7C, len(test_chal) + 4, 0x81, len(test_chal)]) + test_chal + bytes([0x82, 0x00])
auth_apdu = bytes([0x00, 0x87, 0x11, 0x9A, len(t7c)]) + t7c
_, _, _, auth_rsp = send_ccid(0x6F, data=auth_apdu)
assert auth_rsp[-2:] == b"\x90\x00"
assert auth_rsp[0] == 0x7C
# Find tag 82
idx_82 = auth_rsp.find(b"\x82")
sig_len = auth_rsp[idx_82+1]
der_sig = auth_rsp[idx_82+2 : idx_82+2+sig_len]

cert_pub.verify(der_sig, test_chal, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
print("[PASS] GENERAL AUTHENTICATE ECDSA Signature verified against Certificate Public Key 100%!")

# 8. GENERAL AUTHENTICATE ECDH on Slot 9D (Key Agreement)
# Generate ephemeral key in Python
ephem_priv = ec.generate_private_key(ec.SECP256R1())
ephem_pub_bytes = ephem_priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

# Read Slot 9D public key
gen_9d_apdu = bytes.fromhex("0047009D00")
_, _, _, gen_9d_rsp = send_ccid(0x6F, data=gen_9d_apdu)
assert gen_9d_rsp[-2:] == b"\x90\x00"
idx_86 = gen_9d_rsp.find(b"\x86\x41")
card_9d_pub_bytes = gen_9d_rsp[idx_86+2 : idx_86+2+65]
card_9d_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), card_9d_pub_bytes)

# Send ECDH request to card (Tag 85 with peer pubkey, Tag 82 empty)
t7c_ecdh = bytes([0x7C, 65 + 4, 0x85, 65]) + ephem_pub_bytes + bytes([0x82, 0x00])
ecdh_apdu = bytes([0x00, 0x87, 0x11, 0x9D, len(t7c_ecdh)]) + t7c_ecdh
_, _, _, ecdh_rsp = send_ccid(0x6F, data=ecdh_apdu)
assert ecdh_rsp[-2:] == b"\x90\x00"
idx_82 = ecdh_rsp.find(b"\x82\x20")
card_shared_secret = ecdh_rsp[idx_82+2 : idx_82+2+32]

# Compute Python expected shared secret
py_shared_secret = ephem_priv.exchange(ec.ECDH(), card_9d_pub)
assert card_shared_secret == py_shared_secret
print("[PASS] GENERAL AUTHENTICATE ECDH Key Agreement verified against Python 100%!")

# 8b. PIV Ed25519 (Alg 0x22) Public Key Generation & Signature
gen_ed_apdu = bytes.fromhex("0047229A00")
_, _, _, gen_ed_rsp = send_ccid(0x6F, data=gen_ed_apdu)
assert gen_ed_rsp[-2:] == b"\x90\x00"
idx_86 = gen_ed_rsp.find(b"\x86\x20") # Tag 86, 32 bytes
ed_pub_bytes = gen_ed_rsp[idx_86+2 : idx_86+2+32]
print(f"[PASS] PIV Ed25519 Generated Public Key: {ed_pub_bytes.hex()}")

# Sign with Ed25519 (Alg 0x22)
t7c_ed = bytes([0x7C, 32 + 4, 0x81, 32]) + test_chal + bytes([0x82, 0x00])
auth_ed_apdu = bytes([0x00, 0x87, 0x22, 0x9A, len(t7c_ed)]) + t7c_ed
_, _, _, auth_ed_rsp = send_ccid(0x6F, data=auth_ed_apdu)
assert auth_ed_rsp[-2:] == b"\x90\x00"
idx_82 = auth_ed_rsp.find(b"\x82\x40") # Tag 82, 64 bytes
ed_sig_bytes = auth_ed_rsp[idx_82+2 : idx_82+2+64]
assert len(ed_sig_bytes) == 64

# Verify using Python's Ed25519
ed_pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
ed_pub_obj.verify(ed_sig_bytes, test_chal)
print("[PASS] PIV Ed25519 (Alg 0x22) Signature verified against Python cryptography 100%!")

# 9. Verify multi-applet switching back to OpenPGP!
sel_openpgp = bytes([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
_, _, _, sel_opgp_rsp = send_ccid(0x6F, data=sel_openpgp)
assert sel_opgp_rsp == b"\x90\x00"
print("[PASS] Seamlessly switched back to OpenPGP Applet!")

print("\nALL PIV (NIST SP 800-73-4) TESTS PASSED WITH 100% SUCCESS!")

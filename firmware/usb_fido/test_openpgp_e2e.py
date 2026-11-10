import unicorn, unicorn.arm_const as ac
import subprocess, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

runner_c = """
#include "ccid/ccid.h"
#include "openpgp/openpgp.h"
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

with open("s:/hyprkey/firmware/usb_fido/runner_openpgp.c", "w") as f:
    f.write(runner_c)

cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f'-I s:/hyprkey/firmware/usb_fido '
       f'-I s:/hyprkey/firmware/usb_fido/ccid '
       f'-I s:/hyprkey/firmware/usb_fido/openpgp '
       f'-I s:/hyprkey/firmware/usb_fido/sha256 '
       f'-I s:/hyprkey/firmware/usb_fido/micro_ecc '
       f'-I s:/hyprkey/firmware/usb_fido/fips202 '
       f'-I s:/hyprkey/firmware/usb_fido/mlkem '
       f'-DuECC_CURVE=uECC_secp256r1 '
       f's:/hyprkey/firmware/usb_fido/runner_openpgp.c '
       f's:/hyprkey/firmware/usb_fido/ccid/ccid.c '
       f's:/hyprkey/firmware/usb_fido/openpgp/openpgp.c '
       f's:/hyprkey/firmware/usb_fido/sha256/sha256.c '
       f's:/hyprkey/firmware/usb_fido/micro_ecc/uECC.c '
       f's:/hyprkey/firmware/usb_fido/fips202/fips202.c '
       f's:/hyprkey/firmware/usb_fido/mlkem/mlkem.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_openpgp.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_openpgp.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_openpgp.elf s:/hyprkey/firmware/usb_fido/test_openpgp.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_openpgp.bin", "rb") as f: code = f.read()

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
    header[5] = 0 # slot 0
    header[6] = seq
    header[7] = param0
    header[8] = param1
    header[9] = param2
    seq = (seq + 1) & 0xFF

    pkt = bytes(header) + data
    uc.mem_write(symbols['g_ccid_req'], pkt)
    uc.reg_write(ac.UC_ARM_REG_R0, len(pkt))
    uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
    uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
    uc.emu_start(symbols['run_ccid'] | 1, 0x80000)

    rsp_len_bytes = uc.mem_read(symbols['g_ccid_rsp_len'], 2)
    rsp_len = int.from_bytes(rsp_len_bytes, 'little')
    rsp_data = bytes(uc.mem_read(symbols['g_ccid_rsp'], rsp_len))
    r_type = rsp_data[0]
    r_len = int.from_bytes(rsp_data[1:5], 'little')
    r_slot = rsp_data[5]
    r_seq = rsp_data[6]
    r_status = rsp_data[7]
    r_error = rsp_data[8]
    r_data = rsp_data[10:10+r_len]
    return r_type, r_status, r_error, r_data

# 1. Test PC_to_RDR_IccPowerOn
print("1. Testing PC_to_RDR_IccPowerOn...")
r_type, r_status, r_err, atr = send_ccid(0x62)
print(f"ATR len: {len(atr)}, hex: {atr.hex()}")
assert r_type == 0x80 # RDR_to_PC_DataBlock
assert r_status == 0x00 # Active
assert atr.startswith(b"\x3B\xDA")
print("IccPowerOn OK!\n")

# 2. Test Select OpenPGP AID
print("2. Testing SELECT AID (D27600012401)...")
aid = bytes.fromhex("D27600012401")
select_apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
r_type, r_status, r_err, data = send_ccid(0x6F, data=select_apdu)
print(f"Select response: {data.hex()}")
assert data == b"\x90\x00"
print("SELECT AID OK!\n")

# 3. Test GET DATA (00 4F - AID)
print("3. Testing GET DATA 00 4F (AID)...")
get_aid_apdu = bytes([0x00, 0xCA, 0x00, 0x4F, 0x00])
r_type, r_status, r_err, data = send_ccid(0x6F, data=get_aid_apdu)
assert data[-2:] == b"\x90\x00"
card_aid = data[:-2]
print(f"Card AID ({len(card_aid)} bytes): {card_aid.hex()}")
assert card_aid.startswith(aid)
print("GET AID OK!\n")

# 4. Test GET DATA (00 6E - Application Related Data)
print("4. Testing GET DATA 00 6E (Application Related Data)...")
get_6e_apdu = bytes([0x00, 0xCA, 0x00, 0x6E, 0x00])
r_type, r_status, r_err, data = send_ccid(0x6F, data=get_6e_apdu)
assert data[-2:] == b"\x90\x00"
do_6e = data[:-2]
print(f"DO 6E len: {len(do_6e)} bytes")
assert do_6e[0] == 0x6E # Tag 6E
print("DO 6E OK!\n")

# 5. Test GENERATE ASYMMETRIC KEY PAIR (00 47 80 00) for Signature Key
print("5. Testing GENERATE ASYMMETRIC KEY PAIR for Signature Key...")
gen_apdu = bytes([0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00])
# First verify Admin PIN (PW3: "12345678")
verify_pw3 = bytes([0x00, 0x20, 0x00, 0x83, 0x08]) + b"12345678"
_, _, _, v_resp = send_ccid(0x6F, data=verify_pw3)
assert v_resp == b"\x90\x00"
print("PW3 Verified successfully!")

_, _, _, gen_resp = send_ccid(0x6F, data=gen_apdu)
assert gen_resp[-2:] == b"\x90\x00"
# Format is 7F 49 <len> 86 41 04 <x> <y>
pub_tlv = gen_resp[:-2]
print(f"Public Key TLV len: {len(pub_tlv)}, hex: {pub_tlv.hex()[:30]}...")
# Extract public key point (65 bytes: 0x04 || X || Y)
pt_idx = pub_tlv.find(b"\x86\x41")
assert pt_idx != -1
pubkey_raw = pub_tlv[pt_idx+2 : pt_idx+2+65]
assert pubkey_raw[0] == 0x04
print("Public key extracted successfully (65 bytes uncompressed point)!\n")

# 6. Test PSO: COMPUTE DIGITAL SIGNATURE
print("6. Testing PSO: COMPUTE DIGITAL SIGNATURE...")
# Verify PW1 (User PIN "123456")
verify_pw1 = bytes([0x00, 0x20, 0x00, 0x81, 0x06]) + b"123456"
_, _, _, v1_resp = send_ccid(0x6F, data=verify_pw1)
assert v1_resp == b"\x90\x00"
print("PW1 Verified successfully!")

test_msg = b"Git Commit: Add Post-Quantum FIDO2 and OpenPGP"
digest = hashlib.sha256(test_msg).digest()
sign_apdu = bytes([0x00, 0x2A, 0x9E, 0x9A, len(digest)]) + digest
_, _, _, sign_resp = send_ccid(0x6F, data=sign_apdu)
assert sign_resp[-2:] == b"\x90\x00"
sig_bytes = sign_resp[:-2]
print(f"Signature ({len(sig_bytes)} bytes): {sig_bytes.hex()}")
assert len(sig_bytes) == 64
r = int.from_bytes(sig_bytes[:32], 'big')
s = int.from_bytes(sig_bytes[32:], 'big')

# Cryptography ECDSA Verification
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
der_sig = encode_dss_signature(r, s)
peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey_raw)
peer_pub.verify(der_sig, test_msg, ec.ECDSA(hashes.SHA256()))
print("CRYPTOGRAPHY VERIFIED OPENPGP SECP256R1 SIGNATURE: 100% SUCCESS!\n")

# 7. Test INTERNAL AUTHENTICATE (SSH Authentication)
print("7. Testing INTERNAL AUTHENTICATE (SSH login)...")
# Verify PW1 mode 82
verify_pw1_aut = bytes([0x00, 0x20, 0x00, 0x82, 0x06]) + b"123456"
_, _, _, v_aut = send_ccid(0x6F, data=verify_pw1_aut)
assert v_aut == b"\x90\x00"

ssh_challenge = hashlib.sha256(b"SSH-AGENT-CHALLENGE-2026").digest()
ssh_apdu = bytes([0x00, 0x88, 0x00, 0x00, len(ssh_challenge)]) + ssh_challenge
_, _, _, ssh_resp = send_ccid(0x6F, data=ssh_apdu)
assert ssh_resp[-2:] == b"\x90\x00"
ssh_sig_bytes = ssh_resp[:-2]
assert len(ssh_sig_bytes) == 64
print(f"SSH Signature len: {len(ssh_sig_bytes)} bytes")

# Extract Aut public key
gen_aut_apdu = bytes([0x00, 0x47, 0x80, 0x00, 0x02, 0xA4, 0x00])
_, _, _, gen_aut_resp = send_ccid(0x6F, data=gen_aut_apdu)
assert gen_aut_resp[-2:] == b"\x90\x00"
aut_tlv = gen_aut_resp[:-2]
pt_idx = aut_tlv.find(b"\x86\x41")
aut_pubkey_raw = aut_tlv[pt_idx+2 : pt_idx+2+65]
aut_peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), aut_pubkey_raw)

r_aut = int.from_bytes(ssh_sig_bytes[:32], 'big')
s_aut = int.from_bytes(ssh_sig_bytes[32:], 'big')
der_ssh = encode_dss_signature(r_aut, s_aut)
aut_peer_pub.verify(der_ssh, b"SSH-AGENT-CHALLENGE-2026", ec.ECDSA(hashes.SHA256()))
print("CRYPTOGRAPHY VERIFIED SSH AUTHENTICATION SIGNATURE: 100% SUCCESS!\n")

# 8. Test Post-Quantum ML-KEM-768 Deciphering via OpenPGP Smart Card (Draft PQC)
print("8. Testing Post-Quantum ML-KEM-768 Deciphering (Extended APDU)...")
from cryptography.hazmat.primitives.asymmetric import mlkem

# Read ML-KEM-768 public key via GET DATA 0x00D6
get_pqc_apdu = bytes([0x00, 0xCA, 0x00, 0xD6, 0x00])
_, _, _, pqc_resp = send_ccid(0x6F, data=get_pqc_apdu)
assert pqc_resp[-2:] == b"\x90\x00"
pqc_pk_bytes = pqc_resp[:-2]
print(f"Retrieved ML-KEM-768 Public Key: {len(pqc_pk_bytes)} bytes")
assert len(pqc_pk_bytes) == 1184

# Python encapsulates against the card's ML-KEM public key
pqc_pubkey = mlkem.MLKEM768PublicKey.from_public_bytes(pqc_pk_bytes)
shared_secret_ref, ciphertext = pqc_pubkey.encapsulate()
print(f"Generated ML-KEM-768 Ciphertext: {len(ciphertext)} bytes")
print(f"Python Shared Secret: {shared_secret_ref.hex()}")

# Send PSO: DECIPHER (0x2A) with Extended APDU
# Extended APDU Header: 00 2A 86 80 00 L1 L2 (Lc = 1088 = 0x0440)
l1 = (len(ciphertext) >> 8) & 0xFF
l2 = len(ciphertext) & 0xFF
decipher_ext_apdu = bytes([0x00, 0x2A, 0x86, 0x80, 0x00, l1, l2]) + ciphertext
_, _, _, decipher_resp = send_ccid(0x6F, data=decipher_ext_apdu)
assert decipher_resp[-2:] == b"\x90\x00", f"Decipher failed with SW: {decipher_resp[-2:].hex()}"
card_shared_secret = decipher_resp[:-2]
print(f"Card Decrypted Shared Secret: {card_shared_secret.hex()}")
assert card_shared_secret == shared_secret_ref, "Shared secret mismatch!"
print("CRYPTOGRAPHY VERIFIED OPENPGP ML-KEM-768 POST-QUANTUM DECIPHER: 100% SUCCESS!\n")

print("ALL OPENPGP CARD 3.4 & CCID & POST-QUANTUM ML-KEM TESTS PASSED WITH 100% SUCCESS!")

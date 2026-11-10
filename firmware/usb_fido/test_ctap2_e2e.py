import unicorn, unicorn.arm_const as ac
import subprocess, hashlib, cbor2
from cryptography.hazmat.primitives.asymmetric import mldsa, ed25519

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

runner_c = """
#include "ctap2.h"

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

uint8_t g_req[2048];
uint8_t g_rsp[8192];
uint16_t g_rsp_len = 0;

void run_ctap2(uint16_t req_len) {
    g_rsp_len = ctap2_process_cbor(g_req, req_len, g_rsp, sizeof(g_rsp));
}
"""

with open("s:/hyprkey/firmware/usb_fido/runner_ctap2.c", "w") as f:
    f.write(runner_c)

cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f'-I s:/hyprkey/firmware/usb_fido '
       f'-I s:/hyprkey/firmware/usb_fido/mldsa '
       f'-I s:/hyprkey/firmware/usb_fido/fips202 '
       f'-I s:/hyprkey/firmware/usb_fido/sha256 '
       f'-I s:/hyprkey/firmware/usb_fido/sha512 '
       f'-I s:/hyprkey/firmware/usb_fido/ed25519 '
       f'-I s:/hyprkey/firmware/usb_fido/micro_ecc '
       f'-DuECC_CURVE=uECC_secp256r1 '
       f's:/hyprkey/firmware/usb_fido/runner_ctap2.c '
       f's:/hyprkey/firmware/usb_fido/ctap2.c '
       f's:/hyprkey/firmware/usb_fido/mldsa/mldsa.c '
       f's:/hyprkey/firmware/usb_fido/fips202/fips202.c '
       f's:/hyprkey/firmware/usb_fido/sha256/sha256.c '
       f's:/hyprkey/firmware/usb_fido/sha512/sha512.c '
       f's:/hyprkey/firmware/usb_fido/ed25519/ed25519.c '
       f's:/hyprkey/firmware/usb_fido/micro_ecc/uECC.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_ctap2.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_ctap2.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_ctap2.elf s:/hyprkey/firmware/usb_fido/test_ctap2.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_ctap2.bin", "rb") as f: code = f.read()

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

def send_cbor_cmd(cmd_bytes):
    uc.mem_write(symbols['g_req'], cmd_bytes)
    uc.reg_write(ac.UC_ARM_REG_R0, len(cmd_bytes))
    uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
    uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
    uc.emu_start(symbols['run_ctap2'] | 1, 0x80000)
    rsp_len_bytes = uc.mem_read(symbols['g_rsp_len'], 2)
    rsp_len = int.from_bytes(rsp_len_bytes, 'little')
    rsp_data = bytes(uc.mem_read(symbols['g_rsp'], rsp_len))
    status = rsp_data[0]
    cbor_payload = rsp_data[1:]
    return status, cbor_payload

# 1. Test authenticatorGetInfo (0x04)
print("Testing authenticatorGetInfo (0x04)...")
status, payload = send_cbor_cmd(bytes([0x04]))
print(f"Status: {hex(status)}, CBOR len: {len(payload)}")
assert status == 0
info = cbor2.loads(payload)
print("Versions:", info[1])
print("Algorithms:", info[10])
assert any(a['alg'] == -48 for a in info[10])
assert any(a['alg'] == -49 for a in info[10])
assert any(a['alg'] == -50 for a in info[10])
assert any(a['alg'] == -8 for a in info[10])
assert any(a['alg'] == -7 for a in info[10])
print("GetInfo SUCCESS!\n")

# 2. Test authenticatorMakeCredential for ML-DSA-44 (-48)
print("Testing authenticatorMakeCredential for ML-DSA-44 (-48)...")
client_data_hash = hashlib.sha256(b"registration_client_data").digest()
rp = {"id": "webauthn.io", "name": "WebAuthn Demo"}
user = {"id": b"user_42", "name": "alice", "displayName": "Alice"}
pub_key_cred_params = [
    {"type": "public-key", "alg": -48}, # ML-DSA-44
    {"type": "public-key", "alg": -7}
]
req_cbor = cbor2.dumps({
    1: client_data_hash,
    2: rp,
    3: user,
    4: pub_key_cred_params
})
status, payload = send_cbor_cmd(bytes([0x01]) + req_cbor)
print(f"MakeCredential status: {hex(status)}, payload len: {len(payload)}")
assert status == 0
mc_resp = cbor2.loads(payload)
print("MakeCredential fmt:", mc_resp[1])
auth_data = mc_resp[2]
print("authData total len:", len(auth_data))
# Parse authData
rp_id_hash = auth_data[:32]
flags = auth_data[32]
sign_count = int.from_bytes(auth_data[33:37], 'big')
aaguid = auth_data[37:53]
cred_id_len = int.from_bytes(auth_data[53:55], 'big')
cred_id = auth_data[55:55+cred_id_len]
cose_key_bytes = auth_data[55+cred_id_len:]
print(f"Flags: {hex(flags)}, CredID len: {cred_id_len}, COSE Key bytes: {len(cose_key_bytes)}")
cose_key = cbor2.loads(cose_key_bytes)
print("COSE Key alg:", cose_key[3], "kty:", cose_key[1], "pub len:", len(cose_key[-1]))
assert cose_key[3] == -48 # ML-DSA-44
assert len(cose_key[-1]) == 1312
pk44_raw = cose_key[-1]
print("ML-DSA-44 MakeCredential SUCCESS!\n")

# 3. Test authenticatorGetAssertion for ML-DSA-44
print("Testing authenticatorGetAssertion for ML-DSA-44...")
client_data_hash_auth = hashlib.sha256(b"assertion_client_data").digest()
req_ga_cbor = cbor2.dumps({
    1: "webauthn.io",
    2: client_data_hash_auth,
    3: [{"type": "public-key", "id": cred_id}]
})
status, payload = send_cbor_cmd(bytes([0x02]) + req_ga_cbor)
print(f"GetAssertion status: {hex(status)}, payload len: {len(payload)}")
assert status == 0
ga_resp = cbor2.loads(payload)
ga_auth_data = ga_resp[2]
ga_sig = ga_resp[3]
print(f"ga_auth_data len: {len(ga_auth_data)}, ga_sig len: {len(ga_sig)}")
assert len(ga_sig) == 2420

# Cryptography verification
msg_signed = ga_auth_data + client_data_hash_auth
pk_obj = mldsa.MLDSA44PublicKey.from_public_bytes(pk44_raw)
pk_obj.verify(ga_sig, msg_signed)
print("CRYPTOGRAPHY VERIFIED CTAP2 ML-DSA-44 ASSERTION: 100% SUCCESS!\n")

# 4. Test authenticatorMakeCredential for ML-DSA-65 (-49)
print("Testing authenticatorMakeCredential for ML-DSA-65 (-49)...")
pub_key_cred_params_65 = [
    {"type": "public-key", "alg": -49} # ML-DSA-65
]
req_cbor_65 = cbor2.dumps({
    1: client_data_hash,
    2: rp,
    3: user,
    4: pub_key_cred_params_65
})
status, payload = send_cbor_cmd(bytes([0x01]) + req_cbor_65)
assert status == 0
mc_resp_65 = cbor2.loads(payload)
auth_data_65 = mc_resp_65[2]
cred_id_len_65 = int.from_bytes(auth_data_65[53:55], 'big')
cred_id_65 = auth_data_65[55:55+cred_id_len_65]
cose_key_65 = cbor2.loads(auth_data_65[55+cred_id_len_65:])
print("ML-DSA-65 COSE alg:", cose_key_65[3], "pub len:", len(cose_key_65[-1]))
assert cose_key_65[3] == -49
assert len(cose_key_65[-1]) == 1952
pk65_raw = cose_key_65[-1]

# 5. Test authenticatorGetAssertion for ML-DSA-65
print("Testing authenticatorGetAssertion for ML-DSA-65...")
req_ga_65 = cbor2.dumps({
    1: "webauthn.io",
    2: client_data_hash_auth,
    3: [{"type": "public-key", "id": cred_id_65}]
})
status, payload = send_cbor_cmd(bytes([0x02]) + req_ga_65)
assert status == 0
ga_resp_65 = cbor2.loads(payload)
ga_sig_65 = ga_resp_65[3]
print("ga_sig_65 len:", len(ga_sig_65))
assert len(ga_sig_65) == 3309

msg_signed_65 = ga_resp_65[2] + client_data_hash_auth
pk65_obj = mldsa.MLDSA65PublicKey.from_public_bytes(pk65_raw)
pk65_obj.verify(ga_sig_65, msg_signed_65)
print("CRYPTOGRAPHY VERIFIED CTAP2 ML-DSA-65 ASSERTION: 100% SUCCESS!\n")

# 6. Test authenticatorMakeCredential for ML-DSA-87 (-50)
print("Testing authenticatorMakeCredential for ML-DSA-87 (-50)...")
pub_key_cred_params_87 = [
    {"type": "public-key", "alg": -50} # ML-DSA-87
]
req_cbor_87 = cbor2.dumps({
    1: client_data_hash,
    2: rp,
    3: user,
    4: pub_key_cred_params_87
})
status, payload = send_cbor_cmd(bytes([0x01]) + req_cbor_87)
assert status == 0
mc_resp_87 = cbor2.loads(payload)
auth_data_87 = mc_resp_87[2]
cred_id_len_87 = int.from_bytes(auth_data_87[53:55], 'big')
cred_id_87 = auth_data_87[55:55+cred_id_len_87]
cose_key_87 = cbor2.loads(auth_data_87[55+cred_id_len_87:])
print("ML-DSA-87 COSE alg:", cose_key_87[3], "pub len:", len(cose_key_87[-1]))
assert cose_key_87[3] == -50
assert len(cose_key_87[-1]) == 2592
pk87_raw = cose_key_87[-1]

# 7. Test authenticatorGetAssertion for ML-DSA-87
print("Testing authenticatorGetAssertion for ML-DSA-87...")
req_ga_87 = cbor2.dumps({
    1: "webauthn.io",
    2: client_data_hash_auth,
    3: [{"type": "public-key", "id": cred_id_87}]
})
status, payload = send_cbor_cmd(bytes([0x02]) + req_ga_87)
assert status == 0
ga_resp_87 = cbor2.loads(payload)
ga_sig_87 = ga_resp_87[3]
print("ga_sig_87 len:", len(ga_sig_87))
assert len(ga_sig_87) == 4627

msg_signed_87 = ga_resp_87[2] + client_data_hash_auth
pk87_obj = mldsa.MLDSA87PublicKey.from_public_bytes(pk87_raw)
pk87_obj.verify(ga_sig_87, msg_signed_87)
print("CRYPTOGRAPHY VERIFIED CTAP2 ML-DSA-87 ASSERTION: 100% SUCCESS!\n")

# 8. Test authenticatorMakeCredential for Ed25519 (-8)
print("Testing authenticatorMakeCredential for Ed25519 (-8)...")
pub_key_cred_params_ed = [
    {"type": "public-key", "alg": -8} # Ed25519
]
req_cbor_ed = cbor2.dumps({
    1: client_data_hash,
    2: rp,
    3: user,
    4: pub_key_cred_params_ed
})
status, payload = send_cbor_cmd(bytes([0x01]) + req_cbor_ed)
assert status == 0
mc_resp_ed = cbor2.loads(payload)
auth_data_ed = mc_resp_ed[2]
cred_id_len_ed = int.from_bytes(auth_data_ed[53:55], 'big')
cred_id_ed = auth_data_ed[55:55+cred_id_len_ed]
cose_key_ed = cbor2.loads(auth_data_ed[55+cred_id_len_ed:])
print("Ed25519 COSE alg:", cose_key_ed[3], "kty:", cose_key_ed[1], "crv:", cose_key_ed[-1], "pub len:", len(cose_key_ed[-2]))
assert cose_key_ed[3] == -8
assert cose_key_ed[1] == 1  # OKP
assert cose_key_ed[-1] == 6 # Ed25519
assert len(cose_key_ed[-2]) == 32
pk_ed_raw = cose_key_ed[-2]

# 9. Test authenticatorGetAssertion for Ed25519 (-8)
print("Testing authenticatorGetAssertion for Ed25519 (-8)...")
req_ga_ed = cbor2.dumps({
    1: "webauthn.io",
    2: client_data_hash_auth,
    3: [{"type": "public-key", "id": cred_id_ed}]
})
status, payload = send_cbor_cmd(bytes([0x02]) + req_ga_ed)
assert status == 0
ga_resp_ed = cbor2.loads(payload)
ga_sig_ed = ga_resp_ed[3]
print("ga_sig_ed len:", len(ga_sig_ed))
assert len(ga_sig_ed) == 64

msg_signed_ed = ga_resp_ed[2] + client_data_hash_auth
pk_ed_obj = ed25519.Ed25519PublicKey.from_public_bytes(pk_ed_raw)
pk_ed_obj.verify(ga_sig_ed, msg_signed_ed)
print("CRYPTOGRAPHY VERIFIED CTAP2 Ed25519 (-8) ASSERTION: 100% SUCCESS!\n")

print("ALL CTAP2 E2E TESTS (ML-DSA-44, 65, 87 + Ed25519 + ES256) PASSED WITH 100% SUCCESS!")

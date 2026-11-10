import ctypes
from ctypes import wintypes
import time
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

winscard = ctypes.windll.winscard

SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0  = 1
SCARD_PROTOCOL_T1  = 2

class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [
        ("dwProtocol", wintypes.DWORD),
        ("cbPciLength", wintypes.DWORD),
    ]

winscard.SCardEstablishContext.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
winscard.SCardEstablishContext.restype  = wintypes.LONG

winscard.SCardListReadersA.argtypes = [ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(wintypes.DWORD)]
winscard.SCardListReadersA.restype  = wintypes.LONG

winscard.SCardConnectA.argtypes = [ctypes.c_size_t, ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(wintypes.DWORD)]
winscard.SCardConnectA.restype  = wintypes.LONG

winscard.SCardTransmit.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_char_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(wintypes.DWORD)]
winscard.SCardTransmit.restype  = wintypes.LONG

winscard.SCardDisconnect.argtypes = [ctypes.c_size_t, wintypes.DWORD]
winscard.SCardDisconnect.restype  = wintypes.LONG

winscard.SCardReleaseContext.argtypes = [ctypes.c_size_t]
winscard.SCardReleaseContext.restype  = wintypes.LONG

ctx = ctypes.c_size_t()
rc = winscard.SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, ctypes.byref(ctx))
assert rc == 0, f"SCardEstablishContext failed: {hex(rc)}"

m = wintypes.DWORD(0)
winscard.SCardListReadersA(ctx, None, None, ctypes.byref(m))
buf = ctypes.create_string_buffer(m.value)
winscard.SCardListReadersA(ctx, None, buf, ctypes.byref(m))
readers = [r for r in buf.raw[:m.value].split(b'\x00') if r]

target_reader = None
for r in readers:
    if b"hyprkey" in r:
        target_reader = r
        break

assert target_reader is not None, "hyprkey CCID reader not found!"
print(f"Connecting to: {target_reader.decode('latin1')}")

hCard = ctypes.c_size_t()
activeProto = wintypes.DWORD()
rc = winscard.SCardConnectA(
    ctx.value, target_reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
    ctypes.byref(hCard), ctypes.byref(activeProto)
)
assert rc == 0, f"SCardConnectA failed: {hex(rc)}"

pci_t1 = ctypes.c_void_p.in_dll(winscard, "g_rgSCardT1Pci")
pci_t0 = ctypes.c_void_p.in_dll(winscard, "g_rgSCardT0Pci")

def transmit(apdu_bytes):
    send_buf = ctypes.create_string_buffer(apdu_bytes)
    recv_buf = ctypes.create_string_buffer(6144)
    recv_len = wintypes.DWORD(6144)
    pci_send = ctypes.byref(pci_t1) if activeProto.value == SCARD_PROTOCOL_T1 else ctypes.byref(pci_t0)
    r = winscard.SCardTransmit(
        hCard.value, pci_send, send_buf, len(apdu_bytes),
        None, recv_buf, ctypes.byref(recv_len)
    )
    assert r == 0, f"SCardTransmit failed: {hex(r)}"
    return bytes(recv_buf.raw[:recv_len.value])

print("\n=======================================================")
print("  LIVE FULL POST-QUANTUM CRYPTO TEST ON PHYSICAL KEY   ")
print("=======================================================")

# 1. SELECT OpenPGP AID
aid = bytes.fromhex("D27600012401")
select_apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
rsp = transmit(select_apdu)
assert rsp[-2:] == b"\x90\x00", f"SELECT AID failed: {rsp.hex()}"
print("[PASS] SELECT OpenPGP AID: 90 00")

# 2. VERIFY PW1 (123456)
v_pw1 = bytes([0x00, 0x20, 0x00, 0x81, 0x06]) + b"123456"
assert transmit(v_pw1) == b"\x90\x00"
v_pw1_other = bytes([0x00, 0x20, 0x00, 0x82, 0x06]) + b"123456"
assert transmit(v_pw1_other) == b"\x90\x00"
print("[PASS] VERIFY PW1 User PIN accepted!")

# =====================================================================
# TEST 1: ML-KEM-768 (Kyber-768, NIST Category 3)
# =====================================================================
print("\n--- [1/4] ML-KEM-768 (Kyber-768, NIST Cat 3) ---")
# Extended APDU to read Public Key (role 0xBA)
read_pk_apdu = bytes([0x00, 0x47, 0x81, 0x00, 0x02, 0xBA, 0x00])
t0 = time.time()
rsp = transmit(read_pk_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Read PK failed: {rsp.hex()}"
pk768 = rsp[9:-2]
assert len(pk768) == 1184, f"PK768 length mismatch: {len(pk768)}"
print(f"  ✔ ML-KEM-768 Public Key read dynamically ({dt:.1f}ms): {len(pk768)} bytes")

# Encapsulate with Python
py_pk768 = mlkem.MLKEM768PublicKey.from_public_bytes(pk768)
py_ss768, py_ct768 = py_pk768.encapsulate()

# Decapsulate on card: Extended APDU: 00 2A 86 80 00 [len_hi] [len_lo] [ct]
ext_dec_apdu = bytes([0x00, 0x2A, 0x86, 0x80, 0x00, (len(py_ct768) >> 8) & 0xFF, len(py_ct768) & 0xFF]) + py_ct768
t0 = time.time()
rsp = transmit(ext_dec_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Decaps failed: {rsp.hex()}"
card_ss768 = rsp[:-2]
assert card_ss768 == py_ss768, f"SS mismatch! Card={card_ss768.hex()} Py={py_ss768.hex()}"
print(f"  ✔ ML-KEM-768 Decapsulation verified ({dt:.1f}ms)! Shared secret: {card_ss768.hex()[:24]}...")

# =====================================================================
# TEST 2: ML-KEM-1024 (Kyber-1024, NIST Category 5 - Military Grade)
# =====================================================================
print("\n--- [2/4] ML-KEM-1024 (Kyber-1024, NIST Cat 5 - Maximum Level) ---")
read_pk_apdu = bytes([0x00, 0x47, 0x81, 0x00, 0x02, 0xBB, 0x00])
t0 = time.time()
rsp = transmit(read_pk_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Read PK failed: {rsp.hex()}"
pk1024 = rsp[9:-2]
assert len(pk1024) == 1568, f"PK1024 length mismatch: {len(pk1024)}"
print(f"  ✔ ML-KEM-1024 Public Key read dynamically ({dt:.1f}ms): {len(pk1024)} bytes")

# Encapsulate with Python
py_pk1024 = mlkem.MLKEM1024PublicKey.from_public_bytes(pk1024)
py_ss1024, py_ct1024 = py_pk1024.encapsulate()

# Decapsulate on card
ext_dec_apdu = bytes([0x00, 0x2A, 0x86, 0x80, 0x00, (len(py_ct1024) >> 8) & 0xFF, len(py_ct1024) & 0xFF]) + py_ct1024
t0 = time.time()
rsp = transmit(ext_dec_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Decaps failed: {rsp.hex()}"
card_ss1024 = rsp[:-2]
assert card_ss1024 == py_ss1024, f"SS mismatch! Card={card_ss1024.hex()} Py={py_ss1024.hex()}"
print(f"  ✔ ML-KEM-1024 Decapsulation verified ({dt:.1f}ms)! Shared secret: {card_ss1024.hex()[:24]}...")

# =====================================================================
# TEST 3: ML-DSA-65 (Dilithium-65, NIST Category 3)
# =====================================================================
print("\n--- [3/4] ML-DSA-65 (Dilithium-65, NIST Cat 3) ---")
read_pk_apdu = bytes([0x00, 0x47, 0x81, 0x00, 0x02, 0xBC, 0x00])
t0 = time.time()
rsp = transmit(read_pk_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Read PK failed: {rsp.hex()}"
pk_dsa65 = rsp[9:-2]
assert len(pk_dsa65) == 1952, f"PK DSA65 length mismatch: {len(pk_dsa65)}"
print(f"  ✔ ML-DSA-65 Public Key read dynamically ({dt:.1f}ms): {len(pk_dsa65)} bytes")

# Sign message on card
test_msg = b"hyprkey live post-quantum ML-DSA-65 signature test"
# Re-verify PW1 before sign
assert transmit(v_pw1) == b"\x90\x00"
sign_apdu = bytes([0x00, 0x2A, 0xBC, 0x86, 0x00, (len(test_msg) >> 8) & 0xFF, len(test_msg) & 0xFF]) + test_msg
t0 = time.time()
rsp = transmit(sign_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Sign failed: {rsp.hex()}"
sig_dsa65 = rsp[:-2]
assert len(sig_dsa65) == 3309, f"Signature length mismatch: {len(sig_dsa65)}"

py_pk_dsa65 = mldsa.MLDSA65PublicKey.from_public_bytes(pk_dsa65)
py_pk_dsa65.verify(sig_dsa65, test_msg)
print(f"  ✔ ML-DSA-65 Signature verified ({dt:.1f}ms) with Python cryptography: 100% VALID!")

# =====================================================================
# TEST 4: ML-DSA-87 (Dilithium-87, NIST Category 5 - Maximum Level)
# =====================================================================
print("\n--- [4/4] ML-DSA-87 (Dilithium-87, NIST Cat 5 - Maximum Level) ---")
read_pk_apdu = bytes([0x00, 0x47, 0x81, 0x00, 0x02, 0xBD, 0x00])
t0 = time.time()
rsp = transmit(read_pk_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Read PK failed: {rsp.hex()}"
pk_dsa87 = rsp[9:-2]
assert len(pk_dsa87) == 2592, f"PK DSA87 length mismatch: {len(pk_dsa87)}"
print(f"  ✔ ML-DSA-87 Public Key read dynamically ({dt:.1f}ms): {len(pk_dsa87)} bytes")

# Sign message on card
test_msg87 = b"hyprkey live military-grade ML-DSA-87 signature test"
assert transmit(v_pw1) == b"\x90\x00"
sign_apdu = bytes([0x00, 0x2A, 0xBD, 0x86, 0x00, (len(test_msg87) >> 8) & 0xFF, len(test_msg87) & 0xFF]) + test_msg87
t0 = time.time()
rsp = transmit(sign_apdu)
dt = (time.time() - t0) * 1000
assert rsp[-2:] == b"\x90\x00", f"Sign failed: {rsp.hex()}"
sig_dsa87 = rsp[:-2]
assert len(sig_dsa87) == 4627, f"Signature length mismatch: {len(sig_dsa87)}"

py_pk_dsa87 = mldsa.MLDSA87PublicKey.from_public_bytes(pk_dsa87)
py_pk_dsa87.verify(sig_dsa87, test_msg87)
print(f"  ✔ ML-DSA-87 Signature verified ({dt:.1f}ms) with Python cryptography: 100% VALID!")

winscard.SCardDisconnect(hCard.value, 0)
winscard.SCardReleaseContext(ctx.value)

print("\n=======================================================")
print(" [SUCCESS] ALL 4 POST-QUANTUM ALGORITHMS FULLY VERIFIED!")
print("   - ML-KEM-768   (NIST Cat 3) [PASSED]")
print("   - ML-KEM-1024  (NIST Cat 5) [PASSED]")
print("   - ML-DSA-65    (NIST Cat 3) [PASSED]")
print("   - ML-DSA-87    (NIST Cat 5) [PASSED]")
print("=======================================================")

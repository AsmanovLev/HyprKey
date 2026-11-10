import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.asymmetric import ed25519

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

# Establish context
ctx = ctypes.c_size_t()
rc = winscard.SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, ctypes.byref(ctx))
assert rc == 0, f"SCardEstablishContext failed: {hex(rc)}"

# List readers
m = wintypes.DWORD(0)
winscard.SCardListReadersA(ctx, None, None, ctypes.byref(m))
buf = ctypes.create_string_buffer(m.value)
winscard.SCardListReadersA(ctx, None, buf, ctypes.byref(m))
readers = [r for r in buf.raw[:m.value].split(b'\x00') if r]
print("Found readers:", readers)

target_reader = None
for r in readers:
    if b"hyprkey" in r:
        target_reader = r
        break

assert target_reader is not None, "hyprkey CCID reader not found!"
print(f"Connecting to: {target_reader.decode('latin1', errors='replace')}")

hCard = ctypes.c_size_t()
activeProto = wintypes.DWORD()
rc = winscard.SCardConnectA(
    ctx.value, target_reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
    ctypes.byref(hCard), ctypes.byref(activeProto)
)
assert rc == 0, f"SCardConnectA failed: {hex(rc)}"
print(f"Connected! Active Protocol: {activeProto.value}")

pci_t1 = ctypes.c_void_p.in_dll(winscard, "g_rgSCardT1Pci")
pci_t0 = ctypes.c_void_p.in_dll(winscard, "g_rgSCardT0Pci")

def transmit(apdu_bytes):
    send_buf = ctypes.create_string_buffer(apdu_bytes)
    recv_buf = ctypes.create_string_buffer(1024)
    recv_len = wintypes.DWORD(1024)
    pci_send = ctypes.byref(pci_t1) if activeProto.value == SCARD_PROTOCOL_T1 else ctypes.byref(pci_t0)
    r = winscard.SCardTransmit(
        hCard.value, pci_send, send_buf, len(apdu_bytes),
        None, recv_buf, ctypes.byref(recv_len)
    )
    assert r == 0, f"SCardTransmit failed: {hex(r)}"
    return bytes(recv_buf.raw[:recv_len.value])

# 1. SELECT PIV AID
piv_aid = bytes.fromhex("00A404000BA000000308000010000100")
rsp = transmit(piv_aid)
print("1. SELECT PIV AID response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"

# 2. GET DATA CHUID
chuid_cmd = bytes.fromhex("00CB3FFF055C035FC102")
rsp = transmit(chuid_cmd)
print("2. GET DATA CHUID response:", rsp.hex()[:40], "... SW:", rsp[-2:].hex())
assert rsp[-2:] == b"\x90\x00"

# 3. VERIFY PIV PIN (123456)
pin_cmd = bytes.fromhex("0020008008313233343536FFFF")
rsp = transmit(pin_cmd)
print("3. VERIFY PIN response:", rsp.hex())
assert rsp == b"\x90\x00"

# 4. PIV Ed25519 (Alg 0x22) GENERATE ASYMMETRIC KEY PAIR on Slot 9A
gen_ed = bytes.fromhex("0047229A00")
rsp = transmit(gen_ed)
print("4. GENERATE Ed25519 KEYPAIR response:", rsp.hex()[:40], "... SW:", rsp[-2:].hex())
assert rsp[-2:] == b"\x90\x00"
idx_86 = rsp.find(b"\x86\x20")
ed_pub_bytes = rsp[idx_86+2 : idx_86+2+32]
print(f"   Derived Ed25519 Public Key: {ed_pub_bytes.hex()}")

# 5. PIV Ed25519 (Alg 0x22) GENERAL AUTHENTICATE (Sign challenge)
test_chal = b"hyprkey_live_ed25519_challenge32"
t7c = bytes([0x7C, 32 + 4, 0x81, 32]) + test_chal + bytes([0x82, 0x00])
auth_cmd = bytes([0x00, 0x87, 0x22, 0x9A, len(t7c)]) + t7c
rsp = transmit(auth_cmd)
print("5. GENERAL AUTHENTICATE response SW:", rsp[-2:].hex())
assert rsp[-2:] == b"\x90\x00"
idx_82 = rsp.find(b"\x82\x40")
ed_sig_bytes = rsp[idx_82+2 : idx_82+2+64]
print(f"   Signature length: {len(ed_sig_bytes)} bytes")
assert len(ed_sig_bytes) == 64

# 6. Verify signature using Python cryptography
ed_pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
ed_pub_obj.verify(ed_sig_bytes, test_chal)
print("\n[SUCCESS] Live PIV Ed25519 Signature cryptographically VERIFIED against hardware!")

# Disconnect
winscard.SCardDisconnect(hCard.value, 0)
winscard.SCardReleaseContext(ctx.value)
print("ALL LIVE CCID / PIV TESTS PASSED 100%!")

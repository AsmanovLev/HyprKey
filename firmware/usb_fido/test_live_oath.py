import ctypes
from ctypes import wintypes
import struct
import time
import hmac
import hashlib

winscard = ctypes.windll.winscard

SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0  = 1
SCARD_PROTOCOL_T1  = 2

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

print("\n--- Testing Yubico OATH Applet over CCID on Physical Hardware ---")

# 1. SELECT Yubico OATH AID: A0 00 00 05 27 21 01
oath_aid = bytes.fromhex("00A4040007A0000005272101")
rsp = transmit(oath_aid)
print("1. SELECT OATH AID response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00", f"SELECT failed: {rsp.hex()}"
# Check version & salt tag 0x79
assert rsp[0] == 0x79
print("   -> Applet Version and Salt OK!")

# 2. LIST Accounts (INS 0xA1)
list_cmd = bytes.fromhex("00A1000000")
rsp = transmit(list_cmd)
print("2. LIST Accounts response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"

# Parse listed accounts
idx = 0
accounts = []
while idx < len(rsp) - 2:
    tag = rsp[idx]
    length = rsp[idx+1]
    name = rsp[idx+2 : idx+2+length]
    accounts.append(name.decode('utf-8', errors='replace'))
    idx += 2 + length
print(f"   -> Listed accounts: {accounts}")

# 3. CALCULATE TOTP for default demo account (INS 0xA2, P2=0x01: truncate)
# For T = 59 // 30 = 1, RFC 6238 test vector gives 287082!
ts_challenge = struct.pack(">Q", 1)
demo_name = b"Google:alice@hyprkey.local"
calc_data = bytes([0x71, len(demo_name)]) + demo_name + bytes([0x74, len(ts_challenge)]) + ts_challenge
calc_cmd = bytes([0x00, 0xA2, 0x00, 0x01, len(calc_data)]) + calc_data
rsp = transmit(calc_cmd)
print("3. CALCULATE TOTP response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"
# Response format: 76 05 <digits> <4B code>
assert rsp[0] == 0x76 and rsp[1] == 0x05
digits = rsp[2]
raw_code = struct.unpack(">I", rsp[3:7])[0]
totp_code = f"{raw_code % (10**digits):0{digits}d}"
print(f"   -> Calculated TOTP Code for '{demo_name.decode()}': {totp_code}")

# Verify against Python HMAC-SHA1
py_mac1 = hmac.new(b"12345678901234567890", ts_challenge, hashlib.sha1).digest()
off1 = py_mac1[-1] & 0x0F
py_code1 = ((py_mac1[off1] & 0x7F) << 24) | (py_mac1[off1+1] << 16) | (py_mac1[off1+2] << 8) | py_mac1[off1+3]
py_totp1 = f"{(py_code1 % 1000000):06d}"
print(f"   -> Python HMAC-SHA1 TOTP: {py_totp1}")
assert totp_code == "287082" == py_totp1, f"Mismatch: hardware={totp_code}, python={py_totp1}"
print("   -> EXACT MATCH with RFC 6238 test vector (287082) & Python!")

# 4. PUT new account (INS 0x01)
# Key: "12345678901234567890" (20 bytes), SHA-256 HMAC, TOTP, 6 digits
new_name = b"GitHub:hyprkey"
key = b"12345678901234567890"
prop = 0x22 # TOTP(0x20) | SHA256(0x02)
digits_prop = 6
put_data = (
    bytes([0x71, len(new_name)]) + new_name +
    bytes([0x73, len(key) + 2, prop, digits_prop]) + key
)
put_cmd = bytes([0x00, 0x01, 0x00, 0x00, len(put_data)]) + put_data
rsp = transmit(put_cmd)
print("4. PUT new account ('GitHub:hyprkey') response:", rsp.hex())
assert rsp == b"\x90\x00"
print("   -> PUT success!")

# 5. CALCULATE on new account
calc_data2 = bytes([0x71, len(new_name)]) + new_name + bytes([0x74, len(ts_challenge)]) + ts_challenge
calc_cmd2 = bytes([0x00, 0xA2, 0x00, 0x01, len(calc_data2)]) + calc_data2
rsp = transmit(calc_cmd2)
print("5. CALCULATE on 'GitHub:hyprkey' response:", rsp.hex())
assert rsp[-2:] == b"\x90\x00"
raw_code2 = struct.unpack(">I", rsp[3:7])[0]
totp2 = f"{raw_code2 % 1000000:06d}"
print(f"   -> Calculated TOTP Code: {totp2}")

# Verify against Python HMAC-SHA256
h = hmac.new(key, ts_challenge, hashlib.sha256).digest()
offset = h[-1] & 0x0F
expected_code = ((struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000)
print(f"   -> Python HMAC-SHA256 TOTP: {expected_code:06d}")
assert totp2 == f"{expected_code:06d}"
print("   -> EXACT MATCH with Python HMAC-SHA256 computation!")

# 6. DELETE new account (INS 0x02)
del_data = bytes([0x71, len(new_name)]) + new_name
del_cmd = bytes([0x00, 0x02, 0x00, 0x00, len(del_data)]) + del_data
rsp = transmit(del_cmd)
print("6. DELETE 'GitHub:hyprkey' response:", rsp.hex())
assert rsp == b"\x90\x00"
print("   -> DELETE success!")

winscard.SCardDisconnect(hCard.value, 0)
winscard.SCardReleaseContext(ctx.value)
print("\n[SUCCESS] ALL LIVE YUBICO OATH TESTS PASSED ON PHYSICAL HARDWARE!")

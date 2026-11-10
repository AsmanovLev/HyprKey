import ctypes
from ctypes import wintypes

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
print("Found readers:", readers)

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
    recv_buf = ctypes.create_string_buffer(2048)
    recv_len = wintypes.DWORD(2048)
    pci_send = ctypes.byref(pci_t1) if activeProto.value == SCARD_PROTOCOL_T1 else ctypes.byref(pci_t0)
    r = winscard.SCardTransmit(
        hCard.value, pci_send, send_buf, len(apdu_bytes),
        None, recv_buf, ctypes.byref(recv_len)
    )
    assert r == 0, f"SCardTransmit failed: {hex(r)}"
    return bytes(recv_buf.raw[:recv_len.value])

# 1. SELECT OpenPGP AID
print("\n--- 1. SELECT OpenPGP AID ---")
aid = bytes.fromhex("D27600012401")
select_apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
rsp = transmit(select_apdu)
print(f"SELECT AID: {rsp.hex()}")
assert rsp[-2:] == b"\x90\x00"

# 2. GET DATA (00 4F - AID)
print("\n--- 2. GET DATA 00 4F (AID) ---")
rsp = transmit(bytes.fromhex("00CA004F00"))
print(f"AID ({len(rsp)-2}B): {rsp.hex()}")
assert rsp[-2:] == b"\x90\x00"

# 3. GET DATA (00 6E - Application Related Data)
print("\n--- 3. GET DATA 00 6E (App Related Data) ---")
rsp = transmit(bytes.fromhex("00CA006E00"))
print(f"DO 6E ({len(rsp)-2}B): {rsp.hex()[:80]}... SW:{rsp[-2:].hex()}")
assert rsp[-2:] == b"\x90\x00"

# 4. GET DATA (00 C4 - PW Status Bytes)
print("\n--- 4. GET DATA 00 C4 (PW Status Bytes) ---")
rsp = transmit(bytes.fromhex("00CA00C400"))
print(f"PW Status ({len(rsp)-2}B): {rsp.hex()}")
assert rsp[-2:] == b"\x90\x00"

# 5. GET DATA (00 C5 - Fingerprints)
print("\n--- 5. GET DATA 00 C5 (Fingerprints) ---")
rsp = transmit(bytes.fromhex("00CA00C500"))
print(f"Fingerprint ({len(rsp)-2}B): {rsp.hex()}")
assert rsp[-2:] == b"\x90\x00"

# 6. Read Public Keys (00 47 81 00 ...)
print("\n--- 6. Read Public Keys (00 47 81 00) ---")
pubkeys = {}
for role_name, role_tag in [("SIG", 0xB6), ("DEC", 0xB8), ("AUT", 0xA4)]:
    read_pk_apdu = bytes([0x00, 0x47, 0x81, 0x00, 0x02, role_tag, 0x00])
    rsp = transmit(read_pk_apdu)
    print(f"Read PubKey {role_name} (tag 0x{role_tag:02X}): SW={rsp[-2:].hex()}, len={len(rsp)-2}")
    assert rsp[-2:] == b"\x90\x00"
    # Format: 7F 49 <len> 86 41 04 <x> <y>
    idx_86 = rsp.find(b"\x86\x41")
    if idx_86 != -1:
        raw_pt = rsp[idx_86+2 : idx_86+2+65]
        pubkeys[role_name] = raw_pt

# 7. VERIFY User PIN (PW1: 123456) & Sign Data (PSO: CDS)
print("\n--- 7. VERIFY PW1 (123456) & Sign Data (PSO: CDS) ---")
v_pw1 = bytes([0x00, 0x20, 0x00, 0x81, 0x06]) + b"123456"
rsp = transmit(v_pw1)
print(f"VERIFY PW1 response: {rsp.hex()}")
assert rsp == b"\x90\x00"

import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

test_data = b"hyprkey live openpgp test signature message"
digest = hashlib.sha256(test_data).digest()

cds_apdu = bytes([0x00, 0x2A, 0x9E, 0x9A, len(digest)]) + digest
rsp = transmit(cds_apdu)
print(f"PSO: CDS signature response: SW={rsp[-2:].hex()}, len={len(rsp)-2}")
assert rsp[-2:] == b"\x90\x00"
sig_raw = rsp[:-2]
assert len(sig_raw) == 64
r = int.from_bytes(sig_raw[:32], 'big')
s = int.from_bytes(sig_raw[32:], 'big')
der_sig = encode_dss_signature(r, s)

sig_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkeys["SIG"])
sig_pubkey.verify(der_sig, test_data, ec.ECDSA(hashes.SHA256()))
print("[SUCCESS] Live OpenPGP ECDSA Signature verified with cryptography library!")

# 8. VERIFY PW1 for Decryption & Test ECDH (PSO: DECIPHER)
print("\n--- 8. VERIFY PW1 & Test ECDH Shared Secret (PSO: DECIPHER) ---")
v_pw1_dec = bytes([0x00, 0x20, 0x00, 0x82, 0x06]) + b"123456"
rsp = transmit(v_pw1_dec)
assert rsp == b"\x90\x00"

peer_priv = ec.generate_private_key(ec.SECP256R1())
peer_pub = peer_priv.public_key()
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
peer_bytes = peer_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

dec_apdu = bytes([0x00, 0x2A, 0x86, 0x80, len(peer_bytes)]) + peer_bytes
rsp = transmit(dec_apdu)
print(f"PSO: DECIPHER response: SW={rsp[-2:].hex()}, len={len(rsp)-2}")
assert rsp[-2:] == b"\x90\x00"
card_secret = rsp[:-2]

dec_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkeys["DEC"])
py_secret = peer_priv.exchange(ec.ECDH(), dec_pubkey)
assert card_secret == py_secret
print(f"Shared secret: {card_secret.hex()[:24]}...")
print("[SUCCESS] Live OpenPGP ECDH Shared Secret matches Python 100%!")

winscard.SCardDisconnect(hCard.value, 0)
winscard.SCardReleaseContext(ctx.value)
print("\n==================================================================")
print(" [SUCCESS] ALL LIVE CCID OPENPGP HARDWARE CRYPTO TESTS PASSED 100%!")
print("==================================================================")

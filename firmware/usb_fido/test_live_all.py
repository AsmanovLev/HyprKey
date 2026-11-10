import hid, struct, time, cbor2, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

print("=" * 60)
print("   hyprkey LIVE HARDWARE VERIFICATION (USB)")
print("=" * 60)

# Find FIDO HID interface (Usage Page 0xF1D0)
devices = hid.enumerate(0x1209, 0x0005)
print(f"Found {len(devices)} HID interfaces for VID 0x1209 PID 0x0005:")
fido_path = None
kbd_path = None

for d in devices:
    usage_page = d.get('usage_page', 0)
    usage = d.get('usage', 0)
    print(f"  Interface: {d['interface_number']}, UsagePage: 0x{usage_page:04X}, Usage: 0x{usage:04X}, Prod: {d['product_string']}")
    if usage_page == 0xF1D0:
        fido_path = d['path']
    elif usage_page == 0x0001 and usage == 0x0006:
        kbd_path = d['path']

assert fido_path is not None, "FIDO HID interface not found!"
print(f"\n[OK] FIDO HID interface detected at: {fido_path}")
if kbd_path:
    print(f"[OK] Keyboard HID interface detected at: {kbd_path}")

dev = hid.device()
dev.open_path(fido_path)

def send_ctaphid(cmd, payload):
    cid = 0xFFFFFFFF
    # Send INIT
    nonce = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    init_pkt = struct.pack(">IBBH", cid, 0x86, 0, len(nonce)) + nonce
    init_pkt = init_pkt.ljust(64, b"\x00")
    dev.write(b"\x00" + init_pkt)
    rsp = bytes(dev.read(64))
    new_cid = struct.unpack(">I", rsp[15:19])[0]

    # Send command
    cmd_pkt = struct.pack(">IBH", new_cid, cmd, len(payload)) + payload
    cmd_pkt = cmd_pkt.ljust(64, b"\x00")
    dev.write(b"\x00" + cmd_pkt)

    # Read response
    rsp = bytes(dev.read(64))
    r_cid, r_cmd, r_len = struct.unpack(">IBH", rsp[0:7])
    data = rsp[7:7+r_len]
    return data

# 1. CTAP2 GetInfo (0x04)
print("\n1. Testing Live CTAP2 GetInfo (0x04)...")
resp = send_ctaphid(0x90, bytes([0x04]))
status = resp[0]
assert status == 0, f"GetInfo failed with status {status}"
info = cbor2.loads(resp[1:])
print(f"  Versions: {info.get(1)}")
algs = info.get(10)
print(f"  Supported Algorithms: {algs}")
assert any(a['alg'] == -8 for a in algs), "Ed25519 (-8) not found in GetInfo!"
assert any(a['alg'] == -48 for a in algs), "ML-DSA-44 (-48) not found in GetInfo!"
assert any(a['alg'] == -7 for a in algs), "ES256 (-7) not found in GetInfo!"
print("  [PASS] CTAP2 GetInfo verified live on hardware!")

# 2. CTAP2 MakeCredential with Ed25519 (-8)
print("\n2. Testing Live CTAP2 MakeCredential for Ed25519 (-8)...")
cdh = hashlib.sha256(b"live_test_cdh").digest()
rp = {"id": "hyprkey.local", "name": "hyprkey Live"}
user = {"id": b"user_live", "name": "live_user", "displayName": "Live User"}
params = [{"type": "public-key", "alg": -8}] # Ed25519!

mc_req = cbor2.dumps({
    1: cdh,
    2: rp,
    3: user,
    4: params
})
resp = send_ctaphid(0x90, bytes([0x01]) + mc_req)
assert resp[0] == 0, f"MakeCredential failed: {resp[0]}"
mc_cbor = cbor2.loads(resp[1:])
auth_data = mc_cbor[2]
cred_id_len = int.from_bytes(auth_data[53:55], 'big')
cred_id = auth_data[55:55+cred_id_len]
cose_key = cbor2.loads(auth_data[55+cred_id_len:])
print(f"  Credential ID: {cred_id.hex()}")
print(f"  COSE Key: alg={cose_key[3]}, kty={cose_key[1]}, crv={cose_key[-1]}, pub={cose_key[-2].hex()}")
assert cose_key[3] == -8
assert cose_key[1] == 1 # OKP
assert cose_key[-1] == 6 # Ed25519
ed_pub_bytes = cose_key[-2]
print("  [PASS] Live Ed25519 MakeCredential SUCCESS!")

# 3. CTAP2 GetAssertion with Ed25519 (-8)
print("\n3. Testing Live CTAP2 GetAssertion for Ed25519 (-8)...")
cdh_auth = hashlib.sha256(b"live_test_auth").digest()
ga_req = cbor2.dumps({
    1: "hyprkey.local",
    2: cdh_auth,
    3: [{"type": "public-key", "id": cred_id}]
})
resp = send_ctaphid(0x90, bytes([0x02]) + ga_req)
assert resp[0] == 0, f"GetAssertion failed: {resp[0]}"
ga_cbor = cbor2.loads(resp[1:])
ga_auth_data = ga_cbor[2]
ga_sig = ga_cbor[3]
print(f"  Signature length: {len(ga_sig)} bytes (expected 64)")
assert len(ga_sig) == 64

# Verify signature using python cryptography
ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
msg_signed = ga_auth_data + cdh_auth
ed_pub.verify(ga_sig, msg_signed)
print("  [PASS] Live Ed25519 Signature cryptographically VERIFIED by python-cryptography!")

dev.close()
print("\n" + "=" * 60)
print("   ALL LIVE HARDWARE TESTS PASSED 100%!")
print("=" * 60)

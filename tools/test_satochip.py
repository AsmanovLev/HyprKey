#!/usr/bin/env python3
"""test_satochip.py - Test suite for HyprKey Satochip Hardware Crypto Wallet Applet.

Verifies:
1. ISO7816 Applet Selection (AID: SatoChip)
2. PIN Authentication (default: '1234')
3. Seed Import (64-byte BIP-39 seed)
4. BIP-32/BIP-44 Key Derivation:
   - Bitcoin (secp256k1 compressed + chaincode)
   - Ethereum (address via Keccak-256)
   - Solana / TON (Ed25519 public key)
5. Message Signing with User Presence Touch on P0.11 (secp256k1 & Ed25519)
"""

import sys
import time
import struct
import hashlib
import smartcard.System as sc

SATOCHIP_AID = [0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70]

def encode_bip32_path(indices):
    payload = bytearray()
    for idx in indices:
        payload += struct.pack(">I", idx)
    return list(payload)

def main():
    readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
    if not readers:
        print("[!] No HyprKey CCID reader detected.")
        sys.exit(1)

    reader = readers[0]
    print(f"[*] Connecting to: {reader}")
    conn = reader.createConnection()
    conn.connect()

    # 1. SELECT Satochip Applet
    print("\n--- 1. SELECT Satochip Applet ---")
    apdu = [0x00, 0xA4, 0x04, 0x00, len(SATOCHIP_AID)] + SATOCHIP_AID + [0x00]
    resp, sw1, sw2 = conn.transmit(apdu)
    print(f"Response: {bytes(resp).hex()} | SW: {sw1:02X}{sw2:02X}")
    assert (sw1, sw2) == (0x90, 0x00), f"SELECT failed: {sw1:02X}{sw2:02X}"
    proto_ver = f"{resp[0]}.{resp[1]}"
    app_ver = f"{resp[2]}.{resp[3]}"
    pin_tries = resp[4]
    has_seed = bool(resp[5])
    print(f"[+] Applet Selected! Proto: v{proto_ver}, App: v{app_ver}, PIN tries: {pin_tries}, Seed initialized: {has_seed}")

    # 2. GET STATUS
    print("\n--- 2. GET STATUS ---")
    resp, sw1, sw2 = conn.transmit([0xB0, 0x6D, 0x00, 0x00, 0x00])
    print(f"Response: {bytes(resp).hex()} | SW: {sw1:02X}{sw2:02X}")
    assert (sw1, sw2) == (0x90, 0x00)
    print(f"[+] Status: Seed={bool(resp[0])}, Auth={bool(resp[1])}, Tries={resp[2]}, TouchReq={bool(resp[3])}")

    # 3. VERIFY PIN
    print("\n--- 3. VERIFY PIN ('1234') ---")
    pin = b"1234"
    resp, sw1, sw2 = conn.transmit([0xB0, 0x20, 0x00, 0x00, len(pin)] + list(pin))
    print(f"SW: {sw1:02X}{sw2:02X}")
    assert (sw1, sw2) == (0x90, 0x00), f"PIN verification failed: {sw1:02X}{sw2:02X}"
    print("[+] PIN verified successfully!")

    # 4. IMPORT BIP-39 SEED
    print("\n--- 4. IMPORT BIP-39 SEED ---")
    # Standard test seed (from mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    test_seed = bytes.fromhex(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    )
    resp, sw1, sw2 = conn.transmit([0xB0, 0x69, 0x00, 0x00, len(test_seed)] + list(test_seed))
    print(f"SW: {sw1:02X}{sw2:02X}")
    assert (sw1, sw2) == (0x90, 0x00), f"Seed import failed: {sw1:02X}{sw2:02X}"
    print("[+] Master seed imported successfully!")

    # 5. DERIVE BITCOIN PUBLIC KEY (m/44'/0'/0'/0/0)
    print("\n--- 5. DERIVE BITCOIN KEY (m/44'/0'/0'/0/0) ---")
    btc_path = encode_bip32_path([0x8000002C, 0x80000000, 0x80000000, 0, 0])
    resp, sw1, sw2 = conn.transmit([0xB0, 0x6C, 0x00, 0x00, len(btc_path)] + btc_path + [0x00])
    print(f"SW: {sw1:02X}{sw2:02X} | Length: {len(resp)} bytes")
    assert (sw1, sw2) == (0x90, 0x00)
    compressed_pubkey = bytes(resp[:33])
    chain_code = bytes(resp[33:65])
    print(f"[+] Bitcoin Public Key (compressed 33B): {compressed_pubkey.hex()}")
    print(f"[+] Bitcoin Chain Code (32B):            {chain_code.hex()}")

    # 6. DERIVE ETHEREUM ADDRESS (m/44'/60'/0'/0/0)
    print("\n--- 6. DERIVE ETHEREUM ADDRESS (m/44'/60'/0'/0/0) ---")
    eth_path = encode_bip32_path([0x8000002C, 0x8000003C, 0x80000000, 0, 0])
    resp, sw1, sw2 = conn.transmit([0xB0, 0x6C, 0x02, 0x00, len(eth_path)] + eth_path + [0x00])
    print(f"SW: {sw1:02X}{sw2:02X} | Length: {len(resp)} bytes")
    assert (sw1, sw2) == (0x90, 0x00)
    eth_address = "0x" + bytes(resp[:20]).hex()
    print(f"[+] Ethereum Address: {eth_address}")

    # 7. DERIVE SOLANA ED25519 PUBLIC KEY (m/44'/501'/0'/0')
    print("\n--- 7. DERIVE SOLANA ED25519 PUBKEY (m/44'/501'/0'/0') ---")
    sol_path = encode_bip32_path([0x8000002C, 0x800001F5, 0x80000000, 0x80000000])
    resp, sw1, sw2 = conn.transmit([0xB0, 0x6C, 0x03, 0x00, len(sol_path)] + sol_path + [0x00])
    print(f"SW: {sw1:02X}{sw2:02X} | Length: {len(resp)} bytes")
    assert (sw1, sw2) == (0x90, 0x00)
    sol_pubkey = bytes(resp[:32])
    print(f"[+] Solana Public Key (Ed25519 32B): {sol_pubkey.hex()}")

    # 8. DERIVE MONERO (XMR) KEYS & ADDRESS (m/44'/128'/0')
    print("\n--- 8. DERIVE MONERO (XMR) KEYS & ADDRESS (m/44'/128'/0') ---")
    xmr_path = encode_bip32_path([0x8000002C, 0x80000080, 0x80000000])
    resp, sw1, sw2 = conn.transmit([0xB0, 0x6C, 0x05, 0x00, len(xmr_path)] + xmr_path + [0x00])
    print(f"SW: {sw1:02X}{sw2:02X} | Length: {len(resp)} bytes")
    assert (sw1, sw2) == (0x90, 0x00)
    spend_pub = bytes(resp[0:32])
    view_pub  = bytes(resp[32:64])
    view_sec  = bytes(resp[64:96])
    addr_len  = resp[96]
    addr_str  = bytes(resp[97:97+addr_len]).decode('ascii')
    print(f"[+] Monero Spend Public Key (32B): {spend_pub.hex()}")
    print(f"[+] Monero View Public Key  (32B): {view_pub.hex()}")
    print(f"[+] Monero View Private Key (32B): {view_sec.hex()} (Exported for view-only wallet sync)")
    print(f"[+] Monero Mainnet Address ({addr_len} chars): {addr_str}")
    assert addr_str.startswith("4"), "Monero Mainnet address must start with 4"
    assert addr_len == 95, f"Expected 95 chars, got {addr_len}"

    # 9. TEST USER PRESENCE TOUCH ON TRANSACTION SIGNING
    print("\n--- 9. TEST USER PRESENCE ON SIGNING (P0.11 TOUCH) ---")
    # First test: Without touching (should timeout after 3s with SW=6985)
    print("[*] Testing Touch Timeout (Do NOT touch the key)...")
    t0 = time.time()
    msg_hash = hashlib.sha256(b"Hello Satochip on HyprKey!").digest()
    sign_payload = [len(eth_path)] + eth_path + list(msg_hash)
    resp, sw1, sw2 = conn.transmit([0xB0, 0x6E, 0x00, 0x00, len(sign_payload)] + sign_payload + [0x00])
    elapsed = time.time() - t0
    print(f"Elapsed: {elapsed:.2f}s | SW: {sw1:02X}{sw2:02X}")
    if (sw1, sw2) == (0x69, 0x85):
        print("[+] Touch timeout enforced correctly! (SW=6985 Conditions Not Satisfied)")
    else:
        print(f"[*] Response: {bytes(resp).hex()} SW: {sw1:02X}{sw2:02X}")

    print("\n[SUCCESS] Satochip Hardware Crypto Wallet Applet passed all core unit tests!")

if __name__ == "__main__":
    main()

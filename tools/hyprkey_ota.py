#!/usr/bin/env python3
"""hyprkey_ota.py - Live Seamless In-Application OTA Update over USB CCID.

Streams firmware directly into the inactive flash slot via Vendor APDU (FF FC),
verifies on-chip SHA-256 cryptographic digest, and triggers a 100ms soft-reset.
No virtual USB disk (NICENANO) ever mounts.
"""

import sys
import os
import time
import hashlib
import smartcard.System as sc

FW_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firmware", "usb_fido")
CHUNK_SIZE = 220

def perform_ota():
    readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
    if not readers:
        print("Error: HyprKey CCID reader not detected!")
        sys.exit(1)

    reader = readers[0]
    print(f"Connected to reader: {reader}")
    conn = reader.createConnection()
    conn.connect()

    t0 = time.perf_counter()

    # Step 0: Authenticate Admin PIN (OpenPGP PW3)
    admin_pin = sys.argv[1] if len(sys.argv) > 1 else "12345678"
    print(f"\n0. Authenticating Admin PIN (PW3)...")
    # SELECT OpenPGP Card Applet
    resp, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
    # VERIFY PW3 (Admin PIN)
    pin_bytes = list(admin_pin.encode("ascii"))
    resp, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, 0x83, len(pin_bytes)] + pin_bytes)
    if (sw1, sw2) != (0x90, 0x00):
        print(f"Error: Admin PIN verification failed! SW={sw1:02X}{sw2:02X}")
        sys.exit(1)
    print("   Admin PIN (PW3) successfully verified!")

    # Step 1: Begin OTA Session
    print("\n1. Initializing OTA Session (erasing inactive slot)...")
    t_erase_start = time.perf_counter()
    resp, sw1, sw2 = conn.transmit([0xFF, 0xFC, 0x00, 0x00, 0x00])
    t_erase = time.perf_counter() - t_erase_start

    if (sw1, sw2) != (0x90, 0x00) or len(resp) < 2:
        print(f"Error starting OTA session: SW={sw1:02X}{sw2:02X}, resp={resp}")
        sys.exit(1)

    cur_slot_id = resp[0]
    tgt_slot_id = resp[1]
    cur_slot = "Slot A" if cur_slot_id == 0 else "Slot B"
    tgt_slot = "Slot A" if tgt_slot_id == 0 else "Slot B"
    print(f"   Active Running Slot: {cur_slot}")
    print(f"   Target Inactive Slot: {tgt_slot}")
    print(f"   Target slot erased in: {t_erase*1000:.1f} ms")

    # Select target-specific binary (linked for 0x00028000 or 0x00040000)
    slot_bin_name = "usb_fido_slot_b.bin" if tgt_slot_id == 1 else "usb_fido_slot_a.bin"
    target_bin_path = os.path.join(FW_DIR, slot_bin_name)
    if not os.path.exists(target_bin_path):
        target_bin_path = os.path.join(FW_DIR, "usb_fido.bin")

    if not os.path.exists(target_bin_path):
        print(f"Error: Target binary not found at {target_bin_path}")
        sys.exit(1)

    with open(target_bin_path, "rb") as f:
        fw_data = f.read()

    total_len = len(fw_data)
    fw_sha256 = hashlib.sha256(fw_data).digest()

    print(f"   Selected Image: {slot_bin_name}")
    print(f"   Size: {total_len} bytes (~{total_len/1024:.1f} KB)")
    print(f"   SHA-256: {fw_sha256.hex()}")

    # Step 2: Stream Chunks
    print(f"\n2. Streaming {total_len} bytes in {CHUNK_SIZE}-byte chunks over USB CCID...")
    offset = 0
    t_stream_start = time.perf_counter()
    chunk_idx = 0
    num_chunks = (total_len + CHUNK_SIZE - 1) // CHUNK_SIZE

    while offset < total_len:
        chunk = fw_data[offset : offset + CHUNK_SIZE]
        chunk_len = len(chunk)
        payload_len = 4 + chunk_len

        # APDU: FF FC 01 00 <payload_len> <offset:4> <chunk>
        apdu = [
            0xFF, 0xFC, 0x01, 0x00,
            payload_len,
            (offset >> 24) & 0xFF,
            (offset >> 16) & 0xFF,
            (offset >> 8) & 0xFF,
            offset & 0xFF
        ] + list(chunk)

        resp, sw1, sw2 = conn.transmit(apdu)
        if (sw1, sw2) != (0x90, 0x00):
            print(f"\nError writing chunk at offset {offset}: SW={sw1:02X}{sw2:02X}")
            sys.exit(1)

        offset += chunk_len
        chunk_idx += 1
        pct = (offset / total_len) * 100
        print(f"\r   Progress: [{chunk_idx}/{num_chunks}] {offset}/{total_len} bytes ({pct:.1f}%)", end="", flush=True)

    t_stream = time.perf_counter() - t_stream_start
    throughput = (total_len / 1024) / t_stream if t_stream > 0 else 0
    print(f"\n   Stream completed in {t_stream:.2f} s ({throughput:.1f} KB/s)")

    # Step 3: Finalize & Verify SHA-256 on-chip
    print("\n3. Verifying on-chip SHA-256 cryptographic digest...")
    size_bytes = [
        (total_len >> 24) & 0xFF,
        (total_len >> 16) & 0xFF,
        (total_len >> 8) & 0xFF,
        total_len & 0xFF
    ]
    finalize_apdu = [0xFF, 0xFC, 0x02, 0x00, 36] + size_bytes + list(fw_sha256)
    
    t_fin_start = time.perf_counter()
    resp, sw1, sw2 = conn.transmit(finalize_apdu)
    t_fin = time.perf_counter() - t_fin_start

    if (sw1, sw2) == (0x90, 0x00):
        print(f"   SUCCESS! On-chip SHA-256 matched bit-for-bit (verified in {t_fin*1000:.1f} ms)!")
    else:
        print(f"   FAILED! On-chip SHA-256 verification failed: SW={sw1:02X}{sw2:02X}")
        sys.exit(1)

    conn.disconnect()

    # Step 4: Wait for reboot
    print("\n4. Waiting for Stage-2 seamless reboot into updated firmware...")
    t_reboot_start = time.perf_counter()
    time.sleep(0.5)

    re_opened = False
    for _ in range(10):
        try:
            r_list = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
            if r_list:
                c2 = r_list[0].createConnection()
                c2.connect()
                # Query ATR or APDU
                c2.transmit([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
                c2.disconnect()
                re_opened = True
                break
        except Exception:
            pass
        time.sleep(0.1)

    t_reboot = time.perf_counter() - t_reboot_start
    t_total = time.perf_counter() - t0

    if re_opened:
        print(f"   SUCCESS! HyprKey re-opened and responsive in {t_reboot:.2f} s!")
        print("\n" + "="*50)
        print(f"LIVE OTA TOTAL TIME: {t_total:.2f} seconds!")
        print("="*50)
    else:
        print("Note: Token rebooted, re-enumeration in progress.")

if __name__ == "__main__":
    perform_ota()

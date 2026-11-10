#!/usr/bin/env python3
"""flash_key.py - 1-Click Autonomous Flash for HyprKey over USB CCID.

No COM ports, no serial cables, no physical buttons required.
1. Detects if device is in normal CCID mode or bootloader mode.
2. If CCID mode: sends Vendor APDU (FF FD 42 00 00) to reboot into UF2 bootloader.
3. Waits for NICENANO drive.
4. Copies usb_fido.uf2 to the drive.
5. Waits for device to reboot and verifies CCID reader.
"""

import sys
import os
import time
import shutil
import subprocess

UF2_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "firmware", "usb_fido", "usb_fido.uf2")

def find_nicenano_drive():
    # Check common drive letters
    for letter in "EFGHIJKLMNOPQRSTUVWXYZ":
        path = f"{letter}:\\INFO_UF2.TXT"
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="latin1") as f:
                    content = f.read()
                    if "nice!nano" in content or "UF2 Bootloader" in content:
                        return f"{letter}:\\"
            except Exception:
                pass
    return None

def trigger_dfu_via_ccid():
    try:
        import smartcard.System as sc
        readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
        if not readers:
            return False
        
        reader = readers[0]
        print(f"Connecting to {reader}...")
        conn = reader.createConnection()
        conn.connect()
        # APDU: CLA=0xFF, INS=0xFD, P1=0x42 (Reboot to DFU)
        data, sw1, sw2 = conn.transmit([0xFF, 0xFD, 0x42, 0x00, 0x00])
        print(f"Sent Reboot-to-DFU APDU -> SW={sw1:02X}{sw2:02X}")
        conn.disconnect()
        return True
    except Exception as e:
        print(f"CCID trigger exception: {e}")
        return False

def flash():
    if not os.path.exists(UF2_PATH):
        print(f"Error: Firmware binary not found at {UF2_PATH}")
        sys.exit(1)

    print(f"Firmware binary: {UF2_PATH} ({os.path.getsize(UF2_PATH)} bytes)")

    # 1. Check if already in bootloader
    drive = find_nicenano_drive()
    if not drive:
        print("Device in CCID mode. Sending autonomous DFU reboot command...")
        if not trigger_dfu_via_ccid():
            print("Could not send CCID command. Checking if bootloader drive appears anyway...")
        
        # Wait for drive to appear
        for i in range(12):
            time.sleep(0.5)
            drive = find_nicenano_drive()
            if drive:
                break
        
        if not drive:
            print("Error: NICENANO bootloader drive did not appear within 6 seconds.")
            sys.exit(1)

    print(f"Target drive located at: {drive}")
    dst_uf2 = os.path.join(drive, "usb_fido.uf2")
    print(f"Writing UF2 -> {dst_uf2}...")
    shutil.copyfile(UF2_PATH, dst_uf2)
    print("Write complete! Device is flashing and rebooting...")

    # Wait for reboot and CCID re-enumeration
    time.sleep(2.5)
    try:
        import smartcard.System as sc
        for _ in range(10):
            readers = [r for r in sc.readers() if "hyprkey" in str(r).lower()]
            if readers:
                print(f"SUCCESS: HyprKey re-enumerated as '{readers[0]}'")
                break
            time.sleep(0.5)
        else:
            print("Warning: CCID reader did not re-appear yet (may still be enumerating).")
    except Exception as e:
        print(f"Note: {e}")

if __name__ == "__main__":
    flash()

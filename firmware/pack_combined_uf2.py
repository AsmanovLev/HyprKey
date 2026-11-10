#!/usr/bin/env python3
"""pack_combined_uf2.py - Package multiple binary segments into a single UF2 file.

Used to pack:
- Stage-2 Switcher at 0x00026000 (8 KB)
- Slot A Application at 0x00028000 (96 KB max)
into one single usb_fido.uf2 that the Adafruit UF2 Bootloader can flash directly.
"""

import struct
import sys
import os

UF2_MAGIC_START0 = 0x0A324655 # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END    = 0x0AB16F30
UF2_FLAG_FAMILY  = 0x00002000
FAMILY_NRF52840  = 0xADA52840

def make_blocks(data, start_addr):
    # Pad to 256 bytes
    rem = len(data) % 256
    if rem > 0:
        data += b"\x00" * (256 - rem)
    
    blocks = []
    n_blocks = len(data) // 256
    for b_idx in range(n_blocks):
        payload = data[b_idx * 256 : (b_idx + 1) * 256]
        target = start_addr + (b_idx * 256)
        blocks.append((target, payload))
    return blocks

def pack_segments(segments, output_uf2):
    """segments is a list of tuples: (bin_path, start_addr)"""
    all_blocks = []
    for bin_path, addr in segments:
        with open(bin_path, "rb") as f:
            data = f.read()
        blocks = make_blocks(data, addr)
        print(f"Segment: {bin_path} -> {len(data)} bytes, {len(blocks)} blocks at 0x{addr:08X}")
        all_blocks.extend(blocks)
    
    total_blocks = len(all_blocks)
    print(f"Total UF2 blocks to write: {total_blocks} ({total_blocks * 512} bytes UF2)")

    with open(output_uf2, "wb") as out:
        for idx, (target_addr, payload) in enumerate(all_blocks):
            header = struct.pack(
                "<IIIIIIII",
                UF2_MAGIC_START0,
                UF2_MAGIC_START1,
                UF2_FLAG_FAMILY,
                target_addr,
                256,
                idx,
                total_blocks,
                FAMILY_NRF52840
            )
            block_data = payload + b"\x00" * (476 - 256)
            footer = struct.pack("<I", UF2_MAGIC_END)
            out.write(header + block_data + footer)
    
    print(f"Successfully generated combined UF2: {output_uf2}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    stage2_bin = os.path.join(base_dir, "stage2_bootloader", "stage2.bin")
    app_bin = os.path.join(base_dir, "usb_fido", "usb_fido.bin")
    out_uf2 = os.path.join(base_dir, "usb_fido", "usb_fido.uf2")

    pack_segments([
        (stage2_bin, 0x00026000),
        (app_bin,    0x00028000)
    ], out_uf2)

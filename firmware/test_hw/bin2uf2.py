#!/usr/bin/env python3
import struct
import sys

UF2_MAGIC_START0 = 0x0A324655 # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END    = 0x0AB16F30
UF2_FLAG_FAMILY  = 0x00002000
FAMILY_NRF52840  = 0xADA52840

def convert_bin_to_uf2(bin_path, uf2_path, start_addr=0x00026000):
    with open(bin_path, "rb") as f:
        data = f.read()

    # Pad data to multiple of 256
    rem = len(data) % 256
    if rem > 0:
        data += b"\x00" * (256 - rem)

    num_blocks = len(data) // 256
    print(f"Converting {len(data)} bytes -> {num_blocks} UF2 blocks at 0x{start_addr:08X}...")

    with open(uf2_path, "wb") as out:
        for block_no in range(num_blocks):
            payload = data[block_no * 256 : (block_no + 1) * 256]
            target_addr = start_addr + block_no * 256

            # 512-byte block format
            header = struct.pack(
                "<IIIIIIII",
                UF2_MAGIC_START0,
                UF2_MAGIC_START1,
                UF2_FLAG_FAMILY,
                target_addr,
                256,              # payload size
                block_no,         # block sequence number
                num_blocks,       # total blocks
                FAMILY_NRF52840   # board family
            )

            # 476 bytes data space (256 bytes payload + 220 padding zeroes)
            block_data = payload + b"\x00" * (476 - 256)
            footer = struct.pack("<I", UF2_MAGIC_END)

            out.write(header + block_data + footer)

    print(f"Successfully generated UF2 file: {uf2_path}")

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "test_ble.bin"
    dst = sys.argv[2] if len(sys.argv) > 2 else "test_ble.uf2"
    convert_bin_to_uf2(src, dst)

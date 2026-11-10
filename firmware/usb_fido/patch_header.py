#!/usr/bin/env python3
"""patch_header.py - Stamp firmware metadata, SHA-256 digest, git commit, and build date into app_header_t.

Header layout at offset 0x40:
  0x00: magic (0x48595052 'HYPR')
  0x04: version (Major.Minor.Patch.Build)
  0x08: security_counter (Anti-rollback)
  0x0C: image_size (total bytes)
  0x10..0x2F: sha256 (32 bytes payload digest starting at 0x80)
  0x30..0x37: git_commit (8 bytes ASCII null-padded)
  0x38..0x3F: build_date (8 bytes ASCII "YYYYMMDD")
"""

import sys
import os
import struct
import hashlib
import subprocess
from datetime import datetime

MAGIC_HYPR = 0x48595052
HEADER_OFFSET = 0x40
HEADER_SIZE = 64
PAYLOAD_OFFSET = 0x80

def get_git_commit():
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode("ascii").strip()[:7]
    except Exception:
        return "95f2032"

def patch_binary(bin_path):
    if not os.path.exists(bin_path):
        print(f"Error: {bin_path} does not exist!")
        sys.exit(1)

    with open(bin_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < PAYLOAD_OFFSET:
        print(f"Error: binary too small ({len(data)} bytes)!")
        sys.exit(1)

    # Verify Header Magic
    magic = struct.unpack_from("<I", data, HEADER_OFFSET)[0]
    if magic != MAGIC_HYPR:
        print(f"Error: Invalid header magic: 0x{magic:08X} (expected 0x{MAGIC_HYPR:08X})")
        sys.exit(1)

    version, sec_cnt = struct.unpack_from("<II", data, HEADER_OFFSET + 4)
    image_size = len(data)

    # Compute payload SHA-256 (from offset 0x80 to EOF)
    payload_sha256 = hashlib.sha256(data[PAYLOAD_OFFSET:]).digest()

    # Git commit and Build date
    git_commit = get_git_commit().encode("ascii").ljust(8, b"\x00")[:8]
    build_date = datetime.now().strftime("%Y%m%d").encode("ascii").ljust(8, b"\x00")[:8]

    # Stamp image_size, sha256, git_commit, build_date
    struct.pack_into("<I", data, HEADER_OFFSET + 12, image_size)
    data[HEADER_OFFSET + 16 : HEADER_OFFSET + 48] = payload_sha256
    data[HEADER_OFFSET + 48 : HEADER_OFFSET + 56] = git_commit
    data[HEADER_OFFSET + 56 : HEADER_OFFSET + 64] = build_date

    with open(bin_path, "wb") as f:
        f.write(data)

    v_major = (version >> 24) & 0xFF
    v_minor = (version >> 16) & 0xFF
    v_patch = (version >> 8) & 0xFF
    v_build = version & 0xFF

    print(f"Stamped {bin_path}:")
    print(f"  Version:          v{v_major}.{v_minor}.{v_patch}.{v_build} (0x{version:08X})")
    print(f"  Security Counter: {sec_cnt}")
    print(f"  Image Size:       {image_size} bytes")
    print(f"  Payload SHA-256:  {payload_sha256.hex()}")
    print(f"  Git Commit:       {git_commit.decode('ascii', errors='ignore').strip(chr(0))}")
    print(f"  Build Date:       {build_date.decode('ascii', errors='ignore').strip(chr(0))}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "usb_fido.bin")
    patch_binary(target)

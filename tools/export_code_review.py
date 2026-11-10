#!/usr/bin/env python3
"""export_code_review.py - Export HyprKey core codebase into code.md for external agent review.
"""

import os
import sys

files_to_export = [
    # 1. Architecture & Bootloader
    ('firmware/stage2_bootloader/linker_stage2.ld', 'Stage-2 Linker Script', 'ld'),
    ('firmware/stage2_bootloader/stage2_main.c', 'Stage-2 Bootloader Switcher (Fast A/B Dispatcher)', 'c'),
    
    # 2. Dual-Slot OTA & Storage
    ('firmware/usb_fido/app_header.h', 'Firmware Image Header & Metadata Definition', 'c'),
    ('firmware/usb_fido/crypto_consttime.h', 'Constant-Time Memory & Secret Comparison Primitives', 'c'),
    ('firmware/usb_fido/storage_flash.h', 'Flash Layout & Dual-Slot Storage Header', 'c'),
    ('firmware/usb_fido/storage_flash.c', 'Dual-Slot Flash Manager, 4-Byte Journal & Live OTA APDU', 'c'),
    ('firmware/usb_fido/patch_header.py', 'Header Stamping & Cryptographic Image Signer', 'python'),
    ('firmware/usb_fido/linker_slot_a.ld', 'Slot A Linker Script (ORIGIN = 0x00028000)', 'ld'),
    ('firmware/usb_fido/linker_slot_b.ld', 'Slot B Linker Script (ORIGIN = 0x00040000)', 'ld'),
    
    # 3. Core & USB / CCID Transport
    ('firmware/usb_fido/device_log.h', 'Device Diagnostics Ring Buffer Header', 'c'),
    ('firmware/usb_fido/device_log.c', 'Device Diagnostics Ring Buffer Implementation', 'c'),
    ('firmware/usb_fido/ccid/ccid.h', 'USB CCID Smart Card Transport Header', 'c'),
    ('firmware/usb_fido/ccid/ccid.c', 'USB CCID Smart Card Transport Implementation', 'c'),
    ('firmware/usb_fido/main.c', 'Firmware Entry Point, USB Stack, Interrupt Handlers', 'c'),

    # 4. Protocols & Applications
    ('firmware/usb_fido/fido_u2f.h', 'FIDO U2F Protocol Definitions', 'c'),
    ('firmware/usb_fido/fido_u2f.c', 'FIDO U2F Protocol Implementation', 'c'),
    ('firmware/usb_fido/ctap2.h', 'FIDO2 / CTAP2 Protocol Definitions', 'c'),
    ('firmware/usb_fido/ctap2.c', 'FIDO2 / CTAP2 Protocol Implementation', 'c'),
    ('firmware/usb_fido/openpgp/openpgp.h', 'OpenPGP Smart Card 3.4 Definitions', 'c'),
    ('firmware/usb_fido/openpgp/openpgp.c', 'OpenPGP Smart Card 3.4 Implementation', 'c'),
    ('firmware/usb_fido/piv/piv.h', 'PIV (NIST SP 800-73-4) Definitions', 'c'),
    ('firmware/usb_fido/piv/piv.c', 'PIV (NIST SP 800-73-4) Implementation', 'c'),
    ('firmware/usb_fido/oath/oath.h', 'OATH TOTP/HOTP Definitions', 'c'),
    ('firmware/usb_fido/oath/oath.c', 'OATH TOTP/HOTP Implementation', 'c'),

    # 5. Host Tools
    ('tools/hyprkey_ota.py', 'Host Live OTA CCID Streaming Tool', 'python'),
    ('tools/flash_key.py', 'Host Autonomous 1-Click DFU Flasher', 'python')
]

def generate_export():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_path = os.path.join(base, 'code.md')

    with open(out_path, 'w', encoding='utf-8') as out:
        out.write('# HyprKey Codebase Export for Architectural & Security Review\n\n')
        out.write('> **Target MCU:** Nordic Semiconductor nRF52840 (Cortex-M4F @ 64 MHz, 1 MB Flash, 256 KB RAM)\n')
        out.write('> **Device:** nice!nano v2 Security Key Token\n')
        out.write('> **Export Date:** 2026-11-10\n')
        out.write('> **Scope:** Bootloader Switcher, Dual-Slot A/B Architecture, Storage Journal, Protocols (FIDO2, OpenPGP, PIV, OATH), Live OTA & Host Tools.\n\n')

        out.write('## Flash Memory Map\n\n')
        out.write('```text\n')
        out.write('+-------------------------+ 0x00000000\n')
        out.write('| Nordic S140 SoftDevice  | (152 KB, 0x00000 - 0x25FFF)\n')
        out.write('+-------------------------+ 0x00026000\n')
        out.write('| Stage-2 Switcher        | (8 KB, 0x26000 - 0x27FFF, runs in < 0.1 ms)\n')
        out.write('+-------------------------+ 0x00028000\n')
        out.write('| Slot A Application      | (96 KB, 0x28000 - 0x3FFFF)\n')
        out.write('+-------------------------+ 0x00040000\n')
        out.write('| Slot B Application      | (96 KB, 0x40000 - 0x57FFF)\n')
        out.write('+-------------------------+ 0x00058000\n')
        out.write('| OTA Metadata Page       | (4 KB, 0x58000 - 0x58FFF, 4-byte append-only log)\n')
        out.write('+-------------------------+ 0x00059000\n')
        out.write('| User Data & Storage     | (592 KB, 0x59000 - 0xECFFF, Passkeys, PGP, LittleFS)\n')
        out.write('+-------------------------+ 0x000ED000\n')
        out.write('| SoftDevice Flash Data   | (28 KB, 0xED000 - 0xF3FFF)\n')
        out.write('+-------------------------+ 0x000F4000\n')
        out.write('| Adafruit UF2 Bootloader | (48 KB, 0xF4000 - 0xFFFFF)\n')
        out.write('+-------------------------+ 0x00100000 (1 MB End)\n')
        out.write('```\n\n')

        out.write('## Table of Contents\n\n')
        for rel, desc, _ in files_to_export:
            anchor = rel.replace('/', '').replace('.', '').replace('_', '').replace('-', '').lower()
            out.write(f'- [{rel}](#{anchor}) - *{desc}*\n')
        out.write('\n---\n\n')

        for rel, desc, lang in files_to_export:
            p = os.path.join(base, rel.replace('/', os.sep))
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            anchor = rel.replace('/', '').replace('.', '').replace('_', '').replace('-', '').lower()
            out.write(f'<a id="{anchor}"></a>\n')
            out.write(f'# File: `{rel}`\n\n')
            out.write(f'> **Description:** {desc}  \n')
            out.write(f'> **Path:** `{rel}`  \n')
            out.write(f'> **Lines:** {len(content.splitlines())}  \n\n')
            out.write(f'```{lang}\n')
            out.write(content)
            if not content.endswith('\n'):
                out.write('\n')
            out.write('```\n\n---\n\n')

    size_kb = os.path.getsize(out_path) / 1024
    print(f'code.md generated successfully at {out_path} ({size_kb:.1f} KB, {len(files_to_export)} files)')

if __name__ == '__main__':
    generate_export()

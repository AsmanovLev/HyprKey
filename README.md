# HyprKey 🛡️

**Open-Source Post-Quantum Hardware Security Key, Dual NFC Controller & Multi-Applet Smart Card**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-nRF52840-brightgreen.svg)
![Standards](https://img.shields.io/badge/standards-FIDO2%20%7C%20OpenPGP%203.4%20%7C%20OATH%20%7C%20PQC-orange.svg)
![Languages](https://img.shields.io/badge/C-C11%20(Zero--Alloc)-blue.svg)

**HyprKey** is an advanced, open-source hardware security token and cryptographic enclave built on the **Nordic nRF52840** (Cortex-M4F @ 64 MHz) and **NXP PN532** NFC controller. It combines classical cryptography with next-generation **Post-Quantum Cryptography (NIST ML-KEM and ML-DSA)**, multi-protocol smart card emulation, and an atomic, power-cut-resilient flash storage engine.

---

## ⚡ Highlights & Key Capabilities

- **Post-Quantum Ready (NIST FIPS 203 & 204):**
  - **ML-KEM-768 / ML-KEM-1024** (Kyber): Quantum-resistant key encapsulation and public-key encryption.
  - **ML-DSA-44 / ML-DSA-65 / ML-DSA-87** (Dilithium): Quantum-resistant digital signatures.
- **FIDO2 / WebAuthn / Passkeys:**
  - Full CTAP 2.0 / 2.1 compliance with Resident Keys (Discoverable Credentials).
  - High-speed hardware NIST P-256 (`uECC` with `umaal` assembly acceleration) and Ed25519.
  - User Presence verification via capacitive touch pin or tactile button.
- **OpenPGP Card v3.4:**
  - Standard ISO 7816-4 smart card applet with Signature, Decryption, and Authentication key slots.
  - Seamlessly supported by **GnuPG** (`gpg --card-status`), **SSH** (`gpg-agent`), and **OpenKeychain** on mobile.
  - Supports on-token key generation, certificate storage (DO `0x7F21`), and public key URL (DO `0x5F50`).
- **OATH Authenticator (2FA):**
  - Hardware storage for up to 32 TOTP / HOTP accounts.
  - Compatible with Yubico Authenticator and companion tools over USB CCID, NFC, and BLE.
- **Dual-Mode NFC Engine (NXP PN532 over SPI):**
  - **Card Emulation (PICC Target):** Emulates an ISO 14443-4 contactless smart card. Tap to authenticate on Android/iOS via NFC.
  - **Reader / Scanner (PCD Initiator):** Can switch on-the-fly to scan, identify, and dump external RFID / MIFARE Classic / ISO 14443A transit & access cards.
- **Crash-Resilient Journaled Storage (`hypr_storage`):**
  - **Zero Dynamic Allocation:** 100% strict C11 with `malloc`/`free` prohibited across the entire codebase.
  - **1 → 0 Bit Burning Invariant:** Multi-phase atomic commits (`ALLOCATING` → `COMMITTED` → `INVALIDATED`) without block erasures during normal writes.
  - **Silicon-Bound Master Key:** 256-bit Storage Master Key (SMK) deterministically derived via Keccak SHAKE256 from factory-programmed hardware registers (`NRF_FICR->ER`, `IR`, `DEVICEID`).
  - **Authenticated Encryption:** All records encrypted at rest using constant-time **ChaCha20-Poly1305 (RFC 8439)** with deterministic Nonce derivation (`HYPR-NONCE-v2`).
  - **Wear-Leveling & Power-Loss Recovery:** 656 KB NOR flash storage partitioned across 164 pages with hardware POFCON low-voltage warning abort.
- **Triple Interface Support:**
  - **USB 2.0 Full-Speed Composite:** Simultaneous FIDO HID + CCID Smart Card + Virtual CDC UART.
  - **NFC (13.56 MHz):** High-speed passive smartcard emulation with dynamic APDU chaining.
  - **Bluetooth Low Energy (BLE 5.0):** Nordic S140 SoftDevice integration for wireless passkey and 2FA authentication.

---

## 🛠️ Hardware Bill of Materials (BOM)

| Component | Description | Connection / Pinout |
|---|---|---|
| **MCU** | SuperMini nRF52840 (HW-954 / Nice!Nano v2 clone) | Cortex-M4F, 1MB Flash, 256KB RAM, USB |
| **NFC Controller** | NXP PN532 Breakout Board | High-speed SPI (`SEL0=0, SEL1=0`) |
| **User Presence** | Capacitive Touch Pad or Tactile Button | Pin `P0.11` (internal pull-down) |
| **Status LED** | Blue/Green on-board LED | Pin `P0.15` (Active LOW) |
| **Hardware Reset** | Optional auto-reset via CH340 TX or button | Pin `P0.18` (RST / 1200 baud pulse) |

### Pinout Configuration

```
SuperMini nRF52840          NXP PN532 (SPI Mode)
+-------------------+       +-------------------+
|             3.3V  | ----> | VCC (3.3V)        |
|              GND  | ----> | GND               |
|      P1.13 (SCK)  | ----> | SCK               |
|      P1.11 (MOSI) | ----> | MOSI              |
|      P0.10 (MISO) | <---- | MISO              |
|      P0.09 (CS)   | ----> | NSS / SSEL        |
|      P0.24 (IRQ)  | <---- | IRQ               |
|      P0.22 (RST)  | ----> | RSTPDN            |
+-------------------+       +-------------------+
```

---

## 🗺️ Flash Memory Partitioning (1024 KB)

```
0x0000_0000 +--------------------------------------+
            | Nordic S140 SoftDevice v6.x (152 KB)  |
0x0002_6000 +--------------------------------------+
            | Zone A: Application Firmware (140 KB) |
            | (FIDO2, OpenPGP, OATH, PQC, BLE, USB) |
0x0004_9000 +--------------------------------------+
            | Zone B: hypr_storage Journal (656 KB) |
            | 164 pages * 4096 B (ChaCha20-Poly1305)|
0x000E_D000 +--------------------------------------+
            | Adafruit / Nice!Nano UF2 Bootloader   |
            | + MBR / Bootloader Settings (76 KB)   |
0x0010_0000 +--------------------------------------+
```

---

## 🚀 Building & Flashing

### Prerequisites
- `arm-none-eabi-gcc` (GCC for ARM Cortex-M, version 10+ recommended)
- `python3` (for UF2 binary packing)
- Windows PowerShell or Bash

### 1. Build Firmware
Run the automated build script:
```powershell
cd firmware/ble_fido
./build.ps1
```
This produces `ble_fido.bin`, `ble_fido.elf`, and `ble_fido.uf2`.

### 2. Flash to Device
1. Double-tap the reset button (or send a 1200-baud pulse over UART) to enter the UF2 bootloader.
2. A mass-storage drive named `NICENANO` will appear.
3. Copy `ble_fido.uf2` to the drive:
```powershell
Copy-Item ble_fido.uf2 E:\
```
The device will automatically reboot and start running HyprKey!

---

## 🔍 Verification & Testing

### OpenPGP Smart Card (USB CCID)
```bash
gpg --card-status
```
Output:
```text
Reader ...........: hyprkey hyprkey Smart Card 0
Application ID ...: D2760001240103040001000000010000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: PPC Card Systems
Name of cardholder: hyprkey OpenPGP User
Key attributes ...: nistp256 nistp256 nistp256
PIN retry counter : 3 0 3
Signature counter : 0
```

### WebAuthn / Passkeys
Navigate to [webauthn.io](https://webauthn.io) or [passkeys-debugger.io](https://passkeys-debugger.io) in Chrome, Brave, or Edge. Register a new Passkey and tap the touch pin to authenticate!

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

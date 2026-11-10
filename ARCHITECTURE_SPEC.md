# SYSTEM SPECIFICATION & ARCHITECTURAL BRIEF: HYPRKEY v2.0

## 1. PROJECT IDENTITY & ROLE
You are developing **HyprKey v2.0**, an open-source, multi-protocol post-quantum hardware security token (combining YubiKey 5 / Nitrokey 3 capabilities with native NIST FIPS 203 & FIPS 204 post-quantum cryptography and a distributed 2-of-3 Split-Trust container architecture).
- **Target Language & Standard:** Strict C11 (`-std=c11 -Wall -Wextra -Werror -pedantic -ffreestanding -fno-common`).
- **Prohibited Constructs:** Zero dynamic memory allocation (`malloc`/`free` are strictly banned), no heavy RTOS, no unaligned memory accesses, no suppressing compiler warnings.

---

## 2. HARDWARE PLATFORM & MEMORY MAP
- **MCU:** Nordic Semiconductor nRF52840 (ARM Cortex-M4F @ 64 MHz, FPU, CryptoCell-310 at `0x5002A000`, hardware TRNG `NRF_RNG`, power comparator `NRF_POWER->POFCON`, hardware MPU with 8 regions).
- **Silicon Requirement:** nRF52840 Rev 3 (Build Code AAF0 or newer) with two-stage hardware/firmware `APPROTECT` enabled.
- **Optional Co-Processor (Dual-Footprint PCB):** I2C footprint (SOIC-8/UDFN-8) for Microchip ATECC608B / NXP EdgeLock SE050 (`Pro` build stores `Share_MCU` inside SE; `DIY` build leaves footprint DNP and binds to `FICR`/`UICR`).
- **Power Architecture:** Rechargeable LiPo battery + USB VBUS. External NFC controller **NXP PN532** (SPI + IRQ) has its VCC rail gated via a P-channel MOSFET (powered only on button press or active session to hold sleep current under 2 uA). `NRF_POWER->POFCON` threshold is set to 2.8V (`POFWARN`).
- **SRAM Layout (256 KB Total: `0x20000000 - 0x20040000`):**
  - `0x20000000 - 0x20003600` (13.5 KB): Nordic SoftDevice S140 v7.3.0 RAM.
  - `0x20003600 - 0x20003640` (64 Bytes): `RAM_MASTER_KEYS` (`MSK[32]` + `MK[32]`). Protected by MPU (`Privileged Only`). Unconditionally wiped in `Reset_Handler` on Brown-Out Reset (BOR) and by `RTC1` timeout (60s idle on BLE/NFC, 10m on USB).
  - `69 KB Static BSS Scratchpad`: Shared matrix/polynomial workspace for ML-KEM/ML-DSA and Balloon KDF. Zeroed via `explicit_bzero()` before returning from any `SVC` call.
- **NOR Flash Layout (1024 KB Total, 4 KB page size, 10,000 erase cycles/page):**
  - `0x00000000 - 0x00026000` (152 KB): SoftDevice S140 v7.3.0.
  - `0x00026000 - 0x00046000` (128 KB): Core Firmware, Crypto Broker, Applet Code, Packed Mnemonic Wordlist.
  - `0x00046000 - 0x00048000` (8 KB, 2 Pages): **KeySlot Dual Header** (Primary & Backup `hypr_keyslot_header_t`).
  - `0x00048000 - 0x00050000` (32 KB, 8 Pages): **Zone A — Hot Unary Counters Ring** (32-bit word bitmaps burning `1 -> 0` without page erase for PIN attempts, `device_epoch`, `session_epoch`; 32,768 increments per page).
  - `0x00050000 - 0x000F4000` (656 KB, 164 Pages): **Zone B — Encrypted TLV Record Log** (162 active pages + 2 reserve pages for Copy-Before-Erase Garbage Collection).
  - `0x000F4000 - 0x00100000` (48 KB): Immutable Secure Bootloader verifying `Ed25519 + ML-DSA-65` firmware signatures and anti-rollback counter in `UICR`.
- **Transports:**
  - USB 2.0 FS Composite: IF0 HID FIDO2 (64B), IF1 CCID Smart Card (Bulk, up to 6 KB APDU), IF2 HID Keyboard (8B).
  - BLE 5.0: FIDO2 GATT + OATH GATT (Disabled by default; enabled via button; administrative/backup ops strictly blocked over BLE).
  - NFC (PN532): ISO 14443-4 Type A **Target Mode** (default, for readers & smartphone unlock) and **Initiator Mode** (triggered on button hold to read passive emergency NFC card).

---

## 3. CRYPTOGRAPHIC STACK & SECURITY INVARIANTS
1. **Asymmetric & Post-Quantum Primitives:**
   - Classical: `ECDSA secp256r1`, `Ed25519`, `X25519`.
   - Post-Quantum (NIST FIPS 203 / 204): `ML-KEM-768`, `ML-KEM-1024`, `ML-DSA-65`, `ML-DSA-87`.
   - **On-Demand Key Derivation:** Private PQC keys are never stored in Flash or persistent RAM; they are deterministically expanded on the fly from `MSK` via `cSHAKE256` into the 69 KB scratchpad.
   - **Fault-Attack Countermeasure (FIPS 204):** All `ML-DSA` signatures MUST use **Hedged Signing** (32-byte fresh `rnd` from `NRF_RNG`) followed by mandatory internal **Verify-after-Sign** (`ml_dsa_verify`) before outputting the signature. If verification fails, zero the buffer and return `SW_HARDWARE_FAULT (0x6F00)`.
2. **Symmetric, KDF & AEAD Primitives:**
   - **PRF / KDF / MAC:** NIST SP 800-185 `cSHAKE256` and `KMAC256` built on the existing `Keccak-f[1600]` sponge.
   - **PIN KDF:** **Balloon Hashing (`Balloon-cSHAKE256`)** operating over 64 KB of the PQC RAM scratchpad ($s=64\text{ KiB}, t=3$) taking ~300 ms on 64 MHz Cortex-M4.
   - **Container AEAD:** Constant-time **ChaCha20-Poly1305 (RFC 8439)** (256-bit key `MK`, 96-bit deterministic nonce, 128-bit tag).
   - **Deterministic Nonce Rule:** Nonces are NEVER drawn randomly for storage records. Always derive:
     `nonce[0..11] = KMAC256(MK, record_type || record_id || record_version, "HYPR_NONCE")`.

---

## 4. SPLIT-TRUST 2-OF-3 KEY HIERARCHY & UNLOCK PROTOCOL
Master secrets (`MSK` 256-bit seed and `MK` 256-bit storage key) are protected via a 2-of-3 threshold wrapping scheme in `hypr_keyslot_header_t`:
- **Share 1 (`Share_MCU`):** Derived from User PIN + `HW_SALT` (`FICR->DEVICEID || FICR->DEVICEADDR || UICR_TOKEN`) via `Balloon-cSHAKE256` (or via ATECC608B/SE050 on Pro builds).
- **Share 2 (`Share_Phone` — Daily Unlock):** Stored in smartphone TEE/StrongBox. Because iOS restricts HCE, **the smartphone acts as the NFC Reader** (`CoreNFC` / Android `IsoDep`) and **HyprKey acts as the ISO 14443-4 Target** (`AID: F048595052554E4C4B`).
  - *Protocol:* Phone sends `INS_INIT_UNLOCK` with $R_{phone}$ (16B). HyprKey increments `session_epoch` in Zone A and replies with $R_{dev}$ (16B) + `KMAC256(K_Auth_Device, R_phone || R_dev || session_epoch)`. Phone verifies tag, prompts user biometric, derives $K_{sess}$, and sends `Share_Phone` encrypted under `ChaCha20-Poly1305(K_sess)`.
- **Share 3 (`Share_Card` — Emergency Unlock):** Stored on a passive `NXP NTAG 424 DNA` / `DESFire EV3` smart card (or rolling-code tag). HyprKey switches PN532 to Initiator Mode and executes AES-128 challenge-response.
- **Anti-Bruteforce (`Write-Before-Verify`):** Upon receiving a PIN, MCU burns 1 bit (`1 -> 0`) in the Zone A unary PIN counter **BEFORE** executing `Balloon-cSHAKE256`. A successful 2-factor unlock burns a reset token and applies exponential backoff on failures.
- **Duress PIN:** Derives a deterministic decoy `MSK`/`MK` mounting a plausible decoy profile by default (silent header wipe in 85 ms is an opt-in flag).

---

## 5. APPLET ISOLATION (MPU + SVC BROKER)
Applets (`FIDO2`, `OpenPGP 3.4`, `Yubico OATH`, `NIST PIV`, `PassGen`) run in **Unprivileged Thread Mode** restricted by the Cortex-M4 MPU:
- Applets have zero direct access to Flash, `FICR`, `RAM_MASTER_KEYS`, or other applets' RAM.
- All cryptographic and storage operations go through **Privileged Handler Mode (`SVC` interrupts)**:
  - `svc_crypto_derive_and_sign(applet_id, key_path, msg, sig_out)`
  - `svc_storage_read(applet_id, record_id, ...)` / `svc_storage_write(...)`
- The kernel broker enforces domain separation by prepending the hardware-verified `applet_id` to the `cSHAKE256` customization string.

---

## 6. TWO-TIER BACKUP & STATELESS PASSWORD CANONICALIZATION
1. **Tier 1 (Offline Root):** 256-bit `MSK` is exported during initialization as a 16-word **Polyseed** (with GF(2048) Reed-Solomon error correction and creation timestamp) or **SLIP-39** (2-of-3 Shamir shares).
2. **Tier 2 (Zero-Trust Cloud Blob `HPK2`):**
   - Encrypted inside the MCU using `Final_BK = cSHAKE256(MSK || Balloon(App_Passphrase, export_salt), "HYPR_CLOUD_BACKUP_V2")`.
   - Streamed in 4 KB chunks over USB CCID to companion app -> untrusted cloud (Telegram Bot / S3 / GDrive).
   - **Anti-Rollback Hash Chain:** Header contains monotonic `backup_epoch` and `prev_backup_hash[32]`. Restoring onto a live token rejects older epochs; restoring onto a fresh token forces per-credential FIDO2 `signCount` jump (`+5000`).
3. **Stateless Password Manager (`HYPR_PASSGEN`):**
   - Normalizes domains to lowercase `eTLD+1` (`github.com`). Default profile: `counter = 1`, `length = 20`, `charset = Base62 + "!@#$%^&*"`.
   - Custom overrides and usernames are stored in a compact `PASS_META` TLV record included in Tier 2 backups.

---

## 7. BINARY C11 ABI & STORAGE ENGINE INVARIANTS
- **Header (`hypr_keyslot_header_t`):** Magic `0x32505948UL` ("HYP2"), dual-buffered across 2 pages (`0x00046000` and `0x00047000`) with monotonic `generation_seq`.
- **TLV Record (`hypr_tlv_record_hdr_v2_t`, 32 Bytes):**
  - `state_flags` transitions strictly via bit clearing (`1 -> 0`): `EMPTY (0xFFFFFFFF)` -> `ALLOCATING (0xFFFFFFFE)` -> `COMMITTED (0xFFFFFFFC)` -> `INVALIDATED (0xFFFFFFF0)`.
  - Update sequence: Write new record (`ALLOCATING` -> payload -> `COMMITTED`) **before** burning `INVALIDATED` on the previous version.
  - Garbage Collection (`hypr_storage_gc`): Copy-Before-Erase using 2 reserve pages (`HYPR_PAGE_STATE_COMPACTING = 0xFFFFFFFC`). Every Flash mutation checks `NRF_POWER->POFCON` (`pofwarn_is_active`) first.
  - Mount resolution (`hypr_storage_mount`): Builds an $O(1)$ SRAM lookup table (`index[1024]`), automatically invalidates `ALLOCATING` torn tails, and resolves duplicate `COMMITTED` records after power loss by keeping the higher `record_version` (or the `ACTIVE` page copy over `COMPACTING`).

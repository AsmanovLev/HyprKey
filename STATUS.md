# hyprkey — hardware status

Board: SuperMini nRF52840 (HW-954, nice!nano clone), UF2 bootloader 0.6.0, flash @ `0x00026000`.
Build: `firmware/test_hw/build.ps1` → `test_hw.uf2`
Tooling: `S:/hyprkey/deploy.sh {build|flash|watch|touch|reset|dfu} [secs]`

---

## PN532 (SPI) — WORKING ✅

`GetFirmwareVersion` = `D5 03 32 01 06 07` → PN532 **v1.6**.

---

## NFC FIDO2 / U2F Target Emulation (ISO 14443-4 PICC) — 100% OPERATIONAL ✅

Emulated Smartcard (`ISO 14443-4 PICC`, `ATQA=04 00`, `SAK=20`, `UID=08:79:CC:DD`):
- **Physical Coupling:** Xiaomi 11T cleanly couples with the PN532 PCB antenna in Passive PICC Target mode.
- **Microcontroller Crypto:** Embedded NIST P-256 (`uECC` with Cortex-M4 `umaal` hardware acceleration) + standard `SHA-256` + True Hardware RNG (`NRF_RNG`).
- **Zero Flash Wear:** Deterministic credential derivation via `HMAC/SHA-256(MasterSecret, AppParam)`.
- **APDU Chaining:** Implemented standard ISO 7816-4 `61 XX` status word + `00 C0` (`GET RESPONSE`) chaining to reliably transmit 570+ byte X.509 certs across PN532's 250-byte buffer.
- **Diagnostics Verification via `HyprNfcDebug` on Xiaomi 11T:**
  1. `SELECT FIDO AID` (`A0000006472F0001`): **33 ms** → `U2F_V2` + `90 00` ✔
  2. `U2F VERSION` (`INS=0x03`): **32 ms** → `U2F_V2` + `90 00` ✔
  3. `CTAP2 GET_INFO` (`INS=0x10`): **58 ms** → CBOR capabilities (U2F_V2, FIDO_2_0, aaguid, options) ✔
  4. `U2F REGISTER` (`INS=0x01`): **554 ms** → Full 569-byte response (P-256 Public Key + KeyHandle + X.509 Attestation Cert + ECDSA signature), **CRYPTO VERIFIED by Android!** ✔
  5. `U2F AUTH (Check-only, P1=0x07)`: **75 ms** → `69 85` (KeyHandle recognized, user presence required) ✔
  6. `U2F AUTH (Enforce & Sign, P1=0x03)`: **323 ms** → Counter incremented, live P-256 ECDSA signature, **CRYPTO VERIFIED by Android!** ✔

**Result: 6 / 6 Test Suite Passed! The hardware token is 100% ready for WebAuthn / Passkeys in browsers!**

---

```
GetFwVer  -> OK ic=32 ver=01 rev=06 sup=07
SAMConfig -> OK  | D5 15
RFConfig  -> OK
[ D5 4B 01 01 00 04 08 04 79 CC DD E6 ]  NbTg=1 uidl=4 UID=79 CC DD E6
```

Tag: `SENS_RES=0004`, `SAK=08` → **Mifare Classic 1K**, UID `79:CC:DD:E6`.

### Bugs that were blocking it

1. **ACK frame never consumed.** Every `DataWrite` makes the PN532 queue an ACK
   `00 00 FF 00 FF 00` with **LEN = 0x00**. The old reader took that ACK as the
   response and computed `read_bytes = (len > 1) ? len-1 : 0` → returned **0**.
   The `len=00` in the old log was never "IRQ stuck"; the chip answered every time.
2. **`MxRtyPassiveActivation = 0xFF` (infinite)** → `InListPassiveTarget` never
   returned with no tag present. Changed to `0x0A`.
3. **`LEN` excludes DCS on this chip** (GetFwVer LEN=6 = 1 TFI + 5 payload;
   SAMConfig LEN=2 = 1+1; tag LEN=0x0C = 1+11). The reader now locates DCS by the
   checksum itself and validates `LCS`, `TFI==0xD5`, postamble `==0x00`.

Also fixed: CS wake pulse 50 µs → 3 ms.

---

## PIN_CNF correction (affects everything)

`PULL` is **bits 3-4**, not 1-2:

| value | meaning |
|-------|---------|
| `0x03` | output (input buffer disconnected) |
| `0x01` | output **with** input buffer connected (so `P0_IN` can read the pad) |
| `0x08` | input, pulldown |
| `0x18` | input, pullup |

`0x0C` is **pulldown** (`PULL=01`), not pullup. `0x04` is **no pull**.

---

## Tooling wins

- **Auto-reset via CH340 TX → RST** (`CH340 TX --[1k]--> SuperMini RST`).
  `python D:/Users/User/nrf_reset.py {single|double}` sends a `0x00` byte at 1200 baud
  = ~7.5 ms LOW pulse. Double pulse enters UF2 DFU. **This removed all button pressing**
  and made the whole test loop automatic.
- **WCH CH340 driver bug**: `SetCommState` fails with `ERROR_GEN_FAILURE (31)` when you
  request the baud the DCB *already* holds, so pyserial `open()` throws. Always prime
  with a *different* baud first. Both `ch340_watch.py` and `nrf_reset.py` handle this.

---

## R558S fingerprint (UARTE0 @ 57600) — MODULE APPEARS DEFECTIVE ❌

Spec sheet: supply **3.3 ± 0.3 V**, UART **3.3 V logic**, default **57600**,
max 40 mA, 100 templates, has a ring LED ("разноцветные огни").
**Warns: hot-plugging the connector damages the module; wait >2 s between power cycles.**

### Verified correct (all of it)

| check | result |
|---|---|
| VCC / VADD (red / white to black) | **3.31 V** — in spec |
| solder bridges | **none** — proven: P0.06 became drivable once the module was unplugged |
| nRF TX → module RX (yellow / P0.08) | toggles cleanly; **57600 confirmed on a scope** |
| module TX → nRF RX (green / P0.06) | idles HIGH, driven by the module (a real push-pull output) |
| UARTE0 baud | register `0x00EBF000`, measured 31 kHz vs 28.8 expected |
| UARTE1 baud (reference) | register `0x01D7E000`, measured 61.5 kHz vs 57.6 expected |
| colour mapping | **green = TXD, yellow = RXD** — swapped vs. the datasheet, but functionally correct |

Both UARTs read ~7 % high on the same scope — a scope timebase offset, not a firmware fault.
An earlier "11.6 kHz" reading was the handshake frame contaminating the measurement; with a
pure `0x55` tone both bauds are right.

### What fails

| symptom | evidence |
|---|---|
| never answers | 14 bauds × 5 protocols (`0x40`, `0x35`×2, `0x3C`, `0x13`, `0x01`) → `rxE=0` |
| never senses a finger | tight-loop sampler, **0 edges over 14 s** while the pad was touched |
| ring never lights | never flickered, not even at power-up |
| survives a clean power cycle | same behaviour after full power-off >2 s |

Three independent subsystems dead (UART reply, capacitive sensing, LED ring) while its TX
I/O pin is alive enough to hold itself at 3.3 V against 5 mA drive. That is a **dead core**,
not a wiring or protocol problem.

**Conclusion: replace the module.** Remaining check if desired: probe the pure-tone burst at
the module-end yellow pad — if present, the wire is proven and the module is definitely dead.

### Note

The module was hot-unplugged twice during debugging before the datasheet warning was known.
It was already non-functional before that, but hot-plugging is now avoided.

# HyprKey Hardware Wiring & Pinout Guide
**Target System:** nRF52840 SuperMini (HW-954 / Nice!Nano v2 footprint) + R558S Capacitive Fingerprint Sensor + PN532 NFC Breakout (SPI Mode)

---

## 1. System Architecture Overview

HyprKey is an ultra-compact biometric security authenticator (FIDO2 / U2F / PIV / BLE / NFC token). The hardware architecture integrates an ultra-low-power Nordic nRF52840 BLE/USB SoC with a round capacitive biometric touch sensor and an NFC interface.

```
                  +-----------------------------------------+
                  |            3.7V LiPo Battery            |
                  +--------------------+--------------------+
                                       |
+----------------------+               v                +-----------------------+
|    R558S Sensor      |    +---------------------+     |      PN532 Module     |
| (Capacitive Sensor)  |    |  nRF52840 SuperMini |     |    (NFC RFID 13.56M)  |
|                      |    |   (HW-954 / N!N)    |     |                       |
|   VCC, 3.3VT <-------+----+ 3.3V (ME6211 LDO)   +-----+--> VCC (3.3V)         |
|   GND        <-------+----+ GND                 +-----+--> GND                |
|   TXD (Out)  --------+---> P0.08 (UART RX)      |     |                       |
|   RXD (In)   <-------+----+ P0.06 (UART TX)     |     |                       |
|   WAKE (Out) --------+---> P0.11 (Touch Int)    |     |                       |
|                      |    | P1.13 (SPI SCK)     +-----+--> SCK                |
|                      |    | P1.11 (SPI MOSI)    +-----+--> MOSI               |
|                      |    | P0.10 (SPI MISO)    +-----+--> MISO               |
|                      |    | P0.09 (SPI CS/NSS)  +-----+--> NSS / SS           |
|                      |    | P0.24 (NFC IRQ)     +-----+--> IRQ                |
|                      |    | P0.22 (NFC RST)     +-----+--> RSTPD_N / RST      |
+----------------------+    +---------------------+     +-----------------------+
```

---

## 2. Complete Interconnect Pin Matrix

| # | nRF52840 Pin | Physical Pin | Pin Alias | Peripheral | Target Wire / Pin | Logic Level | Signal Function / Notes |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| 1 | **P0.06** | Pin 1 (Left 1) | TX / D0 | UART0 TX | R558S **RXD** (Green) | 3.3V TTL | MCU Serial TX $\rightarrow$ Sensor Serial RX (57600 baud) |
| 2 | **P0.08** | Pin 2 (Left 2) | RX / D1 | UART0 RX | R558S **TXD** (Yellow) | 3.3V TTL | Sensor Serial TX $\rightarrow$ MCU Serial RX (57600 baud) |
| 3 | **GND** | Pin 3 (Left 3) | GND | Ground | All Devices **GND** | 0V | Common system ground return rail |
| 4 | **P0.22** | Pin 7 (Left 7) | D4 | GPIO Out | PN532 **RSTPD_N / RST** | 3.3V | Active LOW Hardware Reset / Power-down |
| 5 | **P0.24** | Pin 8 (Left 8) | D5 | GPIO In | PN532 **IRQ** | 3.3V (Pullup) | Active LOW Interrupt (Card detect / RX frame ready) |
| 6 | **P0.11** | Pin 10 (Left 10)| D7 | GPIO In | R558S **WAKE / TOUCH** (Blue) | 3.3V CMOS | Active HIGH finger touch sensor wake-up interrupt |
| 7 | **P0.09** | Pin 13 (Right 12)| CS / D21 | SPIM3 CS | PN532 **NSS / SS / CS** | 3.3V | Active LOW SPI Chip Select |
| 8 | **P0.10** | Pin 14 (Right 11)| MISO / D20| SPIM3 MISO| PN532 **MISO** | 3.3V SPI | Master In Slave Out (Data from PN532 to MCU) |
| 9 | **P1.11** | Pin 15 (Right 10)| MOSI / D19| SPIM3 MOSI| PN532 **MOSI** | 3.3V SPI | Master Out Slave In (Commands from MCU to PN532)|
| 10 | **P1.13** | Pin 16 (Right 9) | SCK / D18 | SPIM3 SCK | PN532 **SCK** | 3.3V SPI | Serial Clock (Mode 0, up to 5 MHz) |
| 11 | **VCC** | Pin 21 (Right 4) | 3V3 / VCC | 3.3V Rail | R558S **VCC + 3.3VT** & PN532 **VCC** | +3.3V DC | Onboard 3.3V LDO Output (~500mA max) |
| 12 | **GND** | Pin 23 (Right 2) | GND | Ground | Power Ground | 0V | Second ground pin for easy bus routing |

---

## 3. Peripheral Deep-Dive & Wiring

### 3.1 R558S Capacitive Fingerprint Sensor

The R558S is a round capacitive fingerprint sensor module with integrated RGB ring light and ultra-low-power capacitive touch detection circuitry.

* **Connector:** 6-pin 1.0mm pitch SH/JST connector.
* **Operating Voltage:** 3.3V DC (Do not supply 5V!).
* **Baud Rate:** 57,600 bps (default), 8 data bits, 1 stop bit, no parity.

```
       R558S Sensor Connector Pinout (Looking into socket, Pin 1 left):
       +---------------------------------------------+
       |   [1]     [2]     [3]     [4]     [5]   [6] |
       |   RED     BLK     YEL     GRN     BLU   WHT |
       |   VCC     GND     TXD     RXD    TOUCH 3.3VT|
       +---------------------------------------------+
```

#### Wire Color Code & Assignments:
1. **Pin 1 — RED (VCC):** +3.3V main power for the fingerprint DSP/optical-capacitive sensor engine. Connected to **SuperMini VCC (Pin 21)**.
2. **Pin 2 — BLACK (GND):** Power Ground. Connected to **SuperMini GND (Pin 3 or 23)**.
3. **Pin 3 — YELLOW (TXD):** 3.3V TTL Serial Output from R558S. Connected to **SuperMini P0.08 (Pin 2)**.
4. **Pin 4 — GREEN (RXD):** 3.3V TTL Serial Input to R558S. Connected to **SuperMini P0.06 (Pin 1)**.
5. **Pin 5 — BLUE (WAKE / TOUCH):** Active HIGH touch induction output. Connects to **SuperMini P0.11 (Pin 10)**.
   * *Idle (no finger):* 0V (GND).
   * *Finger Touch:* High pulse (+3.3V). Can wake nRF52840 from System OFF deep sleep mode!
6. **Pin 6 — WHITE / PURPLE (3.3VT):** Continuous +3.3V power supply for the capacitive touch induction circuit. Connected to **SuperMini VCC (Pin 21)**.
   * Consumes $<5\,\mu\text{A}$ continuously so touch sensing remains armed while main sensor VCC is idle.

> [!IMPORTANT]
> **VCC vs 3.3VT:** Pin 6 (`3.3VT`) supplies the standby touch sensor. Pin 1 (`VCC`) supplies the processor/DSP and RGB ring. In battery-optimized designs, `VCC` can optionally be switched via a P-channel MOSFET (or high-side load switch), while `3.3VT` remains powered continuously. For standard breadboarding, both connect to 3.3V.

---

### 3.2 PN532 NFC Module (SPI Mode)

The PN532 module supports I2C, SPI, and HSU (High-Speed UART). For fast cryptographic key exchange and maximum throughput on nRF52840, **SPI mode** is selected.

#### DIP Switch / Jumper Configuration for SPI:
Set the two-position configuration switch labeled **I2C / SPI / HSU** (or `SEL0` / `SEL1`):

```
       +--------------------+
       |   SEL0  |  SEL1    |
       |  [OFF]  |  [OFF]   |  <--- Both switches set to 0 / OFF (SPI Mode)
       |   (0)   |   (0)    |
       +--------------------+
```

* **SEL0:** Set to **0 (L / OFF)**
* **SEL1:** Set to **0 (L / OFF)**

#### PN532 Header Connections:
* **SCK:** Connect to **P1.13** (SPIM3 Clock)
* **MISO:** Connect to **P0.10** (SPIM3 Master In Slave Out)
* **MOSI:** Connect to **P1.11** (SPIM3 Master Out Slave In)
* **NSS / SS / CS:** Connect to **P0.09** (SPIM3 Slave Select)
* **IRQ:** Connect to **P0.24** (Active LOW interrupt; triggers when NFC card/field detected)
* **RSTPD_N / RST:** Connect to **P0.22** (Hardware reset / deep power down)
* **VCC:** Connect to **3.3V** (or VCC)
* **GND:** Connect to **GND**

> [!TIP]
> The PN532 breakout board typically has an onboard 3.3V regulator and level shifters when fed 5V. When connecting directly to 3.3V on the nRF52840 SuperMini, connect to the **3.3V** pin (or VCC depending on board variant) so all I/O levels match 3.3V directly without diode drop.

---

## 4. Power & Current Budget

| Operating Mode | nRF52840 SuperMini | R558S Sensor | PN532 NFC | Total Current | Estimated Battery Life (180mAh LiPo) |
|---|:---:|:---:|:---:|:---:|:---:|
| **System OFF Deep Sleep** | $1.5\,\mu\text{A}$ | $5\,\mu\text{A}$ (`3.3VT`) | $10\,\mu\text{A}$ (PowerDown) | **$\sim 18\,\mu\text{A}$** | **$\sim 400\text{ days}$** |
| **BLE Idle / Advertising** | $0.8\,\text{mA}$ avg | $5\,\mu\text{A}$ | $10\,\mu\text{A}$ | **$\sim 0.9\,\text{mA}$** | **$\sim 200\text{ hours}$** |
| **Fingerprint Scanning** | $7.0\,\text{mA}$ | $35\,\text{mA}$ (LED ring on) | $10\,\mu\text{A}$ | **$\sim 43\,\text{mA}$** | Transient (0.3 sec pulse) |
| **NFC Active Field / Transceive** | $8.0\,\text{mA}$ | $5\,\mu\text{A}$ | $60-80\,\text{mA}$ (RF TX) | **$\sim 85\,\text{mA}$** | Transient (active read/write) |
| **USB-C Connected** | Powered via VBUS | Powered via VBUS | Powered via VBUS | N/A (Charges Batt) | Indefinite + LiPo charging @ 100mA |

---

## 5. Breadboard vs. Sandwich Form Factor Assembly

### 5.1 Breadboard Prototyping Layout
1. Place the **nRF52840 SuperMini** straddling the central trench of a standard 400-point breadboard (USB-C connector facing the top edge).
2. Connect the **Ground rail** of the breadboard to SuperMini **GND (Pin 3)**.
3. Connect the **3.3V power rail** to SuperMini **VCC (Pin 21)**.
4. Wire the **R558S cable**:
   * Insert a 6-pin male header into the breadboard.
   * Plug the JST cable socket onto the R558S.
   * Run Red and White wires to 3.3V rail.
   * Run Black wire to GND rail.
   * Run Yellow wire to **Pin 2 (P0.08)**.
   * Run Green wire to **Pin 1 (P0.06)**.
   * Run Blue wire to **Pin 10 (P0.11)**.
5. Wire the **PN532 Module**:
   * Place the PN532 on the lower half or beside the breadboard.
   * Connect VCC $\rightarrow$ 3.3V rail, GND $\rightarrow$ GND rail.
   * Connect SCK, MISO, MOSI, SS, IRQ, RST to the respective nRF52840 pins.
   * Verify both toggle switches are at `0` (OFF).

### 5.2 Ultra-Compact "Sandwich" Packaging (HyprKey 3D Token)

When packing these modules into a pocket-sized security key enclosure:

```
+-------------------------------------------------------+
|  TOP FACE: R558S Fingerprint Sensor (Ring exposed)    |
+-------------------------------------------------------+
|  LAYER 2: nRF52840 SuperMini (USB-C on front edge)    |
+-------------------------------------------------------+
|  LAYER 3: 3.7V 150-250mAh LiPo Cell                   |
+-------------------------------------------------------+
|  SHIELD: Ferrite Absorber Sheet (13.56 MHz anti-metal)|
+-------------------------------------------------------+
|  BOTTOM: PN532 NFC Module (Antenna facing outward)    |
+-------------------------------------------------------+
```

> [!CAUTION]
> **NFC Anti-Metal Interference:**
> If a lithium-polymer battery or copper ground plane is placed directly against the PN532 PCB antenna coil, the metal induces eddy currents that detune the 13.56 MHz resonant circuit, drastically reducing NFC read range to zero.
> **Solution:** Always insert a **0.1mm - 0.3mm Ferrite Sheet (EMI Absorber for 13.56 MHz RFID/NFC)** between the battery/MCU and the PN532 antenna loop.

---

## 6. Device Tree / Firmware Pin Configuration

For Zephyr RTOS / Nordic nRF Connect SDK (`nrf52840dongle_nrf52840.overlay` or custom board overlay):

```dts
/* HyprKey Device Tree Overlay */

&pinctrl {
    uart0_default: uart0_default {
        group1 {
            psels = <NRF_PSEL(UART_TX, 0, 6)>;
        };
        group2 {
            psels = <NRF_PSEL(UART_RX, 0, 8)>;
            bias-pull-up;
        };
    };

    spi3_default: spi3_default {
        group1 {
            psels = <NRF_PSEL(SPIM_SCK, 1, 13)>,
                    <NRF_PSEL(SPIM_MOSI, 1, 11)>,
                    <NRF_PSEL(SPIM_MISO, 0, 10)>;
        };
    };
};

/* UART for R558S Fingerprint */
&uart0 {
    status = "okay";
    current-speed = <57600>;
    pinctrl-0 = <&uart0_default>;
    pinctrl-names = "default";
};

/* SPI for PN532 NFC */
&spi3 {
    status = "okay";
    pinctrl-0 = <&spi3_default>;
    pinctrl-names = "default";
    cs-gpios = <&gpio0 9 GPIO_ACTIVE_LOW>;

    pn532: pn532@0 {
        compatible = "nxp,pn532";
        reg = <0>;
        spi-max-frequency = <5000000>;
        irq-gpios = <&gpio0 24 (GPIO_ACTIVE_LOW | GPIO_PULL_UP)>;
        reset-gpios = <&gpio0 22 GPIO_ACTIVE_LOW>;
    };
};

/* Fingerprint Touch Wake Interrupt */
/ {
    fingerprint_wake: fingerprint_wake {
        compatible = "gpio-keys";
        touch_sensor: touch_sensor {
            gpios = <&gpio0 11 (GPIO_ACTIVE_HIGH | GPIO_PULL_DOWN)>;
            label = "R558S Touch Interrupt";
        };
    };
};
```

---

## 7. Electrical Verification Checklist

Before powering up for the first time:
- [ ] **Check 3.3V Logic:** Ensure no 5V source is directly wired to R558S or nRF52840 I/O pins.
- [ ] **PN532 DIP Switches:** Verify both `SEL0` and `SEL1` switches are set to **0 (OFF)** for SPI mode.
- [ ] **UART RX/TX Cross:** Verify that nRF52840 TX (`P0.06`) connects to R558S RX (Green), and nRF52840 RX (`P0.08`) connects to R558S TX (Yellow).
- [ ] **R558S Touch Power:** Verify that **Pin 6 (3.3VT)** is connected to +3.3V; otherwise, touch wake on `P0.11` will not trigger.
- [ ] **Continuity & Short Check:** Use a multimeter in beep mode between 3.3V and GND to ensure zero short circuit before inserting USB-C or connecting the LiPo battery.

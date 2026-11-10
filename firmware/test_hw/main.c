#include <stdint.h>
#include <stdbool.h>

#define FP_SNIFF 0   /* 1 = raw line sniffer instead of UART polling */
#define FP_TOUCHMETER 0  /* 1 = fast P0.11 edge meter only */
#define FP_TXTONE 0
#define FP_QUIET 0       /* 1 = quiet pin-ID mode, nRF drives nothing */      /* 1 = scope-friendly TX tone on P0.08 */

/* ==================== nRF52840 Memory Map ==================== */
#define CLOCK_BASE 0x40000000UL
#define UART1_BASE 0x40028000UL
#define UART0_BASE 0x40002000UL   /* R558S fingerprint, 57600 on P0.06/P0.08 */
#define P0_BASE    0x50000000UL
#define P1_BASE    0x50000300UL

#define CLOCK_TASKS_HFCLKSTART    (*(volatile uint32_t *)(CLOCK_BASE + 0x000))
#define CLOCK_EVENTS_HFCLKSTARTED (*(volatile uint32_t *)(CLOCK_BASE + 0x100))

/* GPIO */
#define P0_OUTSET       (*(volatile uint32_t *)(P0_BASE + 0x508))
#define P0_OUTCLR       (*(volatile uint32_t *)(P0_BASE + 0x50C))
#define P0_IN           (*(volatile uint32_t *)(P0_BASE + 0x510))
#define P0_DIRSET       (*(volatile uint32_t *)(P0_BASE + 0x518))
#define P0_PIN_CNF(n)   (*(volatile uint32_t *)(P0_BASE + 0x700 + ((n) * 4)))

#define P1_OUTSET       (*(volatile uint32_t *)(P1_BASE + 0x508))
#define P1_OUTCLR       (*(volatile uint32_t *)(P1_BASE + 0x50C))
#define P1_IN           (*(volatile uint32_t *)(P1_BASE + 0x510))
#define P1_DIRSET       (*(volatile uint32_t *)(P1_BASE + 0x518))
#define P1_PIN_CNF(n)   (*(volatile uint32_t *)(P1_BASE + 0x700 + ((n) * 4)))

/* UARTE1 - CH340 debug, 115200 on P0.10 */
#define UART1_TASKS_STARTTX   (*(volatile uint32_t *)(UART1_BASE + 0x008))
#define UART1_ENABLE          (*(volatile uint32_t *)(UART1_BASE + 0x500))
#define UART1_PSEL_TXD        (*(volatile uint32_t *)(UART1_BASE + 0x50C))
#define UART1_PSEL_RXD        (*(volatile uint32_t *)(UART1_BASE + 0x514))
#define UART1_BAUDRATE        (*(volatile uint32_t *)(UART1_BASE + 0x524))
#define UART1_TXD_PTR         (*(volatile uint32_t *)(UART1_BASE + 0x544))
#define UART1_TXD_MAXCNT      (*(volatile uint32_t *)(UART1_BASE + 0x548))
#define UART1_EVENTS_ENDTX    (*(volatile uint32_t *)(UART1_BASE + 0x120))

/* UARTE0 - R558S fingerprint */
#define UART0_TASKS_STARTRX   (*(volatile uint32_t *)(UART0_BASE + 0x000))
#define UART0_TASKS_STOPRX    (*(volatile uint32_t *)(UART0_BASE + 0x004))
#define UART0_TASKS_STARTTX   (*(volatile uint32_t *)(UART0_BASE + 0x008))
#define UART0_TASKS_STOPTX    (*(volatile uint32_t *)(UART0_BASE + 0x00C))
#define UART0_TASKS_FLUSHRX   (*(volatile uint32_t *)(UART0_BASE + 0x01C))
#define UART0_EVENTS_ENDRX    (*(volatile uint32_t *)(UART0_BASE + 0x110))
#define UART0_EVENTS_ENDTX    (*(volatile uint32_t *)(UART0_BASE + 0x120))
#define UART0_EVENTS_ENDTX_ALT (*(volatile uint32_t *)(UART0_BASE + 0x150))
#define UART0_ENABLE          (*(volatile uint32_t *)(UART0_BASE + 0x500))
#define UART0_PSEL_TXD        (*(volatile uint32_t *)(UART0_BASE + 0x50C))
#define UART0_PSEL_RXD        (*(volatile uint32_t *)(UART0_BASE + 0x514))
#define UART0_BAUDRATE        (*(volatile uint32_t *)(UART0_BASE + 0x524))
#define UART0_RXD_PTR         (*(volatile uint32_t *)(UART0_BASE + 0x534))
#define UART0_RXD_MAXCNT      (*(volatile uint32_t *)(UART0_BASE + 0x538))
#define UART0_RXD_AMOUNT      (*(volatile uint32_t *)(UART0_BASE + 0x53C))
#define UART0_TXD_PTR         (*(volatile uint32_t *)(UART0_BASE + 0x544))
#define UART0_TXD_MAXCNT      (*(volatile uint32_t *)(UART0_BASE + 0x548))
#define UART0_ERRORS          (*(volatile uint32_t *)(UART0_BASE + 0x300))

/* 57600 baud = UART_BAUDRATE_BAUDRATE_Baud57600 (NOT 0x00EBE000) */
#define FP_BAUD_57600         0x00EBF000UL

/* PIN_CNF: bits1-2 = INPUT(0=connect,1=disconnect), bits3-4 = PULL
 *   0x03 = output (dir=out, input disconnected)
 *   0x08 = input, PULL=01 pulldown
 *   0x18 = input, PULL=11 pullup
 * NOTE 0x0C is pulldown (PULL=01) + INPUT=2, not pullup. */
#define CNF_OUT     0x00000003UL
#define CNF_IN_PD   0x00000008UL
#define CNF_IN_PU   0x00000018UL

/* ==================== Pins ==================== */
#define PIN_LED       15   /* P0.15, active LOW */
#define PIN_DBG_TX    10   /* P0.10 -> CH340 RX */

#define PIN_SPI_SCK   17   /* P0.17 */
#define PIN_SPI_MISO  20   /* P0.20 */
#define PIN_SPI_MOSI  22   /* P0.22 */
#define PIN_SPI_CS    24   /* P0.24, active LOW */

#define PIN_NFC_RST   6    /* P1.06 */
#define PIN_NFC_IRQ   4    /* P1.04 */

#define PIN_FP_WAKE   11   /* P0.11, R558S touch WAKE (active HIGH) */
#define PIN_FP_TX     6    /* P0.06 -> sensor RXD */
#define PIN_FP_RX     8    /* P0.08 <- sensor TXD */

#define PIN_CS_HI()  (P0_OUTSET = (1UL << PIN_SPI_CS))
#define PIN_CS_LO()  (P0_OUTCLR = (1UL << PIN_SPI_CS))

/* ==================== Delay ==================== */
static void delay_cycles(volatile uint32_t n) { while (n--) __asm__ volatile ("nop"); }
static void delay_us(uint32_t us) { delay_cycles(us * 16); }   /* ~64 MHz */
static void delay_ms(uint32_t ms) { while (ms--) delay_us(1000); }

static inline void led_on(void)  { P0_OUTCLR = (1UL << PIN_LED); }
static inline void led_off(void) { P0_OUTSET = (1UL << PIN_LED); }

/* ==================== Debug output (SRAM for EasyDMA) ==================== */
static uint8_t dma_buf[256] __attribute__((aligned(4)));

static void dbg_send(const uint8_t *d, uint16_t len) {
    if (!len) return;
    for (uint16_t i = 0; i < len && i < 256; i++) dma_buf[i] = d[i];
    UART1_TXD_PTR = (uint32_t)dma_buf;
    UART1_TXD_MAXCNT = len;
    UART1_EVENTS_ENDTX = 0;
    UART1_TASKS_STARTTX = 1;
    while (!UART1_EVENTS_ENDTX);
}

/* tiny string builder so debug lines are one DMA burst and never split */
static char     obuf[224];
static uint16_t olen;

static void o_reset(void)              { olen = 0; }   /* used by nothing? keep for clarity */
static void o_ch(char c)               { if (olen < sizeof(obuf) - 1) obuf[olen++] = c; }
static void o_str(const char *s)       { while (*s) o_ch(*s++); }
static void o_hex(uint8_t b)           { const char h[] = "0123456789ABCDEF"; o_ch(h[b >> 4]); o_ch(h[b & 15]); }
static void o_hexsp(uint8_t b)         { o_hex(b); o_ch(' '); }
static void o_hex32(uint32_t v) { o_hex((uint8_t)(v>>24)); o_hex((uint8_t)(v>>16)); o_hex((uint8_t)(v>>8)); o_hex((uint8_t)v); }
static void o_dec(uint16_t v)          { char t[6]; int i = 0; if (!v) { o_ch('0'); return; } while (v) { t[i++] = '0' + (v % 10); v /= 10; } while (i--) o_ch(t[i]); }
static void o_flush(void)              { dbg_send((const uint8_t *)obuf, olen); olen = 0; }

/* P() appends, it must NOT reset (o_flush() resets after each line) */
#define P(...) do { o_str(__VA_ARGS__); } while (0)
#define PL()   do { o_str("\r\n"); o_flush(); } while (0)

/* ==================== Bit-banged SPI (LSB first, mode 0) ==================== */
static uint8_t spi_xfer(uint8_t b) {
    uint8_t rx = 0;
    for (int i = 0; i < 8; i++) {
        if (b & (1u << i)) P0_OUTSET = (1UL << PIN_SPI_MOSI);
        else               P0_OUTCLR = (1UL << PIN_SPI_MOSI);
        delay_us(2);
        P0_OUTSET = (1UL << PIN_SPI_SCK);
        delay_us(2);
        if (P0_IN & (1UL << PIN_SPI_MISO)) rx |= (uint8_t)(1u << i);
        P0_OUTCLR = (1UL << PIN_SPI_SCK);
        delay_us(2);
    }
    return rx;
}

/* ==================== PN532 SPI transport ==================== */
/* PN532 frame on the wire:  00 00 FF LEN LCS TFI PD... DCS 00
 * LEN counts TFI + PD... + DCS.   LCS = ~LEN+1,  DCS = ~(TFI+PD..)+1
 * After DataWrite the chip queues an ACK frame:  00 00 FF 00 FF 00  (LEN = 0x00)
 * That ACK MUST be consumed, otherwise the next DataRead returns it. */

enum { PN_OK = 0, PN_NOFRAME = -1, PN_TIMEOUT = -2 };

static uint8_t  g_len, g_lcs, g_tfi, g_dcs;
static uint8_t  g_frame_ok;

/* read one frame; returns payload length (bytes incl TFI+DCS), 0 for ACK,
 * PN_NOFRAME if no preamble found.  */
static int pn532_read_frame(uint8_t *out, uint16_t max) {
    g_len = g_lcs = g_tfi = g_dcs = 0;
    g_frame_ok = 0;

    PIN_CS_LO();
    delay_us(20);
    spi_xfer(0x03);                       /* DataRead */

    /* hunt for preamble 00 00 FF */
    uint8_t a = 0, b = 0;
    bool found = false;
    for (int i = 0; i < 160; i++) {
        uint8_t c = spi_xfer(0x00);
        if (a == 0x00 && b == 0x00 && c == 0xFF) { found = true; break; }
        a = b; b = c;
    }
    if (!found) { delay_us(20); PIN_CS_HI(); delay_us(20); return PN_NOFRAME; }

    uint8_t len = spi_xfer(0x00);
    uint8_t lcs = spi_xfer(0x00);
    g_len = len; g_lcs = lcs;

    uint16_t n = 0;
    uint8_t  sum = 0;
    for (uint16_t i = 0; i < len; i++) {
        uint8_t d = spi_xfer(0x00);
        sum += d;
        if (n < max) out[n++] = d;
    }

    /* Do not trust LEN to say whether DCS is included: locate DCS by the
     * checksum itself. DCS is the byte that makes TFI+PD+DCS == 0. */
    bool have_dcs = false;
    if (len >= 2 && (sum & 0xFF) == 0) {
        g_dcs = out[n - 1];       /* last byte inside LEN was the DCS */
        n -= 1;
        have_dcs = true;
    } else {
        for (int k = 0; k < 3; k++) {
            uint8_t c = spi_xfer(0x00);
            if (((sum + c) & 0xFF) == 0) { g_dcs = c; have_dcs = true; break; }
            sum += c;                       /* was payload, not DCS */
            if (n < max) out[n++] = c;
        }
    }

    uint8_t post = spi_xfer(0x00);   /* postamble, must be 0x00 */
    delay_us(20);
    PIN_CS_HI();
    delay_us(20);

    if (n >= 1) g_tfi = out[0];
    g_frame_ok = (uint8_t)(have_dcs && n >= 2 && out[0] == 0xD5 && post == 0x00);

    return (int)n;
}

/* STATREAD: status byte bit0 = 1 -> chip ready */
static uint8_t pn532_status(void) {
    PIN_CS_LO();
    delay_us(20);
    spi_xfer(0x02);
    uint8_t s = spi_xfer(0x00);
    delay_us(20);
    PIN_CS_HI();
    delay_us(20);
    return s;
}

static bool pn532_wait_ready(uint16_t timeout_ms) {
    for (uint16_t t = 0; t < timeout_ms; t++) {
        if (pn532_status() & 0x01) return true;
        delay_ms(1);
    }
    return false;
}

/* CS must stay LOW >= 1..2 ms to wake the 27.12 MHz oscillator */
static void pn532_wakeup(void) {
    PIN_CS_LO();
    delay_ms(3);
    PIN_CS_HI();
    delay_ms(2);
}

static void pn532_send(const uint8_t *pd, uint8_t len) {
    uint8_t lenb = (uint8_t)(len + 1);                  /* TFI + PD + DCS */
    uint8_t lcs  = (uint8_t)(~lenb + 1);
    uint8_t sum  = 0xD4;                                /* TFI */
    for (uint8_t i = 0; i < len; i++) sum += pd[i];
    uint8_t dcs  = (uint8_t)(~sum + 1);

    PIN_CS_LO();
    delay_us(20);
    spi_xfer(0x01);          /* DataWrite */
    spi_xfer(0x00);          /* }\ preamble: these two zeros double */
    spi_xfer(0x00);          /* }  as the frame's leading 00 00      */
    spi_xfer(0xFF);
    spi_xfer(lenb);
    spi_xfer(lcs);
    spi_xfer(0xD4);          /* TFI host->PN532 */
    for (uint8_t i = 0; i < len; i++) spi_xfer(pd[i]);
    spi_xfer(dcs);
    spi_xfer(0x00);          /* postamble */
    delay_us(20);
    PIN_CS_HI();
    delay_us(20);
}

/* send command, consume ACK, return real response.
 * returns payload byte count (out[0]=TFI 0xD5, out[1]=PD0 ...) or <0 on error */
static int pn532_exec(const uint8_t *pd, uint8_t plen, uint8_t *out, uint16_t max,
                      uint16_t timeout_ms) {
    pn532_send(pd, plen);

    for (int guard = 0; guard < 6; guard++) {
        if (!pn532_wait_ready(timeout_ms)) return PN_TIMEOUT;
        int n = pn532_read_frame(out, max);
        if (n == PN_NOFRAME) continue;
        if (n == 0) continue;                    /* ACK - discard, wait for response */
        if (g_frame_ok) return n;                /* valid D5 frame */
        /* bad LCS/DCS: discard and keep trying */
    }
    return PN_NOFRAME;
}

static void pn532_drain(void) {
    uint8_t tmp[64];
    for (int i = 0; i < 8; i++) {
        if (!(pn532_status() & 0x01)) break;
        pn532_read_frame(tmp, sizeof(tmp));
    }
}

static void dump_frame(int n, const uint8_t *buf) {
    o_str(" len="); o_hex(g_len);
    o_str(" lcs="); o_hex(g_lcs);
    o_str(" tfi="); o_hex(g_tfi);
    o_str(" dcs="); o_hex(g_dcs);
    o_str(" ok=");  o_ch(g_frame_ok ? '1' : '0');
    if (n > 0) {
        o_str(" | ");
        for (int i = 0; i < n && i < 12; i++) o_hexsp(buf[i]);
    }
    (void)o_reset;
}

/* ==================== Grow R558S fingerprint (UARTE0 @57600) ====================
 * Packet: EF 01 FF FF FF FF <pid> <len_hi> <len_lo> <payload...> <cks_hi> <cks_lo>
 *   len = payload_len + 2
 *   cks = pid + len_hi + len_lo + sum(payload)          (16 bit)
 * pid: 0x01 command | 0x02 data | 0x07 ack | 0x08 end-of-data
 * Response payload[0] is the confirmation code (0x00 = OK).
 * EasyDMA needs both buffers in SRAM.
 */
static uint8_t  fp_txbuf[64] __attribute__((aligned(4)));
static uint8_t  fp_rxbuf[96] __attribute__((aligned(4)));
static uint16_t g_fp_got;
static uint8_t  g_fp_pid;
static bool     g_fp_ok;
static bool     g_fp_swap;
static uint8_t  g_fp_rx_pin = PIN_FP_RX;
static uint8_t  g_fp_tx_pin = PIN_FP_TX;
static uint32_t g_fp_tx_edges;
static uint16_t g_fp_hunt;
static uint32_t g_fp_edges;   /* line transitions seen on P0.08 during a command */

/* Configure BOTH the PSELs and the GPIO directions. Swapping only the PSELs
 * leaves TXD on a pin configured as input and RXD on a pin configured as
 * output, which can never work. */
static void fp_uart_cfg(bool swap, uint32_t baud) {
    UART0_ENABLE = 0;

    uint8_t txp = swap ? PIN_FP_RX : PIN_FP_TX;
    uint8_t rxp = swap ? PIN_FP_TX : PIN_FP_RX;

    P0_PIN_CNF(txp) = 0x00000001UL; /* dir=out WITH input buffer connected,
                                     * so P0_IN can observe our own TX pad */
    P0_PIN_CNF(rxp) = CNF_IN_PU;    /* input, pull-up -> idle high */
    P0_OUTSET = (1UL << txp);       /* idle high */

    UART0_PSEL_TXD = txp;
    g_fp_tx_pin    = txp;
    UART0_PSEL_RXD = rxp;
    g_fp_rx_pin    = rxp;
    UART0_BAUDRATE = baud;
    UART0_ENABLE   = 8;
    delay_ms(1);
}

static void fp_uart_init(void) {
    P0_DIRSET |= (1UL << PIN_FP_TX);
    P0_PIN_CNF(PIN_FP_TX) = CNF_OUT;
    P0_PIN_CNF(PIN_FP_RX) = CNF_IN_PU;
    P0_OUTSET = (1UL << PIN_FP_TX);          /* idle high */
    fp_uart_cfg(false, FP_BAUD_57600);
}

/* Drive a pad low, then high, reading it back each time.
 * If it reads 1 while we drive 0, something external is winning:
 * a short to VCC, or another chip's OUTPUT on that net. */
static void pin_drive_test(uint8_t p) {
    /* detach the peripheral first: while UARTE has PSEL.TXD on this pad it
     * drives the line itself and GPIO writes are ignored */
    UART0_ENABLE   = 0;
    UART0_PSEL_TXD = 0xFFFFFFFFUL;
    UART0_PSEL_RXD = 0xFFFFFFFFUL;
    UART0_TASKS_STOPTX = 1;
    delay_ms(1);

    P0_PIN_CNF(p) = 0x00000001UL;          /* output, input buffer connected */
    P0_OUTCLR = (1UL << p);
    delay_ms(2);
    uint8_t lo = (uint8_t)((P0_IN >> p) & 1);
    P0_OUTSET = (1UL << p);
    delay_ms(2);
    uint8_t hi = (uint8_t)((P0_IN >> p) & 1);

    P("P0."); o_dec(p);
    P(" drive0->"); o_ch((char)('0' + lo));
    P(" drive1->"); o_ch((char)('0' + hi));
    if (lo == 0 && hi == 1)      P(" DRIVABLE ok");
    else if (lo == 1 && hi == 1) P(" STUCK HIGH (short to 3V3 / external output)");
    else if (lo == 0 && hi == 0) P(" STUCK LOW  (short to GND)");
    else                         P(" WEAK");
    PL();
}

/* Same as pin_drive_test but with DRIVE=H0H1 (strongest, ~5 mA) at CNF bits 5-6.
 * Distinguishes "weak external pull-up" (we win) from "another push-pull output"
 * (we still lose). The hardware UART can use such a pad because PIN_CNF.DRIVE
 * configures the pad even while a peripheral drives it. */
static void pin_drive_test_hd(uint8_t p) {
    UART0_ENABLE   = 0;
    UART0_PSEL_TXD = 0xFFFFFFFFUL;
    UART0_PSEL_RXD = 0xFFFFFFFFUL;
    UART0_TASKS_STOPTX = 1;
    delay_ms(1);

    P0_PIN_CNF(p) = 0x00000061UL;      /* dir=out, input connected, DRIVE=H0H1 */
    delay_ms(1);
    P0_OUTCLR = (1UL << p);
    delay_ms(2);
    uint8_t lo = (uint8_t)((P0_IN >> p) & 1);
    P0_OUTSET = (1UL << p);
    delay_ms(2);
    uint8_t hi = (uint8_t)((P0_IN >> p) & 1);

    P("P0."); o_dec(p);
    P(" HIDRIVE drive0->"); o_ch((char)('0' + lo));
    P(" drive1->"); o_ch((char)('0' + hi));
    if (lo == 0 && hi == 1)      P(" WIN - it is a weak pull-up, we can drive it");
    else if (lo == 1 && hi == 1) P(" still held - real push-pull output");
    else                         P(" odd");
    PL();
}

/* Decide whether a pin is externally driven or floating: sample it with a
 * pulldown and with a pullup. Same value both ways => driven by something. */
static void pin_probe(void) {
    static const uint8_t pins[3] = { PIN_FP_TX, PIN_FP_RX, PIN_FP_WAKE };
    for (int i = 0; i < 3; i++) {
        uint8_t p = pins[i];
        P0_PIN_CNF(p) = CNF_IN_PD;
        delay_ms(2);
        uint8_t lo = (uint8_t)((P0_IN >> p) & 1);
        P0_PIN_CNF(p) = CNF_IN_PU;
        delay_ms(2);
        uint8_t hi = (uint8_t)((P0_IN >> p) & 1);
        P("P0."); o_dec(p);
        P(lo == hi ? " DRIVEN level=" : " FLOAT  pd=");
        o_ch((char)('0' + (lo == hi ? hi : lo)));
        if (lo != hi) { P(" pu="); o_ch((char)('0' + hi)); }
        PL();
    }
    P0_PIN_CNF(PIN_FP_TX)   = CNF_OUT;
    P0_PIN_CNF(PIN_FP_RX)   = CNF_IN_PU;
    P0_PIN_CNF(PIN_FP_WAKE) = CNF_IN_PD;
}

static uint16_t fp_build(uint8_t pid, const uint8_t *p, uint8_t n) {
    uint16_t len = (uint16_t)(n + 2);
    uint16_t i = 0, sum;
    fp_txbuf[i++] = 0xEF; fp_txbuf[i++] = 0x01;
    fp_txbuf[i++] = 0xFF; fp_txbuf[i++] = 0xFF;
    fp_txbuf[i++] = 0xFF; fp_txbuf[i++] = 0xFF;
    fp_txbuf[i++] = pid;
    fp_txbuf[i++] = (uint8_t)(len >> 8);
    fp_txbuf[i++] = (uint8_t)(len & 0xFF);
    sum = (uint16_t)(pid + (len >> 8) + (len & 0xFF));
    for (uint8_t k = 0; k < n; k++) { fp_txbuf[i++] = p[k]; sum += p[k]; }
    fp_txbuf[i++] = (uint8_t)(sum >> 8);
    fp_txbuf[i++] = (uint8_t)(sum & 0xFF);
    return i;
}

static bool fp_parse(uint16_t got, uint8_t *pid, uint8_t *code) {
    for (uint16_t i = 0; i + 12 <= got; i++) {
        if (fp_rxbuf[i] != 0xEF || fp_rxbuf[i + 1] != 0x01) continue;
        uint16_t len = (uint16_t)((fp_rxbuf[i + 7] << 8) | fp_rxbuf[i + 8]);
        if (len < 3 || (uint32_t)i + 9 + len > got) continue;
        uint16_t sum = 0;
        for (uint16_t k = 6; k < 7 + len; k++) sum += fp_rxbuf[i + k];
        uint16_t cks = (uint16_t)((fp_rxbuf[i + 7 + len] << 8) | fp_rxbuf[i + 8 + len]);
        if (sum != cks) continue;
        *pid  = fp_rxbuf[i + 6];
        *code = fp_rxbuf[i + 9];
        return true;
    }
    return false;
}

/* Arm RX first, then transmit, then collect.
 * Arming after TX loses fast replies (and 0x120 is RXTO, not ENDTX). */
static int fp_cmd(const uint8_t *p, uint8_t n, uint16_t timeout_ms) {
    g_fp_pid = 0;
    uint16_t len = fp_build(0x01, p, n);

    /* 1. receiver armed before we send anything */
    UART0_RXD_PTR      = (uint32_t)fp_rxbuf;
    UART0_RXD_MAXCNT   = sizeof(fp_rxbuf);
    UART0_EVENTS_ENDRX = 0;
    UART0_TASKS_STARTRX = 1;
    delay_us(200);

    /* 2. transmit (char time = 10 bits / baud, padded) */
    UART0_TXD_PTR      = (uint32_t)fp_txbuf;
    UART0_TXD_MAXCNT   = len;
    UART0_EVENTS_ENDTX = 0;
    UART0_TASKS_STARTTX = 1;

    /* watch our own TX pad: proves the bytes physically leave the pin */
    g_fp_tx_edges = 0;
    {
        uint32_t tl = P0_IN & (1UL << g_fp_tx_pin);
        for (uint32_t i = 0; i < (uint32_t)(len * 3000U) + 20000U; i++) {
            uint32_t c = P0_IN & (1UL << g_fp_tx_pin);
            if (c != tl) { g_fp_tx_edges++; tl = c; }
        }
    }

    /* 3. wait for the answer, counting transitions on the RXD pad itself.
     *    The GPIO input buffer is connected, so P0_IN mirrors the UART line.
     *    edges == 0  -> the sensor never spoke.
     *    edges  > 0  -> it did, so a got==0 means our receiver is at fault. */
    g_fp_edges = 0;
    uint32_t last = P0_IN & (1UL << g_fp_rx_pin);
    for (uint32_t ms = 0; ms < timeout_ms; ms++) {
        for (uint32_t i = 0; i < 8000U; i++) {
            uint32_t cur = P0_IN & (1UL << g_fp_rx_pin);
            if (cur != last) { g_fp_edges++; last = cur; }
        }
    }

    /* 4. stop and collect */
    UART0_TASKS_STOPRX = 1;
    delay_us(500);
    g_fp_got = (uint16_t)UART0_RXD_AMOUNT;
    if (g_fp_got > sizeof(fp_rxbuf)) g_fp_got = sizeof(fp_rxbuf);
    UART0_TASKS_FLUSHRX = 1;
    delay_us(200);

    if (!g_fp_got) return -1;
    uint8_t pid, code;
    if (!fp_parse(g_fp_got, &pid, &code)) return -2;
    g_fp_pid = pid;
    return code;
}

static void fp_show(const char *label, int r) {
    P(label);
    if (r == -1)      P("(no response)");
    else if (r == -2) P("(bad checksum)");
    else { P("code="); o_hex((uint8_t)r); P(r == 0 ? " OK" : " ERR"); }
    P(" got="); o_dec(g_fp_got);
    P(" rxE="); o_dec((uint16_t)(g_fp_edges > 999 ? 999 : g_fp_edges));
    P(" txE="); o_dec((uint16_t)(g_fp_tx_edges > 999 ? 999 : g_fp_tx_edges));
    P(" pid="); o_hex(g_fp_pid);
    if (g_fp_got) {
        P(" [");
        for (uint16_t i = 0; i < g_fp_got && i < 12; i++) o_hexsp(fp_rxbuf[i]);
        P("]");
    }
    PL();
}

/* handshake + green breathing Aura LED + template count.
 * Sweeps baud rates and TX/RX assignment so wrong wiring is self-diagnosing. */
static bool fp_try_init(void) {
    static const uint8_t  hs[] = { 0x40 };
    static const uint32_t bauds[] = {
        FP_BAUD_57600,      /* 57600 - Grow default */
        0x00275000UL,       /* 9600  */
        0x004EA000UL,       /* 19200 */
        0x009D5000UL,       /* 38400 */
        0x01D7E000UL,       /* 115200*/
    };
    const unsigned nbaud = sizeof(bauds) / sizeof(bauds[0]);

    pin_probe();
    pin_drive_test(PIN_FP_TX);
    pin_drive_test(PIN_FP_RX);

    bool found = false;
    uint32_t best_edges = 0;
    int best_sw = -1; unsigned best_b = 0;
    for (int sw = 0; sw < 2 && !found; sw++) {
        for (unsigned b = 0; b < nbaud; b++) {
            fp_uart_cfg(sw != 0, bauds[b]);
            delay_ms(15);
            int r = fp_cmd(hs, sizeof(hs), 110);
            if (g_fp_edges > best_edges) { best_edges = g_fp_edges; best_sw = sw; best_b = b; }
            if (r >= 0) {
                g_fp_swap = (sw != 0);
                P("FP found: swap="); o_dec((uint16_t)sw);
                P(" baud="); o_dec((uint16_t)b);
                PL();
                fp_show("FP HandShake  -> ", r);
                found = true;
                break;
            }
            if (g_fp_got) {          /* bytes but bad frame => baud is close */
                P("FP garbage swap="); o_dec((uint16_t)sw);
                P(" baud="); o_dec((uint16_t)b);
                fp_show("", r);
            }
        }
    }
    if (!found) {
        P("FP: no reply. max_edges="); o_dec((uint16_t)(best_edges > 999 ? 999 : best_edges));
        P(" at swap="); o_dec((uint16_t)(best_sw < 0 ? 0 : best_sw));
        P(" baud="); o_dec((uint16_t)best_b);
        P(" errors="); o_hex((uint8_t)(UART0_ERRORS & 0xFF));
        PL();
        return false;
    }

    /* AuraLedConfig 0x35: func=0x01 breathing, start=0x02 green,
     * end=0x02 green, cycles=0x00 infinite  ->  green breathing ring */
    static const uint8_t aura[] = { 0x35, 0x01, 0x02, 0x02, 0x00 };
    int r = fp_cmd(aura, sizeof(aura), 150);
    fp_show("FP AuraLed GRN -> ", r);
    if (r != 0) return false;

    static const uint8_t cnt[] = { 0x1D };          /* TemplateCount */
    r = fp_cmd(cnt, sizeof(cnt), 150);
    fp_show("FP TemplateCnt-> ", r);
    return true;
}

static void fp_boot_report(void) {
    fp_uart_init();
    delay_ms(400);                                  /* sensor MCU boot */

    P("FP touch@boot="); o_ch((P0_IN & (1UL << PIN_FP_WAKE)) ? '1' : '0');
    P(" p0.11="); o_hex((uint8_t)((P0_IN >> PIN_FP_WAKE) & 1));
    PL();

    g_fp_ok = fp_try_init();
    if (!g_fp_ok) { P("FP: not detected yet - keep retrying, hot-plug is fine\r\n"); PL(); }
}


static void fp_line_break(uint16_t ms) {
    uint8_t txp = g_fp_tx_pin;
    UART0_ENABLE   = 0;
    UART0_PSEL_TXD = 0xFFFFFFFFUL;
    UART0_PSEL_RXD = 0xFFFFFFFFUL;
    P0_PIN_CNF(txp) = 0x00000001UL;
    P0_OUTCLR = (1UL << txp);
    delay_ms(ms);                  /* hold the module's RX line LOW */
    P0_OUTSET = (1UL << txp);
    delay_ms(2);
}

/* Hunt for the ring LED. We can only transmit on P0.08 (yellow) because P0.06
 * (green) cannot be driven by the nRF at all, so this always uses swap=1:
 * TX = P0.08, RX = P0.06. Cycles baud x LED-command variant; each attempt is
 * preceded by a wake break on the module's RX line. */
static void fp_led_hunt(void) {
    static const uint32_t bauds[] = {
        FP_BAUD_57600,   /* 57600  - Grow default                */
        0x00275000UL,    /* 9600                                 */
        0x01D7E000UL,    /* 115200                               */
        0x004EA000UL,    /* 19200                                */
        0x009D5000UL,    /* 38400                                */
        0x03AFB000UL,    /* 230400                               */
        0x0013B000UL,    /* 4800                                 */
        0x0009D000UL,    /* 2400                                 */
        0x0004F000UL,    /* 1200                                 */
        0x003B0000UL,    /* 14400                                */
        0x0075F000UL,    /* 28800                                */
        0x013A9000UL,    /* 76800                                */
        0x075F7000UL,    /* 460800                               */
        0x0EBED000UL,    /* 921600                               */
    };
    static const uint8_t hs[]        = { 0x40 };
    static const uint8_t led_breath[] = { 0x35, 0x01, 0x02, 0x02, 0x00 };
    static const uint8_t led_on[]     = { 0x35, 0x03, 0x02, 0x02, 0x00 };
    static const uint8_t led_alt[]    = { 0x3C, 0x02, 0x01, 0x01, 0x01 };
    /* ZFM/R307 family "open" is VerifyPassword 0x13, not Grow's 0x40 */
    static const uint8_t zfm_pwd[]    = { 0x13, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t zfm_img[]    = { 0x01 };
    static const uint8_t *const cmds[5] = { led_breath, led_on, led_alt, zfm_pwd, zfm_img };

    const unsigned nb = sizeof(bauds) / sizeof(bauds[0]);
    unsigned idx = (unsigned)g_fp_hunt++;
    unsigned b = idx % nb;
    unsigned c = (idx / nb) % 5;

    /* pad health every cycle: DRIVEN vs FLOAT reveals where pull-ups come from */
    pin_probe();
    pin_drive_test_hd(PIN_FP_TX);
    pin_drive_test_hd(PIN_FP_RX);

    fp_uart_cfg(true, bauds[b]);
    delay_ms(5);
    fp_line_break(30);                 /* wake pulse */
    fp_uart_cfg(true, bauds[b]);
    delay_ms(5);

    int r  = fp_cmd(hs, sizeof(hs), 300);
    int ra = fp_cmd(cmds[c], (c == 4) ? 1 : 5, 300);

    P("LED baud#"); o_dec((uint16_t)b);
    P(" cmd"); o_dec((uint16_t)c);
    P(" hs="); o_ch(r  >= 0 ? 'Y' : 'n');
    P(" led="); o_ch(ra >= 0 ? 'Y' : 'n');
    P(" rxE="); o_dec((uint16_t)(g_fp_edges > 999 ? 999 : g_fp_edges));
    PL();
}



/* ==================== raw line sniffer (diagnostic only) ====================
 * No UART at all: just watch both pads as plain GPIO and count transitions.
 * Tells us whether the sensor's TX line ever speaks, at any time, for any
 * stimulus (touch, power-cycle, our commands). */
static void fp_sniff(void) {
    UART0_ENABLE   = 0;
    UART0_PSEL_TXD = 0xFFFFFFFFUL;
    UART0_PSEL_RXD = 0xFFFFFFFFUL;

    P0_DIRSET &= ~((1UL << PIN_FP_TX) | (1UL << PIN_FP_RX));
    P0_PIN_CNF(PIN_FP_TX)   = CNF_IN_PU;
    P0_PIN_CNF(PIN_FP_RX)   = CNF_IN_PU;
    P0_PIN_CNF(PIN_FP_WAKE) = CNF_IN_PD;

    uint32_t b6 = (P0_IN >> PIN_FP_TX)   & 1;
    uint32_t b8 = (P0_IN >> PIN_FP_RX)   & 1;
    uint32_t e6 = 0, e8 = 0;

    P("SNIFF start (no UART, GPIO only)\r\n"); PL();

    for (;;) {
        for (uint32_t i = 0; i < 900000U; i++) {        /* ~100 ms */
            uint32_t v = P0_IN;
            uint32_t n6 = (v >> PIN_FP_TX) & 1;
            uint32_t n8 = (v >> PIN_FP_RX) & 1;
            if (n6 != b6) { b6 = n6; e6++; }
            if (n8 != b8) { b8 = n8; e8++; }
        }
        P("SNIFF P0.6="); o_ch((char)('0' + b6));
        P(" e6="); o_dec((uint16_t)(e6 > 9999 ? 9999 : e6));
        P(" | P0.8="); o_ch((char)('0' + b8));
        P(" e8="); o_dec((uint16_t)(e8 > 9999 ? 9999 : e8));
        P(" | wake="); o_ch(((P0_IN >> PIN_FP_WAKE) & 1) ? 'T' : '-');
        PL();
    }
}


/* Fast P0.11 (blue / WAKE) sampler: tight loop so even a millisecond-wide
 * pulse is counted. Reports level + cumulative edges + high-time per window. */
static void fp_touch_meter(void) {
    UART0_ENABLE   = 0;
    UART0_PSEL_TXD = 0xFFFFFFFFUL;
    UART0_PSEL_RXD = 0xFFFFFFFFUL;
    P0_PIN_CNF(PIN_FP_WAKE) = CNF_IN_PD;

    P("TOUCHMETER start (P0.11 blue, pull-down)\r\n"); PL();

    uint32_t prev = (P0_IN >> PIN_FP_WAKE) & 1;
    uint32_t edges = 0;

    for (;;) {
        uint32_t highs = 0;
        for (uint32_t i = 0; i < 450000U; i++) {      /* ~50 ms */
            uint32_t v = (P0_IN >> PIN_FP_WAKE) & 1;
            if (v != prev) { prev = v; edges++; }
            highs += v;
        }
        P("TOUCH lvl="); o_ch((char)('0' + prev));
        P(" edges="); o_dec((uint16_t)(edges > 9999 ? 9999 : edges));
        P(" high="); o_dec((uint16_t)(highs > 9999 ? 9999 : highs));
        PL();
    }
}


/* Scope-friendly transmitter. Repeatedly sends the Grow handshake frame plus a
 * run of 0x55 bytes. 0x55 = 0101... -> a clean square wave at baud/2, i.e.
 * 28.8 kHz at 57600, which is trivial to trigger on and measure.
 * Probe the YELLOW pad AT THE MODULE: if the bursts are there, the wire is good
 * and the module itself is not responding. If they are absent, the wire is open.
 */
static void fp_tx_tone(void) {
    fp_uart_cfg(true, FP_BAUD_57600);      /* TX = P0.08 */

    P("PURE 0x55 TONE.  P0.10@115200 -> 57.6kHz | P0.08@57600 -> 28.8kHz\r\n"); PL();
    P("UART0 baud_reg="); o_hex32(UART0_BAUDRATE);
    P(" psel_txd="); o_hex32(UART0_PSEL_TXD);
    P(" enable="); o_dec((uint16_t)UART0_ENABLE); PL();
    P("UART1 baud_reg="); o_hex32(UART1_BAUDRATE); PL();

    for (;;) {
        for (int i = 0; i < 32; i++) fp_txbuf[i] = 0x55;

        UART0_TXD_PTR      = (uint32_t)fp_txbuf;
        UART0_TXD_MAXCNT   = 32;
        UART0_EVENTS_ENDTX = 0;
        UART0_TASKS_STARTTX = 1;
        delay_ms(8);

        UART1_TXD_PTR      = (uint32_t)fp_txbuf;
        UART1_TXD_MAXCNT   = 32;
        UART1_EVENTS_ENDTX = 0;
        UART1_TASKS_STARTTX = 1;
        delay_ms(6);

        delay_ms(180);
    }
}


/* Quiet mode: nRF drives NOTHING on the three FP pins (all inputs, pulldown),
 * so any signal seen on a module pad comes from the module itself.
 * Lets you find TouchOut by probing pads while touching the sensor. */
static void fp_quiet(void) {
    UART0_ENABLE   = 0;
    UART0_PSEL_TXD = 0xFFFFFFFFUL;
    UART0_PSEL_RXD = 0xFFFFFFFFUL;
    P0_DIRSET &= ~((1UL << PIN_FP_TX) | (1UL << PIN_FP_RX));
    P0_PIN_CNF(PIN_FP_TX)   = CNF_IN_PD;
    P0_PIN_CNF(PIN_FP_RX)   = CNF_IN_PD;
    P0_PIN_CNF(PIN_FP_WAKE) = CNF_IN_PD;

    P("QUIET MODE - nRF drives nothing on the FP pins.\r\n"); PL();
    P("Probe the 6 module pads. 0.00V=GND  3.30V=VCC/V_Touch\r\n"); PL();
    P("Touch the sensor: the pad that PULSES is TouchOut.\r\n"); PL();

    for (;;) {
        P("quiet P0.6="); o_ch(((P0_IN >> PIN_FP_TX)   & 1) ? '1' : '0');
        P(" P0.8=");       o_ch(((P0_IN >> PIN_FP_RX)   & 1) ? '1' : '0');
        P(" P0.11(blue)="); o_ch(((P0_IN >> PIN_FP_WAKE) & 1) ? '1' : '0');
        PL();
        delay_ms(200);
    }
}

/* ==================== main ==================== */
int main(void) {
    CLOCK_TASKS_HFCLKSTART = 1;
    while (!CLOCK_EVENTS_HFCLKSTARTED);

    /* LED */
    P0_DIRSET |= (1UL << PIN_LED);
    P0_PIN_CNF(PIN_LED) = CNF_OUT;
    led_off();

    /* debug UART TX */
    P0_DIRSET |= (1UL << PIN_DBG_TX);
    P0_OUTSET = (1UL << PIN_DBG_TX);
    P0_PIN_CNF(PIN_DBG_TX) = CNF_OUT;

    /* SPI */
    P0_DIRSET |= (1UL << PIN_SPI_CS) | (1UL << PIN_SPI_SCK) | (1UL << PIN_SPI_MOSI);
    P0_PIN_CNF(PIN_SPI_CS)   = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_SCK)  = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_MOSI) = CNF_OUT;
    P0_PIN_CNF(PIN_SPI_MISO) = CNF_IN_PU;
    PIN_CS_HI();
    P0_OUTCLR = (1UL << PIN_SPI_SCK);

    /* NFC reset + IRQ */
    P1_DIRSET |= (1UL << PIN_NFC_RST);
    P1_PIN_CNF(PIN_NFC_RST) = CNF_OUT;
    P1_PIN_CNF(PIN_NFC_IRQ) = CNF_IN_PU;

    /* fingerprint WAKE: active HIGH, must not float */
    P0_PIN_CNF(PIN_FP_WAKE) = CNF_IN_PD;

    /* UARTE1 115200 8N1 TX only */
    UART1_PSEL_TXD   = PIN_DBG_TX;
    UART1_PSEL_RXD   = 0xFFFFFFFFUL;
    UART1_BAUDRATE   = 0x01D7E000UL;
    UART1_ENABLE     = 8;

    uint8_t rsp[64];

    P("hyprkey test_hw v2  PN532 SPI diag\r\n"); PL();

    /* ---- hard reset ---- */
    P1_OUTCLR = (1UL << PIN_NFC_RST);
    delay_ms(20);
    P1_OUTSET = (1UL << PIN_NFC_RST);
    delay_ms(50);

    pn532_wakeup();
    pn532_drain();

    P("stat@boot="); o_hex(pn532_status());
    P(" irq="); o_ch((P1_IN & (1UL << PIN_NFC_IRQ)) ? '1' : '0');
    PL();

    /* ---- 1. GetFirmwareVersion: proves the bus without needing a tag ---- */
    static const uint8_t fw_cmd[] = { 0x02 };
    int n = pn532_exec(fw_cmd, sizeof(fw_cmd), rsp, sizeof(rsp), 200);
    P("GetFwVer -> ");
    if (n >= 6 && rsp[1] == 0x03) {
        o_str("OK ic=");  o_hex(rsp[2]);
        o_str(" ver=");   o_hex(rsp[3]);
        o_str(" rev=");   o_hex(rsp[4]);
        o_str(" sup=");   o_hex(rsp[5]);
    } else if (n < 0) {
        o_str("FAIL "); o_dec((uint16_t)(-n));
    } else {
        o_str("BAD n="); o_dec((uint16_t)n);
    }
    dump_frame(n, rsp);
    PL();

    /* ---- 2. SAMConfiguration: normal mode ---- */
    static const uint8_t sam_cmd[] = { 0x14, 0x01, 0x14, 0x01 };
    n = pn532_exec(sam_cmd, sizeof(sam_cmd), rsp, sizeof(rsp), 200);
    P("SAMConfig -> ");
    if (n >= 2 && rsp[1] == 0x15) o_str("OK");
    else if (n < 0) { o_str("FAIL "); o_dec((uint16_t)(-n)); }
    else { o_str("BAD n="); o_dec((uint16_t)n); }
    dump_frame(n, rsp);
    PL();

    /* ---- 3. RFConfiguration: bounded retries so polling returns promptly ----
     * 32 05 MxRtyATR MxRtyPSL MxRtyPassiveActivation
     * 0xFF passive-activation would block forever with no tag present.      */
    static const uint8_t rf_cmd[] = { 0x32, 0x05, 0xFF, 0x01, 0x0A };
    n = pn532_exec(rf_cmd, sizeof(rf_cmd), rsp, sizeof(rsp), 200);
    P("RFConfig  -> ");
    if (n >= 2 && rsp[1] == 0x33) o_str("OK");
    else if (n < 0) { o_str("FAIL "); o_dec((uint16_t)(-n)); }
    else { o_str("BAD n="); o_dec((uint16_t)n); }
    PL();
    PL();

    /* ---- 4. R558S fingerprint sensor ---- */
    fp_boot_report();
    PL();

#if FP_SNIFF
    fp_sniff();      /* never returns */
#endif
#if FP_TOUCHMETER
    fp_touch_meter();   /* never returns */
#endif
#if FP_TXTONE
    fp_tx_tone();       /* never returns */
#endif
#if FP_QUIET
    fp_quiet();         /* never returns */
#endif

    /* ---- poll loop ---- */
    uint16_t tick = 0;
    uint8_t  last_stat = 0xFF;

    while (1) {
        uint8_t irq = (P1_IN & (1UL << PIN_NFC_IRQ)) ? 1 : 0;

        /* not seen yet: cycle configs sending Aura LED; a lit ring proves
         * the sensor hears us even when we cannot read its reply */
        if (!g_fp_ok && (tick % 2) == 0) fp_led_hunt();

        static const uint8_t list_cmd[] = { 0x4A, 0x01, 0x00 };
        n = pn532_exec(list_cmd, sizeof(list_cmd), rsp, sizeof(rsp), 250);

        tick++;
        P("t="); o_dec(tick);
        P(" irq="); o_ch(irq ? '1' : '0');
        P(" fp="); o_ch((P0_IN & (1UL << PIN_FP_WAKE)) ? 'T' : '-' );
        P(" n="); o_dec((uint16_t)(n < 0 ? 0 : n));
        P(" ok="); o_ch(g_frame_ok ? '1' : '0');
        P(" L="); o_hex(g_len);

        if (n < 0) {
            P(" err="); o_dec((uint16_t)(-n));
            uint8_t s = pn532_status();
            P(" stat="); o_hex(s);
            if (s != last_stat) { P(" *"); last_stat = s; }
        } else {
            /* full raw frame, TFI first */
            P(" [");
            for (int i = 0; i < n && i < 14; i++) o_hexsp(rsp[i]);
            P("]");

            if (n >= 8 && rsp[1] == 0x4B) {
                uint8_t nt = rsp[2];
                P(" NbTg="); o_dec(nt);
                if (nt > 0) {
                    uint8_t uidl = rsp[7];
                    P(" uidl="); o_dec(uidl);
                    P(" UID=");
                    for (uint8_t i = 0; i < uidl && (8 + i) < (uint16_t)n; i++)
                        o_hexsp(rsp[8 + i]);
                    led_on();
                } else {
                    led_off();
                }
            }
        }
        PL();

        if (n >= 8 && rsp[1] == 0x4B && rsp[2] > 0) { delay_ms(250); led_off(); }
        delay_ms(120);
    }

    return 0;
}

/* ==================== startup ==================== */
extern uint32_t _estack, _etext, _sdata, _edata, _sbss, _ebss;

void Reset_Handler(void) {
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0;
    main();
    while (1);
}

void Default_Handler(void) { while (1); }

__attribute__((section(".isr_vector"), used))
const uint32_t vector_table[] = {
    (uint32_t)&_estack,
    (uint32_t)Reset_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0, 0, 0, 0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
    0,
    (uint32_t)Default_Handler,
    (uint32_t)Default_Handler,
};

#!/usr/bin/env python3
"""
HyprKey In-Memory Binary Log Tail (Over USB CCID)
Reads the live internal ring buffer of the hardware security key via Vendor APDU:
  >> FF FD 00 [count] 00
No physical COM port or serial wires needed!
"""

import sys
import time
import struct
import ctypes
from ctypes import wintypes

# WinSCard definitions
winscard = ctypes.windll.winscard

SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T1  = 2

class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [
        ("dwProtocol", wintypes.DWORD),
        ("cbPciLength", wintypes.DWORD),
    ]

winscard.SCardEstablishContext.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
winscard.SCardEstablishContext.restype  = wintypes.LONG

winscard.SCardListReadersA.argtypes = [ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(wintypes.DWORD)]
winscard.SCardListReadersA.restype  = wintypes.LONG

winscard.SCardConnectA.argtypes = [ctypes.c_size_t, ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(wintypes.DWORD)]
winscard.SCardConnectA.restype  = wintypes.LONG

winscard.SCardTransmit.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_char_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(wintypes.DWORD)]
winscard.SCardTransmit.restype  = wintypes.LONG

winscard.SCardDisconnect.argtypes = [ctypes.c_size_t, wintypes.DWORD]
winscard.SCardDisconnect.restype  = wintypes.LONG

# Modules
MODULES = {
    0x01: ("SYS",    "\033[96m"),
    0x02: ("USB",    "\033[94m"),
    0x03: ("CCID",   "\033[95m"),
    0x04: ("CTAP2",  "\033[92m"),
    0x05: ("OATH",   "\033[93m"),
    0x06: ("PGP",    "\033[91m"),
    0x07: ("PIV",    "\033[35m"),
    0x08: ("CRYPTO", "\033[36m"),
    0x09: ("TOUCH",  "\033[33m"),
}

# Events
EVENTS = {
    0x0001: "BOOT",
    0x0002: "USB_RESET",
    0x0003: "USB_CONFIGURED",
    0x0004: "USB_SUSPEND",
    0x0010: "CCID_ICC_ON",
    0x0011: "CCID_ICC_OFF",
    0x0012: "CCID_XFR_APDU",
    0x0013: "CCID_APDU_ROUTE",
    0x0014: "CCID_SW_RETURN",
    0x0020: "OATH_SELECT",
    0x0021: "OATH_CALC",
    0x0022: "OATH_PUT",
    0x0023: "OATH_DELETE",
    0x0024: "OATH_RESET",
    0x0030: "PGP_SELECT",
    0x0031: "PGP_VERIFY_PW1",
    0x0032: "PGP_VERIFY_PW3",
    0x0033: "PGP_CHANGE_PW",
    0x0034: "PGP_GEN_KEY",
    0x0035: "PGP_SIGN",
    0x0036: "PGP_DEC",
    0x0040: "CTAP_INIT",
    0x0041: "CTAP_MSG",
    0x0042: "CTAP_TOUCH",
    0x0050: "CRYPTO_ECDSA",
    0x0051: "CRYPTO_ED25519",
    0x0052: "CRYPTO_MLKEM",
    0x0053: "CRYPTO_MLDSA",
}

SEVERITY = {
    0x00: ("INFO", "\033[0m"),
    0x01: ("WARN", "\033[33m"),
    0x02: ("ERR",  "\033[91m"),
}

RESET = "\033[0m"

class CardConnection:
    def __init__(self):
        self.ctx = ctypes.c_size_t()
        self.card = ctypes.c_size_t()
        self.proto = wintypes.DWORD()
        self.io_req = None
        self.connected = False

    def connect(self):
        rc = winscard.SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, ctypes.byref(self.ctx))
        if rc != 0:
            return False, f"SCardEstablishContext failed: {hex(rc)}"

        m = wintypes.DWORD(0)
        winscard.SCardListReadersA(self.ctx, None, None, ctypes.byref(m))
        buf = ctypes.create_string_buffer(m.value)
        winscard.SCardListReadersA(self.ctx, None, buf, ctypes.byref(m))
        readers = [r for r in buf.raw[:m.value].split(b'\x00') if r]

        target = None
        for r in readers:
            if b"hyprkey" in r.lower():
                target = r
                break
        if not target:
            return False, "No HyprKey smart card reader detected!"

        rc = winscard.SCardConnectA(self.ctx, target, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, ctypes.byref(self.card), ctypes.byref(self.proto))
        if rc != 0:
            return False, f"SCardConnect failed: {hex(rc)}"

        self.io_req = SCARD_IO_REQUEST(dwProtocol=self.proto.value, cbPciLength=ctypes.sizeof(SCARD_IO_REQUEST))
        self.connected = True
        return True, target.decode()

    def transmit(self, apdu_bytes):
        send_buf = ctypes.create_string_buffer(bytes(apdu_bytes))
        recv_buf = ctypes.create_string_buffer(4096)
        recv_len = wintypes.DWORD(4096)

        rc = winscard.SCardTransmit(
            self.card,
            ctypes.byref(self.io_req),
            send_buf,
            len(apdu_bytes),
            None,
            recv_buf,
            ctypes.byref(recv_len)
        )
        if rc != 0:
            return None, rc
        return bytes(recv_buf.raw[:recv_len.value]), 0

    def close(self):
        if self.connected:
            winscard.SCardDisconnect(self.card, 0)
            self.connected = False

def format_event(entry):
    ts_ms, mod_id, sev, evt_id, arg0, arg1 = entry
    mod_name, mod_col = MODULES.get(mod_id, (f"MOD_{mod_id:02X}", "\033[90m"))
    evt_name = EVENTS.get(evt_id, f"EVT_{evt_id:04X}")
    sev_name, sev_col = SEVERITY.get(sev, ("???", ""))

    sec = ts_ms / 1000.0
    ts_str = f"{sec:8.3f}s"

    desc = ""
    if evt_id == 0x0012: # CCID_XFR_APDU
        cla = (arg0 >> 24) & 0xFF
        ins = (arg0 >> 16) & 0xFF
        p1  = (arg0 >> 8) & 0xFF
        p2  = arg0 & 0xFF
        desc = f"APDU [{cla:02X} {ins:02X} {p1:02X} {p2:02X}] len={arg1}"
    elif evt_id == 0x0014: # CCID_SW
        applet_names = {0: "OpenPGP", 1: "PIV", 2: "OATH"}
        applet = applet_names.get(arg0, f"Applet_{arg0}")
        sw = arg1
        sw_col = "\033[92m" if sw == 0x9000 else "\033[91m"
        desc = f"{applet} -> SW={sw_col}{sw:04X}{RESET}"
    else:
        desc = f"arg0=0x{arg0:08X} arg1=0x{arg1:08X}"

    return f"\033[90m[{ts_str}]\033[0m {mod_col}[{mod_name:^6}]{RESET} {sev_col}[{sev_name:^4}]{RESET} {evt_name:<18} {desc}"

def main():
    follow = "-f" in sys.argv or "--follow" in sys.argv or len(sys.argv) == 1
    clear = "--clear" in sys.argv

    conn = CardConnection()
    ok, msg = conn.connect()
    if not ok:
        print(f"\033[91mError: {msg}\033[0m")
        return 1

    print(f"\033[92mConnected to HyprKey: {msg}\033[0m")
    print(f"\033[90mStreaming in-memory binary logs directly over USB CCID (No COM port needed)\033[0m\n" + "-"*80)

    if clear:
        conn.transmit([0xFF, 0xFD, 0x01, 0x00, 0x00])
        print("Device log buffer cleared.")
        return 0

    last_seen_ts = 0
    seen_hashes = set()

    try:
        while True:
            # Vendor APDU: FF FD 00 40 00 (Read up to 64 latest tail entries)
            rsp, rc = conn.transmit([0xFF, 0xFD, 0x00, 0x40, 0x00])
            if rsp and len(rsp) >= 11 and rsp[-2:] == b'\x90\x00':
                tot_events, upt_ms, count = struct.unpack(">IIB", rsp[:9])
                payload = rsp[9:-2]
                entry_size = 16

                for i in range(count):
                    offset = i * entry_size
                    if offset + entry_size <= len(payload):
                        chunk = payload[offset:offset+entry_size]
                        ts_ms, mod_id, sev, evt_id, arg0, arg1 = struct.unpack("<IBBHII", chunk)
                        h = (ts_ms, mod_id, evt_id, arg0, arg1)
                        if h not in seen_hashes:
                            seen_hashes.add(h)
                            print(format_event((ts_ms, mod_id, sev, evt_id, arg0, arg1)))
                            if len(seen_hashes) > 1000:
                                seen_hashes.clear()
            else:
                if rc != 0:
                    print(f"\033[93m[Wait] Reconnecting to SmartCard...\033[0m")
                    conn.close()
                    time.sleep(1.0)
                    conn.connect()

            if not follow:
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\nTail stopped.")
    finally:
        conn.close()

if __name__ == "__main__":
    sys.exit(main())

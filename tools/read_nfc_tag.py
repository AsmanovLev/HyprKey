import smartcard.System
from smartcard.util import toHexString, toBytes

def scan_tag():
    readers = smartcard.System.readers()
    print(f"Readers: {readers}")
    hypr_reader = None
    for r in readers:
        if "hyprkey" in str(r).lower() or "smart card" in str(r).lower():
            hypr_reader = r
            break
    
    if not hypr_reader:
        if readers:
            hypr_reader = readers[0]
        else:
            print("No smartcard readers found!")
            return

    print(f"Connecting to: {hypr_reader}")
    conn = hypr_reader.createConnection()
    conn.connect()

    # APDU: CLA=0x00, INS=0xEA, P1=0x00, P2=0x00, Le=0x00
    apdu = [0x00, 0xEA, 0x00, 0x00, 0x00]
    print(f"Sending APDU: {toHexString(apdu)}")
    rsp, sw1, sw2 = conn.transmit(apdu)
    print(f"Response (SW={sw1:02X}{sw2:02X}, len={len(rsp)}): {toHexString(rsp)}")

    if sw1 != 0x90 or sw2 != 0x00 or len(rsp) == 0:
        print(f"Scanner command failed with status {sw1:02X}{sw2:02X}")
        return

    found = rsp[0]
    if found == 0:
        print("\n===> [PN532] В радиополе сейчас НЕТ метки (No tag detected in RF field).")
        return

    atqa = (rsp[1] << 8) | rsp[2]
    sak = rsp[3]
    uid_len = rsp[4]
    uid = bytes(rsp[5:5+uid_len])
    idx = 5 + uid_len

    ats_len = rsp[idx] if idx < len(rsp) else 0
    idx += 1
    ats = bytes(rsp[idx:idx+ats_len]) if ats_len > 0 else b""
    idx += ats_len

    user_data_len = rsp[idx] if idx < len(rsp) else 0
    idx += 1
    user_data = bytes(rsp[idx:idx+user_data_len]) if user_data_len > 0 else b""

    print("\n" + "="*50)
    print("       NFC TAG IDENTIFICATION REPORT")
    print("="*50)
    print(f"Tag Detected    : YES")
    print(f"UID Length      : {uid_len} bytes")
    print(f"UID (Hex)       : {uid.hex().upper()} ({':'.join(f'{b:02X}' for b in uid)})")
    print(f"ATQA            : 0x{atqa:04X}")
    print(f"SAK             : 0x{sak:02X}")

    # Tag classification
    tag_type = "Unknown"
    if sak == 0x00:
        if uid_len == 7:
            tag_type = "MIFARE Ultralight / NTAG213 / NTAG215 / NTAG216"
        else:
            tag_type = "MIFARE Ultralight (4-byte UID)"
    elif sak == 0x08:
        tag_type = "MIFARE Classic 1K"
    elif sak == 0x18:
        tag_type = "MIFARE Classic 4K"
    elif sak == 0x20:
        tag_type = "ISO/IEC 14443-4 Tag (MIFARE DESFire, JCOP, YubiKey, Bank Card EMV, or Passport)"
    elif sak == 0x28:
        tag_type = "JCOP 31/41 or MIFARE Classic 1K emulated"
    elif sak == 0x09:
        tag_type = "MIFARE Mini 0.3K"

    print(f"Guessed Type    : {tag_type}")

    if ats:
        print(f"ATS (Historical): {ats.hex().upper()}")
    if user_data:
        print(f"User Data (Pg4) : {user_data.hex().upper()} | ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in user_data)}")
    print("="*50)

if __name__ == "__main__":
    scan_tag()

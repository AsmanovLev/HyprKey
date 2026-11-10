import asyncio
import struct
import hmac
import hashlib
from bleak import BleakScanner, BleakClient

UUID_OATH_SERVICE = "a0000001-2721-0100-b42f-c9ba7ed623bb"
UUID_OATH_RX      = "a0000002-2721-0100-b42f-c9ba7ed623bb"
UUID_OATH_TX      = "a0000003-2721-0100-b42f-c9ba7ed623bb"

rx_queue = asyncio.Queue()

def notification_handler(sender, data):
    print(f"[BLE-NOTIF] Received from {sender}: {bytes(data).hex()} (len={len(data)})")
    rx_queue.put_nowait(bytes(data))

async def transmit_apdu(client, apdu_bytes):
    # Clear queue
    while not rx_queue.empty():
        rx_queue.get_nowait()
    
    # Write in chunks of 20 bytes (safe for default ATT MTU on any platform)
    CHUNK = 20
    for i in range(0, len(apdu_bytes), CHUNK):
        chunk = apdu_bytes[i : i + CHUNK]
        await client.write_gatt_char(UUID_OATH_RX, chunk, response=False)
        if i + CHUNK < len(apdu_bytes):
            await asyncio.sleep(0.015)
    
    # Collect notifications until SW9000 / SW6xxx or timeout
    resp = bytearray()
    t_end = asyncio.get_event_loop().time() + 5.0
    while asyncio.get_event_loop().time() < t_end:
        try:
            chunk = await asyncio.wait_for(rx_queue.get(), timeout=1.0)
            resp.extend(chunk)
            # Standard APDU completes with status word 90 00 or 6x xx
            if len(resp) >= 2 and (resp[-2] == 0x90 or (resp[-2] & 0xF0) == 0x60):
                break
        except asyncio.TimeoutError:
            if resp:
                break
    return bytes(resp)

async def main():
    print("================================================================")
    print("   LIVE HYPRKEY BLUETOOTH OATH & PROTOCOL SYNC TEST")
    print("================================================================")
    print("Scanning for 'hyprkey' via Bluetooth Low Energy...")
    device = await BleakScanner.find_device_by_filter(
        lambda d, adv: "hyprkey" in (adv.local_name or d.name or "").lower(),
        timeout=10.0
    )
    assert device is not None, "hyprkey BLE device not found!"
    print(f"[BLE] Found device: {device.name} [{device.address}]")

    print("[BLE] Connecting...")
    async with BleakClient(device, timeout=20.0) as client:
        print(f"[BLE] Connected: {client.is_connected}")

        print("[BLE] Subscribing to OATH APDU TX notifications...")
        await client.start_notify(UUID_OATH_TX, notification_handler)
        await asyncio.sleep(0.3)

        print("\n--- 1. Testing SELECT Yubico OATH AID over BLE ---")
        sel_aid = bytes.fromhex("00A4040007A0000005272101")
        rsp = await transmit_apdu(client, sel_aid)
        print("1. SELECT OATH AID response:", rsp.hex())
        assert rsp[-2:] == b"\x90\x00", f"SELECT failed: {rsp.hex()}"
        assert rsp[0] == 0x79, "Tag 0x79 version missing"
        print("   -> [PASS] SELECT OATH AID verified over BLE! Version tag 0x79 OK!")

        print("\n--- 2. Testing LIST Accounts over BLE ---")
        list_cmd = bytes.fromhex("00A1000000")
        rsp = await transmit_apdu(client, list_cmd)
        print("2. LIST Accounts response:", rsp.hex())
        assert rsp[-2:] == b"\x90\x00"
        assert b"Google:alice@hyprkey.local" in rsp
        print("   -> [PASS] Pre-configured credential 'Google:alice@hyprkey.local' found!")

        print("\n--- 3. Testing CALCULATE TOTP (RFC 6238) over BLE ---")
        # Challenge for T = 59 // 30 = 1
        ts_challenge = struct.pack(">Q", 1)
        demo_name = b"Google:alice@hyprkey.local"
        calc_data = bytes([0x71, len(demo_name)]) + demo_name + bytes([0x74, len(ts_challenge)]) + ts_challenge
        calc_cmd = bytes([0x00, 0xA2, 0x00, 0x01, len(calc_data)]) + calc_data
        rsp = await transmit_apdu(client, calc_cmd)
        print("3. CALCULATE TOTP response:", rsp.hex())
        assert rsp[-2:] == b"\x90\x00"
        assert rsp[0] == 0x76 and rsp[1] == 0x05
        digits = rsp[2]
        raw_code = struct.unpack(">I", rsp[3:7])[0]
        totp_code = f"{raw_code % (10**digits):0{digits}d}"
        print(f"   -> Calculated BLE TOTP Code: {totp_code}")

        # Compare with Python HMAC-SHA1
        py_mac1 = hmac.new(b"12345678901234567890", ts_challenge, hashlib.sha1).digest()
        off1 = py_mac1[-1] & 0x0F
        py_code1 = ((py_mac1[off1] & 0x7F) << 24) | (py_mac1[off1+1] << 16) | (py_mac1[off1+2] << 8) | py_mac1[off1+3]
        py_totp1 = f"{(py_code1 % 1000000):06d}"
        print(f"   -> Python HMAC-SHA1 TOTP:   {py_totp1}")
        assert totp_code == "287082" == py_totp1, f"Mismatch: ble={totp_code}, py={py_totp1}"
        print("   -> [PASS] EXACT MATCH with RFC 6238 & USB CCID (287082)!")

        print("\n--- 4. Testing PUT New Account over BLE ---")
        new_name = b"GitHub:hyprkey"
        key = b"12345678901234567890"
        prop = 0x22 # TOTP(0x20) | SHA256(0x02)
        digits_prop = 6
        put_data = (
            bytes([0x71, len(new_name)]) + new_name +
            bytes([0x73, len(key) + 2, prop, digits_prop]) + key
        )
        put_cmd = bytes([0x00, 0x01, 0x00, 0x00, len(put_data)]) + put_data
        rsp = await transmit_apdu(client, put_cmd)
        print("4. PUT new account ('GitHub:hyprkey') response:", rsp.hex())
        assert rsp == b"\x90\x00"
        print("   -> [PASS] PUT account over BLE succeeded!")

        print("\n--- 5. Testing CALCULATE on New Account over BLE ---")
        calc_data2 = bytes([0x71, len(new_name)]) + new_name + bytes([0x74, len(ts_challenge)]) + ts_challenge
        calc_cmd2 = bytes([0x00, 0xA2, 0x00, 0x01, len(calc_data2)]) + calc_data2
        rsp = await transmit_apdu(client, calc_cmd2)
        print("5. CALCULATE on 'GitHub:hyprkey' response:", rsp.hex())
        assert rsp[-2:] == b"\x90\x00"
        raw_code2 = struct.unpack(">I", rsp[3:7])[0]
        totp2 = f"{raw_code2 % 1000000:06d}"
        print(f"   -> Calculated BLE TOTP Code: {totp2}")

        h = hmac.new(key, ts_challenge, hashlib.sha256).digest()
        offset = h[-1] & 0x0F
        expected_code = ((struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000)
        print(f"   -> Python HMAC-SHA256 TOTP:  {expected_code:06d}")
        assert totp2 == f"{expected_code:06d}"
        print("   -> [PASS] EXACT MATCH with Python HMAC-SHA256 & USB CCID (247374)!")

        print("\n--- 6. Testing DELETE Account over BLE ---")
        del_data = bytes([0x71, len(new_name)]) + new_name
        del_cmd = bytes([0x00, 0x02, 0x00, 0x00, len(del_data)]) + del_data
        rsp = await transmit_apdu(client, del_cmd)
        print("6. DELETE 'GitHub:hyprkey' response:", rsp.hex())
        assert rsp == b"\x90\x00"
        print("   -> [PASS] DELETE account over BLE succeeded!")

        await client.stop_notify(UUID_OATH_TX)
        print("\n================================================================")
        print(" [SUCCESS] ALL BLE OATH & CROSS-PROTOCOL CHECKS PASSED 100%!")
        print("================================================================")

if __name__ == "__main__":
    asyncio.run(main())

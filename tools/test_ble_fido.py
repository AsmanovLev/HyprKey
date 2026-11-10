import asyncio
from bleak import BleakClient

DEVICE_ADDR = "C4:5C:B7:83:5F:AD"

# FIDO UUIDs
UUID_FIDO_SERVICE  = "0000fffd-0000-1000-8000-00805f9b34fb"
UUID_CONTROL_POINT = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
UUID_STATUS        = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
UUID_CP_LEN        = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
UUID_REVISION      = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"

notifications = []

def notification_handler(sender, data):
    print(f"[NOTIF] Received from {sender}: {data.hex()} (len={len(data)})")
    notifications.append(bytes(data))

async def main():
    print(f"Connecting to hyprkey at {DEVICE_ADDR}...")
    async with BleakClient(DEVICE_ADDR, timeout=25.0) as client:
        print(f"Connected: {client.is_connected}")

        # 1. Enumerate services & characteristics
        print("\n--- GATT Services & Characteristics ---")
        for s in client.services:
            print(f"Service: {s.uuid} ({s.description})")
            for c in s.characteristics:
                props = ",".join(c.properties)
                print(f"  Char: {c.uuid} [{props}] ({c.description})")

        # 2. Read Control Point Length
        cplen_data = await client.read_gatt_char(UUID_CP_LEN)
        cplen = int.from_bytes(cplen_data, byteorder="big")
        print(f"\n[FIDO] Control Point Length: {cplen} bytes (raw: {cplen_data.hex()})")

        # 3. Read Service Revision Bitfield
        rev_data = await client.read_gatt_char(UUID_REVISION)
        print(f"[FIDO] Service Revision Bitfield: 0x{rev_data.hex()}")

        # 4. Subscribe to FIDO Status notifications
        print("\n[FIDO] Subscribing to FIDO Status notifications...")
        await client.start_notify(UUID_STATUS, notification_handler)
        await asyncio.sleep(0.5)

        # 5. Send CTAP PING command (CMD=0x81, LEN=4, DATA='PING')
        ping_payload = b"PING"
        ping_packet = bytes([0x81, 0x00, len(ping_payload)]) + ping_payload
        print(f"\n[CTAP] Sending PING command: {ping_packet.hex()}")
        notifications.clear()
        await client.write_gatt_char(UUID_CONTROL_POINT, ping_packet, response=False)

        # Wait for notification response
        for _ in range(20):
            if notifications:
                break
            await asyncio.sleep(0.1)

        if notifications:
            resp = notifications.pop(0)
            print(f"[CTAP] PING Response received: {resp.hex()}")
            if resp[0] == 0x81 and resp[3:] == ping_payload:
                print("===> PING TEST PASSED!")
            else:
                print("===> PING MISMATCH!")
        else:
            print("===> NO PING RESPONSE RECEIVED (TIMEOUT)!")

        # 6. Send U2F Version APDU (CMD=0x83 MSG, APDU: 00 03 00 00 00)
        u2f_ver_apdu = bytes([0x00, 0x03, 0x00, 0x00, 0x00])
        msg_packet = bytes([0x83, 0x00, len(u2f_ver_apdu)]) + u2f_ver_apdu
        print(f"\n[CTAP] Sending U2F VERSION APDU: {msg_packet.hex()}")
        notifications.clear()
        await client.write_gatt_char(UUID_CONTROL_POINT, msg_packet, response=False)

        for _ in range(20):
            if notifications:
                break
            await asyncio.sleep(0.1)

        if notifications:
            resp = notifications.pop(0)
            print(f"[CTAP] U2F Version Response received: {resp.hex()}")
            payload = resp[3:]
            print(f"[CTAP] Payload ASCII: {payload.decode('latin1', errors='replace')}")
            if b"U2F_V2" in payload:
                print("===> U2F VERSION TEST PASSED ('U2F_V2')!")
        else:
            print("===> NO U2F VERSION RESPONSE RECEIVED (TIMEOUT)!")

        await client.stop_notify(UUID_STATUS)
        print("\nTest completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())

import threading
import serial
import time
import asyncio
from bleak import BleakScanner, BleakClient

stop_uart = False

def uart_logger():
    try:
        s = serial.Serial('COM9', 115200, timeout=0.2)
        while not stop_uart:
            d = s.read(s.in_waiting or 1)
            if d:
                print(f"[UART] {d.decode('latin1', errors='replace')}", end='', flush=True)
        s.close()
    except Exception as e:
        print(f"[UART ERR] {e}")

async def ble_test():
    print("[BLE] Scanning...")
    device = await BleakScanner.find_device_by_filter(
        lambda d, adv: "hyprkey" in (adv.local_name or d.name or "").lower(),
        timeout=8.0
    )
    if not device:
        print("[BLE] Device not found!")
        return
    print(f"[BLE] Found: {device.name} [{device.address}]")
    print("[BLE] Connecting...")
    async with BleakClient(device, timeout=15.0) as client:
        print(f"[BLE] Connected: {client.is_connected}")
        for s in client.services:
            print(f"  Service: {s.uuid}")

async def main():
    global stop_uart
    t = threading.Thread(target=uart_logger, daemon=True)
    t.start()
    time.sleep(0.5)
    try:
        await ble_test()
    finally:
        stop_uart = True
        t.join(timeout=1.0)

if __name__ == "__main__":
    asyncio.run(main())

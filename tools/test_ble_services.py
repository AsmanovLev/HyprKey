import asyncio
from bleak import BleakScanner, BleakClient

async def main():
    print("Scanning for 'hyprkey'...")
    device = await BleakScanner.find_device_by_filter(
        lambda d, adv: "hyprkey" in (adv.local_name or d.name or "").lower(),
        timeout=10.0
    )
    if not device:
        print("Device 'hyprkey' NOT found during scan!")
        return

    print(f"Found device: {device.name} ({device.address}), connecting...")
    async with BleakClient(device, timeout=20.0) as client:
        print(f"Connected: {client.is_connected}")
        print("\n=== Discovered Services & Characteristics ===")
        for s in client.services:
            print(f"\n[SERVICE] {s.uuid} ({s.description})")
            for c in s.characteristics:
                props = ",".join(c.properties)
                print(f"  [CHAR] {c.uuid} [{props}] ({c.description})")
                for d in c.descriptors:
                    print(f"    [DESC] {d.uuid} ({d.description})")

if __name__ == "__main__":
    asyncio.run(main())

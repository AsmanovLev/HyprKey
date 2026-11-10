import asyncio
from bleak import BleakClient

DEVICE_ADDR = "C4:5C:B7:83:5F:AD"

async def main():
    print(f"Connecting to {DEVICE_ADDR}...")
    async with BleakClient(DEVICE_ADDR, timeout=20.0) as client:
        print(f"Connected: {client.is_connected}")
        print("\nAll Services:")
        for s in client.services:
            print(f"Service: {s.uuid} handle_start={s.handle}")
            for c in s.characteristics:
                print(f"  Char: {c.uuid} handle={c.handle} props={c.properties}")
                for d in c.descriptors:
                    print(f"    Desc: {d.uuid} handle={d.handle}")

if __name__ == "__main__":
    asyncio.run(main())

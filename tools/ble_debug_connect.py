import asyncio
import logging
from bleak import BleakClient

logging.basicConfig(level=logging.DEBUG)

async def main():
    addr = "C4:5C:B7:83:5F:AD"
    print(f"Connecting to {addr} with full debug...")
    try:
        async with BleakClient(addr, timeout=10.0) as client:
            print("Connected:", client.is_connected)
            for s in client.services:
                print("Service:", s.uuid)
    except Exception as e:
        print("Caught exception:", type(e), e)

if __name__ == "__main__":
    asyncio.run(main())

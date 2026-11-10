import asyncio
import logging
from bleak import BleakClient

logging.basicConfig(level=logging.DEBUG)

async def test():
    async with BleakClient('C4:5C:B7:83:5F:AD', timeout=15.0, winrt=dict(use_cached_services=False)) as client:
        print("Connected:", client.is_connected)
        for s in client.services:
            print("GATT Service:", s.uuid)
            for c in s.characteristics:
                print("  Char:", c.uuid)

if __name__ == "__main__":
    asyncio.run(test())

import asyncio
from bleak import BleakScanner

async def main():
    print("Scanning BLE devices for 5 seconds...")
    devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
    for d, adv in devices.values():
        name = adv.local_name or d.name or "<unknown>"
        uuids = list(adv.service_uuids)
        if "hyprkey" in name.lower() or "fffd" in str(uuids).lower():
            print(f"===> MATCH: [{d.address}] {name} RSSI={adv.rssi} UUIDs={uuids}")
        else:
            print(f"[{d.address}] {name} RSSI={adv.rssi} UUIDs={uuids}")

if __name__ == "__main__":
    asyncio.run(main())

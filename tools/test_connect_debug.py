import asyncio
import threading
import time
import serial
from bleak import BleakClient

PRIMES = [9600, 2400, 4800, 19200, 38400, 57600, 1200, 230400]

def open_at(port, baud):
    last = None
    for _ in range(3):
        for b in PRIMES:
            if b == baud: continue
            try:
                s = serial.Serial(port, b, timeout=0.1)
                s.baudrate = baud
                return s
            except Exception as e:
                last = e
                try: s.close()
                except: pass
        time.sleep(0.2)
    raise last

serial_log = []
stop_event = threading.Event()

def serial_reader():
    try:
        s = open_at('COM9', 115200)
        while not stop_event.is_set():
            data = s.read(128)
            if data:
                text = data.decode('latin1', errors='replace')
                print(f"[UART] {text}", end='', flush=True)
                serial_log.append(text)
        s.close()
    except Exception as e:
        print(f"[UART ERR] {e}")

async def main():
    t = threading.Thread(target=serial_reader, daemon=True)
    t.start()
    time.sleep(0.5)

    print("Attempting Bleak connection to C4:5C:B7:83:5F:AD...")
    try:
        import traceback
        async with BleakClient("C4:5C:B7:83:5F:AD", timeout=15.0) as client:
            print("Connected successfully!")
            print(f"Is connected: {client.is_connected}")
            for s in client.services:
                print(f"Service: {s.uuid}")
                for c in s.characteristics:
                    print(f"  Char: {c.uuid}")
    except Exception as e:
        print(f"Bleak connect error: {repr(e)}")
        import traceback
        traceback.print_exc()

    stop_event.set()
    time.sleep(0.5)

if __name__ == "__main__":
    asyncio.run(main())

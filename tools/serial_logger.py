import serial, time

PRIMES = [9600, 2400, 4800, 19200, 38400, 57600, 1200, 230400]

def open_at(port, baud):
    last = None
    for _ in range(3):
        for b in PRIMES:
            if b == baud:
                continue
            try:
                s = serial.Serial(port, b, timeout=0.2)
            except Exception as e:
                last = e
                continue
            try:
                s.baudrate = baud
                return s
            except Exception as e:
                last = e
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(0.3)
    raise last

try:
    s = open_at('COM9', 115200)
    s.timeout = 0.5
    with open('S:/hyprkey/tools/ble_log.txt', 'a', encoding='utf-8') as f:
        f.write("\n=== Logger Started ===\n")
        f.flush()
        while True:
            line = s.readline()
            if line:
                decoded = line.decode('latin1', errors='replace')
                print(decoded, end='', flush=True)
                f.write(decoded)
                f.flush()
except Exception as e:
    with open('S:/hyprkey/tools/ble_log.txt', 'a', encoding='utf-8') as f:
        f.write(f"\nLogger error: {e}\n")

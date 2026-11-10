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

s = open_at('COM9', 115200)
t0 = time.time()
data = b''
while time.time() - t0 < 1.0:
    chunk = s.read(128)
    if chunk:
        data += chunk
s.close()
print("Tail output:")
print(data.decode('latin1', errors='replace'))

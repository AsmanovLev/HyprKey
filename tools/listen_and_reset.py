import serial
import time
import sys

s = serial.Serial('COM9', 115200, timeout=0.1)

# Send single reset pulse via low baud
s.baudrate = 1200
s.write(b'\x00')
s.flush()
time.sleep(0.06)

# Return to 115200 baud to read boot logs
s.baudrate = 115200
t0 = time.time()
out = b''
while time.time() - t0 < 2.0:
    chunk = s.read(128)
    if chunk:
        out += chunk

s.close()
print("Captured logs:")
print(out.decode('latin1', errors='replace'))

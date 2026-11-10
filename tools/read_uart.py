import serial
import time

try:
    s = serial.Serial('COM9', 115200, timeout=1.0)
    time.sleep(0.1)
    end = time.time() + 2.0
    while time.time() < end:
        line = s.readline()
        if line:
            print(line.decode('latin1', errors='replace'), end='')
    s.close()
except Exception as e:
    print(f"Error: {e}")

import serial
import time
import subprocess

subprocess.run(["python", r"D:\Users\User\nrf_reset.py", "single", "COM9"], check=True)
time.sleep(0.05)

try:
    s = serial.Serial('COM9', 115200, timeout=0.5)
    end = time.time() + 4.5
    while time.time() < end:
        data = s.read(s.in_waiting or 1)
        if data:
            print(data.decode('latin1', errors='replace'), end='', flush=True)
    s.close()
except Exception as e:
    print(f"Serial error: {e}")

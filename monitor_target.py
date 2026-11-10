import sys, time
sys.path.append(r'D:\Users\User')
from nrf_reset import open_at

port = 'COM9'
print(f"Connecting to {port} @ 115200...")
s = open_at(port, 115200)
print(f"=== LISTENING FOR NFC TARGET ACTIVATION (30 seconds) ===")
print("Touch or slide phone back near the camera across PN532 antenna...")

t_end = time.time() + 30
try:
    while time.time() < t_end:
        n = s.in_waiting
        if n:
            b = s.read(n)
            txt = b.decode('latin-1', errors='replace')
            sys.stdout.write(txt)
            sys.stdout.flush()
        time.sleep(0.02)
finally:
    s.close()
    print("\n=== Monitoring complete ===")

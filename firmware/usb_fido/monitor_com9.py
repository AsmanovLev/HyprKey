import serial
import time
import sys

def main():
    try:
        # Prime the port
        s = serial.Serial('COM9', 9600, timeout=0.1)
        s.close()
    except Exception:
        pass

    try:
        s = serial.Serial('COM9', 115200, timeout=0.5)
        print("COM9 open at 115200 baud. Monitoring...", flush=True)
    except Exception as e:
        print(f"Failed to open COM9: {e}", flush=True)
        return

    while True:
        try:
            line = s.readline()
            if line:
                decoded = line.decode('latin1', errors='replace').strip()
                if decoded:
                    print(f"[{time.strftime('%H:%M:%S')}] {decoded}", flush=True)
        except Exception as e:
            print(f"Serial read error: {e}", flush=True)
            break

if __name__ == "__main__":
    main()

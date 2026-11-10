import serial
import time
import sys

PRIMES = [9600, 2400, 4800, 19200, 38400, 57600, 1200, 230400]

def open_ch340(port, target_baud, timeout=0.1):
    for prime in PRIMES:
        if prime == target_baud:
            continue
        try:
            s = serial.Serial(port, prime, timeout=timeout)
            s.baudrate = target_baud
            return s
        except Exception:
            continue
    return serial.Serial(port, target_baud, timeout=timeout)

def main():
    print("Opening COM9 at 115200...")
    s = open_ch340('COM9', 115200, timeout=0.1)
    print("Listening for UART logs (press Ctrl+C to stop)...")
    try:
        while True:
            line = s.readline()
            if line:
                try:
                    text = line.decode('utf-8', errors='replace')
                except Exception:
                    text = str(line)
                print(text, end='', flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == '__main__':
    main()

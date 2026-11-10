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
    s = open_ch340('COM9', 115200, timeout=0.2)
    print("LOGGING_READY: listening on COM9 at 115200...")
    sys.stdout.flush()
    t_end = time.time() + 15  # listen for 15 seconds
    while time.time() < t_end:
        line = s.readline()
        if line:
            print(line.decode('latin1', errors='replace'), end='', flush=True)
    s.close()
    print("\nLOGGING_FINISHED")

if __name__ == '__main__':
    main()

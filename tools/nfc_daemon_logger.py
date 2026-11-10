import serial
import time
import sys

PRIMES = [9600, 2400, 4800, 19200, 38400, 57600, 1200, 230400]

def open_ch340(port, target_baud, timeout=0.2):
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
    log_path = r"s:\hyprkey\tools\nfc_live_log.txt"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n--- NFC Live Logger Started: {time.ctime()} ---\n")
        f.flush()
        print("LOGGER_READY", flush=True)
        while True:
            line = s.readline()
            if line:
                decoded = line.decode('latin1', errors='replace')
                print(decoded, end='', flush=True)
                f.write(decoded)
                f.flush()

if __name__ == '__main__':
    main()

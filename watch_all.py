import serial, subprocess, threading, time, sys
import serial.tools.list_ports

stop_event = threading.Event()

def open_ch340(port='COM9', baud=115200):
    for b in [9600, 2400, 38400, 57600, 115200]:
        try:
            s = serial.Serial(port, b, timeout=0.1)
            s.baudrate = baud
            return s
        except Exception:
            pass
    return serial.Serial(port, baud, timeout=0.1)

def watch_com():
    try:
        s = open_ch340('COM9', 115200)
        print("[COM9 connected OK!]")
        while not stop_event.is_set():
            data = s.read(s.in_waiting or 1)
            if data:
                text = data.decode('latin-1', errors='replace')
                sys.stdout.write(text)
                sys.stdout.flush()
        s.close()
    except Exception as e:
        print(f"\n[COM Error: {e}]")

def watch_logcat():
    try:
        proc = subprocess.Popen(
            ['adb', '-s', '192.168.0.3:34303', 'logcat', '-v', 'brief', 'StNfcHal:D', 'libnfc_nci:D', '*:S'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1
        )
        while not stop_event.is_set():
            line_b = proc.stdout.readline()
            if not line_b:
                break
            line = line_b.decode('latin-1', errors='ignore')
            if any(k in line for k in ['41 03', '41 06', 'val = 0x1', 'Activated', 'IsoDep', 'TAG', 'SELECT', 'AID']):
                # Only print if not spam
                if '01 a0' not in line:
                    print(f"[PHONE] {line.strip()}")
        proc.terminate()
    except Exception as e:
        print(f"\n[Logcat Error: {e}]")

dur = int(sys.argv[1]) if len(sys.argv) > 1 else 15
print(f"=== Monitoring PN532 (COM9) and Phone NFC for {dur}s ===")

t_com = threading.Thread(target=watch_com, daemon=True)
t_log = threading.Thread(target=watch_logcat, daemon=True)

t_com.start()
t_log.start()

time.sleep(dur)
stop_event.set()
print(f"\n=== Done monitoring ({dur}s) ===")

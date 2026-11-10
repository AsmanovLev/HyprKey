import sys, time, threading, subprocess
sys.path.append(r'D:\Users\User')
from nrf_reset import open_at

stop = threading.Event()

def watch_logcat():
    try:
        proc = subprocess.Popen(
            ['adb', '-s', '192.168.0.3:34303', 'logcat', '-T', '1', '-v', 'brief', 'HyprNfc:V', '*:S'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        while not stop.is_set():
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line:
                print(f"[APP] {line}")
        proc.terminate()
    except Exception as e:
        print(f"[Logcat err: {e}]")

def watch_uart():
    try:
        s = open_at('COM9', 115200)
        while not stop.is_set():
            n = s.in_waiting
            if n:
                data = s.read(n).decode('latin-1', errors='replace')
                sys.stdout.write(data)
                sys.stdout.flush()
            time.sleep(0.02)
        s.close()
    except Exception as e:
        print(f"[UART err: {e}]")

t1 = threading.Thread(target=watch_logcat, daemon=True)
t2 = threading.Thread(target=watch_uart, daemon=True)

t1.start()
t2.start()

dur = int(sys.argv[1]) if len(sys.argv) > 1 else 10
print(f"=== READY! Bring PN532 or blue tag to phone ({dur}s) ===")
time.sleep(dur)
stop.set()
print("\n=== Done monitoring ===")

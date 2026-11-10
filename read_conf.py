import subprocess

res = subprocess.run(['adb', '-s', '192.168.0.3:34303', 'shell', 'su -c "cat /vendor/etc/libnfc-hal-st.conf"'], capture_output=True, text=True)
for line in res.stdout.splitlines():
    line = line.strip()
    if line and not line.startswith('#'):
        print(line)

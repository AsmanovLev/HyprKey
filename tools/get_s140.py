import urllib.request
import os

BASE_URL = "https://raw.githubusercontent.com/adafruit/Adafruit_nRF52_Arduino/master/cores/nRF5/nordic/softdevice/s140_nrf52_6.1.1_API/include/"
FILES = [
    "ble.h", "ble_err.h", "ble_gap.h", "ble_gatt.h", "ble_gattc.h",
    "ble_gatts.h", "ble_hci.h", "ble_l2cap.h", "ble_ranges.h", "ble_types.h",
    "nrf_error.h", "nrf_error_sdm.h", "nrf_error_soc.h", "nrf_nvic.h",
    "nrf_sdm.h", "nrf_soc.h", "nrf_svc.h", "nrf52/nrf_mbr.h"
]

OUT_DIR = "S:/hyprkey/firmware/ble_fido/s140"
os.makedirs(f"{OUT_DIR}/nrf52", exist_ok=True)

for fname in FILES:
    url = BASE_URL + fname
    out_path = f"{OUT_DIR}/{fname}"
    print(f"Downloading {fname}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp, open(out_path, 'wb') as out_f:
            out_f.write(resp.read())
        print(f"  Saved {out_path}")
    except Exception as e:
        print(f"  Failed: {e}")

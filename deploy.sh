#!/usr/bin/env bash
# deploy.sh - build / flash / capture helper for hyprkey test_hw
#
#   ./deploy.sh build [secs]   build, then auto-reset into DFU, flash, capture
#   ./deploy.sh flash [secs]   auto-reset into DFU, flash, capture
#   ./deploy.sh watch [secs]   auto-reset once, then capture (boot banner)
#   ./deploy.sh touch [secs]   prints a TOUCH NOW prompt, then captures
#   ./deploy.sh reset          single reset pulse (restart firmware)
#   ./deploy.sh dfu            double reset pulse (enter UF2 bootloader)
#
# Auto-reset drives the nRF RST line through the CH340 TX pin
# (CH340 TX --[1k]--> SuperMini RST). No button pressing, no beeps.
set -u

FW=/s/hyprkey/firmware/test_hw/test_hw.uf2
RESET=/d/Users/User/nrf_reset.py
WATCH=/d/Users/User/ch340_watch.py
MODE=${1:-flash}
SECS=${2:-10}

wait_drive() {   # $1 = seconds to wait
  for i in $(seq 1 "$1"); do
    [ -f /e/INFO_UF2.TXT ] && return 0
    sleep 1
  done
  return 1
}

case "$MODE" in
  build)
    echo "== building =="
    powershell -NoProfile -ExecutionPolicy Bypass \
      -File "S:\\hyprkey\\firmware\\test_hw\\build.ps1" 2>&1 | grep -Ei "error|warning|Converting|complete"
    MODE=flash
    ;;&
  flash)
    if [ ! -f /e/INFO_UF2.TXT ]; then
      for attempt in 1 2 3; do
        python "$RESET" double >/dev/null 2>&1 || true
        if wait_drive 3; then
          echo "   auto-reset into DFU (attempt $attempt)"
          break
        fi
      done
    else
      echo "   bootloader already mounted"
    fi
    if [ ! -f /e/INFO_UF2.TXT ]; then
      echo "   !! could not reach the bootloader - reset the board manually"
      exit 1
    fi
    echo "   flashing $(basename "$FW") ($(stat -c%s "$FW") bytes)"
    cp "$FW" /e/ || { echo "copy failed"; exit 1; }
    for i in $(seq 1 30); do
      [ -f /e/INFO_UF2.TXT ] || { echo "   rebooted (${i}s)"; break; }
      sleep 1
    done
    sleep 3
    ;;
  watch)
    if python "$RESET" single >/dev/null 2>&1; then
      echo "   single auto-reset sent"
      sleep 1
    else
      echo "   !! auto-reset failed - press RESET once"
      sleep 3
    fi
    ;;
  touch)
    echo "** TOUCH THE SENSOR NOW **"
    sleep 1
    ;;
  reset) python "$RESET" single ;;
  dfu)   python "$RESET" double ;;
  *) echo "usage: $0 {build|flash|watch|touch|reset|dfu} [secs]"; exit 1 ;;
esac

echo "== capture ${SECS}s @115200 =="
cd /s/hyprkey && python "$WATCH" "$SECS" 2>&1 | grep -v "hex:"

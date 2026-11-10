#!/usr/bin/env python3
"""tools/nfc_lock.py - HyprKey NFC Physical Presence Lock Management Tool.

Communicates purely over USB CCID (Smart Card APDU) without requiring COM ports.
Manages physical 2FA/Master Lock with support for:
  - Mode 1: Static UID (fobs, badges, NTAG) with explicit cloning warning
  - Mode 2: Zero-Clone EMV Crypto (bank cards, secure elements)
"""

import sys
import smartcard.System as sc
from smartcard.util import toHexString

def get_connection():
    readers = [r for r in sc.readers() if "hyprkey" in str(r).lower() or "smart card" in str(r).lower()]
    if not readers:
        all_r = sc.readers()
        if all_r:
            readers = [all_r[0]]
        else:
            print("Error: No HyprKey smart card readers found!")
            sys.exit(1)
    
    conn = readers[0].createConnection()
    conn.connect()
    return conn

def auth_admin_pin(conn, pin="12345678"):
    # SELECT OpenPGP Card Applet
    conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
    pin_bytes = list(pin.encode("ascii"))
    # VERIFY PW3
    resp, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, 0x83, len(pin_bytes)] + pin_bytes)
    if (sw1, sw2) != (0x90, 0x00):
        print(f"Error: Admin PIN (PW3) verification failed! (SW={sw1:02X}{sw2:02X})")
        sys.exit(1)

def cmd_status():
    conn = get_connection()
    resp, sw1, sw2 = conn.transmit([0xFF, 0xEB, 0x00, 0x00, 0x00])
    if (sw1, sw2) != (0x90, 0x00) or len(resp) < 35:
        print(f"Failed to read lock status: SW={sw1:02X}{sw2:02X}")
        return

    mode = resp[0]
    is_locked = resp[1]
    uid_len = resp[2]
    uid = bytes(resp[3:3+uid_len]) if uid_len > 0 else b""
    card_hash = bytes(resp[13:45])

    print("\n" + "="*60)
    print("      HYPRKEY NFC PHYSICAL PRESENCE LOCK STATUS")
    print("="*60)
    
    mode_str = {
        0: "DISABLED (Обычный режим без физической блокировки)",
        1: "MODE 1: STATIC UID (Метка / Домофон / Пропуск)",
        2: "MODE 2: ZERO-CLONE EMV CRYPTO (Банковская смарт-карта)"
    }.get(mode, f"UNKNOWN ({mode})")
    print(f"Режим блокировки : {mode_str}")
    
    state_str = "🔒 ЗАБЛОКИРОВАН (Ожидает прикладывания карты к антенне)" if is_locked else "🔓 РАЗБЛОКИРОВАН (Активен)"
    print(f"Текущий статус   : {state_str}")

    if mode == 1:
        print(f"Привязанный UID  : {uid.hex().upper()} ({':'.join(f'{b:02X}' for b in uid)}) [{uid_len} байт]")
        print("\n⚠️  ПРЕДУПРЕЖДЕНИЕ: Привязана статическая метка. Данный режим не защищен")
        print("   от клонирования с помощью Flipper Zero или смартфона.")
    elif mode == 2:
        print(f"Хэш сертификата  : {card_hash.hex().upper()[:32]}...")
        print("\n🛡️  ЗАЩИТА: Активен криптографический режим. Клонирование карты невозможно.")
    print("="*60 + "\n")

def cmd_enroll_uid(pin="12345678"):
    conn = get_connection()
    print("Авторизация администратора (PW3)...")
    auth_admin_pin(conn, pin)

    print("Сканирование метки на антенне...")
    resp, sw1, sw2 = conn.transmit([0xFF, 0xEB, 0x01, 0x01, 0x00])
    if (sw1, sw2) == (0x6A, 0x80) or len(resp) < 2:
        print("\n❌ ОШИБКА: На антенне сейчас НЕТ метки. Положите метку на антенну и повторите команду.")
        return
    if (sw1, sw2) != (0x90, 0x00):
        print(f"\n❌ Ошибка привязки: SW={sw1:02X}{sw2:02X}")
        return

    warning_flag = resp[0]
    uid_len = resp[1]
    uid = bytes(resp[2:2+uid_len])

    print("\n" + "="*65)
    print("   МЕТКА УСПЕШНО ПРИВЯЗАНА (РЕЖИМ 1: STATIC UID)")
    print("="*65)
    print(f"UID метки: {uid.hex().upper()} ({':'.join(f'{b:02X}' for b in uid)}) [{uid_len} байт]")
    if warning_flag == 1:
        print("\n⚠️  ВНИМАНИЕ! ПРЕДУПРЕЖДЕНИЕ О БЕЗОПАСНОСТИ:")
        print("   Вы привязали метку со статическим серийным номером (UID).")
        print("   Данный номер передается в эфир в открытом виде и НЕ защищен криптографией.")
        print("   Любое устройство (Flipper Zero, Proxmark3, телефон) может скопировать")
        print("   эту метку на пустую болванку за 1 секунду.")
        print("   Используйте этот режим только для защиты от случайного доступа дома,")
        print("   но НЕ для защиты критически важных мастер-ключей.")
    print("="*65 + "\n")

def cmd_enroll_emv(pin="12345678"):
    conn = get_connection()
    print("Авторизация администратора (PW3)...")
    auth_admin_pin(conn, pin)

    print("Чтение защищенной смарт-карты на антенне...")
    resp, sw1, sw2 = conn.transmit([0xFF, 0xEB, 0x01, 0x02, 0x00])
    if (sw1, sw2) == (0x6A, 0x80) or len(resp) < 33:
        print("\n❌ ОШИБКА: На антенне нет подходящей EMV смарт-карты (МИР / Visa / Mastercard).")
        return
    if (sw1, sw2) != (0x90, 0x00):
        print(f"\n❌ Ошибка привязки: SW={sw1:02X}{sw2:02X}")
        return

    card_hash = bytes(resp[1:33])
    print("\n" + "="*65)
    print("   СМАРТ-КАРТА УСПЕШНО ПРИВЯЗАНА (РЕЖИМ 2: ZERO-CLONE EMV)")
    print("="*65)
    print(f"Криптографический хэш карты: {card_hash.hex().upper()}")
    print("\n🛡️  МАКСИМАЛЬНЫЙ УРОВЕНЬ ЗАЩИТЫ:")
    print("   Ключ аппаратно привязан к вашей банковской смарт-карте.")
    print("   Клонирование невозможно даже при полном перехвате радиосигнала.")
    print("   Для разблокировки токена потребуется положить именно эту физическую карту.")
    print("="*65 + "\n")

def cmd_disable(pin="12345678"):
    conn = get_connection()
    print("Авторизация администратора (PW3)...")
    auth_admin_pin(conn, pin)

    resp, sw1, sw2 = conn.transmit([0xFF, 0xEB, 0x02, 0x00, 0x00])
    if (sw1, sw2) == (0x90, 0x00):
        print("\n✔ Физическая блокировка NFC успешно ОТКЛЮЧЕНА.")
    else:
        print(f"\n❌ Ошибка отключения: SW={sw1:02X}{sw2:02X}")

def cmd_lock():
    conn = get_connection()
    resp, sw1, sw2 = conn.transmit([0xFF, 0xEB, 0x03, 0x00, 0x00])
    if (sw1, sw2) == (0x90, 0x00):
        print("\n🔒 Токен заблокирован. Для работы положите привязанную карту на антенну.")
    else:
        print(f"\n❌ Ошибка блокировки: SW={sw1:02X}{sw2:02X}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python tools/nfc_lock.py <команда> [admin_pin]")
        print("Команды:")
        print("  status       - Показать текущий статус физической блокировки")
        print("  enroll-uid   - Привязать метку по статическому UID (Режим 1, с предупреждением)")
        print("  enroll-emv   - Привязать банковскую смарт-карту (Режим 2, криптографический)")
        print("  lock         - Немедленно заблокировать токен до следующего прикладывания")
        print("  disable      - Отключить физическую блокировку")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    pin = sys.argv[2] if len(sys.argv) > 2 else "12345678"

    if cmd == "status":
        cmd_status()
    elif cmd in ("enroll-uid", "enroll_uid"):
        cmd_enroll_uid(pin)
    elif cmd in ("enroll-emv", "enroll_emv"):
        cmd_enroll_emv(pin)
    elif cmd == "disable":
        cmd_disable(pin)
    elif cmd == "lock":
        cmd_lock()
    else:
        print(f"Неизвестная команда: {cmd}")

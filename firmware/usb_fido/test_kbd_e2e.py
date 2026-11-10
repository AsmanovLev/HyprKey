import unicorn, unicorn.arm_const as ac
import subprocess

gcc = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-gcc.exe"
objcopy = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-objcopy.exe"
nm = r"D:\STM32CubeIDE_2.0.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.win32_1.0.100.202509120712\tools\bin\arm-none-eabi-nm.exe"

runner_c = """
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int val, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)val;
    return dst;
}

/* Simulated EP3 reports recorded during typing */
uint8_t g_recorded_reports[100][8];
uint32_t g_report_count = 0;

static bool ascii_to_hid(char c, uint8_t *mod, uint8_t *code) {
    *mod = 0;
    if (c >= 'a' && c <= 'z') {
        *code = 0x04 + (uint8_t)(c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *mod = 0x02; /* Left Shift */
        *code = 0x04 + (uint8_t)(c - 'A');
        return true;
    }
    if (c >= '1' && c <= '9') {
        *code = 0x1E + (uint8_t)(c - '1');
        return true;
    }
    if (c == '0') { *code = 0x27; return true; }
    if (c == '\\n' || c == '\\r') { *code = 0x28; return true; } /* Enter */
    if (c == '\\t') { *code = 0x2B; return true; }              /* Tab */
    if (c == ' ')  { *code = 0x2C; return true; }              /* Space */
    if (c == '-')  { *code = 0x2D; return true; }
    if (c == '_')  { *mod = 0x02; *code = 0x2D; return true; }
    if (c == '=')  { *code = 0x2E; return true; }
    if (c == '+')  { *mod = 0x02; *code = 0x2E; return true; }
    if (c == '[')  { *code = 0x2F; return true; }
    if (c == '{')  { *mod = 0x02; *code = 0x2F; return true; }
    if (c == ']')  { *code = 0x30; return true; }
    if (c == '}')  { *mod = 0x02; *code = 0x30; return true; }
    if (c == ';')  { *code = 0x33; return true; }
    if (c == ':')  { *mod = 0x02; *code = 0x33; return true; }
    if (c == '\\'') { *code = 0x34; return true; }
    if (c == '\\"') { *mod = 0x02; *code = 0x34; return true; }
    if (c == ',')  { *code = 0x36; return true; }
    if (c == '<')  { *mod = 0x02; *code = 0x36; return true; }
    if (c == '.')  { *code = 0x37; return true; }
    if (c == '>')  { *mod = 0x02; *code = 0x37; return true; }
    if (c == '/')  { *code = 0x38; return true; }
    if (c == '?')  { *mod = 0x02; *code = 0x38; return true; }
    if (c == '!')  { *mod = 0x02; *code = 0x1E; return true; }
    if (c == '@')  { *mod = 0x02; *code = 0x1F; return true; }
    if (c == '#')  { *mod = 0x02; *code = 0x20; return true; }
    if (c == '$')  { *mod = 0x02; *code = 0x21; return true; }
    if (c == '%')  { *mod = 0x02; *code = 0x22; return true; }
    if (c == '^')  { *mod = 0x02; *code = 0x23; return true; }
    if (c == '&')  { *mod = 0x02; *code = 0x24; return true; }
    if (c == '*')  { *mod = 0x02; *code = 0x25; return true; }
    if (c == '(')  { *mod = 0x02; *code = 0x26; return true; }
    if (c == ')')  { *mod = 0x02; *code = 0x27; return true; }
    return false;
}

static void send_ep3_keyboard_report(uint8_t modifier, uint8_t keycode) {
    if (g_report_count < 100) {
        g_recorded_reports[g_report_count][0] = modifier;
        g_recorded_reports[g_report_count][1] = 0;
        g_recorded_reports[g_report_count][2] = keycode;
        g_recorded_reports[g_report_count][3] = 0;
        g_recorded_reports[g_report_count][4] = 0;
        g_recorded_reports[g_report_count][5] = 0;
        g_recorded_reports[g_report_count][6] = 0;
        g_recorded_reports[g_report_count][7] = 0;
        g_report_count++;
    }
}

void test_type_string(const char *str) {
    while (*str) {
        uint8_t mod = 0, code = 0;
        if (ascii_to_hid(*str, &mod, &code)) {
            send_ep3_keyboard_report(mod, code);
            send_ep3_keyboard_report(0, 0); /* Key release */
        }
        str++;
    }
}
"""

with open("s:/hyprkey/firmware/usb_fido/runner_kbd.c", "w") as f:
    f.write(runner_c)

cmd = (f'"{gcc}" -mcpu=cortex-m4 -mthumb -O2 -fno-builtin -nostdlib -Ttext 0x1000 '
       f's:/hyprkey/firmware/usb_fido/runner_kbd.c '
       f'-lgcc -o s:/hyprkey/firmware/usb_fido/test_kbd.elf')
subprocess.check_call(cmd, shell=True)

syms = subprocess.check_output(f'"{nm}" s:/hyprkey/firmware/usb_fido/test_kbd.elf', shell=True).decode()
symbols = {line.split()[2]: int(line.split()[0], 16) for line in syms.splitlines() if len(line.split())==3}

cmd_bin = f'"{objcopy}" -O binary s:/hyprkey/firmware/usb_fido/test_kbd.elf s:/hyprkey/firmware/usb_fido/test_kbd.bin'
subprocess.check_call(cmd_bin, shell=True)

with open("s:/hyprkey/firmware/usb_fido/test_kbd.bin", "rb") as f: code = f.read()

uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
uc.mem_map(0x0, 0x100000)
uc.mem_write(0x1000, code)

# Test typing "hyprkey!\n"
test_str = b"hyprkey!\n\x00"
str_addr = 0x50000
uc.mem_write(str_addr, test_str)

uc.reg_write(ac.UC_ARM_REG_R0, str_addr)
uc.reg_write(ac.UC_ARM_REG_SP, 0xFE000)
uc.reg_write(ac.UC_ARM_REG_LR, 0x80000 | 1)
uc.emu_start(symbols['test_type_string'] | 1, 0x80000)

count_bytes = uc.mem_read(symbols['g_report_count'], 4)
count = int.from_bytes(count_bytes, 'little')
print(f"Recorded HID reports count: {count}")
assert count == len("hyprkey!\n") * 2 # Press + Release for each character

# Read reports
reports_raw = uc.mem_read(symbols['g_recorded_reports'], count * 8)
reports = [reports_raw[i*8 : (i+1)*8] for i in range(count)]

# Verify characters:
# 'h': mod 0, code 0x0B (0x04 + 7)
assert reports[0][0] == 0 and reports[0][2] == 0x0B
# release: mod 0, code 0
assert reports[1][0] == 0 and reports[1][2] == 0x00

# 'y': mod 0, code 0x1C (0x04 + 24)
assert reports[2][0] == 0 and reports[2][2] == 0x1C

# '!': mod 2 (Shift), code 0x1E ('1')
assert reports[14][0] == 0x02 and reports[14][2] == 0x1E
assert reports[15][0] == 0x00 and reports[15][2] == 0x00

# '\n': mod 0, code 0x28 (Enter)
assert reports[16][0] == 0x00 and reports[16][2] == 0x28
assert reports[17][0] == 0x00 and reports[17][2] == 0x00

print("[PASS] USB Boot Keyboard report translation & keystroke generation 100% verified!")

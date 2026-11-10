
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
    if (c == '\n' || c == '\r') { *code = 0x28; return true; } /* Enter */
    if (c == '\t') { *code = 0x2B; return true; }              /* Tab */
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
    if (c == '\'') { *code = 0x34; return true; }
    if (c == '\"') { *mod = 0x02; *code = 0x34; return true; }
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

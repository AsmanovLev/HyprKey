#include "hyprkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

static void get_password_interactive(const char *prompt, char *buffer, size_t max_len) {
    printf("%s", prompt);
    fflush(stdout);

    size_t idx = 0;
#ifdef _WIN32
    while (idx < max_len - 1) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            break;
        } else if (ch == '\b' || ch == 127) {
            if (idx > 0) {
                idx--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (ch == 3) { /* Ctrl+C */
            printf("\n");
            exit(1);
        } else if (ch >= 32 && ch <= 126) {
            buffer[idx++] = (char)ch;
            putchar('*');
            fflush(stdout);
        }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(buffer, (int)max_len, stdin) != NULL) {
        size_t l = strlen(buffer);
        if (l > 0 && (buffer[l - 1] == '\n' || buffer[l - 1] == '\r')) {
            buffer[l - 1] = '\0';
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    return;
#endif
    buffer[idx] = '\0';
    printf("\n");
}

static void print_usage(const char *prog) {
    printf("Hyprkey Hardware Security Key & Wallet CLI Tool\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  status                     Query hardware wallet status\n");
    printf("  pin verify <pin>           Verify device PIN\n");
    printf("  pin change <old> <new>     Change device PIN\n");
    printf("  seed import <64-byte-hex>  Import raw BIP-39 binary seed\n");
    printf("  address <coin>             Retrieve public address for specified crypto\n");
    printf("                             Coins: btc-legacy, btc-nested, btc-native, btc-taproot,\n");
    printf("                                    eth, bnb, pol, sol, ton, trx, ltc-legacy, ltc-nested,\n");
    printf("                                    ltc-native, xmr\n");
    printf("  monero                     Export Monero keys (SpendPub, ViewPub, ViewSec, Address)\n");
    printf("  rng [bytes]                Request hardware TRNG entropy from nRF52 (default: 32)\n");
    printf("\n");
}

static hyprkey_coin_t parse_coin(const char *name) {
    if (strcmp(name, "btc-legacy") == 0) return HYPRKEY_COIN_BTC_LEGACY;
    if (strcmp(name, "btc-nested") == 0) return HYPRKEY_COIN_BTC_NESTED_SEGWIT;
    if (strcmp(name, "btc-native") == 0 || strcmp(name, "btc") == 0) return HYPRKEY_COIN_BTC_NATIVE_SEGWIT;
    if (strcmp(name, "btc-taproot") == 0) return HYPRKEY_COIN_BTC_TAPROOT;
    if (strcmp(name, "eth") == 0 || strcmp(name, "bnb") == 0 || strcmp(name, "pol") == 0 || strcmp(name, "evm") == 0) return HYPRKEY_COIN_EVM;
    if (strcmp(name, "sol") == 0 || strcmp(name, "solana") == 0) return HYPRKEY_COIN_SOLANA;
    if (strcmp(name, "ton") == 0) return HYPRKEY_COIN_TON;
    if (strcmp(name, "trx") == 0 || strcmp(name, "tron") == 0) return HYPRKEY_COIN_TRON;
    if (strcmp(name, "ltc-legacy") == 0) return HYPRKEY_COIN_LTC_LEGACY;
    if (strcmp(name, "ltc-nested") == 0) return HYPRKEY_COIN_LTC_NESTED;
    if (strcmp(name, "ltc-native") == 0 || strcmp(name, "ltc") == 0) return HYPRKEY_COIN_LTC_NATIVE;
    if (strcmp(name, "xmr") == 0 || strcmp(name, "monero") == 0) return HYPRKEY_COIN_MONERO;
    return (hyprkey_coin_t)-1;
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
}

static int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    if (strlen(hex) != bin_len * 2) return -1;
    for (size_t i = 0; i < bin_len; ++i) {
        unsigned int val;
        if (sscanf(&hex[i * 2], "%02x", &val) != 1) return -1;
        bin[i] = (uint8_t)val;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    hyprkey_device_t *dev = NULL;
    hyprkey_status_t st = hyprkey_connect(&dev, NULL);
    if (st != HYPRKEY_OK) {
        fprintf(stderr, "[-] Failed to connect to Hyprkey: %s\n", hyprkey_strerror(st));
        return 1;
    }

    printf("[+] Connected to: %s\n", hyprkey_get_reader_name(dev));

    if (strcmp(cmd, "status") == 0) {
        hyprkey_status_info_t info;
        st = hyprkey_get_status(dev, &info);
        if (st == HYPRKEY_OK) {
            printf("\n--- Hyprkey Device Status ---\n");
            printf("Protocol Version : %d\n", info.protocol_version);
            printf("Applet Version   : %d.%d\n", info.applet_version_major, info.applet_version_minor);
            printf("PIN Retries Left : %d\n", info.pin_retry_count);
            printf("Master Seed      : %s\n", info.has_seed ? "LOADED" : "EMPTY");
            printf("PIN Authenticated: %s\n", info.pin_verified ? "YES" : "NO");
        } else {
            fprintf(stderr, "[-] Error getting status: %s\n", hyprkey_strerror(st));
        }
    } else if (strcmp(cmd, "pin") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            hyprkey_disconnect(dev);
            return 1;
        }
        if (strcmp(argv[2], "verify") == 0) {
            char pin_buf[32];
            const char *pin = NULL;
            if (argc >= 4) {
                pin = argv[3];
            } else {
                get_password_interactive("Enter Hyprkey PIN: ", pin_buf, sizeof(pin_buf));
                pin = pin_buf;
            }
            st = hyprkey_verify_pin(dev, pin);
            if (st == HYPRKEY_OK) {
                printf("[+] PIN verified successfully!\n");
            } else {
                fprintf(stderr, "[-] PIN verification failed: %s\n", hyprkey_strerror(st));
            }
        } else if (strcmp(argv[2], "change") == 0) {
            char old_buf[32];
            char new_buf[32];
            const char *old_p = NULL;
            const char *new_p = NULL;
            if (argc >= 5) {
                old_p = argv[3];
                new_p = argv[4];
            } else {
                get_password_interactive("Enter Current PIN: ", old_buf, sizeof(old_buf));
                get_password_interactive("Enter New PIN:     ", new_buf, sizeof(new_buf));
                old_p = old_buf;
                new_p = new_buf;
            }
            st = hyprkey_change_pin(dev, old_p, new_p);
            if (st == HYPRKEY_OK) {
                printf("[+] PIN changed successfully!\n");
            } else {
                fprintf(stderr, "[-] PIN change failed: %s\n", hyprkey_strerror(st));
            }
        }
    } else if (strcmp(cmd, "seed") == 0) {
        if (argc < 4 || strcmp(argv[2], "import") != 0) {
            print_usage(argv[0]);
            hyprkey_disconnect(dev);
            return 1;
        }
        uint8_t seed[64];
        if (hex2bin(argv[3], seed, sizeof(seed)) != 0) {
            fprintf(stderr, "[-] Invalid seed hex string (expected 128 hex chars / 64 bytes)\n");
            hyprkey_disconnect(dev);
            return 1;
        }
        st = hyprkey_import_bip39_seed(dev, seed);
        if (st == HYPRKEY_OK) {
            printf("[+] Master seed imported successfully into secure element!\n");
        } else {
            fprintf(stderr, "[-] Failed to import seed: %s\n", hyprkey_strerror(st));
        }
    } else if (strcmp(cmd, "address") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            hyprkey_disconnect(dev);
            return 1;
        }
        hyprkey_coin_t coin = parse_coin(argv[2]);
        if ((int)coin < 0) {
            fprintf(stderr, "[-] Unknown coin: %s\n", argv[2]);
            hyprkey_disconnect(dev);
            return 1;
        }

        char addr[128];
        uint8_t pubkey[65];
        size_t pk_len = sizeof(pubkey);

        st = hyprkey_get_address(dev, coin, addr, sizeof(addr), pubkey, &pk_len);
        if (st == HYPRKEY_OK) {
            printf("\nCoin    : %s\n", argv[2]);
            printf("Address : %s\n", addr);
            printf("Pubkey  : ");
            print_hex(pubkey, pk_len);
            printf("\n");
        } else {
            fprintf(stderr, "[-] Failed to get address: %s\n", hyprkey_strerror(st));
        }
    } else if (strcmp(cmd, "monero") == 0) {
        hyprkey_monero_keys_t xmr;
        st = hyprkey_get_monero_keys(dev, &xmr);
        if (st == HYPRKEY_OK) {
            printf("\n--- Monero (XMR) Account Info ---\n");
            printf("Standard Address : %s\n", xmr.address);
            printf("Spend Public Key : ");
            print_hex(xmr.spend_pub, 32);
            printf("\n");
            printf("View Public Key  : ");
            print_hex(xmr.view_pub, 32);
            printf("\n");
            printf("Private View Key : ");
            print_hex(xmr.view_sec, 32);
            printf(" (View-Only Wallet Export)\n");
        } else {
            fprintf(stderr, "[-] Failed to get Monero keys: %s\n", hyprkey_strerror(st));
        }
    } else if (strcmp(cmd, "rng") == 0) {
        size_t count = 32;
        if (argc >= 3) {
            count = (size_t)atoi(argv[2]);
            if (count == 0 || count > 255) count = 32;
        }
        uint8_t rnd[256];
        st = hyprkey_get_random(dev, rnd, count);
        if (st == HYPRKEY_OK) {
            printf("[+] %zu bytes of hardware entropy (nRF52840 TRNG):\n", count);
            print_hex(rnd, count);
            printf("\n");
        } else {
            fprintf(stderr, "[-] TRNG request failed: %s\n", hyprkey_strerror(st));
        }
    } else {
        print_usage(argv[0]);
    }

    hyprkey_disconnect(dev);
    return 0;
}

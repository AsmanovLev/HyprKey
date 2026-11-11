# Simple Makefile to build Windows binaries (libhyprkey.dll, hyprkey.exe)
# using x86_64-w64-mingw32-gcc directly inside s:\hyprkey\sdk

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 -Iinclude -D_WIN32_WINNT=0x0600
LDFLAGS = -lwinscard

SRCS_LIB = libhyprkey/transport_pcsc.c libhyprkey/satochip.c
SRCS_CLI = cli/main.c

all: build/libhyprkey.dll build/hyprkey.exe

build/libhyprkey.dll: $(SRCS_LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -shared -DHYPRKEY_BUILD_DLL -o $@ $^ $(LDFLAGS)

build/hyprkey.exe: $(SRCS_CLI) $(SRCS_LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf build

.PHONY: all clean

#ifndef APP_HEADER_H
#define APP_HEADER_H

#include <stdint.h>

#define APP_HEADER_MAGIC 0x48595052UL /* 'HYPR' */

typedef struct __attribute__((packed)) {
    uint32_t magic;            /* 0x48595052 'HYPR' (offset 0x00) */
    uint32_t version;          /* (Major<<24) | (Minor<<16) | (Patch<<8) | Build (offset 0x04) */
    uint32_t security_counter; /* Monotonic Anti-Rollback Counter (offset 0x08) */
    uint32_t image_size;       /* Total image length in bytes (offset 0x0C) */
    uint8_t  sha256[32];       /* SHA-256 digest of payload starting at 0x80 (offset 0x10..0x2F) */
    char     git_commit[8];    /* Git short commit hash (offset 0x30..0x37) */
    char     build_date[8];    /* Build date YYYYMMDD (offset 0x38..0x3F) */
} app_header_t;

_Static_assert(sizeof(app_header_t) == 64, "app_header_t must be exactly 64 bytes");

#endif /* APP_HEADER_H */

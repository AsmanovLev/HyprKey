#ifndef HYPR_STORAGE_H
#define HYPR_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define HYPR_FLASH_PAGE_SIZE     4096U
#define HYPR_TLV_TOTAL_PAGES     164U   /* 656 КБ под Зону Б */
#define HYPR_GC_RESERVE_PAGES    2U     /* 8 КБ скользящий резерв GC */
#define HYPR_MAX_RECORDS         1024U  /* Максимум уникальных record_id */
#define HYPR_MAX_PAYLOAD_LEN     1024U  /* Максимальный размер полезной нагрузки записи */

#define HYPR_PAGE_MAGIC          0x50475948UL /* "HYGP" */

/* Состояния страницы (строгий переход битов 1 -> 0 без стирания) */
#define HYPR_PAGE_STATE_EMPTY         0xFFFFFFFFUL
#define HYPR_PAGE_STATE_ACTIVE        0xFFFFFFFEUL
#define HYPR_PAGE_STATE_COMPACTING    0xFFFFFFFCUL
#define HYPR_PAGE_STATE_ERASE_PENDING 0xFFFFFFF0UL

/* Состояния записи TLV (строгий переход битов 1 -> 0 без стирания) */
#define HYPR_TLV_STATE_EMPTY          0xFFFFFFFFUL
#define HYPR_TLV_STATE_ALLOCATING     0xFFFFFFFEUL
#define HYPR_TLV_STATE_COMMITTED      0xFFFFFFFCUL
#define HYPR_TLV_STATE_INVALIDATED    0xFFFFFFF0UL

/* Типы записей TLV */
#define HYPR_REC_TYPE_FIDO_RK         1U
#define HYPR_REC_TYPE_OATH            2U
#define HYPR_REC_TYPE_PGP_DATA        3U
#define HYPR_REC_TYPE_CONFIG          4U

typedef enum {
    HYPR_OK = 0,
    HYPR_ERR_INVALID_ARG,
    HYPR_ERR_NOT_FOUND,
    HYPR_ERR_LOW_POWER,       /* Сработал аппаратный компаратор POFWARN (< 2.8V) */
    HYPR_ERR_AUTH_FAILED,     /* Ошибка проверки тега Poly1305 */
    HYPR_ERR_STORAGE_FULL,    /* Нет места даже после сборки мусора */
    HYPR_ERR_FLASH_CORRUPTED
} hypr_err_t;

/* Заголовок страницы 4 КБ (16 байт, 4 слова) */
typedef struct __attribute__((packed, aligned(4))) {
    uint32_t magic;           /* HYPR_PAGE_MAGIC */
    uint32_t page_state;      /* HYPR_PAGE_STATE_* */
    uint32_t erase_count;     /* Счетчик циклов стирания для wear-leveling */
    uint32_t reserved;        /* Выравнивание до 16 байт */
} hypr_page_hdr_t;

/* Заголовок записи TLV v2.0 (32 байта, 8 слов) */
typedef struct __attribute__((packed, aligned(4))) {
    uint32_t state_flags;     /* HYPR_TLV_STATE_* */
    uint16_t record_type;     /* 1=FIDO_RK, 2=OATH, 3=PGP_CERT, 4=PASS_META */
    uint16_t record_id;       /* Логический индекс объекта (0 .. HYPR_MAX_RECORDS-1) */
    uint32_t record_version;  /* Монотонный счетчик версий для деривации Nonce */
    uint16_t payload_len;     /* Реальный размер данных (до выравнивания) */
    uint16_t flags;           /* Политики доступа к записи */
    uint8_t  poly1305_tag[16];/* Тег аутентификации ChaCha20-Poly1305 (RFC 8439) */
} hypr_tlv_record_hdr_v2_t;

/* Ассоциированные данные (AAD) для привязки шифротекста к метаданным (12 байт) */
typedef struct __attribute__((packed, aligned(4))) {
    uint16_t record_type;
    uint16_t record_id;
    uint32_t record_version;
    uint16_t payload_len;
    uint16_t flags;
} hypr_tlv_aad_t;

/* Абстракция аппаратного уровня (NVMC + POFCON + Crypto) */
typedef struct {
    void *user_ctx;
    bool (*pofwarn_is_active)(void *user_ctx);
    void (*flash_read)(void *user_ctx, uint32_t addr, void *dst, uint32_t len);
    void (*flash_write_words)(void *user_ctx, uint32_t addr, const uint32_t *src, uint32_t words);
    void (*flash_erase_page)(void *user_ctx, uint32_t page_idx);
    void (*derive_nonce)(const uint8_t mk[32], uint16_t type, uint16_t id, uint32_t ver, uint8_t nonce[12]);
    void (*aead_encrypt)(const uint8_t mk[32], const uint8_t nonce[12], const void *aad, uint32_t aad_len,
                         const uint8_t *plain, uint8_t *cipher, uint32_t len, uint8_t tag_out[16]);
    bool (*aead_decrypt)(const uint8_t mk[32], const uint8_t nonce[12], const void *aad, uint32_t aad_len,
                         const uint8_t *cipher, uint8_t *plain, uint32_t len, const uint8_t tag[16]);
} hypr_storage_hal_t;

/* Элемент O(1) индекса в SRAM (8 байт на запись -> 8 КБ на 1024 записи) */
typedef struct {
    uint32_t flash_offset;    /* Смещение заголовка в Зоне Б (0 = запись отсутствует) */
    uint32_t version;         /* Последняя подтвержденная версия record_version */
} hypr_ram_index_t;

/* Контекст хранилища */
typedef struct {
    const hypr_storage_hal_t *hal;
    const uint8_t            *mk; /* Указатель на 32-байтный Storage Master Key в SRAM */
    uint32_t                  active_write_page;
    uint32_t                  active_write_offset;
    hypr_ram_index_t          index[HYPR_MAX_RECORDS];
    uint16_t                  page_dirty_bytes[HYPR_TLV_TOTAL_PAGES];
} hypr_storage_ctx_t;

hypr_err_t hypr_storage_mount(hypr_storage_ctx_t *ctx, const hypr_storage_hal_t *hal, const uint8_t mk[32]);
hypr_err_t hypr_storage_read(hypr_storage_ctx_t *ctx, uint16_t record_id, uint16_t *type_out,
                             uint16_t *flags_out, uint8_t *plain_out, uint16_t max_len, uint16_t *actual_len);
hypr_err_t hypr_storage_write(hypr_storage_ctx_t *ctx, uint16_t record_id, uint16_t record_type,
                              uint16_t flags, const uint8_t *plain, uint16_t payload_len);
hypr_err_t hypr_storage_delete(hypr_storage_ctx_t *ctx, uint16_t record_id);
hypr_err_t hypr_storage_gc(hypr_storage_ctx_t *ctx);

#endif /* HYPR_STORAGE_H */

#include "hypr_storage.h"
#include <string.h>

static inline uint32_t align4(uint32_t val) {
    return (val + 3U) & ~3U;
}

static inline uint32_t page_base_addr(uint32_t page_idx) {
    return page_idx * HYPR_FLASH_PAGE_SIZE;
}

/* Безопасное затирание временных буферов на стеке */
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0U;
    }
}

/* Прожиг одного 32-битного слова статуса (переход 1 -> 0) */
static void burn_u32(hypr_storage_ctx_t *ctx, uint32_t addr, uint32_t val) {
    ctx->hal->flash_write_words(ctx->hal->user_ctx, addr, &val, 1U);
}

/* Форматирование заголовка страницы */
static void format_page_header(hypr_storage_ctx_t *ctx, uint32_t page_idx, uint32_t state, uint32_t erase_cnt) {
    hypr_page_hdr_t hdr = {
        .magic       = HYPR_PAGE_MAGIC,
        .page_state  = state,
        .erase_count = erase_cnt,
        .reserved    = 0xFFFFFFFFUL
    };
    ctx->hal->flash_write_words(ctx->hal->user_ctx, page_base_addr(page_idx),
                                (const uint32_t *)&hdr, sizeof(hdr) / 4U);
}

/* Поиск чистой страницы с минимальным износом (Wear-Leveling) */
static bool find_best_empty_page(hypr_storage_ctx_t *ctx, uint32_t *page_out, uint32_t *empty_count_out) {
    uint32_t min_erases = 0xFFFFFFFFUL;
    uint32_t best_page  = 0xFFFFFFFFUL;
    uint32_t empty_cnt  = 0U;

    for (uint32_t p = 0U; p < HYPR_TLV_TOTAL_PAGES; p++) {
        hypr_page_hdr_t phdr;
        ctx->hal->flash_read(ctx->hal->user_ctx, page_base_addr(p), &phdr, sizeof(phdr));

        if (phdr.magic == HYPR_PAGE_MAGIC && phdr.page_state == HYPR_PAGE_STATE_EMPTY) {
            empty_cnt++;
            if (phdr.erase_count < min_erases) {
                min_erases = phdr.erase_count;
                best_page  = p;
            }
        }
    }
    if (empty_count_out != NULL) {
        *empty_count_out = empty_cnt;
    }
    if (best_page != 0xFFFFFFFFUL) {
        *page_out = best_page;
        return true;
    }
    return false;
}

/* Внутренняя функция двухфазной записи записи по известному смещению */
static void write_record_at(hypr_storage_ctx_t *ctx, uint32_t offset,
                            const hypr_tlv_record_hdr_v2_t *hdr_template,
                            const uint32_t *aligned_cipher_words, uint32_t cipher_word_cnt) {
    /* Фаза 1: Запись заголовка со статусом ALLOCATING (0xFFFFFFFE) */
    hypr_tlv_record_hdr_v2_t alloc_hdr = *hdr_template;
    alloc_hdr.state_flags = HYPR_TLV_STATE_ALLOCATING;

    ctx->hal->flash_write_words(ctx->hal->user_ctx, offset,
                                (const uint32_t *)&alloc_hdr, sizeof(alloc_hdr) / 4U);

    /* Фаза 2: Запись выровненного шифротекста */
    if (cipher_word_cnt > 0U) {
        ctx->hal->flash_write_words(ctx->hal->user_ctx, offset + sizeof(alloc_hdr),
                                    aligned_cipher_words, cipher_word_cnt);
    }

    /* Фаза 3: Атомарная фиксация статуса COMMITTED (0xFFFFFFFC) */
    burn_u32(ctx, offset, HYPR_TLV_STATE_COMMITTED);
}

hypr_err_t hypr_storage_mount(hypr_storage_ctx_t *ctx, const hypr_storage_hal_t *hal, const uint8_t mk[32]) {
    if (ctx == NULL || hal == NULL || mk == NULL) {
        return HYPR_ERR_INVALID_ARG;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->hal = hal;
    ctx->mk  = mk;
    ctx->active_write_page   = 0xFFFFFFFFUL;
    ctx->active_write_offset = HYPR_FLASH_PAGE_SIZE;

    /* Проход 1: Инициализация неразмеченных/сорванных страниц и построение индекса */
    for (uint32_t p = 0U; p < HYPR_TLV_TOTAL_PAGES; p++) {
        uint32_t base = page_base_addr(p);
        hypr_page_hdr_t phdr;
        hal->flash_read(hal->user_ctx, base, &phdr, sizeof(phdr));

        /* Если страница стерта без заголовка или оборвалась на ERASE_PENDING */
        if (phdr.magic != HYPR_PAGE_MAGIC || phdr.page_state == HYPR_PAGE_STATE_ERASE_PENDING) {
            if (!hal->pofwarn_is_active(hal->user_ctx)) {
                uint32_t next_erase = (phdr.magic == HYPR_PAGE_MAGIC) ? (phdr.erase_count + 1U) : 1U;
                hal->flash_erase_page(hal->user_ctx, p);
                format_page_header(ctx, p, HYPR_PAGE_STATE_EMPTY, next_erase);
            }
            continue;
        }

        if (phdr.page_state == HYPR_PAGE_STATE_EMPTY) {
            continue;
        }

        /* Сканирование записей внутри ACTIVE или COMPACTING страницы */
        uint32_t off = sizeof(hypr_page_hdr_t);
        bool page_has_torn_tail = false;

        while (off + sizeof(hypr_tlv_record_hdr_v2_t) <= HYPR_FLASH_PAGE_SIZE) {
            hypr_tlv_record_hdr_v2_t rhdr;
            hal->flash_read(hal->user_ctx, base + off, &rhdr, sizeof(rhdr));

            if (rhdr.state_flags == HYPR_TLV_STATE_EMPTY) {
                break; /* Чистый хвост страницы */
            }

            uint32_t rec_total_len = sizeof(rhdr) + align4(rhdr.payload_len);

            /* Проверка корректности границ при оборванной записи (Тест PL-03) */
            if (rhdr.payload_len > HYPR_MAX_PAYLOAD_LEN || (off + rec_total_len > HYPR_FLASH_PAGE_SIZE)) {
                ctx->page_dirty_bytes[p] += (uint16_t)(HYPR_FLASH_PAGE_SIZE - off);
                page_has_torn_tail = true;
                off = HYPR_FLASH_PAGE_SIZE;
                break;
            }

            if (rhdr.state_flags == HYPR_TLV_STATE_ALLOCATING) {
                /* Запись не была закоммичена до сбоя питания: помечаем как INVALIDATED */
                if (!hal->pofwarn_is_active(hal->user_ctx)) {
                    burn_u32(ctx, base + off, HYPR_TLV_STATE_INVALIDATED);
                }
                ctx->page_dirty_bytes[p] += (uint16_t)rec_total_len;
                off += rec_total_len;
                continue;
            }

            if (rhdr.state_flags == HYPR_TLV_STATE_INVALIDATED) {
                ctx->page_dirty_bytes[p] += (uint16_t)rec_total_len;
                off += rec_total_len;
                continue;
            }

            if (rhdr.state_flags == HYPR_TLV_STATE_COMMITTED && rhdr.record_id < HYPR_MAX_RECORDS) {
                uint16_t id = rhdr.record_id;
                if (ctx->index[id].flash_offset == 0U) {
                    ctx->index[id].flash_offset = base + off;
                    ctx->index[id].version      = rhdr.record_version;
                } else {
                    /* Разрешение дубликатов после сбоя питания при обновлении или GC (Тесты PL-04, PL-05) */
                    uint32_t old_addr = ctx->index[id].flash_offset;
                    uint32_t old_page = old_addr / HYPR_FLASH_PAGE_SIZE;
                    uint32_t old_ver  = ctx->index[id].version;

                    hypr_page_hdr_t old_phdr;
                    hal->flash_read(hal->user_ctx, page_base_addr(old_page), &old_phdr, sizeof(old_phdr));

                    bool keep_new = (rhdr.record_version > old_ver) ||
                                    (rhdr.record_version == old_ver &&
                                     phdr.page_state == HYPR_PAGE_STATE_ACTIVE &&
                                     old_phdr.page_state == HYPR_PAGE_STATE_COMPACTING);

                    if (keep_new) {
                        if (!hal->pofwarn_is_active(hal->user_ctx)) {
                            burn_u32(ctx, old_addr, HYPR_TLV_STATE_INVALIDATED);
                        }
                        ctx->page_dirty_bytes[old_page] += (uint16_t)rec_total_len;
                        ctx->index[id].flash_offset = base + off;
                        ctx->index[id].version      = rhdr.record_version;
                    } else {
                        if (!hal->pofwarn_is_active(hal->user_ctx)) {
                            burn_u32(ctx, base + off, HYPR_TLV_STATE_INVALIDATED);
                        }
                        ctx->page_dirty_bytes[p] += (uint16_t)rec_total_len;
                    }
                }
            }
            off += rec_total_len;
        }

        /* Выбор активной страницы для дозаписи */
        if (phdr.page_state == HYPR_PAGE_STATE_ACTIVE && !page_has_torn_tail &&
            (off + sizeof(hypr_tlv_record_hdr_v2_t) < HYPR_FLASH_PAGE_SIZE)) {
            ctx->active_write_page   = p;
            ctx->active_write_offset = off;
        }
    }

    /* Проход 2: Если при прошлом запуске прервался GC (осталась страница COMPACTING), завершаем его */
    for (uint32_t p = 0U; p < HYPR_TLV_TOTAL_PAGES; p++) {
        hypr_page_hdr_t phdr;
        hal->flash_read(hal->user_ctx, page_base_addr(p), &phdr, sizeof(phdr));
        if (phdr.magic == HYPR_PAGE_MAGIC && phdr.page_state == HYPR_PAGE_STATE_COMPACTING) {
            if (!hal->pofwarn_is_active(hal->user_ctx)) {
                (void)hypr_storage_gc(ctx);
            }
            break;
        }
    }

    return HYPR_OK;
}

hypr_err_t hypr_storage_read(hypr_storage_ctx_t *ctx, uint16_t record_id, uint16_t *type_out,
                             uint16_t *flags_out, uint8_t *plain_out, uint16_t max_len, uint16_t *actual_len) {
    if (ctx == NULL || record_id >= HYPR_MAX_RECORDS || plain_out == NULL) {
        return HYPR_ERR_INVALID_ARG;
    }

    uint32_t addr = ctx->index[record_id].flash_offset;
    if (addr == 0U) {
        return HYPR_ERR_NOT_FOUND;
    }

    hypr_tlv_record_hdr_v2_t rhdr;
    ctx->hal->flash_read(ctx->hal->user_ctx, addr, &rhdr, sizeof(rhdr));

    if (rhdr.state_flags != HYPR_TLV_STATE_COMMITTED || rhdr.payload_len > max_len ||
        rhdr.payload_len > HYPR_MAX_PAYLOAD_LEN) {
        return HYPR_ERR_FLASH_CORRUPTED;
    }

    uint8_t cipher_buf[HYPR_MAX_PAYLOAD_LEN];
    ctx->hal->flash_read(ctx->hal->user_ctx, addr + sizeof(rhdr), cipher_buf, rhdr.payload_len);

    uint8_t nonce[12];
    ctx->hal->derive_nonce(ctx->mk, rhdr.record_type, rhdr.record_id, rhdr.record_version, nonce);

    hypr_tlv_aad_t aad = {
        .record_type    = rhdr.record_type,
        .record_id      = rhdr.record_id,
        .record_version = rhdr.record_version,
        .payload_len    = rhdr.payload_len,
        .flags          = rhdr.flags
    };

    bool ok = ctx->hal->aead_decrypt(ctx->mk, nonce, &aad, sizeof(aad),
                                     cipher_buf, plain_out, rhdr.payload_len, rhdr.poly1305_tag);
    secure_zero(nonce, sizeof(nonce));
    secure_zero(cipher_buf, sizeof(cipher_buf));

    if (!ok) {
        secure_zero(plain_out, max_len);
        return HYPR_ERR_AUTH_FAILED;
    }

    if (type_out != NULL)  *type_out  = rhdr.record_type;
    if (flags_out != NULL) *flags_out = rhdr.flags;
    if (actual_len != NULL) *actual_len = rhdr.payload_len;

    return HYPR_OK;
}

/* Выделение места в журнале с учетом резерва GC */
static hypr_err_t allocate_space(hypr_storage_ctx_t *ctx, uint32_t total_rec_bytes, uint32_t *addr_out) {
    if (ctx->active_write_page != 0xFFFFFFFFUL &&
        (ctx->active_write_offset + total_rec_bytes <= HYPR_FLASH_PAGE_SIZE)) {
        *addr_out = page_base_addr(ctx->active_write_page) + ctx->active_write_offset;
        ctx->active_write_offset += total_rec_bytes;
        return HYPR_OK;
    }

    uint32_t next_page = 0xFFFFFFFFUL;
    uint32_t empty_cnt = 0U;

    /* Если свободных страниц осталось <= HYPR_GC_RESERVE_PAGES, сначала запускаем GC */
    if (!find_best_empty_page(ctx, &next_page, &empty_cnt) || empty_cnt <= HYPR_GC_RESERVE_PAGES) {
        hypr_err_t gc_err = hypr_storage_gc(ctx);
        if (gc_err != HYPR_OK) {
            return gc_err;
        }
        if (!find_best_empty_page(ctx, &next_page, &empty_cnt) || empty_cnt <= HYPR_GC_RESERVE_PAGES) {
            return HYPR_ERR_STORAGE_FULL;
        }
    }

    /* Активация пустой страницы (переход бита EMPTY -> ACTIVE без стирания) */
    burn_u32(ctx, page_base_addr(next_page) + offsetof(hypr_page_hdr_t, page_state), HYPR_PAGE_STATE_ACTIVE);
    ctx->active_write_page   = next_page;
    ctx->active_write_offset = sizeof(hypr_page_hdr_t) + total_rec_bytes;
    *addr_out = page_base_addr(next_page) + sizeof(hypr_page_hdr_t);

    return HYPR_OK;
}

hypr_err_t hypr_storage_write(hypr_storage_ctx_t *ctx, uint16_t record_id, uint16_t record_type,
                              uint16_t flags, const uint8_t *plain, uint16_t payload_len) {
    if (ctx == NULL || record_id >= HYPR_MAX_RECORDS || plain == NULL || payload_len > HYPR_MAX_PAYLOAD_LEN) {
        return HYPR_ERR_INVALID_ARG;
    }

    /* Проверка аппаратного компаратора питания до начала модификации Flash */
    if (ctx->hal->pofwarn_is_active(ctx->hal->user_ctx)) {
        return HYPR_ERR_LOW_POWER;
    }

    uint32_t aligned_len   = align4(payload_len);
    uint32_t total_rec_len = sizeof(hypr_tlv_record_hdr_v2_t) + aligned_len;
    uint32_t target_addr   = 0U;

    hypr_err_t err = allocate_space(ctx, total_rec_len, &target_addr);
    if (err != HYPR_OK) {
        return err;
    }

    uint32_t old_addr = ctx->index[record_id].flash_offset;
    uint32_t new_ver  = (old_addr != 0U) ? (ctx->index[record_id].version + 1U) : 1U;

    uint8_t nonce[12];
    ctx->hal->derive_nonce(ctx->mk, record_type, record_id, new_ver, nonce);

    hypr_tlv_aad_t aad = {
        .record_type    = record_type,
        .record_id      = record_id,
        .record_version = new_ver,
        .payload_len    = payload_len,
        .flags          = flags
    };

    uint32_t cipher_words[HYPR_MAX_PAYLOAD_LEN / 4U];
    memset(cipher_words, 0xFF, aligned_len); /* Паддинг единицами (0xFF не прожигает Flash) */

    hypr_tlv_record_hdr_v2_t new_hdr = {
        .state_flags    = HYPR_TLV_STATE_ALLOCATING,
        .record_type    = record_type,
        .record_id      = record_id,
        .record_version = new_ver,
        .payload_len    = payload_len,
        .flags          = flags
    };

    ctx->hal->aead_encrypt(ctx->mk, nonce, &aad, sizeof(aad),
                           plain, (uint8_t *)cipher_words, payload_len, new_hdr.poly1305_tag);
    secure_zero(nonce, sizeof(nonce));

    /* Запись новой версии: ALLOCATING -> Payload -> COMMITTED */
    write_record_at(ctx, target_addr, &new_hdr, cipher_words, aligned_len / 4U);

    /* Только после коммита новой версии инвалидируем старую (Тест PL-04) */
    if (old_addr != 0U) {
        burn_u32(ctx, old_addr, HYPR_TLV_STATE_INVALIDATED);
        uint32_t old_page = old_addr / HYPR_FLASH_PAGE_SIZE;
        hypr_tlv_record_hdr_v2_t old_hdr;
        ctx->hal->flash_read(ctx->hal->user_ctx, old_addr, &old_hdr, sizeof(old_hdr));
        ctx->page_dirty_bytes[old_page] += (uint16_t)(sizeof(old_hdr) + align4(old_hdr.payload_len));
    }

    ctx->index[record_id].flash_offset = target_addr;
    ctx->index[record_id].version      = new_ver;

    return HYPR_OK;
}

hypr_err_t hypr_storage_delete(hypr_storage_ctx_t *ctx, uint16_t record_id) {
    if (ctx == NULL || record_id >= HYPR_MAX_RECORDS) {
        return HYPR_ERR_INVALID_ARG;
    }
    if (ctx->hal->pofwarn_is_active(ctx->hal->user_ctx)) {
        return HYPR_ERR_LOW_POWER;
    }

    uint32_t addr = ctx->index[record_id].flash_offset;
    if (addr == 0U) {
        return HYPR_ERR_NOT_FOUND;
    }

    hypr_tlv_record_hdr_v2_t hdr;
    ctx->hal->flash_read(ctx->hal->user_ctx, addr, &hdr, sizeof(hdr));
    burn_u32(ctx, addr, HYPR_TLV_STATE_INVALIDATED);

    uint32_t page = addr / HYPR_FLASH_PAGE_SIZE;
    ctx->page_dirty_bytes[page] += (uint16_t)(sizeof(hdr) + align4(hdr.payload_len));
    ctx->index[record_id].flash_offset = 0U;

    return HYPR_OK;
}

hypr_err_t hypr_storage_gc(hypr_storage_ctx_t *ctx) {
    if (ctx == NULL) {
        return HYPR_ERR_INVALID_ARG;
    }
    if (ctx->hal->pofwarn_is_active(ctx->hal->user_ctx)) {
        return HYPR_ERR_LOW_POWER;
    }

    /* 1. Поиск прерванной COMPACTING страницы или выбор ACTIVE страницы с максимумом мусора */
    uint32_t victim_page = 0xFFFFFFFFUL;
    uint16_t max_dirty   = 0U;

    for (uint32_t p = 0U; p < HYPR_TLV_TOTAL_PAGES; p++) {
        hypr_page_hdr_t phdr;
        ctx->hal->flash_read(ctx->hal->user_ctx, page_base_addr(p), &phdr, sizeof(phdr));
        if (phdr.magic == HYPR_PAGE_MAGIC && phdr.page_state == HYPR_PAGE_STATE_COMPACTING) {
            victim_page = p;
            break;
        }
        if (p != ctx->active_write_page && phdr.magic == HYPR_PAGE_MAGIC &&
            phdr.page_state == HYPR_PAGE_STATE_ACTIVE && ctx->page_dirty_bytes[p] > max_dirty) {
            max_dirty   = ctx->page_dirty_bytes[p];
            victim_page = p;
        }
    }

    if (victim_page == 0xFFFFFFFFUL) {
        return HYPR_ERR_STORAGE_FULL;
    }

    /* 2. Выделение чистой резервной страницы */
    uint32_t dst_page = 0xFFFFFFFFUL;
    if (!find_best_empty_page(ctx, &dst_page, NULL)) {
        return HYPR_ERR_STORAGE_FULL;
    }

    /* 3. Перевод целевой страницы в ACTIVE, а старой — в COMPACTING */
    burn_u32(ctx, page_base_addr(dst_page) + offsetof(hypr_page_hdr_t, page_state), HYPR_PAGE_STATE_ACTIVE);
    burn_u32(ctx, page_base_addr(victim_page) + offsetof(hypr_page_hdr_t, page_state), HYPR_PAGE_STATE_COMPACTING);

    uint32_t dst_off = sizeof(hypr_page_hdr_t);

    /* 4. Миграция всех живых записей из victim_page в dst_page (Copy-Before-Erase, Тест PL-05) */
    for (uint16_t id = 0U; id < HYPR_MAX_RECORDS; id++) {
        uint32_t rec_addr = ctx->index[id].flash_offset;
        if (rec_addr == 0U || (rec_addr / HYPR_FLASH_PAGE_SIZE) != victim_page) {
            continue;
        }

        if (ctx->hal->pofwarn_is_active(ctx->hal->user_ctx)) {
            return HYPR_ERR_LOW_POWER;
        }

        hypr_tlv_record_hdr_v2_t rhdr;
        ctx->hal->flash_read(ctx->hal->user_ctx, rec_addr, &rhdr, sizeof(rhdr));

        uint32_t aligned_len = align4(rhdr.payload_len);
        uint32_t cipher_words[HYPR_MAX_PAYLOAD_LEN / 4U];
        memset(cipher_words, 0xFF, aligned_len);
        ctx->hal->flash_read(ctx->hal->user_ctx, rec_addr + sizeof(rhdr), cipher_words, rhdr.payload_len);

        uint32_t new_addr = page_base_addr(dst_page) + dst_off;
        write_record_at(ctx, new_addr, &rhdr, cipher_words, aligned_len / 4U);

        /* Инвалидация старой копии только после коммита новой */
        burn_u32(ctx, rec_addr, HYPR_TLV_STATE_INVALIDATED);
        ctx->index[id].flash_offset = new_addr;
        dst_off += sizeof(rhdr) + aligned_len;
    }

    /* 5. Стирание освобожденной страницы и возврат её в пул резерва */
    if (ctx->hal->pofwarn_is_active(ctx->hal->user_ctx)) {
        return HYPR_ERR_LOW_POWER;
    }

    hypr_page_hdr_t vhdr;
    ctx->hal->flash_read(ctx->hal->user_ctx, page_base_addr(victim_page), &vhdr, sizeof(vhdr));
    burn_u32(ctx, page_base_addr(victim_page) + offsetof(hypr_page_hdr_t, page_state), HYPR_PAGE_STATE_ERASE_PENDING);

    ctx->hal->flash_erase_page(ctx->hal->user_ctx, victim_page);
    format_page_header(ctx, victim_page, HYPR_PAGE_STATE_EMPTY, vhdr.erase_count + 1U);
    ctx->page_dirty_bytes[victim_page] = 0U;

    /* Если в новой странице осталось место, делаем её текущей активной страницей записи */
    if (dst_off + sizeof(hypr_tlv_record_hdr_v2_t) < HYPR_FLASH_PAGE_SIZE) {
        ctx->active_write_page   = dst_page;
        ctx->active_write_offset = dst_off;
    }

    return HYPR_OK;
}

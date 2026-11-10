#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief RFC 8439 ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)
 *
 * @param key       32-byte symmetric key
 * @param nonce     12-byte nonce
 * @param aad       Associated Authenticated Data (can be NULL if aad_len == 0)
 * @param aad_len   Length of AAD in bytes
 * @param plain     Plaintext input buffer
 * @param cipher    Ciphertext output buffer (same length as plain)
 * @param len       Length of plaintext/ciphertext in bytes
 * @param tag_out   16-byte output authentication tag
 */
void chacha20_poly1305_encrypt(const uint8_t key[32],
                               const uint8_t nonce[12],
                               const void *aad, size_t aad_len,
                               const uint8_t *plain,
                               uint8_t *cipher, size_t len,
                               uint8_t tag_out[16]);

/**
 * @brief RFC 8439 ChaCha20-Poly1305 AEAD Decryption and Authentication
 *
 * @param key       32-byte symmetric key
 * @param nonce     12-byte nonce
 * @param aad       Associated Authenticated Data (can be NULL if aad_len == 0)
 * @param aad_len   Length of AAD in bytes
 * @param cipher    Ciphertext input buffer
 * @param plain     Plaintext output buffer (same length as cipher)
 * @param len       Length of ciphertext/plaintext in bytes
 * @param tag       16-byte expected authentication tag
 * @return true     Authentication succeeded, plaintext is valid
 * @return false    Authentication failed, plaintext zeroed
 */
bool chacha20_poly1305_decrypt(const uint8_t key[32],
                               const uint8_t nonce[12],
                               const void *aad, size_t aad_len,
                               const uint8_t *cipher,
                               uint8_t *plain, size_t len,
                               const uint8_t tag[16]);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20POLY1305_H */

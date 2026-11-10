#ifndef ED25519_H
#define ED25519_H

#include <stdint.h>
#include <stddef.h>

#define ED25519_SEED_BYTES       32
#define ED25519_PUBLIC_KEY_BYTES 32
#define ED25519_PRIVATE_KEY_BYTES 64
#define ED25519_SIGNATURE_BYTES  64

void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);

void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                  const uint8_t pk[32], const uint8_t sk[64]);

int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                   const uint8_t pk[32]);

#endif /* ED25519_H */

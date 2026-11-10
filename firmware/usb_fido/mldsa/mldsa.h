#ifndef MLDSA_H
#define MLDSA_H

#include <stdint.h>
#include <stddef.h>

#define MLDSA44_PUBLIC_KEY_SIZE  1312
#define MLDSA44_SECRET_KEY_SIZE  2560
#define MLDSA44_SIGNATURE_SIZE   2420
#define MLDSA44_SEED_SIZE        32

#define MLDSA65_PUBLIC_KEY_SIZE  1952
#define MLDSA65_SECRET_KEY_SIZE  4032
#define MLDSA65_SIGNATURE_SIZE   3309
#define MLDSA65_SEED_SIZE        32

#define MLDSA87_PUBLIC_KEY_SIZE  2592
#define MLDSA87_SECRET_KEY_SIZE  4896
#define MLDSA87_SIGNATURE_SIZE   4627
#define MLDSA87_SEED_SIZE        32

/* Key generation from 32-byte seed */
int mldsa44_keygen(const uint8_t seed[32], uint8_t *pk, uint8_t *sk);
int mldsa65_keygen(const uint8_t seed[32], uint8_t *pk, uint8_t *sk);
int mldsa87_keygen(const uint8_t seed[32], uint8_t *pk, uint8_t *sk);

/* Signing using 32-byte seed directly (saves RAM & flash) */
int mldsa44_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t msglen, const uint8_t rnd[32], uint8_t *sig);
int mldsa65_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t msglen, const uint8_t rnd[32], uint8_t *sig);
int mldsa87_sign_seed(const uint8_t seed[32], const uint8_t *msg, size_t msglen, const uint8_t rnd[32], uint8_t *sig);

/* Signing using expanded private key */
int mldsa44_sign(const uint8_t *sk, const uint8_t *msg, size_t msglen, const uint8_t rnd[32], uint8_t *sig);
int mldsa65_sign(const uint8_t *sk, const uint8_t *msg, size_t msglen, const uint8_t rnd[32], uint8_t *sig);
int mldsa87_sign(const uint8_t *sk, const uint8_t *msg, size_t msglen, const uint8_t rnd[32], uint8_t *sig);

#endif /* MLDSA_H */

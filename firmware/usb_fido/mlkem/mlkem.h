#ifndef MLKEM_H
#define MLKEM_H

#include <stdint.h>
#include <stddef.h>

/* ML-KEM-768 parameters (FIPS 203) */
#define MLKEM768_K 3
#define MLKEM768_PUBLICKEYBYTES  1184
#define MLKEM768_SECRETKEYBYTES  2400
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM768_SSBYTES         32

/* ML-KEM-1024 parameters (FIPS 203) */
#define MLKEM1024_K 4
#define MLKEM1024_PUBLICKEYBYTES  1568
#define MLKEM1024_SECRETKEYBYTES  3168
#define MLKEM1024_CIPHERTEXTBYTES 1568
#define MLKEM1024_SSBYTES         32

/* ML-KEM-768 API */
int mlkem768_keygen_internal(uint8_t pk[MLKEM768_PUBLICKEYBYTES],
                             uint8_t sk[MLKEM768_SECRETKEYBYTES],
                             const uint8_t d[32],
                             const uint8_t z[32]);

int mlkem768_encaps_internal(uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                             uint8_t ss[32],
                             const uint8_t pk[MLKEM768_PUBLICKEYBYTES],
                             const uint8_t m[32]);

int mlkem768_decaps_internal(uint8_t ss[32],
                             const uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                             const uint8_t sk[MLKEM768_SECRETKEYBYTES]);

/* ML-KEM-1024 API */
int mlkem1024_keygen_internal(uint8_t pk[MLKEM1024_PUBLICKEYBYTES],
                              uint8_t sk[MLKEM1024_SECRETKEYBYTES],
                              const uint8_t d[32],
                              const uint8_t z[32]);

int mlkem1024_encaps_internal(uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                              uint8_t ss[32],
                              const uint8_t pk[MLKEM1024_PUBLICKEYBYTES],
                              const uint8_t m[32]);

int mlkem1024_decaps_internal(uint8_t ss[32],
                              const uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                              const uint8_t sk[MLKEM1024_SECRETKEYBYTES]);

#endif /* MLKEM_H */

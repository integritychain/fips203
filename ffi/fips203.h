#ifndef __FIPS203_H__
#define __FIPS203_H__
/*
  Minimalist ML-KEM C interface
  Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>

  Memory allocation and tracking are entirely the job of the caller.

  The shared object backing this interface has no internal state
  between calls, and should be completely reentrant.

  These functions return 0 (ML_KEM_OK) on success, or a more specific
  non-zero octet on error.
*/
#include <stdint.h>

typedef uint8_t ml_kem_err;

const ml_kem_err ML_KEM_OK = 0;
const ml_kem_err ML_KEM_NULL_PTR_ERROR = 1;
const ml_kem_err ML_KEM_SERIALIZATION_ERROR = 2;
const ml_kem_err ML_KEM_DESERIALIZATION_ERROR = 3;
const ml_kem_err ML_KEM_KEYGEN_ERROR = 4;
const ml_kem_err ML_KEM_ENCAPSULATION_ERROR = 5;
const ml_kem_err ML_KEM_DECAPSULATION_ERROR = 6;


typedef struct ml_kem_shared_secret {
  uint8_t data[32];
} ml_kem_shared_secret;


typedef struct ml_kem_512_encaps_key {
  uint8_t data[800];
} ml_kem_512_encaps_key;

typedef struct ml_kem_512_decaps_key {
  uint8_t data[1632];
} ml_kem_512_decaps_key;

typedef struct ml_kem_512_ciphertext {
  uint8_t data[768];
} ml_kem_512_ciphertext;

typedef struct ml_kem_768_encaps_key {
  uint8_t data[1184];
} ml_kem_768_encaps_key;

typedef struct ml_kem_768_decaps_key {
  uint8_t data[2400];
} ml_kem_768_decaps_key;

typedef struct ml_kem_768_ciphertext {
  uint8_t data[1088];
} ml_kem_768_ciphertext;

typedef struct ml_kem_1024_encaps_key {
  uint8_t data[1568];
} ml_kem_1024_encaps_key;

typedef struct ml_kem_1024_decaps_key {
  uint8_t data[3168];
} ml_kem_1024_decaps_key;

typedef struct ml_kem_1024_ciphertext {
  uint8_t data[1568];
} ml_kem_1024_ciphertext;

#ifdef  __cplusplus
extern "C" {
#endif

ml_kem_err ml_kem_512_keygen(ml_kem_512_encaps_key *encaps_out,
                             ml_kem_512_decaps_key *decaps_out);

ml_kem_err ml_kem_512_encaps(const ml_kem_512_encaps_key *encaps,
                             ml_kem_512_ciphertext *ciphertext_out,
                             ml_kem_shared_secret *shared_secret_out);

ml_kem_err ml_kem_512_decaps(const ml_kem_512_decaps_key *decaps,
                             const ml_kem_512_ciphertext *ciphertext,
                             ml_kem_shared_secret *shared_secret_out);

ml_kem_err ml_kem_768_keygen(ml_kem_768_encaps_key *encaps_out,
                             ml_kem_768_decaps_key *decaps_out);

ml_kem_err ml_kem_768_encaps(const ml_kem_768_encaps_key *encaps,
                             ml_kem_768_ciphertext *ciphertext_out,
                             ml_kem_shared_secret *shared_secret_out);

ml_kem_err ml_kem_768_decaps(const ml_kem_768_decaps_key *decaps,
                             const ml_kem_768_ciphertext *ciphertext,
                             ml_kem_shared_secret *shared_secret_out);

ml_kem_err ml_kem_1024_keygen(ml_kem_1024_encaps_key *encaps_out,
                              ml_kem_1024_decaps_key *decaps_out);

ml_kem_err ml_kem_1024_encaps(const ml_kem_1024_encaps_key *encaps,
                              ml_kem_1024_ciphertext *ciphertext_out,
                              ml_kem_shared_secret *shared_secret_out);

ml_kem_err ml_kem_1024_decaps(const ml_kem_1024_decaps_key *decaps,
                              const ml_kem_1024_ciphertext *ciphertext,
                              ml_kem_shared_secret *shared_secret_out);

#ifdef  __cplusplus
} // extern "C"
#endif
#endif // __FIPS203_H__

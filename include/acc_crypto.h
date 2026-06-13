#ifndef ACC_CRYPTO_H
#define ACC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define MASC256_VERSION 2
#define MASC256_NONCE_SIZE 16
#define MASC256_TAG_SIZE 32
#define MASC256_OVERHEAD (MASC256_NONCE_SIZE + MASC256_TAG_SIZE)

#define MASC256_OK 0
#define MASC256_ERR_INVALID -1
#define MASC256_ERR_AUTH -2
#define MASC256_ERR_RANDOM -3
#define MASC256_ERR_BUFFER -4

int masc256_random_nonce(uint8_t nonce[MASC256_NONCE_SIZE]);

int masc256_encrypt(uint8_t *data,
                    size_t len,
                    const uint8_t *key,
                    size_t klen,
                    const uint8_t nonce[MASC256_NONCE_SIZE],
                    const uint8_t *aad,
                    size_t aad_len,
                    uint8_t tag[MASC256_TAG_SIZE]);

int masc256_decrypt(uint8_t *data,
                    size_t len,
                    const uint8_t *key,
                    size_t klen,
                    const uint8_t nonce[MASC256_NONCE_SIZE],
                    const uint8_t *aad,
                    size_t aad_len,
                    const uint8_t tag[MASC256_TAG_SIZE]);

int masc256_seal(uint8_t *out,
                 size_t out_cap,
                 size_t *out_len,
                 const uint8_t *plaintext,
                 size_t plaintext_len,
                 const uint8_t *key,
                 size_t klen,
                 const uint8_t *aad,
                 size_t aad_len);

int masc256_open(uint8_t *out,
                 size_t out_cap,
                 size_t *out_len,
                 const uint8_t *sealed,
                 size_t sealed_len,
                 const uint8_t *key,
                 size_t klen,
                 const uint8_t *aad,
                 size_t aad_len);

#endif

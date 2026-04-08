#ifndef ACC_CRYPTO_H
#define ACC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
} ACC;

uint64_t rotl(uint64_t x, int r);
uint64_t rotr(uint64_t x, int r);

void stack_mix(ACC *acc, uint64_t v);
void heap_mix(ACC *acc, uint64_t seed);
void accumulator_round(ACC *acc);

void init_acc(ACC *acc, const uint8_t *key, size_t len);

void encrypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen);
void decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen);

#endif
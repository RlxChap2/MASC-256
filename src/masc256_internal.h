#ifndef MASC256_INTERNAL_H
#define MASC256_INTERNAL_H

#include "acc_crypto.h"

#include <stdint.h>
#include <stddef.h>

#define MASC256_KEY_SIZE 32
#define MASC256_HEAP_WORDS 64

typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
} ACC;

uint64_t rotl(uint64_t x, int r);
uint64_t rotr(uint64_t x, int r);

void stack_mix(ACC *acc, uint64_t v);
void heap_mix_scratch(ACC *acc, uint64_t seed, uint64_t heap[MASC256_HEAP_WORDS]);
void accumulator_round(ACC *acc);

#endif

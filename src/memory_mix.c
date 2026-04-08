#include <stdlib.h>
#include "acc_crypto.h"

uint64_t rotl(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

uint64_t rotr(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}

void stack_mix(ACC *acc, uint64_t v) {
    uint64_t stack_buf[8];

    for(int i = 0 ; i < 8; i++) {
        stack_buf[i] = rotl(v ^ (acc->a + i), i + 1);
        acc->a ^= stack_buf[i];
        acc->b += rotl(stack_buf[i], (i + 3) % 64);
        acc->c ^= acc->b + stack_buf[i];
        acc->d = rotl(acc->d ^ acc->c, 7);
    }
}

void heap_mix(ACC *acc, uint64_t seed) {
    uint64_t *heap = malloc(64 * sizeof(uint64_t));

    for(int i = 0; i < 64; i++) {
        heap[i] = rotl(seed ^ (acc->a + i), (i % 31) + 1);
        acc->a += heap[i];
        acc->b ^= rotl(heap[i], (i % 17) + 3);
        acc->c += acc->b ^ heap[i];
        acc->d ^= rotl(acc->c, (i % 13) + 5);
    }

    free(heap);
}

void accumulator_round(ACC *acc) {
    acc->a = rotl(acc->a ^ acc->d, 17);
    acc->b = rotl(acc->b + acc->a, 23);
    acc->c = rotl(acc->c ^ acc->b, 31);
    acc->d = rotl(acc->d + acc->c, 47);
}
#include "acc_crypto.h"

void init_acc(ACC *acc, const uint8_t *key, size_t len) {
    acc->a = 0x9e3779b97f4a7c15ULL;
    acc->b = 0x6a09e667f3bcc909ULL;
    acc->c = 0xbb67ae8584caa73bULL;
    acc->d = 0x3c6ef372fe94f82bULL;

    for(size_t i = 0; i < len; i++) {
        acc->a ^= key[i] + rotl(acc->d, i%63);
        stack_mix(acc, key[i]);
        heap_mix(acc, key[i] ^ acc->a);
        accumulator_round(acc);
    }
}

void encrypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen) {
    ACC acc;
    init_acc(&acc, key, klen);

    for(size_t i = 0; i < len; i++) {
        uint64_t mix = acc.a ^ acc.b ^ acc.c ^ acc.d;
        data[i] ^= (uint8_t)(mix & 0xFF);

        stack_mix(&acc, data[i]);
        heap_mix(&acc, mix ^ data[i]);
        accumulator_round(&acc);
    }
}

void decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen) {
    ACC acc;
    init_acc(&acc, key, klen);

    for(size_t i = 0; i < len; i++) {
        uint64_t mix = acc.a ^ acc.b ^ acc.c ^ acc.d;
        uint8_t cipher = data[i];
        data[i] ^= (uint8_t)(mix & 0xFF);

        stack_mix(&acc, cipher);
        heap_mix(&acc, mix ^ cipher);
        accumulator_round(&acc);
    }
}
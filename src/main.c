#include <stdio.h>
#include <string.h>
#include "acc_crypto.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s", label);
    for(size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {

    uint8_t key[] = "UltraEncryptedKey";
    uint8_t aad[] = "MASC-256 demo metadata";
    uint8_t plaintext[] = "Advanced Memory Encryption System";
    uint8_t sealed[(sizeof(plaintext) - 1U) + MASC256_OVERHEAD];
    uint8_t opened[sizeof(plaintext)];
    uint8_t tampered[sizeof(sealed)];
    size_t sealed_len = 0U;
    size_t opened_len = 0U;
    int rc;

    size_t len = strlen((char*)plaintext);

    rc = masc256_seal(sealed,
                      sizeof(sealed),
                      &sealed_len,
                      plaintext,
                      len,
                      key,
                      strlen((char*)key),
                      aad,
                      strlen((char*)aad));
    if(rc != MASC256_OK) {
        printf("Seal failed: %d\n", rc);
        return 1;
    }

    print_hex("Sealed:   ", sealed, sealed_len);

    memcpy(tampered, sealed, sealed_len);
    tampered[MASC256_NONCE_SIZE] ^= 0x01U;
    rc = masc256_open(opened,
                      sizeof(opened),
                      &opened_len,
                      tampered,
                      sealed_len,
                      key,
                      strlen((char*)key),
                      aad,
                      strlen((char*)aad));
    printf("Tamper test: %s\n", rc == MASC256_ERR_AUTH ? "rejected" : "unexpected result");

    rc = masc256_open(opened,
                      sizeof(opened),
                      &opened_len,
                      sealed,
                      sealed_len,
                      key,
                      strlen((char*)key),
                      aad,
                      strlen((char*)aad));
    if(rc != MASC256_OK) {
        printf("Open failed: %d\n", rc);
        return 1;
    }
    opened[opened_len] = '\0';

    printf("Decrypted: %s\n", opened);

    return 0;
}

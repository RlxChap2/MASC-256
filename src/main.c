#include <stdio.h>
#include <string.h>
#include "acc_crypto.h"

int main() {

    uint8_t key[] = "UltraEncryptedKey";
    uint8_t data[] = "Advanced Memory Encryption System";

    size_t len = strlen((char*)data);

    encrypt(data, len, key, strlen((char*)key));

    printf("Encrypted: ");
    for(size_t i = 0; i < len; i++)
        printf("%02X", data[i]);

    printf("\n");

    decrypt(data, len, key, strlen((char*)key));

    printf("Decrypted: %s\n", data);

    return 0;
}
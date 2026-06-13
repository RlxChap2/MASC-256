#include <stdio.h>
#include <string.h>

#include "acc_crypto.h"

static int expect(int condition, const char *message) {
    if(!condition) {
        printf("FAIL: %s\n", message);
        return 1;
    }
    return 0;
}

static int expect_bytes(const uint8_t *actual,
                        const uint8_t *expected,
                        size_t len,
                        const char *message) {
    return expect(memcmp(actual, expected, len) == 0, message);
}

int main(void) {
    uint8_t key[] = "test master key";
    uint8_t aad[] = "test aad";
    uint8_t wrong_aad[] = "wrong aad";
    uint8_t nonce[MASC256_NONCE_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t wrong_nonce[MASC256_NONCE_SIZE] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t expected_ciphertext[] = {
        0xcc, 0xa0, 0x5f, 0xcf, 0xd1, 0x38, 0xc6, 0x5d,
        0x69, 0xd3, 0x19, 0xe7, 0x84, 0xed, 0x17, 0xc4,
        0x83, 0x1a, 0x4a, 0x75, 0xd7, 0x63, 0x63, 0x37,
        0xfe, 0xec, 0x19, 0x9e, 0x9a, 0x3f, 0x2f, 0x76,
        0x57, 0xab, 0x47, 0xbb, 0x81, 0xbd
    };
    uint8_t expected_tag[MASC256_TAG_SIZE] = {
        0x57, 0x9d, 0x83, 0x35, 0x14, 0xd4, 0x14, 0x9d,
        0x24, 0xa1, 0xc9, 0xa6, 0x9d, 0x6e, 0x08, 0x59,
        0xd1, 0x2b, 0x83, 0x4f, 0x85, 0xbb, 0x6f, 0x79,
        0x5d, 0x6c, 0x67, 0xa1, 0x23, 0x7d, 0xc3, 0x95
    };
    uint8_t original[] = "MASC-256 authenticated encryption test";
    uint8_t data[sizeof(original)];
    uint8_t sealed[(sizeof(original) - 1U) + MASC256_OVERHEAD];
    uint8_t tampered[sizeof(sealed)];
    uint8_t opened[sizeof(original)];
    uint8_t tag[MASC256_TAG_SIZE];
    size_t len = strlen((char *)original);
    size_t sealed_len = 0U;
    size_t opened_len = 0U;
    int failures = 0;
    int rc;

    memcpy(data, original, sizeof(original));

    rc = masc256_encrypt(data,
                         len,
                         key,
                         strlen((char *)key),
                         nonce,
                         aad,
                         strlen((char *)aad),
                         tag);
    failures += expect(rc == MASC256_OK, "deterministic vector encryption succeeds");
    failures += expect(sizeof(expected_ciphertext) == len, "test vector length matches plaintext");
    failures += expect_bytes(data, expected_ciphertext, len, "ciphertext matches test vector");
    failures += expect_bytes(tag, expected_tag, MASC256_TAG_SIZE, "tag matches test vector");

    memcpy(tampered, data, len);
    tampered[1] ^= 0x40U;
    rc = masc256_decrypt(tampered,
                         len,
                         key,
                         strlen((char *)key),
                         nonce,
                         aad,
                         strlen((char *)aad),
                         tag);
    failures += expect(rc == MASC256_ERR_AUTH, "tampered ciphertext is rejected");

    memcpy(tampered, data, len);
    rc = masc256_decrypt(tampered,
                         len,
                         key,
                         strlen((char *)key),
                         nonce,
                         wrong_aad,
                         strlen((char *)wrong_aad),
                         tag);
    failures += expect(rc == MASC256_ERR_AUTH, "wrong AAD is rejected");

    memcpy(tampered, data, len);
    rc = masc256_decrypt(tampered,
                         len,
                         key,
                         strlen((char *)key),
                         wrong_nonce,
                         aad,
                         strlen((char *)aad),
                         tag);
    failures += expect(rc == MASC256_ERR_AUTH, "wrong nonce is rejected");

    rc = masc256_decrypt(data,
                         len,
                         key,
                         strlen((char *)key),
                         nonce,
                         aad,
                         strlen((char *)aad),
                         tag);
    failures += expect(rc == MASC256_OK, "valid ciphertext decrypts");
    failures += expect_bytes(data, original, len, "plaintext is restored");

    rc = masc256_seal(NULL,
                      0U,
                      &sealed_len,
                      original,
                      len,
                      key,
                      strlen((char *)key),
                      aad,
                      strlen((char *)aad));
    failures += expect(rc == MASC256_ERR_BUFFER, "seal reports required output size");
    failures += expect(sealed_len == len + MASC256_OVERHEAD, "sealed size includes nonce and tag");

    rc = masc256_seal(sealed,
                      sizeof(sealed),
                      &sealed_len,
                      original,
                      len,
                      key,
                      strlen((char *)key),
                      aad,
                      strlen((char *)aad));
    failures += expect(rc == MASC256_OK, "seal succeeds");
    failures += expect(sealed_len == len + MASC256_OVERHEAD, "seal returns exact output size");

    memcpy(tampered, sealed, sealed_len);
    tampered[MASC256_NONCE_SIZE] ^= 0x01U;
    rc = masc256_open(opened,
                      sizeof(opened),
                      &opened_len,
                      tampered,
                      sealed_len,
                      key,
                      strlen((char *)key),
                      aad,
                      strlen((char *)aad));
    failures += expect(rc == MASC256_ERR_AUTH, "sealed tamper is rejected");

    rc = masc256_open(sealed,
                      sizeof(sealed),
                      &opened_len,
                      sealed,
                      sealed_len,
                      key,
                      strlen((char *)key),
                      aad,
                      strlen((char *)aad));
    failures += expect(rc == MASC256_OK, "in-place open succeeds");
    failures += expect(opened_len == len, "open returns plaintext length");
    failures += expect_bytes(sealed, original, len, "in-place open restores plaintext");

    if(failures == 0) {
        printf("PASS\n");
    }

    return failures == 0 ? 0 : 1;
}

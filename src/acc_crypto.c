#include "masc256_internal.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buffer_len;
} SHA256_CTX;

typedef struct {
    SHA256_CTX inner;
    SHA256_CTX outer;
} HMAC_SHA256_CTX;

static const uint32_t SHA256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while(len-- != 0U) {
        *p++ = 0U;
    }
}

static uint32_t rotr32(uint32_t x, uint32_t r) {
    return (x >> r) | (x << (32U - r));
}

static uint32_t load32_be(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) |
           (uint32_t)src[3];
}

static void store32_be(uint8_t dst[4], uint32_t value) {
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static uint64_t load64_le_partial(const uint8_t *src, size_t len) {
    uint64_t value = 0U;
    for(size_t i = 0; i < len; i++) {
        value |= ((uint64_t)src[i]) << (8U * i);
    }
    return value;
}

static void store64_le(uint8_t dst[8], uint64_t value) {
    for(size_t i = 0; i < 8U; i++) {
        dst[i] = (uint8_t)(value >> (8U * i));
    }
}

static uint64_t avalanche64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    for(size_t i = 0; i < 16U; i++) {
        w[i] = load32_be(block + (i * 4U));
    }

    for(size_t i = 16U; i < 64U; i++) {
        uint32_t s0 = rotr32(w[i - 15U], 7U) ^ rotr32(w[i - 15U], 18U) ^ (w[i - 15U] >> 3);
        uint32_t s1 = rotr32(w[i - 2U], 17U) ^ rotr32(w[i - 2U], 19U) ^ (w[i - 2U] >> 10);
        w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for(size_t i = 0; i < 64U; i++) {
        uint32_t s1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + SHA256_K[i] + w[i];
        uint32_t s0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    secure_zero(w, sizeof(w));
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
    ctx->bitlen = 0U;
    ctx->buffer_len = 0U;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8U;

    while(len != 0U) {
        size_t want = sizeof(ctx->buffer) - ctx->buffer_len;
        size_t take = len < want ? len : want;

        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if(ctx->buffer_len == sizeof(ctx->buffer)) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0U;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t out[32]) {
    uint64_t bitlen = ctx->bitlen;

    ctx->buffer[ctx->buffer_len++] = 0x80U;

    if(ctx->buffer_len > 56U) {
        while(ctx->buffer_len < 64U) {
            ctx->buffer[ctx->buffer_len++] = 0U;
        }
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0U;
    }

    while(ctx->buffer_len < 56U) {
        ctx->buffer[ctx->buffer_len++] = 0U;
    }

    for(size_t i = 0; i < 8U; i++) {
        ctx->buffer[63U - i] = (uint8_t)(bitlen >> (8U * i));
    }

    sha256_transform(ctx, ctx->buffer);

    for(size_t i = 0; i < 8U; i++) {
        store32_be(out + (i * 4U), ctx->state[i]);
    }

    secure_zero(ctx, sizeof(*ctx));
}

static void hmac_sha256_init(HMAC_SHA256_CTX *ctx, const uint8_t *key, size_t key_len) {
    uint8_t key_block[64];
    uint8_t hashed_key[32];
    uint8_t ipad[64];
    uint8_t opad[64];

    memset(key_block, 0, sizeof(key_block));

    if(key_len > sizeof(key_block)) {
        SHA256_CTX key_hash;
        sha256_init(&key_hash);
        sha256_update(&key_hash, key, key_len);
        sha256_final(&key_hash, hashed_key);
        memcpy(key_block, hashed_key, sizeof(hashed_key));
    } else if(key_len != 0U) {
        memcpy(key_block, key, key_len);
    }

    for(size_t i = 0; i < sizeof(key_block); i++) {
        ipad[i] = key_block[i] ^ 0x36U;
        opad[i] = key_block[i] ^ 0x5cU;
    }

    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, ipad, sizeof(ipad));
    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, opad, sizeof(opad));

    secure_zero(key_block, sizeof(key_block));
    secure_zero(hashed_key, sizeof(hashed_key));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
}

static void hmac_sha256_update(HMAC_SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    if(len != 0U) {
        sha256_update(&ctx->inner, data, len);
    }
}

static void hmac_sha256_final(HMAC_SHA256_CTX *ctx, uint8_t out[32]) {
    uint8_t inner_hash[32];
    sha256_final(&ctx->inner, inner_hash);
    sha256_update(&ctx->outer, inner_hash, sizeof(inner_hash));
    sha256_final(&ctx->outer, out);
    secure_zero(inner_hash, sizeof(inner_hash));
    secure_zero(ctx, sizeof(*ctx));
}

static void hmac_sha256(const uint8_t *key,
                        size_t key_len,
                        const uint8_t *data,
                        size_t data_len,
                        uint8_t out[32]) {
    HMAC_SHA256_CTX ctx;
    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, data_len);
    hmac_sha256_final(&ctx, out);
}

static int hkdf_expand_sha256(const uint8_t prk[32],
                              const uint8_t *info,
                              size_t info_len,
                              uint8_t *okm,
                              size_t okm_len) {
    uint8_t t[32];
    size_t t_len = 0U;
    size_t done = 0U;
    uint8_t counter = 1U;

    if(okm_len > (255U * 32U)) {
        return MASC256_ERR_INVALID;
    }

    while(done < okm_len) {
        HMAC_SHA256_CTX ctx;
        size_t take;

        hmac_sha256_init(&ctx, prk, 32U);
        hmac_sha256_update(&ctx, t, t_len);
        hmac_sha256_update(&ctx, info, info_len);
        hmac_sha256_update(&ctx, &counter, 1U);
        hmac_sha256_final(&ctx, t);

        take = (okm_len - done) < sizeof(t) ? (okm_len - done) : sizeof(t);
        memcpy(okm + done, t, take);
        done += take;
        t_len = sizeof(t);
        counter++;
    }

    secure_zero(t, sizeof(t));
    return MASC256_OK;
}

static int derive_keys(const uint8_t *key,
                       size_t klen,
                       const uint8_t nonce[MASC256_NONCE_SIZE],
                       uint8_t enc_key[MASC256_KEY_SIZE],
                       uint8_t mac_key[MASC256_KEY_SIZE]) {
    static const uint8_t enc_info[] = "MASC-256 v2 stream key";
    static const uint8_t mac_info[] = "MASC-256 v2 authentication key";
    uint8_t prk[32];
    int rc;

    hmac_sha256(nonce, MASC256_NONCE_SIZE, key, klen, prk);

    rc = hkdf_expand_sha256(prk, enc_info, sizeof(enc_info) - 1U, enc_key, MASC256_KEY_SIZE);
    if(rc == MASC256_OK) {
        rc = hkdf_expand_sha256(prk, mac_info, sizeof(mac_info) - 1U, mac_key, MASC256_KEY_SIZE);
    }

    secure_zero(prk, sizeof(prk));
    return rc;
}

static void init_base(ACC *acc) {
    acc->a = 0x9e3779b97f4a7c15ULL ^ 0x4d41534332353632ULL;
    acc->b = 0x6a09e667f3bcc909ULL ^ 0x56325f4145435400ULL;
    acc->c = 0xbb67ae8584caa73bULL ^ 0x484b44465f484d41ULL;
    acc->d = 0x3c6ef372fe94f82bULL ^ 0x5348413235360000ULL;
}

static void absorb_word(ACC *acc, uint64_t word, uint64_t heap[MASC256_HEAP_WORDS]) {
    acc->a ^= word + rotl(acc->d, 17);
    acc->b += rotl(word ^ acc->a, 29);
    acc->c ^= rotr(word + acc->b, 31);
    acc->d += avalanche64(word ^ acc->c);

    stack_mix(acc, word ^ acc->c);
    heap_mix_scratch(acc, word ^ acc->a ^ rotl(acc->d, 13), heap);

    for(size_t round = 0; round < 4U; round++) {
        accumulator_round(acc);
    }
}

static void absorb_bytes(ACC *acc,
                         uint64_t domain,
                         const uint8_t *data,
                         size_t len,
                         uint64_t heap[MASC256_HEAP_WORDS]) {
    size_t offset = 0U;
    uint64_t block = 0U;

    absorb_word(acc, domain ^ avalanche64((uint64_t)len), heap);

    while(offset < len) {
        size_t block_len = (len - offset) < 8U ? (len - offset) : 8U;
        uint64_t word = load64_le_partial(data + offset, block_len);
        word ^= ((uint64_t)block_len << 56);
        word ^= avalanche64(domain + block);
        absorb_word(acc, word, heap);
        offset += block_len;
        block++;
    }
}

static void init_acc_nonce(ACC *acc,
                           const uint8_t *key,
                           size_t klen,
                           const uint8_t nonce[MASC256_NONCE_SIZE]) {
    uint64_t heap[MASC256_HEAP_WORDS];
    uint8_t zero_nonce[MASC256_NONCE_SIZE] = {0};
    static const uint64_t key_domain = 0x6b65795f6d617363ULL;
    static const uint64_t nonce_domain = 0x6e6f6e63655f7632ULL;

    if(acc == NULL) {
        return;
    }
    if(key == NULL) {
        klen = 0U;
    }
    if(nonce == NULL) {
        nonce = zero_nonce;
    }

    init_base(acc);
    absorb_bytes(acc, nonce_domain, nonce, MASC256_NONCE_SIZE, heap);
    absorb_bytes(acc, key_domain, key, klen, heap);

    for(size_t round = 0; round < 12U; round++) {
        absorb_word(acc, 0xa5a5a5a5a5a5a5a5ULL ^ round, heap);
    }

    secure_zero(heap, sizeof(heap));
    secure_zero(zero_nonce, sizeof(zero_nonce));
}

static uint64_t keystream_word(const ACC *acc, uint64_t block_index) {
    uint64_t mix = acc->a ^
                   rotl(acc->b, 17) ^
                   rotr(acc->c, 23) ^
                   acc->d ^
                   avalanche64(block_index ^ 0xfeedfacedeadbeefULL);
    return avalanche64(mix);
}

static void absorb_cipher_block(ACC *acc,
                                const uint8_t cipher_block[8],
                                size_t block_len,
                                uint64_t block_index,
                                uint64_t heap[MASC256_HEAP_WORDS]) {
    uint64_t word = load64_le_partial(cipher_block, block_len);
    word ^= ((uint64_t)block_len << 56);
    word ^= avalanche64(block_index ^ 0x7365635f626c6f63ULL);
    absorb_word(acc, word, heap);
}

static void stream_crypt(ACC *acc, uint8_t *data, size_t len, int encrypting) {
    uint64_t heap[MASC256_HEAP_WORDS];
    size_t offset = 0U;
    uint64_t block_index = 0U;

    while(offset < len) {
        uint8_t cipher_block[8] = {0};
        size_t block_len = (len - offset) < 8U ? (len - offset) : 8U;
        uint64_t ks = keystream_word(acc, block_index);

        for(size_t i = 0; i < block_len; i++) {
            uint8_t input = data[offset + i];
            uint8_t output = input ^ (uint8_t)(ks >> (8U * i));

            if(encrypting) {
                data[offset + i] = output;
                cipher_block[i] = output;
            } else {
                cipher_block[i] = input;
                data[offset + i] = output;
            }
        }

        absorb_cipher_block(acc, cipher_block, block_len, block_index, heap);
        secure_zero(cipher_block, sizeof(cipher_block));
        offset += block_len;
        block_index++;
    }

    secure_zero(heap, sizeof(heap));
}

static void hmac_update_u64(HMAC_SHA256_CTX *ctx, uint64_t value) {
    uint8_t encoded[8];
    store64_le(encoded, value);
    hmac_sha256_update(ctx, encoded, sizeof(encoded));
    secure_zero(encoded, sizeof(encoded));
}

static void compute_tag(const uint8_t mac_key[MASC256_KEY_SIZE],
                        const uint8_t nonce[MASC256_NONCE_SIZE],
                        const uint8_t *aad,
                        size_t aad_len,
                        const uint8_t *ciphertext,
                        size_t ciphertext_len,
                        uint8_t tag[MASC256_TAG_SIZE]) {
    static const uint8_t tag_domain[] = "MASC-256 v2 EtM HMAC-SHA256";
    HMAC_SHA256_CTX ctx;

    hmac_sha256_init(&ctx, mac_key, MASC256_KEY_SIZE);
    hmac_sha256_update(&ctx, tag_domain, sizeof(tag_domain) - 1U);
    hmac_sha256_update(&ctx, nonce, MASC256_NONCE_SIZE);
    hmac_update_u64(&ctx, (uint64_t)aad_len);
    hmac_sha256_update(&ctx, aad, aad_len);
    hmac_update_u64(&ctx, (uint64_t)ciphertext_len);
    hmac_sha256_update(&ctx, ciphertext, ciphertext_len);
    hmac_sha256_final(&ctx, tag);
}

static int constant_time_equal(const uint8_t *left, const uint8_t *right, size_t len) {
    uint8_t diff = 0U;
    for(size_t i = 0; i < len; i++) {
        diff |= left[i] ^ right[i];
    }
    return diff == 0U;
}

static int validate_inputs(const uint8_t *data,
                           size_t len,
                           const uint8_t *key,
                           size_t klen,
                           const uint8_t *nonce,
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *tag) {
    if(key == NULL || klen == 0U || nonce == NULL || tag == NULL) {
        return MASC256_ERR_INVALID;
    }
    if(data == NULL && len != 0U) {
        return MASC256_ERR_INVALID;
    }
    if(aad == NULL && aad_len != 0U) {
        return MASC256_ERR_INVALID;
    }
    return MASC256_OK;
}

int masc256_random_nonce(uint8_t nonce[MASC256_NONCE_SIZE]) {
    if(nonce == NULL) {
        return MASC256_ERR_INVALID;
    }

#if defined(_WIN32)
    if(BCryptGenRandom(NULL, nonce, MASC256_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        return MASC256_OK;
    }
    return MASC256_ERR_RANDOM;
#else
    FILE *random = fopen("/dev/urandom", "rb");
    if(random == NULL) {
        return MASC256_ERR_RANDOM;
    }
    if(fread(nonce, 1U, MASC256_NONCE_SIZE, random) != MASC256_NONCE_SIZE) {
        fclose(random);
        return MASC256_ERR_RANDOM;
    }
    fclose(random);
    return MASC256_OK;
#endif
}

int masc256_encrypt(uint8_t *data,
                    size_t len,
                    const uint8_t *key,
                    size_t klen,
                    const uint8_t nonce[MASC256_NONCE_SIZE],
                    const uint8_t *aad,
                    size_t aad_len,
                    uint8_t tag[MASC256_TAG_SIZE]) {
    uint8_t enc_key[MASC256_KEY_SIZE];
    uint8_t mac_key[MASC256_KEY_SIZE];
    ACC acc;
    int rc = validate_inputs(data, len, key, klen, nonce, aad, aad_len, tag);

    if(rc != MASC256_OK) {
        return rc;
    }

    rc = derive_keys(key, klen, nonce, enc_key, mac_key);
    if(rc != MASC256_OK) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        return rc;
    }

    init_acc_nonce(&acc, enc_key, MASC256_KEY_SIZE, nonce);
    stream_crypt(&acc, data, len, 1);
    compute_tag(mac_key, nonce, aad, aad_len, data, len, tag);

    secure_zero(&acc, sizeof(acc));
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    return MASC256_OK;
}

int masc256_decrypt(uint8_t *data,
                    size_t len,
                    const uint8_t *key,
                    size_t klen,
                    const uint8_t nonce[MASC256_NONCE_SIZE],
                    const uint8_t *aad,
                    size_t aad_len,
                    const uint8_t tag[MASC256_TAG_SIZE]) {
    uint8_t enc_key[MASC256_KEY_SIZE];
    uint8_t mac_key[MASC256_KEY_SIZE];
    uint8_t expected_tag[MASC256_TAG_SIZE];
    ACC acc;
    int rc = validate_inputs(data, len, key, klen, nonce, aad, aad_len, tag);

    if(rc != MASC256_OK) {
        return rc;
    }

    rc = derive_keys(key, klen, nonce, enc_key, mac_key);
    if(rc != MASC256_OK) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        return rc;
    }

    compute_tag(mac_key, nonce, aad, aad_len, data, len, expected_tag);
    if(!constant_time_equal(expected_tag, tag, MASC256_TAG_SIZE)) {
        secure_zero(expected_tag, sizeof(expected_tag));
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        return MASC256_ERR_AUTH;
    }

    init_acc_nonce(&acc, enc_key, MASC256_KEY_SIZE, nonce);
    stream_crypt(&acc, data, len, 0);

    secure_zero(&acc, sizeof(acc));
    secure_zero(expected_tag, sizeof(expected_tag));
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    return MASC256_OK;
}

int masc256_seal(uint8_t *out,
                 size_t out_cap,
                 size_t *out_len,
                 const uint8_t *plaintext,
                 size_t plaintext_len,
                 const uint8_t *key,
                 size_t klen,
                 const uint8_t *aad,
                 size_t aad_len) {
    uint8_t tag[MASC256_TAG_SIZE];
    uint8_t *ciphertext;
    size_t sealed_len;
    int rc;

    if(out_len == NULL || key == NULL || klen == 0U) {
        return MASC256_ERR_INVALID;
    }
    if(plaintext == NULL && plaintext_len != 0U) {
        return MASC256_ERR_INVALID;
    }
    if(aad == NULL && aad_len != 0U) {
        return MASC256_ERR_INVALID;
    }
    if(plaintext_len > ((size_t)-1) - MASC256_OVERHEAD) {
        return MASC256_ERR_INVALID;
    }

    sealed_len = plaintext_len + MASC256_OVERHEAD;
    *out_len = sealed_len;

    if(out == NULL || out_cap < sealed_len) {
        return MASC256_ERR_BUFFER;
    }

    ciphertext = out + MASC256_NONCE_SIZE;
    if(plaintext_len != 0U) {
        memmove(ciphertext, plaintext, plaintext_len);
    }

    rc = masc256_random_nonce(out);
    if(rc != MASC256_OK) {
        secure_zero(out, sealed_len);
        return rc;
    }

    rc = masc256_encrypt(ciphertext,
                         plaintext_len,
                         key,
                         klen,
                         out,
                         aad,
                         aad_len,
                         tag);
    if(rc != MASC256_OK) {
        secure_zero(out, sealed_len);
        return rc;
    }

    memcpy(out + MASC256_NONCE_SIZE + plaintext_len, tag, MASC256_TAG_SIZE);
    secure_zero(tag, sizeof(tag));
    return MASC256_OK;
}

int masc256_open(uint8_t *out,
                 size_t out_cap,
                 size_t *out_len,
                 const uint8_t *sealed,
                 size_t sealed_len,
                 const uint8_t *key,
                 size_t klen,
                 const uint8_t *aad,
                 size_t aad_len) {
    const uint8_t *nonce;
    const uint8_t *ciphertext;
    const uint8_t *tag;
    uint8_t nonce_copy[MASC256_NONCE_SIZE];
    uint8_t tag_copy[MASC256_TAG_SIZE];
    size_t ciphertext_len;
    int rc;

    if(out_len == NULL || key == NULL || klen == 0U || sealed == NULL) {
        return MASC256_ERR_INVALID;
    }
    if(aad == NULL && aad_len != 0U) {
        return MASC256_ERR_INVALID;
    }
    if(sealed_len < MASC256_OVERHEAD) {
        return MASC256_ERR_AUTH;
    }

    ciphertext_len = sealed_len - MASC256_OVERHEAD;
    *out_len = ciphertext_len;

    if((out == NULL && ciphertext_len != 0U) || out_cap < ciphertext_len) {
        return MASC256_ERR_BUFFER;
    }

    nonce = sealed;
    ciphertext = sealed + MASC256_NONCE_SIZE;
    tag = sealed + MASC256_NONCE_SIZE + ciphertext_len;
    memcpy(nonce_copy, nonce, MASC256_NONCE_SIZE);
    memcpy(tag_copy, tag, MASC256_TAG_SIZE);

    if(ciphertext_len != 0U) {
        memmove(out, ciphertext, ciphertext_len);
    }

    rc = masc256_decrypt(out,
                         ciphertext_len,
                         key,
                         klen,
                         nonce_copy,
                         aad,
                         aad_len,
                         tag_copy);
    if(rc != MASC256_OK) {
        secure_zero(out, ciphertext_len);
    }

    secure_zero(nonce_copy, sizeof(nonce_copy));
    secure_zero(tag_copy, sizeof(tag_copy));
    return rc;
}

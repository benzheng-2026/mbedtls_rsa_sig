#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <string.h>

int rsa_public_encrypt(const char *pub_key_path,
                       const unsigned char *input,
                       size_t input_len,
                       unsigned char *output,
                       size_t *output_len)
{
    int ret;

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char *pers = "rsa_pk_encrypt";

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // RNG初始化（必须）
    ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (const unsigned char *)pers,
            strlen(pers)
    );
    if (ret != 0) {
        printf("RNG init failed\n");
        return ret;
    }

    // 读取公钥（2.16支持这个API）
    ret = mbedtls_pk_parse_public_keyfile(&pk, pub_key_path);
    if (ret != 0) {
        char err[128];
        mbedtls_strerror(ret, err, sizeof(err));
        printf("PK parse failed: %s\n", err);
        goto exit;
    }

    // 检查是不是RSA
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        printf("Not RSA key\n");
        ret = -1;
        goto exit;
    }

    size_t olen = 0;

    // RSA 加密（PKCS#1 v1.5）
    ret = mbedtls_pk_encrypt(
            &pk,
            input,
            input_len,
            output,
            &olen,
            256,   // 2048-bit RSA = 256 bytes
            mbedtls_ctr_drbg_random,
            &ctr_drbg
    );

    if (ret == 0) {
        *output_len = olen;
    } else {
        char err[128];
        mbedtls_strerror(ret, err, sizeof(err));
        printf("Encrypt failed: %s\n", err);
    }

    exit:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int main()
{
    // 加密公钥路径
    const char *pub_key = "E:/03_chaopeng/04_freetech/02_clion/mbedtls_rsa_sig/key/public_key.pem";
    // 明文数据
    unsigned char plaintext[] = "Hello RSA mbedTLS 2.16";
   // 密文数据变量
    unsigned char ciphertext[256];
    // 密文数据长度变量
    size_t ciphertext_len = 0;

    int ret = rsa_public_encrypt(
            pub_key,
            plaintext,
            strlen((char *)plaintext),
            ciphertext,
            &ciphertext_len
    );

    if (ret == 0) {
        printf("Encrypt OK!\nHEX:\n");

        for (size_t i = 0; i < ciphertext_len; i++) {
            printf("%02X", ciphertext[i]);
        }
        printf("\n");
    }

    return ret;
}
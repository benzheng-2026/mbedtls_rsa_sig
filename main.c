#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include <string.h>
#include <stdio.h>

#define PLAINTEXT        "Hello, RSAES-OAEP encryption!"
#define PLAINTEXT_LEN    strlen(PLAINTEXT)
#define CIPHERTEXT_BUF   256

#define PRIVATE_KEY_PATH "private_key.pem"
#define PUBLIC_KEY_PATH  "public_key.pem"

int main(void) {
    int ret;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_priv;
    mbedtls_pk_context pk_pub;
    mbedtls_rsa_context *rsa_pub;
    mbedtls_rsa_context *rsa_priv;
    unsigned char ciphertext[CIPHERTEXT_BUF];
    unsigned char decrypted[CIPHERTEXT_BUF];
    size_t decrypted_len;
    const char *pers = "rsa_oaep_example";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_priv);
    mbedtls_pk_init(&pk_pub);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        mbedtls_printf("随机数生成器初始化失败: -0x%04X\n", -ret);
        goto exit;
    }

    mbedtls_printf("正在从文件加载RSA私钥...\n");
    ret = mbedtls_pk_parse_keyfile(&pk_priv, PRIVATE_KEY_PATH, NULL);
    if (ret != 0) {
        mbedtls_printf("加载私钥失败: -0x%04X\n", -ret);
        mbedtls_printf("请先使用OpenSSL生成密钥对:\n");
        mbedtls_printf("  openssl genrsa -out private_key.pem 2048\n");
        mbedtls_printf("  openssl rsa -in private_key.pem -pubout -out public_key.pem\n");
        goto exit;
    }

    mbedtls_printf("正在从文件加载RSA公钥...\n");
    ret = mbedtls_pk_parse_public_keyfile(&pk_pub, PUBLIC_KEY_PATH);
    if (ret != 0) {
        mbedtls_printf("加载公钥失败: -0x%04X\n", -ret);
        goto exit;
    }

    mbedtls_printf("密钥加载成功！\n");
    mbedtls_printf("私钥类型: %s\n", mbedtls_pk_get_name(&pk_priv));
    mbedtls_printf("公钥类型: %s\n", mbedtls_pk_get_name(&pk_pub));

    rsa_pub = mbedtls_pk_rsa(pk_pub);
    rsa_priv = mbedtls_pk_rsa(pk_priv);

    mbedtls_rsa_set_padding(rsa_pub, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_set_padding(rsa_priv, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    mbedtls_printf("\n原始明文: %s\n", PLAINTEXT);

    ret = mbedtls_rsa_rsaes_oaep_encrypt(
            rsa_pub,
            mbedtls_ctr_drbg_random, &ctr_drbg,
            MBEDTLS_RSA_PUBLIC,
            NULL, 0,
            PLAINTEXT_LEN,
            (const unsigned char *)PLAINTEXT,
            ciphertext
    );
    if (ret != 0) {
        mbedtls_printf("加密失败: -0x%04X\n", -ret);
        goto exit;
    }
    mbedtls_printf("加密成功，密文长度: %d字节\n", (int)mbedtls_rsa_get_len(rsa_pub));

    mbedtls_printf("密文数据(HEX):\n");
    for (size_t i = 0; i < mbedtls_rsa_get_len(rsa_pub); i++) {
        mbedtls_printf("%02X ", ciphertext[i]);
        if ((i + 1) % 16 == 0) {
            mbedtls_printf("\n");
        }
    }
    mbedtls_printf("\n");

    ret = mbedtls_rsa_rsaes_oaep_decrypt(
            rsa_priv,
            mbedtls_ctr_drbg_random, &ctr_drbg,
            MBEDTLS_RSA_PRIVATE,
            NULL, 0,
            &decrypted_len,
            ciphertext,
            decrypted,
            sizeof(decrypted)
    );
    if (ret != 0) {
        mbedtls_printf("解密失败: -0x%04X\n", -ret);
        goto exit;
    }

    decrypted[decrypted_len] = '\0';
    mbedtls_printf("\n解密结果: %s\n", decrypted);
    if (strncmp((char *)decrypted, PLAINTEXT, PLAINTEXT_LEN) == 0) {
        mbedtls_printf("验证成功: 解密结果与原始明文一致\n");
    } else {
        mbedtls_printf("验证失败: 解密结果与原始明文不一致\n");
        ret = -1;
    }

exit:
    mbedtls_pk_free(&pk_pub);
    mbedtls_pk_free(&pk_priv);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

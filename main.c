#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include <string.h>
#include <stdio.h>

#define MESSAGE          "Hello, RSASSA-PKCS1-v1_5 signature!"
#define MESSAGE_LEN      strlen(MESSAGE)
#define SIGNATURE_BUF    256
#define HASH_LEN         32

#define PRIVATE_KEY_PATH "private_key.pem"
#define PUBLIC_KEY_PATH  "public_key.pem"

int main(void) {
    int ret;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_priv;
    mbedtls_pk_context pk_pub;
    mbedtls_rsa_context *rsa_priv;
    unsigned char signature[SIGNATURE_BUF];
    unsigned char mHash[HASH_LEN];
    size_t signature_len;
    const char *pers = "rsa_pkcs1v15_example";

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

    rsa_priv = mbedtls_pk_rsa(pk_priv);

    mbedtls_rsa_set_padding(rsa_priv, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    mbedtls_printf("\n原始消息: %s\n", MESSAGE);
    mbedtls_printf("消息长度: %zu 字节\n", MESSAGE_LEN);

    mbedtls_printf("\n========== 预计算消息哈希 ==========\n");
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                     (const unsigned char *)MESSAGE, MESSAGE_LEN,
                     mHash);
    if (ret != 0) {
        mbedtls_printf("哈希计算失败: -0x%04X\n", -ret);
        goto exit;
    }

    mbedtls_printf("消息哈希(SHA-256):\n");
    for (size_t i = 0; i < HASH_LEN; i++) {
        mbedtls_printf("%02X ", mHash[i]);
        if ((i + 1) % 16 == 0) {
            mbedtls_printf("\n");
        }
    }
    mbedtls_printf("\n");

    mbedtls_printf("\n========== RSASSA-PKCS1-v1_5 签名阶段 ==========\n");

    ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(
            rsa_priv,
            mbedtls_ctr_drbg_random, &ctr_drbg,
            MBEDTLS_RSA_PRIVATE,
            MBEDTLS_MD_SHA256,
            HASH_LEN,
            mHash,
            signature
    );
    if (ret != 0) {
        mbedtls_printf("签名失败: -0x%04X\n", -ret);
        goto exit;
    }

    signature_len = mbedtls_rsa_get_len(rsa_priv);
    mbedtls_printf("签名成功，签名长度: %zu 字节\n", signature_len);

    mbedtls_printf("签名数据(HEX):\n");
    for (size_t i = 0; i < signature_len; i++) {
        mbedtls_printf("%02X ", signature[i]);
        if ((i + 1) % 16 == 0) {
            mbedtls_printf("\n");
        }
    }
    mbedtls_printf("\n");

    mbedtls_printf("\n========== RSASSA-PKCS1-v1_5 验证阶段 ==========\n");

    mbedtls_rsa_context *rsa_pub = mbedtls_pk_rsa(pk_pub);
    mbedtls_rsa_set_padding(rsa_pub, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(
            rsa_pub,
            NULL, NULL,
            MBEDTLS_RSA_PUBLIC,
            MBEDTLS_MD_SHA256,
            HASH_LEN,
            mHash,
            signature
    );
    if (ret != 0) {
        mbedtls_printf("验证失败: -0x%04X\n", -ret);
        mbedtls_printf("  可能原因:\n");
        mbedtls_printf("  1. 消息被篡改\n");
        mbedtls_printf("  2. 签名不匹配\n");
        mbedtls_printf("  3. 密钥不配对\n");
        goto exit;
    }

    mbedtls_printf("验证成功: 签名有效，消息完整性得到保证\n");
    mbedtls_printf("  ✓ 消息未被篡改\n");
    mbedtls_printf("  ✓ 签名由私钥持有者生成\n");

exit:
    mbedtls_pk_free(&pk_pub);
    mbedtls_pk_free(&pk_priv);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

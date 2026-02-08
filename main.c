#include <stdio.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define BUFFER_SIZE 1024 // 定义缓冲区大小
#define RSA_KEY_SIZE 2048 // RSA 密钥长度

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <filename> <private_key_file> <signature_output_file>\n", argv[0]);
        return -1;
    }

    const char *filename = argv[1];
    const char *key_file = argv[2];
    const char *sig_file = argv[3]; // 签名输出文件

    // 打开待签名的文件
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }

    // 初始化熵源和随机数生成器
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "rsa_sign"; // 个性化字符串
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed RNG: %d\n", ret);
        goto cleanup;
    }

    // 加载私钥
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_keyfile(&pk, key_file, NULL); // 不需要密码
    if (ret != 0) {
        printf("Failed to load private key: %d\n", ret);
        goto cleanup;
    }

    // 检查密钥是否为 RSA 类型
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        printf("Key is not an RSA key\n");
        ret = -1;
        goto cleanup;
    }

    // 计算文件的 SHA256 哈希值
    unsigned char buffer[BUFFER_SIZE];
    unsigned char hash[32];
    size_t bytes_read;

    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts_ret(&sha256_ctx, 0); // 初始化 SHA256 上下文

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        mbedtls_sha256_update_ret(&sha256_ctx, buffer, bytes_read);
    }

    if (ferror(file)) {
        perror("Error reading file");
        ret = -1;
        goto cleanup;
    }

    mbedtls_sha256_finish_ret(&sha256_ctx, hash); // 完成哈希计算
    mbedtls_sha256_free(&sha256_ctx);

    // 打印文件的 SHA256 哈希值
    printf("File SHA256 Hash:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // 使用 RSA 私钥对哈希值进行签名
    unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
    size_t sig_len;

    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0,
                          signature, &sig_len,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("Failed to sign: %d\n", ret);
        goto cleanup;
    }

    // 输出签名结果（以十六进制形式）
    printf("Signature:\n");
    for (size_t i = 0; i < sig_len; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");

    // 将签名保存为二进制文件
    FILE *sig_output = fopen(sig_file, "wb");
    if (!sig_output) {
        perror("Failed to open signature output file");
        ret = -1;
        goto cleanup;
    }

    if (fwrite(signature, 1, sig_len, sig_output) != sig_len) {
        perror("Failed to write signature to file");
        ret = -1;
        fclose(sig_output);
        goto cleanup;
    }

    fclose(sig_output);

    cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    fclose(file);
    return ret;
}

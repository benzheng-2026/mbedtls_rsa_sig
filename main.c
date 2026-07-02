#include "mbedtls/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE   16
#define AES_BLOCK_SIZE 16

static const unsigned char key[AES_KEY_SIZE] =
        {
                '0','1','2','3',
                '4','5','6','7',
                '8','9','a','b',
                'c','d','e','f'
        };

static const unsigned char iv[AES_BLOCK_SIZE] =
        {
                'f','e','d','c',
                'b','a','9','8',
                '7','6','5','4',
                '3','2','1','0'
        };

void print_hex(const char *title,
               const unsigned char *buf,
               size_t len)
{
    printf("%s (%zu bytes)\n", title, len);

    for(size_t i=0;i<len;i++)
    {
        printf("%02X ", buf[i]);

        if((i+1)%16==0)
            printf("\n");
    }

    if(len%16)
        printf("\n");

    printf("\n");
}
size_t pkcs7_padding(const unsigned char *input,
                     size_t input_len,
                     unsigned char *output)
{
    size_t padding = AES_BLOCK_SIZE - input_len % AES_BLOCK_SIZE;

    if(padding==0)
        padding=AES_BLOCK_SIZE;

    memcpy(output,input,input_len);

    for(size_t i=0;i<padding;i++)
        output[input_len+i]=(unsigned char)padding;

    return input_len+padding;
}
size_t pkcs7_unpadding(unsigned char *buf,
                       size_t len)
{
    if(len==0)
        return 0;

    unsigned char pad=buf[len-1];

    if(pad==0 || pad>16)
        return 0;

    for(size_t i=0;i<pad;i++)
    {
        if(buf[len-1-i]!=pad)
            return 0;
    }

    return len-pad;
}
int aes_encrypt(const unsigned char *input,
                size_t len,
                unsigned char *output)
{
    mbedtls_aes_context aes;

    unsigned char iv_copy[AES_BLOCK_SIZE];

    memcpy(iv_copy, iv, AES_BLOCK_SIZE);

    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, key, 128);
    if(ret != 0)
    {
        mbedtls_aes_free(&aes);
        return ret;
    }

    ret = mbedtls_aes_crypt_cbc(&aes,
                                MBEDTLS_AES_ENCRYPT,
                                len,
                                iv_copy,
                                input,
                                output);

    mbedtls_aes_free(&aes);

    return ret;
}
int aes_decrypt(const unsigned char *input,
                size_t len,
                unsigned char *output)
{
    mbedtls_aes_context aes;

    unsigned char iv_copy[16];

    memcpy(iv_copy,iv,16);

    mbedtls_aes_init(&aes);

    int ret=mbedtls_aes_setkey_dec(&aes,key,128);

    if(ret!=0)
        return ret;

    ret=mbedtls_aes_crypt_cbc(&aes,
                              MBEDTLS_AES_DECRYPT,
                              len,
                              iv_copy,
                              input,
                              output);

    mbedtls_aes_free(&aes);

    return ret;
}
int main(void)
{
     const char *text="12345678123456781234567812345678"; //32bytes，padin
   //const char *text="12"; //2bytes
  // const char *text="1234567812345678"; //16bytes
    size_t plain_len=strlen(text);

    printf("Original:\n%s\n\n",text);

    print_hex("Plain",
              (const unsigned char*)text,
              plain_len);

    unsigned char padded[256];

    size_t padded_len=
            pkcs7_padding(
                    (const unsigned char*)text,
                    plain_len,
                    padded);

    print_hex("After PKCS7 Padding",
              padded,
              padded_len);

    unsigned char cipher[256];

    if(aes_encrypt(padded,
                   padded_len,
                   cipher)!=0)
    {
        printf("encrypt failed\n");
        return -1;
    }

    print_hex("Cipher",
              cipher,
              padded_len);

    unsigned char decrypted[256];

    if(aes_decrypt(cipher,
                   padded_len,
                   decrypted)!=0)
    {
        printf("decrypt failed\n");
        return -1;
    }

    print_hex("Decrypt(with padding)",
              decrypted,
              padded_len);

    size_t real_len=
            pkcs7_unpadding(
                    decrypted,
                    padded_len);

    decrypted[real_len]=0;

    print_hex("After UnPadding",
              decrypted,
              real_len);

    printf("Recovered:\n%s\n",decrypted);

    return 0;
}
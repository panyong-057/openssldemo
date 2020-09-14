//
// Created by Administrator on 2020/9/14.
//

#include "MySm4.h"
#include "../include/openssl/ossl_typ.h"
#include "../include/openssl/evp.h"
#include "../macro.h"


void MySm4::deCode( unsigned char *key,  unsigned char *iv, int encLen, int &outlen,
             unsigned char *encData, int decLen,  unsigned char *decData) {
    EVP_CIPHER_CTX *ctx2;
    ctx2 = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx2, EVP_sm4_ecb(), NULL, key, iv, 0);
    EVP_CipherUpdate(ctx2, decData, &outlen, encData, encLen);
    decLen = outlen;
    EVP_CipherFinal(ctx2, decData + outlen, &outlen);
    decLen += outlen;
    EVP_CIPHER_CTX_free(ctx2);
    LOGE("sm4 decrypt: %s\n", decData);
}

void MySm4::enCode(unsigned char *key, unsigned char *iv,  char *inStr, int inLen, int encLen,
           int &outlen,  unsigned char *encData) {//加密
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv, 1);
    EVP_CipherUpdate(ctx, encData, &outlen, reinterpret_cast<const unsigned char *>(inStr), inLen);
    encLen = outlen;
    EVP_CipherFinal(ctx, encData + outlen, &outlen);
    encLen += outlen;
    EVP_CIPHER_CTX_free(ctx);
    LOGE("sm4 encrypt: %s\n", encData);
}

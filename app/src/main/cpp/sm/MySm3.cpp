//
// Created by Administrator on 2020/9/14.
//

#include "MySm3.h"
#include "../include/openssl/ossl_typ.h"
#include "../include/openssl/evp.h"

void MySm3 ::sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash,
             unsigned int *hash_len) {
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;

    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, message, len);
    EVP_DigestFinal_ex(md_ctx, hash, hash_len);
    EVP_MD_CTX_free(md_ctx);

}
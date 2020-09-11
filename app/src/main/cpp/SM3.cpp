//
// Created by Administrator on 2020/9/11.
//

#include "include/openssl/evp.h"
#include "/include/openssl/ossl_typ.h"
#include "SM3.h"

int SM3::DigestData(string &in_data,string &out_data){


    unsigned int len;
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;

    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, nullptr);
    EVP_DigestUpdate(md_ctx, in_data.c_str(), in_data.length());
    EVP_DigestFinal_ex(md_ctx, out_data.c_str(), &len);
    EVP_MD_CTX_free(md_ctx);

}
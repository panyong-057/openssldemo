//
// Created by Administrator on 2020/9/14.
//

#ifndef OPENSSL_TEST_MYSM2_H
#define OPENSSL_TEST_MYSM2_H

#include <string>
#include "../include/openssl/ossl_typ.h"
#include "../macro.h"
using namespace std;
class MySm2 {
private:

    // 通过公钥/私钥返回EVP_PKEY
    // key pem格式
    // is_public
    // out_ecKey
    static bool CreateEVP_PKEY(unsigned char *key, int is_public, EVP_PKEY **out_ecKey);

public:

    // 根据私钥计算出公钥
    bool PriKey2PubKey(string in_priKey, string &out_pubKey);

    //生成EC秘钥对
    //pem格式的私钥
    //pem格式的公钥
    int GenEcPairKey(string &out_priKey, string &out_pubKey);


    // 签名 私钥加密 0成功
    // in_buf 待签名数据
    // in_buflen 长度
    // out_sig 签名后数据
    // len_sig 签名数据长度
    // priKey 私钥pem格式

    int Sign(string in_buf, int in_buflen, string &out_sig, int &len_sig, string priKey);


    // 验签 公钥解密 0成功
    // in_buf 待验签数据 明文
    // buflen 数据长度
    // sig 签名数据
    // siglen 签名数据长度
    // pubkey 公钥
    // keylen 公钥长度
    int Verify(string in_buf, const int buflen, string sig, const int siglen,
               string pubkey, const int keylen);


    // 加密 公钥加密 0成功

    // in_buf
    // in_buflen
    // out_encrypted
    // len_encrypted
    // pubKey pem格式公钥

    int
    Encrypt(string in_buf, int in_buflen, string &out_encrypted, int &len_encrypted, string pubKey);


    // 解密 私钥解密 0成功

    // in_buf
    // in_buflen
    // out_plaint
    // len_plaint
    // prikey pem格式私钥

    int Decrypt(string in_buf, int in_buflen, string &out_plaint, int &len_plaint, string prikey);
};

#endif //OPENSSL_TEST_MYSM2_H

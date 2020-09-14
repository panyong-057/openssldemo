//
// Created by Administrator on 2020/9/14.
//

#include "MyAes.h"
void MyAes::aes_encrypt(char *in, char *key, unsigned char *out)//, int olen)可能会设置buf长度
{
    if (!in || !key || !out){
        //return 0;
    }
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for (int i = 0; i < AES_BLOCK_SIZE; ++i){
        iv[i] = 0;
    }//iv一般设置为全0,可以设置其他，但是加密解密要一样就行

    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *) key, 128, &aes) < 0) {
       // return 0;
    }
    int len = strlen(in);//这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话

    //那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度

    //至于解密也是一个道理，光以'\0'来判断字符串长度，确有不妥，后面都是一个道理。
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, len, &aes, iv, AES_ENCRYPT);

}

void MyAes::aes_decrypt(unsigned char *in, char *key, char *out) {
    if (!in || !key || !out){
        //return 0;
    }

    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for (int i = 0; i < AES_BLOCK_SIZE; ++i){
        iv[i] = 0;
    }//iv一般设置为全0,可以设置其他，但是加密解密要一样就行

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char *) key, 128, &aes) < 0) {
        //return 0;
    }
    int len = strlen(reinterpret_cast<const char *>(in));
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, len, &aes, iv, AES_DECRYPT);

}
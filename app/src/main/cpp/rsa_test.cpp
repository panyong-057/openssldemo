//
// Created by Administrator on 2020/9/2.
//

#include "rsa_test.h"

#include<stdio.h>
#include<string.h>
#include <errno.h>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"



#define OPENSSLKEY "test.key"
#define PUBLICKEY  "test_pub.key"
#define BUFFSIZE   1024

char *my_encrypt(char *str, char *path_key);    //加密
char *my_decrypt(char *str, char *path_key);        //解密
void test_rsa()
{
    char *source = "i like dancing !!!";

    char *ptf_en, *ptf_de;

    LOGE("source is   :%s\n", source);

    //1.加密
    ptf_en = my_encrypt(source, PUBLICKEY);
    if (ptf_en  == NULL){
        return 0;
    }else{
        LOGE("ptf_en is   :%s\n", ptf_en);
    }
    //2.解密
    ptf_de = my_decrypt(ptf_en, OPENSSLKEY);
    if (ptf_de == NULL){
        return 0;
    }else{
        LOGE("ptf_de is   :%s\n", ptf_de);
    }
    if(ptf_en)            free(ptf_en);
    if(ptf_de)            free(ptf_de);

    return 0;

}

//加密
char *my_encrypt(char *str, char *path_key)
{
    char *p_en = NULL;
    RSA  *p_rsa = NULL;
    FILE *file = NULL;

    int  lenth = 0;    //flen为源文件长度， rsa_len为秘钥长度

    //1.打开秘钥文件
    if((file = fopen(path_key, "rb")) == NULL)
    {
        perror("fopen() error 111111111 ");
        goto End;
    }

    //2.从公钥中获取 加密的秘钥
    if((p_rsa = PEM_read_RSA_PUBKEY(file, NULL,NULL,NULL )) == NULL)
    {
        ERR_print_errors_fp(stdout);
        goto End;
    }
    lenth = strlen(str);

    p_en = (char *)malloc(256);
    if(!p_en)
    {
        perror("malloc() error 2222222222");
        goto End;
    }
    memset(p_en, 0, 256);

    //5.对内容进行加密
    if(RSA_public_encrypt(lenth, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_PKCS1_PADDING) < 0)
    {
        perror("RSA_public_encrypt() error 2222222222");
        goto End;
    }
    End:

    //6.释放秘钥空间， 关闭文件
    if(p_rsa)    RSA_free(p_rsa);
    if(file)     fclose(file);

    return p_en;
}

//解密
char *my_decrypt(char *str, char *path_key)
{
    char *p_de = NULL;
    RSA  *p_rsa = NULL;
    FILE *file = NULL;

    //1.打开秘钥文件
    file = fopen(path_key, "rb");
    if(!file)
    {
        perror("fopen() error 22222222222");
        goto End;
    }

    //2.从私钥中获取 解密的秘钥
    if((p_rsa = PEM_read_RSAPrivateKey(file, NULL,NULL,NULL )) == NULL)
    {
        ERR_print_errors_fp(stdout);
        goto End;
    }

    p_de = (char *)malloc(245);
    if(!p_de)
    {
        perror("malloc() error ");
        goto End;
    }
    memset(p_de, 0, 245);

    //5.对内容进行加密
    if(RSA_private_decrypt(256, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_PKCS1_PADDING) < 0)
    {
        perror("RSA_public_encrypt() error ");
        goto End;
    }

    End:
    //6.释放秘钥空间， 关闭文件
    if(p_rsa)    RSA_free(p_rsa);
    if(file)     fclose(file);

    return p_de;
}
//
// Created by Administrator on 2020/9/14.
//

#ifndef OPENSSL_TEST_MYSM4_H
#define OPENSSL_TEST_MYSM4_H


class MySm4 {


public:
    void enCode( unsigned char *key,  unsigned char *iv,  char *inStr, int inLen, int encLen,
           int &outlen,  unsigned char *encData);


    void deCode( unsigned char *key,  unsigned char *iv, int encLen, int &outlen,
                 unsigned char *encData, int decLen,  unsigned char *decData);
};


#endif //OPENSSL_TEST_MYSM4_H

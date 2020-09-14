//
// Created by Administrator on 2020/9/14.
//

#ifndef OPENSSL_TEST_MYAES_H
#define OPENSSL_TEST_MYAES_H

#include "../include/openssl/aes.h"
#include <string>
class MyAes {
public:
    void aes_encrypt(char *in, char *key, unsigned char *out);
    void aes_decrypt(unsigned char *in, char *key, char *out);
};


#endif //OPENSSL_TEST_MYAES_H

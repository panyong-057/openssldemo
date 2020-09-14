//
// Created by Administrator on 2020/9/14.
//

#ifndef OPENSSL_TEST_MYMD5_H
#define OPENSSL_TEST_MYMD5_H
#include "../include/openssl/md5.h"

class MyMd5 {
public:
    void Mymd5Encode(char *charPtr, int dataLen, unsigned char *md5);
};


#endif //OPENSSL_TEST_MYMD5_H

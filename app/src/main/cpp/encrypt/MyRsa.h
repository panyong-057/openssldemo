//
// Created by Administrator on 2020/9/14.
//

#ifndef OPENSSL_TEST_MYRSA_H
#define OPENSSL_TEST_MYRSA_H

#include <string>
#include "../macro.h"
using namespace std;

class MyRsa {

public:
    void EnCrypt(RSA *rsa,string in,string &out);
    void DeCrypt(RSA *rsa,string in,string &out);
};


#endif //OPENSSL_TEST_MYRSA_H

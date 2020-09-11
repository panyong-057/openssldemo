//
// Created by Administrator on 2020/9/11.
//

#ifndef OPENSSL_TEST_SM3_H
#define OPENSSL_TEST_SM3_H
#include <string>
using namespace std;

class SM3 {
public:
    int DigestData(string &in_data,string &out_data);
};


#endif //OPENSSL_TEST_SM3_H

//
// Created by Administrator on 2020/9/14.
//

#ifndef OPENSSL_TEST_MYSM3_H
#define OPENSSL_TEST_MYSM3_H


class MySm3 {


public:
    void sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash,
                 unsigned int *hash_len);
};


#endif //OPENSSL_TEST_MYSM3_H

//
// Created by Administrator on 2020/9/14.
//

#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include "MyRsa.h"
void MyRsa::EnCrypt(RSA *rsa,string in,string &out){



    size_t outl = RSA_public_encrypt(in.length(), reinterpret_cast<const unsigned char *>(in.c_str()),
                              (unsigned char *) out.c_str(), rsa, RSA_PKCS1_OAEP_PADDING);

}
void MyRsa::DeCrypt(RSA *rsa,string in,string &out){

    size_t outl= RSA_private_decrypt(in.length(), reinterpret_cast<const unsigned char *>(in.c_str()),
            (unsigned char *) out.c_str(), rsa, RSA_PKCS1_OAEP_PADDING);
}
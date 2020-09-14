//
// Created by Administrator on 2020/9/14.
//

#include "MyMd5.h"

#include <string>
void MyMd5::Mymd5Encode(char *charPtr, int dataLen , unsigned char *md5) {
    MD5_CTX ctx;//context
//   char *idata = const_cast<char *>(hello.c_str());
    memset(&ctx, 0, sizeof(ctx));
    MD5_Init(&ctx);
    MD5_Update(&ctx, charPtr, dataLen);
    MD5_Final(md5, &ctx);
}

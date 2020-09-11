
 # 工程说明

 1、下载openssl 1.1.1 版本进行交叉编译

 2、提供ubuntu 编译脚本 openssl_cross_compilation.sh  其他平台参考  INSTALL NOTES.ANDROID

 3、本工程 提供 国密 sm2/sm3/sm4 、RSA 、AES、MD5 、BASE64 加密算法

 4、其他算法，可以参考源码  openssl/crypto/

 5、其中sm2 /sm3 /sm4 通过evp.h 调用


参考链接：
- [官方openssl](https://github.com/openssl/openssl/tree/master/crypto)





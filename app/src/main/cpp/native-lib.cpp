#include <jni.h>
#include <string>
#include <iostream>
#include "/openssl/crypto.h"
#include "/openssl/md5.h"
#include "/openssl/aes.h"
#include <android/log.h>
#include "/openssl/bio.h"
#include "/openssl/pem.h"
#include "/openssl/rsa.h"
#include "/openssl/aes.h"

using namespace std;
#define AES_BITS 128
#define MSG_LEN 128
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"JNI",__VA_ARGS__)
typedef unsigned char uint8;
typedef unsigned long uint32;

jbyteArray getMd5Array(JNIEnv *env, const jbyteArray *_jbyte);

//char *  test_base64(string msg);
void testRSA();

void testAES();

uint32 base64_encode(const uint8 *text, uint32 text_len, uint8 *encode);

uint32 base64_decode(const uint8 *code, uint32 code_len, uint8 *plain);


void testBase();

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniMd5(
        JNIEnv *env,
        jobject /* this */, jbyteArray _jbyte) {

    jbyteArray byteArray = getMd5Array(env, &_jbyte);

    return byteArray;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniBase64(JNIEnv *env, jobject thiz,
                                                          jstring clear_text) {
    // TODO: implement getJniBase64()


    const char *tempStr = env->GetStringUTFChars(clear_text, 0);
    // char * result =test_base64(tempStr);

    testBase();

    char input[256];
    strncpy(input, tempStr, strlen(tempStr) + 1);


    uint8 *text = (uint8 *) input;
    uint32 text_len = (uint32) strlen((char *) text);
    uint8 buffer[1024], buffer2[4096];

    uint32 encode_size = base64_encode(text, text_len, buffer);
    LOGE("encode:size %ld\n", encode_size);
   // buffer[encode_size] = 0;
    LOGE("encode: %s\n", buffer);
    uint32 decode_size = base64_decode(buffer, encode_size, buffer2);
   // buffer2[decode_size] = 0;
    LOGE("decode:size %ld\n", decode_size);
    LOGE("decode: %s\n", buffer2);


    return env->NewStringUTF(reinterpret_cast<const char *>(buffer));
}

void testBase() {
    //char []与char *之间转换

    // char []转char *：直接进行赋值即可

    // char[] 转char *
    char str[] = "lala";
    char *str1 = str;
    cout << str1 << endl;

    // char *转char[]：字符拷贝实现，不能进行赋值操作

    // char *转换为char []
    const char *st = "hehe";
    char st1[] = "lalalala";
    strncpy(st1, st, strlen(st) + 1); // 注意加1操作
    // tp = temp; //错误，不能实现
    cout << st1 << endl;

    // char 与const char 之间转换
    // const char 转char ：拷贝实现，不能进行赋值
    // const char *转char *
    const char *st2 = "lala";
    // 直接赋值不可以
    //char *st1 = st; // （不可以编译器报错）
    //cout << st1 << endl;
    // 另外开辟空间，将字符一个一个复制过去
    char *ncstr = new char[strlen(st2) + 1];
    strcpy(ncstr, st2);
    cout << ncstr << endl;

    // char 转const char ：直接进行赋值

    // char *转const char *
    char *st3 = "hehe"; // （编译提示警告）
    const char *st4 = st3;
    cout << st4 << endl;

    //  char *与string之间转换

    //char *转string：1）直接赋值；2）构造转换实现

    // char*转换为string
    // （注意，定义char *变量，并直接赋值，最好定义为const变量，否则编译器警告）
    const char *st5 = "hello";
    // 赋值转换
    string st6 = st5;
    cout << st6 << endl;
    // 构造转换
    string s1(st, st + strlen(st));
    cout << s1 << endl;
    // 改变const char *变量值
    st = "lalala";
    cout << st << endl;

    // string转char *：赋值操作（注意类型转换）

    // string转char *
    string st7 = "My test";
    //char *st1 = st; // 错误类型不同
    //char *st1 = st.c_str(); // 错误类型不同
    char *st8 = const_cast<char *>(st7.c_str());
    cout << st8 << endl;

    //char[]与string之间转换

    //char []转string：1）直接赋值；2）构造转换实现

    // char[]转换为string
    char st9[] = "hello";
    // 直接赋值实现
    string st10 = st9;
    cout << st10 << endl;
    // 构造实现
    string st11(st, st + strlen(st9));
    cout << st11 << endl;

    //string转char[]：拷贝实现，不能直接赋值

    // string转char []
    string ts = "My test1";
    //char ts1[] = ts; // 错误
    //char ts1[] = const_cast<char *>(ts.c_str()); // 错误
    char ts1[] = "lalallalalaaaa";
    strncpy(ts1, ts.c_str(), ts.length() + 1); // 注意，一定要加1，否则没有赋值'\0'
    cout << ts1 << endl;
}


int aes_encrypt(char *in, char *key, char *out)//, int olen)可能会设置buf长度
{
    if (!in || !key || !out) return 0;
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
        iv[i] = 0;
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return 0;
    }
    int len = strlen(in);//这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话

    //那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度

    //至于解密也是一个道理，光以'\0'来判断字符串长度，确有不妥，后面都是一个道理。
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, len, &aes, iv, AES_ENCRYPT);
    return 1;
}

int aes_decrypt(char *in, char *key, char *out) {
    if (!in || !key || !out) return 0;
    unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
        iv[i] = 0;
    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return 0;
    }
    int len = strlen(in);
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, len, &aes, iv, AES_DECRYPT);
    return 1;
}


void testAES() {

    char sourceStringTemp[MSG_LEN];
    char dstStringTemp[MSG_LEN];
    memset((char *) sourceStringTemp, 0, MSG_LEN);
    memset((char *) dstStringTemp, 0, MSG_LEN);
    strcpy((char *) sourceStringTemp, "hello world");
    //strcpy((char*)sourceStringTemp, argv[1]);

    char key[AES_BLOCK_SIZE];
    int i;
    for (i = 0; i < 16; i++)//可自由设置密钥
    {
        key[i] = 32 + i;
    }
    if (!aes_encrypt(sourceStringTemp, key, dstStringTemp)) {
        LOGE("encrypt error\n");

    }
    LOGE("加密后长度 %d:", strlen((char *) dstStringTemp));
    LOGE("加密 %s\n", dstStringTemp);
    for (i = 0; dstStringTemp[i]; i += 1) {
        // LOGE("%x", (unsigned char) dstStringTemp[i]);
    }
    memset((char *) sourceStringTemp, 0, MSG_LEN);
    if (!aes_decrypt(dstStringTemp, key, sourceStringTemp)) {
        LOGE("decrypt error\n");

    }
    LOGE("解密后长度 %d:", strlen((char *) sourceStringTemp));
    LOGE("解密 %s", sourceStringTemp);
    for (i = 0; sourceStringTemp[i]; i += 1) {
        // LOGE("%x", (unsigned char) sourceStringTemp[i]);
    }
}


void testRSA() {


    LOGE("\nRSA_generate_key_ex TESTING...\n\n");
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne = BN_new();
    ret = BN_set_word(bne, RSA_F4);
    ret = RSA_generate_key_ex(rsa, 512, bne, NULL);

    unsigned char plain[512] = "Hello world!";
    unsigned char cipper[512] = {0};
    unsigned char newplain[512] = {0};
    size_t outl = 512;
    size_t outl2;
    LOGE("%s\n", plain);
    for (int i = 0; i < strlen((char *) plain); i++) {
        LOGE("%02x ", plain[i]);
    }
    outl = RSA_public_encrypt(strlen((char *) plain), plain, cipper, rsa, RSA_PKCS1_OAEP_PADDING);
    for (int i = 0; i < outl; i++) {
        LOGE("%02x ", cipper[i]);
        if ((i + 1) % 10 == 0) printf("\n");
    }
    outl2 = RSA_private_decrypt(outl, cipper, newplain, rsa, RSA_PKCS1_OAEP_PADDING);
    LOGE("----\n%s\n", newplain);
    for (int i = 0; i < outl2; i++) {
        LOGE("%02x ", newplain[i]);
    }
    RSA_free(rsa);


}


jbyteArray getMd5Array(JNIEnv *env, const jbyteArray *_jbyte) {
    char *charPtr;
    jsize dataLen = env->GetArrayLength(*_jbyte);
    jbyte *bytePtr = env->GetByteArrayElements(*_jbyte, JNI_FALSE);
    if (dataLen > 0) {
        charPtr = (char *) malloc(dataLen + 1); //"\0"
        memcpy(charPtr, bytePtr, dataLen);
        charPtr[dataLen] = 0;
        std::string st1 = charPtr;
        LOGE("chris getMd5Array ：%s", st1.c_str());
    }

    MD5_CTX ctx;//context
//char *idata = const_cast<char *>(hello.c_str());
    unsigned char md5[16];
    memset(&ctx, 0, sizeof(ctx));
    MD5_Init(&ctx);
    MD5_Update(&ctx, charPtr, dataLen);
    MD5_Final(md5, &ctx);
    int i;
    for (i = 0; i < dataLen; i++) {
        // LOGE("chris ：%02x", md5[i]);
    }
    //std::string str = (char *) md5;
// LOGE("chris :%s", str.c_str());

    env->ReleaseByteArrayElements(*_jbyte, bytePtr, 0);

    // 转为baidu byte[] 返回zhidao
    int length = sizeof(md5) / sizeof(char);
    jbyteArray byteArray = env->NewByteArray(length);
    env->SetByteArrayRegion(byteArray, 0, length, (jbyte *) md5);
    return byteArray;
}

//char *  test_base64(string msg) {
// const char *p = msg.c_str();
// char *encode_result = base64Encode(p, strlen(p), false);
// LOGE("chris base64 encode:\t%s", encode_result);
//char *decode_result = base64Decode(encode_result, strlen(encode_result), false);
//LOGE("chris base64 decode:\t%s", decode_result);
// return encode_result;
//}



extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniRSA(JNIEnv *env, jobject thiz,
                                                       jstring clear_text) {
    // TODO: implement getJniRSA()

    testRSA();


}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniAES(JNIEnv *env, jobject thiz,
                                                       jstring clear_text) {
    testAES();
}


static uint8 alphabet_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8 reverse_map[] =
        {
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
                255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
                255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255
        };

uint32 base64_encode(const uint8 *text, uint32 text_len, uint8 *encode) {
    uint32 i, j;
    for (i = 0, j = 0; i + 3 <= text_len; i += 3) {
        encode[j++] = alphabet_map[text[i]
                >> 2];                             //取出第一个字符的前6位并找出对应的结果字符
        encode[j++] = alphabet_map[((text[i] << 4) & 0x30) |
                                   (text[i + 1] >> 4)];     //将第一个字符的后2位与第二个字符的前4位进行组合并找到对应的结果字符
        encode[j++] = alphabet_map[((text[i + 1] << 2) & 0x3c) |
                                   (text[i + 2] >> 6)];   //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符
        encode[j++] = alphabet_map[text[i + 2] & 0x3f];                         //取出第三个字符的后6位并找出结果字符
    }

    if (i < text_len) {
        uint32 tail = text_len - i;
        if (tail == 1) {
            encode[j++] = alphabet_map[text[i] >> 2];
            encode[j++] = alphabet_map[(text[i] << 4) & 0x30];
            encode[j++] = '=';
            encode[j++] = '=';
        } else //tail==2
        {
            encode[j++] = alphabet_map[text[i] >> 2];
            encode[j++] = alphabet_map[((text[i] << 4) & 0x30) | (text[i + 1] >> 4)];
            encode[j++] = alphabet_map[(text[i + 1] << 2) & 0x3c];
            encode[j++] = '=';
        }
    }
    return j;
}

uint32 base64_decode(const uint8 *code, uint32 code_len, uint8 *plain) {
    assert((code_len & 0x03) == 0);  //如果它的条件返回错误，则终止程序执行。4的倍数。

    uint32 i, j = 0;
    uint8 quad[4];
    for (i = 0; i < code_len; i += 4) {
        for (uint32 k = 0; k < 4; k++) {
            quad[k] = reverse_map[code[i + k]];//分组，每组四个分别依次转换为base64表内的十进制数
        }

        assert(quad[0] < 64 && quad[1] < 64);

        plain[j++] = (quad[0] << 2) |
                     (quad[1] >> 4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的前2位进行组合

        if (quad[2] >= 64)
            break;
        else if (quad[3] >= 64) {
            plain[j++] = (quad[1] << 4) |
                         (quad[2] >> 2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应base64表的十进制数的前4位进行组合
            break;
        } else {
            plain[j++] = (quad[1] << 4) | (quad[2] >> 2);
            plain[j++] = (quad[2] << 6) | quad[3];//取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合}
        }
    }
    return j;
}
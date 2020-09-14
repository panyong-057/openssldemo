#include <jni.h>
#include <string>
#include <iostream>
#include "/include/openssl/rsa.h"
#include "macro.h"
#include "/sm/MySm2.h"
#include "/sm/MySm3.h"
#include "/sm/MySm4.h"
#include "/encrypt/MyAes.h"
#include "/encrypt/MyMd5.h"
#include "/encrypt/MyRsa.h"

#if defined(OPENSSL_VERSION_NUMBER) \
 && OPENSSL_VERSION_NUMBER < 0x10101001L
static const EVP_CIPHER *(*EVP_sm4_ecb)()=EVP_aes_128_ecb;
#endif
typedef struct {
    const unsigned char *in_data;
    size_t in_data_len;
    int in_data_is_already_padded;
    const unsigned char *in_ivec;
    const unsigned char *in_key;
    size_t in_key_len;
} test_case_t;


using namespace std;
typedef unsigned char uint8;
typedef unsigned long uint32;

jbyteArray getMd5Array(JNIEnv *env, const jbyteArray *_jbyte);

//char *  test_base64(string msg);
void testRSA();

void testAES();

uint32 base64_encode(const uint8 *text, uint32 text_len, uint8 *encode);

uint32 base64_decode(const uint8 *code, uint32 code_len, uint8 *plain);


void testBase();

void getsm3();

void getsm4();

void getsm2();


//字节数组转换为HEX 字符串
 string Byte2HexString(unsigned char *bytes, const int length) {

        if (bytes == NULL) {
            return "";
        }
        std::string buff;
        const int len = length;
        for (int j = 0; j < len; j++) {
            /*if ((bytes[j] & 0xff) < 16) {
                buff.append("0");
            }*/
            int high = bytes[j]/16, low = bytes[j]%16;
            buff += (high<10) ? ('0' + high) : ('a' + high - 10);
            buff += (low<10) ? ('0' + low) : ('a' + low - 10);
        }
        return buff;
}

void hexToBytes(const std::string& hex,unsigned char *bytes)
{
    int bytelen = hex.length() / 2;
    std::string strByte;
    unsigned int n;
    for (int i = 0; i < bytelen; i++)
    {
        strByte = hex.substr(i * 2, 2);
        sscanf(strByte.c_str(),"%x",&n);
        bytes[i] = n;
    }
}


extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniMd5(
        JNIEnv *env,
        jobject /* this */, jbyteArray _jbyte) {

    jbyteArray byteArray = getMd5Array(env, &_jbyte);
    getsm2();
    getsm3();
    getsm4();
    testAES();
    testRSA();
    return byteArray;
}


void getsm2() {
    MySm2 *sm2 = new MySm2;
    string priKey;
    string pubKey;
    sm2->GenEcPairKey(priKey, pubKey);
    LOGE("getsm2  priKey = %s pubKey = %s ", priKey.c_str(), pubKey.c_str());

    string clear_str = "da jiang wu ren ji";
    string en_str;
    int en_len;
    sm2->Encrypt(clear_str, clear_str.length(), en_str, en_len, pubKey);
    LOGE("getsm2  en_str = %s len = %d ", en_str.c_str(), en_len);
    string de_str;
    int de_len;
    sm2->Decrypt(en_str, en_len, de_str, de_len, priKey);
    LOGE("getsm2  de_str = %s de_len = %d ", de_str.c_str(), de_len);

    DELETE(sm2)
}


void getsm4() {

    MySm4 *mySm4 = new MySm4;

    unsigned char key[32] = "11111111";
    unsigned char iv[16] = {0};

    int MSG_LEN = 128;
    char inStr[MSG_LEN];

    memset((char *) inStr, 0, MSG_LEN);
    strcpy((char *) inStr, "hello world");

    //unsigned char *inStr = "this is test string";
    int inLen = strlen(inStr);
    int encLen = 0;
    int outlen = 0;
    unsigned char encData[1024];

    LOGE("sm4 source: %s", inStr);
    mySm4->enCode(key, iv, inStr, inLen, encLen, outlen, encData);

    //解密
    int decLen = 0;
    outlen = 0;
    unsigned char decData[1024];
    mySm4->deCode(key, iv, encLen, outlen, encData, decLen, decData);


}


void getsm3() {


    MySm3 *mySm3 = new MySm3;


    const unsigned char input_str[] = {'a', 'b', 'c', 0};
    unsigned int input_str_len = strlen((char *) input_str);

    unsigned char out_hash_value[64];
    unsigned int out_hash_len;

    mySm3->sm3_hash(input_str, input_str_len, out_hash_value, &out_hash_len);
    LOGE(" sm3 data: %s", input_str);
    LOGE(" sm3 length: %d", out_hash_len);
    out_hash_value[out_hash_len] = 0;
    LOGE(" sm3 value: %s", Byte2HexString(out_hash_value, out_hash_len).c_str());
    LOGE(" sm3 value: %s", out_hash_value);

    DELETE(mySm3)

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
    // LOGE("base64 encode:size %ld", encode_size);
    buffer[encode_size] = 0;
    // LOGE(" base64 encode %s ", buffer);;
    uint32 decode_size = base64_decode(buffer, encode_size, buffer2);
    buffer2[decode_size] = 0;
    //LOGE("base64 decode_size:%ld", decode_size);


    LOGE("base64 decode %s ", buffer2);

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


void testAES() {

    MyAes *myAes = new MyAes;

    int MSG_LEN = 128;
    char sourceStringTemp[MSG_LEN];
    unsigned char dstStringTemp[MSG_LEN];
    memset((char *) sourceStringTemp, 0, MSG_LEN);
    memset((char *) dstStringTemp, 0, MSG_LEN);
    strcpy((char *) sourceStringTemp, "wu yan zu");
    //strcpy((char*)sourceStringTemp, argv[1]);

    char key[AES_BLOCK_SIZE];
    int i;
    for (i = 0; i < 16; i++)//可自由设置密钥
    {
        key[i] = 32 + i;
    }
    myAes->aes_encrypt(sourceStringTemp, key, dstStringTemp);

    LOGE("AES encrypt len %d:", strlen((char *) dstStringTemp));


    LOGE("AES encrypt %s", dstStringTemp);
    int len = strlen((char *) dstStringTemp);
    string string1 = Byte2HexString(dstStringTemp, len);
    LOGE("AES encrypt %s", string1.c_str());


    for (i = 0; dstStringTemp[i]; i += 1) {
        // LOGE("%x", (unsigned char) dstStringTemp[i]);
    }
    memset((char *) sourceStringTemp, 0, MSG_LEN);
    myAes->aes_decrypt(dstStringTemp, key, sourceStringTemp);

    LOGE("AES decrypt len %d:", strlen((char *) sourceStringTemp));
    LOGE("AES decrypt %s", sourceStringTemp);
    for (i = 0; sourceStringTemp[i]; i += 1) {
        // LOGE("%x", (unsigned char) sourceStringTemp[i]);
    }
}


void testRSA() {
    auto * myRsa =new MyRsa;

    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne = BN_new();
    ret = BN_set_word(bne, RSA_F4);
    ret = RSA_generate_key_ex(rsa, 512, bne, NULL);
    //PEM_read_bio_RSAPrivateKey()
    //unsigned char plain[1021] = "cai xv kun";
    string str_in="xiaoyuer";
    unsigned char cipper[512] = {0};

    unsigned char newplain[512] = {0};
    size_t outl = 512;
    size_t outl2;
    LOGE("RSA %s", str_in.c_str());
    outl = RSA_public_encrypt(str_in.length(),
                              reinterpret_cast<const unsigned char *>(str_in.c_str()), cipper, rsa, RSA_PKCS1_OAEP_PADDING);
    int len = strlen((char *) cipper);
    LOGE("RSA encrypt %s", cipper);
    string string1 = Byte2HexString(cipper, len);
    LOGE("RSA encrypt %s", string1.c_str());
    outl2 = RSA_private_decrypt(outl, cipper, newplain, rsa, RSA_PKCS1_OAEP_PADDING);
    LOGE("RSA decrypt %s", newplain);
    RSA_free(rsa);

}


jbyteArray getMd5Array(JNIEnv *env, const jbyteArray *_jbyte) {
    char *charPtr = nullptr;
    jsize dataLen = env->GetArrayLength(*_jbyte);
    jbyte *bytePtr = env->GetByteArrayElements(*_jbyte, JNI_FALSE);
    if (dataLen > 0) {
        charPtr = (char *) malloc(dataLen + 1); //"\0"
        memcpy(charPtr, bytePtr, dataLen);
        charPtr[dataLen] = 0;
        std::string st1 = charPtr;
        LOGE("chris getMd5Array ：%s", st1.c_str());
    }

    unsigned char md5[16];

    MyMd5 *myMd5 = new MyMd5;

    myMd5->Mymd5Encode(charPtr, dataLen, md5);


    // 转为baidu byte[] 返回zhidao
    int length = sizeof(md5) / sizeof(char);

    LOGE("md5：%s", md5);
    LOGE("md5：len %s",Byte2HexString(md5,length).c_str());
    env->ReleaseByteArrayElements(*_jbyte, bytePtr, 0);

    jbyteArray byteArray = env->NewByteArray(length);
    env->SetByteArrayRegion(byteArray, 0, length, (jbyte *) md5);
    return byteArray;
}


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

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniSM2(JNIEnv *env, jobject thiz,
                                                       jstring clear_text) {
    // TODO: implement getJniSM2()

    getsm2();
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniSM3(JNIEnv *env, jobject thiz,
                                                       jstring clear_text) {
    getsm3();
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jin_ende_1test_MainActivity_getJniSM4(JNIEnv *env, jobject thiz,
                                                       jstring clear_text) {
    getsm4();
}
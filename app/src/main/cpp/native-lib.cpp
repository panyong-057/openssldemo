#include <jni.h>
#include <string>
#include <iostream>
#include "/include/openssl/crypto.h"
#include "/include/openssl/md5.h"
#include "/include/openssl/aes.h"
#include "include/openssl/evp.h"
#include "include/openssl/ec.h"
#include "include/openssl/err.h"
#include <android/log.h>
#include <include/openssl/obj_mac.h>
#include "/include/openssl/bio.h"
#include "/include/openssl/pem.h"
#include "/include/openssl/rsa.h"
#include "/include/openssl/aes.h"
#include "SM3.h"
#include "/include/openssl/pem.h"
#include "/include/openssl/ossl_typ.h"
#include "/include/openssl/bio.h"

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

int sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash,
             unsigned int *hash_len);

void testBase();

void getsm3();

void getsm4();

void getsm2();

//字节数组转换为HEX 字符串
const string Byte2HexString(const unsigned char *input, const int datasize) {
    char output[datasize * 2];
    for (int j = 0; j < datasize; j++) {
        unsigned char b = *(input + j);
        snprintf(output + j * 2, 3, "%02x", b);
    }
    return string(output);
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


class SM2 {
private:

    // 通过公钥/私钥返回EVP_PKEY
    // key pem格式
    // is_public
    // out_ecKey
    static bool CreateEVP_PKEY(unsigned char *key, int is_public, EVP_PKEY **out_ecKey);

public:

    // 根据私钥计算出公钥
    bool PriKey2PubKey(string in_priKey, string &out_pubKey);

    //生成EC秘钥对
    //pem格式的私钥
    //pem格式的公钥
    int GenEcPairKey(string &out_priKey, string &out_pubKey);


    // 签名 私钥加密 0成功
    // in_buf 待签名数据
    // in_buflen 长度
    // out_sig 签名后数据
    // len_sig 签名数据长度
    // priKey 私钥pem格式

    int Sign(string in_buf, int in_buflen, string &out_sig, int &len_sig, string priKey);


    // 验签 公钥解密 0成功
    // in_buf 待验签数据 明文
    // buflen 数据长度
    // sig 签名数据
    // siglen 签名数据长度
    // pubkey 公钥
    // keylen 公钥长度
    int Verify(string in_buf, const int buflen, string sig, const int siglen,
               string pubkey, const int keylen);


    // 加密 公钥加密 0成功

    // in_buf
    // in_buflen
    // out_encrypted
    // len_encrypted
    // pubKey pem格式公钥

    int
    Encrypt(string in_buf, int in_buflen, string &out_encrypted, int &len_encrypted, string pubKey);


    // 解密 私钥解密 0成功

    // in_buf
    // in_buflen
    // out_plaint
    // len_plaint
    // prikey pem格式私钥

    int Decrypt(string in_buf, int in_buflen, string &out_plaint, int &len_plaint, string prikey);
};

void getsm2() {
    SM2 *sm2 = new SM2;
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
}

inline int SM2::GenEcPairKey(string &out_priKey, string &out_pubKey) {
    EC_KEY *ecKey;
    EC_GROUP *ecGroup;
    int ret_val = -1;
    if (NULL == (ecKey = EC_KEY_new())) {
        return -1;
    }

    if (NULL == (ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))) {
        EC_KEY_free(ecKey);
        return -2;
    }

    if (EC_KEY_set_group(ecKey, ecGroup) != 1) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return -3;
    }

    if (!EC_KEY_generate_key(ecKey)) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return -3;
    }

    //可以从EC_KEY类型返回char*数组
    size_t pri_len;
    size_t pub_len;
    char *pri_key = NULL;
    char *pub_key = NULL;

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = new char[pri_len + 1];
    pub_key = new char[pub_len + 1];

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pubKey = pub_key;
    out_priKey = pri_key;

    BIO_free_all(pub);
    BIO_free_all(pri);
    delete[] pri_key;
    delete[] pub_key;
    EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return 0;
}

inline bool SM2::CreateEVP_PKEY(unsigned char *key, int is_public, EVP_PKEY **out_pKey) {
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed.\n");
        return false;
    }

    if (is_public) {
        //*out_ecKey = PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
        *out_pKey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
    } else {
        //*out_ecKey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
        *out_pKey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    }

    if (*out_pKey == NULL) {
        LOGE("Failed to Get Key");
        BIO_free(keybio);
        return false;
    }

    BIO_free(keybio);
    return true;
}

inline bool SM2::PriKey2PubKey(string in_priKey, string &out_pubKey) {
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(in_priKey.c_str(), -1);

    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed.\n");
        return false;
    }

    EC_KEY *ecKey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    if (ecKey == NULL) {
        LOGE("PEM_read_bio_ECPrivateKey failed.");
        BIO_free(keybio);
        return false;
    }

    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(pub, ecKey);
    int pub_len = BIO_pending(pub);
    char *pub_key = new char[pub_len + 1];
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';

    out_pubKey = pub_key;

    delete[] pub_key;
    BIO_free(pub);
    BIO_free(keybio);
    return true;
}

inline int SM2::Sign(string in_buf, int in_buflen, string &out_sig, int &len_sig, string priKey) {
    int ret_val = 0;
    //通过私钥得到EC_KEY
    EC_KEY *eckey = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(priKey.c_str(), -1);
    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed\n");
        return -1;
    }
    eckey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    if (eckey == NULL) {
        LOGE("PEM_read_bio_ECPrivateKey failed\n");
        BIO_free(keybio);
        return -2;
    }

    unsigned char szSign[256] = {0};
    if (1 != ECDSA_sign(0, (const unsigned char *) in_buf.c_str(), in_buflen, szSign,
                        (unsigned int *) &len_sig, eckey)) {
        LOGE("ECDSA_sign failed\n");
        ret_val = -3;
    } else {
        out_sig = string((char *) szSign, len_sig);
        ret_val = 0;
    }
    BIO_free(keybio);
    EC_KEY_free(eckey);
    return ret_val;
}

inline int SM2::Verify(string in_buf, const int buflen, string sig, const int siglen,
                       string pubkey, const int keylen) {
    int ret_val = 0;
    //通过公钥得到EC_KEY
    EC_KEY *eckey = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(pubkey.c_str(), -1);
    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed\n");
        return -1;
    }
    eckey = PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
    if (eckey == NULL) {
        LOGE("PEM_read_bio_EC_PUBKEY failed\n");
        BIO_free(keybio);
        return -2;
    }
    if (1 != ECDSA_verify(0, (const unsigned char *) in_buf.c_str(), buflen,
                          (const unsigned char *) sig.c_str(), siglen, eckey)) {
        LOGE("ECDSA_verify failed\n");
        ret_val = -3;
    } else {
        ret_val = 0;
    }
    BIO_free(keybio);
    EC_KEY_free(eckey);

    return ret_val;
}


inline int SM2::Encrypt(string in_buf, int in_buflen, string &out_encrypted, int &len_encrypted,
                        string pubKey) {
    int ret = -1, i;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key_pair = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len, plaintext_len;

    CreateEVP_PKEY((unsigned char *) pubKey.c_str(), 1, &pkey);

    /* compute SM2 encryption */
    if ((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1) {
        LOGE("EVP_PKEY_set_alias_type failed.");
        goto clean_up;
    }

    if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        LOGE("EVP_PKEY_CTX_new failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt_init(ectx)) != 1) {
        LOGE("EVP_PKEY_encrypt failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt(ectx, NULL, &ciphertext_len, (const unsigned char *) in_buf.c_str(),
                          in_buflen)) != 1) {
        LOGE("EVP_PKEY_set_alias_type failed.");
        goto clean_up;
    }

    if (!(ciphertext = (unsigned char *) malloc(ciphertext_len))) {
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt(ectx, ciphertext, &ciphertext_len, (const unsigned char *) in_buf.c_str(),
                          in_buflen)) != 1) {
        LOGE("EVP_PKEY_encrypt failed.");
        goto clean_up;
    }
    out_encrypted = string((char *) ciphertext, ciphertext_len);
    len_encrypted = ciphertext_len;
    ret = 0;
    clean_up:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ectx) {
        EVP_PKEY_CTX_free(ectx);
    }

    if (ciphertext) {
        free(ciphertext);
    }

    return ret;
}

inline int
SM2::Decrypt(string in_buf, int in_buflen, string &out_plaint, int &len_plaint, string prikey) {
    int ret = -1, i;
    EVP_PKEY_CTX *pctx = NULL, *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key_pair = NULL;
    unsigned char *plaintext = NULL;
    size_t ciphertext_len, plaintext_len;

    CreateEVP_PKEY((unsigned char *) prikey.c_str(), 0, &pkey);

    if ((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1) {
        LOGE("EVP_PKEY_set_alias_type failed.");
        goto clean_up;
    }

    if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        LOGE("EVP_PKEY_CTX_new failed.");
        goto clean_up;
    }

    /* compute SM2 decryption */
    if ((EVP_PKEY_decrypt_init(ectx)) != 1) {
        LOGE("EVP_PKEY_decrypt_init failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_decrypt(ectx, NULL, &plaintext_len, (const unsigned char *) in_buf.c_str(),
                          in_buflen)) != 1) {
        LOGE("EVP_PKEY_decrypt failed.");
        goto clean_up;
    }

    if (!(plaintext = (unsigned char *) malloc(plaintext_len))) {
        goto clean_up;
    }

    if ((EVP_PKEY_decrypt(ectx, plaintext, &plaintext_len, (const unsigned char *) in_buf.c_str(),
                          in_buflen)) != 1) {
        LOGE("EVP_PKEY_decrypt failed.");
        goto clean_up;
    }
    out_plaint = string((char *) plaintext, plaintext_len);
    len_plaint = plaintext_len;
    ret = 0;
    clean_up:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ectx) {
        EVP_PKEY_CTX_free(ectx);
    }

    if (plaintext) {
        free(plaintext);
    }

    return ret;
}


void getsm4() {


    unsigned char key[32] = "11111111";
    unsigned char iv[16] = {0};

    char inStr[MSG_LEN];

    memset((char *) inStr, 0, MSG_LEN);
    strcpy((char *) inStr, "hello world");

    //unsigned char *inStr = "this is test string";
    int inLen = strlen(inStr);
    int encLen = 0;
    int outlen = 0;
    unsigned char encData[1024];

    LOGE("sm4 source: %s", inStr);

    //加密
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv, 1);
    EVP_CipherUpdate(ctx, encData, &outlen, reinterpret_cast<const unsigned char *>(inStr), inLen);
    encLen = outlen;
    EVP_CipherFinal(ctx, encData + outlen, &outlen);
    encLen += outlen;
    EVP_CIPHER_CTX_free(ctx);
    LOGE(" sm4 value: %s", Byte2HexString(encData, encLen).c_str());
    LOGE("sm4 encrypt: %s\n", encData);
    //解密
    int decLen = 0;
    outlen = 0;
    unsigned char decData[1024];
    EVP_CIPHER_CTX *ctx2;
    ctx2 = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx2, EVP_sm4_ecb(), NULL, key, iv, 0);
    EVP_CipherUpdate(ctx2, decData, &outlen, encData, encLen);
    decLen = outlen;
    EVP_CipherFinal(ctx2, decData + outlen, &outlen);
    decLen += outlen;
    EVP_CIPHER_CTX_free(ctx2);

    decData[decLen] = '\0';
    LOGE("sm4 decrypt: %s\n", decData);


}


void getsm3() {


    SM3 *sm3 =new SM3;





    const unsigned char input_str[] = {'a', 'b', 'c', 0};
    unsigned int input_str_len = strlen((char *) input_str);
    const unsigned char sample2[] = {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                     0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};
    unsigned int sample2_len = sizeof(sample2);
    unsigned char out_hash_value[64];
    unsigned int out_hash_len;

    sm3_hash(input_str, input_str_len, out_hash_value, &out_hash_len);
    LOGE(" sm3 data: %s", input_str);
    //LOGE(" sm3 length: %d", out_hash_len);
    out_hash_value[out_hash_len] = 0;
    LOGE(" sm3 value: %s", Byte2HexString(out_hash_value, out_hash_len).c_str());
    // LOGE(" sm3 value: %s", out_hash_value);


//     sm3_hash(sample2, sample2_len, hash_value, &hash_len);


//    LOGE("sample2 raw data%s:",sample2);
//    LOGE("sample2 hash length: %d bytes.", hash_len);
//    LOGE("sample2 hash value%s:",hash_value);


}


int sm3_hash(const unsigned char *message, unsigned int len, unsigned char *hash,
             unsigned int *hash_len) {
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;

    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, message, len);
    EVP_DigestFinal_ex(md_ctx, hash, hash_len);
    EVP_MD_CTX_free(md_ctx);
    return 0;
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
    strcpy((char *) sourceStringTemp, "wu yan zu");
    //strcpy((char*)sourceStringTemp, argv[1]);

    char key[AES_BLOCK_SIZE];
    int i;
    for (i = 0; i < 16; i++)//可自由设置密钥
    {
        key[i] = 32 + i;
    }
    if (!aes_encrypt(sourceStringTemp, key, dstStringTemp)) {
        LOGE("encrypt error");

    }
    LOGE("AES encrypt len %d:", strlen((char *) dstStringTemp));


    LOGE("AES encrypt %s", dstStringTemp);
    int len = strlen((char *) dstStringTemp);
    string string1 = Byte2HexString(reinterpret_cast<const unsigned char *>(dstStringTemp), len);
    LOGE("RSA encrypt %s", string1.c_str());


    for (i = 0; dstStringTemp[i]; i += 1) {
        // LOGE("%x", (unsigned char) dstStringTemp[i]);
    }
    memset((char *) sourceStringTemp, 0, MSG_LEN);
    if (!aes_decrypt(dstStringTemp, key, sourceStringTemp)) {
        LOGE("decrypt error\n");

    }
    LOGE("AES decrypt len %d:", strlen((char *) sourceStringTemp));
    LOGE("AES decrypt %s", sourceStringTemp);
    for (i = 0; sourceStringTemp[i]; i += 1) {
        // LOGE("%x", (unsigned char) sourceStringTemp[i]);
    }
}


void testRSA() {

    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne = BN_new();
    ret = BN_set_word(bne, RSA_F4);
    ret = RSA_generate_key_ex(rsa, 512, bne, NULL);

    //PEM_read_bio_RSAPrivateKey()


    unsigned char plain[512] = "cai xv kun";
    unsigned char cipper[512] = {0};
    unsigned char newplain[512] = {0};
    size_t outl = 512;
    size_t outl2;
    LOGE("RSA %s", plain);
//    for (int i = 0; i < strlen((char *) plain); i++) {
//        LOGE("%02x ", plain[i]);
//    }
    outl = RSA_public_encrypt(strlen((char *) plain), plain, cipper, rsa, RSA_PKCS1_OAEP_PADDING);
    int len = strlen((char *) cipper);
    LOGE("RSA encrypt %s", cipper);

    string string1 = Byte2HexString(cipper, len);

    LOGE("RSA encrypt %s", string1.c_str());

//    for (int i = 0; i < outl; i++) {
//        LOGE("%02x ", cipper[i]);
//        if ((i + 1) % 10 == 0) printf("\n");
//    }
    outl2 = RSA_private_decrypt(outl, cipper, newplain, rsa, RSA_PKCS1_OAEP_PADDING);


    LOGE("RSA decrypt %s", newplain);
//    for (int i = 0; i < outl2; i++) {
//        LOGE("%02x ", newplain[i]);
//    }
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
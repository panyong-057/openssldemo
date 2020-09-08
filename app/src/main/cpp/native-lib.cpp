#include <jni.h>
#include <string>
#include "/openssl/crypto.h"
#include "/openssl/md5.h"
#include "/openssl/aes.h"
#include <android/log.h>
#include "/openssl/bio.h"
#include "/openssl/pem.h"
#include "/openssl/rsa.h"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"JNI",__VA_ARGS__)

jbyteArray getMd5Array(JNIEnv *env, const jbyteArray *_jbyte);
//char *  test_base64(string msg);
void testRSA();

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


   // const char *  tempStr = env->GetStringUTFChars(clear_text, 0);
    // char * result =test_base64(tempStr);
    char * result="1111";

    testRSA();
    return env->NewStringUTF(result);
}

void testRSA() {


    //5.对内容进行加密

    int result=   RSA_private_decrypt(256, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_PKCS1_PADDING);

    if(result < 0){

    }



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




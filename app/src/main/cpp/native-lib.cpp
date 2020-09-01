#include <jni.h>
#include <string>
#include "/openssl/crypto.h"
#include "/openssl/md5.h"
#include "/openssl/aes.h"
#include <android/log.h>

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"JNI",__VA_ARGS__)
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_jin_ende_1test_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */, jbyteArray _jbyte) {
   // std::string hello = "1234567891234567";
//    return env->NewStringUTF(hello.c_str());
    //jboolean isCopy;
   // jbyte *dataArray = env->GetByteArrayElements(_jbyte, 0);
    //jsize dataLen = env->GetArrayLength(_jbyte);
    // jbyte * arrayBody = env->GetByteArrayElements(data,0);


    char *charPtr;
    jsize dataLen = env->GetArrayLength(_jbyte);
    jbyte *bytePtr = env->GetByteArrayElements(_jbyte, JNI_FALSE);
    if (dataLen > 0) {
        charPtr = (char *) malloc(dataLen + 1); //"\0"
        memcpy(charPtr, bytePtr, dataLen);
        charPtr[dataLen] = 0;
        std::string st1 = charPtr;
        LOGE("chris1 ：%s", st1.c_str());
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

    env->ReleaseByteArrayElements(_jbyte, bytePtr, 0);

    // 转为baidu byte[] 返回zhidao
    int length = sizeof(md5) / sizeof(char);
    jbyteArray byteArray = env->NewByteArray(length);
    env->SetByteArrayRegion(byteArray, 0, length, (jbyte *) md5);

    return byteArray;
}

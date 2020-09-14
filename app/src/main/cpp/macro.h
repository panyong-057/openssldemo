
#ifndef DNPLAYER_MACRO_H
#define DNPLAYER_MACRO_H

#include <android/log.h>


#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"openssl",__VA_ARGS__)

//宏函数
#define DELETE(obj) if(obj){ delete obj; obj = 0; }

//标记线程 因为子线程需要attach
#define THREAD_MAIN 1
#define THREAD_CHILD 2




#endif //DNPLAYER_MACRO_H

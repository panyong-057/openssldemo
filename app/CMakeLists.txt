

cmake_minimum_required(VERSION 3.4.1)

# 创建一个变量 source_file 它的值就是src/main/cpp/ 所有的.cpp文件
file(GLOB source_file src/main/cpp/*.cpp)
file(GLOB source_file_sm src/main/cpp/sm/*.cpp)
file(GLOB source_file_encrypt src/main/cpp/encrypt/*.cpp)

#add_library(
#        native-lib
#        SHARED
#        src/main/cpp/native-lib.cpp)

add_library(
        native-lib
        SHARED
        ${source_file}
        ${source_file_sm}
        ${source_file_encrypt}
        ) #导入所有的cpp文件

#表示把src/main/cpp/include.openssl 加入到include目录，这样在代码中使用：#include <...>就能访问到头文件
include_directories(src/main/cpp/include)  #导入头文件
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__STDC_CONSTANT_MACROS -L${CMAKE_SOURCE_DIR}/src/main/cpp/libs/${ANDROID_ABI}")


#[[#添加两个预编译库
add_library(
        include.openssl-include.crypto
        STATIC
        IMPORTED)

set_target_properties(
        include.openssl-include.crypto
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/src/main/cpp/libs/${ANDROID_ABI}/libcrypto.a)

add_library(
        include.openssl-ssl
        STATIC
        IMPORTED)

set_target_properties(
        include.openssl-ssl
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/src/main/cpp/libs/${ANDROID_ABI}/libssl.a)]]




target_link_libraries(
        native-lib
        ssl
        crypto
        log  z android
        )


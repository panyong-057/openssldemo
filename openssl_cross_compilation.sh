#!/bin/bash
export ANDROID_NDK_HOME=/home/administrator/Downloads/android-ndk-r20b
PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_HOME/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
./Configure android-arm --api=1.1.1 -D__ANDROID_API__=29 --prefix=/home/administrator/Downloads/test1
make clean
make
make install



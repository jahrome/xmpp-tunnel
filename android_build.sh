# New Version !
# See android-ndk-r5/docs/STANDALONE-TOOLCHAIN.html
export NDK=/home/jer/Projet_android/android-ndk-r5
export TOOLCHAIN=/home/jer/standalone-toolchain
export AOSP=/home/jer/cm7
export PRODUCT=vision

$NDK/build/tools/make-standalone-toolchain.sh --platform=android-9 --install-dir=$TOOLCHAIN
export PATH=$TOOLCHAIN/bin/:$PATH
export CC=arm-linux-androideabi-gcc
export CXX=arm-linux-androideabi-g++
export CPPFLAGS="-march=armv7-a -mfloat-abi=softfp -I$AOSP/external/openssl/include -I$AOSP/external/expat/lib -I$AOSP/external/libncurses/include"
export CPPFLAGS="-march=armv7-a -mfloat-abi=softfp -I$AOSP/external/openssl/include -I$AOSP/external/expat/lib -I$AOSP/external/libncurses/include"
export LDFLAGS="-Wl,--fix-cortex-a8 -lsupc++ -L$AOSP/out/target/product/$PRODUCT/system/lib"
export LIBS="$TOOLCHAIN/arm-linux-androideabi/lib/libstdc++.a"
autoreconf
./configure --host=arm-linux-androideabi
make -j2

# Old version
export PATH=$PATH:/home/jer/Projet_android/android-ndk-r5/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/
export CXX=ag++2
./configure --host=arm-eabi --build=i686
make -j2

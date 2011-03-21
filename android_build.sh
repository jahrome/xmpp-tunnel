export PATH=$PATH:/home/jer/Projet_android/android-ndk-r5/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/
export CXX=ag++2
./configure --host=arm-eabi --build=i686
make -j2

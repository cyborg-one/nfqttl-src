cd ./lib/libmnl && ./configure  --enable-static  --includedir=$HOME/Android/Sdk/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include
cd ../../

cd ./lib/libnfnetlink && ./configure  --enable-static  --includedir=$HOME/Android/Sdk/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include
cd ../../

cd ./lib/libnetfilter_queue && ./configure  --enable-static  --includedir=$HOME/Android/Sdk/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include \
        LIBNFNETLINK_LIBS="-L`pwd | sed  's/\/libnetfilter_queue//'`/libnfnetlink/src/.libs" \
        LIBNFNETLINK_CFLAGS="-I`pwd | sed  's/\/libnetfilter_queue//'`/libnfnetlink/include" \
        LIBMNL_LIBS="-L`pwd | sed  's/\/libnetfilter_queue//'`/libmnl/src/.libs" \
        LIBMNL_CFLAGS="-I`pwd | sed  's/\/libnetfilter_queue//'`/libmnl/include"
cd ../../


~/Android/Sdk/ndk/23.1.7779620/ndk-build  NDK_APPLICATION_MK=./Application.mk NDK_PROJECT_PATH=./ -C ./


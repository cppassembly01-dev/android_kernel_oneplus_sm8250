export ARCH=arm64
export SUBARCH=arm64
export CLANG_TRIPLE=aarch64-linux-gnu-
export LLVM=1
export CLANG=/home/akronnos/toolchains/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin
export PATH=$CLANG:$PATH

rm -rf out
make O=out vendor/kona-perf_defconfig vendor/oplus.config
sed -i 's/# CONFIG_KSU_SUSFS is not set/CONFIG_KSU_SUSFS=y/g' out/.config
sed -i 's/# CONFIG_KPM is not set/CONFIG_KPM=y/g' out/.config
make O=out olddefconfig
make O=out -j$(nproc --all)

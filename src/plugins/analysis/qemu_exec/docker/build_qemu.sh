#!/bin/bash

QEMU_VERSION=qemu-3.0.0

cd /opt
mkdir /opt/qemu-targets
wget https://download.qemu.org/${QEMU_VERSION}.tar.xz
tar -xvf ${QEMU_VERSION}.tar.xz
rm ${QEMU_VERSION}.tar.xz
cd ${QEMU_VERSION}

# possible targets: aarch64 alpha arm armeb cris i386 m68k microblaze microblazeel mips mips64 mips64el mipsel mipsn32 mipsn32el or32 ppc ppc64 ppc64abi32 ppc64le s390x sh4 sh4eb sparc sparc32plus sparc64 unicore32 x86_64
CPU_TARGETS="aarch64 alpha arm armeb i386 m68k mips mips64 mips64el mipsel mipsn32 mipsn32el ppc ppc64 ppc64abi32 ppc64le s390x sh4 sh4eb sparc sparc32plus sparc64 x86_64"

for CPU_TARGET in $CPU_TARGETS; do

    echo "[*] Configuring QEMU for $CPU_TARGET..."

    CFLAGS="-O3" ./configure --disable-system --enable-linux-user \
      --disable-gtk --disable-sdl --disable-vnc \
      --target-list="${CPU_TARGET}-linux-user" || exit 1

    echo "[+] Configuration complete."

    echo "[*] Attempting to build QEMU (fingers crossed!)..."

    make -j || exit 1

    echo "[+] Build process successful!"

    echo "[*] Copying binary..."

    cp -f "${CPU_TARGET}-linux-user/qemu-${CPU_TARGET}" "/opt/qemu-targets" || exit 1
done

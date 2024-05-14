#!/bin/bash
SCRIPT_DIR=$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )

set -e
set -v

cd /opt
curl https://download.qemu.org/qemu-8.2.2.tar.xz -o qemu.tar.xz
tar xvJf qemu.tar.xz
mv qemu-8.2.2 qemu
cd qemu
patch -p1 < $SCRIPT_DIR/../qemu-patch.patch
mkdir build
cd build
../configure --target-list=x86_64-softmmu
make -j$(nproc)

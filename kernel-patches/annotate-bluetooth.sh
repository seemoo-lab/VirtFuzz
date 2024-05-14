#!/bin/bash

set -e
set -v

PATCHES_DIR=$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )

if ! git log -- drivers/bluetooth/virtio_bt.c | grep "Bluetooth: virtio_bt: fix memory leak in virtbt_rx_handle()"; then
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/0001-Bluetooth-virtio_bt-fix-memory-leak-in-virtbt_rx_han.patch
fi


if git log -- net/bluetooth/hci_core.c | grep "Collect kcov coverage from hci_rx_work"; then
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/0004-Instrument-virtio-bt-with-kcov_ivshmem-alt.patch
else 
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/0004-Instrument-virtio-bt-with-kcov_ivshmem.patch
fi


# Increase Blutooth timeouts
sed -i "s/TIMEOUT[ \t]\+msecs_to_jiffies(.*)/TIMEOUT    msecs_to_jiffies(900000)/" include/net/bluetooth/hci.h
git add include/net/bluetooth/hci.h

# Add Coverage
find net/bluetooth -name Makefile | xargs -L1 -I {} bash -c 'echo "KCOV_INSTRUMENT := y" >> {} && git add {}'

git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' commit -m "Add coverage Bluetooth" --no-gpg-sign
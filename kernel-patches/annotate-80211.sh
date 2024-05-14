#!/bin/bash

set -e
set -v

PATCHES_DIR=$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )

if ! git log -- drivers/net/wireless/mac80211_hwsim.c | grep "wifi: mac80211_hwsim: check length for virtio packets"; then
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/0001-wifi-mac80211_hwsim-check-length-for-virtio-packets.patch
fi

git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' am -3 --no-gpg-sign < $PATCHES_DIR/0008-Add-802.11-virtio-driver-and-coverage-for-Mac802.11.patch

# Add Coverage
find net/ -name Makefile | xargs -L1 -I {} bash -c 'echo "KCOV_INSTRUMENT := y" >> {} && git add {}'
echo "KCOV_INSTRUMENT_mac80211_hwsim.o := y" >> drivers/net/wireless/Makefile
git add drivers/net/wireless/Makefile

git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' commit -m "Add coverage for /net" --no-gpg-sign
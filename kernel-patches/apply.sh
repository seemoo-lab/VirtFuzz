#!/bin/bash

set -e
set -v

PATCHES_DIR=$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )
git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' am -3 --no-gpg-sign < $PATCHES_DIR/0001-Add-kcov-ivshmem-device-driver.patch

if ! grep "ivshmem" drivers/staging/Kconfig; then
    echo "Manually amending commit to include ivshmem device in drivers/staging/Kconfig"
    sed -i 's/endif # STAGING/source "drivers\/staging\/ivshmem\/Kconfig"\nendif # STAGING/g' drivers/staging/Kconfig
    git add drivers/staging/Kconfig
    git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' commit --no-gpg-sign --amend -m "$(git log --format=%B -n1)" -m "Add ivshmem to Kconfig"
fi

if ! grep "CONFIG_IVSHMEM" drivers/staging/Makefile; then
    echo "Manually amending commit to include ivshmem device in drivers/staging/Makefile"
    echo 'obj-$(CONFIG_IVSHMEM)	+= ivshmem/' >> drivers/staging/Makefile;
    git add drivers/staging/Makefile
    git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' commit --no-gpg-sign --amend -m "$(git log --format=%B -n1)" -m "Add ivshmem to Makefile"
fi

if ! git log -- kernel/kcov.c | grep "kcov: replace local_irq_save() with a local_lock_t"; then
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/kcov-backports/0001-kcov-allocate-per-CPU-memory-on-the-relevant-node.patch
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/kcov-backports/0002-kcov-avoid-enable-disable-interrupts-if-in_task.patch
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/kcov-backports/0003-kcov-replace-local_irq_save-with-a-local_lock_t.patch
fi


git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de' am -3 --no-gpg-sign < $PATCHES_DIR/0002-Add-methods-to-collect-coverage-to-IVSHMEM-on-boot.patch

if git log -- include/linux/kcov.h | grep "kcov: add prototypes for helper functions"; then
	git -c user.name='VirtFuzz' -c user.email='shuster@seemoo.tu-darmstadt.de'  am -3 --no-gpg-sign < $PATCHES_DIR/0001-Add-function-definitions-in-header.patch
fi


echo "Applied the kcov patches. Device annotations must still be applied!"
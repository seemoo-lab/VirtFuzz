# Generate kernel-config

Generate a base configuration as follows:

    rm .config
    make x86_64_defconfig
    make kvm_guest.config
    scripts/kconfig/merge_config.sh -m .config $THESIS/kernel-config/base.config

You can either add KASAN:

    scripts/kconfig/merge_config.sh -m .config $THESIS/kernel-config/kasan.config

*OR* UBSAN + KCSAN, but not both:

    scripts/kconfig/merge_config.sh -m .config $THESIS/kernel-config/kcsan-ubsan.config

And finish it with:

    make olddefconfig

As we do not use kernel modules, compile the modules into the kernel:

    sed -i 's/=m/=y/' .config

Now, you can build your kernel with: 

    make -j8

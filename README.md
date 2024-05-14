# VirtFuzz
VirtFuzz is a Linux Kernel Fuzzer that uses VirtIO to provide inputs into the kernels subsystem. It is built with [LibAFL](https://github.com/AFLplusplus/LibAFL).

Read our paper:
Sönke Huster, Matthias Hollick, Jiska Classen: "[To Boldly Go Where No Fuzzer Has Gone Before: Finding Bugs in Linux’ Wireless Stacks through VirtIO Devices](https://doi.ieeecomputersociety.org/10.1109/SP54263.2024.00024)". 45th IEEE Symposium on Security and Privacy (S&P), 2024.

# Instructions

## Requirements
* Rust with the cargo toolchain
* Patched QEMU
* Image for VM
* Patched Kernel

### Patched QEMU
Please see QEMUs requirements for building [here](https://wiki.qemu.org/Hosts/Linux#Building_QEMU_for_Linux).
QEMU with our universal VirtIO device is built as follows:

    curl https://download.qemu.org/qemu-8.2.2.tar.xz -o qemu.tar.xz
    tar xvJf qemu.tar.xz
    mv qemu-8.2.2 qemu
    cd qemu
    patch -p1 < $SCRIPT_DIR/../qemu-patch.patch
    mkdir build
    cd build
    ../configure --target-list=x86_64-softmmu
    make -j$(nproc)

### Debian Image for the VM
This script is adopted from [Syzkaller](https://github.com/google/syzkaller/blob/master/tools/create-image.sh). To generate a guestimage for the VM, run the following:

    cd guestimage
    ./create-image.sh -d stretch
    
### Patched Kernel
Finally, VirtFuzz requires a patched kernel. Therefore, pull a kernel version and apply our patches.
For example:

    git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
    cd linux
    git checkout v6.0
    ../virtfuzz/kernel-patches/apply.sh
    # Depending on the target, apply the patches to annotate for a specific device
    ../virtfuzz/kernel-patches/annotate-80211.sh
    
    # Make the config
    make x86_64_defconfig
    make kvm_guest.config
    scripts/kconfig/merge_config.sh -m .config ../virtfuzz/kernel-config/base.config
    
    # For example enable KASAN
    scripts/kconfig/merge_config.sh -m .config ../virtfuzz/kernel-config/kasan.config
    make olddefconfig
    make -j$(nproc)

## Usage
The following programs exist:

* virtfuzz-fuzz - the fuzzer
* virtfuzz-proxy - the proxy
* virtfuzz-replay - several utility scripts to e.g. minimize and replay crashes

### Fuzzer
See `cargo run --release --bin virtfuzz-fuzz` for all options.
For example, to fuzz the WLAN stack compiled in the requirements, run the following:

    export QEMU=PATH_TO-qemu-system-x86_64
    export IMAGE=guestimage/stretch.img
    export KERNEL=PATH_TO/linux/arch/x86/boot/bzImage
    cargo run --release --package virtfuzz-fuzz -- --device-definition device-definitions/hwsim-scan.json --cores 0-1 --stages standard

Now, the fuzzer runs two instances on the 802.11 stack through the mac802.11_hwsim driver.

Run `cargo run --release --package virtfuzz-fuzz -- --help` to see all available options.

#### Fuzzing Options
During the development, several options to support fuzzing where introduced. We'll explain selected ones here in the following:

##### Choosing a target
By now, a JSON file with a device definition can be passed to our fuzzer with the argument `--device-definition`. Still, pre-built device definitions can be used instead, using the `--device` argument.

```
-d, --device <DEVICE>
      Device that should be fuzzed
      
      [possible values: bluetooth, bluetooth-scan, net, wifi-scan, wifi-ap, wifi-ibss, wifi-syzkaller, console, input]

  --device-definition <DEVICE_DEFINITION>
      A JSON device defintion to be used instead of --device
```

##### Tracking comparisons
The argument `--stages` chooses the kind of coverage that should be used: Either AFL-Map style (standard) or tracking comparisons (cmplog).
```
-s, --stages <STAGES>
      Stages to be used
      
      [possible values: standard, cmplog]
```

##### Quirks
Some subsystems, e.g., the Bluetooth subsystem, usually exchange some messages for initialization with the hardware before being fully available. To speed up fuzzing, a PCAP file with such a recorded initialization can be provided. When the VM starts, the fuzzer first sends the messages from the PCAP file before starting to fuzz. See our recorded example in `resources/setup.pcap`.
```
--init-path <INIT_PATH>
  Path to a PCAP file containing the initialization sequence
```

Similarly, wait until the VM sends a first frame before starting to fuzz.
```
--wait-for-rx
  Start fuzzing after receiving a frame from the VM
```

If the VM  sends a command, the fuzzer fakes a command complete message when provided with the following argument.
```
--bt-fake-cc
  Respond to Bluetooth commands with dummy command complete frames
```

# History
Our fuzzer evolved from a Linux Kernel fuzzer purely focused on the Bluetooth stack to a more universal kernel fuzzer.
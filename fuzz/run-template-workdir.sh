#trap "jobs -p | xargs -r kill" SIGINT
FUZZING_TARGET=/opt/virtfuzz/device-definitions/hwsim-scan.json
KERNEL_CHECKOUT=master
KERNEL_TARGET=80211

kernel_location () {
  echo "/opt/kernels/linux-$KERNEL_CHECKOUT-$KERNEL_TARGET-$1/arch/x86/boot/bzImage"
}

FLAGS="--logfile log.jsonl"

virtfuzz-fuzz --device-definition $FUZZING_TARGET --stages cmplog --cores 0-7 --kernel $(kernel_location no-sanitizer) $FLAGS 2>&1 &
virtfuzz-fuzz --device-definition $FUZZING_TARGET --stages standard --cores 8-27 --kernel $(kernel_location ubsan) --client $FLAGS 2>&1 &
virtfuzz-fuzz --device-definition $FUZZING_TARGET --stages standard --cores 28-47 --kernel $(kernel_location kasan) --client $FLAGS 2>&1 &
libafl-dashboard --host fuzz.eknoes.de --external-hostname fuzz.eknoes.de log.jsonl
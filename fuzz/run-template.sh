#trap "jobs -p | xargs -r kill" SIGINT
KERNEL=bluetooth-next-8a3fd9bb4fac67ad5d44d6540c7ac20004767076
CORPUS=/dev/shm/net-corpus
CRASHES=/media/data/crashes-net
LOG=net.log
DEV=net
INITIAL="--initial-inputs ../virtio-net-inputs"
FLAGS=""
virtfuzz-fuzz --device $DEV --stages cmplog --cores 0-3 --kernel /dev/shm/$KERNEL-bzImage-nosan.kernel --client --crashes $CRASHES --corpus $CORPUS $FLAGS 2>&1 | tee -a $LOG &
virtfuzz-fuzz --device $DEV --stages standard --cores 4-5 --kernel /dev/shm/$KERNEL-bzImage-kasan.kernel --client --crashes $CRASHES --corpus $CORPUS $FLAGS 2>&1 | tee -a $LOG &
virtfuzz-fuzz --device $DEV --stages standard --cores 6-7 --kernel /dev/shm/$KERNEL-bzImage-kcsan-ubsan.kernel --client --crashes $CRASHES --corpus $CORPUS $FLAGS 2>&1 | tee -a $LOG &
virtfuzz-fuzz --device $DEV --stages standard --cores 8-11 --kernel /dev/shm/$KERNEL-bzImage-nosan.kernel --record-coverage --crashes $CRASHES --corpus $CORPUS $INITIAL $FLAGS  2>&1 | tee -a $LOG

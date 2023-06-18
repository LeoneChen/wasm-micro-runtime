#!/bin/bash
CUR_DIR=$(realpath .)
SGXSAN_DIR=$(realpath ${CUR_DIR}/../../)

source ${SGXSAN_DIR}/kAFL/kafl/env.sh
kafl fuzz --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir --seed-dir ${CUR_DIR}/seeds -t 4 -ts 2 -tc -p 1 --redqueen --grimoire --radamsa -D --funky --purge --log-hprintf --abort-time 24 -w ${CUR_DIR}/workdir_T0 --cpu-offset 8
# kafl debug --action single -w ${CUR_DIR}/workdir_debug --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir --purge --qemu-base "-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -nic user,hostfwd=tcp::5555-:1234 -display none" -t 0 --input $1

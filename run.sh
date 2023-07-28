#!/bin/bash
CUR_DIR=$(realpath .)
SGXSAN_DIR=$(realpath ${CUR_DIR}/../../)

source ${SGXSAN_DIR}/kAFL/kafl/env.sh
kafl fuzz --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir --seed-dir ${CUR_DIR}/seeds -t 4 -ts 2 -tc -p 1 --redqueen --grimoire --radamsa -D --funky --purge --log-hprintf --abort-time 24 -w ${CUR_DIR}/workdir_T0 --cpu-offset 8
# kafl debug --action single -w ${CUR_DIR}/workdir_debug --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target_debug.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir --purge --qemu-base "-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -nic user,hostfwd=tcp::5555-:1234 -display none" -t 0 --input $1
# kafl cov --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir -r -ip0 0x7ffff6a0b000-0x7ffff6b71000 -w ${CUR_DIR}/workdir_T0 -p 16
# ${SGXSAN_DIR}/Tool/GetLayout.py Enclave/Enclave_t.o Enclave/Enclave.o libvmlib.a /home/leone/Documents/SGXSan/install/lib64/libSGXSanRTEnclave.a /home/leone/Documents/SGXSan/install/lib64/libsgx_trts_sim.a /home/leone/Documents/SGXSan/install/lib64/libsgx_tkey_exchange.a /home/leone/Documents/SGXSan/install/lib64/libsgx_tcrypto.a /home/leone/Documents/SGXSan/install/lib64/libsgx_tservice_sim.a -d product-mini/platforms/linux-sgx/enclave-sample
# ${SGXSAN_DIR}/kAFL/kafl/fuzzer/scripts/ghidra_run.sh ${CUR_DIR}/workdir_T0 ${CUR_DIR}/product-mini/platforms/linux-sgx/enclave-sample/enclave.so ${SGXSAN_DIR}/ghidra_cov_analysis.py

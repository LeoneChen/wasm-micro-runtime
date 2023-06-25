#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))
ROOT_CIR=${CUR_DIR}

rm -rf ${ROOT_CIR}/product-mini/platforms/linux-sgx/build
make -C ${ROOT_CIR}/product-mini/platforms/linux-sgx/enclave-sample clean

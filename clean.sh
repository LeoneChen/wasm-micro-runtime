#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))

rm -rf ${SCRIPT_DIR}/product-mini/platforms/linux-sgx/build
make -C ${SCRIPT_DIR}/product-mini/platforms/linux-sgx/enclave-sample clean

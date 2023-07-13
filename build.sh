#!/bin/bash
set -e

for ARG in "$@"
do
   KEY="$(echo $ARG | cut -f1 -d=)"
   VAL="$(echo $ARG | cut -f2 -d=)"
   export "$KEY"="$VAL"
done

CUR_DIR=$(realpath $(dirname $0))
ROOT_CIR=${CUR_DIR}
SGXSAN_DIR=$(realpath ${CUR_DIR}/../../install)
MAKE_FLAGS="CC=clang-13 CXX=clang++-13 LD=lld SGX_SDK=${SGXSAN_DIR} SGX_SSL=${SGXSAN_DIR}/sgxssl -j$(nproc)"
CMAKE_FLAGS=
MODE=${MODE:="RELEASE"}
FUZZER=${FUZZER:="LIBFUZZER"}
SIM=${SIM:="TRUE"}

echo "-- MODE: ${MODE}"
echo "-- FUZZER: ${FUZZER}"
echo "-- SIM: ${SIM}"

if [[ "${MODE}" = "DEBUG" ]]
then
    MAKE_FLAGS+=" SGX_DEBUG=1 SGX_PRERELEASE=0"
    CMAKE_FLAGS+=" -DCMAKE_BUILD_TYPE=Debug"
else
    MAKE_FLAGS+=" SGX_DEBUG=0 SGX_PRERELEASE=1"
    CMAKE_FLAGS+=" -DCMAKE_BUILD_TYPE=Release"
fi

if [[ "${FUZZER}" = "KAFL" ]]
then
    MAKE_FLAGS+=" KAFL_FUZZER=1"
    CMAKE_FLAGS+=" -DKAFL_FUZZER=1"
else
    MAKE_FLAGS+=" KAFL_FUZZER=0"
    CMAKE_FLAGS+=" -DKAFL_FUZZER=0"
fi

if [[ "${SIM}" = "TRUE" ]]
then
    MAKE_FLAGS+=" SGX_MODE=SIM"
else
    MAKE_FLAGS+=" SGX_MODE=HW"
fi

cd ${ROOT_CIR}/product-mini/platforms/linux-sgx
CC="clang-13" CXX="clang++-13" SGX_SDK=${SGXSAN_DIR} cmake -B build ${CMAKE_FLAGS}
cmake --build build -j$(nproc)

make -C ${ROOT_CIR}/product-mini/platforms/linux-sgx/enclave-sample ${MAKE_FLAGS}

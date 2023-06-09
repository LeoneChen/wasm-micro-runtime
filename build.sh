#!/bin/bash
set -e

for ARG in "$@"
do
   KEY="$(echo $ARG | cut -f1 -d=)"
   VAL="$(echo $ARG | cut -f2 -d=)"
   export "$KEY"="$VAL"
done

SCRIPT_DIR=$(realpath $(dirname $0))
MAKE_FLAGS=
CMAKE_FLAGS=
MODE=${MODE:="RELEASE"}
SIM=${SIM:="FALSE"}

echo "-- MODE: ${MODE}"
echo "-- SIM: ${SIM}"

if [[ "${MODE}" = "DEBUG" ]]
then
    MAKE_FLAGS+=" SGX_DEBUG=1 SGX_PRERELEASE=0"
    CMAKE_FLAGS+=" -DCMAKE_BUILD_TYPE=Debug"
else
    MAKE_FLAGS+=" SGX_DEBUG=0 SGX_PRERELEASE=1"
    CMAKE_FLAGS+=" -DCMAKE_BUILD_TYPE=Release"
fi

if [[ "${SIM}" = "TRUE" ]]
then
    MAKE_FLAGS+=" SGX_MODE=SIM"
else
    MAKE_FLAGS+=" SGX_MODE=HW"
fi

cd ${SCRIPT_DIR}/product-mini/platforms/linux-sgx
cmake -B build ${CMAKE_FLAGS}
cmake --build build -j$(nproc)

make -C ${SCRIPT_DIR}/product-mini/platforms/linux-sgx/enclave-sample ${MAKE_FLAGS}
# ~/SGXSan/Tool/GetLayout.sh -d product-mini/platforms/linux-sgx/enclave-sample Enclave/Enclave_t.o Enclave/Enclave.o libvmlib.a /opt/intel/sgxsdk/lib64/libsgx_trts.a /opt/intel/sgxsdk/lib64/libsgx_tstdc.a /opt/intel/sgxsdk/lib64/libsgx_tcxx.a /opt/intel/sgxsdk/lib64/libsgx_pthread.a /opt/intel/sgxsdk/lib64/libsgx_tkey_exchange.a /opt/intel/sgxsdk/lib64/libsgx_tcrypto.a /opt/intel/sgxsdk/lib64/libsgx_tservice.a

#!/bin/sh
cd fuzz
ifconfig eth0 10.0.2.15 2>&1 | vmcall hcat
ip addr 2>&1 | vmcall hcat
# ./gdbserver 127.0.0.1:1234 ./iwasm 2>&1 | vmcall hcat
./iwasm 2>&1 | vmcall hcat

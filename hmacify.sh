#!/bin/sh

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 target/release/libkryoptic_pkcs11.so"
    exit 1
fi


LD_LIBRARY_PATH=./openssl openssl/apps/openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813 < $1 > $1.hmac
objcopy --update-section .rodata1=$1.hmac $1 $1.mac
cp $1 $1.orig
mv $1.mac $1

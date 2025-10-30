#!/bin/bash

trap status ERR

status() {
    if [ $? -eq 0 ]; then
        echo "SUCCESS"
    else
        echo "FAILURE"
    fi
    exit 1
}

DEBUG_FLAG=""
if [ "$1" == "--debug" ]; then
    DEBUG_FLAG="-d"
fi

find_soname() {
    for _lib in "$@" ; do
        SO_NAME="${_lib}/libkryoptic_pkcs11.so"
        if test -f "$SO_NAME" ; then
            echo "Using kryoptic path $_lib"
            SO_TARGET_DIR="$_lib"
            return
        fi
    done
    echo "skipped: Unable to find kryoptic PKCS#11 library"
    exit 0
}

if [ "x$P11LIB" = "x" ]; then
    find_soname \
        "target/debug" \
        "target/i686-unknown-linux-gnu/debug"

    export P11LIB="${P11LIB:-$SO_NAME}"
    export TARGET_DIR="${TARGET_DIR:-$SO_TARGET_DIR}"
else
    export TARGET_DIR="${TARGET_DIR:-target/debug}"
fi

export XMLDIR="${XMLDIR:-tools/profiles}"
export TOKDIR="${TOKDIR:-test/profiles}"
mkdir -p "${TOKDIR}"

export PINVALUE="${PINVALUE:-12345678}"
export SOPINVALUE="${SOPINVALUE:-87654321}"
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/token.sql}"
export TOKENLABEL="${TOKENLABEL:-Kryoptic Token}"
export TOKENLABELURI="${TOKENLABELURI:-Kryoptic%20Token}"

echo "Commencing profile tests"

echo "Testing profile ${XMLDIR}/BL-M-1-32.xml"
rm -f "${TOKDIR}"/token.sql
$TARGET_DIR/profile_conformance --init -m "${P11LIB}" -p "${PINVALUE}" --so-pin "${SOPINVALUE}" --token-label "${TOKENLABEL}" --profile baseline
$TARGET_DIR/profile_conformance $DEBUG_FLAG -m "${P11LIB}" -p "${PINVALUE}" "${XMLDIR}/BL-M-1-32.xml"

echo "Testing profile ${XMLDIR}/EXT-M-1-32.xml"
rm -f "${TOKDIR}"/token.sql
$TARGET_DIR/profile_conformance --init -m "${P11LIB}" -p "${PINVALUE}" --so-pin "${SOPINVALUE}" --token-label "${TOKENLABEL}" --profile extended
$TARGET_DIR/profile_conformance $DEBUG_FLAG -m "${P11LIB}" -p "${PINVALUE}" "${XMLDIR}/EXT-M-1-32.xml"

echo "Testing profile ${XMLDIR}/AUTH-M-1-32.xml"
rm -f "${TOKDIR}"/token.sql
$TARGET_DIR/profile_conformance --init -m "${P11LIB}" -p "${PINVALUE}" --so-pin "${SOPINVALUE}" --token-label "${TOKENLABEL}" --genkey RSA --profile authentication
$TARGET_DIR/profile_conformance $DEBUG_FLAG -m "${P11LIB}" -p "${PINVALUE}" "${XMLDIR}/AUTH-M-1-32.xml"

# TODO: We need a database with prepopulated certs for this
# echo "Testing profile ${XMLDIR}/CERT-M-1-32.xml"
# rm -f "${TOKDIR}"/token.sql
# $TARGET_DIR/profile_conformance --init -m "${P11LIB}" -p "${PINVALUE}" --so-pin "${SOPINVALUE}" --token-label "${TOKENLABEL}"
# $TARGET_DIR/profile_conformance $DEBUG_FLAG -m "${P11LIB}" -p "${PINVALUE}" "${XMLDIR}/CERT-M-1-32.xml"

echo "all ok"

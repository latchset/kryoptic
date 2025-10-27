#!/bin/bash

trap status ERR

status() {
    if [ $? -eq 0 ]; then
        echo "SUCCESS"
    else
        cat < ${LOGFILE}
        echo ""
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
rm -f "${TOKDIR}"/token.sql

export PINVALUE="${PINVALUE:-12345678}"
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/token.sql}"
export TOKENLABEL="${TOKENLABEL:-Kryoptic Token}"
export TOKENLABELURI="${TOKENLABELURI:-Kryoptic%20Token}"
export LOGFILE="${LOGFILE:-$TOKDIR/comnformance.log}"

echo "Commencing profile tests" > ${LOGFILE}

for profile in ${XMLDIR}/*.xml; do
    echo "Testing profile ${profile}"
    $TARGET_DIR/profile_conformance $DEBUG_FLAG -m "${P11LIB}" -p "${PINVALUE}" "${profile}" >>${LOGFILE} 2>&1
done

echo "all ok"

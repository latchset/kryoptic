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

export TOKDIR="${TOKDIR:-test/softhsm}"
mkdir -p "${TOKDIR}"
rm -f "${TOKDIR}"/token.sql

export PINVALUE="${PINVALUE:-12345678}"
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/token.sql}"
export TOKENLABEL="${TOKENLABEL:-Kryoptic Token}"
export TOKENLABELURI="${TOKENLABELURI:-Kryoptic%20Token}"
export LOGFILE="${LOGFILE:-$TOKDIR/migration.log}"
export SOFTHSM_TOKEN="${SOFTHSM_TOKEN:-testdata/softhsm/tokens/9a19985a-9037-e9df-657d-9947f7ba2120}"

$TARGET_DIR/kryoptic_init -m "${P11LIB}" -s "${PINVALUE}" -p "${PINVALUE}" -l "${TOKENLABEL}" >>${LOGFILE} 2>&1

$TARGET_DIR/softhsm_migrate -m "${P11LIB}" -i "${KRYOPTIC_CONF}" \
    -p "${PINVALUE}" -q "${PINVALUE}" "${SOFTHSM_TOKEN}" >>${LOGFILE} 2>&1

$TARGET_DIR/test_signature -m "${P11LIB}" -p "${PINVALUE}" >>${LOGFILE} 2>&1

echo "all ok"

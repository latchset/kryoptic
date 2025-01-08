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


export TOKDIR="${TOKDIR:-test/softhsm}"

mkdir -p "${TOKDIR}"
rm -f "${TOKDIR}"/token.sql

export PINVALUE="${PINVALUE:-12345678}"
export P11LIB="${P11LIB:-target/debug/libkryoptic_pkcs11.so}"
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/token.sql}"
export TOKENLABEL="${TOKENLABEL:-Kryoptic Token}"
export TOKENLABELURI="${TOKENLABELURI:-Kryoptic%20Token}"
export LOGFILE="${LOGFILE:-$TOKDIR/migration.log}"
export SOFTHSM_TOKEN="${SOFTHSM_TOKEN:-testdata/softhsm/tokens/9a19985a-9037-e9df-657d-9947f7ba2120}"

# init token
pkcs11-tool --module "${P11LIB}" --init-token \
    --label "${TOKENLABEL}" --so-pin "${PINVALUE}" >>${LOGFILE} 2>&1

# set user pin
pkcs11-tool --module "${P11LIB}" --so-pin "${PINVALUE}" \
    --login --login-type so --init-pin --pin "${PINVALUE}" >>${LOGFILE} 2>&1

target/debug/softhsm_migrate -m "${P11LIB}" -i "${KRYOPTIC_CONF}" \
    -p "${PINVALUE}" -q "${PINVALUE}" "${SOFTHSM_TOKEN}" >>${LOGFILE} 2>&1

P11DEFARGS=("--module=${P11LIB}" "--login" "--pin=${PINVALUE}" "--token-label=${TOKENLABEL}")

# Check that some imported data exists
pkcs11-tool "${P11DEFARGS[@]}" -O -a testCert 2>&1 |grep testCert >>${LOGFILE} 2>&1

echo "Signature Test" | \
    pkcs11-tool "${P11DEFARGS[@]}" --sign --id '0001' --mechanism RSA-PKCS \
                --output-file ${TOKDIR}/data.sig >>${LOGFILE} 2>&1

echo "Signature Test" | \
    pkcs11-tool "${P11DEFARGS[@]}" --verify --id '0001' --mechanism RSA-PKCS \
                --signature-file ${TOKDIR}/data.sig >>${LOGFILE} 2>&1


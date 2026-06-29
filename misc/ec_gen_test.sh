#!/bin/bash

TOKDIR=/tmp/ec_gen_test
SLOTID=42
PINVALUE="S3cr37-4-m3-bu7-n07-4-7h33"

rm -fr "${TOKDIR}"
mkdir -p "${TOKDIR}"

# Kryoptic configuration
cat << EOF > "${TOKDIR}/kryoptic.conf"
[[slots]]
slot = ${SLOTID}
dbtype = "sqlite"
dbargs = "${TOKDIR}/kryoptic.sql"
#mechanisms
EOF
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/kryoptic.conf}"

export TOKENLABEL="${TOKENLABEL:-Kryoptic Token}"
export TOKENLABELURI="${TOKENLABELURI:-Kryoptic%20Token}"

# init token
pkcs11-tool --module target/debug/libkryoptic_pkcs11.so --init-token \
    --slot "${SLOTID}" --label "${TOKENLABEL}" --so-pin "${PINVALUE}" 2>&1
# set user pin
pkcs11-tool --module target/debug/libkryoptic_pkcs11.so \
    --slot "${SLOTID}" --so-pin "${PINVALUE}" --slot "${SLOTID}" \
    --login --login-type so --init-pin --pin "${PINVALUE}" 2>&1

LOGFILE=${TOKDIR}/ec_gen_test.log

echo `date` > ${LOGFILE}

for i in $(seq 1 65535); do
    ID=$(printf "%04x" "$i")
    PRIVKEYFILE="${TOKDIR}/private_ec_key_${i}.der"
    PUBKEYFILE="${TOKDIR}/public_ec_key_${i}.der"

    openssl genpkey -algorithm EC -outform DER -pkeyopt ec_paramgen_curve:P-256 \
        -out "${PRIVKEYFILE}" >>${LOGFILE} 2>&1

    pkcs11-tool --module target/debug/libkryoptic_pkcs11.so --slot "${SLOTID}" \
        --pin "${PINVALUE}" --write-object "${PRIVKEYFILE}" \
        --id "${ID}" --type privkey --label "EC private key ${ID}" \
    >>${LOGFILE} 2>&1 || {
        echo "Failed to import private key from ${PRIVKEYFILE}"
        continue
    }

    openssl pkey -pubout -inform DER -outform DER -in "${PRIVKEYFILE}" \
        -out "${PUBKEYFILE}" >>${LOGFILE} 2>&1


    pkcs11-tool --module target/debug/libkryoptic_pkcs11.so --slot "${SLOTID}" \
        --pin "${PINVALUE}" --write-object "${PUBKEYFILE}" \
        --id "${ID}" --type pubkey --label "EC public key ${ID}" \
    >>${LOGFILE} 2>&1 || {
        echo "Failed to import public key from ${PUBKEYFILE}"
        continue
    }
done

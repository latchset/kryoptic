#!/bin/bash

set -e

trap status ERR

status() {
    if [ $? -eq 0 ]; then
        echo "SUCCESS"
    else
        cat < ${LOGFILE} 2>/dev/null || true
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

export TOKDIR="${TOKDIR:-test/otp}"
mkdir -p "${TOKDIR}"
rm -rf "${TOKDIR}"/*

export DB_PATH="${TOKDIR}/token.sql"
export PINVALUE="12345678"
export LOGFILE="${TOKDIR}/test.log"

echo "=== 1. Test creating a new TOTP token ===" >> ${LOGFILE}
OUT=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -N -n "test_totp" -p "${PINVALUE}" -f all)
echo "$OUT" >> ${LOGFILE}

# Verify output contains expected fields
echo "$OUT" | grep "OTP Name:       test_totp" >> ${LOGFILE}
echo "$OUT" | grep "Type:           TOTP" >> ${LOGFILE}
echo "$OUT" | grep "Algorithm:      SHA256" >> ${LOGFILE}
echo "$OUT" | grep "Base32 Secret:" >> ${LOGFILE}
echo "$OUT" | grep "URI:            otpauth://totp/" >> ${LOGFILE}

echo "=== 2. Test generating code from single key without -n ===" >> ${LOGFILE}
CODE=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -p "${PINVALUE}")
echo "Generated code: $CODE" >> ${LOGFILE}
if [[ ! "$CODE" =~ ^[0-9]{6}$ ]]; then
    echo "Expected 6-digit code, got: $CODE" >> ${LOGFILE}
    exit 1
fi

echo "=== 3. Test creating a second key (HOTP, high security) ===" >> ${LOGFILE}
OUT_HOTP=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -N -n "test_hotp" -t hotp -s high -p "${PINVALUE}" -f uri)
echo "$OUT_HOTP" >> ${LOGFILE}
echo "$OUT_HOTP" | grep "otpauth://hotp/" >> ${LOGFILE}
echo "$OUT_HOTP" | grep "algorithm=SHA512" >> ${LOGFILE}

echo "=== 4. Test ambiguous key selection fails without -n ===" >> ${LOGFILE}
if $TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -p "${PINVALUE}" >> ${LOGFILE} 2>&1; then
    echo "Expected failure when multiple keys exist without -n" >> ${LOGFILE}
    exit 1
fi

echo "=== 5. Test generating code specifying -n ===" >> ${LOGFILE}
CODE_TOTP=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -n "test_totp" -p "${PINVALUE}")
echo "TOTP code: $CODE_TOTP" >> ${LOGFILE}
if [[ ! "$CODE_TOTP" =~ ^[0-9]{6}$ ]]; then
    echo "Expected 6-digit TOTP code, got: $CODE_TOTP" >> ${LOGFILE}
    exit 1
fi

CODE_HOTP1=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -n "test_hotp" -p "${PINVALUE}")
CODE_HOTP2=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -n "test_hotp" -p "${PINVALUE}")
echo "HOTP codes: $CODE_HOTP1, $CODE_HOTP2" >> ${LOGFILE}
if [[ ! "$CODE_HOTP1" =~ ^[0-9]{6}$ ]] || [[ ! "$CODE_HOTP2" =~ ^[0-9]{6}$ ]]; then
    echo "Expected 6-digit HOTP codes" >> ${LOGFILE}
    exit 1
fi
if [ "$CODE_HOTP1" = "$CODE_HOTP2" ]; then
    echo "HOTP counter did not advance between calls" >> ${LOGFILE}
    exit 1
fi

echo "=== 6. Test duplicate key name fails ===" >> ${LOGFILE}
if $TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -N -n "test_totp" -p "${PINVALUE}" >> ${LOGFILE} 2>&1; then
    echo "Expected duplicate key creation to fail" >> ${LOGFILE}
    exit 1
fi

echo "=== 7. Test non-existent database without -N fails ===" >> ${LOGFILE}
if $TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${TOKDIR}/nonexistent.sql" -p "${PINVALUE}" >> ${LOGFILE} 2>&1; then
    echo "Expected non-existent database to fail without -N" >> ${LOGFILE}
    exit 1
fi

echo "=== 8. Test invalid digits fails ===" >> ${LOGFILE}
if $TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${DB_PATH}" -N -n "bad_digits" --digits 5 -p "${PINVALUE}" >> ${LOGFILE} 2>&1; then
    echo "Expected digits=5 to fail" >> ${LOGFILE}
    exit 1
fi

echo "=== 9. Test creating a new token with --no-pin ===" >> ${LOGFILE}
export NOPIN_DB="${TOKDIR}/nopin.sql"
OUT_NOPIN=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${NOPIN_DB}" -N -n "nopin_key" --no-pin -f uri)
echo "$OUT_NOPIN" >> ${LOGFILE}
echo "$OUT_NOPIN" | grep "otpauth://totp/nopin_key" >> ${LOGFILE}

echo "=== 10. Test generating code from --no-pin token without -p or PIN env ===" >> ${LOGFILE}
unset PINVALUE
unset KRYOPTIC_OTP_PIN
unset PIN
CODE_NOPIN=$($TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${NOPIN_DB}")
echo "Generated NOPIN code: $CODE_NOPIN" >> ${LOGFILE}
if [[ ! "$CODE_NOPIN" =~ ^[0-9]{6}$ ]]; then
    echo "Expected 6-digit code without PIN prompt, got: $CODE_NOPIN" >> ${LOGFILE}
    exit 1
fi

echo "=== 11. Test using --no-pin on already initialized token fails ===" >> ${LOGFILE}
if $TARGET_DIR/kryoptic_otp -m "${P11LIB}" -d "${NOPIN_DB}" -N -n "nopin_key2" --no-pin >> ${LOGFILE} 2>&1; then
    echo "Expected --no-pin to fail on already initialized database" >> ${LOGFILE}
    exit 1
fi

echo "All tests passed successfully!"

#!/bin/bash

if test "$1" != "check-jtreg"
then
    echo "Usage: $(basename "$0") check-jtreg"
    exit 1
fi

set -o errexit
set -o xtrace

KRYOPTIC="$(realpath "$(dirname "$0")"/../..)"
export KRYOPTIC

OPENJDK="${KRYOPTIC}"/testdata/openjdk

# Keep jtreg_version, openjdk_feature, and openjdk_name in sync with
# .github/workflows/openjdk-integration.yml.
jtreg_version=8+2
openjdk_feature=25
openjdk_name=jdk25u

# Download dependencies.
if test -z "${PKCS11_PROVIDER}"
then
    if ! test -d "${OPENJDK}"/deps/pkcs11-provider
    then
        mkdir -p "${OPENJDK}"/deps
        pushd "${OPENJDK}"/deps
        git clone https://github.com/latchset/pkcs11-provider.git
        popd
    fi
    export PKCS11_PROVIDER="${OPENJDK}"/deps/pkcs11-provider
fi
if test -z "${JDK}"
then
    if ! test -d "${OPENJDK}"/deps/"${openjdk_name}"
    then
        mkdir -p "${OPENJDK}"/deps
        pushd "${OPENJDK}"/deps
        git clone --depth 10 --branch kryoptic-jdk-"${openjdk_feature}" \
            https://github.com/fitzsim/"${openjdk_name}"
        popd
    fi
    export JDK="${OPENJDK}"/deps/"${openjdk_name}"
fi
if test -z "${JTREG}"
then
    if ! test -d "${OPENJDK}"/deps/jtreg
    then
        mkdir -p "${OPENJDK}"/deps
        pushd "${OPENJDK}"/deps
        wget --no-verbose \
             https://builds.shipilev.net/jtreg/jtreg-"${jtreg_version}".zip
        unzip jtreg-"${jtreg_version}".zip
        chmod +x jtreg/bin/jtreg
        popd
    fi
    export JTREG="${OPENJDK}"/deps/jtreg
fi

# Initialize Kryoptic token.
export TESTSSRCDIR="${PKCS11_PROVIDER}"/tests
# Note intentional extra "P" in "TMPPDIR".
export TMPPDIR="${OPENJDK}"/conf
NSSDIR="${TMPPDIR}/nss"
export TOKDIR="${NSSDIR}/db"
export PINVALUE="fo0m4nchU"
mkdir --parents "${TOKDIR}"
title() { echo "$@"; }
# Needed so that kryoptic.nss-init.sh can be rerun without error.
rm --force "${TOKDIR}"/cert9.db
# Clean up other files too.
rm --force "${TOKDIR}"/key4.db \
   "${TOKDIR}"/kryoptic.conf \
   "${TMPPDIR}"/kryoptic.conf \
   "${TMPPDIR}"/libkryoptic_pkcs11.so
source "${TESTSSRCDIR}"/kryoptic.nss-init.sh
# Remove superfluous configuration file created by kryoptic-init.sh
# when it is called from kryoptic.nss-init.sh (which creates its own
# configuration file, "${TMPPDIR}"/kryoptic.conf).
rm --force "${TOKDIR}"/kryoptic.conf
mv "${TMPPDIR}"/kryoptic.conf "${TOKDIR}"/kryoptic.conf
cp "${OPENJDK}"/p11-nss.txt "${OPENJDK}"/p11-nss-sensitive.txt "${NSSDIR}"

# PKCS11Test.java does a depth-first search for the first file with
# this name under jdk.test.lib.artifacts.nsslib-linux_x64.  It finds
# kryoptic/target/debug/deps/libkryoptic_pkcs11.so.  This fails with:
#
# |thread '<unnamed>' panicked at ossl/src/fips.rs:706:5:
# |assertion failed: ret == 1
# |note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
# |fatal runtime error: failed to initiate panic, error 5
#
# because hmacify.sh is only run on kryoptic/target/debug/libkryoptic_pkcs11.so.
#
# To protect against this, copy libkryoptic_pkcs11.so to
# kryoptic-configuration and point
# jdk.test.lib.artifacts.nsslib-linux_x64 there.
cp "${P11LIB}" "${TMPPDIR}"

NATIVE_DEBUGGER=${NATIVE_DEBUGGER:-}
export JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-"${openjdk_feature}"-openjdk}
JAVA_RUNNER=${JAVA_RUNNER:-java}
pushd "${JDK}"
${NATIVE_DEBUGGER} "${JAVA_HOME}"/bin/"${JAVA_RUNNER}" \
    -Dprogram=jtreg \
    -jar "${JTREG}"/lib/jtreg.jar \
    -verbose:fail,error \
    -javaoption:-DCUSTOM_P11_CONFIG_BASE_DIR="${TMPPDIR}" \
    -javaoption:-DCUSTOM_P11_LIBRARY_NAME=kryoptic_pkcs11 \
    -javaoption:-Djdk.test.lib.artifacts.nsslib-linux_x64="${TMPPDIR}" \
    -javaoption:--enable-native-access=ALL-UNNAMED \
    -testjdk:"${JAVA_HOME}" \
    -javacoption:-g \
    @"${OPENJDK}"/openjdk-jtreg-tests.txt
popd

# Local Variables:
# compile-command: "ln -s \
# ../../testdata/openjdk/deps/pkcs11-provider/tests/kryoptic.nss-init.sh . \
# && shellcheck --external-sources $(pwd)/jtreg-kryoptic.sh \
# && rm kryoptic.nss-init.sh"
# fill-column: 80
# End:

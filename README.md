This is a pkcs11 soft token written in rust.

# Dependencies

 * rustc
 * openssl dependencies
 * sqlite

Note, the default feature links against the system installed OpenSSL
libraries, you need the OpenSSL development packages to build with
the default features selection.

# Crates

To make it easier to deal with some of the tools and bindings kryoptic has
been changed from a monolithic crate to a workspace that holds multiple
packages. Specifically the main output artifact, the cdylib named
libkryoptic_pkcs11.so has been moved to the kryoptic_pkcs11 package in the
cdylib directory.

# Setup

Kryoptic normally builds and dynamically links against a system version
of OpenSSL; alternatively the build system can be pointed to OpenSSL
sources to generate a build with the crypto library statically linked
into the binaries.

For builds that need to include a static build of OpenSSL, download and
unpack the desired version and set the env var KRYOPTIC_OPENSSL_SOURCES
to the path where the source were unpacked.

Example:

    export KRYOPTIC_OPENSSL_SOURCES=/path/to/src/openssl

When building, you'll need to disable the dynamic feature.  Since
features are additive in `Cargo`, you'll need to disable the default
features and then select the features that you need.  For instance, if
you want the standard features, you can do:

    cargo build --no-default-features --features standard

# Build

Build the rust project:

    $ CONFDIR=/etc cargo build

The default build specifies "standard" as the default feature for
ease of use. "Standard" pulls in all the standard algorithms and the
sqlitedb storage backend.

In order to make a different selection you need to use the cargo
switch to disable default features (`--no-default-features`) and then
specify the features you want to build with, eg:

    $ cargo build --no-default-features --features fips,ossl-backend,sqlitedb,nssdb

Note that you can set `OSSL_BINDGEN_CLANG_ARGS` (whitespace delimited)
to pass additional arguments into bindgen, in case that is important
for your build.

# Crypto Backends

Kryoptic's cryptographic primitives are implemented against a pluggable
backend, selected at compile time via exactly one of three mutually
exclusive Cargo features:

 * `ossl-backend` (the default, pulled in by `standard`): OpenSSL, as
   described above.
 * `awslc`: [AWS-LC](https://github.com/aws/aws-lc) (Amazon's
   BoringSSL-derived library), non-FIPS.
 * `awslc-fips`: AWS-LC's FIPS-140-3-validated module.

The `awslc`/`awslc-fips` backends need no system OpenSSL at all -- Cargo
fetches and builds `aws-lc-sys`/`aws-lc-fips-sys` from source, which in
turn need `cmake` and (for `awslc-fips` specifically) Go and Perl in
addition to a C compiler. Select one with the same `--no-default-features
--features ...` pattern used above -- note that `standard` itself pulls in
`ossl-backend` and `chacha20`, both incompatible with `awslc`/`awslc-fips`,
so list the individual algorithm features you need instead, e.g.:

    $ cargo build --no-default-features --features \
        awslc,sqlitedb,ecc_all,ffdh,hash_all,kdf_all,rsa,hotp,ike
    $ cargo build --no-default-features --features \
        awslc-fips,sqlitedb,ecc_all,ffdh,hash_all,kdf_all,rsa,hotp,ike

A handful of mechanisms AWS-LC has no primitive for at all (ciphertext
stealing, Ed448/X448, SLH-DSA, and ML-DSA's deterministic signing mode)
are permanent, documented gaps under `awslc`/`awslc-fips` -- correctly
absent from `C_GetMechanismList` rather than advertised and then failing.

# FIPS Builds

The `--feature fips` builds create a token linking just to OpenSSL libfips.a
and enable FIPS behavior, restricting how algorithms behave and reporting
FIPS indicators for (non)approved algorithms and operations. It forces the
presence of the PKCS#11 3.2 interfaces as well as the PQC algorithms. See
"Crypto Backends" above for the AWS-LC-FIPS alternative (`awslc-fips`):
you don't need to pass `--features fips` yourself for it -- `awslc-fips`
already implies it (and gates the same `fips`-conditional behavior in
shared, backend-agnostic code, e.g. minimum RSA key size), it just never
touches the OpenSSL-specific FIPS provider this section otherwise
describes.

The FIPS build allows to specify the name, version, and additional build
information returned by the embedded OpenSSL FIPS provider by setting the
following environment variables (requires custom patches to the OpenSSL
code base to take effect):
- KRYOPTIC_FIPS_VENDOR
- KRYOPTIC_FIPS_VERSION
- KRYOPTIC_FIPS_BUILD

If these variables are not set build defaults respectively to:
- CARGO_PKG_NAME
- CARGO_PKG_VERSION
- "test"

For the FIPS build, you need to generate the hmac checksum:

    $ ./misc/hmacify.sh target/release/libkryoptic_pkcs11.so

Without this step the token will panic at initialization.

# Tests

To run the tests, run the test command:

    $ cargo test

This command accepts the same feature set as the build command

# License

The license is currently set as the Apache Software License 2.0 the same license
OpenSSL uses.

In versions prior than and including 1.5.2 the license for the token code was 
the GPLv3.0+ as released by the FSF, we changed it to make the project more
easily reusable across a wider set of Open Source communities.

# Contributions

Contributions to the project are made under the project's [License](LICENSE.txt)
unless otherwise explicitly indicated by the contributor at the time of the
contribution.

See also the [default agreement](https://developercertificate.org/), which we assume
for contribution, and which is currently enforced by the github DCO check.

This is a pkcs11 soft token written in rust.

# Dependencies

 * rustc
 * openssl dependencies
 * sqlite

Note, the default feature links against the system installed OpenSSL
libraries, you need the OpenSSL development packages to build with
the default features selection.

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

For the FIPS build, you need to generate the hmac checksum:

    $ ./misc/hmacify.sh target/release/libkryoptic_pkcs11.so

The default build specifies "standard" as the default feature for
ease of use. "Standard" pulls in all the standard algorithms and the
sqlitedb storage backend.

In order to make a different selection you need to use the cargo
switch to disable default features (`--no-default-features`) and then
specify the features you want to build with, eg:

    $ cargo build --no-default-features --features fips,sqlitedb,nssdb

# Tests

To run the tests, run the test command:

    $ cargo test

This command accepts the same feature set as the build command

# License

The license is currently set as the GPLv3.0+ as released by the FSF.

This license is compatible with the OpenSSL ASL2.0 license and is a strong
copyleft license, which we find useful.

Unlike other copyleft projects we are not dogmatic and chose this license
for the benefits we think it will bring to a self-contained project like
kryoptic. Namely that it strongly encourages modifications to be
contributed back.

If a party asks for it, we will pragmatically evaluate a different license
and will be open to making a change if we think that such a change would in fact
be in the best interest of the project. Note that requests of this kind
need to come with a well-reasoned rationale that shows benefits both for
the requesting party and the upstream project.


# Contributions

Contributions to the project are made under the project's [License](LICENSE.txt)
unless otherwise explicitly indicated by the contributor at the time of the
contribution.

See also the [default agreement](https://developercertificate.org/), which we assume
for contribution, and which is currently enforced by the github DCO check.

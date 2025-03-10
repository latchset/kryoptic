This is a pkcs11 soft token written in rust

# Dependencies

 * rustc
 * openssl dependencies
 * sqlite

Note, the default feature links against the system installed openssl
and does not use the openssl submodule, you need the openssl
development package to build with the default features.

# Setup

First after cloning, we need to pull and update openssl submodule:

    $ git submodule init
    $ git submodule update

# Build

Build the rust project:

    $ CONFDIR=/etc cargo build

For FIPS module, you need to generate hmac checksum:

    $ ./misc/hmacify.sh target/release/libkryoptic_pkcs11.so

The default build specifies "standard" as the default feature for
ease of use. "Standard" pulls in all the standard algorithms and the
sqlitedb storage backend.

In order to make a different selection you need to use the cargo
switch to disable default features (--no-default-features) and then
specify the features you want to build with:

eg: cargo build --no-default-features --features fips,sqlitedb,nssdb

# Tests

To run test, run the check command:

    $ cargo test


# License

The license is currently set as the GPLv3.0+ as released by the FSF.

This license is compatible with the OpenSSL ASL2.0 license and is a strong
copyleft license which we find useful.

Unlike other copyleft projects we are not dogmatic and chose this license
for the benefits we think it will brings to a self-contained project like
kryoptic. Namely that it strongly encourages modifications to be
contributed back.

If a party asks for it we will pragmatically evaluate a different license
and will be open to make a change if we think that such change would in fact
be in the best interest of the project. Note that requests of this kind
need to come with a well reasoned rationale that shows benefits both for
the requesting party and the upstream project.


# Contributions

Contributions to the project are made under the project's [License][License]
unless otherwise explicitly indicated by the contributor at the time of the
contribution.

See also the [default agreement](https://developercertificate.org/) we assume
for contribution which is currently enforced by the github DCO check.

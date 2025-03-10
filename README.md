This is a pkcs11 soft token written in rust

# Dependencies

 * rustc
 * openssl dependencies
 * sqlite

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

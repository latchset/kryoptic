This is a pkcs11 soft token written in rust

# Dependencies

 * rustc
 * openssl dependencies
 * sqlite

# Setup

First after cloning, we need to pull and update openssl submodule:

    $ git submodule init
    $ git submodule update

Build the rust project:

    $ CONFDIR=/etc cargo build

For FIPS module, you need to generate hmac checksum:

    $ ./hmacify.sh target/release/libkryoptic_pkcs11.so

# Tests

To run test, run the check command:

    $ cargo test

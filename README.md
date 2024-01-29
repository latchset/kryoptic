This is an experimental pkcs11 token written in rust

# Dependencies

 * rustc
 * openssl dependencies

# Setup

First after cloning, we need to pull and update openssl submodule:

$ git submodule init
$ git submodule update

Build the rust project:

$ cargo build

For FIPS module, you need to generate hmac checksum:

$ ./hmacify.sh target/release/libkryoptic_pkcs11.so

# Tests

To run test, run the check command:

$ cargo test

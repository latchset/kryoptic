# ossl

A crate providing low-level Rust bindings to the OpenSSL library.

`ossl` was spun off from the `kryoptic` project to provide a focused,
standalone set of bindings for interacting with OpenSSL's C API.

This crate is intentionally focused on the modern OpenSSL 3+ APIs, primarily
the high-level EVP interface and the `OSSL_PARAM` mechanism for parameter
handling. It avoids legacy APIs to promote a more consistent and
forward-looking approach to using OpenSSL from Rust.

This crate provides unsafe FFI bindings and some thin, safe wrappers around
common OpenSSL objects and patterns. It is intended as a foundational
building block for higher-level cryptographic libraries rather than for
direct application use.

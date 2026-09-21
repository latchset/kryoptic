# rustls-ossl

A crate providing a Rustls cryptographic provider backed by OpenSSL.

`rustls-ossl` implements the Rustls `CryptoProvider` interface using the `ossl`
crate, allowing Rustls to use OpenSSL 3+ as its cryptographic engine for TLS 1.2
and TLS 1.3.

This crate exists alongside `rustls-openssl` because the `ossl` bindings use
modern OpenSSL 3+ APIs that are FIPS compliant. In contrast, the `openssl` crate
relies on legacy APIs for all non-PQC algorithms, which are not FIPS compliant.

The crate integrates with OpenSSL's library context and provider architecture,
inheriting the configured OpenSSL providers and supporting FIPS mode operation.

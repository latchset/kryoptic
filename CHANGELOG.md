# Changelog

All notable changes to this project should be documented in this file.

## [Unreleased]

### What Changed

--

## [1.4.0]
## 2025-11-24

This release adds more PKCS#11 compatibility/completeness features as well
as fixes various issues.

One of the most notable additions is support for the a mechanism to derive
public keys from private keys. This allows to better handle tokens where only
the private key has been imported, but no corresponding public key object.
To make this more effective and efficient the code now automatically
generates and stores the `CKA_PUBLIC_KEY_INFO` attribute for all asymmetric
key types.

### What Changed

* Added support to store Trust Objects
    - [Add support for CKO_TRUST
       objects](https://github.com/latchset/kryoptic/pull/348)

* Added support for CKO_PROFILE objects
  - [Support CKO_PROFILES objects in
     Kryoptic](https://github.com/latchset/kryoptic/pull/353)

* Support for CKM_PUB_KEY_FROM_PRIV_KEY
  - [Implement simple derivation function that extracts a public key from a
     private key](https://github.com/latchset/kryoptic/pull/357)

* Support for CKA_PUBLIC_KEY_INFO
  - [Store computed CKA_PUBLIC_KEY_INFO on
     keys]( https://github.com/latchset/kryoptic/pull/366)

* Fixed an error that could return sensitive values to an
  **authenticated** user when the CKA_SENSITIVE flag is set to true.
  - [Add test for sensitive key attribute
     extraction](https://github.com/latchset/kryoptic/pull/373)

## [1.3.1]
## 2025-09-18

This is a bugfix release that addresses an issue with publishing to crates.io.

### What Changed

* fix issus publishing to crates.io
  - [Remove large test vectors from release
     artifacts](https://github.com/latchset/kryoptic/pull/337)

# [1.3.0]
## 2025-09-18

This release splits the kryoptic crate in four separate crates:
- ossl: the bindings to openssl libraries
- kryoptic: the kryoptic pkcs11 token (the .so module)
- kryoptic-lib: the builk fo the implementation of kryoptic functionality
- kryoptic-tools: utility tools (like softhsm2 migration tools)

The split between kryoptic and kryoptic-lib was necessary because of the way
cargo handles libs and cdylibs, both can't be built from the same crate

The PKCS#11 3.2 API is now the default API offered to applications.
New mechanisms have been added, see the rest of the changelog for details.

### What Changed

* The project was reorganized in a workspace with several crates
 - [Switch cargo setup to a workspace with several
    packages](https://github.com/latchset/kryoptic/pull/263)
 - [Rename and restructure some of the crates we recently
    crated](https://github.com/latchset/kryoptic/pull/281)

* Added support for SP800 ECDH KDF variant
 - [Support Sp800 ECDH KDF
    flavor](https://github.com/latchset/kryoptic/pull/273)

* PKCS#11 3.2 is now the default interface
 - [Make PKCS#11 3.2 the default
    interface](https://github.com/latchset/kryoptic/pull/276)

* Implemented simple KDF functions for key concatenation and XOR of
  a base key with provided data.
 - [Implement simple KDFs](https://github.com/latchset/kryoptic/pull/278)

* Added support for SLH-DSA keys and operations
 - [Add support for SLH-DSA](https://github.com/latchset/kryoptic/pull/316)

* Change the OSSL bindings license to Apache 2.0
 - [Change ossl lisence to ASL 2.0](https://github.com/latchset/kryoptic/pull/322)

* Added support for DSA signature algorithm and 3DES cipher for OSSL bindings
 - [Add support for legacy algorithms (DSA, 3DES)](https://github.com/latchset/kryoptic/pull/321)

* Added support for automatically deriving Private Key value from seed for
  ML-DSA and ML-KEM
  - [Handle imports where only the Seed is
     provided](https://github.com/latchset/kryoptic/pull/330)

* Added OpenPGP (RFC9580) relevant legacy algorithms in ossl bindings
  - [Implement remaining legacy algorithms needed for OpenPGP](https://github.com/latchset/kryoptic/pull/334)

# [1.2.0]
## 2025-06-09

This release adds support for PQC algorithms, comprehensive doc string coverage
and a few important compatibility fixes in the database format and key wrapping
data formats.

### What Changed

* The jsondb storage backend has been removed
  - [Drop jsondb](https://github.com/latchset/kryoptic/pull/262)

* Added initial support for tracing logs
  - [Add some basic infrastructure to perform
     tracing](https://github.com/latchset/kryoptic/pull/259)

* Added support for FFDH key generation and derivation
  - [Add support fo FFDH key generation and
     derivation](https://github.com/latchset/kryoptic/pull/257)

* Added support for ML-DSA signature scheme

* Added support for SignatureVerify APIs with all algorithms
  - [Support SignatureVerify APIs with all
     algorithms](https://github.com/latchset/kryoptic/pull/216)

* Fixed a database format bug that would affect cross-platform portability
  - [Add better support for array of
     attributes](https://github.com/latchset/kryoptic/pull/219)

* Added doc string with Gemini's help to most files
  - [Add more documentation strings and cleanup
     changes](https://github.com/latchset/kryoptic/pull/229)

* Made Token Info more spec compliant and added relevant information like the
  software release version.
  - [Make token info a little more
     useful](https://github.com/latchset/kryoptic/pull/237)

* Fix Asymmetric keys export format for Key Wrapping and extend it to all EC key
  types
  - [Fix PrivateKeyInfo ASN.1
     structure](https://github.com/latchset/kryoptic/pull/238)
  - [Add Key wrapping support and tests for all EC
     keys](https://github.com/latchset/kryoptic/pull/239)

# [1.1.0]
## 2025-04-14

This release fixes several issues found by 3rd party testing, and adds
preliminary support for PKCS#11 3.2 APIs.
The PKCS#11 3.2 API allows us to add Post Quantum algorithms.
This release adds support for the first PQ algorithm (ML-KEM).
Both the pkcs#11 3.2 API and ML-KEM are optional features and can be
both enabled by passing --feature mlkem at build time.

### What Changed

* Added support for PKCS#11 3.2 interfaces
  - [Pkcs11 3.2 Draft](https://github.com/latchset/kryoptic/pull/149)

* Added support for Key Encapdulation/Decapsulation and ML-KEM Support
  - [Add Encapsulation/Decapsulation and ML-KEM
     support](https://github.com/latchset/kryoptic/pull/197)

* Sundry fixes that result in minor, but visible, behavior changes:
  - [Deal with length query
     issues](https://github.com/latchset/kryoptic/pull/185)
  - [aes: Restrict AES-GCM to at least 1B tag
     length](https://github.com/latchset/kryoptic/pull/189)
  - [Fix incorrect error returned on un-initialized
     operations](https://github.com/latchset/kryoptic/pull/192)
  - [Ensure token store objects can be extracted if the right booleans are
     set](https://github.com/latchset/kryoptic/pull/194)
  - [Fix check for object sensitivity as per
     spec](https://github.com/latchset/kryoptic/pull/198)
  - [ecdh: Fix max ECDH output
     size](https://github.com/latchset/kryoptic/pull/203)
  - [Fix C_WrapKey size query](https://github.com/latchset/kryoptic/pull/202)

* Minor enhancements:
  - [Add Stricter FIPS options to
     configuration](https://github.com/latchset/kryoptic/pull/199)
  - [Allow digesting AES keys and add test
     coverage.](https://github.com/latchset/kryoptic/pull/204)


# [1.0.0]
## 2025-03-11

### What Changed

This is the first release.

Kryoptic implements most of the functions available in the PKCS#11 3.1 spec with
the exception of some message based operations.

The initial version supports both symmetric and asymmetric algorithms.
Asymmetric Algorithms:
- ECDSA
- EDDSA
- ECDH
- RSA

Symmetric Algorithms:
- AES

Hashes and HMAC:
- SHA1
- SHA2 (224, 256, 384, 512, 512/224, 512/256)
- SHA3 (224, 256, 384, 512)

Key derivation functions:
- PBKDF2
- HKDF
- SP108
- SSHKDF
- TLSKDF

The token supports 2 main database types:
- sqlitedb: this is the default and the recommended option
- nssdb: a NSS softokn database driver, which allows to reuse
an existing token (this is the same format used by the Firefox
security token)

Kryoptic uses OpenSSL (3.2+) for most of the cryptography primitives.
A static build option is available with libcrypto.a (or libfips.a with the
fips feature), or dynamic linking to the system libcrypto.so (default) is
available.

Unimplemented functions are noted in the source code and can be easily
explored by building the documentation. There is a Makefile file to provide
shortcut commands for common tasks, use `make docs` to build documentation
that includes non public interfaces.

[1.0.0]: https://github.com/latchset/kryoptic/releases/tag/v1.0.0
[1.1.0]: https://github.com/latchset/kryoptic/releases/tag/v1.1.0
[1.2.0]: https://github.com/latchset/kryoptic/releases/tag/v1.2.0
[1.3.0]: https://github.com/latchset/kryoptic/releases/tag/v1.3.0
[1.3.1]: https://github.com/latchset/kryoptic/releases/tag/v1.3.1
[1.4.0]: https://github.com/latchset/kryoptic/releases/tag/v1.4.0

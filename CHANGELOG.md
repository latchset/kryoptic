# Changelog

All notable changes to this project should be documented in this file.

## [Unreleased]

### What Changed

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
  [Pkcs11 3.2 Draft](https://github.com/latchset/kryoptic/pull/149)

* Added support for Key Encapdulation/Decapsulation and ML-KEM Support
  [Add Encapsulation/Decapsulation and ML-KEM support](https://github.com/latchset/kryoptic/pull/197)

* Sundry fixes that result in minor, but visible, behavior changes:
  [Deal with length query issues](https://github.com/latchset/kryoptic/pull/185)
  [aes: Restrict AES-GCM to at least 1B tag length](https://github.com/latchset/kryoptic/pull/189)
  [Fix incorrect error returned on un-initialized operations](https://github.com/latchset/kryoptic/pull/192)
  [Ensure token store objects can be extracted if the right booleans are
set](https://github.com/latchset/kryoptic/pull/194)
  [Fix check for object sensitivity as per spec](https://github.com/latchset/kryoptic/pull/198)
  [ecdh: Fix max ECDH output size](https://github.com/latchset/kryoptic/pull/203)
  [Fix C_WrapKey size query](https://github.com/latchset/kryoptic/pull/202)

* Minor enhancements:
  [Add Stricter FIPS options to configuration](https://github.com/latchset/kryoptic/pull/199)
  [Allow digesting AES keys and add test coverage.](https://github.com/latchset/kryoptic/pull/204)


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


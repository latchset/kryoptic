# Changelog

All notable changes to this project should be documented in this file.

## [Unreleased]

### What Changed

* Added support for PKCS#11 3.2 interfaces
  [Pkcs11 3.2 Draft](https://github.com/latchset/kryoptic/pull/149)

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


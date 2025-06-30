// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

/// The static instance of the library context lazily created on first use
#[cfg(not(feature = "fips"))]
static OSSL_CONTEXT: ::std::sync::LazyLock<::ossl::OsslContext> =
    ::std::sync::LazyLock::new(|| ::ossl::OsslContext::new_lib_ctx());

pub mod aes;
pub mod common;
pub mod drbg;

// the derive code for both ECDSA and Montgomery curves
#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "ec_montgomery")]
pub mod montgomery;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "ffdh")]
pub mod ffdh;

#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "hkdf")]
pub mod hkdf;

#[cfg(all(feature = "hmac", feature = "fips"))]
pub mod hmac;

#[cfg(all(feature = "sp800_108", feature = "fips"))]
pub mod kbkdf;

#[cfg(all(feature = "pbkdf2", feature = "fips"))]
pub mod pbkdf2;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(all(feature = "sshkdf", feature = "fips"))]
pub mod sshkdf;

#[cfg(feature = "mlkem")]
pub mod mlkem;

#[cfg(feature = "mldsa")]
pub mod mldsa;

// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed implementation of kryoptic's backend-agnostic crypto
//! traits (see `crate::mechanism`), mirroring `crate::ossl`.

#[cfg(feature = "aes")]
pub mod aes;
pub mod common;
pub mod drbg;
#[cfg(feature = "ecdh")]
pub mod ecdh;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "eddsa")]
pub mod eddsa;
#[cfg(feature = "ffdh")]
pub mod ffdh;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "hkdf")]
pub mod hkdf;
#[cfg(feature = "sp800_108")]
pub mod kbkdf;
// Excluded under awslc-fips specifically: see the matching gate's doc
// comment in src/enabled.rs for the FIPS-validation-boundary rationale.
#[cfg(all(feature = "mldsa", not(feature = "awslc-fips")))]
pub mod mldsa;
#[cfg(feature = "mlkem")]
pub mod mlkem;
#[cfg(feature = "ec_montgomery")]
pub mod montgomery;
#[cfg(all(feature = "pbkdf2", feature = "fips"))]
pub mod pbkdf2;
#[cfg(feature = "rsa")]
pub mod rsa;
#[cfg(feature = "sshkdf")]
pub mod sshkdf;

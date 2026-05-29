// Copyright 2026 Stephan Müller
// See LICENSE.txt file for terms

//! This is a meta crate to provide access to native Rust implementations
//! of cryptographic mechanisms

pub mod common;
pub mod drbg;

//#[cfg(feature = "hmac")]
//pub mod hmac;
#[cfg(all(feature = "pbkdf2", not(feature = "fips")))]
pub mod pbkdf2;
//#[cfg(feature = "simplekdf")]
//pub mod simplekdf;
//#[cfg(all(feature = "sp800_108", not(feature = "fips")))]
//pub mod sp800_108;
//#[cfg(all(feature = "sshkdf", not(feature = "fips")))]
//pub mod sshkdf;
//#[cfg(feature = "tlskdf")]
//pub mod tlskdf;

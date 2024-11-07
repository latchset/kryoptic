// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    include!("bindings.rs");
}

use once_cell::sync::Lazy;

struct OsslContext {
    context: *mut bindings::OSSL_LIB_CTX,
}

unsafe impl Send for OsslContext {}
unsafe impl Sync for OsslContext {}

static OSSL_CONTEXT: Lazy<OsslContext> = Lazy::new(|| unsafe {
    OsslContext {
        context: bindings::OSSL_LIB_CTX_new(),
    }
});

pub fn get_libctx() -> *mut bindings::OSSL_LIB_CTX {
    OSSL_CONTEXT.context
}

pub mod aes;
pub mod common;
pub mod drbg;

// the derive code for both ECDSA and Montgomery curves
#[cfg(any(feature = "ecc", feature = "ec_montgomery"))]
pub mod ecdh;

#[cfg(feature = "ecc")]
pub mod ecc;

#[cfg(all(feature = "ec_montgomery", not(feature = "fips")))]
pub mod ec_montgomery;

#[cfg(all(feature = "eddsa", not(feature = "fips")))]
pub mod eddsa;

#[cfg(feature = "fips")]
pub mod fips;

pub mod hash;
pub mod hkdf;

#[cfg(all(feature = "hmac", feature = "fips"))]
pub mod hmac;

#[cfg(all(feature = "sp800_108", feature = "fips"))]
pub mod kbkdf;

#[cfg(all(feature = "pbkdf2", feature = "fips"))]
pub mod pbkdf2;

pub mod rsa;

#[cfg(all(feature = "sshkdf", feature = "fips"))]
pub mod sshkdf;

// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/ossl_bindings.rs"));
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
#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "ec_montgomery")]
pub mod montgomery;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "fips")]
pub mod fips;

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

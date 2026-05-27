// Copyright 2024 Stephan Müller
// See LICENSE.txt file for terms

//! This module provides common utilities, wrappers, and constants for interacting
//! with the leancrypto library.

use crate::error::Result;
use crate::pkcs11::*;

use leancrypto_sys::lcr_hash::lcr_hash_type;

//#[cfg(feature = "mldsa")]
//use leancrypto_sys::lcr_dilithium::{lcr_dilithium, lcr_dilithium_type};
//#[cfg(feature = "eddsa")]
//use leancrypto_sys::lcr_ed25519::lcr_ed25519;
//#[cfg(feature = "mlkem")]
//use leancrypto_sys::lcr_kyber::{lcr_kyber, lcr_kyber_type};
//#[cfg(feature = "slhdsa")]
//use leancrypto_sys::lcr_sphincs::{lcr_sphincs, lcr_sphincs_type};

/// Maps a PKCS#11 mechanism type involving a hash to the corresponding
/// leancrypto algorithm type
pub fn mech_type_to_digest_alg(
    mech: CK_MECHANISM_TYPE,
) -> Result<lcr_hash_type> {
    Ok(match mech {
        CKM_SHA256_RSA_PKCS
        | CKM_ECDSA_SHA256
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA256_HMAC
        | CKM_SHA256_HMAC_GENERAL
        | CKM_SHA256 => lcr_hash_type::lcr_sha2_256,
        CKM_SHA384_RSA_PKCS
        | CKM_ECDSA_SHA384
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA384_HMAC
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA384 => lcr_hash_type::lcr_sha2_384,
        CKM_SHA512_RSA_PKCS
        | CKM_ECDSA_SHA512
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA512_HMAC
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA512 => lcr_hash_type::lcr_sha2_512,
        CKM_SHA3_256_RSA_PKCS
        | CKM_ECDSA_SHA3_256
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_256_HMAC
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_256 => lcr_hash_type::lcr_sha3_256,
        CKM_SHA3_384_RSA_PKCS
        | CKM_ECDSA_SHA3_384
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_384_HMAC
        | CKM_SHA3_384_HMAC_GENERAL
        | CKM_SHA3_384 => lcr_hash_type::lcr_sha3_384,
        CKM_SHA3_512_RSA_PKCS
        | CKM_ECDSA_SHA3_512
        | CKM_SHA3_512_RSA_PKCS_PSS
        | CKM_SHA3_512_HMAC
        | CKM_SHA3_512_HMAC_GENERAL
        | CKM_SHA3_512 => lcr_hash_type::lcr_sha3_512,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

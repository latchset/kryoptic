// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides common utilities, wrappers, and constants for interacting
//! with the OpenSSL library (`libcrypto`) via its C API, primarily focusing on
//! the EVP (high-level) interface and parameter handling (`OSSL_PARAM`).

use std::ffi::c_char;

use crate::error::Result;
#[cfg(feature = "ecc")]
use crate::kasn1::oid;
use crate::misc::*;
use crate::object::Object;

use ossl::bindings::*;
use ossl::*;
use pkcs11::*;

#[cfg(feature = "ecc")]
use crate::ec::get_oid_from_obj;
#[cfg(feature = "ecdsa")]
use crate::ossl::ecdsa;
#[cfg(feature = "eddsa")]
use crate::ossl::eddsa;
#[cfg(feature = "ffdh")]
use crate::ossl::ffdh;
#[cfg(feature = "mldsa")]
use crate::ossl::mldsa;
#[cfg(feature = "mlkem")]
use crate::ossl::mlkem;
#[cfg(feature = "ec_montgomery")]
use crate::ossl::montgomery as ecm;
#[cfg(feature = "rsa")]
use crate::ossl::rsa;

pub fn osslctx() -> &'static OsslContext {
    #[cfg(feature = "fips")]
    {
        ossl::fips::get_libctx()
    }
    #[cfg(not(feature = "fips"))]
    {
        &crate::ossl::OSSL_CONTEXT
    }
}

/// Creates an `EvpPkey` (public or private) from a PKCS#11 `Object`.
///
/// Extracts necessary attributes from the `Object` based on its
/// `CKA_KEY_TYPE` and `class` (public/private), converts them into
/// `OSSL_PARAM`s using algorithm-specific helpers, and then calls
/// `EvpPkey::fromdata`.
pub fn evp_pkey_from_object(
    obj: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let key_class = match class {
        CKO_PUBLIC_KEY => EVP_PKEY_PUBLIC_KEY,
        CKO_PRIVATE_KEY => EVP_PKEY_PRIVATE_KEY,
        _ => return Err(CKR_GENERAL_ERROR)?,
    };
    let key_type = obj.get_attr_as_ulong(CKA_KEY_TYPE)?;
    let (name, params) = match key_type {
        #[cfg(feature = "ecdsa")]
        CKK_EC => ecdsa::ecc_object_to_params(obj, class)?,
        #[cfg(feature = "eddsa")]
        CKK_EC_EDWARDS => eddsa::eddsa_object_to_params(obj, class)?,
        #[cfg(feature = "ec_montgomery")]
        CKK_EC_MONTGOMERY => ecm::ecm_object_to_params(obj, class)?,
        #[cfg(feature = "ffdh")]
        CKK_DH => ffdh::ffdh_object_to_params(obj, class)?,
        #[cfg(feature = "rsa")]
        CKK_RSA => rsa::rsa_object_to_params(obj, class)?,
        #[cfg(feature = "mlkem")]
        CKK_ML_KEM => mlkem::mlkem_object_to_params(obj, class)?,
        #[cfg(feature = "mldsa")]
        CKK_ML_DSA => mldsa::mldsa_object_to_params(obj, class)?,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };
    Ok(EvpPkey::fromdata(osslctx(), name, key_class, &params)?)
}

/// Creates a public `EvpPkey` from a PKCS#11 `Object`.
#[allow(dead_code)]
pub fn pubkey_from_object(obj: &Object) -> Result<EvpPkey> {
    evp_pkey_from_object(obj, CKO_PUBLIC_KEY)
}

/// Creates a private `EvpPkey` from a PKCS#11 `Object`.
#[allow(dead_code)]
pub fn privkey_from_object(obj: &Object) -> Result<EvpPkey> {
    evp_pkey_from_object(obj, CKO_PRIVATE_KEY)
}

pub const CIPHER_NAME_AES128: &[u8; 7] = b"AES128\0";
pub const CIPHER_NAME_AES192: &[u8; 7] = b"AES192\0";
pub const CIPHER_NAME_AES256: &[u8; 7] = b"AES256\0";

/// Utility function to cast a Rust byte slice (`&[u8]`) to a C-style
/// null-terminated string pointer (`*const c_char`).
pub fn name_as_char(name: &[u8]) -> *const c_char {
    name.as_ptr() as *const c_char
}

/// Maps a PKCS#11 mechanism type involving a hash to the corresponding
/// OpenSSL digest name string (e.g., `CKM_SHA256_RSA_PKCS` -> `"SHA256"`).
pub fn mech_type_to_digest_name(mech: CK_MECHANISM_TYPE) -> *const c_char {
    (match mech {
        CKM_SHA1_RSA_PKCS
        | CKM_ECDSA_SHA1
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA_1_HMAC
        | CKM_SHA_1_HMAC_GENERAL
        | CKM_SHA_1 => OSSL_DIGEST_NAME_SHA1.as_ptr(),
        CKM_SHA224_RSA_PKCS
        | CKM_ECDSA_SHA224
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA224_HMAC
        | CKM_SHA224_HMAC_GENERAL
        | CKM_SHA224 => OSSL_DIGEST_NAME_SHA2_224.as_ptr(),
        CKM_SHA256_RSA_PKCS
        | CKM_ECDSA_SHA256
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA256_HMAC
        | CKM_SHA256_HMAC_GENERAL
        | CKM_SHA256 => OSSL_DIGEST_NAME_SHA2_256.as_ptr(),
        CKM_SHA384_RSA_PKCS
        | CKM_ECDSA_SHA384
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA384_HMAC
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA384 => OSSL_DIGEST_NAME_SHA2_384.as_ptr(),
        CKM_SHA512_RSA_PKCS
        | CKM_ECDSA_SHA512
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA512_HMAC
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA512 => OSSL_DIGEST_NAME_SHA2_512.as_ptr(),
        CKM_SHA3_224_RSA_PKCS
        | CKM_ECDSA_SHA3_224
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_224_HMAC
        | CKM_SHA3_224_HMAC_GENERAL
        | CKM_SHA3_224 => OSSL_DIGEST_NAME_SHA3_224.as_ptr(),
        CKM_SHA3_256_RSA_PKCS
        | CKM_ECDSA_SHA3_256
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_256_HMAC
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_256 => OSSL_DIGEST_NAME_SHA3_256.as_ptr(),
        CKM_SHA3_384_RSA_PKCS
        | CKM_ECDSA_SHA3_384
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_384_HMAC
        | CKM_SHA3_384_HMAC_GENERAL
        | CKM_SHA3_384 => OSSL_DIGEST_NAME_SHA3_384.as_ptr(),
        CKM_SHA3_512_RSA_PKCS
        | CKM_ECDSA_SHA3_512
        | CKM_SHA3_512_RSA_PKCS_PSS
        | CKM_SHA3_512_HMAC
        | CKM_SHA3_512_HMAC_GENERAL
        | CKM_SHA3_512 => OSSL_DIGEST_NAME_SHA3_512.as_ptr(),
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL | CKM_SHA512_224 => {
            OSSL_DIGEST_NAME_SHA2_512_224.as_ptr()
        }
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL | CKM_SHA512_256 => {
            OSSL_DIGEST_NAME_SHA2_512_256.as_ptr()
        }
        _ => std::ptr::null(),
    }) as *const c_char
}

#[cfg(feature = "ecc")]
pub static EC_NAME: &[u8; 3] = b"EC\0";
#[cfg(all(feature = "ecc", feature = "fips"))]
pub static ECDSA_NAME: &[u8; 6] = b"ECDSA\0";

/* Curve names as used in OpenSSL */
#[cfg(feature = "ecc")]
const NAME_SECP256R1: &[u8] = b"prime256v1\0";
#[cfg(feature = "ecc")]
const NAME_SECP384R1: &[u8] = b"secp384r1\0";
#[cfg(feature = "ecc")]
const NAME_SECP521R1: &[u8] = b"secp521r1\0";
#[cfg(feature = "ecc")]
const NAME_ED25519: &[u8] = b"ED25519\0";
#[cfg(feature = "ecc")]
const NAME_ED448: &[u8] = b"ED448\0";
#[cfg(feature = "ecc")]
const NAME_X25519: &[u8] = b"X25519\0";
#[cfg(feature = "ecc")]
const NAME_X448: &[u8] = b"X448\0";

/// Maps an ASN.1 Object Identifier for an EC curve to the OpenSSL curve name
/// string.
#[cfg(feature = "ecc")]
fn oid_to_ossl_name(oid: &asn1::ObjectIdentifier) -> Result<&'static [u8]> {
    match oid {
        &oid::EC_SECP256R1 => Ok(NAME_SECP256R1),
        &oid::EC_SECP384R1 => Ok(NAME_SECP384R1),
        &oid::EC_SECP521R1 => Ok(NAME_SECP521R1),
        &oid::ED25519_OID => Ok(NAME_ED25519),
        &oid::ED448_OID => Ok(NAME_ED448),
        &oid::X25519_OID => Ok(NAME_X25519),
        &oid::X448_OID => Ok(NAME_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Gets the OpenSSL curve name string associated with a PKCS#11 EC key `Object`.
#[cfg(feature = "ecc")]
pub fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    oid_to_ossl_name(&get_oid_from_obj(key)?)
}

/// Securely zeroizes a memory slice using `OPENSSL_cleanse`.
pub fn zeromem(mem: &mut [u8]) {
    unsafe {
        OPENSSL_cleanse(void_ptr!(mem.as_mut_ptr()), mem.len());
    }
}

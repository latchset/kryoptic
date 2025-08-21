// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides common utilities, wrappers, and constants for interacting
//! with the OpenSSL library (`libcrypto`) via its C API, primarily focusing on
//! the EVP (high-level) interface and parameter handling (`OSSL_PARAM`).

use crate::error::Result;
#[cfg(feature = "ecc")]
use crate::kasn1::oid;
use crate::object::Object;
use crate::pkcs11::*;

use ossl::digest::DigestAlg;
use ossl::pkey::{EvpPkey, EvpPkeyType};
use ossl::OsslContext;

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
#[cfg(feature = "slhdsa")]
use crate::ossl::slhdsa;

pub fn osslctx() -> &'static OsslContext {
    #[cfg(feature = "fips")]
    {
        ossl::fips::get_libctx()
    }
    #[cfg(not(feature = "fips"))]
    {
        &(*crate::ossl::OSSL_CONTEXT)
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
    let key_type = obj.get_attr_as_ulong(CKA_KEY_TYPE)?;
    match key_type {
        #[cfg(feature = "ecdsa")]
        CKK_EC => return ecdsa::ecc_object_to_pkey(obj, class),
        #[cfg(feature = "eddsa")]
        CKK_EC_EDWARDS => return eddsa::eddsa_object_to_pkey(obj, class),
        #[cfg(feature = "ec_montgomery")]
        CKK_EC_MONTGOMERY => return ecm::ecm_object_to_pkey(obj, class),
        #[cfg(feature = "ffdh")]
        CKK_DH => return ffdh::ffdh_object_to_pkey(obj, class),
        #[cfg(feature = "rsa")]
        CKK_RSA => return rsa::rsa_object_to_pkey(obj, class),
        #[cfg(feature = "mlkem")]
        CKK_ML_KEM => return mlkem::mlkem_object_to_pkey(obj, class),
        #[cfg(feature = "mldsa")]
        CKK_ML_DSA => return mldsa::mldsa_object_to_pkey(obj, class),
        #[cfg(feature = "slhdsa")]
        CKK_SLH_DSA => return slhdsa::slhdsa_object_to_pkey(obj, class),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
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

/// Maps a PKCS#11 mechanism type involving a hash to the corresponding
/// ossl DigestAlg
pub fn mech_type_to_digest_alg(mech: CK_MECHANISM_TYPE) -> Result<DigestAlg> {
    Ok(match mech {
        #[cfg(not(feature = "no_sha1"))]
        CKM_SHA1_RSA_PKCS
        | CKM_ECDSA_SHA1
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA_1_HMAC
        | CKM_SHA_1_HMAC_GENERAL
        | CKM_SHA_1 => DigestAlg::Sha1,
        CKM_SHA224_RSA_PKCS
        | CKM_ECDSA_SHA224
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA224_HMAC
        | CKM_SHA224_HMAC_GENERAL
        | CKM_SHA224 => DigestAlg::Sha2_224,
        CKM_SHA256_RSA_PKCS
        | CKM_ECDSA_SHA256
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA256_HMAC
        | CKM_SHA256_HMAC_GENERAL
        | CKM_SHA256 => DigestAlg::Sha2_256,
        CKM_SHA384_RSA_PKCS
        | CKM_ECDSA_SHA384
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA384_HMAC
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA384 => DigestAlg::Sha2_384,
        CKM_SHA512_RSA_PKCS
        | CKM_ECDSA_SHA512
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA512_HMAC
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA512 => DigestAlg::Sha2_512,
        CKM_SHA3_224_RSA_PKCS
        | CKM_ECDSA_SHA3_224
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_224_HMAC
        | CKM_SHA3_224_HMAC_GENERAL
        | CKM_SHA3_224 => DigestAlg::Sha3_224,
        CKM_SHA3_256_RSA_PKCS
        | CKM_ECDSA_SHA3_256
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_256_HMAC
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_256 => DigestAlg::Sha3_256,
        CKM_SHA3_384_RSA_PKCS
        | CKM_ECDSA_SHA3_384
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_384_HMAC
        | CKM_SHA3_384_HMAC_GENERAL
        | CKM_SHA3_384 => DigestAlg::Sha3_384,
        CKM_SHA3_512_RSA_PKCS
        | CKM_ECDSA_SHA3_512
        | CKM_SHA3_512_RSA_PKCS_PSS
        | CKM_SHA3_512_HMAC
        | CKM_SHA3_512_HMAC_GENERAL
        | CKM_SHA3_512 => DigestAlg::Sha3_512,
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL | CKM_SHA512_224 => {
            DigestAlg::Sha2_512_224
        }
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL | CKM_SHA512_256 => {
            DigestAlg::Sha2_512_256
        }
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

/// Maps an ASN.1 Object Identifier for an EC curve to EvpPkeyType
#[cfg(feature = "ecc")]
fn oid_to_evp_key_type(oid: &asn1::ObjectIdentifier) -> Result<EvpPkeyType> {
    match oid {
        &oid::EC_SECP256R1 => Ok(EvpPkeyType::P256),
        &oid::EC_SECP384R1 => Ok(EvpPkeyType::P384),
        &oid::EC_SECP521R1 => Ok(EvpPkeyType::P521),
        &oid::ED25519_OID => Ok(EvpPkeyType::Ed25519),
        &oid::ED448_OID => Ok(EvpPkeyType::Ed448),
        &oid::X25519_OID => Ok(EvpPkeyType::X25519),
        &oid::X448_OID => Ok(EvpPkeyType::X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Gets the EvpPkeyType associated with a PKCS#11 EC key `Object`.
#[cfg(feature = "ecc")]
pub fn get_evp_pkey_type_from_obj(key: &Object) -> Result<EvpPkeyType> {
    oid_to_evp_key_type(&get_oid_from_obj(key)?)
}

// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements functionalities related to Montgomery curves
//! (Curve25519/X25519, Curve448/X448) using the OpenSSL EVP interface,
//! primarily key generation and parameter conversion.

use std::ffi::{c_int, CStr};

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::object::Object;
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::pkey::EvpPkey;
use ossl::OsslParam;
use pkcs11::*;

/// Converts a PKCS#11 Montgomery curve key `Object` (X25519/X448) into
/// OpenSSL parameters (`OsslParam`).
///
/// Extracts the curve name and relevant key components (public point or
/// private value) based on the object `class` and populates an `OsslParam`
/// structure.
pub fn ecm_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(&'static CStr, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    let mut params = OsslParam::with_capacity(1);
    params.zeroize = true;

    let name = get_ossl_name_from_obj(key)?;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_owned_octet_string(
                cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                get_ec_point_from_obj(key)?,
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_octet_string(
                cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?;
        }

        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    Ok((name, params))
}

/// Represents state for Montgomery curve operations (currently mainly keygen).
/// Placeholder for potential future stateful operations like key derivation.
#[derive(Debug)]
pub struct ECMontgomeryOperation {}

impl ECMontgomeryOperation {
    /// Generates a Montgomery curve key pair (X25519 or X448).
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s (which define the curve via CKA_EC_PARAMS), generates the
    /// key pair using OpenSSL, and populates the CKA_EC_POINT and CKA_VALUE
    /// attributes.
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let evp_pkey =
            EvpPkey::generate(osslctx(), get_evp_pkey_type_from_obj(pubkey)?)?;

        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_todata(
                evp_pkey.as_ptr(),
                c_int::try_from(EVP_PKEY_KEYPAIR)?,
                &mut params,
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let params = OsslParam::from_ptr(params)?;
        /* Public Key */
        let point = params
            .get_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY))?
            .to_vec();
        pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, point))?;

        /* Private Key */
        let value = params
            .get_octet_string(cstr!(OSSL_PKEY_PARAM_PRIV_KEY))?
            .to_vec();
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, value))?;
        Ok(())
    }
}

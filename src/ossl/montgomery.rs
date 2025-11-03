// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements functionalities related to Montgomery curves
//! (Curve25519/X25519, Curve448/X448) using the OpenSSL EVP interface,
//! primarily key generation and parameter conversion.

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::object::Object;
use crate::ossl::common::{get_evp_pkey_type_from_obj, osslctx};
use crate::pkcs11::*;

use ossl::pkey::{EccData, EvpPkey, PkeyData};
use ossl::OsslSecret;

/// Converts a PKCS#11 Montgomery curve key `Object` (X25519/X448) into
/// an `EvpPkey`.
///
/// Extracts the curve name and relevant key components (public point or
/// private value) based on the object `class` and populates an `EccData`
/// structure.
pub fn ecm_object_to_pkey(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    match kclass {
        CKO_PUBLIC_KEY => Ok(EvpPkey::import(
            osslctx(),
            get_evp_pkey_type_from_obj(key)?,
            PkeyData::Ecc(EccData {
                pubkey: Some(get_ec_point_from_obj(key)?),
                prikey: None,
            }),
        )?),
        CKO_PRIVATE_KEY => Ok(EvpPkey::import(
            osslctx(),
            get_evp_pkey_type_from_obj(key)?,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(OsslSecret::from_vec(
                    key.get_attr_as_bytes(CKA_VALUE)?.clone(),
                )),
            }),
        )?),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
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
        let pkey =
            EvpPkey::generate(osslctx(), get_evp_pkey_type_from_obj(pubkey)?)?;
        let mut ecc = match pkey.export()? {
            PkeyData::Ecc(e) => e,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        /* Set Public Key */
        if let Some(key) = ecc.pubkey.take() {
            pubkey.set_attr(Attribute::from_bytes(
                CKA_EC_POINT,
                (&key).to_vec(),
            ))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* Set Private Key */
        if let Some(key) = ecc.prikey.take() {
            privkey
                .set_attr(Attribute::from_bytes(CKA_VALUE, (&key).to_vec()))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }
}

/// Extracts the public key point from a private key object.
///
/// This is done by importing the private key into OpenSSL and then
/// exporting the full keypair to get the public key.
/// The public key is returned as raw bytes.
pub fn extract_public_key(privkey: &Object) -> Result<Vec<u8>> {
    // 1. Import private key into EvpPkey
    let pkey = ecm_object_to_pkey(privkey, CKO_PRIVATE_KEY)?;

    // 2. Export key data
    let mut ecc = match pkey.export()? {
        PkeyData::Ecc(e) => e,
        _ => return Err(CKR_GENERAL_ERROR)?,
    };

    // 3. Extract public key point
    if let Some(key) = ecc.pubkey.take() {
        // 4. Return as raw bytes
        Ok((&key).to_vec())
    } else {
        Err(CKR_KEY_UNEXTRACTABLE)?
    }
}

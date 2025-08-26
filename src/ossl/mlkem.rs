// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the ML-KEM Key Encapsulation Mechanism as defined
//! in FIPS 203, using the OpenSSL (3.5+) EVP_PKEY interface. It handles key
//! generation, encapsulation, and decapsulation.

use crate::attribute::Attribute;
use crate::error::Result;
use crate::object::Object;
use crate::ossl::common::{osslctx, privkey_from_object, pubkey_from_object};
use crate::pkcs11::*;

use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::{ErrorKind, OsslSecret};

/// Maps a PKCS#11 ML-KEM parameter set type (`CK_ML_KEM_PARAMETER_SET_TYPE`)
/// to the corresponding EvpPkeyType
pub fn mlkem_param_set_to_pkey_type(
    pset: CK_ML_KEM_PARAMETER_SET_TYPE,
) -> Result<EvpPkeyType> {
    match pset {
        CKP_ML_KEM_512 => Ok(EvpPkeyType::MlKem512),
        CKP_ML_KEM_768 => Ok(EvpPkeyType::MlKem768),
        CKP_ML_KEM_1024 => Ok(EvpPkeyType::MlKem1024),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Extracts the parameter set (`CKA_PARAMETER_SET`) to determine the algorithm
/// name. Extracts key components (`CKA_VALUE` for public/private key,
/// `CKA_SEED`) based on the object `class` and populates a `MlkeyData`
/// structure.
pub fn mlkem_object_to_pkey(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }

    let param_set = key.get_attr_as_ulong(CKA_PARAMETER_SET)?;

    match kclass {
        CKO_PUBLIC_KEY => Ok(EvpPkey::import(
            osslctx(),
            mlkem_param_set_to_pkey_type(param_set)?,
            PkeyData::Mlkey(MlkeyData {
                pubkey: Some(key.get_attr_as_bytes(CKA_VALUE)?.clone()),
                prikey: None,
                seed: None,
            }),
            None,
        )?),
        CKO_PRIVATE_KEY => Ok(EvpPkey::import(
            osslctx(),
            mlkem_param_set_to_pkey_type(param_set)?,
            PkeyData::Mlkey(MlkeyData {
                pubkey: None,
                prikey: Some(OsslSecret::from_vec(
                    key.get_attr_as_bytes(CKA_VALUE)?.clone(),
                )),
                seed: match key.get_attr_as_bytes(CKA_SEED) {
                    Ok(s) => Some(OsslSecret::from_vec(s.clone())),
                    Err(_) => None,
                },
            }),
            None,
        )?),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
}

/// Performs the ML-KEM key encapsulation operation using the recipient's
/// public key.
///
/// Returns a tuple containing the derived shared secret (`Vec<u8>`) and
/// the actual length of the generated ciphertext written to the `ciphertext`
/// buffer.
pub fn encapsulate(
    key: &Object,
    ciphertext: &mut [u8],
) -> Result<(Vec<u8>, usize)> {
    let mut pubkey = pubkey_from_object(key)?;
    let mut ctx =
        OsslAsymcipher::new(osslctx(), EncOp::Encapsulate, &mut pubkey, None)?;
    match ctx.encapsulate(ciphertext) {
        Ok(ret) => Ok(ret),
        Err(e) => match e.kind() {
            ErrorKind::BufferSize => Err(CKR_BUFFER_TOO_SMALL)?,
            _ => Err(CKR_DEVICE_ERROR)?,
        },
    }
}

/// Performs the ML-KEM key decapsulation operation using the recipient's
/// private key and the received ciphertext.
///
/// Uses the `OsslEncapsulation` API.
///
/// Returns the derived shared secret (`Vec<u8>`).
pub fn decapsulate(key: &Object, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut prikey = privkey_from_object(key)?;
    let mut ctx =
        OsslAsymcipher::new(osslctx(), EncOp::Decapsulate, &mut prikey, None)?;
    Ok(ctx.decapsulate(ciphertext)?)
}

/// Generates an ML-KEM key pair for the specified parameter set.
///
/// Uses the OpenSSL `EVP_PKEY_generate` API and populates the public key
/// (`CKA_VALUE`), private key (`CKA_VALUE`), and private seed (`CKA_SEED`)
/// attributes in the provided `Object`s.
pub fn generate_keypair(
    param_set: CK_ML_KEM_PARAMETER_SET_TYPE,
    pubkey: &mut Object,
    privkey: &mut Object,
) -> Result<()> {
    let pkey = EvpPkey::generate(
        osslctx(),
        mlkem_param_set_to_pkey_type(param_set)?,
        None,
    )?;

    let mut mlk = match pkey.export()? {
        PkeyData::Mlkey(m) => m,
        _ => return Err(CKR_GENERAL_ERROR)?,
    };

    /* Set Public Key */
    if let Some(key) = mlk.pubkey.take() {
        pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
    } else {
        return Err(CKR_DEVICE_ERROR)?;
    }

    /* Set private key and/or seed */
    if mlk.prikey.is_none() && mlk.seed.is_none() {
        return Err(CKR_DEVICE_ERROR)?;
    }
    if let Some(key) = mlk.prikey.take() {
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, key.to_vec()))?;
    }
    if let Some(seed) = mlk.seed.take() {
        privkey.set_attr(Attribute::from_bytes(CKA_SEED, seed.to_vec()))?;
    }

    Ok(())
}

// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the ML-KEM Key Encapsulation Mechanism as defined
//! in FIPS 203, using the OpenSSL (3.5+) EVP_PKEY interface. It handles key
//! generation, encapsulation, and decapsulation.

use std::ffi::c_char;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::object::Object;
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::{ErrorKind, EvpPkey, OsslParam};
use pkcs11::*;

/* Openssl Key types */
static ML_KEM_512_TYPE: &[u8; 11] = b"ML-KEM-512\0";
static ML_KEM_768_TYPE: &[u8; 11] = b"ML-KEM-768\0";
static ML_KEM_1024_TYPE: &[u8; 12] = b"ML-KEM-1024\0";

/// Maps a PKCS#11 ML-KEM parameter set type (`CK_ML_KEM_PARAMETER_SET_TYPE`)
/// to the corresponding OpenSSL algorithm name string (e.g., "ML-KEM-768").
pub fn mlkem_param_set_to_name(
    pset: CK_ML_KEM_PARAMETER_SET_TYPE,
) -> Result<*const c_char> {
    match pset {
        CKP_ML_KEM_512 => Ok(name_as_char(ML_KEM_512_TYPE)),
        CKP_ML_KEM_768 => Ok(name_as_char(ML_KEM_768_TYPE)),
        CKP_ML_KEM_1024 => Ok(name_as_char(ML_KEM_1024_TYPE)),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// Converts a PKCS#11 ML-KEM key `Object` into OpenSSL parameters
/// (`OsslParam`).
///
/// Extracts the parameter set (`CKA_PARAMETER_SET`) to determine the algorithm
/// name. Extracts key components (`CKA_VALUE` for public/private key,
/// `CKA_SEED`) based on the object `class` and populates an `OsslParam`
/// structure.
pub fn mlkem_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(*const c_char, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }
    let mut params = OsslParam::with_capacity(3);
    params.zeroize = true;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PUB_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.to_vec(),
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_owned_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.to_vec(),
            )?;
            match key.get_attr_as_bytes(CKA_SEED) {
                Ok(s) => params.add_owned_octet_string(
                    name_as_char(OSSL_PKEY_PARAM_ML_KEM_SEED),
                    s.to_vec(),
                )?,
                Err(_) => (),
            }
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    let param_set = key.get_attr_as_ulong(CKA_PARAMETER_SET)?;
    Ok((mlkem_param_set_to_name(param_set)?, params))
}

/// Performs the ML-KEM key encapsulation operation using the recipient's
/// public key.
///
/// Uses the OpenSSL `EVP_PKEY_encapsulate` API.
///
/// Returns a tuple containing the derived shared secret (`Vec<u8>`) and
/// the actual length of the generated ciphertext written to the `ciphertext`
/// buffer.
pub fn encapsulate(
    key: &Object,
    ciphertext: &mut [u8],
) -> Result<(Vec<u8>, usize)> {
    let mut pubkey = pubkey_from_object(key)?;
    let mut ctx = pubkey.new_ctx(osslctx())?;
    if unsafe {
        EVP_PKEY_encapsulate_init(ctx.as_mut_ptr(), std::ptr::null_mut())
    } != 1
    {
        return Err(CKR_DEVICE_ERROR)?;
    }

    let mut outlen = 0;
    let mut keylen = 0;

    if unsafe {
        EVP_PKEY_encapsulate(
            ctx.as_mut_ptr(),
            std::ptr::null_mut(),
            &mut outlen,
            std::ptr::null_mut(),
            &mut keylen,
        )
    } != 1
    {
        return Err(CKR_DEVICE_ERROR)?;
    }

    if ciphertext.len() < outlen {
        return Err(CKR_BUFFER_TOO_SMALL)?;
    }

    let mut keydata = vec![0u8; keylen];
    if unsafe {
        EVP_PKEY_encapsulate(
            ctx.as_mut_ptr(),
            ciphertext.as_mut_ptr(),
            &mut outlen,
            keydata.as_mut_ptr(),
            &mut keylen,
        )
    } != 1
    {
        return Err(CKR_DEVICE_ERROR)?;
    }

    Ok((keydata, outlen))
}

/// Performs the ML-KEM key decapsulation operation using the recipient's
/// private key and the received ciphertext.
///
/// Uses the OpenSSL `EVP_PKEY_decapsulate` API.
///
/// Returns the derived shared secret (`Vec<u8>`).
pub fn decapsulate(key: &Object, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut privkey = privkey_from_object(key)?;
    let mut ctx = privkey.new_ctx(osslctx())?;
    if unsafe {
        EVP_PKEY_decapsulate_init(ctx.as_mut_ptr(), std::ptr::null_mut())
    } != 1
    {
        return Err(CKR_DEVICE_ERROR)?;
    }

    let mut keylen = 0;
    if unsafe {
        EVP_PKEY_decapsulate(
            ctx.as_mut_ptr(),
            std::ptr::null_mut(),
            &mut keylen,
            ciphertext.as_ptr(),
            ciphertext.len(),
        )
    } != 1
    {
        return Err(CKR_DEVICE_ERROR)?;
    }

    let mut keydata = vec![0u8; keylen];
    if unsafe {
        EVP_PKEY_decapsulate(
            ctx.as_mut_ptr(),
            keydata.as_mut_ptr(),
            &mut keylen,
            ciphertext.as_ptr(),
            ciphertext.len(),
        )
    } != 1
    {
        return Err(CKR_DEVICE_ERROR)?;
    }

    Ok(keydata)
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
    let evp_pkey = EvpPkey::generate(
        osslctx(),
        mlkem_param_set_to_name(param_set)?,
        &OsslParam::empty(),
    )?;

    let params = evp_pkey.todata(EVP_PKEY_KEYPAIR)?;

    let val = params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?;
    pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, val.to_vec()))?;

    let val =
        params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?;
    privkey.set_attr(Attribute::from_bytes(CKA_VALUE, val.to_vec()))?;

    match params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_ML_KEM_SEED)) {
        Ok(val) => {
            privkey.set_attr(Attribute::from_bytes(CKA_SEED, val.to_vec()))?
        }
        Err(e) => {
            if e.kind() != ErrorKind::NullPtr {
                return Err(CKR_GENERAL_ERROR)?;
            }
        }
    }
    Ok(())
}

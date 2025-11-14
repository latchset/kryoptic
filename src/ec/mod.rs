// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module provides access to Eliipitic Curve Cryptography related
//! operations

use crate::attribute::Attribute;
use crate::error::{device_error, general_error, Error, Result};
use crate::kasn1::oid::*;
use crate::kasn1::pkcs::*;
use crate::kasn1::PrivateKeyInfo;
use crate::misc::zeromem;
use crate::object::Object;
use crate::pkcs11::*;

use asn1;

#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "ec_montgomery")]
pub mod montgomery;

/* Bit sizes for curves */
pub const BITS_SECP256R1: usize = 256;
#[allow(dead_code)]
pub const BITS_SECP384R1: usize = 384;
pub const BITS_SECP521R1: usize = 521;
pub const BITS_ED25519: usize = 256;
pub const BITS_ED448: usize = 456;
pub const BITS_X25519: usize = 256;
pub const BITS_X448: usize = 448;

const EC_POINT_BYTES_SECP256R1: usize = 2 * ((BITS_SECP256R1 + 7) / 8) + 1;
const EC_POINT_BYTES_SECP384R1: usize = 2 * ((BITS_SECP384R1 + 7) / 8) + 1;
const EC_POINT_BYTES_SECP521R1: usize = 2 * ((BITS_SECP521R1 + 7) / 8) + 1;
const EC_POINT_BYTES_ED25519: usize = (BITS_ED25519 + 7) / 8;
const EC_POINT_BYTES_ED448: usize = (BITS_ED448 + 7) / 8;
const EC_POINT_BYTES_X25519: usize = (BITS_X25519 + 7) / 8;
const EC_POINT_BYTES_X448: usize = (BITS_X448 + 7) / 8;

const EC_KEY_BYTES_SECP256R1: usize = (BITS_SECP256R1 + 7) / 8;
const EC_KEY_BYTES_SECP384R1: usize = (BITS_SECP384R1 + 7) / 8;
const EC_KEY_BYTES_SECP521R1: usize = (BITS_SECP521R1 + 7) / 8;
const EC_KEY_BYTES_ED25519: usize = (BITS_ED25519 + 7) / 8;
const EC_KEY_BYTES_ED448: usize = (BITS_ED448 + 7) / 8;
const EC_KEY_BYTES_X25519: usize = (BITS_X25519 + 7) / 8;
const EC_KEY_BYTES_X448: usize = (BITS_X448 + 7) / 8;

/* Curve names as used in CurveName PrinableString */
pub const PRIME256V1: &str = "prime256v1";
pub const SECP384R1: &str = "secp384r1";
pub const SECP521R1: &str = "secp521r1";
pub const EDWARDS25519: &str = "edwards25519";
pub const EDWARDS448: &str = "edwards448";
pub const CURVE25519: &str = "curve25519";
pub const CURVE448: &str = "curve448";

/// Returns the Point size in bytes for the curve identified by the OID
pub fn ec_point_size(oid: &asn1::ObjectIdentifier) -> Result<usize> {
    match oid {
        &EC_SECP256R1 => Ok(EC_POINT_BYTES_SECP256R1),
        &EC_SECP384R1 => Ok(EC_POINT_BYTES_SECP384R1),
        &EC_SECP521R1 => Ok(EC_POINT_BYTES_SECP521R1),
        &ED25519_OID => Ok(EC_POINT_BYTES_ED25519),
        &ED448_OID => Ok(EC_POINT_BYTES_ED448),
        &X25519_OID => Ok(EC_POINT_BYTES_X25519),
        &X448_OID => Ok(EC_POINT_BYTES_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Returns the Key size in bytes for the curve identified by the OID
pub fn ec_key_size(oid: &asn1::ObjectIdentifier) -> Result<usize> {
    match oid {
        &EC_SECP256R1 => Ok(EC_KEY_BYTES_SECP256R1),
        &EC_SECP384R1 => Ok(EC_KEY_BYTES_SECP384R1),
        &EC_SECP521R1 => Ok(EC_KEY_BYTES_SECP521R1),
        &ED25519_OID => Ok(EC_KEY_BYTES_ED25519),
        &ED448_OID => Ok(EC_KEY_BYTES_ED448),
        &X25519_OID => Ok(EC_KEY_BYTES_X25519),
        &X448_OID => Ok(EC_KEY_BYTES_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Returns the Key size in bits for the curve identified by the OID
#[cfg(feature = "fips")]
pub fn oid_to_bits(oid: asn1::ObjectIdentifier) -> Result<usize> {
    match oid {
        EC_SECP256R1 => Ok(BITS_SECP256R1),
        EC_SECP384R1 => Ok(BITS_SECP384R1),
        EC_SECP521R1 => Ok(BITS_SECP521R1),
        ED25519_OID => Ok(BITS_ED25519),
        ED448_OID => Ok(BITS_ED448),
        X25519_OID => Ok(BITS_X25519),
        X448_OID => Ok(BITS_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Return the OID for the given named curve
fn curvename_to_oid(name: &str) -> Result<asn1::ObjectIdentifier> {
    match name {
        PRIME256V1 => Ok(EC_SECP256R1),
        SECP384R1 => Ok(EC_SECP384R1),
        SECP521R1 => Ok(EC_SECP521R1),
        EDWARDS25519 => Ok(ED25519_OID),
        EDWARDS448 => Ok(ED448_OID),
        CURVE25519 => Ok(X25519_OID),
        CURVE448 => Ok(X448_OID),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Returns the curve OID for the key object
pub fn get_oid_from_obj(key: &Object) -> Result<asn1::ObjectIdentifier> {
    let params = key.get_attr_as_bytes(CKA_EC_PARAMS)?;
    let ecp = asn1::parse_single::<ECParameters>(params)
        .map_err(|e| Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e))?;
    match ecp {
        ECParameters::OId(oid) => Ok(oid),
        ECParameters::CurveName(c) => curvename_to_oid(c.as_str()),
        _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
    }
}

/// returns the public EC point for the key object
pub fn get_ec_point_from_obj(key: &Object) -> Result<Vec<u8>> {
    let point = key.get_attr_as_bytes(CKA_EC_POINT)?;
    let octet = match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        CKK_EC => {
            /* [u8] is an octet string for the asn1 library */
            asn1::parse_single::<&[u8]>(point).map_err(device_error)?
        }
        CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => point.as_slice(),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };
    Ok(octet.to_vec())
}

#[cfg(test)]
pub fn curvename_to_key_size(name: &str) -> Result<usize> {
    ec_key_size(&curvename_to_oid(name)?)
}

#[cfg(test)]
pub fn curvename_to_ec_params(name: &str) -> Result<Vec<u8>> {
    let params = ECParameters::OId(curvename_to_oid(name)?);
    Ok(asn1::write_single(&params)?.to_vec())
}

/* These functions are needed to fixup CKA_EC_POINT because of the different
 * expected encoding in applications following the 3.0 spec vs applications
 * following 3.1. It is not pretty, but it is the simplest way to handle
 * this issue for now */

/// Converts the point len to the len of the DER encoded point
#[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
pub fn point_len_to_der(len: usize) -> usize {
    match len {
        EC_POINT_BYTES_ED448
        | EC_POINT_BYTES_ED25519 /* matches also X25519 */
        | EC_POINT_BYTES_X448 => len + 2,
        _ => len
    }
}

/// Returns the ASN.1 DER Encoded buffer for a point
#[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
pub fn point_buf_to_der(buf: &[u8], bufsize: usize) -> Result<Option<Vec<u8>>> {
    match buf.len() {
        EC_POINT_BYTES_ED448
        | EC_POINT_BYTES_ED25519 /* matches also X25519 */
        | EC_POINT_BYTES_X448 => {
            if bufsize < buf.len() + 2 {
                return Err(CKR_BUFFER_TOO_SMALL)?;
            }
            Ok(Some(asn1::write_single(&buf)?))
        }
        _ => Ok(None),
    }
}

/// Verifies that the public point on the key object has an acceptable
/// encoding and converts to the canonical encoding if necessary
#[cfg(feature = "ecc")]
pub fn check_ec_point_from_obj(
    oid: &asn1::ObjectIdentifier,
    key: &mut Object,
) -> Result<()> {
    let point = key.get_attr_as_bytes(CKA_EC_POINT)?;
    let size = ec_point_size(&oid)?;

    let octet: &[u8];
    let compat: bool;
    match oid {
        &EC_SECP256R1 | &EC_SECP384R1 | &EC_SECP521R1 => {
            octet = asn1::parse_single::<&[u8]>(point).map_err(device_error)?;
            compat = false;
        }
        &ED25519_OID | &ED448_OID | &X25519_OID | &X448_OID => {
            octet = point.as_slice();
            compat = true;
        }
        _ => return Err(CKR_GENERAL_ERROR)?,
    }

    if octet.len() == size {
        return Ok(());
    }

    if compat && octet.len() == size + 2 {
        /* Compatibility with applications that use DER encoding */
        let raw = asn1::parse_single::<&[u8]>(octet).map_err(device_error)?;
        key.set_attr(Attribute::from_bytes(CKA_EC_POINT, raw.to_vec()))
            .map_err(general_error)?;
        return Ok(());
    }

    Err(CKR_ATTRIBUTE_VALUE_INVALID)?
}

/// Common function to format a private EC key using PKCS#8 encoding
pub fn export_for_wrapping(key: &Object) -> Result<Vec<u8>> {
    key.check_key_ops(
        CKO_PRIVATE_KEY,
        CK_UNAVAILABLE_INFORMATION,
        CKA_EXTRACTABLE,
    )?;

    let key_type = key.get_attr_as_ulong(CKA_KEY_TYPE)?;
    match key_type {
        CKK_EC | CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => (),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };

    let oid = match get_oid_from_obj(key) {
        Ok(o) => o,
        _ => return Err(CKR_GENERAL_ERROR)?,
    };

    let mut asn1_vec = {
        let val = key.get_attr_as_bytes(CKA_VALUE)?;
        match key_type {
            CKK_EC => {
                match asn1::write_single(&ECPrivateKey::new_owned(val)?) {
                    Ok(p) => p,
                    _ => return Err(CKR_GENERAL_ERROR)?,
                }
            }
            CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => val.to_vec(),
            _ => return Err(CKR_GENERAL_ERROR)?,
        }
    };
    let pkeyinfo = PrivateKeyInfo::new(
        &asn1_vec.as_slice(),
        match oid {
            EC_SECP256R1 => EC_SECP256R1_ALG,
            EC_SECP384R1 => EC_SECP384R1_ALG,
            EC_SECP521R1 => EC_SECP521R1_ALG,
            ED25519_OID => ED25519_ALG,
            ED448_OID => ED448_ALG,
            X25519_OID => X25519_ALG,
            X448_OID => X448_ALG,
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
    )?;
    let ret = match asn1::write_single(&pkeyinfo) {
        Ok(x) => Ok(x),
        Err(_) => Err(CKR_GENERAL_ERROR)?,
    };
    drop(pkeyinfo);
    zeromem(asn1_vec.as_mut_slice());
    ret
}

/// Common function to parse a private EC key from PKCS#8 encoded data
pub fn import_from_wrapped(
    key_type: CK_KEY_TYPE,
    data: Vec<u8>,
    mut key: Object,
) -> Result<Object> {
    key.ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
        .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
    key.ensure_ulong(CKA_KEY_TYPE, key_type)
        .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

    let (tlv, extra) = match asn1::strip_tlv(&data) {
        Ok(x) => x,
        Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
    };
    /* Some Key Wrapping algorithms may 0 pad to match block size */
    if !extra.iter().all(|b| *b == 0) {
        return Err(CKR_WRAPPED_KEY_INVALID)?;
    }
    let pkeyinfo = match tlv.parse::<PrivateKeyInfo>() {
        Ok(k) => k,
        Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
    };
    /* filter out unknown OIDs */
    let oid = match pkeyinfo.get_algorithm() {
        &EC_SECP256R1_ALG => &EC_SECP256R1,
        &EC_SECP384R1_ALG => &EC_SECP384R1,
        &EC_SECP521R1_ALG => &EC_SECP521R1,
        &ED25519_ALG => &ED25519_OID,
        &ED448_ALG => &ED448_OID,
        &X25519_ALG => &X25519_OID,
        &X448_ALG => &X448_OID,
        _ => return Err(CKR_WRAPPED_KEY_INVALID)?,
    };
    key.ensure_bytes(
        CKA_EC_PARAMS,
        asn1::write_single(oid).map_err(|_| CKR_WRAPPED_KEY_INVALID)?,
    )?;

    let ecpkey: ECPrivateKey;
    let pkeyval = pkeyinfo.get_private_key();
    let value: &[u8] = match key_type {
        CKK_EC => {
            match oid {
                &EC_SECP256R1 | &EC_SECP384R1 | &EC_SECP521R1 => (),
                _ => return Err(CKR_TEMPLATE_INCONSISTENT)?,
            }
            ecpkey = match asn1::parse_single::<ECPrivateKey>(pkeyval) {
                Ok(k) => k,
                Err(_) => return Err(CKR_WRAPPED_KEY_INVALID)?,
            };
            ecpkey.private_key.as_bytes()
        }
        CKK_EC_EDWARDS => match oid {
            &ED25519_OID | &ED448_OID => pkeyval,
            _ => return Err(CKR_TEMPLATE_INCONSISTENT)?,
        },
        CKK_EC_MONTGOMERY => match oid {
            &X25519_OID | &X448_OID => pkeyval,
            _ => return Err(CKR_TEMPLATE_INCONSISTENT)?,
        },
        _ => return Err(CKR_GENERAL_ERROR)?,
    };

    key.ensure_slice(CKA_VALUE, value)?;

    Ok(key)
}

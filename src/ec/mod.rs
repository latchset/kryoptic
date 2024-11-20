// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use crate::bytes_attr_not_empty;
use crate::error::{device_error, general_error, Result};
use crate::interface::*;
use crate::kasn1::oid::*;
use crate::kasn1::pkcs::*;
use crate::object::Object;

use asn1;

#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "eddsa")]
pub mod eddsa;

#[cfg(feature = "ec_montgomery")]
pub mod montgomery;

pub fn ec_key_check_import(obj: &mut Object) -> Result<()> {
    bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
    bytes_attr_not_empty!(obj; CKA_VALUE);
    Ok(())
}

// Bit sized for curves
pub const BITS_SECP256R1: usize = 256;
#[allow(dead_code)]
pub const BITS_SECP384R1: usize = 384;
pub const BITS_SECP521R1: usize = 521;
pub const BITS_ED25519: usize = 256;
pub const BITS_ED448: usize = 448;
pub const BITS_X25519: usize = 256;
pub const BITS_X448: usize = 448;

/* Curve names as used in CurveName PrinableString */
pub const PRIME256V1: &str = "prime256v1";
pub const SECP384R1: &str = "secp384r1";
pub const SECP521R1: &str = "secp521r1";
pub const EDWARDS25519: &str = "edwards25519";
pub const EDWARDS448: &str = "edwards448";
pub const CURVE25519: &str = "curve25519";
pub const CURVE448: &str = "curve448";

/* Curve names as used in OpenSSL */
const NAME_SECP256R1: &[u8] = b"prime256v1\0";
const NAME_SECP384R1: &[u8] = b"secp384r1\0";
const NAME_SECP521R1: &[u8] = b"secp521r1\0";
const NAME_ED25519: &[u8] = b"ED25519\0";
const NAME_ED448: &[u8] = b"ED448\0";
const NAME_X25519: &[u8] = b"X25519\0";
const NAME_X448: &[u8] = b"X448\0";

pub static EC_NAME: &[u8; 3] = b"EC\0";

#[cfg(any(test, feature = "fips"))]
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

fn oid_to_ossl_name(oid: asn1::ObjectIdentifier) -> Result<&'static [u8]> {
    match oid {
        EC_SECP256R1 => Ok(NAME_SECP256R1),
        EC_SECP384R1 => Ok(NAME_SECP384R1),
        EC_SECP521R1 => Ok(NAME_SECP521R1),
        ED25519_OID => Ok(NAME_ED25519),
        ED448_OID => Ok(NAME_ED448),
        X25519_OID => Ok(NAME_X25519),
        X448_OID => Ok(NAME_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

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

fn curvename_to_ossl_name(
    name: asn1::PrintableString,
) -> Result<&'static [u8]> {
    oid_to_ossl_name(curvename_to_oid(name.as_str())?)
}

pub fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    let params = key
        .get_attr_as_bytes(CKA_EC_PARAMS)
        .map_err(general_error)?;
    let ecp =
        asn1::parse_single::<ECParameters>(params).map_err(general_error)?;
    match ecp {
        ECParameters::OId(oid) => oid_to_ossl_name(oid),
        ECParameters::CurveName(curve) => curvename_to_ossl_name(curve),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn get_oid_from_obj(key: &Object) -> Result<asn1::ObjectIdentifier> {
    let params = key
        .get_attr_as_bytes(CKA_EC_PARAMS)
        .map_err(general_error)?;
    let ecp =
        asn1::parse_single::<ECParameters>(params).map_err(general_error)?;
    match ecp {
        ECParameters::OId(oid) => Ok(oid),
        ECParameters::CurveName(c) => curvename_to_oid(c.as_str()),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn get_ec_point_from_obj(key: &Object) -> Result<Vec<u8>> {
    let point = key.get_attr_as_bytes(CKA_EC_POINT).map_err(general_error)?;
    /* [u8] is an octet string for the asn1 library */
    let octet = asn1::parse_single::<&[u8]>(point).map_err(device_error)?;
    Ok(octet.to_vec())
}

#[cfg(test)]
pub fn curvename_to_bits(name: &str) -> Result<usize> {
    oid_to_bits(curvename_to_oid(name)?)
}

#[cfg(test)]
pub fn curvename_to_ec_params(name: &str) -> Result<Vec<u8>> {
    let params = ECParameters::OId(curvename_to_oid(name)?);
    Ok(asn1::write_single(&params)?.to_vec())
}

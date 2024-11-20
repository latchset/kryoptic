// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use crate::bytes_attr_not_empty;
use crate::error::{device_error, general_error, Result};
use crate::interface::*;
use crate::kasn1::DerEncOctetString;
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

type Version = u64;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub enum ECParameters<'a> {
    // ecParametdders   ECParameters,
    OId(asn1::ObjectIdentifier),
    ImplicitlyCA(asn1::Null),
    CurveName(asn1::PrintableString<'a>),
}

/// Defined in SECG SEC 1, C.4
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct ECPrivateKey<'a> {
    version: Version,
    pub private_key: DerEncOctetString<'a>,
    #[explicit(0)]
    parameters: Option<ECParameters<'a>>,
    #[explicit(1)]
    public_key: Option<asn1::BitString<'a>>,
}

impl ECPrivateKey<'_> {
    pub fn new_owned<'a>(private_key: &'a Vec<u8>) -> Result<ECPrivateKey<'a>> {
        Ok(ECPrivateKey {
            version: 1,
            private_key: DerEncOctetString::new(private_key.as_slice())?,
            parameters: None,
            public_key: None,
        })
    }
}

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

// ASN.1 encoding of OIDs
pub const OID_SECP256R1: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
pub const OID_SECP384R1: asn1::ObjectIdentifier = asn1::oid!(1, 3, 132, 0, 34);
pub const OID_SECP521R1: asn1::ObjectIdentifier = asn1::oid!(1, 3, 132, 0, 35);
pub const OID_ED25519: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 112);
pub const OID_ED448: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 113);
pub const OID_X25519: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 110);
pub const OID_X448: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 111);

// ASN.1 encoding of curve names
const OCTSTR_SECP256R1: &[u8] = &[
    0x13, 0x0a, 0x70, 0x72, 0x69, 0x6d, 0x65, 0x32, 0x35, 0x36, 0x76, 0x31,
];
const OCTSTR_SECP384R1: &[u8] = &[
    0x13, 0x09, 0x73, 0x65, 0x63, 0x70, 0x33, 0x38, 0x34, 0x72, 0x31,
];
const OCTSTR_SECP521R1: &[u8] = &[
    0x13, 0x09, 0x73, 0x65, 0x63, 0x70, 0x35, 0x32, 0x31, 0x72, 0x31,
];
const OCTSTR_ED25519: &[u8] = &[
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35,
    0x31, 0x39,
];
const OCTSTR_ED448: &[u8] = &[
    0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38,
];
const OCTSTR_X25519: &[u8] = &[
    0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
];
const OCTSTR_X448: &[u8] =
    &[0x13, 0x08, 0x63, 0x75, 0x72, 0x76, 0x65, 0x34, 0x34, 0x38];

const NAME_SECP256R1: &[u8] = b"prime256v1\0";
const NAME_SECP384R1: &[u8] = b"secp384r1\0";
const NAME_SECP521R1: &[u8] = b"secp521r1\0";
const NAME_ED25519: &[u8] = b"ED25519\0";
const NAME_ED448: &[u8] = b"ED448\0";
const NAME_X25519: &[u8] = b"X25519\0";
const NAME_X448: &[u8] = b"X448\0";

pub static EC_NAME: &[u8; 3] = b"EC\0";

#[cfg(any(test, feature = "fips"))]
pub fn curve_name_to_bits(name: &[u8]) -> Result<usize> {
    match name {
        NAME_SECP256R1 => Ok(BITS_SECP256R1),
        NAME_SECP384R1 => Ok(BITS_SECP384R1),
        NAME_SECP521R1 => Ok(BITS_SECP521R1),
        NAME_ED25519 => Ok(BITS_ED25519),
        NAME_ED448 => Ok(BITS_ED448),
        NAME_X25519 => Ok(BITS_X25519),
        NAME_X448 => Ok(BITS_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

fn oid_to_ossl_name(oid: asn1::ObjectIdentifier) -> Result<&'static [u8]> {
    match oid {
        OID_SECP256R1 => Ok(NAME_SECP256R1),
        OID_SECP384R1 => Ok(NAME_SECP384R1),
        OID_SECP521R1 => Ok(NAME_SECP521R1),
        OID_ED25519 => Ok(NAME_ED25519),
        OID_ED448 => Ok(NAME_ED448),
        OID_X25519 => Ok(NAME_X25519),
        OID_X448 => Ok(NAME_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

fn curve_to_oid(name: asn1::PrintableString) -> Result<asn1::ObjectIdentifier> {
    match asn1::write_single(&name).map_err(general_error)?.as_slice() {
        OCTSTR_SECP256R1 => Ok(OID_SECP256R1),
        OCTSTR_SECP384R1 => Ok(OID_SECP384R1),
        OCTSTR_SECP521R1 => Ok(OID_SECP521R1),
        OCTSTR_ED25519 => Ok(OID_ED25519),
        OCTSTR_ED448 => Ok(OID_ED448),
        OCTSTR_X25519 => Ok(OID_X25519),
        OCTSTR_X448 => Ok(OID_X448),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

fn curve_to_ossl_name(name: asn1::PrintableString) -> Result<&'static [u8]> {
    match asn1::write_single(&name).map_err(general_error)?.as_slice() {
        OCTSTR_SECP256R1 => Ok(NAME_SECP256R1),
        OCTSTR_SECP384R1 => Ok(NAME_SECP384R1),
        OCTSTR_SECP521R1 => Ok(NAME_SECP521R1),
        OCTSTR_ED25519 => Ok(NAME_ED25519),
        OCTSTR_ED448 => Ok(NAME_ED448),
        OCTSTR_X25519 => Ok(NAME_X25519),
        OCTSTR_X448 => Ok(NAME_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    let params = key
        .get_attr_as_bytes(CKA_EC_PARAMS)
        .map_err(general_error)?;
    let ecp =
        asn1::parse_single::<ECParameters>(params).map_err(general_error)?;
    match ecp {
        ECParameters::OId(oid) => oid_to_ossl_name(oid),
        ECParameters::CurveName(curve) => curve_to_ossl_name(curve),
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
        ECParameters::CurveName(c) => curve_to_oid(c),
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
pub fn map_curve_name(curve: &str) -> Option<&'static [u8]> {
    static NAME_SECP224R1: &[u8; 11] = b"prime224v1\0";
    match curve {
        "P-224" => Some(NAME_SECP224R1),
        "P-256" => Some(NAME_SECP256R1),
        "P-384" => Some(NAME_SECP384R1),
        "P-521" => Some(NAME_SECP521R1),
        _ => None,
    }
}

#[cfg(test)]
pub fn curve_name_to_ec_params(name: &[u8]) -> Result<&'static [u8]> {
    match name {
        NAME_SECP256R1 => Ok(OCTSTR_SECP256R1),
        NAME_SECP384R1 => Ok(OCTSTR_SECP384R1),
        NAME_SECP521R1 => Ok(OCTSTR_SECP521R1),
        NAME_ED25519 => Ok(OCTSTR_ED25519),
        NAME_ED448 => Ok(OCTSTR_ED448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

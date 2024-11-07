// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

use std::ffi::{c_char, c_int};

use crate::attribute::Attribute;
use crate::ecc_misc::*;
use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;

#[cfg(feature = "fips")]
use crate::ossl::fips::*;

static OSSL_CURVE25519: &[u8; 7] = b"X25519\0";
static OSSL_CURVE448: &[u8; 5] = b"X448\0";

pub const BITS_CURVE25519: usize = 255;
pub const BITS_CURVE448: usize = 448;

// ASN.1 encoding of the OID
const OID_CURVE25519: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 110);
const OID_CURVE448: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 111);

// ASN.1 encoding of the curve name
const STRING_CURVE25519: &[u8] = &[
    0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39,
];
const STRING_CURVE448: &[u8] =
    &[0x13, 0x08, 0x63, 0x75, 0x72, 0x76, 0x65, 0x34, 0x34, 0x38];

fn oid_to_bits(oid: asn1::ObjectIdentifier) -> Result<usize> {
    match oid {
        OID_CURVE25519 => Ok(BITS_CURVE25519),
        OID_CURVE448 => Ok(BITS_CURVE448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

fn curve_name_to_bits(name: asn1::PrintableString) -> Result<usize> {
    let asn1_name = match asn1::write_single(&name) {
        Ok(r) => r,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    match asn1_name.as_slice() {
        STRING_CURVE25519 => Ok(BITS_CURVE25519),
        STRING_CURVE448 => Ok(BITS_CURVE448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

fn make_bits_from_obj(key: &Object) -> Result<usize> {
    let x = match key.get_attr_as_bytes(CKA_EC_PARAMS) {
        Ok(b) => b,
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    let bits = match asn1::parse_single::<ECParameters>(x) {
        Ok(a) => match a {
            ECParameters::OId(o) => oid_to_bits(o)?,
            ECParameters::CurveName(c) => curve_name_to_bits(c)?,
            _ => return Err(CKR_GENERAL_ERROR)?,
        },
        Err(_) => return Err(CKR_GENERAL_ERROR)?,
    };
    Ok(bits)
}

fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    match make_bits_from_obj(key) {
        Ok(BITS_CURVE25519) => Ok(OSSL_CURVE25519),
        Ok(BITS_CURVE448) => Ok(OSSL_CURVE448),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn make_output_length_from_montgomery_obj(key: &Object) -> Result<usize> {
    match make_bits_from_obj(key) {
        Ok(255) => Ok(64),
        Ok(448) => Ok(114),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

pub fn make_ec_montgomery_public_key(
    key: &Object,
    ec_point: &Vec<u8>,
) -> Result<EvpPkey> {
    let mut params = OsslParam::with_capacity(1);
    params.zeroize = true;
    params.add_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY), ec_point)?;
    params.finalize();

    EvpPkey::fromdata(
        get_ossl_name_from_obj(key)?.as_ptr() as *const c_char,
        EVP_PKEY_PUBLIC_KEY,
        &params,
    )
}

/// Convert the PKCS #11 private key object to OpenSSL EVP_PKEY
pub fn montgomery_object_to_ecc_private_key(key: &Object) -> Result<EvpPkey> {
    let priv_key = match key.get_attr_as_bytes(CKA_VALUE) {
        Ok(v) => v,
        Err(_) => return Err(CKR_DEVICE_ERROR)?,
    };
    let mut priv_key_octet: Vec<u8> = Vec::with_capacity(priv_key.len() + 2);
    priv_key_octet.push(4); /* tag octet string */
    priv_key_octet.push(u8::try_from(priv_key.len())?); /* length */
    priv_key_octet.extend(priv_key);

    let mut params = OsslParam::with_capacity(1);
    params.zeroize = true;
    params
        .add_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY), priv_key)?;
    params.finalize();

    EvpPkey::fromdata(
        get_ossl_name_from_obj(key)?.as_ptr() as *const c_char,
        EVP_PKEY_PRIVATE_KEY,
        &params,
    )
}

#[derive(Debug)]
pub struct ECMontgomeryOperation {}

impl ECMontgomeryOperation {
    pub fn generate_keypair(
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let evp_pkey = EvpPkey::generate(
            get_ossl_name_from_obj(pubkey)?.as_ptr() as *const c_char,
            &OsslParam::empty(),
        )?;

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
        let point_encoded = match asn1::write_single(
            &params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?,
        ) {
            Ok(b) => b,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        };
        pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, point_encoded))?;

        /* Private Key */
        let value = params
            .get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?
            .to_vec();
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, value))?;
        Ok(())
    }
}

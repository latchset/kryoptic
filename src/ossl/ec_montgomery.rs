// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

use std::ffi::{c_char, c_int};

use crate::attribute::Attribute;
use crate::ecc_misc::*;
use crate::error::{device_error, general_error, Result};
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

pub fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    match make_bits_from_obj(key) {
        Ok(BITS_CURVE25519) => Ok(OSSL_CURVE25519),
        Ok(BITS_CURVE448) => Ok(OSSL_CURVE448),
        _ => return Err(CKR_GENERAL_ERROR)?,
    }
}

fn get_ec_point_from_obj(key: &Object) -> Result<Vec<u8>> {
    let point = key.get_attr_as_bytes(CKA_EC_POINT).map_err(general_error)?;
    /* [u8] is an octet string for the asn1 library */
    let octet = asn1::parse_single::<&[u8]>(point).map_err(device_error)?;
    Ok(octet.to_vec())
}

pub fn ecm_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(*const c_char, OsslParam)> {
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
                name_as_char(OSSL_PKEY_PARAM_PUB_KEY),
                get_ec_point_from_obj(key)?,
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_octet_string(
                name_as_char(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?;
        }

        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    Ok((name_as_char(name), params))
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
        let point_encoded = asn1::write_single(
            &params.get_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY))?,
        )?;
        pubkey.set_attr(Attribute::from_bytes(CKA_EC_POINT, point_encoded))?;

        /* Private Key */
        let value = params
            .get_octet_string(name_as_char(OSSL_PKEY_PARAM_PRIV_KEY))?
            .to_vec();
        privkey.set_attr(Attribute::from_bytes(CKA_VALUE, value))?;
        Ok(())
    }
}

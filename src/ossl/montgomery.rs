// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

use std::ffi::{c_char, c_int};

use crate::attribute::Attribute;
use crate::ec::get_ec_point_from_obj;
use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;

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

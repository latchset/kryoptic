// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::c_uint;

use crate::error::Result;
use crate::interface::*;
use crate::mechanism::Mechanisms;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::common::*;

pub fn pbkdf2_derive(
    _: &Mechanisms,
    prf: CK_MECHANISM_TYPE,
    pass: &Object,
    salt: &Vec<u8>,
    iter: usize,
    len: usize,
) -> Result<Vec<u8>> {
    let mut params = OsslParam::with_capacity(4);
    params.zeroize = true;
    params.add_octet_string(
        name_as_char(OSSL_KDF_PARAM_PASSWORD),
        pass.get_attr_as_bytes(CKA_VALUE)?,
    )?;
    params.add_octet_string(name_as_char(OSSL_KDF_PARAM_SALT), salt)?;
    params.add_owned_uint(
        name_as_char(OSSL_KDF_PARAM_ITER),
        c_uint::try_from(iter)?,
    )?;
    params.add_const_c_string(
        name_as_char(OSSL_KDF_PARAM_DIGEST),
        mech_type_to_digest_name(prf),
    )?;
    params.finalize();

    let mut kctx = EvpKdfCtx::new(name_as_char(OSSL_KDF_NAME_PBKDF2))?;
    let mut dkm = vec![0u8; len];
    let res = unsafe {
        EVP_KDF_derive(
            kctx.as_mut_ptr(),
            dkm.as_mut_ptr(),
            dkm.len(),
            params.as_ptr(),
        )
    };
    if res != 1 {
        return Err(CKR_DEVICE_ERROR)?;
    }

    Ok(dkm)
}

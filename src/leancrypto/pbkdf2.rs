// Copyright 2026 Stephan Müller
// See LICENSE.txt file for terms

//! This module links with Leancrypto's PBKDF2 support

use crate::error::{Error, Result};
use crate::mechanism::Mechanisms;
use crate::object::Object;
use crate::pkcs11::*;

use crate::leancrypto::common::mech_type_to_digest_alg;
use leancrypto_sys::lcr_pbkdf2::lcr_pbkdf2;

pub fn pbkdf2_derive(
    _: &Mechanisms,
    prf: CK_MECHANISM_TYPE,
    pass: &Object,
    salt: &Vec<u8>,
    iter: usize,
    len: usize,
) -> Result<Vec<u8>> {
    let iter_count = u32::try_from(iter)?;
    let alg_type = mech_type_to_digest_alg(prf)?;
    let mut pbkdf2 = lcr_pbkdf2::new(alg_type);

    let mut dkm = vec![0u8; len];
    pbkdf2
        .derive(
            pass.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
            salt,
            iter_count,
            &mut dkm,
        )
        .map_err(|e| Error::other_error(format!("leancrypto encrypt: {e}")))?;

    Ok(dkm)
}

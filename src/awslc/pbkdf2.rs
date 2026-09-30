// Copyright 2026
// See LICENSE.txt file for terms

//! AWS-LC-backed PBKDF2, used by `src/pbkdf2.rs`'s PKCS#11 dispatcher
//! under `fips`. Mirrors `crate::ossl::pbkdf2`.

use crate::awslc::common::mech_type_to_digest_alg;
use crate::error::Result;
use crate::mechanism::Mechanisms;
use crate::object::Object;
use crate::pkcs11::*;

pub fn pbkdf2_derive(
    _: &Mechanisms,
    prf: CK_MECHANISM_TYPE,
    pass: &Object,
    salt: &Vec<u8>,
    iter: usize,
    len: usize,
) -> Result<Vec<u8>> {
    let digest = mech_type_to_digest_alg(prf)?;
    let mut dkm = vec![0u8; len];
    crate::lowlevel::pbkdf2::pbkdf2(
        pass.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
        salt.as_slice(),
        u32::try_from(iter)?,
        digest,
        &mut dkm,
    )?;
    Ok(dkm)
}

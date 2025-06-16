// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::mechanism::Mechanisms;
use crate::object::Object;
use crate::ossl::common::{mech_type_to_digest_alg, osslctx};

use ossl::derive::Pbkdf2Derive;
use pkcs11::*;

pub fn pbkdf2_derive(
    _: &Mechanisms,
    prf: CK_MECHANISM_TYPE,
    pass: &Object,
    salt: &Vec<u8>,
    iter: usize,
    len: usize,
) -> Result<Vec<u8>> {
    let mut kdf = Pbkdf2Derive::new(osslctx(), mech_type_to_digest_alg(prf)?)?;
    kdf.set_password(pass.get_attr_as_bytes(CKA_VALUE)?.as_slice());
    kdf.set_iterations(iter);
    kdf.set_salt(salt.as_slice());

    let mut dkm = vec![0u8; len];
    kdf.derive(&mut dkm)?;

    Ok(dkm)
}

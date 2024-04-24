// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::err_rv;
use super::error;
use super::interface;
use super::mechanism;
use super::object;

use error::{KError, KResult};
use interface::*;
use mechanism::*;

use std::fmt::Debug;

#[derive(Debug)]
struct HashMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HashMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(Box::new(HashOperation::new(mech.mechanism)?))
    }
}

#[derive(Debug)]
pub struct HashOperation {
    state: HashState,
    finalized: bool,
    in_use: bool,
}

pub fn register(mechs: &mut Mechanisms, _: &mut object::ObjectFactories) {
    HashOperation::register_mechanisms(mechs);
}

include! {"ossl/hash.rs"}

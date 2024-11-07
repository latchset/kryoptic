// Copyright 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::ecc::*;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms, Operation};
use crate::object::ObjectFactories;
use crate::ossl::ecdh::ECDHOperation;

use crate::cast_params;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    ECDHMechanism::register_mechanisms(mechs);
}

#[derive(Debug)]
struct ECDHMechanism {
    info: CK_MECHANISM_INFO,
}

impl ECDHMechanism {
    fn new_mechanism() -> Box<dyn Mechanism> {
        Box::new(ECDHMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                flags: CKF_DERIVE,
            },
        })
    }

    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE] {
            mechs.add_mechanism(*ckm, Self::new_mechanism());
        }
    }
}

impl Mechanism for ECDHMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        let kdf = match mech.mechanism {
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => {
                let params = cast_params!(mech, CK_ECDH1_DERIVE_PARAMS);
                ECDHOperation::derive_new(mech.mechanism, params)?
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        Ok(Operation::Derive(Box::new(kdf)))
    }
}

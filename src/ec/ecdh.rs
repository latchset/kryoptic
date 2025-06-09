// Copyright 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ECDH (Elliptic Curve
//! Diffie-Hellman) key derivation.

use std::fmt::Debug;

use crate::ec::ecdsa::{MAX_EC_SIZE_BITS, MIN_EC_SIZE_BITS};
use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::misc::cast_params;
use crate::object::ObjectFactories;
use crate::ossl::ecdh::ECDHOperation;

use pkcs11::*;

/// Public entry to register the ECDH Mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    ECDHMechanism::register_mechanisms(mechs);
}

/// Object that represents an ECDH Mechanism
#[derive(Debug)]
struct ECDHMechanism {
    info: CK_MECHANISM_INFO,
}

impl ECDHMechanism {
    /// Helper function to instantiate a mechanism to be registered
    fn new_mechanism() -> Box<dyn Mechanism> {
        Box::new(ECDHMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                flags: CKF_DERIVE,
            },
        })
    }

    /// Actual implementation of mechanism registration
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for ckm in &[CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE] {
            mechs.add_mechanism(*ckm, Self::new_mechanism());
        }
    }
}

impl Mechanism for ECDHMechanism {
    /// Returns a reference to the mechanism info (CK_MECHANISM_INFO)
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes an ECDH derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
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
        Ok(Box::new(kdf))
    }
}

// Copyright 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ECDH (Elliptic Curve
//! Diffie-Hellman) key derivation.

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::ec::*;
use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::object::ObjectFactories;
use crate::ossl::ecdh::ECDHOperation;

/// Object that holds Mechanisms for ECDH
static ECDH_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(ECDHMechanism {
            minfo: MechanismInfo::new(
                CKM_ECDH1_DERIVE,
                MIN_EC_SIZE_BITS,
                MAX_EC_SIZE_BITS,
                CKF_DERIVE | COMMON_CKF_EC_FLAGS,
                KeySizeKind::Bits,
                Some(CKK_EC),
            ),
        }),
        Box::new(ECDHMechanism {
            minfo: MechanismInfo::new(
                CKM_ECDH1_COFACTOR_DERIVE,
                MIN_EC_SIZE_BITS,
                MAX_EC_SIZE_BITS,
                CKF_DERIVE | COMMON_CKF_EC_FLAGS,
                KeySizeKind::Bits,
                Some(CKK_EC),
            ),
        }),
    ]
});

/// Public entry to register the ECDH Mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for mbox in &(*ECDH_MECHS) {
        let mtype = (*mbox).mechinfo().mech_type();
        mechs.add_mechanism(mtype, mbox);
    }
}

/// Object that represents an ECDH Mechanism
#[derive(Debug)]
struct ECDHMechanism {
    minfo: MechanismInfo,
}

impl Mechanism for ECDHMechanism {
    /// Returns a reference to the mechanism info
    fn mechinfo(&self) -> &MechanismInfo {
        &self.minfo
    }

    /// Initializes an ECDH derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info().flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        let kdf = match mech.mechanism {
            CKM_ECDH1_DERIVE | CKM_ECDH1_COFACTOR_DERIVE => {
                let params = mech.get_parameters::<CK_ECDH1_DERIVE_PARAMS>()?;
                ECDHOperation::derive_new(mech.mechanism, params)?
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        Ok(Box::new(kdf))
    }
}

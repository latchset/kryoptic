// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms, Operation};
use crate::object::ObjectFactories;

#[cfg(not(feature = "fips"))]
use crate::native::sshkdf::*;

#[cfg(feature = "fips")]
use crate::ossl::sshkdf::*;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    SSHKDFMechanism::register_mechanisms(mechs);
}

#[derive(Debug)]
struct SSHKDFMechanism {
    info: CK_MECHANISM_INFO,
}
impl SSHKDFMechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            KRM_SSHKDF_DERIVE,
            Box::new(SSHKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
    }
}

impl Mechanism for SSHKDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            KRM_SSHKDF_DERIVE => {
                Ok(Operation::Derive(Box::new(SSHKDFOperation::new(mech)?)))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

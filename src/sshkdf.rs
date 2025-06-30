// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for SSH Key Derivation
//! Function (KDF) as specified in RFC 4253, Section 7.2.

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::object::ObjectFactories;
use crate::pkcs11::vendor::*;
use crate::pkcs11::*;

#[cfg(not(feature = "fips"))]
use crate::native::sshkdf::*;

#[cfg(feature = "fips")]
use crate::ossl::sshkdf::*;

/// Object that holds the Mechanism for SSHKDF
static SSH_KDF_MECH: LazyLock<Box<dyn Mechanism>> = LazyLock::new(|| {
    Box::new(SSHKDFMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
            flags: CKF_DERIVE,
        },
    })
});

/// Registers the SSHKDF mechanism
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    mechs.add_mechanism(KRM_SSHKDF_DERIVE, &SSH_KDF_MECH);
}

#[derive(Debug)]
struct SSHKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SSHKDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            KRM_SSHKDF_DERIVE => Ok(Box::new(SSHKDFOperation::new(mech)?)),
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

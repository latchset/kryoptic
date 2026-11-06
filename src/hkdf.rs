// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms to access the HMAC-based
//! Key Derivation Function (HKDF) as specified in
//! [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::error::Result;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::object::{
    GenericSecretKeyFactory, GenericSecretKeyMechanism, ObjectFactories,
    ObjectFactory, ObjectType, MAX_GENERIC_SECRET_KEY_SIZE,
    MIN_GENERIC_SECRET_KEY_SIZE,
};
use crate::ossl::hkdf::HKDFOperation;
use crate::pkcs11::*;

/// Object that holds Mechanisms for HKDF
static HKDF_MECHS: LazyLock<[Box<dyn Mechanism>; 3]> = LazyLock::new(|| {
    [
        Box::new(HKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_HKDF_DERIVE,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                Some(CKK_HKDF),
            ),
        }),
        Box::new(HKDFMechanism {
            minfo: MechanismInfo::new(
                CKM_HKDF_DATA,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                Some(CKK_HKDF),
            ),
        }),
        Box::new(GenericSecretKeyMechanism::new(
            CKM_HKDF_KEY_GEN,
            CKK_HKDF,
            MIN_GENERIC_SECRET_KEY_SIZE,
            MAX_GENERIC_SECRET_KEY_SIZE,
            KeySizeKind::Bytes,
        )),
    ]
});

static HKDF_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(GenericSecretKeyFactory::new()));

/// Registers all HKDF related mechanisms
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    for mbox in &(*HKDF_MECHS) {
        let mtype = (*mbox).mechinfo().mech_type();
        mechs.add_mechanism(mtype, mbox);
    }
    ot.add_factory(
        ObjectType::new(CKO_SECRET_KEY, CKK_HKDF),
        &(*HKDF_KEY_FACTORY),
    );
}

/// Object that represents the HKDF mechanism
#[derive(Debug)]
struct HKDFMechanism {
    minfo: MechanismInfo,
}

impl Mechanism for HKDFMechanism {
    /// Returns a reference to the mechanism info
    fn mechinfo(&self) -> &MechanismInfo {
        &self.minfo
    }

    /// Initializes a HKDF Derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info().flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_HKDF_DERIVE | CKM_HKDF_DATA => {
                Ok(Box::new(HKDFOperation::new(mech)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

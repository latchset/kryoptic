// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for deriving keys within
//! the TLS protocol as defined in
//! [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::error::Result;
use crate::mechanism::*;
use crate::native::tlskdf::*;
use crate::object::{Object, ObjectFactories};
use crate::pkcs11::*;

#[cfg(feature = "fips")]
use crate::fips::check_fips_state_ok;

/// Object that holds Mechanisms for TLS
static TLS_MECHS: LazyLock<[Box<dyn Mechanism>; 10]> = LazyLock::new(|| {
    [
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS_KDF,
                TLS_MASTER_SECRET_SIZE as usize,
                TLS_MASTER_SECRET_SIZE as usize,
                CKF_DERIVE,
                KeySizeKind::Bytes,
                Some(CKK_GENERIC_SECRET),
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_KDF,
                TLS_MASTER_SECRET_SIZE as usize,
                TLS_MASTER_SECRET_SIZE as usize,
                CKF_DERIVE,
                KeySizeKind::Bytes,
                Some(CKK_GENERIC_SECRET),
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_MASTER_KEY_DERIVE,
                TLS_MASTER_SECRET_SIZE as usize,
                TLS_MASTER_SECRET_SIZE as usize,
                CKF_DERIVE,
                KeySizeKind::Bytes,
                Some(CKK_GENERIC_SECRET),
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_MASTER_KEY_DERIVE_DH,
                TLS_MASTER_SECRET_SIZE as usize,
                TLS_MASTER_SECRET_SIZE as usize,
                CKF_DERIVE,
                KeySizeKind::Bytes,
                Some(CKK_GENERIC_SECRET),
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                TLS_MASTER_SECRET_SIZE as usize,
                TLS_MASTER_SECRET_SIZE as usize,
                CKF_DERIVE,
                KeySizeKind::Bytes,
                Some(CKK_GENERIC_SECRET),
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
                TLS_MASTER_SECRET_SIZE as usize,
                TLS_MASTER_SECRET_SIZE as usize,
                CKF_DERIVE,
                KeySizeKind::Bytes,
                Some(CKK_GENERIC_SECRET),
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_KEY_AND_MAC_DERIVE,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_KEY_SAFE_DERIVE,
                0,
                0,
                CKF_DERIVE,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS_MAC,
                0,
                0,
                CKF_SIGN | CKF_VERIFY,
                KeySizeKind::Unused,
                None,
            ),
        }),
        Box::new(TLSPRFMechanism {
            minfo: MechanismInfo::new(
                CKM_TLS12_MAC,
                0,
                0,
                CKF_SIGN | CKF_VERIFY,
                KeySizeKind::Unused,
                None,
            ),
        }),
    ]
});

/// Registers all TLS mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for mbox in &(*TLS_MECHS) {
        let mtype = (*mbox).mechinfo().mech_type();
        mechs.add_mechanism(mtype, mbox);
    }
}

#[derive(Debug)]
struct TLSPRFMechanism {
    minfo: MechanismInfo,
}

impl Mechanism for TLSPRFMechanism {
    fn mechinfo(&self) -> &MechanismInfo {
        &self.minfo
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        #[cfg(feature = "fips")]
        if !check_fips_state_ok() {
            return Err(CKR_FIPS_SELF_TEST_FAILED)?;
        }

        if self.info().flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE
            | CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH => {
                Ok(Box::new(TLSKDFOperation::new(mech)?))
            }
            CKM_TLS12_MASTER_KEY_DERIVE
            | CKM_TLS12_MASTER_KEY_DERIVE_DH
            | CKM_TLS12_KEY_AND_MAC_DERIVE
            | CKM_TLS12_KEY_SAFE_DERIVE
            | CKM_TLS12_KDF
            | CKM_TLS_KDF => Ok(Box::new(TLSKDFOperation::new(mech)?)),
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        #[cfg(feature = "fips")]
        if !check_fips_state_ok() {
            return Err(CKR_FIPS_SELF_TEST_FAILED)?;
        }

        if self.info().flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match mech.mechanism {
            CKM_TLS_MAC | CKM_TLS12_MAC => {
                Ok(Box::new(TLSMACOperation::new(mech, key)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        #[cfg(feature = "fips")]
        if !check_fips_state_ok() {
            return Err(CKR_FIPS_SELF_TEST_FAILED)?;
        }

        if self.info().flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match mech.mechanism {
            CKM_TLS_MAC | CKM_TLS12_MAC => {
                Ok(Box::new(TLSMACOperation::new(mech, key)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

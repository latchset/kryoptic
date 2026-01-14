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
static TLS_MECHS: LazyLock<[Box<dyn Mechanism>; 3]> = LazyLock::new(|| {
    [
        Box::new(TLSPRFMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                flags: CKF_DERIVE,
            },
        }),
        Box::new(TLSPRFMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: u32::MAX as CK_ULONG,
                flags: CKF_DERIVE,
            },
        }),
        Box::new(TLSPRFMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: u32::MAX as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    ]
});

/// Registers all TLS mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for ckm in &[
        CKM_TLS_KDF,
        CKM_TLS12_KDF,
        CKM_TLS12_MASTER_KEY_DERIVE,
        CKM_TLS12_MASTER_KEY_DERIVE_DH,
        CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
        CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
    ] {
        mechs.add_mechanism(*ckm, &TLS_MECHS[0]);
    }
    for ckm in &[CKM_TLS12_KEY_AND_MAC_DERIVE, CKM_TLS12_KEY_SAFE_DERIVE] {
        mechs.add_mechanism(*ckm, &TLS_MECHS[1]);
    }
    for ckm in &[CKM_TLS_MAC, CKM_TLS12_MAC] {
        mechs.add_mechanism(*ckm, &TLS_MECHS[2]);
    }
}

#[derive(Debug)]
struct TLSPRFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for TLSPRFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        #[cfg(feature = "fips")]
        if !check_fips_state_ok() {
            return Err(CKR_FIPS_SELF_TEST_FAILED)?;
        }

        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
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

        if self.info.flags & CKF_SIGN != CKF_SIGN {
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

        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
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

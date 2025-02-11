// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::interface::*;
use crate::mechanism::*;
use crate::native::tlskdf::*;
use crate::object::{Object, ObjectFactories};

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    TLSPRFMechanism::register_mechanisms(mechs);
}

#[derive(Debug)]
struct TLSPRFMechanism {
    info: CK_MECHANISM_INFO,
}

impl TLSPRFMechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_TLS12_MASTER_KEY_DERIVE,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_KEY_AND_MAC_DERIVE,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_KEY_SAFE_DERIVE,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS_MAC,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_SIGN | CKF_VERIFY,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_MAC,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: u32::MAX as CK_ULONG,
                    flags: CKF_SIGN | CKF_VERIFY,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS_KDF,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_TLS12_KDF,
            Box::new(TLSPRFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: TLS_MASTER_SECRET_SIZE,
                    ulMaxKeySize: TLS_MASTER_SECRET_SIZE,
                    flags: CKF_DERIVE,
                },
            }),
        );
    }
}

impl Mechanism for TLSPRFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_TLS12_MASTER_KEY_DERIVE
            | CKM_TLS12_KEY_AND_MAC_DERIVE
            | CKM_TLS12_KEY_SAFE_DERIVE
            | CKM_TLS12_KDF
            | CKM_TLS_KDF => {
                Ok(Operation::Derive(Box::new(TLSKDFOperation::new(mech)?)))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
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

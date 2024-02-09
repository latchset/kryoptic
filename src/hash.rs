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
    mech: CK_MECHANISM_TYPE,
    state: HashState,
    finalized: bool,
    in_use: bool,
}

pub fn register(mechs: &mut Mechanisms, _: &mut object::ObjectFactories) {
    mechs.add_mechanism(
        CKM_SHA_1,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA256,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA384,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA512,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA3_256,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA3_384,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_SHA3_512,
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
    );
}

#[cfg(feature = "fips")]
include! {"ossl/hash.rs"}

#[cfg(not(feature = "fips"))]
include! {"ossl/hash.rs"}

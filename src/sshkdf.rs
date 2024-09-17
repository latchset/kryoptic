// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::hash;
use super::interface;
use super::mechanism;
use super::misc;
use super::object;

use attribute::from_bytes;
use error::Result;
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use super::{bytes_to_vec, cast_params};

use std::fmt::Debug;

#[cfg(feature = "fips")]
use {super::fips, fips::*};

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    SSHKDFOperation::register_mechanisms(mechs);
}

#[derive(Debug)]
struct SSHKDFMechanism {
    info: CK_MECHANISM_INFO,
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

#[derive(Debug)]
struct SSHKDFOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    key_type: u8,
    exchange_hash: Vec<u8>,
    session_id: Vec<u8>,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
    is_data: bool,
}

impl SSHKDFOperation {
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

    fn new(mech: &CK_MECHANISM) -> Result<SSHKDFOperation> {
        let params = cast_params!(mech, KR_SSHKDF_PARAMS);

        if !hash::is_valid_hash(params.prfHashMechanism) {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let is_data = match params.derivedKeyType {
            0x41 => true,  /* A */
            0x42 => true,  /* B */
            0x43 => false, /* C */
            0x44 => false, /* D */
            0x45 => false, /* E */
            0x46 => false, /* F */
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        Ok(SSHKDFOperation {
            mech: mech.mechanism,
            finalized: false,
            prf: params.prfHashMechanism,
            key_type: params.derivedKeyType,
            exchange_hash: bytes_to_vec!(
                params.pExchangeHash,
                params.ulExchangeHashLen
            ),
            session_id: bytes_to_vec!(params.pSessionId, params.ulSessionIdLen),
            #[cfg(feature = "fips")]
            fips_approved: None,
            is_data: is_data,
        })
    }
}

impl MechOperation for SSHKDFOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

#[cfg(not(feature = "fips"))]
impl Derive for SSHKDFOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        key.check_key_ops(CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKA_DERIVE)?;

        let mechanism = CK_MECHANISM {
            mechanism: self.prf,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mech = mechanisms.get(self.prf)?;
        let mut op = mech.digest_new(&mechanism)?;
        let segment = op.digest_len()?;

        let (mut dobj, value_len) = if self.is_data {
            misc::common_derive_data_object(template, objfactories, 0)
        } else {
            misc::common_derive_key_object(key, template, objfactories, 0)
        }?;
        if value_len == 0 || value_len > usize::try_from(u32::MAX)? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let keyval = key.get_attr_as_bytes(CKA_VALUE)?;
        let mut dkm = vec![0u8; value_len];

        /* for each segment */
        let mut buffer = vec![0u8; segment];
        let mut curlen = 0;
        for ctr in 0..((value_len + segment - 1) / segment) {
            let len = if curlen + segment > value_len {
                value_len - curlen
            } else {
                segment
            };
            if ctr != 0 {
                op.reset()?;
            }
            /* Key */
            op.digest_update(keyval.as_slice())?;
            /* Exchange Hash */
            op.digest_update(self.exchange_hash.as_slice())?;
            if ctr == 0 {
                op.digest_update(&[self.key_type])?;
                op.digest_update(self.session_id.as_slice())?;
            } else {
                op.digest_update(&dkm[0..curlen])?;
            }
            op.digest_final(buffer.as_mut_slice())?;
            dkm[curlen..(curlen + len)].copy_from_slice(&buffer[0..len]);
            curlen += len;
        }

        dobj.set_attr(from_bytes(CKA_VALUE, dkm))?;
        Ok(vec![dobj])
    }
}

#[cfg(feature = "fips")]
include!("ossl/sshkdf.rs");

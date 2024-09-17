// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::hash;
use super::hmac;
use super::interface;
use super::mechanism;
use super::misc;
use super::object;

use attribute::from_bytes;
use error::Result;
use hash::INVALID_HASH_SIZE;
use hmac::hmac_size;
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use super::{bytes_to_slice, cast_params};

use std::fmt::Debug;

#[cfg(feature = "fips")]
use {super::fips, fips::*};

use core::ffi::c_int;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    HKDFOperation::register_mechanisms(mechs);
}

#[derive(Debug)]
struct HKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HKDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        match mech.mechanism {
            CKM_HKDF_DERIVE | CKM_HKDF_DATA => {
                Ok(Operation::Derive(Box::new(HKDFOperation::new(mech)?)))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

#[derive(Debug)]
struct HKDFOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    extract: bool,
    expand: bool,
    prf: CK_MECHANISM_TYPE,
    prflen: usize,
    salt_type: CK_ULONG,
    salt_key: [CK_OBJECT_HANDLE; 1],
    salt: Vec<u8>,
    info: Vec<u8>,
    emit_data_obj: bool,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl HKDFOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_HKDF_DERIVE,
            Box::new(HKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_HKDF_DATA,
            Box::new(HKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_HKDF_KEY_GEN,
            Box::new(object::GenericSecretKeyMechanism::new(CKK_HKDF)),
        );
    }

    fn verify_key(&self, key: &Object, matchlen: usize) -> Result<()> {
        if let Ok(class) = key.get_attr_as_ulong(CKA_CLASS) {
            match class {
                CKO_SECRET_KEY => {
                    if let Ok(kt) = key.get_attr_as_ulong(CKA_KEY_TYPE) {
                        match kt {
                            CKK_GENERIC_SECRET | CKK_HKDF => key
                                .check_key_ops(
                                    CKO_SECRET_KEY,
                                    CK_UNAVAILABLE_INFORMATION,
                                    CKA_DERIVE,
                                )?,
                            _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
                        }
                    } else {
                        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
                    }
                }
                CKO_DATA => {
                    /* HKDF also allow a DATA object as input key ... */
                    if !self.extract
                        || self.salt_type == CKF_HKDF_SALT_NULL
                        || self.salt.len() == 0
                    {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                }
                _ => return Err(CKR_KEY_HANDLE_INVALID)?,
            }
        } else {
            return Err(CKR_KEY_HANDLE_INVALID)?;
        }

        if matchlen > 0 {
            let keylen = match key.get_attr_as_ulong(CKA_VALUE_LEN) {
                Ok(len) => usize::try_from(len)?,
                Err(_) => match key.get_attr_as_bytes(CKA_VALUE) {
                    Ok(v) => v.len(),
                    Err(_) => 0,
                },
            };
            if keylen == 0 {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
        }

        Ok(())
    }

    fn new(mech: &CK_MECHANISM) -> Result<HKDFOperation> {
        let params = cast_params!(mech, CK_HKDF_PARAMS);
        if params.bExtract == CK_FALSE && params.bExpand == CK_FALSE {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        if params.bExtract != CK_FALSE
            && params.ulSaltLen > 0
            && params.pSalt == std::ptr::null_mut()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        if params.bExpand != CK_FALSE
            && params.ulInfoLen > 0
            && params.pInfo == std::ptr::null_mut()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let hmaclen = match hmac_size(params.prfHashMechanism) {
            INVALID_HASH_SIZE => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            x => x,
        };
        let salt = match params.ulSaltType {
            CKF_HKDF_SALT_NULL => {
                if params.ulSaltLen > 0 || params.pSalt != std::ptr::null_mut()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    vec![0u8; hmaclen]
                }
            }
            CKF_HKDF_SALT_DATA => {
                if params.ulSaltLen == 0 || params.pSalt == std::ptr::null_mut()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    bytes_to_slice!(params.pSalt, params.ulSaltLen, u8).to_vec()
                }
            }
            CKF_HKDF_SALT_KEY => {
                /* a len of 0 indicates a key object is needed.
                 * the salt must be set via [requires/receives]_objects()
                 * if not derive() will error */
                Vec::new()
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        Ok(HKDFOperation {
            mech: mech.mechanism,
            finalized: false,
            extract: params.bExtract != CK_FALSE,
            expand: params.bExpand != CK_FALSE,
            prf: params.prfHashMechanism,
            prflen: hmaclen,
            salt_type: params.ulSaltType,
            salt_key: [params.hSaltKey],
            salt: salt,
            info: bytes_to_slice!(params.pInfo, params.ulInfoLen, u8).to_vec(),
            emit_data_obj: mech.mechanism == CKM_HKDF_DATA,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }
}

impl MechOperation for HKDFOperation {
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
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if self.salt_type == CKF_HKDF_SALT_KEY {
            return Ok(&self.salt_key);
        } else {
            /* we are good, no need to even send a vector */
            return Err(CKR_OK)?;
        }
    }
    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if objs.len() != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.verify_key(objs[0], 0)?;
        if let Ok(salt) = objs[0].get_attr_as_bytes(CKA_VALUE) {
            self.salt.clone_from(salt);
            Ok(())
        } else {
            Err(CKR_KEY_HANDLE_INVALID)?
        }
    }
}

include!("ossl/hkdf.rs");

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms, Operation};
use crate::object::{Object, ObjectFactories};

use crate::{bytes_to_vec, cast_params, map_err, sizeof};

#[cfg(not(feature = "fips"))]
use crate::native::sp800_108::*;

#[cfg(feature = "fips")]
use crate::ossl::kbkdf::*;

#[derive(Debug)]
struct Sp800KDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Sp800KDFMechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_SP800_108_COUNTER_KDF,
            Box::new(Sp800KDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_SP800_108_FEEDBACK_KDF,
            Box::new(Sp800KDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_DERIVE,
                },
            }),
        );
    }
}

impl Mechanism for Sp800KDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        let kdf = match mech.mechanism {
            CKM_SP800_108_COUNTER_KDF => {
                let kdf_params = cast_params!(mech, CK_SP800_108_KDF_PARAMS);
                Sp800Operation::counter_kdf_new(kdf_params)?
            }
            CKM_SP800_108_FEEDBACK_KDF => {
                let kdf_params =
                    cast_params!(mech, CK_SP800_108_FEEDBACK_KDF_PARAMS);
                Sp800Operation::feedback_kdf_new(kdf_params)?
            }
            CKM_SP800_108_DOUBLE_PIPELINE_KDF => {
                return Err(CKR_MECHANISM_INVALID)?;
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        Ok(Operation::Derive(Box::new(kdf)))
    }
}

#[derive(Debug)]
pub struct Sp800CounterFormat {
    pub defined: bool,
    pub le: bool,
    pub bits: usize,
}

#[derive(Debug)]
pub struct Sp800DKMLengthFormat {
    pub method: CK_ULONG,
    pub le: bool,
    pub bits: usize,
}

#[derive(Debug)]
pub enum Sp800Params {
    Iteration(Sp800CounterFormat),
    Counter(Sp800CounterFormat),
    ByteArray(Vec<u8>),
    DKMLength(Sp800DKMLengthFormat),
}

impl Sp800Params {
    fn parse_counter_format(
        p: &CK_PRF_DATA_PARAM,
    ) -> Result<Sp800CounterFormat> {
        if p.ulValueLen == 0 && p.pValue == std::ptr::null_mut() {
            return Ok(Sp800CounterFormat {
                defined: false,
                le: false,
                bits: 16,
            });
        }
        if p.ulValueLen != sizeof!(CK_SP800_108_COUNTER_FORMAT) {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let cf = unsafe { *(p.pValue as *const CK_SP800_108_COUNTER_FORMAT) };
        Ok(Sp800CounterFormat {
            defined: true,
            le: match cf.bLittleEndian {
                0 => false,
                1 => true,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            },
            bits: match cf.ulWidthInBits {
                8 | 16 | 24 | 32 => map_err!(
                    usize::try_from(cf.ulWidthInBits),
                    CKR_MECHANISM_PARAM_INVALID
                )?,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            },
        })
    }

    fn parse_byte_array(p: &CK_PRF_DATA_PARAM) -> Result<Vec<u8>> {
        if p.ulValueLen == 0 || p.pValue == std::ptr::null_mut() {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(bytes_to_vec!(p.pValue, p.ulValueLen))
    }

    fn parse_dkm_length(p: &CK_PRF_DATA_PARAM) -> Result<Sp800DKMLengthFormat> {
        if p.ulValueLen != sizeof!(CK_SP800_108_DKM_LENGTH_FORMAT) {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let dkm =
            unsafe { *(p.pValue as *const CK_SP800_108_DKM_LENGTH_FORMAT) };
        Ok(Sp800DKMLengthFormat {
            method: match dkm.dkmLengthMethod {
                CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
                | CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS => {
                    dkm.dkmLengthMethod
                }
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            },
            le: match dkm.bLittleEndian {
                0 => false,
                1 => true,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            },
            bits: match dkm.ulWidthInBits {
                8 | 16 | 24 | 32 | 40 | 48 | 56 | 64 => map_err!(
                    usize::try_from(dkm.ulWidthInBits),
                    CKR_MECHANISM_PARAM_INVALID
                )?,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            },
        })
    }

    pub fn parse_data_params(
        params: &[CK_PRF_DATA_PARAM],
    ) -> Result<Vec<Sp800Params>> {
        let mut result = Vec::<Sp800Params>::with_capacity(params.len());

        for p in params {
            match p.type_ {
                CK_SP800_108_ITERATION_VARIABLE => {
                    let e = Self::parse_counter_format(p)?;
                    result.push(Sp800Params::Iteration(e));
                }
                CK_SP800_108_COUNTER => {
                    let e = Self::parse_counter_format(p)?;
                    result.push(Sp800Params::Counter(e));
                }
                CK_SP800_108_BYTE_ARRAY => {
                    let e = Self::parse_byte_array(p)?;
                    result.push(Sp800Params::ByteArray(e));
                }
                CK_SP800_108_DKM_LENGTH => {
                    let e = Self::parse_dkm_length(p)?;
                    result.push(Sp800Params::DKMLength(e));
                }
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            }
        }

        Ok(result)
    }
}

fn check_key_op(key: &Object, ktype: CK_KEY_TYPE) -> Result<()> {
    key.check_key_ops(CKO_SECRET_KEY, ktype, CKA_DERIVE)
}

pub fn verify_prf_key(mech: CK_MECHANISM_TYPE, key: &Object) -> Result<()> {
    match check_key_op(key, CKK_GENERIC_SECRET) {
        Ok(_) => match mech {
            CKM_SHA_1_HMAC | CKM_SHA224_HMAC | CKM_SHA256_HMAC
            | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_224_HMAC
            | CKM_SHA3_256_HMAC | CKM_SHA3_384_HMAC | CKM_SHA3_512_HMAC => {
                return Ok(())
            }
            _ => (),
        },
        Err(_) => (),
    }

    match mech {
        CKM_SHA_1_HMAC => check_key_op(key, CKK_SHA_1_HMAC),
        CKM_SHA224_HMAC => check_key_op(key, CKK_SHA224_HMAC),
        CKM_SHA256_HMAC => check_key_op(key, CKK_SHA256_HMAC),
        CKM_SHA384_HMAC => check_key_op(key, CKK_SHA384_HMAC),
        CKM_SHA512_HMAC => check_key_op(key, CKK_SHA512_HMAC),
        CKM_SHA3_224_HMAC => check_key_op(key, CKK_SHA3_224_HMAC),
        CKM_SHA3_256_HMAC => check_key_op(key, CKK_SHA3_256_HMAC),
        CKM_SHA3_384_HMAC => check_key_op(key, CKK_SHA3_384_HMAC),
        CKM_SHA3_512_HMAC => check_key_op(key, CKK_SHA3_512_HMAC),
        CKM_AES_CMAC => check_key_op(key, CKK_AES),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
}

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    Sp800KDFMechanism::register_mechanisms(mechs);
}

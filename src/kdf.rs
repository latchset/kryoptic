// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::err_rv;
use super::error;
use super::interface;
use super::object;

use attribute::from_bytes;
use error::{KError, KResult};
use interface::*;
use object::{Object, ObjectFactories};

use super::mechanism;
use mechanism::*;

use super::bytes_to_vec;

use std::fmt::Debug;

macro_rules! bytes_to_slice {
    ($ptr: expr, $len:expr, $typ:ty) => {
        if $len > 0 {
            unsafe {
                std::slice::from_raw_parts($ptr as *const $typ, $len as usize)
            }
        } else {
            &[]
        }
    };
}

#[derive(Debug)]
struct Sp800KDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for Sp800KDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> KResult<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        let kdf = match mech.mechanism {
            CKM_SP800_108_COUNTER_KDF => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_SP800_108_KDF_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let kdf_params = unsafe {
                    *(mech.pParameter as *const CK_SP800_108_KDF_PARAMS)
                };
                Sp800Operation::counter_kdf_new(kdf_params)?
            }
            CKM_SP800_108_FEEDBACK_KDF => {
                if mech.ulParameterLen as usize
                    != ::std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>()
                {
                    return err_rv!(CKR_ARGUMENTS_BAD);
                }
                let kdf_params = unsafe {
                    *(mech.pParameter
                        as *const CK_SP800_108_FEEDBACK_KDF_PARAMS)
                };
                Sp800Operation::feedback_kdf_new(kdf_params)?
            }
            CKM_SP800_108_DOUBLE_PIPELINE_KDF => {
                return err_rv!(CKR_MECHANISM_INVALID);
            }
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        Ok(Operation::Derive(Box::new(kdf)))
    }
}

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    Sp800Operation::register_mechanisms(mechs);
}

#[derive(Debug)]
struct Sp800CounterFormat {
    defined: bool,
    le: bool,
    bits: usize,
}

#[derive(Debug)]
struct Sp800DKMLengthFormat {
    method: CK_ULONG,
    le: bool,
    bits: usize,
}

#[derive(Debug)]
enum Sp800Params {
    Iteration(Sp800CounterFormat),
    Counter(Sp800CounterFormat),
    ByteArray(Vec<u8>),
    DKMLength(Sp800DKMLengthFormat),
}

#[derive(Debug)]
struct Sp800Operation {
    mech: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    finalized: bool,
    params: Vec<Sp800Params>,
    iv: Vec<u8>,
    addl_drv_keys: Vec<CK_DERIVED_KEY>,
    addl_objects: Vec<Object>,
}

unsafe impl Send for Sp800Operation {}
unsafe impl Sync for Sp800Operation {}

impl Sp800Operation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_SP800_108_COUNTER_KDF,
            Box::new(Sp800KDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: std::u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_SP800_108_FEEDBACK_KDF,
            Box::new(Sp800KDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: std::u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
    }

    fn parse_counter_format(
        p: &CK_PRF_DATA_PARAM,
    ) -> KResult<Sp800CounterFormat> {
        if p.ulValueLen == 0 && p.pValue == std::ptr::null_mut() {
            return Ok(Sp800CounterFormat {
                defined: false,
                le: false,
                bits: 16,
            });
        }
        if p.ulValueLen as usize
            != ::std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>()
        {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        let cf = unsafe { *(p.pValue as *const CK_SP800_108_COUNTER_FORMAT) };
        Ok(Sp800CounterFormat {
            defined: true,
            le: match cf.bLittleEndian {
                0 => false,
                1 => true,
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            bits: match cf.ulWidthInBits {
                8 | 16 | 24 | 32 => cf.ulWidthInBits as usize,
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
        })
    }

    fn parse_byte_array(p: &CK_PRF_DATA_PARAM) -> KResult<Vec<u8>> {
        if p.ulValueLen == 0 {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        Ok(bytes_to_vec!(p.pValue, p.ulValueLen))
    }

    fn parse_dkm_length(
        p: &CK_PRF_DATA_PARAM,
    ) -> KResult<Sp800DKMLengthFormat> {
        if p.ulValueLen as usize
            != ::std::mem::size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>()
        {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        let dkm =
            unsafe { *(p.pValue as *const CK_SP800_108_DKM_LENGTH_FORMAT) };
        Ok(Sp800DKMLengthFormat {
            method: match dkm.dkmLengthMethod {
                CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
                | CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS => {
                    dkm.dkmLengthMethod
                }
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            le: match dkm.bLittleEndian {
                0 => false,
                1 => true,
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
            bits: match dkm.ulWidthInBits {
                8 | 16 | 24 | 32 | 40 | 48 | 56 | 64 => {
                    dkm.ulWidthInBits as usize
                }
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            },
        })
    }

    fn parse_data_params(
        params: &[CK_PRF_DATA_PARAM],
    ) -> KResult<Vec<Sp800Params>> {
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
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            }
        }

        Ok(result)
    }

    fn check_key_op(key: &Object, ktype: CK_KEY_TYPE) -> KResult<()> {
        key.check_key_ops(CKO_SECRET_KEY, ktype, CKA_DERIVE)
    }

    fn verify_prf_key(mech: CK_MECHANISM_TYPE, key: &Object) -> KResult<()> {
        match Self::check_key_op(key, CKK_GENERIC_SECRET) {
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
            CKM_SHA_1_HMAC => Self::check_key_op(key, CKK_SHA_1_HMAC),
            CKM_SHA224_HMAC => Self::check_key_op(key, CKK_SHA224_HMAC),
            CKM_SHA256_HMAC => Self::check_key_op(key, CKK_SHA256_HMAC),
            CKM_SHA384_HMAC => Self::check_key_op(key, CKK_SHA384_HMAC),
            CKM_SHA512_HMAC => Self::check_key_op(key, CKK_SHA512_HMAC),
            CKM_SHA3_224_HMAC => Self::check_key_op(key, CKK_SHA3_224_HMAC),
            CKM_SHA3_256_HMAC => Self::check_key_op(key, CKK_SHA3_256_HMAC),
            CKM_SHA3_384_HMAC => Self::check_key_op(key, CKK_SHA3_384_HMAC),
            CKM_SHA3_512_HMAC => Self::check_key_op(key, CKK_SHA3_512_HMAC),
            CKM_AES_CMAC => Self::check_key_op(key, CKK_AES),
            _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
        }
    }

    fn counter_kdf_new(
        params: CK_SP800_108_KDF_PARAMS,
    ) -> KResult<Sp800Operation> {
        let data_params = bytes_to_slice!(
            params.pDataParams,
            params.ulNumberOfDataParams,
            CK_PRF_DATA_PARAM
        );
        let addl_drv_keys = bytes_to_slice!(
            params.pAdditionalDerivedKeys,
            params.ulAdditionalDerivedKeys,
            CK_DERIVED_KEY
        );
        Ok(Sp800Operation {
            mech: CKM_SP800_108_COUNTER_KDF,
            prf: params.prfType,
            finalized: false,
            params: Self::parse_data_params(&data_params)?,
            iv: Vec::new(),
            addl_drv_keys: addl_drv_keys.to_vec(),
            addl_objects: Vec::with_capacity(addl_drv_keys.len()),
        })
    }

    fn feedback_kdf_new(
        params: CK_SP800_108_FEEDBACK_KDF_PARAMS,
    ) -> KResult<Sp800Operation> {
        let data_params = bytes_to_slice!(
            params.pDataParams,
            params.ulNumberOfDataParams,
            CK_PRF_DATA_PARAM
        );
        let addl_drv_keys = bytes_to_slice!(
            params.pAdditionalDerivedKeys,
            params.ulAdditionalDerivedKeys,
            CK_DERIVED_KEY
        );
        let iv = if params.pIV != std::ptr::null_mut() && params.ulIVLen != 0 {
            bytes_to_vec!(params.pIV, params.ulIVLen)
        } else if params.pIV == std::ptr::null_mut() && params.ulIVLen == 0 {
            Vec::new()
        } else {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        };
        Ok(Sp800Operation {
            mech: CKM_SP800_108_FEEDBACK_KDF,
            prf: params.prfType,
            finalized: false,
            params: Self::parse_data_params(&data_params)?,
            iv: iv,
            addl_drv_keys: addl_drv_keys.to_vec(),
            addl_objects: Vec::with_capacity(addl_drv_keys.len()),
        })
    }
}

impl MechOperation for Sp800Operation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

include!("ossl/kdf.rs");

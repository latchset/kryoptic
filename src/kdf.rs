// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::err_rv;
use super::error;
use super::hash;
use super::hmac;
use super::interface;
use super::mechanism;
use super::object;

use attribute::from_bytes;
use error::{KError, KResult};
use hash::INVALID_HASH_SIZE;
use hmac::hmac_size;
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories, ObjectType};

use super::bytes_to_vec;

use std::fmt::Debug;

#[cfg(feature = "fips")]
use {super::fips, fips::*};

use core::ffi::c_int;

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

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    HKDFOperation::register_mechanisms(mechs);
    Sp800Operation::register_mechanisms(mechs);
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
        if p.ulValueLen == 0 || p.pValue == std::ptr::null_mut() {
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

    fn pop_key(&mut self) -> KResult<(Object, CK_OBJECT_HANDLE_PTR)> {
        if !self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        /* pops a key at a time from the the vectors, this returns keys
         * in reverse order from creation, but that doesn't matter as
         * the pointers in the original structure are what give the order
         * back to the caller */
        let obj = match self.addl_objects.pop() {
            Some(o) => o,
            None => return err_rv!(CKR_EXCEEDED_MAX_ITERATIONS),
        };
        /* len() here now point to the correct handler container because
         * the length is always one more than the last object index and
         * we just reduced by one the length of the objects array */
        let hp = self.addl_drv_keys[self.addl_objects.len()].phKey;

        Ok((obj, hp))
    }
}

impl MechOperation for Sp800Operation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

#[derive(Debug)]
struct HKDFMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HKDFMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> KResult<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        match mech.mechanism {
            CKM_HKDF_DERIVE | CKM_HKDF_DATA => {
                Ok(Operation::Derive(Box::new(HKDFOperation::new(mech)?)))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

#[derive(Debug)]
struct HKDFOperation {
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
}

impl HKDFOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_HKDF_DERIVE,
            Box::new(HKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: std::u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_HKDF_DATA,
            Box::new(HKDFMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: std::u32::MAX as CK_ULONG,
                    flags: CKF_DERIVE,
                },
            }),
        );
        mechs.add_mechanism(
            CKM_HKDF_KEY_GEN,
            Box::new(object::GenericSecretKeyMechanism::new(CKK_HKDF)),
        );
    }

    fn verify_key(&self, key: &Object, matchlen: usize) -> KResult<()> {
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
                            _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
                        }
                    } else {
                        return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
                    }
                }
                CKO_DATA => {
                    /* HKDF also allow a DATA object as input key ... */
                    if !self.extract
                        || self.salt_type == CKF_HKDF_SALT_NULL
                        || self.salt.len() == 0
                    {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                }
                _ => return err_rv!(CKR_KEY_HANDLE_INVALID),
            }
        } else {
            return err_rv!(CKR_KEY_HANDLE_INVALID);
        }

        if matchlen > 0 {
            let keylen = match key.get_attr_as_ulong(CKA_VALUE_LEN) {
                Ok(len) => len as usize,
                Err(_) => match key.get_attr_as_bytes(CKA_VALUE) {
                    Ok(v) => v.len(),
                    Err(_) => 0,
                },
            };
            if keylen == 0 {
                return err_rv!(CKR_KEY_SIZE_RANGE);
            }
        }

        Ok(())
    }

    fn new(mech: &CK_MECHANISM) -> KResult<HKDFOperation> {
        if mech.ulParameterLen as usize
            != ::std::mem::size_of::<CK_HKDF_PARAMS>()
        {
            return err_rv!(CKR_ARGUMENTS_BAD);
        }
        let params = unsafe { *(mech.pParameter as *const CK_HKDF_PARAMS) };

        if params.bExtract == CK_FALSE && params.bExpand == CK_FALSE {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        if params.bExtract != CK_FALSE
            && params.ulSaltLen > 0
            && params.pSalt == std::ptr::null_mut()
        {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        if params.bExpand != CK_FALSE
            && params.ulInfoLen > 0
            && params.pInfo == std::ptr::null_mut()
        {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        let hmaclen = match hmac_size(params.prfHashMechanism) {
            INVALID_HASH_SIZE => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            x => x,
        };
        let salt = match params.ulSaltType {
            CKF_HKDF_SALT_NULL => {
                if params.ulSaltLen > 0 || params.pSalt != std::ptr::null_mut()
                {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                } else {
                    vec![0u8; hmaclen]
                }
            }
            CKF_HKDF_SALT_DATA => {
                if params.ulSaltLen == 0 || params.pSalt == std::ptr::null_mut()
                {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
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
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };

        Ok(HKDFOperation {
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
        })
    }

    fn fixup_template(
        template: &[CK_ATTRIBUTE],
        attributes: &[CK_ATTRIBUTE],
    ) -> Option<Vec<CK_ATTRIBUTE>> {
        /* this function only adds missing defaults, it ain't validation */
        let mut vec: Option<Vec<CK_ATTRIBUTE>> = None;
        for attr in attributes {
            match template.iter().find(|a| a.type_ == attr.type_) {
                Some(_) => (),
                None => {
                    if let Some(ref mut v) = vec {
                        v.push(attr.clone());
                    } else {
                        let mut v = template.to_vec();
                        v.push(attr.clone());
                        vec = Some(v);
                    }
                }
            }
        }
        vec
    }

    fn data_object_and_secret_size(
        &self,
        template: &[CK_ATTRIBUTE],
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
        let default_class = CKO_DATA;
        let mut otmpl = Self::fixup_template(
            template,
            &[CK_ATTRIBUTE::from_ulong(CKA_CLASS, &default_class)],
        );
        let keysize = match template.iter().find(|a| a.type_ == CKA_VALUE_LEN) {
            Some(cka) => {
                let ks = cka.to_ulong()? as usize;
                /* we must remove CKA_VALUE_LEN from the template as it is not a valid
                 * attribute for a CKO_DATA object */
                let mut vec =
                    Vec::<CK_ATTRIBUTE>::with_capacity(template.len() - 1);
                let tmpl = match otmpl {
                    Some(ref o) => o.as_slice(),
                    None => template,
                };
                for a in tmpl {
                    if a.type_ != CKA_VALUE_LEN {
                        vec.push(a.clone());
                    }
                }
                otmpl = Some(vec);
                ks
            }
            None => self.prflen,
        };
        let tmpl = match otmpl {
            Some(ref o) => o.as_slice(),
            None => template,
        };
        let obj = match objfactories.get_factory(ObjectType::new(CKO_DATA, 0)) {
            Ok(f) => f.create(tmpl)?,
            Err(_) => return err_rv!(CKR_GENERAL_ERROR),
        };
        Ok((obj, keysize))
    }

    fn key_object_and_secret_size(
        &self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
        let default_class = CKO_SECRET_KEY;
        let otmpl = Self::fixup_template(
            template,
            &[CK_ATTRIBUTE::from_ulong(CKA_CLASS, &default_class)],
        );
        let tmpl = match otmpl {
            Some(ref o) => o.as_slice(),
            None => template,
        };
        let obj = objfactories.derive_key_from_template(key, tmpl)?;
        let keysize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(n) => n as usize,
            Err(_) => self.prflen,
        };
        Ok((obj, keysize))
    }
}

impl MechOperation for HKDFOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }

    fn requires_objects(&self) -> KResult<&[CK_OBJECT_HANDLE]> {
        if self.salt_type == CKF_HKDF_SALT_KEY {
            return Ok(&self.salt_key);
        } else {
            /* we are good, no need to even send a vector */
            return err_rv!(CKR_OK);
        }
    }
    fn receives_objects(&mut self, objs: &[&Object]) -> KResult<()> {
        if objs.len() != 1 {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        self.verify_key(objs[0], 0)?;
        if let Ok(salt) = objs[0].get_attr_as_bytes(CKA_VALUE) {
            self.salt.clone_from(salt);
            Ok(())
        } else {
            err_rv!(CKR_KEY_HANDLE_INVALID)
        }
    }
}

#[cfg(feature = "fips")]
include!("ossl/kdf.rs");

#[cfg(not(feature = "fips"))]
include!("sp800_108.rs");

include!("ossl/hkdf.rs");

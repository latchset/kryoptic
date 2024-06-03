// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use super::{err_rv, sizeof};

use attribute::from_bytes;
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{Object, ObjectFactories};

use super::{bytes_to_slice, bytes_to_vec, cast_params};

use std::fmt::Debug;

#[cfg(feature = "fips")]
use {super::fips, fips::*};

#[cfg(not(feature = "fips"))]
macro_rules! maxsize {
    ($size: expr) => {
        match $size {
            8 | 16 | 24 | 32 | 40 | 48 | 56 => (1 << $size) - 1,
            64 => u64::MAX as usize,
            _ => panic!("Invalid size"),
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
                let kdf_params = cast_params!(mech, CK_SP800_108_KDF_PARAMS);
                Sp800Operation::counter_kdf_new(kdf_params)?
            }
            CKM_SP800_108_FEEDBACK_KDF => {
                let kdf_params =
                    cast_params!(mech, CK_SP800_108_FEEDBACK_KDF_PARAMS);
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
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
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
        if p.ulValueLen != sizeof!(CK_SP800_108_COUNTER_FORMAT) {
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
        if p.ulValueLen != sizeof!(CK_SP800_108_DKM_LENGTH_FORMAT) {
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
            #[cfg(feature = "fips")]
            fips_approved: None,
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
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    #[cfg(not(feature = "fips"))]
    fn key_to_segment_size(key: usize, segment: usize) -> usize {
        ((key + segment - 1) / segment) * segment
    }

    #[cfg(not(feature = "fips"))]
    fn ctr_update(
        param: &Sp800CounterFormat,
        ctr: usize,
        op: &mut Box<dyn Mac>,
    ) -> KResult<()> {
        if !param.defined {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        match param.bits {
            8 => {
                if ctr > maxsize!(8) {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                op.mac_update(&[ctr as u8])
            }
            16 => {
                if ctr > maxsize!(16) {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let data = if param.le {
                    (ctr as u16).to_le_bytes()
                } else {
                    (ctr as u16).to_be_bytes()
                };
                op.mac_update(&data)
            }
            24 => {
                if ctr > maxsize!(24) {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let (data, s, e) = if param.le {
                    ((ctr as u32).to_le_bytes(), 0, 3)
                } else {
                    ((ctr as u32).to_be_bytes(), 1, 4)
                };
                op.mac_update(&data[s..e])
            }
            32 => {
                if ctr > maxsize!(32) {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                let data = if param.le {
                    (ctr as u32).to_le_bytes()
                } else {
                    (ctr as u32).to_be_bytes()
                };
                op.mac_update(&data)
            }
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        }
    }

    #[cfg(not(feature = "fips"))]
    fn dkm_update(
        param: &Sp800DKMLengthFormat,
        klen: usize,
        slen: usize,
        op: &mut Box<dyn Mac>,
    ) -> KResult<()> {
        let mut len = match param.method {
            CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS => slen,
            CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS => klen,
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };
        /* up to 64 bits */
        match param.bits {
            8 => {
                len = len % maxsize!(8);
                op.mac_update(&[len as u8])
            }
            16 => {
                len = len % maxsize!(16);
                let data = if param.le {
                    (len as u16).to_le_bytes()
                } else {
                    (len as u16).to_be_bytes()
                };
                op.mac_update(&data)
            }
            24 => {
                len = len % maxsize!(24);
                let (data, s, e) = if param.le {
                    ((len as u32).to_le_bytes(), 0, 3)
                } else {
                    ((len as u32).to_be_bytes(), 1, 4)
                };
                op.mac_update(&data[s..e])
            }
            32 => {
                len = len % maxsize!(32);
                let data = if param.le {
                    (len as u32).to_le_bytes()
                } else {
                    (len as u32).to_be_bytes()
                };
                op.mac_update(&data)
            }
            40 => {
                len = len % maxsize!(40);
                let (data, s, e) = if param.le {
                    ((len as u32).to_le_bytes(), 0, 5)
                } else {
                    ((len as u32).to_be_bytes(), 3, 8)
                };
                op.mac_update(&data[s..e])
            }
            48 => {
                len = len % maxsize!(48);
                let (data, s, e) = if param.le {
                    ((len as u32).to_le_bytes(), 0, 6)
                } else {
                    ((len as u32).to_be_bytes(), 2, 8)
                };
                op.mac_update(&data[s..e])
            }
            56 => {
                len = len % maxsize!(56);
                let (data, s, e) = if param.le {
                    ((len as u32).to_le_bytes(), 0, 7)
                } else {
                    ((len as u32).to_be_bytes(), 1, 8)
                };
                op.mac_update(&data[s..e])
            }
            64 => {
                len = len % maxsize!(64);
                let data = if param.le {
                    (len as u64).to_le_bytes()
                } else {
                    (len as u64).to_be_bytes()
                };
                op.mac_update(&data)
            }
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        }
    }

    #[cfg(not(feature = "fips"))]
    fn counter_updates(
        params: &Vec<Sp800Params>,
        op: &mut Box<dyn Mac>,
        ctr: usize,
        dkmklen: usize,
        dkmslen: usize,
    ) -> KResult<()> {
        let mut seen_dkmlen = false;
        let mut seen_iter = false;
        for p in params {
            match p {
                Sp800Params::Iteration(param) => {
                    if seen_iter {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    seen_iter = true;
                    Self::ctr_update(param, ctr, op)?;
                }
                Sp800Params::Counter(_) => {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                Sp800Params::ByteArray(param) => {
                    op.mac_update(param.as_slice())?;
                }
                Sp800Params::DKMLength(param) => {
                    if seen_dkmlen {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    seen_dkmlen = true;
                    Self::dkm_update(param, dkmklen, dkmslen, op)?;
                }
            }
        }
        if !seen_iter {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        Ok(())
    }

    #[cfg(not(feature = "fips"))]
    fn feedback_updates(
        params: &Vec<Sp800Params>,
        op: &mut Box<dyn Mac>,
        iv: &[u8],
        ctr: usize,
        dkmklen: usize,
        dkmslen: usize,
    ) -> KResult<()> {
        let mut seen_dkmlen = false;
        let mut seen_iter = false;
        let mut seen_counter = false;
        for p in params {
            match p {
                Sp800Params::Iteration(param) => {
                    if seen_iter {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    if param.defined {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    seen_iter = true;
                    op.mac_update(iv)?;
                }
                Sp800Params::Counter(param) => {
                    if seen_counter {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    seen_counter = true;
                    Self::ctr_update(param, ctr, op)?;
                }
                Sp800Params::ByteArray(param) => {
                    op.mac_update(param.as_slice())?;
                }
                Sp800Params::DKMLength(param) => {
                    if seen_dkmlen {
                        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                    }
                    seen_dkmlen = true;
                    Self::dkm_update(param, dkmklen, dkmslen, op)?;
                }
            }
        }
        if !seen_iter {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        Ok(())
    }
}

impl MechOperation for Sp800Operation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    Sp800Operation::register_mechanisms(mechs);
}

#[cfg(not(feature = "fips"))]
impl Derive for Sp800Operation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<Vec<Object>> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        Self::verify_prf_key(self.prf, key)?;

        /* Ok so this stuff in the PKCS#11 spec has an insane level
         * of flexibility, fundamentally each parameter correspond to
         * data that will be feed to the MAC operation in the order
         * it should happen, providing maximum composability and an
         * effectively infinite combinatorial matrix.
         *
         * This is an attempt at supporting insanity :-) */

        let mechanism = CK_MECHANISM {
            mechanism: self.prf,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mech = mechanisms.get(self.prf)?;
        let mut op = mech.mac_new(&mechanism, key, CKF_DERIVE)?;
        let segment = op.mac_len()?;

        let obj = objfactories.derive_key_from_template(key, template)?;
        let keysize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(n) => n as usize,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        if keysize == 0 || keysize > (u32::MAX as usize) {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        let mut keys =
            Vec::<Object>::with_capacity(1 + self.addl_drv_keys.len());
        keys.push(obj);

        let mut klen = keysize;
        let mut slen = Self::key_to_segment_size(keysize, segment);

        /* additional keys */
        for ak in &self.addl_drv_keys {
            let tmpl: &[CK_ATTRIBUTE] = unsafe {
                std::slice::from_raw_parts_mut(
                    ak.pTemplate,
                    ak.ulAttributeCount as usize,
                )
            };
            let obj = match objfactories.derive_key_from_template(key, tmpl) {
                Ok(o) => o,
                Err(e) => {
                    /* mark the handle as invalid */
                    unsafe {
                        core::ptr::write(ak.phKey, CK_INVALID_HANDLE);
                    }
                    return Err(e);
                }
            };
            let aksize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
                Ok(n) => n as usize,
                Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
            };
            if aksize == 0 || aksize > (u32::MAX as usize) {
                return err_rv!(CKR_KEY_SIZE_RANGE);
            }
            klen += aksize;
            slen += Self::key_to_segment_size(aksize, segment);
            keys.push(obj);
        }

        let mut dkm = vec![0u8; slen];

        /* for each segment */
        let mut cursor = 0;
        for ctr in 0..(slen / segment) {
            if ctr != 0 {
                op = mech.mac_new(&mechanism, key, CKF_DERIVE)?;
            }
            match self.mech {
                CKM_SP800_108_COUNTER_KDF => {
                    Self::counter_updates(
                        &self.params,
                        &mut op,
                        ctr + 1,
                        klen,
                        slen,
                    )?;
                }
                CKM_SP800_108_FEEDBACK_KDF => {
                    let iv = if ctr == 0 {
                        &self.iv.as_slice()
                    } else {
                        &dkm[(cursor - segment)..cursor]
                    };
                    Self::feedback_updates(
                        &self.params,
                        &mut op,
                        iv,
                        ctr + 1,
                        klen,
                        slen,
                    )?;
                }
                _ => return err_rv!(CKR_GENERAL_ERROR),
            }
            op.mac_final(&mut dkm[cursor..(cursor + segment)])?;
            cursor += segment;
        }

        let mut cursor = 0;
        for key in &mut keys {
            let keysize = key.get_attr_as_ulong(CKA_VALUE_LEN)? as usize;
            key.set_attr(from_bytes(
                CKA_VALUE,
                dkm[cursor..(cursor + keysize)].to_vec(),
            ))?;
            cursor += Self::key_to_segment_size(keysize, segment);
        }
        Ok(keys)
    }
}

#[cfg(feature = "fips")]
include!("ossl/kbkdf.rs");

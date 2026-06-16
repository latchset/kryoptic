// Copyright 2026 Stephan Müller
// See LICENSE.txt file for terms

use crate::attribute::Attribute;
use crate::error::Result;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::bytes_to_slice;
use crate::object::{Object, ObjectFactories};
use crate::pkcs11::*;
use crate::sp800_108::{Sp800Params, verify_prf_key};

use crate::leancrypto::common::mech_type_to_digest_alg;
use leancrypto_sys::lcr_hash::lcr_hash_digestsize_mapping;
use leancrypto_sys::lcr_kbkdf::{lcr_kbkdf_ctr, lcr_kbkdf_fb};

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

fn key_to_segment_size(key: usize, segment: usize) -> usize {
    ((key + segment - 1) / segment) * segment
}

/// Helper macro to return the maximum value `size` bits can express,
/// up to a maximum of 64 bit
macro_rules! maxsize {
    ($size: expr) => {
        match $size {
            8 | 16 | 24 | 32 | 40 | 48 | 56 => (1u64 << $size) - 1,
            64 => u64::MAX,
            _ => panic!("Invalid size"),
        }
    };
}

#[derive(Debug)]
pub struct Sp800Operation {
    mech: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    finalized: bool,
    params: Vec<Sp800Params>,
    iv: Option<&'static [u8]>, /* TODO: 'static -> 'a */
    addl_drv_keys: Vec<CK_DERIVED_KEY>,
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

unsafe impl Send for Sp800Operation {}
unsafe impl Sync for Sp800Operation {}
impl Sp800Operation {
    pub fn counter_kdf_new(
        params: CK_SP800_108_KDF_PARAMS,
    ) -> Result<Sp800Operation> {
        let data_params = unsafe {
            bytes_to_slice(
                params.pDataParams as *const CK_PRF_DATA_PARAM,
                params.ulNumberOfDataParams as usize,
            )
        };
        let addl_drv_keys = unsafe {
            bytes_to_slice(
                params.pAdditionalDerivedKeys as *const CK_DERIVED_KEY,
                params.ulAdditionalDerivedKeys as usize,
            )
        };
        Ok(Sp800Operation {
            mech: CKM_SP800_108_COUNTER_KDF,
            prf: params.prfType,
            finalized: false,
            params: Sp800Params::parse_data_params(&data_params)?,
            iv: None,
            addl_drv_keys: addl_drv_keys.to_vec(),
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    pub fn feedback_kdf_new(
        params: CK_SP800_108_FEEDBACK_KDF_PARAMS,
    ) -> Result<Sp800Operation> {
        let data_params = unsafe {
            bytes_to_slice(
                params.pDataParams as *const CK_PRF_DATA_PARAM,
                params.ulNumberOfDataParams as usize,
            )
        };
        let addl_drv_keys = unsafe {
            bytes_to_slice(
                params.pAdditionalDerivedKeys as *const CK_DERIVED_KEY,
                params.ulAdditionalDerivedKeys as usize,
            )
        };
        let iv = if params.pIV != std::ptr::null_mut() && params.ulIVLen != 0 {
            Some(unsafe {
                bytes_to_slice(params.pIV as *const u8, params.ulIVLen as usize)
            })
        } else if params.pIV == std::ptr::null_mut() && params.ulIVLen == 0 {
            None
        } else {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        };
        Ok(Sp800Operation {
            mech: CKM_SP800_108_FEEDBACK_KDF,
            prf: params.prfType,
            finalized: false,
            params: Sp800Params::parse_data_params(&data_params)?,
            iv: iv,
            addl_drv_keys: addl_drv_keys.to_vec(),
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }
}

impl MechOperation for Sp800Operation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for Sp800Operation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms, //TODO unused
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        verify_prf_key(self.prf, key)?;

        /********************** Define output structure ***********************/

        let obj = objfactories.derive_key_from_template(key, template)?;
        let keysize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(size) => usize::try_from(size)?,
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };
        if keysize == 0 || keysize > usize::try_from(u32::MAX)? {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let mut keys =
            Vec::<Object>::with_capacity(1 + self.addl_drv_keys.len());
        keys.push(obj);

        let hash_type = mech_type_to_digest_alg(self.prf)?;
        let mut segment = 1;
        if self.addl_drv_keys.len() > 0 {
            /* need the mechanism to compute the segment size as
             * leancrypto will just return a linear buffer, that we
             * need to split in segments as the spec requires */
            segment = lcr_hash_digestsize_mapping(hash_type);
        }

        let mut slen = key_to_segment_size(keysize, segment);

        /* additional keys */
        for ak in &self.addl_drv_keys {
            let tmpl: &[CK_ATTRIBUTE] = unsafe {
                std::slice::from_raw_parts_mut(
                    ak.pTemplate,
                    usize::try_from(ak.ulAttributeCount)
                        .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
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
                Ok(n) => usize::try_from(n)?,
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            };
            if aksize == 0 || aksize > usize::try_from(u32::MAX)? {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
            /* increment size in segment steps */
            slen += key_to_segment_size(aksize, segment);
            keys.push(obj);
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut dkm = vec![0u8; slen];

        /************************** Parse input data **************************/

        /* Ok so this stuff in the PKCS#11 spec has an insane level
         * of flexibility, fundamentally each parameter correspond to
         * data that will be feed to the MAC operation in the order
         * it should happen, providing maximum composability and an
         * effectively infinite combinatorial matrix.
         * While some flexibility may make sense, this is excessive
         * and only provide a sharp knife in the hand of users.
         * Therefore upon parsing we accept only "well" formed inputs
         * that follow the NIST specification of Counter and Feedback
         * mode etc.. without flexibility on the ordering for example,
         * although we still need to allow for way more options that
         * I'd like.
         *
         * Some of the restrictions here are due to the leancrypto
         * implementation of KBKDF. For example it hardcodes counters
         * and other lengths as bigendian, and supports only
         * counters of size 32 ...
         */

        let mut label_data = Vec::new();
        if self.params.len() < 1 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        /* Key, iter, [counter], [Label], [0x00], [Context], [Len] */
        match &self.params[0] {
            Sp800Params::Iteration(c) => {
                if c.defined && self.mech == CKM_SP800_108_FEEDBACK_KDF {
                    /* Spec says param must be null for feedback mode */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                /* leancrypto only supports 32 bit counter */
                if c.bits != 32 {
                    return Err(CKR_MECHANISM_INVALID)?;
                }
            }
            /*
             * leancrypto limits the counter location to before fixed which
             * implies that the counter must come first.
             */
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }

        let mut seen_dkmlen = false;
        for idx in 1..self.params.len() {
            match &self.params[idx] {
                Sp800Params::Counter(c) => {
                    if c.le {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    if c.bits != 32 {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                }
                Sp800Params::ByteArray(v) => {
                    label_data.extend_from_slice(v.as_slice());
                }
                Sp800Params::DKMLength(v) => {
                    if seen_dkmlen {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    seen_dkmlen = true;

                    // Feed the length of the sum of the segments or of the keys
                    // to be produced
                    //
                    // NOTE: In this function the len is intentionally truncated by
                    // casting, do not convert with try_from()
                    let mut len = match v.method {
                        CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS => slen,
                        CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS => keysize,
                        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                    } as u64;
                    /* up to 64 bits */
                    match v.bits {
                        8 => {
                            len = len % maxsize!(8);
                            label_data.extend_from_slice(&len.to_le_bytes())
                        }
                        16 => {
                            len = len % maxsize!(16);
                            let data = if v.le {
                                (len as u16).to_le_bytes()
                            } else {
                                (len as u16).to_be_bytes()
                            };
                            label_data.extend_from_slice(&data)
                        }
                        24 => {
                            len = len % maxsize!(24);
                            let (data, s, e) = if v.le {
                                ((len as u32).to_le_bytes(), 0, 3)
                            } else {
                                ((len as u32).to_be_bytes(), 1, 4)
                            };
                            label_data.extend_from_slice(&data[s..e])
                        }
                        32 => {
                            len = len % maxsize!(32);
                            let data = if v.le {
                                (len as u32).to_le_bytes()
                            } else {
                                (len as u32).to_be_bytes()
                            };
                            label_data.extend_from_slice(&data)
                        }
                        40 => {
                            len = len % maxsize!(40);
                            let (data, s, e) = if v.le {
                                ((len as u32).to_le_bytes(), 0, 5)
                            } else {
                                ((len as u32).to_be_bytes(), 3, 8)
                            };
                            label_data.extend_from_slice(&data[s..e])
                        }
                        48 => {
                            len = len % maxsize!(48);
                            let (data, s, e) = if v.le {
                                ((len as u32).to_le_bytes(), 0, 6)
                            } else {
                                ((len as u32).to_be_bytes(), 2, 8)
                            };
                            label_data.extend_from_slice(&data[s..e])
                        }
                        56 => {
                            len = len % maxsize!(56);
                            let (data, s, e) = if v.le {
                                ((len as u32).to_le_bytes(), 0, 7)
                            } else {
                                ((len as u32).to_be_bytes(), 1, 8)
                            };
                            label_data.extend_from_slice(&data[s..e])
                        }
                        64 => {
                            len = len % maxsize!(64);
                            let data = if v.le {
                                (len as u64).to_le_bytes()
                            } else {
                                (len as u64).to_be_bytes()
                            };
                            label_data.extend_from_slice(&data)
                        }
                        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                    }
                }
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            }
        }

        /*************************** Perform KDF op ***************************/

        match self.mech {
            CKM_SP800_108_COUNTER_KDF => {
                let mut kdf = lcr_kbkdf_ctr::new(hash_type);

                match kdf.derive(
                    key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
                    &label_data,
                    &mut dkm,
                ) {
                    Err(_) => return Err(CKR_FUNCTION_FAILED)?,
                    Ok(res) => res,
                };
            }
            CKM_SP800_108_FEEDBACK_KDF => {
                let mut kdf = lcr_kbkdf_fb::new(hash_type);

                let iv = match self.iv {
                    Some(v) => v,
                    None => &[],
                };

                match kdf.derive(
                    key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
                    iv,
                    &label_data,
                    &mut dkm,
                ) {
                    Err(_) => return Err(CKR_FUNCTION_FAILED)?,
                    Ok(res) => res,
                };
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        /*********************** Fill output structure ************************/

        let mut cursor = 0;
        for key in &mut keys {
            let keysize =
                usize::try_from(key.get_attr_as_ulong(CKA_VALUE_LEN)?)?;
            key.set_attr(Attribute::from_bytes(
                CKA_VALUE,
                dkm[cursor..(cursor + keysize)].to_vec(),
            ))?;
            cursor += key_to_segment_size(keysize, segment);
        }
        Ok(keys)
    }
}

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::attribute::Attribute;
use crate::error::{map_err, Result};
use crate::interface::*;
use crate::mechanism::{Derive, Mac, MechOperation, Mechanisms};
use crate::misc::{bytes_to_slice, bytes_to_vec};
use crate::object::{Object, ObjectFactories};
use crate::sp800_108::*;

macro_rules! maxsize {
    ($size: expr) => {
        match $size {
            8 | 16 | 24 | 32 | 40 | 48 | 56 => (1u64 << $size) - 1,
            64 => u64::MAX,
            _ => panic!("Invalid size"),
        }
    };
}

macro_rules! maxsize32 {
    ($size: expr) => {
        match $size {
            8 | 16 | 24 => (1usize << $size) - 1,
            32 => usize::try_from(u32::MAX)?,
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
    iv: Vec<u8>,
    addl_drv_keys: Vec<CK_DERIVED_KEY>,
}

unsafe impl Send for Sp800Operation {}
unsafe impl Sync for Sp800Operation {}

impl Sp800Operation {
    pub fn counter_kdf_new(
        params: CK_SP800_108_KDF_PARAMS,
    ) -> Result<Sp800Operation> {
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
            params: Sp800Params::parse_data_params(&data_params)?,
            iv: Vec::new(),
            addl_drv_keys: addl_drv_keys.to_vec(),
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }

    pub fn feedback_kdf_new(
        params: CK_SP800_108_FEEDBACK_KDF_PARAMS,
    ) -> Result<Sp800Operation> {
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
            fips_approved: None,
        })
    }

    fn key_to_segment_size(key: usize, segment: usize) -> usize {
        ((key + segment - 1) / segment) * segment
    }

    /* NOTE: In this function the ctr is intentionally truncated by
     * casting, do not convert with try_from() */
    fn ctr_update(
        param: &Sp800CounterFormat,
        ctr: usize,
        op: &mut Box<dyn Mac>,
    ) -> Result<()> {
        if !param.defined {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        match param.bits {
            8 => {
                if ctr > maxsize32!(8) {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                op.mac_update(&[ctr as u8])
            }
            16 => {
                if ctr > maxsize32!(16) {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let data = if param.le {
                    (ctr as u16).to_le_bytes()
                } else {
                    (ctr as u16).to_be_bytes()
                };
                op.mac_update(&data)
            }
            24 => {
                if ctr > maxsize32!(24) {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let (data, s, e) = if param.le {
                    ((ctr as u32).to_le_bytes(), 0, 3)
                } else {
                    ((ctr as u32).to_be_bytes(), 1, 4)
                };
                op.mac_update(&data[s..e])
            }
            32 => {
                if ctr > maxsize32!(32) {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                let data = if param.le {
                    (ctr as u32).to_le_bytes()
                } else {
                    (ctr as u32).to_be_bytes()
                };
                op.mac_update(&data)
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }

    /* NOTE: In this function the len is intentionally truncated by
     * casting, do not convert with try_from() */
    fn dkm_update(
        param: &Sp800DKMLengthFormat,
        klen: usize,
        slen: usize,
        op: &mut Box<dyn Mac>,
    ) -> Result<()> {
        let mut len = match param.method {
            CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS => slen,
            CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS => klen,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        } as u64;
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
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }

    fn counter_updates(
        params: &Vec<Sp800Params>,
        op: &mut Box<dyn Mac>,
        ctr: usize,
        dkmklen: usize,
        dkmslen: usize,
    ) -> Result<()> {
        let mut seen_dkmlen = false;
        let mut seen_iter = false;
        for p in params {
            match p {
                Sp800Params::Iteration(param) => {
                    if seen_iter {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    seen_iter = true;
                    Self::ctr_update(param, ctr, op)?;
                }
                Sp800Params::Counter(_) => {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                Sp800Params::ByteArray(param) => {
                    op.mac_update(param.as_slice())?;
                }
                Sp800Params::DKMLength(param) => {
                    if seen_dkmlen {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    seen_dkmlen = true;
                    Self::dkm_update(param, dkmklen, dkmslen, op)?;
                }
            }
        }
        if !seen_iter {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(())
    }

    fn feedback_updates(
        params: &Vec<Sp800Params>,
        op: &mut Box<dyn Mac>,
        iv: &[u8],
        ctr: usize,
        dkmklen: usize,
        dkmslen: usize,
    ) -> Result<()> {
        let mut seen_dkmlen = false;
        let mut seen_iter = false;
        let mut seen_counter = false;
        for p in params {
            match p {
                Sp800Params::Iteration(param) => {
                    if seen_iter {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    if param.defined {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    seen_iter = true;
                    op.mac_update(iv)?;
                }
                Sp800Params::Counter(param) => {
                    if seen_counter {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    seen_counter = true;
                    Self::ctr_update(param, ctr, op)?;
                }
                Sp800Params::ByteArray(param) => {
                    op.mac_update(param.as_slice())?;
                }
                Sp800Params::DKMLength(param) => {
                    if seen_dkmlen {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                    seen_dkmlen = true;
                    Self::dkm_update(param, dkmklen, dkmslen, op)?;
                }
            }
        }
        if !seen_iter {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(())
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
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        verify_prf_key(self.prf, key)?;

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
            Ok(size) => usize::try_from(size)?,
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };
        if keysize == 0 || keysize > usize::try_from(u32::MAX)? {
            return Err(CKR_KEY_SIZE_RANGE)?;
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
                    map_err!(
                        usize::try_from(ak.ulAttributeCount),
                        CKR_MECHANISM_PARAM_INVALID
                    )?,
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
                Ok(size) => usize::try_from(size)?,
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            };
            if aksize == 0 || aksize > usize::try_from(u32::MAX)? {
                return Err(CKR_KEY_SIZE_RANGE)?;
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
                _ => return Err(CKR_GENERAL_ERROR)?,
            }
            op.mac_final(&mut dkm[cursor..(cursor + segment)])?;
            cursor += segment;
        }

        let mut cursor = 0;
        for key in &mut keys {
            let keysize =
                usize::try_from(key.get_attr_as_ulong(CKA_VALUE_LEN)?)?;
            key.set_attr(Attribute::from_bytes(
                CKA_VALUE,
                dkm[cursor..(cursor + keysize)].to_vec(),
            ))?;
            cursor += Self::key_to_segment_size(keysize, segment);
        }
        Ok(keys)
    }
}

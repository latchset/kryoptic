// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::attribute::Attribute;
use crate::error::{map_err, Result};
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::bytes_to_slice;
use crate::object::{Object, ObjectFactories};
use crate::ossl::common::osslctx;
use crate::sp800_108::{verify_prf_key, Sp800Params};

use ossl::derive::{KbkdfCounterLen, KbkdfDerive, KbkdfMode};
use ossl::mac::MacAlg;
use pkcs11::*;

use ossl::fips::FipsApproval;

fn prep_counter_kdf<'a>(
    sparams: &'a Vec<Sp800Params>,
    kbkdf: &mut KbkdfDerive<'a>,
) -> Result<()> {
    if sparams.len() < 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }

    /* Key, counter, [Label], [0x00], [Context], [Len] */
    match &sparams[0] {
        Sp800Params::Iteration(i) => {
            if !i.defined {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            if i.le {
                /* OpenSSL limitations */
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            kbkdf.set_counter_len(match i.bits {
                8 => KbkdfCounterLen::Len8b,
                16 => KbkdfCounterLen::Len16b,
                24 => KbkdfCounterLen::Len24b,
                32 => KbkdfCounterLen::Len32b,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            })?;
        }
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }

    let mut label = false;
    let mut separator = false;
    let mut context = false;
    let mut dkmlen = false;

    for idx in 1..sparams.len() {
        match &sparams[idx] {
            Sp800Params::ByteArray(v) => {
                if context {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if separator {
                    /* separator set, this is a Context */
                    kbkdf.set_info(v.as_slice());
                    context = true;
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        separator = true;
                    } else {
                        if label {
                            /* label set and no separator, this is a Context */
                            kbkdf.set_info(v.as_slice());
                            context = true;
                        } else {
                            kbkdf.set_salt(v.as_slice());
                            label = true;
                        }
                    }
                }
            }
            Sp800Params::DKMLength(v) => {
                if dkmlen {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if v.le
                    || v.bits != 32
                    || v.method != CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS
                {
                    /* OpenSSL limitations */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                dkmlen = true;

                /* DKM Length is always last in OpenSSL, so also mark
                 * context as true regardless as no more Byte Arrays
                 * are allowed */
                context = true;
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }
    kbkdf.use_separator(separator);
    kbkdf.use_fixed_len(dkmlen);
    Ok(())
}

fn prep_feedback_kdf<'a>(
    sparams: &'a Vec<Sp800Params>,
    kbkdf: &mut KbkdfDerive<'a>,
) -> Result<()> {
    if sparams.len() < 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }

    /* Key, iter, [counter], [Label], [0x00], [Context], [Len] */
    match &sparams[0] {
        Sp800Params::Iteration(c) => {
            if c.defined {
                /* Spec says param must be null for feedback mode */
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
        }
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }

    let mut counter = false;
    let mut label = false;
    let mut separator = false;
    let mut context = false;
    let mut dkmlen = false;

    for idx in 1..sparams.len() {
        match &sparams[idx] {
            Sp800Params::Counter(c) => {
                if counter {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if c.le {
                    /* OpenSSL limitations */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                kbkdf.set_counter_len(match c.bits {
                    8 => KbkdfCounterLen::Len8b,
                    16 => KbkdfCounterLen::Len16b,
                    24 => KbkdfCounterLen::Len24b,
                    32 => KbkdfCounterLen::Len32b,
                    _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                })?;
            }
            Sp800Params::ByteArray(v) => {
                /* unconditionally set counter to true as once we get
                 * a byte array, counter can't be set anymore for
                 * OpenSSL */
                counter = true;
                if context {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if separator {
                    /* separator set, this is a Context */
                    kbkdf.set_info(v.as_slice());
                    context = true;
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        separator = true;
                    } else {
                        if label {
                            /* label set and no separator, this is a Context */
                            kbkdf.set_info(v.as_slice());
                            context = true;
                        } else {
                            kbkdf.set_salt(v.as_slice());
                            label = true;
                        }
                    }
                }
            }
            Sp800Params::DKMLength(v) => {
                if dkmlen {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if v.le
                    || v.bits != 32
                    || v.method != CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
                {
                    /* OpenSSL limitations */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                dkmlen = true;

                /* DKM Length is always last in OpenSSL, so also mark
                 * context and counter as true regardless as no more
                 * Counter or Byte Arrays are allowed for OpenSSL */
                counter = true;
                context = true;
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }
    kbkdf.use_separator(separator);
    kbkdf.use_fixed_len(dkmlen);
    Ok(())
}

fn get_segment_size(
    mechanisms: &Mechanisms,
    hmac: CK_MECHANISM_TYPE,
) -> Result<usize> {
    let mech = CK_MECHANISM {
        mechanism: match hmac {
            CKM_SHA_1_HMAC => CKM_SHA_1,
            CKM_SHA224_HMAC => CKM_SHA224,
            CKM_SHA256_HMAC => CKM_SHA256,
            CKM_SHA384_HMAC => CKM_SHA384,
            CKM_SHA512_HMAC => CKM_SHA512,
            CKM_SHA3_224_HMAC => CKM_SHA3_224,
            CKM_SHA3_256_HMAC => CKM_SHA3_256,
            CKM_SHA3_384_HMAC => CKM_SHA3_384,
            CKM_SHA3_512_HMAC => CKM_SHA3_512,
            CKM_SHA512_224_HMAC => CKM_SHA512_224,
            CKM_SHA512_256_HMAC => CKM_SHA512_256,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        },
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    mechanisms
        .get(mech.mechanism)?
        .digest_new(&mech)?
        .digest_len()
}

fn key_to_segment_size(key: usize, segment: usize) -> usize {
    ((key + segment - 1) / segment) * segment
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
            iv: None,
            addl_drv_keys: addl_drv_keys.to_vec(),
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
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
            Some(bytes_to_slice!(params.pIV, params.ulIVLen, u8))
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
         * While some flexibility may make sense, this is excessive
         * and only provide a sharp knife in the hand of users.
         * Therefore upon parsing we accept only "well" formed inputs
         * that follow the NIST specification of Counter and Feedback
         * mode etc.. without flexibility on the ordering for example,
         * although we still need to allow for way more options that
         * I'd like.
         *
         * Some of the restrictions here are due to the OpenSSL
         * implementation of KBKDF. For example it hardcodes counters
         * and other lengths as bigendian, has a fixed size for the L
         * variable of 32 bit (or none at all), and supports only
         * counters of size 8, 16, 24, 32 ...
         */

        let mode = match self.mech {
            CKM_SP800_108_COUNTER_KDF => KbkdfMode::Counter,
            CKM_SP800_108_FEEDBACK_KDF => KbkdfMode::Feedback,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let mac = match self.prf {
            CKM_SHA_1_HMAC => MacAlg::HmacSha1,
            CKM_SHA224_HMAC => MacAlg::HmacSha2_224,
            CKM_SHA256_HMAC => MacAlg::HmacSha2_256,
            CKM_SHA384_HMAC => MacAlg::HmacSha2_384,
            CKM_SHA512_HMAC => MacAlg::HmacSha2_512,
            CKM_SHA512_224_HMAC => MacAlg::HmacSha2_512_224,
            CKM_SHA512_256_HMAC => MacAlg::HmacSha2_512_256,
            CKM_SHA3_224_HMAC => MacAlg::HmacSha3_224,
            CKM_SHA3_256_HMAC => MacAlg::HmacSha3_256,
            CKM_SHA3_384_HMAC => MacAlg::HmacSha3_384,
            CKM_SHA3_512_HMAC => MacAlg::HmacSha3_512,
            CKM_AES_CMAC => match key.get_attr_as_ulong(CKA_VALUE_LEN)? {
                16 => MacAlg::CmacAes128,
                24 => MacAlg::CmacAes192,
                32 => MacAlg::CmacAes256,
                _ => return Err(CKR_KEY_INDIGESTIBLE)?,
            },
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };
        let mut kdf = KbkdfDerive::new(osslctx(), mac, mode)?;
        kdf.set_key(key.get_attr_as_bytes(CKA_VALUE)?.as_slice());
        match mode {
            KbkdfMode::Counter => prep_counter_kdf(&self.params, &mut kdf)?,
            KbkdfMode::Feedback => prep_feedback_kdf(&self.params, &mut kdf)?,
        }
        if let Some(iv) = self.iv {
            kdf.set_seed(iv);
        }

        let mut segment = 1;
        if self.addl_drv_keys.len() > 0 {
            /* need the mechanism to compute the segment size as
             * openssl will just return a linear buffer, that we
             * need to split in segments as the spec requires */
            if self.prf == CKM_AES_CMAC {
                /* AES CMAC always return 16 bytes signatures */
                segment = 16;
            } else {
                segment = get_segment_size(mechanisms, self.prf)?;
            }
        }

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

        let mut slen = key_to_segment_size(keysize, segment);

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
        kdf.derive(&mut dkm)?;

        #[cfg(feature = "fips")]
        self.fips_approval.update();

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

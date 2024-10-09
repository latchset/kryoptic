// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::c_int;

use crate::attribute::from_bytes;
use crate::error;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::object::{Object, ObjectFactories};
use crate::ossl::bindings::*;
use crate::ossl::common::*;
use crate::ossl::fips::*;
use crate::sp800_108::*;
use crate::{bytes_to_slice, bytes_to_vec, map_err};

const SP800_MODE_COUNTER: &[u8; 8] = b"counter\0";
const SP800_MODE_FEEDBACK: &[u8; 9] = b"feedback\0";
const MAC_NAME_CMAC: &[u8; 5] = b"CMAC\0";
const MAC_NAME_HMAC: &[u8; 5] = b"HMAC\0";

fn prep_counter_kdf<'a>(
    sparams: &'a Vec<Sp800Params>,
    params: &mut OsslParam<'a>,
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
            params.add_owned_int(
                name_as_char(OSSL_KDF_PARAM_KBKDF_R),
                c_int::try_from(i.bits)?,
            )?;
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
                    params.add_octet_string(
                        name_as_char(OSSL_KDF_PARAM_INFO),
                        &v,
                    )?;
                    context = true;
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        params.add_owned_int(
                            name_as_char(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
                            1,
                        )?;
                        separator = true;
                    } else {
                        if label {
                            /* label set and no separator, this is a Context */
                            params.add_octet_string(
                                name_as_char(OSSL_KDF_PARAM_INFO),
                                &v,
                            )?;
                            context = true;
                        } else {
                            params.add_octet_string(
                                name_as_char(OSSL_KDF_PARAM_SALT),
                                &v,
                            )?;
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
                params.add_owned_int(
                    name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L),
                    1,
                )?;
                dkmlen = true;

                /* DKM Length is always last in OpenSSL, so also mark
                 * context as true regardless as no more Byte Arrays
                 * are allowed */
                context = true;
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }
    if !separator {
        params.add_owned_int(
            name_as_char(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
            0,
        )?
    }
    if !dkmlen {
        params.add_owned_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L), 0)?
    }
    params.finalize();
    Ok(())
}

fn prep_feedback_kdf<'a>(
    sparams: &'a Vec<Sp800Params>,
    params: &mut OsslParam<'a>,
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
                params.add_owned_int(
                    name_as_char(OSSL_KDF_PARAM_KBKDF_R),
                    c_int::try_from(c.bits)?,
                )?;
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
                    params.add_octet_string(
                        name_as_char(OSSL_KDF_PARAM_INFO),
                        &v,
                    )?;
                    context = true;
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        params.add_owned_int(
                            name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L),
                            1,
                        )?;
                        separator = true;
                    } else {
                        if label {
                            /* label set and no separator, this is a Context */
                            params.add_octet_string(
                                name_as_char(OSSL_KDF_PARAM_INFO),
                                &v,
                            )?;
                            context = true;
                        } else {
                            params.add_octet_string(
                                name_as_char(OSSL_KDF_PARAM_SALT),
                                &v,
                            )?;
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
                params.add_owned_int(
                    name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L),
                    1,
                )?;
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
    if !separator {
        params.add_owned_int(
            name_as_char(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
            0,
        )?
    }
    if !dkmlen {
        params.add_owned_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L), 0)?
    }
    params.finalize();
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
    iv: Vec<u8>,
    addl_drv_keys: Vec<CK_DERIVED_KEY>,
    fips_approved: Option<bool>,
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
         * If any of these restrictions breaks a user we'll have to
         * reimplement the KBKDF code using raw HAMC/CMAC PRFs */

        let mac_type_name = if self.prf == CKM_AES_CMAC {
            name_as_char(MAC_NAME_CMAC)
        } else {
            name_as_char(MAC_NAME_HMAC)
        };
        let (prf_alg_param, prf_alg_value) = match self.prf {
            CKM_SHA_1_HMAC | CKM_SHA224_HMAC | CKM_SHA256_HMAC
            | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_224_HMAC
            | CKM_SHA3_256_HMAC | CKM_SHA3_384_HMAC | CKM_SHA3_512_HMAC => (
                name_as_char(OSSL_KDF_PARAM_DIGEST),
                mech_type_to_digest_name(self.prf),
            ),
            CKM_AES_CMAC => (
                name_as_char(OSSL_KDF_PARAM_CIPHER),
                match key.get_attr_as_ulong(CKA_VALUE_LEN)? {
                    16 => name_as_char(CIPHER_NAME_AES128),
                    24 => name_as_char(CIPHER_NAME_AES192),
                    32 => name_as_char(CIPHER_NAME_AES256),
                    _ => return Err(CKR_KEY_INDIGESTIBLE)?,
                },
            ),
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        let mut params = OsslParam::with_capacity(10);
        params.zeroize = true;
        params.add_const_c_string(
            name_as_char(OSSL_KDF_PARAM_MAC),
            mac_type_name,
        )?;
        params.add_const_c_string(prf_alg_param, prf_alg_value)?;
        params.add_octet_string(
            name_as_char(OSSL_KDF_PARAM_KEY),
            key.get_attr_as_bytes(CKA_VALUE)?,
        )?;

        match self.mech {
            CKM_SP800_108_COUNTER_KDF => {
                params.add_const_c_string(
                    name_as_char(OSSL_KDF_PARAM_MODE),
                    name_as_char(SP800_MODE_COUNTER),
                )?;
                prep_counter_kdf(&self.params, &mut params)?;
            }
            CKM_SP800_108_FEEDBACK_KDF => {
                params.add_const_c_string(
                    name_as_char(OSSL_KDF_PARAM_MODE),
                    name_as_char(SP800_MODE_FEEDBACK),
                )?;
                if self.iv.len() > 0 {
                    params.add_octet_string(
                        name_as_char(OSSL_KDF_PARAM_SEED),
                        &self.iv,
                    )?;
                }
                prep_feedback_kdf(&self.params, &mut params)?;
            }
            _ => return Err(CKR_GENERAL_ERROR)?,
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

        let mut kctx = EvpKdfCtx::new(name_as_char(OSSL_KDF_NAME_KBKDF))?;
        let mut dkm = vec![0u8; slen];
        let res = unsafe {
            EVP_KDF_derive(
                kctx.as_mut_ptr(),
                dkm.as_mut_ptr(),
                dkm.len(),
                params.as_ptr(),
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        self.fips_approved = check_kdf_fips_indicators(&mut kctx)?;

        let mut cursor = 0;
        for key in &mut keys {
            let keysize =
                usize::try_from(key.get_attr_as_ulong(CKA_VALUE_LEN)?)?;
            key.set_attr(from_bytes(
                CKA_VALUE,
                dkm[cursor..(cursor + keysize)].to_vec(),
            ))?;
            cursor += key_to_segment_size(keysize, segment);
        }
        Ok(keys)
    }
}

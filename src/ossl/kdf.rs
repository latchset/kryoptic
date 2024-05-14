// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

const SP800_MODE_COUNTER: &[u8; 8] = b"counter\0";
const SP800_MODE_FEEDBACK: &[u8; 9] = b"feedback\0";

fn prep_counter_kdf(
    sparams: &Vec<Sp800Params>,
    mut params: OsslParam,
) -> KResult<OsslParam> {
    if sparams.len() < 1 {
        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
    }

    /* Key, counter, [Label], [0x00], [Context], [Len] */
    match &sparams[0] {
        Sp800Params::Iteration(i) => {
            if !i.defined {
                return err_rv!(CKR_MECHANISM_PARAM_INVALID);
            }
            if i.le {
                /* OpenSSL limitations */
                return err_rv!(CKR_MECHANISM_PARAM_INVALID);
            }
            params = params.add_int(
                name_as_char(OSSL_KDF_PARAM_KBKDF_R),
                i.bits as c_int,
            )?;
        }
        _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
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
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if separator {
                    /* separator set, this is a Context */
                    params = params.add_octet_string(
                        name_as_char(OSSL_KDF_PARAM_INFO),
                        &v,
                    )?;
                    context = true;
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        params = params.add_int(
                            name_as_char(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
                            1,
                        )?;
                        separator = true;
                    } else {
                        if label {
                            /* label set and no separator, this is a Context */
                            params = params.add_octet_string(
                                name_as_char(OSSL_KDF_PARAM_INFO),
                                &v,
                            )?;
                            context = true;
                        } else {
                            params = params.add_octet_string(
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
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if v.le
                    || v.bits != 32
                    || v.method != CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS
                {
                    /* OpenSSL limitations */
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                params = params
                    .add_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L), 1)?;
                dkmlen = true;

                /* DKM Length is always last in OpenSSL, so also mark
                 * context as true regardless as no more Byte Arrays
                 * are allowed */
                context = true;
            }
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        }
    }
    if !separator {
        params = params
            .add_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR), 0)?
    }
    if !dkmlen {
        params = params.add_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L), 0)?
    }
    Ok(params.finalize())
}

fn prep_feedback_kdf(
    sparams: &Vec<Sp800Params>,
    mut params: OsslParam,
) -> KResult<OsslParam> {
    if sparams.len() < 1 {
        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
    }

    /* Key, iter, [counter], [Label], [0x00], [Context], [Len] */
    match &sparams[0] {
        Sp800Params::Iteration(c) => {
            if c.defined {
                /* Spec says param must be null for feedback mode */
                return err_rv!(CKR_MECHANISM_PARAM_INVALID);
            }
        }
        _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
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
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if c.le {
                    /* OpenSSL limitations */
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                params = params.add_int(
                    name_as_char(OSSL_KDF_PARAM_KBKDF_R),
                    c.bits as c_int,
                )?;
            }
            Sp800Params::ByteArray(v) => {
                /* unconditionally set counter to true as once we get
                 * a byte array, counter can't be set anymore for
                 * OpenSSL */
                counter = true;
                if context {
                    /* already set, bail out */
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if separator {
                    /* separator set, this is a Context */
                    params = params.add_octet_string(
                        name_as_char(OSSL_KDF_PARAM_INFO),
                        &v,
                    )?;
                    context = true;
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        params = params.add_int(
                            name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L),
                            1,
                        )?;
                        separator = true;
                    } else {
                        if label {
                            /* label set and no separator, this is a Context */
                            params = params.add_octet_string(
                                name_as_char(OSSL_KDF_PARAM_INFO),
                                &v,
                            )?;
                            context = true;
                        } else {
                            params = params.add_octet_string(
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
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                if v.le
                    || v.bits != 32
                    || v.method != CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
                {
                    /* OpenSSL limitations */
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                params = params
                    .add_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L), 1)?;
                dkmlen = true;

                /* DKM Length is always last in OpenSSL, so also mark
                 * context and counter as true regardless as no more
                 * Counter or Byte Arrays are allowed for OpenSSL */
                counter = true;
                context = true;
            }
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        }
    }
    if !separator {
        params = params
            .add_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR), 0)?
    }
    if !dkmlen {
        params = params.add_int(name_as_char(OSSL_KDF_PARAM_KBKDF_USE_L), 0)?
    }
    Ok(params.finalize())
}

fn get_segment_size(
    mechanisms: &Mechanisms,
    hmac: CK_MECHANISM_TYPE,
) -> KResult<usize> {
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
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
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

impl Derive for Sp800Operation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
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
                    _ => return err_rv!(CKR_KEY_INDIGESTIBLE),
                },
            ),
            _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
        };

        let mut params = OsslParam::with_capacity(10)
            .set_zeroize()
            .add_const_c_string(
                name_as_char(OSSL_KDF_PARAM_MAC),
                mac_type_name,
            )?
            .add_const_c_string(prf_alg_param, prf_alg_value)?
            .add_octet_string(
                name_as_char(OSSL_KDF_PARAM_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?;

        match self.mech {
            CKM_SP800_108_COUNTER_KDF => {
                params = params.add_const_c_string(
                    name_as_char(OSSL_KDF_PARAM_MODE),
                    name_as_char(SP800_MODE_COUNTER),
                )?;
                params = prep_counter_kdf(&self.params, params)?;
            }
            CKM_SP800_108_FEEDBACK_KDF => {
                params = params.add_const_c_string(
                    name_as_char(OSSL_KDF_PARAM_MODE),
                    name_as_char(SP800_MODE_FEEDBACK),
                )?;
                if self.iv.len() > 0 {
                    params = params.add_octet_string(
                        name_as_char(OSSL_KDF_PARAM_SEED),
                        &self.iv,
                    )?;
                }
                params = prep_feedback_kdf(&self.params, params)?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
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

        let mut obj = objfactories.derive_key_from_template(key, template)?;
        let keysize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(n) => n as usize,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        if keysize == 0 || keysize > (u32::MAX as usize) {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        let mut slen = key_to_segment_size(keysize, segment);

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
            /* increment size in segment steps */
            slen += key_to_segment_size(aksize, segment);
            self.addl_objects.push(obj);
        }

        let mut kdf = match EvpKdf::from_ptr(unsafe {
            EVP_KDF_fetch(
                get_libctx(),
                name_as_char(OSSL_KDF_NAME_KBKDF),
                std::ptr::null(),
            )
        }) {
            Ok(ek) => ek,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        let mut kctx = match EvpKdfCtx::from_ptr(unsafe {
            EVP_KDF_CTX_new(kdf.as_mut_ptr())
        }) {
            Ok(ekc) => ekc,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };

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
            return err_rv!(CKR_DEVICE_ERROR);
        }

        obj.set_attr(from_bytes(CKA_VALUE, dkm[0..keysize].to_vec()))?;

        let mut cursor = key_to_segment_size(keysize, segment);
        for key in &mut self.addl_objects {
            let aksize = key.get_attr_as_ulong(CKA_VALUE_LEN)? as usize;
            key.set_attr(from_bytes(
                CKA_VALUE,
                dkm[cursor..(cursor + aksize)].to_vec(),
            ))?;
            cursor += key_to_segment_size(aksize, segment);
        }

        Ok((obj, self.addl_objects.len()))
    }

    fn derive_additional_key(
        &mut self,
    ) -> KResult<(Object, CK_OBJECT_HANDLE_PTR)> {
        self.pop_key()
    }
}

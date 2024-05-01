// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

fn key_to_segment_size(key: usize, segment: usize) -> usize {
    ((key + segment - 1) / segment) * segment
}

const MAX8: usize = u8::MAX as usize;
const MAX16: usize = u16::MAX as usize;
const MAX24: usize = MAX8 * MAX16;
const MAX32: usize = u32::MAX as usize;
const MAX40: usize = MAX8 * MAX32;
const MAX48: usize = MAX16 * MAX32;
const MAX56: usize = MAX8 * MAX16 * MAX32;
const MAX64: usize = u64::MAX as usize;

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
            if ctr > MAX8 {
                return err_rv!(CKR_MECHANISM_PARAM_INVALID);
            }
            op.mac_update(&[ctr as u8])
        }
        16 => {
            if ctr > MAX16 {
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
            if ctr > MAX24 {
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
            if ctr > MAX32 {
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
            len = len % MAX8;
            op.mac_update(&[len as u8])
        }
        16 => {
            len = len % MAX16;
            let data = if param.le {
                (len as u16).to_le_bytes()
            } else {
                (len as u16).to_be_bytes()
            };
            op.mac_update(&data)
        }
        24 => {
            len = len % MAX24;
            let (data, s, e) = if param.le {
                ((len as u32).to_le_bytes(), 0, 3)
            } else {
                ((len as u32).to_be_bytes(), 1, 4)
            };
            op.mac_update(&data[s..e])
        }
        32 => {
            len = len % MAX32;
            let data = if param.le {
                (len as u32).to_le_bytes()
            } else {
                (len as u32).to_be_bytes()
            };
            op.mac_update(&data)
        }
        40 => {
            len = len % MAX40;
            let (data, s, e) = if param.le {
                ((len as u32).to_le_bytes(), 0, 5)
            } else {
                ((len as u32).to_be_bytes(), 3, 8)
            };
            op.mac_update(&data[s..e])
        }
        48 => {
            len = len % MAX48;
            let (data, s, e) = if param.le {
                ((len as u32).to_le_bytes(), 0, 6)
            } else {
                ((len as u32).to_be_bytes(), 2, 8)
            };
            op.mac_update(&data[s..e])
        }
        56 => {
            len = len % MAX56;
            let (data, s, e) = if param.le {
                ((len as u32).to_le_bytes(), 0, 7)
            } else {
                ((len as u32).to_be_bytes(), 1, 8)
            };
            op.mac_update(&data[s..e])
        }
        64 => {
            len = len % MAX64;
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
                ctr_update(param, ctr, op)?;
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
                dkm_update(param, dkmklen, dkmslen, op)?;
            }
        }
    }

    if !seen_iter {
        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
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
                ctr_update(param, ctr, op)?;
            }
            Sp800Params::ByteArray(param) => {
                op.mac_update(param.as_slice())?;
            }
            Sp800Params::DKMLength(param) => {
                if seen_dkmlen {
                    return err_rv!(CKR_MECHANISM_PARAM_INVALID);
                }
                seen_dkmlen = true;
                dkm_update(param, dkmklen, dkmslen, op)?;
            }
        }
    }

    if !seen_iter {
        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
    }

    Ok(())
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

        let mut obj = objfactories.derive_key_from_template(key, template)?;
        let keysize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(n) => n as usize,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        if keysize == 0 || keysize > (u32::MAX as usize) {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        let mut klen = keysize;
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
            klen += aksize;
            slen += key_to_segment_size(aksize, segment);
            self.addl_objects.push(obj);
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
                    counter_updates(
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
                    feedback_updates(
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

        /* main key first */
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

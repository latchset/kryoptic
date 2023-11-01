// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::cryptography;
use super::err_rv;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use super::token;
use cryptography::*;
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{Object, ObjectTemplates};
use std::fmt::Debug;
use token::RNG;
use zeroize::Zeroize;

fn check_and_fetch_key(key: &Object, keytype: CK_KEY_TYPE) -> KResult<Vec<u8>> {
    if key.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
        return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
    }
    let t = key.get_attr_as_ulong(CKA_KEY_TYPE)?;
    if t != CKK_GENERIC_SECRET && t != keytype {
        return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
    }

    Ok(key.get_attr_as_bytes(CKA_VALUE)?.clone())
}

fn check_and_fetch_param(
    mech: &CK_MECHANISM,
    min: usize,
    max: usize,
) -> KResult<usize> {
    if min == max {
        if mech.ulParameterLen != 0 {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        return Ok(max);
    }
    if mech.ulParameterLen != std::mem::size_of::<CK_ULONG>() as CK_ULONG {
        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
    }
    let genlen = unsafe {
        let val: &[CK_ULONG] =
            std::slice::from_raw_parts(mech.pParameter as *const _, 1);
        val[0] as usize
    };
    if genlen < min || genlen > max {
        return err_rv!(CKR_MECHANISM_PARAM_INVALID);
    }
    Ok(genlen)
}

#[derive(Debug)]
struct HMACMechanism {
    info: CK_MECHANISM_INFO,
    keytype: CK_KEY_TYPE,
    minlen: usize,
    maxlen: usize,
}

impl Mechanism for HMACMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        let output_len = check_and_fetch_param(mech, self.minlen, self.maxlen)?;
        let key = check_and_fetch_key(keyobj, self.keytype)?;
        match mech.mechanism {
            CKM_SHA_1_HMAC | CKM_SHA_1_HMAC_GENERAL => Ok(Box::new(
                SHA1HMACOperation::sign_new(mech.mechanism, key, output_len),
            )),
            CKM_SHA256_HMAC | CKM_SHA256_HMAC_GENERAL => Ok(Box::new(
                SHA256HMACOperation::sign_new(mech.mechanism, key, output_len),
            )),
            CKM_SHA384_HMAC | CKM_SHA384_HMAC_GENERAL => Ok(Box::new(
                SHA384HMACOperation::sign_new(mech.mechanism, key, output_len),
            )),
            CKM_SHA512_HMAC | CKM_SHA512_HMAC_GENERAL => Ok(Box::new(
                SHA512HMACOperation::sign_new(mech.mechanism, key, output_len),
            )),
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> KResult<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        let output_len = check_and_fetch_param(mech, self.minlen, self.maxlen)?;
        let key = check_and_fetch_key(keyobj, self.keytype)?;
        match mech.mechanism {
            CKM_SHA_1_HMAC | CKM_SHA_1_HMAC_GENERAL => Ok(Box::new(
                SHA1HMACOperation::verify_new(mech.mechanism, key, output_len),
            )),
            CKM_SHA256_HMAC | CKM_SHA256_HMAC_GENERAL => {
                Ok(Box::new(SHA256HMACOperation::verify_new(
                    mech.mechanism,
                    key,
                    output_len,
                )))
            }
            CKM_SHA384_HMAC | CKM_SHA384_HMAC_GENERAL => {
                Ok(Box::new(SHA384HMACOperation::verify_new(
                    mech.mechanism,
                    key,
                    output_len,
                )))
            }
            CKM_SHA512_HMAC | CKM_SHA512_HMAC_GENERAL => {
                Ok(Box::new(SHA512HMACOperation::verify_new(
                    mech.mechanism,
                    key,
                    output_len,
                )))
            }
            _ => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

pub fn register(mechs: &mut Mechanisms, _ot: &mut ObjectTemplates) {
    mechs.add_mechanism(
        CKM_SHA_1_HMAC_GENERAL,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA_1_HMAC,
            minlen: 1,
            maxlen: 20,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA_1_HMAC,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA_1_HMAC,
            minlen: 20,
            maxlen: 20,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA256_HMAC_GENERAL,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA256_HMAC,
            minlen: 1,
            maxlen: 32,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA256_HMAC,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA256_HMAC,
            minlen: 32,
            maxlen: 32,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA384_HMAC_GENERAL,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA384_HMAC,
            minlen: 1,
            maxlen: 48,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA384_HMAC,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA384_HMAC,
            minlen: 48,
            maxlen: 48,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA512_HMAC_GENERAL,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA512_HMAC,
            minlen: 1,
            maxlen: 64,
        }),
    );
    mechs.add_mechanism(
        CKM_SHA512_HMAC,
        Box::new(HMACMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_SIGN | CKF_VERIFY,
            },
            keytype: CKK_SHA512_HMAC,
            minlen: 64,
            maxlen: 64,
        }),
    );
}

#[derive(Debug)]
struct SHA1HMACOperation {
    mech: CK_MECHANISM_TYPE,
    key: Vec<u8>,
    output_len: usize,
    finalized: bool,
    in_use: bool,
}

impl Drop for SHA1HMACOperation {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SHA1HMACOperation {
    fn sign_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA1HMACOperation {
        SHA1HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
    fn verify_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA1HMACOperation {
        SHA1HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
}

impl MechOperation for SHA1HMACOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for SHA1HMACOperation {
    fn sign(
        &mut self,
        _rng: &mut RNG,
        data: &[u8],
        signature: &mut [u8],
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if self.output_len == 20 {
            unsafe {
                Hacl_HMAC_legacy_compute_sha1(
                    signature.as_ptr() as *mut u8,
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
        } else {
            let mut vec: Vec<u8> = vec![0; 20];
            unsafe {
                Hacl_HMAC_legacy_compute_sha1(
                    vec.as_mut_ptr(),
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
            signature.copy_from_slice(&vec[..self.output_len]);
        }
        Ok(())
    }

    fn sign_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn sign_final(
        &mut self,
        _rng: &mut RNG,
        _signature: &mut [u8],
    ) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for SHA1HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut vec: Vec<u8> = vec![0; 20];
        unsafe {
            Hacl_HMAC_legacy_compute_sha1(
                vec.as_mut_ptr(),
                self.key.as_mut_ptr(),
                self.key.len() as u32,
                data.as_ptr() as *mut u8,
                data.len() as u32,
            );
        }
        vec.resize(self.output_len, 0);
        if vec != signature {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn verify_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn verify_final(&mut self, _signature: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

#[derive(Debug)]
struct SHA256HMACOperation {
    mech: CK_MECHANISM_TYPE,
    key: Vec<u8>,
    output_len: usize,
    finalized: bool,
    in_use: bool,
}

impl Drop for SHA256HMACOperation {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SHA256HMACOperation {
    fn sign_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA256HMACOperation {
        SHA256HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
    fn verify_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA256HMACOperation {
        SHA256HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
}

impl MechOperation for SHA256HMACOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for SHA256HMACOperation {
    fn sign(
        &mut self,
        _rng: &mut RNG,
        data: &[u8],
        signature: &mut [u8],
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if self.output_len == 32 {
            unsafe {
                Hacl_HMAC_compute_sha2_256(
                    signature.as_ptr() as *mut u8,
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
        } else {
            let mut vec: Vec<u8> = vec![0; 32];
            unsafe {
                Hacl_HMAC_compute_sha2_256(
                    vec.as_mut_ptr(),
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
            signature.copy_from_slice(&vec[..self.output_len]);
        }
        Ok(())
    }

    fn sign_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn sign_final(
        &mut self,
        _rng: &mut RNG,
        _signature: &mut [u8],
    ) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for SHA256HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut vec: Vec<u8> = vec![0; 32];
        unsafe {
            Hacl_HMAC_compute_sha2_256(
                vec.as_mut_ptr(),
                self.key.as_mut_ptr(),
                self.key.len() as u32,
                data.as_ptr() as *mut u8,
                data.len() as u32,
            );
        }
        vec.resize(self.output_len, 0);
        if vec != signature {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn verify_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn verify_final(&mut self, _signature: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

#[derive(Debug)]
struct SHA384HMACOperation {
    mech: CK_MECHANISM_TYPE,
    key: Vec<u8>,
    output_len: usize,
    finalized: bool,
    in_use: bool,
}

impl Drop for SHA384HMACOperation {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SHA384HMACOperation {
    fn sign_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA384HMACOperation {
        SHA384HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
    fn verify_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA384HMACOperation {
        SHA384HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
}

impl MechOperation for SHA384HMACOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for SHA384HMACOperation {
    fn sign(
        &mut self,
        _rng: &mut RNG,
        data: &[u8],
        signature: &mut [u8],
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if self.output_len == 48 {
            unsafe {
                Hacl_HMAC_compute_sha2_384(
                    signature.as_ptr() as *mut u8,
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
        } else {
            let mut vec: Vec<u8> = vec![0; 48];
            unsafe {
                Hacl_HMAC_compute_sha2_384(
                    vec.as_mut_ptr(),
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
            signature.copy_from_slice(&vec[..self.output_len]);
        }
        Ok(())
    }

    fn sign_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn sign_final(
        &mut self,
        _rng: &mut RNG,
        _signature: &mut [u8],
    ) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for SHA384HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut vec: Vec<u8> = vec![0; 48];
        unsafe {
            Hacl_HMAC_compute_sha2_384(
                vec.as_mut_ptr(),
                self.key.as_mut_ptr(),
                self.key.len() as u32,
                data.as_ptr() as *mut u8,
                data.len() as u32,
            );
        }
        vec.resize(self.output_len, 0);
        if vec != signature {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn verify_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn verify_final(&mut self, _signature: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

#[derive(Debug)]
struct SHA512HMACOperation {
    mech: CK_MECHANISM_TYPE,
    key: Vec<u8>,
    output_len: usize,
    finalized: bool,
    in_use: bool,
}

impl Drop for SHA512HMACOperation {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SHA512HMACOperation {
    fn sign_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA512HMACOperation {
        SHA512HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
    fn verify_new(
        mech: CK_MECHANISM_TYPE,
        key: Vec<u8>,
        outlen: usize,
    ) -> SHA512HMACOperation {
        SHA512HMACOperation {
            mech: mech,
            key: key,
            output_len: outlen,
            finalized: false,
            in_use: false,
        }
    }
}

impl MechOperation for SHA512HMACOperation {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
    fn in_use(&self) -> bool {
        self.in_use
    }
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Sign for SHA512HMACOperation {
    fn sign(
        &mut self,
        _rng: &mut RNG,
        data: &[u8],
        signature: &mut [u8],
    ) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        if self.output_len == 64 {
            unsafe {
                Hacl_HMAC_compute_sha2_512(
                    signature.as_ptr() as *mut u8,
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
        } else {
            let mut vec: Vec<u8> = vec![0; 64];
            unsafe {
                Hacl_HMAC_compute_sha2_512(
                    vec.as_mut_ptr(),
                    self.key.as_mut_ptr(),
                    self.key.len() as u32,
                    data.as_ptr() as *mut u8,
                    data.len() as u32,
                );
            }
            signature.copy_from_slice(&vec[..self.output_len]);
        }
        Ok(())
    }

    fn sign_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn sign_final(
        &mut self,
        _rng: &mut RNG,
        _signature: &mut [u8],
    ) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

impl Verify for SHA512HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> KResult<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;
        if signature.len() != self.output_len {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut vec: Vec<u8> = vec![0; 64];
        unsafe {
            Hacl_HMAC_compute_sha2_512(
                vec.as_mut_ptr(),
                self.key.as_mut_ptr(),
                self.key.len() as u32,
                data.as_ptr() as *mut u8,
                data.len() as u32,
            );
        }
        vec.resize(self.output_len, 0);
        if vec != signature {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn verify_update(&mut self, _data: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn verify_final(&mut self, _signature: &[u8]) -> KResult<()> {
        /* Hacl does not support streaming for HMAC yet */
        return err_rv!(CKR_GENERAL_ERROR);
    }

    fn signature_len(&self) -> KResult<usize> {
        Ok(self.output_len)
    }
}

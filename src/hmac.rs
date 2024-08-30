// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::error;
use super::hash;
use super::interface;
use super::mechanism;
use super::object;
use super::{err_rv, sizeof};

use error::{Error, Result};
use interface::*;
use mechanism::*;
use object::{GenericSecretKeyFactory, Object, ObjectFactory};

use std::fmt::Debug;

use once_cell::sync::Lazy;

use constant_time_eq::constant_time_eq;
use zeroize::Zeroize;

#[derive(Debug)]
struct HmacKey {
    raw: Vec<u8>,
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        self.raw.zeroize()
    }
}

pub fn hmac_size(mech: CK_MECHANISM_TYPE) -> usize {
    for hs in &hash::HASH_MECH_SET {
        if hs.hash == mech || hs.mac == mech || hs.mac_general == mech {
            return hs.hash_size;
        }
    }
    hash::INVALID_HASH_SIZE
}

pub fn hmac_mech_to_hash_mech(
    mech: CK_MECHANISM_TYPE,
) -> Result<CK_MECHANISM_TYPE> {
    Ok(match mech {
        CKM_SHA_1_HMAC | CKM_SHA_1_HMAC_GENERAL => CKM_SHA_1,
        CKM_SHA224_HMAC | CKM_SHA224_HMAC_GENERAL => CKM_SHA224,
        CKM_SHA256_HMAC | CKM_SHA256_HMAC_GENERAL => CKM_SHA256,
        CKM_SHA384_HMAC | CKM_SHA384_HMAC_GENERAL => CKM_SHA384,
        CKM_SHA512_HMAC | CKM_SHA512_HMAC_GENERAL => CKM_SHA512,
        CKM_SHA3_224_HMAC | CKM_SHA3_224_HMAC_GENERAL => CKM_SHA3_224,
        CKM_SHA3_256_HMAC | CKM_SHA3_256_HMAC_GENERAL => CKM_SHA3_256,
        CKM_SHA3_384_HMAC | CKM_SHA3_384_HMAC_GENERAL => CKM_SHA3_384,
        CKM_SHA3_512_HMAC | CKM_SHA3_512_HMAC_GENERAL => CKM_SHA3_512,
        _ => return err_rv!(CKR_MECHANISM_INVALID),
    })
}

pub fn hash_to_hmac_mech(mech: CK_MECHANISM_TYPE) -> Result<CK_MECHANISM_TYPE> {
    Ok(match mech {
        CKM_SHA_1 => CKM_SHA_1_HMAC,
        CKM_SHA224 => CKM_SHA224_HMAC,
        CKM_SHA256 => CKM_SHA256_HMAC,
        CKM_SHA384 => CKM_SHA384_HMAC,
        CKM_SHA512 => CKM_SHA512_HMAC,
        CKM_SHA3_224 => CKM_SHA3_224_HMAC,
        CKM_SHA3_256 => CKM_SHA3_256_HMAC,
        CKM_SHA3_384 => CKM_SHA3_384_HMAC,
        CKM_SHA3_512 => CKM_SHA3_512_HMAC,
        _ => return err_rv!(CKR_MECHANISM_INVALID),
    })
}

#[derive(Debug)]
struct HMACMechanism {
    info: CK_MECHANISM_INFO,
    keytype: CK_KEY_TYPE,
    minlen: usize,
    maxlen: usize,
}

impl HMACMechanism {
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        for hs in &hash::HASH_MECH_SET {
            mechs.add_mechanism(
                hs.mac,
                Box::new(HMACMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_SIGN | CKF_VERIFY,
                    },
                    keytype: hs.key_type,
                    minlen: hs.hash_size,
                    maxlen: hs.hash_size,
                }),
            );
            mechs.add_mechanism(
                hs.mac_general,
                Box::new(HMACMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_SIGN | CKF_VERIFY,
                    },
                    keytype: hs.key_type,
                    minlen: 1,
                    maxlen: hs.hash_size,
                }),
            );
        }
    }

    fn check_and_fetch_key(
        &self,
        key: &Object,
        op: CK_ATTRIBUTE_TYPE,
    ) -> Result<HmacKey> {
        if key.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
        }
        let t = key.get_attr_as_ulong(CKA_KEY_TYPE)?;
        if t != CKK_GENERIC_SECRET && t != self.keytype {
            return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
        }
        if !key.get_attr_as_bool(op).or::<Error>(Ok(false))? {
            return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
        }
        Ok(HmacKey {
            raw: key.get_attr_as_bytes(CKA_VALUE)?.clone(),
        })
    }

    fn check_and_fetch_param(&self, mech: &CK_MECHANISM) -> Result<usize> {
        if self.minlen == self.maxlen {
            if mech.ulParameterLen != 0 {
                return err_rv!(CKR_MECHANISM_PARAM_INVALID);
            }
            return Ok(self.maxlen);
        }
        if mech.ulParameterLen != sizeof!(CK_ULONG) {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        let genlen = usize::try_from(unsafe {
            std::slice::from_raw_parts(mech.pParameter as *const CK_ULONG, 1)[0]
        })?;
        if genlen < self.minlen || genlen > self.maxlen {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        Ok(genlen)
    }

    fn new_op(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
        op_type: CK_FLAGS,
    ) -> Result<HMACOperation> {
        /* the mechanism advertises only SIGN/VERIFY to the callers
         * DERIVE is a mediated operation so it is not advertised
         * and we do not check it */
        let op_attr = match op_type {
            CKF_SIGN => {
                if self.info.flags & CKF_SIGN != CKF_SIGN {
                    return err_rv!(CKR_MECHANISM_INVALID);
                }
                CKA_SIGN
            }
            CKF_VERIFY => {
                if self.info.flags & CKF_SIGN != CKF_SIGN {
                    return err_rv!(CKR_MECHANISM_INVALID);
                }
                CKA_VERIFY
            }
            CKF_DERIVE => CKA_DERIVE,
            _ => return err_rv!(CKR_MECHANISM_INVALID),
        };
        HMACOperation::new(
            hmac_mech_to_hash_mech(mech.mechanism)?,
            self.check_and_fetch_key(keyobj, op_attr)?,
            self.check_and_fetch_param(mech)?,
        )
    }
}

impl Mechanism for HMACMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn mac_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
        op_type: CK_FLAGS,
    ) -> Result<Box<dyn Mac>> {
        Ok(Box::new(self.new_op(mech, keyobj, op_type)?))
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> Result<Box<dyn Sign>> {
        Ok(Box::new(self.new_op(mech, keyobj, CKF_SIGN)?))
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> Result<Box<dyn Verify>> {
        Ok(Box::new(self.new_op(mech, keyobj, CKF_VERIFY)?))
    }
}

#[cfg(not(feature = "fips"))]
#[derive(Debug)]
struct HMACOperation {
    key: HmacKey,
    hash: CK_MECHANISM_TYPE,
    hashlen: usize,
    blocklen: usize,
    outputlen: usize,
    state: Vec<u8>,
    ipad: Vec<u8>,
    opad: Vec<u8>,
    inner: Operation,
    finalized: bool,
    in_use: bool,
}

#[cfg(not(feature = "fips"))]
impl Drop for HMACOperation {
    fn drop(&mut self) {
        self.state.zeroize();
        self.ipad.zeroize();
        self.opad.zeroize();
    }
}

/* HMAC spec From FIPS 198-1 */
#[cfg(not(feature = "fips"))]
impl HMACOperation {
    fn new(
        hash: CK_MECHANISM_TYPE,
        key: HmacKey,
        outputlen: usize,
    ) -> Result<HMACOperation> {
        let mut hmac = HMACOperation {
            key: key,
            hash: hash,
            hashlen: 0usize,
            blocklen: 0usize,
            outputlen: outputlen,
            state: Vec::new(),
            ipad: Vec::new(),
            opad: Vec::new(),
            inner: Operation::Empty,
            finalized: false,
            in_use: false,
        };
        hmac.init()?;
        Ok(hmac)
    }

    fn init(&mut self) -> Result<()> {
        /* The hash mechanism is unimportant here,
         * what matters is the psecdef algorithm */
        let hashop = hash::internal_hash_op(self.hash)?;
        self.hashlen = hash::hash_size(self.hash);
        self.blocklen = hash::block_size(self.hash);
        self.inner = Operation::Digest(hashop);

        /* K0 */
        if self.key.raw.len() <= self.blocklen {
            self.state.extend_from_slice(self.key.raw.as_slice());
        } else {
            self.state.resize(self.hashlen, 0);
            match &mut self.inner {
                Operation::Digest(op) => op.digest(
                    self.key.raw.as_slice(),
                    self.state.as_mut_slice(),
                )?,
                _ => return err_rv!(CKR_GENERAL_ERROR),
            }
        }
        self.state.resize(self.blocklen, 0);
        /* K0 ^ ipad */
        self.ipad.resize(self.blocklen, 0x36);
        self.ipad
            .iter_mut()
            .zip(self.state.iter())
            .for_each(|(i1, i2)| *i1 ^= *i2);
        /* K0 ^ opad */
        self.opad.resize(self.blocklen, 0x5c);
        self.opad
            .iter_mut()
            .zip(self.state.iter())
            .for_each(|(i1, i2)| *i1 ^= *i2);
        /* H((K0 ^ ipad) || .. ) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.reset()?;
                op.digest_update(self.ipad.as_slice())?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<()> {
        if self.in_use {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.in_use = true;

        /* H( .. || text ..) */
        let ret = match &mut self.inner {
            Operation::Digest(op) => op.digest_update(data),
            _ => err_rv!(CKR_GENERAL_ERROR),
        };
        if ret.is_err() {
            self.finalized = true;
        }
        ret
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        /* It is valid to finalize without any update */
        self.in_use = true;
        self.finalized = true;

        if output.len() != self.outputlen {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        self.state.resize(self.hashlen, 0);
        /* state = H((K0 ^ ipad) || text) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.digest_final(self.state.as_mut_slice())?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        /* state = H((K0 ^ opad) || H((K0 ^ ipad) || text)) */
        match &mut self.inner {
            Operation::Digest(op) => {
                op.reset()?;
                op.digest_update(self.opad.as_slice())?;
                op.digest_update(self.state.as_slice())?;
                op.digest_final(self.state.as_mut_slice())?;
            }
            _ => return err_rv!(CKR_GENERAL_ERROR),
        }
        /* state -> output */
        output.copy_from_slice(&self.state[..output.len()]);
        Ok(())
    }

    fn reinit(&mut self) -> Result<()> {
        self.hashlen = 0;
        self.blocklen = 0;
        self.state = Vec::new();
        self.ipad = Vec::new();
        self.opad = Vec::new();
        self.inner = Operation::Empty;
        self.finalized = false;
        self.in_use = false;
        self.init()
    }
}

#[cfg(feature = "fips")]
include!("ossl/hmac.rs");

impl MechOperation for HMACOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
    fn reset(&mut self) -> Result<()> {
        self.reinit()
    }
}

impl Mac for HMACOperation {
    fn mac(&mut self, data: &[u8], mac: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(mac)
    }

    fn mac_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn mac_final(&mut self, mac: &mut [u8]) -> Result<()> {
        self.finalize(mac)
    }

    fn mac_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

impl Sign for HMACOperation {
    fn sign(&mut self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.finalize(signature)
    }

    fn sign_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn sign_final(&mut self, signature: &mut [u8]) -> Result<()> {
        self.finalize(signature)
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

impl Verify for HMACOperation {
    fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.begin()?;
        self.update(data)?;
        self.verify_final(signature)
    }

    fn verify_update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn verify_final(&mut self, signature: &[u8]) -> Result<()> {
        let mut verify: Vec<u8> = vec![0; self.outputlen];
        self.finalize(verify.as_mut_slice())?;
        if !constant_time_eq(&verify, signature) {
            return err_rv!(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    }

    fn signature_len(&self) -> Result<usize> {
        Ok(self.outputlen)
    }
}

static HMAC_SECRET_KEY_FACTORIES: Lazy<
    Vec<(CK_KEY_TYPE, Box<dyn ObjectFactory>)>,
> = Lazy::new(|| {
    let mut v = Vec::<(CK_KEY_TYPE, Box<dyn ObjectFactory>)>::with_capacity(
        hash::HASH_MECH_SET.len(),
    );
    for hs in &hash::HASH_MECH_SET {
        v.push((
            hs.key_type,
            Box::new(GenericSecretKeyFactory::with_key_size(hs.hash_size)),
        ));
    }
    v
});

pub fn register_mechs_only(mechs: &mut Mechanisms) {
    HMACMechanism::register_mechanisms(mechs);
}

pub fn register(mechs: &mut Mechanisms, ot: &mut object::ObjectFactories) {
    HMACMechanism::register_mechanisms(mechs);

    /* Key Operations */
    for hs in &hash::HASH_MECH_SET {
        mechs.add_mechanism(
            hs.key_gen,
            Box::new(object::GenericSecretKeyMechanism::new(hs.key_type)),
        );
    }
    for f in Lazy::force(&HMAC_SECRET_KEY_FACTORIES) {
        ot.add_factory(object::ObjectType::new(CKO_SECRET_KEY, f.0), &f.1);
    }
}

#[cfg(test)]
pub fn test_get_hmac(mech: CK_MECHANISM_TYPE) -> Box<dyn Mechanism> {
    for hs in &hash::HASH_MECH_SET {
        if hs.mac == mech {
            return Box::new(HMACMechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: 0,
                    flags: CKF_SIGN | CKF_VERIFY,
                },
                keytype: hs.key_type,
                minlen: hs.hash_size,
                maxlen: hs.hash_size,
            });
        }
    }
    panic!("Invalid mech {}", mech);
}

// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::err_rv;
use super::error;
use super::interface;
use super::mechanism;
use super::object;

use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{GenericSecretKeyFactory, Object, ObjectFactories, ObjectFactory};

use std::fmt::Debug;

use once_cell::sync::Lazy;

pub const INVALID_HASH_SIZE: usize = CK_UNAVAILABLE_INFORMATION as usize;

#[derive(Debug)]
struct HashBasedOp {
    hash: CK_MECHANISM_TYPE,
    key_type: CK_KEY_TYPE,
    key_gen: CK_MECHANISM_TYPE,
    key_derive: CK_MECHANISM_TYPE,
    mac: CK_MECHANISM_TYPE,
    mac_general: CK_MECHANISM_TYPE,
    hash_size: usize,
}

static HASH_MECH_SET: [HashBasedOp; 9] = [
    HashBasedOp {
        hash: CKM_SHA_1,
        key_type: CKK_SHA_1_HMAC,
        key_gen: CKM_SHA_1_KEY_GEN,
        key_derive: CKM_SHA1_KEY_DERIVATION,
        mac: CKM_SHA_1_HMAC,
        mac_general: CKM_SHA_1_HMAC_GENERAL,
        hash_size: 20,
    },
    HashBasedOp {
        hash: CKM_SHA224,
        key_type: CKK_SHA224_HMAC,
        key_gen: CKM_SHA224_KEY_GEN,
        key_derive: CKM_SHA224_KEY_DERIVATION,
        mac: CKM_SHA224_HMAC,
        mac_general: CKM_SHA224_HMAC_GENERAL,
        hash_size: 28,
    },
    HashBasedOp {
        hash: CKM_SHA256,
        key_type: CKK_SHA256_HMAC,
        key_gen: CKM_SHA256_KEY_GEN,
        key_derive: CKM_SHA256_KEY_DERIVATION,
        mac: CKM_SHA256_HMAC,
        mac_general: CKM_SHA256_HMAC_GENERAL,
        hash_size: 32,
    },
    HashBasedOp {
        hash: CKM_SHA384,
        key_type: CKK_SHA384_HMAC,
        key_gen: CKM_SHA384_KEY_GEN,
        key_derive: CKM_SHA384_KEY_DERIVATION,
        mac: CKM_SHA384_HMAC,
        mac_general: CKM_SHA384_HMAC_GENERAL,
        hash_size: 48,
    },
    HashBasedOp {
        hash: CKM_SHA512,
        key_type: CKK_SHA512_HMAC,
        key_gen: CKM_SHA512_KEY_GEN,
        key_derive: CKM_SHA512_KEY_DERIVATION,
        mac: CKM_SHA512_HMAC,
        mac_general: CKM_SHA512_HMAC_GENERAL,
        hash_size: 64,
    },
    HashBasedOp {
        hash: CKM_SHA3_224,
        key_type: CKK_SHA3_224_HMAC,
        key_gen: CKM_SHA3_224_KEY_GEN,
        key_derive: CKM_SHA3_224_KEY_DERIVATION,
        mac: CKM_SHA3_224_HMAC,
        mac_general: CKM_SHA3_224_HMAC_GENERAL,
        hash_size: 28,
    },
    HashBasedOp {
        hash: CKM_SHA3_256,
        key_type: CKK_SHA3_256_HMAC,
        key_gen: CKM_SHA3_256_KEY_GEN,
        key_derive: CKM_SHA3_256_KEY_DERIVATION,
        mac: CKM_SHA3_256_HMAC,
        mac_general: CKM_SHA3_256_HMAC_GENERAL,
        hash_size: 32,
    },
    HashBasedOp {
        hash: CKM_SHA3_384,
        key_type: CKK_SHA3_384_HMAC,
        key_gen: CKM_SHA3_384_KEY_GEN,
        key_derive: CKM_SHA3_384_KEY_DERIVATION,
        mac: CKM_SHA3_384_HMAC,
        mac_general: CKM_SHA3_384_HMAC_GENERAL,
        hash_size: 48,
    },
    HashBasedOp {
        hash: CKM_SHA3_512,
        key_type: CKK_SHA3_512_HMAC,
        key_gen: CKM_SHA3_512_KEY_GEN,
        key_derive: CKM_SHA3_512_KEY_DERIVATION,
        mac: CKM_SHA3_512_HMAC,
        mac_general: CKM_SHA3_512_HMAC_GENERAL,
        hash_size: 64,
    },
];

#[derive(Debug)]
struct HashKey {
    raw: Vec<u8>,
}

impl Drop for HashKey {
    fn drop(&mut self) {
        self.raw.zeroize()
    }
}

pub fn hash_size(hash: CK_MECHANISM_TYPE) -> usize {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return hs.hash_size;
        }
    }
    INVALID_HASH_SIZE
}

pub fn hmac_size(hmac: CK_MECHANISM_TYPE) -> usize {
    for hs in &HASH_MECH_SET {
        if hs.mac == hmac || hs.mac_general == hmac {
            return hs.hash_size;
        }
    }
    INVALID_HASH_SIZE
}

#[derive(Debug)]
struct HashMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HashMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn digest_new(&self, mech: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        Ok(Box::new(HashOperation::new(mech.mechanism)?))
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> KResult<Operation> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return err_rv!(CKR_MECHANISM_INVALID);
        }

        for hs in &HASH_MECH_SET {
            if hs.key_derive == mech.mechanism {
                return Ok(Operation::Derive(Box::new(HashKDFOperation::new(
                    hs.hash,
                )?)));
            }
        }

        err_rv!(CKR_MECHANISM_INVALID)
    }
}

#[derive(Debug)]
pub struct HashOperation {
    state: HashState,
    finalized: bool,
    in_use: bool,
}

#[derive(Debug)]
struct HashKDFOperation {
    prf: CK_MECHANISM_TYPE,
    finalized: bool,
}

impl HashKDFOperation {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for hs in &HASH_MECH_SET {
            if mechs.get(hs.hash).is_err() {
                continue;
            }
            mechs.add_mechanism(
                hs.key_derive,
                Box::new(HashMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_DERIVE,
                    },
                }),
            );
        }
    }

    fn new(prf: CK_MECHANISM_TYPE) -> KResult<HashKDFOperation> {
        Ok(HashKDFOperation {
            prf: prf,
            finalized: false,
        })
    }
}

impl MechOperation for HashKDFOperation {
    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for HashKDFOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        key.check_key_ops(
            CKO_SECRET_KEY,
            CK_UNAVAILABLE_INFORMATION,
            CKA_DERIVE,
        )?;

        let mut op = HashOperation::new(self.prf)?;
        let hashsize = op.hashlen();
        let mut keysize = hashsize as CK_ULONG;

        let gensec: CK_ULONG = CKK_GENERIC_SECRET;
        let mut templ_plus = Vec::<CK_ATTRIBUTE>::new();
        let mut tptr = template;
        if template.iter().find(|a| a.type_ == CKA_KEY_TYPE).is_none() {
            if templ_plus.len() == 0 {
                if templ_plus.try_reserve(template.len() + 1).is_err() {
                    return err_rv!(CKR_HOST_MEMORY);
                }
                templ_plus.extend_from_slice(template);
            }
            templ_plus.push(CK_ATTRIBUTE::from_ulong(CKA_KEY_TYPE, &gensec));
            tptr = templ_plus.as_slice()
        }

        let factory = objfactories.get_obj_factory_from_key_template(tptr)?;

        match template.iter().find(|a| a.type_ == CKA_VALUE_LEN) {
            Some(a) => {
                let size = a.to_ulong()?;
                if size > keysize {
                    return err_rv!(CKR_TEMPLATE_INCONSISTENT);
                }
                keysize = size;
            }
            None => {
                if templ_plus.len() == 0 {
                    if templ_plus.try_reserve(template.len() + 1).is_err() {
                        return err_rv!(CKR_HOST_MEMORY);
                    }
                    templ_plus.extend_from_slice(template);
                }

                keysize = factory
                    .as_secret_key_factory()?
                    .recommend_key_size(hashsize)?
                    as CK_ULONG;

                templ_plus
                    .push(CK_ATTRIBUTE::from_ulong(CKA_VALUE_LEN, &keysize));
                tptr = templ_plus.as_slice()
            }
        }

        let mut obj = factory.default_object_derive(tptr, key)?;

        let mut dkm = vec![0u8; hashsize];
        op.digest(
            key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
            dkm.as_mut_slice(),
        )?;

        factory
            .as_secret_key_factory()?
            .set_key(&mut obj, dkm[..(keysize as usize)].to_vec())?;

        Ok((obj, 0))
    }

    fn derive_additional_key(
        &mut self,
    ) -> KResult<(Object, CK_OBJECT_HANDLE_PTR)> {
        return err_rv!(CKR_GENERAL_ERROR);
    }
}

#[derive(Debug)]
struct HMACMechanism {
    info: CK_MECHANISM_INFO,
    keytype: CK_KEY_TYPE,
    minlen: usize,
    maxlen: usize,
}

impl HMACMechanism {
    fn hmac_mech_to_hash_mech(
        &self,
        hmac: CK_MECHANISM_TYPE,
    ) -> KResult<CK_MECHANISM_TYPE> {
        Ok(match hmac {
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

    fn check_and_fetch_key(
        &self,
        key: &Object,
        op: CK_ATTRIBUTE_TYPE,
    ) -> KResult<HashKey> {
        if key.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
        }
        let t = key.get_attr_as_ulong(CKA_KEY_TYPE)?;
        if t != CKK_GENERIC_SECRET && t != self.keytype {
            return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
        }
        if !key.get_attr_as_bool(op).or(Ok(false))? {
            return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
        }
        Ok(HashKey {
            raw: key.get_attr_as_bytes(CKA_VALUE)?.clone(),
        })
    }

    fn check_and_fetch_param(&self, mech: &CK_MECHANISM) -> KResult<usize> {
        if self.minlen == self.maxlen {
            if mech.ulParameterLen != 0 {
                return err_rv!(CKR_MECHANISM_PARAM_INVALID);
            }
            return Ok(self.maxlen);
        }
        if mech.ulParameterLen != std::mem::size_of::<CK_ULONG>() as CK_ULONG {
            return err_rv!(CKR_MECHANISM_PARAM_INVALID);
        }
        let genlen = unsafe {
            let val: &[CK_ULONG] =
                std::slice::from_raw_parts(mech.pParameter as *const _, 1);
            val[0] as usize
        };
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
    ) -> KResult<HMACOperation> {
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
        HMACOperation::init(
            self.hmac_mech_to_hash_mech(mech.mechanism)?,
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
    ) -> KResult<Box<dyn Mac>> {
        Ok(Box::new(self.new_op(mech, keyobj, op_type)?))
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> KResult<Box<dyn Sign>> {
        Ok(Box::new(self.new_op(mech, keyobj, CKF_SIGN)?))
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> KResult<Box<dyn Verify>> {
        Ok(Box::new(self.new_op(mech, keyobj, CKF_VERIFY)?))
    }
}

static HASH_SECRET_KEY_FACTORIES: Lazy<
    Vec<(CK_KEY_TYPE, Box<dyn ObjectFactory>)>,
> = Lazy::new(|| {
    let mut v = Vec::<(CK_KEY_TYPE, Box<dyn ObjectFactory>)>::with_capacity(
        HASH_MECH_SET.len(),
    );
    for hs in &HASH_MECH_SET {
        /* ensure hash exists or skip */
        match HashOperation::new(hs.hash) {
            Ok(_) => (),
            Err(_) => continue,
        };
        v.push((
            hs.key_type,
            Box::new(GenericSecretKeyFactory::with_key_size(hs.hash_size)),
        ));
    }
    v
});

pub fn register(mechs: &mut Mechanisms, ot: &mut object::ObjectFactories) {
    HashOperation::register_mechanisms(mechs);
    HashKDFOperation::register_mechanisms(mechs);
    HMACOperation::register_mechanisms(mechs);

    /* Key Operations */
    for hs in &HASH_MECH_SET {
        mechs.add_mechanism(
            hs.key_gen,
            Box::new(object::GenericSecretKeyMechanism::new(hs.key_type)),
        );
    }
    for f in Lazy::force(&HASH_SECRET_KEY_FACTORIES) {
        ot.add_factory(object::ObjectType::new(CKO_SECRET_KEY, f.0), &f.1);
    }
}

include!("ossl/hash.rs");

#[cfg(not(feature = "fips"))]
include!("hmac.rs");

#[cfg(feature = "fips")]
include!("ossl/hmac.rs");

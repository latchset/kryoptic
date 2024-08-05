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
use object::{Object, ObjectFactories};

use std::fmt::Debug;

pub const INVALID_HASH_SIZE: usize = CK_UNAVAILABLE_INFORMATION as usize;

#[derive(Debug)]
pub struct HashBasedOp {
    pub hash: CK_MECHANISM_TYPE,
    pub key_type: CK_KEY_TYPE,
    pub key_gen: CK_MECHANISM_TYPE,
    pub key_derive: CK_MECHANISM_TYPE,
    pub mac: CK_MECHANISM_TYPE,
    pub mac_general: CK_MECHANISM_TYPE,
    pub hash_size: usize,
    pub block_size: usize,
}

pub static HASH_MECH_SET: [HashBasedOp; 9] = [
    HashBasedOp {
        hash: CKM_SHA_1,
        key_type: CKK_SHA_1_HMAC,
        key_gen: CKM_SHA_1_KEY_GEN,
        key_derive: CKM_SHA1_KEY_DERIVATION,
        mac: CKM_SHA_1_HMAC,
        mac_general: CKM_SHA_1_HMAC_GENERAL,
        hash_size: 20,
        block_size: 64,
    },
    HashBasedOp {
        hash: CKM_SHA224,
        key_type: CKK_SHA224_HMAC,
        key_gen: CKM_SHA224_KEY_GEN,
        key_derive: CKM_SHA224_KEY_DERIVATION,
        mac: CKM_SHA224_HMAC,
        mac_general: CKM_SHA224_HMAC_GENERAL,
        hash_size: 28,
        block_size: 64,
    },
    HashBasedOp {
        hash: CKM_SHA256,
        key_type: CKK_SHA256_HMAC,
        key_gen: CKM_SHA256_KEY_GEN,
        key_derive: CKM_SHA256_KEY_DERIVATION,
        mac: CKM_SHA256_HMAC,
        mac_general: CKM_SHA256_HMAC_GENERAL,
        hash_size: 32,
        block_size: 64,
    },
    HashBasedOp {
        hash: CKM_SHA384,
        key_type: CKK_SHA384_HMAC,
        key_gen: CKM_SHA384_KEY_GEN,
        key_derive: CKM_SHA384_KEY_DERIVATION,
        mac: CKM_SHA384_HMAC,
        mac_general: CKM_SHA384_HMAC_GENERAL,
        hash_size: 48,
        block_size: 128,
    },
    HashBasedOp {
        hash: CKM_SHA512,
        key_type: CKK_SHA512_HMAC,
        key_gen: CKM_SHA512_KEY_GEN,
        key_derive: CKM_SHA512_KEY_DERIVATION,
        mac: CKM_SHA512_HMAC,
        mac_general: CKM_SHA512_HMAC_GENERAL,
        hash_size: 64,
        block_size: 128,
    },
    HashBasedOp {
        hash: CKM_SHA3_224,
        key_type: CKK_SHA3_224_HMAC,
        key_gen: CKM_SHA3_224_KEY_GEN,
        key_derive: CKM_SHA3_224_KEY_DERIVATION,
        mac: CKM_SHA3_224_HMAC,
        mac_general: CKM_SHA3_224_HMAC_GENERAL,
        hash_size: 28,
        block_size: 144,
    },
    HashBasedOp {
        hash: CKM_SHA3_256,
        key_type: CKK_SHA3_256_HMAC,
        key_gen: CKM_SHA3_256_KEY_GEN,
        key_derive: CKM_SHA3_256_KEY_DERIVATION,
        mac: CKM_SHA3_256_HMAC,
        mac_general: CKM_SHA3_256_HMAC_GENERAL,
        hash_size: 32,
        block_size: 136,
    },
    HashBasedOp {
        hash: CKM_SHA3_384,
        key_type: CKK_SHA3_384_HMAC,
        key_gen: CKM_SHA3_384_KEY_GEN,
        key_derive: CKM_SHA3_384_KEY_DERIVATION,
        mac: CKM_SHA3_384_HMAC,
        mac_general: CKM_SHA3_384_HMAC_GENERAL,
        hash_size: 48,
        block_size: 104,
    },
    HashBasedOp {
        hash: CKM_SHA3_512,
        key_type: CKK_SHA3_512_HMAC,
        key_gen: CKM_SHA3_512_KEY_GEN,
        key_derive: CKM_SHA3_512_KEY_DERIVATION,
        mac: CKM_SHA3_512_HMAC,
        mac_general: CKM_SHA3_512_HMAC_GENERAL,
        hash_size: 64,
        block_size: 72,
    },
];

pub fn is_valid_hash(hash: CK_MECHANISM_TYPE) -> bool {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return true;
        }
    }
    return false;
}

pub fn hash_size(hash: CK_MECHANISM_TYPE) -> usize {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return hs.hash_size;
        }
    }
    INVALID_HASH_SIZE
}

#[cfg(not(feature = "fips"))]
pub fn block_size(hash: CK_MECHANISM_TYPE) -> usize {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return hs.block_size;
        }
    }
    INVALID_HASH_SIZE
}

#[derive(Debug)]
struct HashMechanism {
    info: CK_MECHANISM_INFO,
}

impl HashMechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        for hs in &HASH_MECH_SET {
            mechs.add_mechanism(
                hs.hash,
                Box::new(HashMechanism {
                    info: CK_MECHANISM_INFO {
                        ulMinKeySize: 0,
                        ulMaxKeySize: 0,
                        flags: CKF_DIGEST,
                    },
                }),
            );
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
struct HashOperation {
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
    ) -> KResult<Vec<Object>> {
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
        let hashsize = hash_size(self.prf);
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

        Ok(vec![obj])
    }
}

#[cfg(not(feature = "fips"))]
pub fn internal_hash_op(hash: CK_MECHANISM_TYPE) -> KResult<Box<dyn Digest>> {
    Ok(Box::new(HashOperation::new(hash)?))
}

pub fn register(mechs: &mut Mechanisms, _: &mut object::ObjectFactories) {
    HashMechanism::register_mechanisms(mechs);
}

include!("ossl/hash.rs");

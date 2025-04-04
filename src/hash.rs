// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::*;
use crate::object::{Object, ObjectFactories};
use crate::ossl::hash::HashOperation;

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
    /* not used in FIPS builds */
    #[allow(dead_code)]
    pub block_size: usize,
}

pub static HASH_MECH_SET: [HashBasedOp; 11] = [
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
    HashBasedOp {
        hash: CKM_SHA512_224,
        key_type: CKK_SHA512_224_HMAC,
        key_gen: CKM_SHA512_224_KEY_GEN,
        key_derive: CKM_SHA512_224_KEY_DERIVATION,
        mac: CKM_SHA512_224_HMAC,
        mac_general: CKM_SHA512_224_HMAC_GENERAL,
        hash_size: 28,
        block_size: 128,
    },
    HashBasedOp {
        hash: CKM_SHA512_256,
        key_type: CKK_SHA512_256_HMAC,
        key_gen: CKM_SHA512_256_KEY_GEN,
        key_derive: CKM_SHA512_256_KEY_DERIVATION,
        mac: CKM_SHA512_256_HMAC,
        mac_general: CKM_SHA512_256_HMAC_GENERAL,
        hash_size: 32,
        block_size: 128,
    },
];

#[cfg(feature = "sshkdf")]
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

    fn digest_new(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Digest>> {
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        Ok(Box::new(HashOperation::new(mech.mechanism)?))
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        for hs in &HASH_MECH_SET {
            if hs.key_derive == mech.mechanism {
                return Ok(Box::new(HashKDFOperation::new(
                    mech.mechanism,
                    hs.hash,
                )?));
            }
        }

        Err(CKR_MECHANISM_INVALID)?
    }
}

#[derive(Debug)]
struct HashKDFOperation {
    mech: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    finalized: bool,
}

impl HashKDFOperation {
    fn new(
        mech: CK_MECHANISM_TYPE,
        prf: CK_MECHANISM_TYPE,
    ) -> Result<HashKDFOperation> {
        Ok(HashKDFOperation {
            mech: mech,
            prf: prf,
            finalized: false,
        })
    }
}

impl MechOperation for HashKDFOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

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
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        key.check_key_ops(
            CKO_SECRET_KEY,
            CK_UNAVAILABLE_INFORMATION,
            CKA_DERIVE,
        )?;

        let mut op = HashOperation::new(self.prf)?;
        let hashsize = hash_size(self.prf);
        let mut keysize = CK_ULONG::try_from(hashsize)?;

        let mut tmpl = CkAttrs::from(template);
        if tmpl
            .as_slice()
            .iter()
            .find(|a| a.type_ == CKA_KEY_TYPE)
            .is_none()
        {
            tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)?;
        }
        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;

        match tmpl.as_slice().iter().find(|a| a.type_ == CKA_VALUE_LEN) {
            Some(a) => {
                let size = a.to_ulong()?;
                if size > keysize {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                keysize = size;
            }
            None => {
                keysize = CK_ULONG::try_from(
                    factory
                        .as_secret_key_factory()?
                        .recommend_key_size(hashsize)?,
                )?;

                tmpl.add_ulong(CKA_VALUE_LEN, &keysize);
            }
        }

        let mut obj = factory.default_object_derive(tmpl.as_slice(), key)?;

        let mut dkm = vec![0u8; hashsize];
        op.digest(
            key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
            dkm.as_mut_slice(),
        )?;

        factory
            .as_secret_key_factory()?
            .set_key(&mut obj, dkm[..(usize::try_from(keysize)?)].to_vec())?;

        Ok(vec![obj])
    }
}

#[cfg(not(feature = "fips"))]
pub fn internal_hash_op(hash: CK_MECHANISM_TYPE) -> Result<Box<dyn Digest>> {
    Ok(Box::new(HashOperation::new(hash)?))
}

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    HashMechanism::register_mechanisms(mechs);
}

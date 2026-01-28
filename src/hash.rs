// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms to access the Secure
//! Hash Algorithm Standards (SHA1, SHA2, SHA3) operations.

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::mechanism::*;
use crate::object::{Object, ObjectFactories};
use crate::ossl::hash::HashOperation;
use crate::pkcs11::*;

pub const INVALID_HASH_SIZE: usize = CK_UNAVAILABLE_INFORMATION as usize;

/// The Hash Based Operation object
///
/// This object is used to map different mechanisms that reference
/// a specific hash so that a Mech->Hash lookups becomes easier.
#[derive(Debug)]
pub struct HashBasedOp {
    /// The actual Hash mechanism
    pub hash: CK_MECHANISM_TYPE,
    /// HMAC Keys for the HMAC based on the above hash
    pub key_type: CK_KEY_TYPE,
    /// Key Generation mechanism for the above key type
    pub key_gen: CK_MECHANISM_TYPE,
    /// Hash based key derivation mechanism
    pub key_derive: CK_MECHANISM_TYPE,
    /// The HMAC Mechanism using the above hash
    pub mac: CK_MECHANISM_TYPE,
    /// The corresponding general HMAC mechanism
    pub mac_general: CK_MECHANISM_TYPE,
    /// Size of the hash function output
    pub hash_size: usize,
    /// Size of the internal block_size.
    ///
    /// Used only by the native HMAC implementation
    #[allow(dead_code)]
    pub block_size: usize,
}

/// A table referencing all of the supported hash mechanisms used for
/// mapping purposes
#[cfg(feature = "no_sha1")]
const HASH_MECH_SET_LEN: usize = 10;
#[cfg(not(feature = "no_sha1"))]
const HASH_MECH_SET_LEN: usize = 11;
pub static HASH_MECH_SET: [HashBasedOp; HASH_MECH_SET_LEN] = [
    #[cfg(not(feature = "no_sha1"))]
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

/// Object that holds Mechanisms for Hash
static HASH_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DIGEST,
            },
        }),
        Box::new(HashMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 0,
                ulMaxKeySize: 0,
                flags: CKF_DERIVE,
            },
        }),
    ]
});

/// Registers all Hash related mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for hs in &HASH_MECH_SET {
        mechs.add_mechanism(hs.hash, &HASH_MECHS[0]);
        mechs.add_mechanism(hs.key_derive, &HASH_MECHS[1]);
    }
}

/// function to validate that the hash mechanism is a valid one
///
/// Used only by sshkdf
#[cfg(feature = "sshkdf")]
pub fn is_valid_hash(hash: CK_MECHANISM_TYPE) -> bool {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return true;
        }
    }
    return false;
}

/// Returns the hash output size for the specified mechanism
///
/// If the mechanism is not a valid hash INVALID_HASH_SIZE is
/// returned instead
pub fn hash_size(hash: CK_MECHANISM_TYPE) -> usize {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return hs.hash_size;
        }
    }
    INVALID_HASH_SIZE
}

/// Returns the internal block size for the specified mechanism
pub fn block_size(hash: CK_MECHANISM_TYPE) -> usize {
    for hs in &HASH_MECH_SET {
        if hs.hash == hash {
            return hs.block_size;
        }
    }
    INVALID_HASH_SIZE
}

/// Object that represents a Hash mechanism
#[derive(Debug)]
struct HashMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for HashMechanism {
    /// Returns a reference to the mechanism info
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes a Digest operation
    fn digest_new(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Digest>> {
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        Ok(Box::new(HashOperation::new(mech.mechanism)?))
    }

    fn digest_restore(
        &self,
        mechtype: CK_MECHANISM_TYPE,
        state: &[u8],
    ) -> Result<Box<dyn Digest>> {
        if self.info.flags & CKF_DIGEST != CKF_DIGEST {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        Ok(Box::new(HashOperation::restore(mechtype, state)?))
    }

    /// Initializes a Hash based Key Derive operation
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

/// Object that represents a Hash based Key Derivation Operation
#[derive(Debug)]
struct HashKDFOperation {
    /// The key derivation mechanism
    mech: CK_MECHANISM_TYPE,
    /// The corresponding hash mechanism
    prf: CK_MECHANISM_TYPE,
    /// Finalization guard, prevents further processing once the
    /// operation is finalized
    finalized: bool,
}

impl HashKDFOperation {
    /// Instantiates a new Key Derivation Object
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

/// Public internal function to initialize a digest operation directly
pub fn internal_hash_op(hash: CK_MECHANISM_TYPE) -> Result<Box<dyn Digest>> {
    Ok(Box::new(HashOperation::new(hash)?))
}

pub fn internal_hash_restore_op(
    hash: CK_MECHANISM_TYPE,
    state: &[u8],
) -> Result<Box<dyn Digest>> {
    Ok(Box::new(HashOperation::restore(hash, state)?))
}

// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for HMAC (Hash-based
//! Message Authentication Code) as defined in
//! [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)

use std::fmt::Debug;

use crate::error::{Error, Result};
use crate::hash;
use crate::interface::*;
use crate::mechanism::*;
use crate::misc::{sizeof, zeromem};
use crate::object::*;

use once_cell::sync::Lazy;

#[cfg(not(feature = "fips"))]
use crate::native::hmac::HMACOperation;

#[cfg(feature = "fips")]
use crate::ossl::hmac::HMACOperation;

/// Structure that represents an HMAC Key
#[derive(Debug)]
pub struct HmacKey {
    /// A vector containing the raw key in bytes
    pub raw: Vec<u8>,
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        zeromem(self.raw.as_mut_slice())
    }
}

/// Helper function that returns the underlying hash output size
///
/// Uses the hash module's `HASH_MECH_SET` map to retrieve the data.
/// `mech` can be the Hash or any of the HMAC mechanism types
pub fn hmac_size(mech: CK_MECHANISM_TYPE) -> usize {
    for hs in &hash::HASH_MECH_SET {
        if hs.hash == mech || hs.mac == mech || hs.mac_general == mech {
            return hs.hash_size;
        }
    }
    hash::INVALID_HASH_SIZE
}

/// Returns the underlying hash mechanism type from the HMAC mechanism type
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
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL => CKM_SHA512_224,
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL => CKM_SHA512_256,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

/// Returns the standard HMAC mechanism associated to the provided hash
#[cfg(feature = "tlskdf")]
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
        CKM_SHA512_224 => CKM_SHA512_224_HMAC,
        CKM_SHA512_256 => CKM_SHA512_256_HMAC,
        _ => return Err(CKR_MECHANISM_INVALID)?,
    })
}

/// Object that represents an HMAC Mechanism
#[derive(Debug)]
struct HMACMechanism {
    /// General mechanism information
    info: CK_MECHANISM_INFO,
    /// Associated Key Type
    keytype: CK_KEY_TYPE,
    /// Minimum output length
    minlen: usize,
    /// Maximum output length
    maxlen: usize,
}

impl HMACMechanism {
    /// Internally register all HMAC mechanisms listed in `HASH_MECH_SET`
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

    /// Checks that a key object is usable by the HMAc mechanism and returns
    /// the internal raw key
    ///
    /// The only valid key types are the corresponding mechanism key
    /// (eg CKK_SHA256_HMAC for CKM_SHA256_HMAC) or the generic secret
    /// key type (CKK_GENERIC_SECRET).
    ///
    /// Also ensures that the key is marked as allowed for the requested
    /// operation by checking the corresponding attribute on the key object.
    fn check_and_fetch_key(
        &self,
        key: &Object,
        op: CK_ATTRIBUTE_TYPE,
    ) -> Result<HmacKey> {
        if key.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        let t = key.get_attr_as_ulong(CKA_KEY_TYPE)?;
        if t != CKK_GENERIC_SECRET && t != self.keytype {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        if !key.get_attr_as_bool(op).or::<Error>(Ok(false))? {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        Ok(HmacKey {
            raw: key.get_attr_as_bytes(CKA_VALUE)?.clone(),
        })
    }

    /// Fetches the mechanism parameters and checks them for
    /// consistency with the allowed options
    fn check_and_fetch_param(&self, mech: &CK_MECHANISM) -> Result<usize> {
        if self.minlen == self.maxlen {
            if mech.ulParameterLen != 0 {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            return Ok(self.maxlen);
        }
        if mech.ulParameterLen != sizeof!(CK_ULONG) {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let genlen = usize::try_from(unsafe {
            std::slice::from_raw_parts(mech.pParameter as *const CK_ULONG, 1)[0]
        })?;
        if genlen < self.minlen || genlen > self.maxlen {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(genlen)
    }

    /// Initializes a new HMAC Operation
    ///
    /// The mechanism advertises only SIGN/VERIFY to the callers.
    /// DERIVE is a mediated operation so it is not advertised
    /// and we do not check it against the allowed flags */
    fn new_op(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
        op_type: CK_FLAGS,
        signature: Option<&[u8]>,
    ) -> Result<HMACOperation> {
        let op_attr = match op_type {
            CKF_SIGN => {
                if self.info.flags & CKF_SIGN != CKF_SIGN {
                    return Err(CKR_MECHANISM_INVALID)?;
                }
                CKA_SIGN
            }
            CKF_VERIFY => {
                if self.info.flags & CKF_SIGN != CKF_SIGN {
                    return Err(CKR_MECHANISM_INVALID)?;
                }
                CKA_VERIFY
            }
            CKF_DERIVE => CKA_DERIVE,
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        HMACOperation::new(
            mech.mechanism,
            self.check_and_fetch_key(keyobj, op_attr)?,
            self.check_and_fetch_param(mech)?,
            signature,
        )
    }
}

impl Mechanism for HMACMechanism {
    /// Returns a reference to the mechanism info
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes a pure MAC operation, used internally only
    fn mac_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
        op_type: CK_FLAGS,
    ) -> Result<Box<dyn Mac>> {
        Ok(Box::new(self.new_op(mech, keyobj, op_type, None)?))
    }

    /// Initializes an HMAC operation for the Sign operation
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> Result<Box<dyn Sign>> {
        Ok(Box::new(self.new_op(mech, keyobj, CKF_SIGN, None)?))
    }

    /// Initializes an HMAC operation for the Verify operation
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
    ) -> Result<Box<dyn Verify>> {
        Ok(Box::new(self.new_op(mech, keyobj, CKF_VERIFY, None)?))
    }

    /// Initializes an HMAC operation for the VerifySignature operation
    #[cfg(feature = "pkcs11_3_2")]
    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        keyobj: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        Ok(Box::new(self.new_op(
            mech,
            keyobj,
            CKF_VERIFY,
            Some(signature),
        )?))
    }
}

/// Creates static key factories for each key type in HASH_MECH_SET
/// at process initialization or on first use
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

/// Internal function to register only the HMAC mechanisms
///
/// This is used to provide the `tlskdf` module internal direct
/// access to HMAC primitives
#[cfg(feature = "tlskdf")]
pub fn register_mechs_only(mechs: &mut Mechanisms) {
    HMACMechanism::register_mechanisms(mechs);
}

/// Registers all HMAC related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    HMACMechanism::register_mechanisms(mechs);

    /* Key Operations */
    for hs in &hash::HASH_MECH_SET {
        mechs.add_mechanism(
            hs.key_gen,
            Box::new(GenericSecretKeyMechanism::new(hs.key_type)),
        );
    }
    for f in Lazy::force(&HMAC_SECRET_KEY_FACTORIES) {
        ot.add_factory(ObjectType::new(CKO_SECRET_KEY, f.0), &f.1);
    }
}

/// Internal helper for to get a mechanism operation directly without
/// having to go through a registry. This is used for unit tests and
/// for the FIPS self-test in the native tlskdf implementation.
#[cfg(any(feature = "fips", test))]
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

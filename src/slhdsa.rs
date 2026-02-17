// Copyright 2025 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for SLH-DSA, providing
//! post-quantum digital signatures based on stateless hashes. It
//! handles key pair generation, signing, and verification operations
//! according to [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205):
//! _Stateless Hash-Based Digital Signature Standard_

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::kasn1::pkcs;
use crate::mechanism::{Mechanism, Mechanisms, Sign, Verify, VerifySignature};
use crate::object::*;
use crate::ossl::common::extract_public_key;
use crate::ossl::slhdsa;
use crate::pkcs11::*;

/* See FIPS-205, 11. Parameter Sets */
pub const SLH_DSA_128_PK_SIZE: usize = 32;
pub const SLH_DSA_128_SK_SIZE: usize = 64;
pub const SLH_DSA_192_PK_SIZE: usize = 48;
pub const SLH_DSA_192_SK_SIZE: usize = 96;
pub const SLH_DSA_256_PK_SIZE: usize = 64;
pub const SLH_DSA_256_SK_SIZE: usize = 128;

fn slhdsa_public_key_info(
    obj: &mut Object,
    pubkey: Option<&[u8]>,
) -> Result<()> {
    let pubkey_raw = match pubkey {
        Some(p) => p,
        None => {
            // Get raw public key from CKA_VALUE.
            obj.get_attr_as_bytes(CKA_VALUE)?
        }
    };

    // Get paramset from CKA_PARAMETER_SET
    let paramset = obj.get_attr_as_ulong(CKA_PARAMETER_SET)?;

    // Get AlgorithmIdentifier
    let alg = match paramset {
        CKP_SLH_DSA_SHA2_128S => pkcs::SLHDSA_SHA2_128S_ALG,
        CKP_SLH_DSA_SHAKE_128S => pkcs::SLHDSA_SHAKE_128S_ALG,
        CKP_SLH_DSA_SHA2_128F => pkcs::SLHDSA_SHA2_128F_ALG,
        CKP_SLH_DSA_SHAKE_128F => pkcs::SLHDSA_SHAKE_128F_ALG,
        CKP_SLH_DSA_SHA2_192S => pkcs::SLHDSA_SHA2_192S_ALG,
        CKP_SLH_DSA_SHAKE_192S => pkcs::SLHDSA_SHAKE_192S_ALG,
        CKP_SLH_DSA_SHA2_192F => pkcs::SLHDSA_SHA2_192F_ALG,
        CKP_SLH_DSA_SHAKE_192F => pkcs::SLHDSA_SHAKE_192F_ALG,
        CKP_SLH_DSA_SHA2_256S => pkcs::SLHDSA_SHA2_256S_ALG,
        CKP_SLH_DSA_SHAKE_256S => pkcs::SLHDSA_SHAKE_256S_ALG,
        CKP_SLH_DSA_SHA2_256F => pkcs::SLHDSA_SHA2_256F_ALG,
        CKP_SLH_DSA_SHAKE_256F => pkcs::SLHDSA_SHAKE_256F_ALG,
        _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
    };

    // Check if CKA_PUBLIC_KEY_INFO is already there.
    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, pubkey_raw)?.serialize()?,
    )?;

    Ok(())
}

/// Object that holds Mechanisms for SLH-DSA
static SLHDSA_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(SlhDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(SLH_DSA_128_PK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(SLH_DSA_256_PK_SIZE).unwrap(),
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
        Box::new(SlhDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(SLH_DSA_128_PK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(SLH_DSA_256_PK_SIZE).unwrap(),
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    ]
});

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(SlhDsaPrivFactory::new()));

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(SlhDsaPubFactory::new()));

/// Registers all SLH-DSA related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    for ckm in &[
        CKM_SLH_DSA,
        CKM_HASH_SLH_DSA,
        CKM_HASH_SLH_DSA_SHA224,
        CKM_HASH_SLH_DSA_SHA256,
        CKM_HASH_SLH_DSA_SHA384,
        CKM_HASH_SLH_DSA_SHA512,
        CKM_HASH_SLH_DSA_SHA3_224,
        CKM_HASH_SLH_DSA_SHA3_256,
        CKM_HASH_SLH_DSA_SHA3_384,
        CKM_HASH_SLH_DSA_SHA3_512,
        // TODO SHAKE variants
        // CKM_HASH_SLH_DSA_SHAKE128,
        // CKM_HASH_SLH_DSA_SHAKE256,
    ] {
        mechs.add_mechanism(*ckm, &(*SLHDSA_MECHS)[0]);
    }

    mechs.add_mechanism(CKM_SLH_DSA_KEY_PAIR_GEN, &(*SLHDSA_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_SLH_DSA),
        &(*PUBLIC_KEY_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_SLH_DSA),
        &(*PRIVATE_KEY_FACTORY),
    );
}

/// Helper to check that the public key value size matches the
/// declared SLH-DSA parameter set
fn slhdsa_pub_check_import(obj: &Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(value) => match paramset {
            CKP_SLH_DSA_SHA2_128S
            | CKP_SLH_DSA_SHAKE_128S
            | CKP_SLH_DSA_SHA2_128F
            | CKP_SLH_DSA_SHAKE_128F => {
                if value.len() != SLH_DSA_128_PK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_SLH_DSA_SHA2_192S
            | CKP_SLH_DSA_SHAKE_192S
            | CKP_SLH_DSA_SHA2_192F
            | CKP_SLH_DSA_SHAKE_192F => {
                if value.len() != SLH_DSA_192_PK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_SLH_DSA_SHA2_256S
            | CKP_SLH_DSA_SHAKE_256S
            | CKP_SLH_DSA_SHA2_256F
            | CKP_SLH_DSA_SHAKE_256F => {
                if value.len() != SLH_DSA_256_PK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

/// The SLH-DSA Public Key Factory
#[derive(Debug)]
pub struct SlhDsaPubFactory {
    data: ObjectFactoryData,
}

impl SlhDsaPubFactory {
    /// Initializes a SLH-DSA Public Key Factory
    pub fn new() -> SlhDsaPubFactory {
        let mut factory: SlhDsaPubFactory = SlhDsaPubFactory {
            data: ObjectFactoryData::new(CKO_PUBLIC_KEY),
        };

        factory.add_common_public_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_PARAMETER_SET; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_ulong; val 0));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::RequiredOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for SlhDsaPubFactory {
    /// Creates a SLH-DSA public key object
    ///
    /// Uses [KeyFactory::key_create()]
    ///
    /// Checks the import is consistent via helper function
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;

        slhdsa_pub_check_import(&mut obj)?;

        slhdsa_public_key_info(&mut obj, None)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Ok(self)
    }

    fn as_public_key_factory(&self) -> Result<&dyn PubKeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for SlhDsaPubFactory {}

impl PubKeyFactory for SlhDsaPubFactory {
    fn pub_from_private(
        &self,
        key: &Object,
        template: CkAttrs,
    ) -> Result<Object> {
        let mut template: CkAttrs<'_> = template;
        match key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => template.add_owned_ulong(CKA_PARAMETER_SET, p)?,
            Err(_) => return Err(CKR_KEY_UNEXTRACTABLE)?,
        }
        template.add_vec(CKA_VALUE, extract_public_key(key)?)?;
        self.create(template.as_slice())
    }
}

/// Helper to check that the private key value size (if provided)
/// matches the declared SLH-DSA parameter set.
fn slhdsa_priv_check_import(obj: &Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(value) => match paramset {
            CKP_SLH_DSA_SHA2_128S
            | CKP_SLH_DSA_SHAKE_128S
            | CKP_SLH_DSA_SHA2_128F
            | CKP_SLH_DSA_SHAKE_128F => {
                if value.len() != SLH_DSA_128_SK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_SLH_DSA_SHA2_192S
            | CKP_SLH_DSA_SHAKE_192S
            | CKP_SLH_DSA_SHA2_192F
            | CKP_SLH_DSA_SHAKE_192F => {
                if value.len() != SLH_DSA_192_SK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_SLH_DSA_SHA2_256S
            | CKP_SLH_DSA_SHAKE_256S
            | CKP_SLH_DSA_SHA2_256F
            | CKP_SLH_DSA_SHAKE_256F => {
                if value.len() != SLH_DSA_256_SK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };

    Ok(())
}

/// The SLH-DSA Private Key Factory
#[derive(Debug)]
pub struct SlhDsaPrivFactory {
    data: ObjectFactoryData,
}

impl SlhDsaPrivFactory {
    /// Initializes a SLH-DSA Private Key Factory
    pub fn new() -> SlhDsaPrivFactory {
        let mut factory: SlhDsaPrivFactory = SlhDsaPrivFactory {
            data: ObjectFactoryData::new(CKO_PRIVATE_KEY),
        };

        factory.add_common_private_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_PARAMETER_SET; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_ulong; val 0));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for SlhDsaPrivFactory {
    /// Creates a SLH-DSA private key object
    ///
    /// Uses [KeyFactory::key_create()]
    ///
    /// Checks the import is consistent via helper function
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;

        slhdsa_priv_check_import(&mut obj)?;

        let pubkey_raw = extract_public_key(&obj)?;
        slhdsa_public_key_info(&mut obj, Some(&pubkey_raw))?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for SlhDsaPrivFactory {}
impl PrivKeyFactory for SlhDsaPrivFactory {}

/// Object that represents SLH-DSA related mechanisms
#[derive(Debug)]
struct SlhDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for SlhDsaMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_SLH_DSA, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(slhdsa::SlhDsaOperation::sigver_new(
            mech, key, CKF_SIGN, None,
        )?))
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_SLH_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(slhdsa::SlhDsaOperation::sigver_new(
            mech, key, CKF_VERIFY, None,
        )?))
    }

    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_SLH_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(slhdsa::SlhDsaOperation::sigver_new(
            mech,
            key,
            CKF_VERIFY,
            Some(signature),
        )?))
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        let mut pubkey = PUBLIC_KEY_FACTORY
            .as_key_factory()?
            .key_generate(pubkey_template)?;
        pubkey
            .ensure_ulong(CKA_CLASS, CKO_PUBLIC_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        pubkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_SLH_DSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let param_set = match pubkey.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_SLH_DSA_SHA2_128S
                | CKP_SLH_DSA_SHAKE_128S
                | CKP_SLH_DSA_SHA2_128F
                | CKP_SLH_DSA_SHAKE_128F
                | CKP_SLH_DSA_SHA2_192S
                | CKP_SLH_DSA_SHAKE_192S
                | CKP_SLH_DSA_SHA2_192F
                | CKP_SLH_DSA_SHAKE_192F
                | CKP_SLH_DSA_SHA2_256S
                | CKP_SLH_DSA_SHAKE_256S
                | CKP_SLH_DSA_SHA2_256F
                | CKP_SLH_DSA_SHAKE_256F => p,
                _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
            },
            Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
        };

        let mut privkey = PRIVATE_KEY_FACTORY
            .as_key_factory()?
            .key_generate(prikey_template)?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_SLH_DSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_PARAMETER_SET, param_set)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        slhdsa::generate_keypair(param_set, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        slhdsa_public_key_info(&mut pubkey, None)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }
}

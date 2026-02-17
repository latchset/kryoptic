// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ML-DSA, providing
//! post-quantum digital signatures based on lattice cryptography. It
//! handles key pair generation, signing, and verification operations
//! according to [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204):
//! _Module-Lattice-Based Digital Signature Standard_

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::kasn1::pkcs;
use crate::mechanism::{Mechanism, Mechanisms, Sign, Verify, VerifySignature};
use crate::object::*;
use crate::ossl::common::extract_public_key;
use crate::ossl::mldsa;
use crate::pkcs11::*;

/* See FIPS-204, 4. Parameter Sets */
pub const ML_DSA_44_SK_SIZE: usize = 2560;
pub const ML_DSA_44_PK_SIZE: usize = 1312;
pub const ML_DSA_65_SK_SIZE: usize = 4032;
pub const ML_DSA_65_PK_SIZE: usize = 1952;
pub const ML_DSA_87_SK_SIZE: usize = 4896;
pub const ML_DSA_87_PK_SIZE: usize = 2592;

fn mldsa_public_key_info(
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
        CKP_ML_DSA_44 => pkcs::MLDSA44_ALG,
        CKP_ML_DSA_65 => pkcs::MLDSA65_ALG,
        CKP_ML_DSA_87 => pkcs::MLDSA87_ALG,
        _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
    };

    // Check if CKA_PUBLIC_KEY_INFO is already there.
    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, pubkey_raw)?.serialize()?,
    )?;

    Ok(())
}

/// Object that holds Mechanisms for MLDSA
static MLDSA_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(ML_DSA_44_PK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(ML_DSA_87_PK_SIZE).unwrap(),
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(ML_DSA_44_PK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(ML_DSA_87_PK_SIZE).unwrap(),
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    ]
});

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(MlDsaPrivFactory::new()));

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(MlDsaPubFactory::new()));

/// Registers all ML-DSA related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    for ckm in &[
        CKM_ML_DSA,
        CKM_HASH_ML_DSA,
        CKM_HASH_ML_DSA_SHA224,
        CKM_HASH_ML_DSA_SHA256,
        CKM_HASH_ML_DSA_SHA384,
        CKM_HASH_ML_DSA_SHA512,
        CKM_HASH_ML_DSA_SHA3_224,
        CKM_HASH_ML_DSA_SHA3_256,
        CKM_HASH_ML_DSA_SHA3_384,
        CKM_HASH_ML_DSA_SHA3_512,
    ] {
        mechs.add_mechanism(*ckm, &(*MLDSA_MECHS)[0]);
    }
    mechs.add_mechanism(CKM_ML_DSA_KEY_PAIR_GEN, &(*MLDSA_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_DSA),
        &(*PUBLIC_KEY_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_DSA),
        &(*PRIVATE_KEY_FACTORY),
    );
}

/// Helper to check that the public key value size matches the
/// declared ML-DSA parameter set
fn mldsa_pub_check_import(obj: &Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(value) => match paramset {
            CKP_ML_DSA_44 => {
                if value.len() != ML_DSA_44_PK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_ML_DSA_65 => {
                if value.len() != ML_DSA_65_PK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_ML_DSA_87 => {
                if value.len() != ML_DSA_87_PK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

/// The ML-DSA Public Key Factory
#[derive(Debug)]
pub struct MlDsaPubFactory {
    data: ObjectFactoryData,
}

impl MlDsaPubFactory {
    /// Initializes a ML-DSA Public Key Factory
    pub fn new() -> MlDsaPubFactory {
        let mut factory: MlDsaPubFactory = MlDsaPubFactory {
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

impl ObjectFactory for MlDsaPubFactory {
    /// Creates a ML-DSA public key object
    ///
    /// Uses [KeyFactory::key_create()]
    ///
    /// Checks the import is consistent via helper function
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;

        mldsa_pub_check_import(&mut obj)?;

        mldsa_public_key_info(&mut obj, None)?;

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

impl KeyFactory for MlDsaPubFactory {}

impl PubKeyFactory for MlDsaPubFactory {
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
/// matches the declared ML-DSA parameter set, and that the generation
/// seed value (if provided) is of the correct size.
///
/// Finally checks that at least one of CKA_VALUE and CKA_SEED are provided
fn mldsa_priv_check_import(obj: &mut Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    let seed = match obj.get_attr_as_bytes(CKA_SEED) {
        Ok(s) => {
            if s.len() != 32 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
            Some(s)
        }
        Err(_) => None,
    };
    let key = match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(value) => {
            match paramset {
                CKP_ML_DSA_44 => {
                    if value.len() != ML_DSA_44_SK_SIZE {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKP_ML_DSA_65 => {
                    if value.len() != ML_DSA_65_SK_SIZE {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKP_ML_DSA_87 => {
                    if value.len() != ML_DSA_87_SK_SIZE {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
            }
            Some(value)
        }
        Err(_) => None,
    };
    if seed.is_none() && key.is_none() {
        return Err(CKR_TEMPLATE_INCOMPLETE)?;
    }
    if let Some(seedv) = seed {
        if let Some(val) = mldsa::verify_private_key(paramset, seedv, key)? {
            obj.set_attr(Attribute::from_bytes(CKA_VALUE, val))?;
        }
    }

    Ok(())
}

/// The ML-DSA Private Key Factory
#[derive(Debug)]
pub struct MlDsaPrivFactory {
    data: ObjectFactoryData,
}

impl MlDsaPrivFactory {
    /// Initializes a ML-DSA Private Key Factory
    pub fn new() -> MlDsaPrivFactory {
        let mut factory: MlDsaPrivFactory = MlDsaPrivFactory {
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
        attributes.push(attr_element!(
            CKA_SEED; OAFlags::Sensitive | OAFlags::SettableOnlyOnCreate
            | OAFlags::Unchangeable; Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for MlDsaPrivFactory {
    /// Creates a ML-DSA private key object
    ///
    /// Uses [KeyFactory::key_create()]
    ///
    /// Checks the import is consistent via helper function
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;

        mldsa_priv_check_import(&mut obj)?;

        let pubkey_raw = extract_public_key(&obj)?;
        mldsa_public_key_info(&mut obj, Some(&pubkey_raw))?;

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

impl PrivKeyFactory for MlDsaPrivFactory {}

impl KeyFactory for MlDsaPrivFactory {}

/// Object that represents ML-DSA related mechanisms
#[derive(Debug)]
struct MlDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for MlDsaMechanism {
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
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_ML_DSA, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(mldsa::MlDsaOperation::sigver_new(
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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_ML_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(mldsa::MlDsaOperation::sigver_new(
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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_ML_DSA, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(mldsa::MlDsaOperation::sigver_new(
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
            .ensure_ulong(CKA_KEY_TYPE, CKK_ML_DSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let param_set = match pubkey.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_ML_DSA_44 | CKP_ML_DSA_65 | CKP_ML_DSA_87 => p,
                _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
            },
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };

        let mut privkey = PRIVATE_KEY_FACTORY
            .as_key_factory()?
            .key_generate(prikey_template)?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_ML_DSA)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey.ensure_ulong(CKA_PARAMETER_SET, param_set)?;

        mldsa::generate_keypair(param_set, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        mldsa_public_key_info(&mut pubkey, None)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }
}

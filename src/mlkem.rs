// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ML-KEM, providing a
//! post-quantum Key Encapsulation Mechanism based on lattice cryptography,
//! as specified in [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203):
//! _Module-Lattice-Based Key-Encapsulation Mechanism Standard_.
//! It handles key pair generation, key encapsulation, and key
//! decapsulation operations.

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::kasn1::pkcs;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::object::*;
use crate::ossl::common::extract_public_key;
use crate::ossl::mlkem;
use crate::pkcs11::*;

/* See FIPS-203, 8. Parameter Sets */
pub const ML_KEM_512_EK_SIZE: usize = 800;
pub const ML_KEM_768_EK_SIZE: usize = 1184;
pub const ML_KEM_1024_EK_SIZE: usize = 1568;

pub const ML_KEM_512_DK_SIZE: usize = 1632;
pub const ML_KEM_768_DK_SIZE: usize = 2400;
pub const ML_KEM_1024_DK_SIZE: usize = 3168;

pub const ML_KEM_512_CIPHERTEXT_BYTES: usize = 768;
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;

fn mlkem_public_key_info(
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
        CKP_ML_KEM_512 => pkcs::MLKEM512_ALG,
        CKP_ML_KEM_768 => pkcs::MLKEM768_ALG,
        CKP_ML_KEM_1024 => pkcs::MLKEM1024_ALG,
        _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
    };

    // Check if CKA_PUBLIC_KEY_INFO is already there.
    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, pubkey_raw)?.serialize()?,
    )?;

    Ok(())
}

/// Object that holds Mechanisms for MLKEM
static MLKEM_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(MlKemMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(ML_KEM_512_EK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(ML_KEM_1024_EK_SIZE).unwrap(),
                flags: CKF_ENCAPSULATE | CKF_DECAPSULATE,
            },
        }),
        Box::new(MlKemMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(ML_KEM_512_EK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(ML_KEM_1024_EK_SIZE).unwrap(),
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    ]
});

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(MlKemPubFactory::new()));

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(MlKemPrivFactory::new()));

/// Registers all ML-KEM related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(CKM_ML_KEM, &(*MLKEM_MECHS)[0]);
    mechs.add_mechanism(CKM_ML_KEM_KEY_PAIR_GEN, &(*MLKEM_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_KEM),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_KEM),
        &PRIVATE_KEY_FACTORY,
    );
}

/// Helper to check that the public key value size matches the
/// declared ML-KEM parameter set
fn mlkem_pub_check_import(obj: &Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(value) => match paramset {
            CKP_ML_KEM_512 => {
                if value.len() != ML_KEM_512_EK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_ML_KEM_768 => {
                if value.len() != ML_KEM_768_EK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            CKP_ML_KEM_1024 => {
                if value.len() != ML_KEM_1024_EK_SIZE {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

/// The ML-KEM Public Key Factory
#[derive(Debug)]
pub struct MlKemPubFactory {
    data: ObjectFactoryData,
}

impl MlKemPubFactory {
    /// Initializes a ML-KEM Public Key Factory
    pub fn new() -> MlKemPubFactory {
        let mut factory: MlKemPubFactory = MlKemPubFactory {
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

impl ObjectFactory for MlKemPubFactory {
    /// Creates a ML-KEM public key object
    ///
    /// Uses [ObjectFactory::default_object_create()]
    ///
    /// Checks the import is consistent via helper function
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        mlkem_pub_check_import(&mut obj)?;

        mlkem_public_key_info(&mut obj, None)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    fn as_public_key_factory(&self) -> Result<&dyn PubKeyFactory> {
        Ok(self)
    }
}

impl CommonKeyFactory for MlKemPubFactory {}

impl PubKeyFactory for MlKemPubFactory {
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
/// matches the declared ML-KEM parameter set, and that the generation
/// seed value (if provided) is of the correct size.
///
/// Finally checks that at least one of CKA_VALUE and CKA_SEED are provided
fn mlkem_priv_check_import(obj: &mut Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    let seed = match obj.get_attr_as_bytes(CKA_SEED) {
        Ok(s) => {
            if s.len() != 64 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
            Some(s)
        }
        Err(_) => None,
    };
    let key = match obj.get_attr_as_bytes(CKA_VALUE) {
        Ok(value) => {
            match paramset {
                CKP_ML_KEM_512 => {
                    if value.len() != ML_KEM_512_DK_SIZE {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKP_ML_KEM_768 => {
                    if value.len() != ML_KEM_768_DK_SIZE {
                        return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                    }
                }
                CKP_ML_KEM_1024 => {
                    if value.len() != ML_KEM_1024_DK_SIZE {
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
        if let Some(val) = mlkem::verify_private_key(paramset, seedv, key)? {
            obj.set_attr(Attribute::from_bytes(CKA_VALUE, val))?;
        }
    }

    Ok(())
}

/// The ML-KEM Private Key Factory
#[derive(Debug)]
pub struct MlKemPrivFactory {
    data: ObjectFactoryData,
}

impl MlKemPrivFactory {
    /// Initializes a ML-KEM Private Key Factory
    pub fn new() -> MlKemPrivFactory {
        let mut factory: MlKemPrivFactory = MlKemPrivFactory {
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

        /* default to private */
        let private = attr_element!(
            CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy;
            Attribute::from_bool; val true);
        match attributes.iter().position(|x| x.get_type() == CKA_PRIVATE) {
            Some(idx) => attributes[idx] = private,
            None => attributes.push(private),
        }

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for MlKemPrivFactory {
    /// Creates a ML-KEM private key object
    ///
    /// Uses [ObjectFactory::default_object_create()]
    ///
    /// Checks the import is consistent via helper function
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        mlkem_priv_check_import(&mut obj)?;

        let pubkey_raw = extract_public_key(&obj)?;
        mlkem_public_key_info(&mut obj, Some(&pubkey_raw))?;

        Ok(obj)
    }

    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        PrivKeyFactory::export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        PrivKeyFactory::import_from_wrapped(self, data, template)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for MlKemPrivFactory {}

impl PrivKeyFactory for MlKemPrivFactory {
    fn export_for_wrapping(&self, _key: &Object) -> Result<Vec<u8>> {
        /* TODO */
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
    }

    fn import_from_wrapped(
        &self,
        _data: Vec<u8>,
        _template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        /* TODO */
        Err(CKR_FUNCTION_NOT_SUPPORTED)?
    }
}

/// Object that represents ML-KEM related mechanisms
#[derive(Debug)]
struct MlKemMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for MlKemMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Get expected length of the encapsulated ciphertext for given key
    ///
    /// Returns the size in bytes or Err if the key is not ML-KEM
    fn encapsulate_ciphertext_len(&self, key: &Object) -> Result<usize> {
        let kt = key.get_attr_as_ulong(CKA_KEY_TYPE)?;
        if kt != CKK_ML_KEM {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        match key.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_ML_KEM_512 => Ok(ML_KEM_512_CIPHERTEXT_BYTES),
                CKP_ML_KEM_768 => Ok(ML_KEM_768_CIPHERTEXT_BYTES),
                CKP_ML_KEM_1024 => Ok(ML_KEM_1024_CIPHERTEXT_BYTES),
                _ => Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
            },
            Err(e) => Err(e)?,
        }
    }

    fn encapsulate(
        &self,
        _mech: &CK_MECHANISM,
        key: &Object,
        key_factory: &Box<dyn ObjectFactory>,
        template: &[CK_ATTRIBUTE],
        ciphertext: &mut [u8],
    ) -> Result<(Object, usize)> {
        if self.info.flags & CKF_ENCAPSULATE != CKF_ENCAPSULATE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_ML_KEM, CKA_ENCAPSULATE) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        let (keydata, ctlen) = mlkem::encapsulate(key, ciphertext)?;
        Ok((key_factory.import_from_wrapped(keydata, template)?, ctlen))
    }

    fn decapsulate(
        &self,
        _mech: &CK_MECHANISM,
        key: &Object,
        key_factory: &Box<dyn ObjectFactory>,
        template: &[CK_ATTRIBUTE],
        ciphertext: &[u8],
    ) -> Result<Object> {
        if self.info.flags & CKF_DECAPSULATE != CKF_DECAPSULATE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_ML_KEM, CKA_DECAPSULATE) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        let keydata = mlkem::decapsulate(key, ciphertext)?;
        key_factory.import_from_wrapped(keydata, template)
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        pubkey
            .ensure_ulong(CKA_CLASS, CKO_PUBLIC_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        pubkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_ML_KEM)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let param_set = match pubkey.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_ML_KEM_512 | CKP_ML_KEM_768 | CKP_ML_KEM_1024 => p,
                _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED)?,
            },
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_ML_KEM)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey.ensure_ulong(CKA_PARAMETER_SET, param_set)?;

        mlkem::generate_keypair(param_set, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        mlkem_public_key_info(&mut pubkey, None)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }
}

// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for FFDH (Finite Field
//! Diffie-Hellman) key derivation.

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::ffdh_groups;
use crate::interface::*;
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::misc::bytes_to_vec;
use crate::object::*;
use crate::ossl::ffdh::FFDHOperation;

use crate::Lazy;

/// Minimum FFDH key size
pub const MIN_DH_SIZE_BITS: CK_ULONG = 2048;
/// Maximum FFDH key size
pub const MAX_DH_SIZE_BITS: CK_ULONG = 8192;

/// The FFDH Public-Key Factory
#[derive(Debug, Default)]
pub struct FFDHPubFactory {
    data: ObjectFactoryData,
}

impl FFDHPubFactory {
    /// Initializes a new FFDH Public-Key factory
    pub fn new() -> FFDHPubFactory {
        let mut factory: FFDHPubFactory = Default::default();

        factory.add_common_public_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_PRIME; OAFlags::AlwaysRequired | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_BASE; OAFlags::AlwaysRequired | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for FFDHPubFactory {
    /// Creates an FFDH Public-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates that the key is based on a well known
    /// group based on safe primes
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;
        let _ = ffdh_groups::get_group_name(&obj)?;
        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for FFDHPubFactory {}

impl PubKeyFactory for FFDHPubFactory {}

/// The FFDH Private-Key Factory
#[derive(Debug, Default)]
pub struct FFDHPrivFactory {
    data: ObjectFactoryData,
}

impl FFDHPrivFactory {
    /// Initializes a new FFDH Private-Key factory
    pub fn new() -> FFDHPrivFactory {
        let mut factory: FFDHPrivFactory = Default::default();

        factory.add_common_private_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_PRIME; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_BASE; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE_BITS;
            OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_ulong; val 0));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for FFDHPrivFactory {
    /// Creates an FFDH Private-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates that the key is based on a well known
    /// group based on safe primes
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;
        let _ = ffdh_groups::get_group_name(&obj)?;
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

impl CommonKeyFactory for FFDHPrivFactory {}

impl PrivKeyFactory for FFDHPrivFactory {}

/// The static Public Key factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(FFDHPubFactory::new()));

/// The static Private Key factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(FFDHPrivFactory::new()));

/// Object that represents an FFDH Mechanism
#[derive(Debug)]
pub struct FFDHMechanism {
    info: CK_MECHANISM_INFO,
}

impl FFDHMechanism {
    /// Helper function to instantiate a mechanism to be registered
    pub fn new(flags: CK_FLAGS) -> Box<dyn Mechanism> {
        Box::new(FFDHMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_DH_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_DH_SIZE_BITS).unwrap(),
                flags: flags,
            },
        })
    }
}

impl Mechanism for FFDHMechanism {
    /// Returns a reference to the mechanism info (CK_MECHANISM_INFO)
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes an FFDH derive operation
    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        let kdf = match mech.mechanism {
            CKM_DH_PKCS_DERIVE => {
                let peerpub =
                    bytes_to_vec!(mech.pParameter, mech.ulParameterLen);
                FFDHOperation::derive_new(mech.mechanism, peerpub)?
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };
        Ok(Box::new(kdf))
    }

    /// Generates a CKK_DH Key Pair
    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        if !pubkey.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !pubkey
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_DH))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        if !privkey.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !privkey
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_DH))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let prime = match pubkey.get_attr_as_bytes(CKA_PRIME) {
            Ok(p) => p.clone(),
            Err(_) => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        };
        if !privkey
            .check_or_set_attr(Attribute::from_bytes(CKA_PRIME, prime))?
        {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let base = match pubkey.get_attr_as_bytes(CKA_BASE) {
            Ok(b) => b.clone(),
            Err(_) => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        };
        if !privkey.check_or_set_attr(Attribute::from_bytes(CKA_BASE, base))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        /* We allow generation of keys only for Well-Known Groups.
         * We call this on privkey after we copied prime/base, as only
         * the private template/key can carry CKA_VALUE_BITS which we
         * need to check as well */
        let group = ffdh_groups::get_group_name(&privkey)?;

        FFDHOperation::generate_keypair(group, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

/// Public entry to register the FFDH Mechanisms
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    FFDHOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_DH),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_DH),
        &PRIVATE_KEY_FACTORY,
    );
}

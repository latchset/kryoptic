// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for key derivation using
//! Montgomery curves (Curve25519/X25519, Curve448/X448) as specified in
//! [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::Attribute;
use crate::ec::montgomery::montgomery::ECMontgomeryOperation;
use crate::ec::*;
use crate::error::{general_error, Error, Result};
use crate::kasn1::oid;
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::montgomery;

/// Object that holds Mechanisms for Montgomery Ecc
static MONTGOMERY_MECHS: LazyLock<Box<dyn Mechanism>> = LazyLock::new(|| {
    Box::new(ECMontgomeryMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: CK_ULONG::try_from(MIN_EC_MONTGOMERY_SIZE_BITS)
                .unwrap(),
            ulMaxKeySize: CK_ULONG::try_from(MAX_EC_MONTGOMERY_SIZE_BITS)
                .unwrap(),
            flags: CKF_GENERATE_KEY_PAIR,
        },
    })
});

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(ECMontgomeryPubFactory::new()));

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(ECMontgomeryPrivFactory::new()));

/// Registers all CKK_EC_MONTGOMERY related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, &(*MONTGOMERY_MECHS));

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC_MONTGOMERY),
        &(*PUBLIC_KEY_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC_MONTGOMERY),
        &(*PRIVATE_KEY_FACTORY),
    );
}

pub const MIN_EC_MONTGOMERY_SIZE_BITS: usize = BITS_X25519;
pub const MAX_EC_MONTGOMERY_SIZE_BITS: usize = BITS_X448;

/// The EC-Montgomery Public-Key Factory
#[derive(Debug, Default)]
pub struct ECMontgomeryPubFactory {
    data: ObjectFactoryData,
}

impl ECMontgomeryPubFactory {
    /// Initializes a new EC-Montgomery Public-Key factory
    pub fn new() -> ECMontgomeryPubFactory {
        let mut factory: ECMontgomeryPubFactory = Default::default();

        factory.add_common_public_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_EC_PARAMS; OAFlags::AlwaysRequired | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_EC_POINT; OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for ECMontgomeryPubFactory {
    /// Creates an EC-Montgomery Public-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates the Public Point Format and that its size
    /// is consistent with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.7:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of a Parameters value as defined above (6.3.3?) */
        let oid = get_oid_from_obj(&obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e)
            } else {
                general_error(e)
            }
        })?;
        match oid {
            oid::X25519_OID | oid::X448_OID => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.7:
         * CKA_EC_POINT, Byte array,
         * Public key bytes in little endian order as defined in RFC 7748 */
        check_ec_point_from_obj(&oid, &mut obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else {
                e
            }
        })?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for ECMontgomeryPubFactory {}

impl PubKeyFactory for ECMontgomeryPubFactory {}

/// The EC-Montgomery Private-Key Factory
#[derive(Debug, Default)]
pub struct ECMontgomeryPrivFactory {
    data: ObjectFactoryData,
}

impl ECMontgomeryPrivFactory {
    /// Initializes a new EC-Montgomery Private-Key factory
    pub fn new() -> ECMontgomeryPrivFactory {
        let mut factory: ECMontgomeryPrivFactory = Default::default();

        factory.add_common_private_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_EC_PARAMS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for ECMontgomeryPrivFactory {
    /// Creates an EC-Montgomery Private-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates that the private key size is consistent
    /// with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.8:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of a Parameters value as defined above (6.3.3?) */
        let oid = get_oid_from_obj(&obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e)
            } else {
                general_error(e)
            }
        })?;
        match oid {
            oid::X25519_OID | oid::X448_OID => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.8:
         * CKA_VALUE, BigInteger,
         * Private key bytes in little endian order as defined in RFC 7748 */
        match obj.get_attr_as_bytes(CKA_VALUE) {
            Ok(v) => {
                if v.len() != ec_key_size(&oid)? {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
                }
            }
            Err(e) => {
                if e.attr_not_found() {
                    return Err(CKR_TEMPLATE_INCOMPLETE)?;
                } else {
                    return Err(e);
                }
            }
        }

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

impl CommonKeyFactory for ECMontgomeryPrivFactory {}

impl PrivKeyFactory for ECMontgomeryPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        export_for_wrapping(key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        import_from_wrapped(
            CKK_EC_MONTGOMERY,
            data,
            self.default_object_unwrap(template)?,
        )
    }
}

/// Object that represents CKK_EC_MONTGOMERY related mechanisms
#[derive(Debug)]
struct ECMontgomeryMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for ECMontgomeryMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

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
        if !pubkey.check_or_set_attr(Attribute::from_ulong(
            CKA_KEY_TYPE,
            CKK_EC_MONTGOMERY,
        ))? {
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
        if !privkey.check_or_set_attr(Attribute::from_ulong(
            CKA_KEY_TYPE,
            CKK_EC_MONTGOMERY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let ec_params = match pubkey.get_attr_as_bytes(CKA_EC_PARAMS) {
            Ok(a) => a.clone(),
            Err(_) => {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
        };
        if !privkey.check_or_set_attr(Attribute::from_bytes(
            CKA_EC_PARAMS,
            ec_params,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        ECMontgomeryOperation::generate_keypair(&mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

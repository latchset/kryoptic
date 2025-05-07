// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ECDSA (Elliptic Curve
//! Digital Signature Algorithm), including key pair generation, signing,
//! and verification for standard NIST curves (e.g., P-256, P-384, P-521).

use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::ec::*;
use crate::error::{general_error, Error, Result};
use crate::kasn1::oid;
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::ecdsa::EcdsaOperation;

use once_cell::sync::Lazy;

/// Minimum ECDSA key size
pub const MIN_EC_SIZE_BITS: usize = BITS_SECP256R1;
/// Maximum ECDSA key size
pub const MAX_EC_SIZE_BITS: usize = BITS_SECP521R1;

/// The ECDSA Public-Key Factory
#[derive(Debug, Default)]
pub struct ECDSAPubFactory {
    data: ObjectFactoryData,
}

impl ECDSAPubFactory {
    /// Initializes a new ECDSA Public-Key factory
    pub fn new() -> ECDSAPubFactory {
        let mut factory: ECDSAPubFactory = Default::default();

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

impl ObjectFactory for ECDSAPubFactory {
    /// Creates an EC Public-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates the Public Point Format and that its size
    /// is consistent with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.3:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of an ANSI X9.62 Parameters value */
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
            oid::EC_SECP256R1 | oid::EC_SECP384R1 | oid::EC_SECP521R1 => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.3:
         * CKA_EC_POINT, Byte array,
         * DER-encoding of ANSI X9.62 ECPoint value Q */
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

impl CommonKeyFactory for ECDSAPubFactory {}

impl PubKeyFactory for ECDSAPubFactory {}

/// The ECDSA Private-Key Factory
#[derive(Debug, Default)]
pub struct ECDSAPrivFactory {
    data: ObjectFactoryData,
}

impl ECDSAPrivFactory {
    /// Initializes a new ECDSA Private-Key factory
    pub fn new() -> ECDSAPrivFactory {
        let mut factory: ECDSAPrivFactory = Default::default();

        factory.add_common_private_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_EC_PARAMS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate
            | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable;
            Attribute::from_bytes; val Vec::new()));

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

impl ObjectFactory for ECDSAPrivFactory {
    /// Creates an ECDSA Private-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates that the private key size is consistent
    /// with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.4:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of an ANSI X9.62 Parameters value */
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
            oid::EC_SECP256R1 | oid::EC_SECP384R1 | oid::EC_SECP521R1 => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.4:
         * CKA_VALUE, BigInteger,
         * ANSI X9.62 private value d */
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

impl CommonKeyFactory for ECDSAPrivFactory {}

impl PrivKeyFactory for ECDSAPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        export_for_wrapping(key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        import_from_wrapped(CKK_EC, data, self.default_object_unwrap(template)?)
    }
}

/// The static Public Key factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ECDSAPubFactory::new()));

/// The static Private Key factory
///
/// This is instantiated only once and finalized to make it unchangeable
/// after process startup
static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ECDSAPrivFactory::new()));

/// Object that represents CKK_EC related mechanisms
#[derive(Debug)]
pub struct EcdsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl EcdsaMechanism {
    /// Instantiates a new ECDSA Mechanism
    pub fn new(
        min: CK_ULONG,
        max: CK_ULONG,
        flags: CK_FLAGS,
    ) -> EcdsaMechanism {
        EcdsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: min,
                ulMaxKeySize: max,
                flags: flags,
            },
        }
    }
}

impl Mechanism for EcdsaMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    /// Initializes a signing operation using CKK_EC keys
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_EC, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EcdsaOperation::sign_new(mech, key, &self.info)?))
    }

    /// Initializes a verification operation using CKK_EC keys
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EcdsaOperation::verify_new(mech, key, &self.info)?))
    }

    /// Initializes a PKCS#11 3.2 signature verification operation using
    /// CKK_EC keys
    #[cfg(feature = "pkcs11_3_2")]
    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EcdsaOperation::verify_signature_new(
            mech, key, &self.info, signature,
        )?))
    }

    /// Generates a CKK_EC Key Pair
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
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
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
            .check_or_set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
        {
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

        EcdsaOperation::generate_keypair(&mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

/// Registers all CKK_EC related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    EcdsaOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC),
        &PRIVATE_KEY_FACTORY,
    );
}

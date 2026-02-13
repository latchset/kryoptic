// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for EdDSA (Edwards-curve
//! Digital Signature Algorithm), including key pair generation, signing,
//! and verification for Edwards curves (Ed25519, Ed448) as defined in
//! [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::ec::*;
use crate::error::{general_error, Error, Result};
use crate::kasn1::{oid, pkcs};
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::common::extract_public_key;
use crate::ossl::eddsa::EddsaOperation;

/// Object that holds Mechanisms for EDDSA
static EDDSA_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(EddsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_EDWARDS_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_EDWARDS_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
            },
        }),
        Box::new(EddsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_EDWARDS_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_EDWARDS_SIZE_BITS as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR | COMMON_CKF_EC_FLAGS,
            },
        }),
    ]
});

fn eddsa_public_key_info(obj: &mut Object, point: Option<&[u8]>) -> Result<()> {
    let ec_point_raw = match point {
        Some(p) => p,
        None => {
            // Get raw public point from EC_POINT.
            // For CKK_EC_EDWARDS keys, CKA_EC_POINT is raw public key bytes.
            obj.get_attr_as_bytes(CKA_EC_POINT)?
        }
    };

    // Get curve OID from EC_PARAMS
    let oid = get_oid_from_obj(obj)?;

    // Get AlgorithmIdentifier
    let alg = match oid {
        oid::ED25519_OID => pkcs::ED25519_ALG,
        oid::ED448_OID => pkcs::ED448_ALG,
        _ => return Err(CKR_CURVE_NOT_SUPPORTED)?,
    };

    // Check if CKA_PUBLIC_KEY_INFO is already there.
    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, ec_point_raw)?.serialize()?,
    )?;

    Ok(())
}

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(EDDSAPubFactory::new()));

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(EDDSAPrivFactory::new()));

/// Registers all EdDSA related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(CKM_EDDSA, &(*EDDSA_MECHS)[0]);
    mechs.add_mechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, &(*EDDSA_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC_EDWARDS),
        &(*PUBLIC_KEY_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC_EDWARDS),
        &(*PRIVATE_KEY_FACTORY),
    );
}

/// The EdDSA-Edwards Public-Key Factory
#[derive(Debug)]
pub struct EDDSAPubFactory {
    data: ObjectFactoryData,
}

impl EDDSAPubFactory {
    /// Initializes a new EdDSA Public-Key factory
    pub fn new() -> EDDSAPubFactory {
        let mut factory: EDDSAPubFactory = EDDSAPubFactory {
            data: ObjectFactoryData::new(CKO_PUBLIC_KEY),
        };

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

impl ObjectFactory for EDDSAPubFactory {
    /// Creates a CKK_EC_EDWARDS Public-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates the Public Point Format and that its size
    /// is consistent with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.5:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of a Parameters value as defined above (6.3.3) */
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
            oid::ED25519_OID | oid::ED448_OID => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.5:
         * CKA_EC_POINT, Byte array,
         * Public key bytes in little endian order as defined in RFC 8032 */
        check_ec_point_from_obj(&oid, &mut obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else {
                e
            }
        })?;

        eddsa_public_key_info(&mut obj, None)?;

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

impl CommonKeyFactory for EDDSAPubFactory {}

impl PubKeyFactory for EDDSAPubFactory {
    fn pub_from_private<'a>(
        &self,
        key: &'a Object,
        mut template: CkAttrs<'a>,
    ) -> Result<Object> {
        match key.get_attr(CKA_EC_PARAMS) {
            Some(p) => {
                template.add_slice(CKA_EC_PARAMS, p.get_value().as_slice())?
            }
            None => return Err(CKR_KEY_UNEXTRACTABLE)?,
        }

        template.add_vec(CKA_EC_POINT, extract_public_key(key)?)?;

        self.create(template.as_slice())
    }
}

/// The EdDSA Private-Key Factory
#[derive(Debug)]
pub struct EDDSAPrivFactory {
    data: ObjectFactoryData,
}

impl EDDSAPrivFactory {
    /// Initializes a new EdDSA Private-Key factory
    pub fn new() -> EDDSAPrivFactory {
        let mut factory: EDDSAPrivFactory = EDDSAPrivFactory {
            data: ObjectFactoryData::new(CKO_PRIVATE_KEY),
        };

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

impl ObjectFactory for EDDSAPrivFactory {
    /// Creates an EdDSA Private-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [ObjectFactory::default_object_create()]
    ///
    /// Additionally validates that the private key size is consistent
    /// with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        /* According to PKCS#11 v3.1 6.3.6:
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
            oid::ED25519_OID | oid::ED448_OID => (),
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        }

        /* According to PKCS#11 v3.1 6.3.6:
         * CKA_VALUE, BigInteger,
         * Private key bytes in little endian order as defined in RFC 8032 */
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

        let ec_point_raw = extract_public_key(&obj)?;
        eddsa_public_key_info(&mut obj, Some(&ec_point_raw))?;

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

impl CommonKeyFactory for EDDSAPrivFactory {}

impl PrivKeyFactory for EDDSAPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        export_for_wrapping(key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        import_from_wrapped(
            CKK_EC_EDWARDS,
            data,
            self.default_object_unwrap(template)?,
        )
    }
}

/// Object that represents EdDSA related mechanisms
#[derive(Debug)]
struct EddsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for EddsaMechanism {
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
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_EC_EDWARDS, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EddsaOperation::sign_new(mech, key, &self.info)?))
    }

    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC_EDWARDS, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EddsaOperation::verify_new(mech, key, &self.info)?))
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
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC_EDWARDS, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EddsaOperation::verify_signature_new(
            mech, key, &self.info, signature,
        )?))
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
            .ensure_ulong(CKA_KEY_TYPE, CKK_EC_EDWARDS)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_EC_EDWARDS)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        privkey.ensure_slice(
            CKA_EC_PARAMS,
            pubkey.get_attr_as_bytes(CKA_EC_PARAMS)?,
        )?;

        EddsaOperation::generate_keypair(&mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        eddsa_public_key_info(&mut pubkey, None)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }
}

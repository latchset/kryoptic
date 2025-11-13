// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ECDSA (Elliptic Curve
//! Digital Signature Algorithm), including key pair generation, signing,
//! and verification for standard NIST curves (e.g., P-256, P-384, P-521).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::ec::*;
use crate::error::{general_error, Error, Result};
use crate::kasn1::{oid, pkcs};
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::common::extract_public_key;
use crate::ossl::ecdsa::EcdsaOperation;

use asn1;

/// Minimum ECDSA key size
pub const MIN_EC_SIZE_BITS: usize = BITS_SECP256R1;
/// Maximum ECDSA key size
pub const MAX_EC_SIZE_BITS: usize = BITS_SECP521R1;

/// Object that holds Mechanisms for ECDSA
static ECDSA_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(EcdsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
        Box::new(EcdsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_EC_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_EC_SIZE_BITS).unwrap(),
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    ]
});

fn ecdsa_public_key_info(obj: &mut Object) -> Result<()> {
    // Get raw public point from EC_POINT.
    // For CKK_EC keys, CKA_EC_POINT is a DER-encoded OCTET STRING.
    // SubjectPublicKeyInfo's bit string needs the raw point bytes.
    let ec_point_der = obj.get_attr_as_bytes(CKA_EC_POINT)?;
    let ec_point_raw = asn1::parse_single::<&[u8]>(ec_point_der)
        .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;

    // Get curve OID from EC_PARAMS
    let oid = get_oid_from_obj(obj)?;

    // Get AlgorithmIdentifier
    let alg = match oid {
        oid::EC_SECP256R1 => pkcs::EC_SECP256R1_ALG,
        oid::EC_SECP384R1 => pkcs::EC_SECP384R1_ALG,
        oid::EC_SECP521R1 => pkcs::EC_SECP521R1_ALG,
        _ => return Err(CKR_CURVE_NOT_SUPPORTED)?,
    };

    // Check if CKA_PUBLIC_KEY_INFO is already there.
    if !obj.check_or_set_attr(Attribute::from_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, ec_point_raw)?.serialize()?,
    ))? {
        return Err(CKR_TEMPLATE_INCONSISTENT)?;
    };

    Ok(())
}

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(ECDSAPubFactory::new()));

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(ECDSAPrivFactory::new()));

/// Registers all CKK_EC related mechanisms and key factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    for ckm in &[
        CKM_ECDSA,
        #[cfg(not(feature = "no_sha1"))]
        CKM_ECDSA_SHA1,
        CKM_ECDSA_SHA224,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_ECDSA_SHA3_224,
        CKM_ECDSA_SHA3_256,
        CKM_ECDSA_SHA3_384,
        CKM_ECDSA_SHA3_512,
    ] {
        mechs.add_mechanism(*ckm, &(*ECDSA_MECHS)[0]);
    }
    mechs.add_mechanism(CKM_EC_KEY_PAIR_GEN, &(*ECDSA_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC),
        &(*PUBLIC_KEY_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC),
        &(*PRIVATE_KEY_FACTORY),
    );
}

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

        ecdsa_public_key_info(&mut obj)?;

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

impl CommonKeyFactory for ECDSAPubFactory {}

impl PubKeyFactory for ECDSAPubFactory {
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

        let point = extract_public_key(key)?;
        match asn1::write_single(&point.as_slice()) {
            Ok(e) => template.add_vec(CKA_EC_POINT, e)?,
            Err(_) => Err(CKR_GENERAL_ERROR)?,
        }

        self.create(template.as_slice())
    }
}

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

        // Extract public key and set CKA_PUBLIC_KEY_INFO
        // FIXME: Commented until OpenSSL supports extracting for EC keys
        //        see: https://github.com/openssl/openssl/pull/29054
        // let ec_point_raw = extract_public_key(&obj)?;
        // let alg = match oid {
        //     oid::EC_SECP256R1 => pkcs::EC_SECP256R1_ALG,
        //     oid::EC_SECP384R1 => pkcs::EC_SECP384R1_ALG,
        //     oid::EC_SECP521R1 => pkcs::EC_SECP521R1_ALG,
        //     _ => return Err(CKR_CURVE_NOT_SUPPORTED)?,
        // };
        // if !obj.check_or_set_attr(Attribute::from_bytes(
        //     CKA_PUBLIC_KEY_INFO,
        //     pkcs::SubjectPublicKeyInfo::new(alg, ec_point_raw)?.serialize()?,
        // ))? {
        //     return Err(CKR_TEMPLATE_INCONSISTENT)?;
        // }

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

/// Object that represents CKK_EC related mechanisms
#[derive(Debug)]
pub struct EcdsaMechanism {
    info: CK_MECHANISM_INFO,
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

        ecdsa_public_key_info(&mut pubkey)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        match pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO) {
            Ok(info) => privkey.set_attr(Attribute::from_bytes(
                CKA_PUBLIC_KEY_INFO,
                info.clone(),
            ))?,
            Err(_) => return Err(CKR_GENERAL_ERROR)?,
        }

        Ok((pubkey, privkey))
    }
}

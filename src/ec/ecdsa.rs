// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ECDSA (Elliptic Curve
//! Digital Signature Algorithm), including key pair generation, signing,
//! and verification for standard NIST curves (e.g., P-256, P-384, P-521).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::ec::*;
use crate::error::{Error, Result};
use crate::kasn1::{oid, pkcs};
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::common::extract_public_key;
use crate::ossl::ecdsa::EcdsaOperation;

use asn1;

#[cfg(feature = "no_sha1")]
const ECDSA_MECHS_LEN: usize = 10;
#[cfg(not(feature = "no_sha1"))]
const ECDSA_MECHS_LEN: usize = 11;
/// Object that holds Mechanisms for ECDSA
static ECDSA_MECHS: LazyLock<[Box<dyn Mechanism>; ECDSA_MECHS_LEN]> =
    LazyLock::new(|| {
        [
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            #[cfg(not(feature = "no_sha1"))]
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA1,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA224,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA256,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA384,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA512,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA3_224,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA3_256,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA3_384,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_ECDSA_SHA3_512,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_SIGN | CKF_VERIFY | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
            Box::new(EcdsaMechanism {
                minfo: MechanismInfo::new(
                    CKM_EC_KEY_PAIR_GEN,
                    MIN_EC_SIZE_BITS,
                    MAX_EC_SIZE_BITS,
                    CKF_GENERATE_KEY_PAIR | COMMON_CKF_EC_FLAGS,
                    KeySizeKind::Bits,
                    Some(CKK_EC),
                ),
            }),
        ]
    });

fn ecdsa_public_key_info(obj: &mut Object, point: Option<&[u8]>) -> Result<()> {
    let ec_point_raw = match point {
        Some(p) => p,
        None => {
            // Get raw public point from EC_POINT.
            // For CKK_EC keys, CKA_EC_POINT is a DER-encoded OCTET STRING.
            // SubjectPublicKeyInfo's bit string needs the raw point bytes.
            let ec_point_der = obj.get_attr_as_bytes(CKA_EC_POINT)?;
            asn1::parse_single::<&[u8]>(ec_point_der)
                .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?
        }
    };

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
    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, ec_point_raw)?.serialize()?,
    )?;

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
    for mbox in &(*ECDSA_MECHS) {
        let mtype = (*mbox).mechinfo().mech_type();
        mechs.add_mechanism(mtype, mbox);
    }
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
#[derive(Debug)]
pub struct ECDSAPubFactory {
    data: ObjectFactoryData,
}

impl ECDSAPubFactory {
    /// Initializes a new ECDSA Public-Key factory
    pub fn new() -> ECDSAPubFactory {
        let mut factory: ECDSAPubFactory = ECDSAPubFactory {
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
impl ObjectFactory for ECDSAPubFactory {
    /// Creates an EC Public-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [KeyFactory::create_key_object()]
    ///
    /// Additionally validates the Public Point Format and that its size
    /// is consistent with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.create_key_object(template, KeyOrigin::Create)?;

        /* According to PKCS#11 v3.1 6.3.3:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of an ANSI X9.62 Parameters value */
        let oid = get_oid_from_obj(&obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e)
            } else {
                Error::ck_rv_from_error(CKR_GENERAL_ERROR, e)
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

        ecdsa_public_key_info(&mut obj, None)?;

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

impl KeyFactory for ECDSAPubFactory {}

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
#[derive(Debug)]
pub struct ECDSAPrivFactory {
    data: ObjectFactoryData,
}

impl ECDSAPrivFactory {
    /// Initializes a new ECDSA Private-Key factory
    pub fn new() -> ECDSAPrivFactory {
        let mut factory: ECDSAPrivFactory = ECDSAPrivFactory {
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

        factory.data.finalize();

        factory
    }
}
impl ObjectFactory for ECDSAPrivFactory {
    /// Creates an ECDSA Private-Key Object from a template
    ///
    /// Validates that the provided attributes are consistent with the
    /// factory via [KeyFactory::create_key_object()]
    ///
    /// Additionally validates that the private key size is consistent
    /// with the EC Parameters provided
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.create_key_object(template, KeyOrigin::Create)?;

        /* According to PKCS#11 v3.1 6.3.4:
         * CKA_EC_PARAMS, Byte array,
         * DER-encoding of an ANSI X9.62 Parameters value */
        let oid = get_oid_from_obj(&obj).map_err(|e| {
            if e.attr_not_found() {
                Error::ck_rv_from_error(CKR_TEMPLATE_INCOMPLETE, e)
            } else if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                Error::ck_rv_from_error(CKR_ATTRIBUTE_VALUE_INVALID, e)
            } else {
                Error::ck_rv_from_error(CKR_GENERAL_ERROR, e)
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
                if v.len() > ec_key_size(&oid)? {
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
        match extract_public_key(&obj) {
            Ok(ec_point_raw) => {
                ecdsa_public_key_info(&mut obj, Some(&ec_point_raw))?;
            }
            Err(e) => {
                // Key is unextractable on OpenSSL versions older than 4.0.0
                // do not fail if key is missing in that case which is reported
                // via CKR_KEY_UNEXTRACTABLE error.
                if e.rv() != CKR_KEY_UNEXTRACTABLE {
                    return Err(e);
                }
            }
        }

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

impl KeyFactory for ECDSAPrivFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<SecVec> {
        export_for_wrapping(key)
    }

    fn import_from_wrapped(
        &self,
        data: SecVec,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        import_from_wrapped(
            CKK_EC,
            data,
            self.create_key_object(template, KeyOrigin::Unwrap)?,
        )
    }
}

impl PrivKeyFactory for ECDSAPrivFactory {}

/// Object that represents CKK_EC related mechanisms
#[derive(Debug)]
pub struct EcdsaMechanism {
    minfo: MechanismInfo,
}

impl Mechanism for EcdsaMechanism {
    fn mechinfo(&self) -> &MechanismInfo {
        &self.minfo
    }

    /// Initializes a signing operation using CKK_EC keys
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Sign>> {
        if self.info().flags & CKF_SIGN != CKF_SIGN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_EC, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EcdsaOperation::sign_new(mech, key, &self.info())?))
    }

    /// Initializes a verification operation using CKK_EC keys
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Verify>> {
        if self.info().flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EcdsaOperation::verify_new(
            mech,
            key,
            &self.info(),
        )?))
    }

    /// Initializes a PKCS#11 3.2 signature verification operation using
    /// CKK_EC keys
    fn verify_signature_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
        signature: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        if self.info().flags & CKF_VERIFY != CKF_VERIFY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EcdsaOperation::verify_signature_new(
            mech,
            key,
            &self.info(),
            signature,
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
            PUBLIC_KEY_FACTORY.as_key_factory()?.create_key_object(
                pubkey_template,
                KeyOrigin::Generate(mech.mechanism),
            )?;
        pubkey
            .ensure_ulong(CKA_CLASS, CKO_PUBLIC_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        pubkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_EC)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let mut privkey =
            PRIVATE_KEY_FACTORY.as_key_factory()?.create_key_object(
                prikey_template,
                KeyOrigin::Generate(mech.mechanism),
            )?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_EC)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        privkey.ensure_slice(
            CKA_EC_PARAMS,
            pubkey.get_attr_as_bytes(CKA_EC_PARAMS)?,
        )?;

        EcdsaOperation::generate_keypair(&mut pubkey, &mut privkey)?;

        ecdsa_public_key_info(&mut pubkey, None)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }
}

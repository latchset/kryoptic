// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for FFDH (Finite Field
//! Diffie-Hellman) key derivation.

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::ffdh_groups;
use crate::kasn1::{pkcs, DerEncBigUint};
use crate::mechanism::{Derive, Mechanism, Mechanisms};
use crate::misc::bytes_to_vec;
use crate::object::*;
use crate::ossl::ffdh::FFDHOperation;
use crate::pkcs11::*;
use asn1;

/// Minimum FFDH key size
pub const MIN_DH_SIZE_BITS: CK_ULONG = 2048;
/// Maximum FFDH key size
pub const MAX_DH_SIZE_BITS: CK_ULONG = 8192;

/// Object that holds Mechanisms for FFDH
static FFDH_MECHS: LazyLock<[Box<dyn Mechanism>; 2]> = LazyLock::new(|| {
    [
        Box::new(FFDHMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_DH_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_DH_SIZE_BITS).unwrap(),
                flags: CKF_DERIVE,
            },
        }),
        Box::new(FFDHMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(MIN_DH_SIZE_BITS).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(MAX_DH_SIZE_BITS).unwrap(),
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    ]
});

/// The static Public Key factory
static PUBLIC_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(FFDHPubFactory::new()));

/// The static Private Key factory
static PRIVATE_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(FFDHPrivFactory::new()));

/// Public entry to register the FFDH Mechanisms
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(CKM_DH_PKCS_DERIVE, &(*FFDH_MECHS)[0]);
    mechs.add_mechanism(CKM_DH_PKCS_KEY_PAIR_GEN, &(*FFDH_MECHS)[1]);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_DH),
        &(*PUBLIC_KEY_FACTORY),
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_DH),
        &(*PRIVATE_KEY_FACTORY),
    );
}

fn ffdh_public_key_info(
    group: ffdh_groups::DHGroupName,
    obj: &mut Object,
) -> Result<()> {
    let (p, g, q) = ffdh_groups::group_values(group)?;

    let p_der = DerEncBigUint::new(p)?;
    let g_der = DerEncBigUint::new(g)?;
    let q_der = DerEncBigUint::new(q)?;

    let dhx_params = pkcs::DHXParams {
        p: asn1::BigUint::new(p_der.as_bytes()).ok_or(CKR_GENERAL_ERROR)?,
        g: asn1::BigUint::new(g_der.as_bytes()).ok_or(CKR_GENERAL_ERROR)?,
        q: asn1::BigUint::new(q_der.as_bytes()).ok_or(CKR_GENERAL_ERROR)?,
        j: None,
        validation_params: None,
    };

    let alg = pkcs::AlgorithmIdentifier {
        oid: asn1::DefinedByMarker::marker(),
        params: pkcs::AlgorithmParameters::Dh(dhx_params),
    };

    let y = obj.get_attr_as_bytes(CKA_VALUE)?;
    let y_der = match asn1::write_single(&DerEncBigUint::new(y)?) {
        Ok(der) => der,
        Err(_) => Err(CKR_GENERAL_ERROR)?,
    };

    obj.ensure_bytes(
        CKA_PUBLIC_KEY_INFO,
        pkcs::SubjectPublicKeyInfo::new(alg, &y_der)?.serialize()?,
    )?;

    Ok(())
}

/// The FFDH Public-Key Factory
#[derive(Debug)]
pub struct FFDHPubFactory {
    data: ObjectFactoryData,
}

impl FFDHPubFactory {
    /// Initializes a new FFDH Public-Key factory
    pub fn new() -> FFDHPubFactory {
        let mut factory: FFDHPubFactory = FFDHPubFactory {
            data: ObjectFactoryData::new(CKO_PUBLIC_KEY),
        };

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
    /// factory via [KeyFactory::key_create()]
    ///
    /// Additionally validates that the key is based on a well known
    /// group based on safe primes
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;
        let group = ffdh_groups::get_group_name(&obj)?;
        ffdh_public_key_info(group, &mut obj)?;
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

impl KeyFactory for FFDHPubFactory {}

impl PubKeyFactory for FFDHPubFactory {}

/// The FFDH Private-Key Factory
#[derive(Debug)]
pub struct FFDHPrivFactory {
    data: ObjectFactoryData,
}

impl FFDHPrivFactory {
    /// Initializes a new FFDH Private-Key factory
    pub fn new() -> FFDHPrivFactory {
        let mut factory: FFDHPrivFactory = FFDHPrivFactory {
            data: ObjectFactoryData::new(CKO_PRIVATE_KEY),
        };

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
    /// factory via [KeyFactory::key_create()]
    ///
    /// Additionally validates that the key is based on a well known
    /// group based on safe primes
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.key_create(template)?;

        let _ = ffdh_groups::get_group_name(&obj)?;

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

impl KeyFactory for FFDHPrivFactory {}

impl PrivKeyFactory for FFDHPrivFactory {}

/// Object that represents an FFDH Mechanism
#[derive(Debug)]
pub struct FFDHMechanism {
    info: CK_MECHANISM_INFO,
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
        let mut pubkey = PUBLIC_KEY_FACTORY
            .as_key_factory()?
            .key_generate(pubkey_template)?;
        pubkey
            .ensure_ulong(CKA_CLASS, CKO_PUBLIC_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        pubkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_DH)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        let mut privkey = PRIVATE_KEY_FACTORY
            .as_key_factory()?
            .key_generate(prikey_template)?;
        privkey
            .ensure_ulong(CKA_CLASS, CKO_PRIVATE_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        privkey
            .ensure_ulong(CKA_KEY_TYPE, CKK_DH)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        privkey
            .ensure_slice(CKA_PRIME, pubkey.get_attr_as_bytes(CKA_PRIME)?)?;
        privkey.ensure_slice(CKA_BASE, pubkey.get_attr_as_bytes(CKA_BASE)?)?;

        /* We allow generation of keys only for Well-Known Groups.
         * We call this on privkey after we copied prime/base, as only
         * the private template/key can carry CKA_VALUE_BITS which we
         * need to check as well */
        let group = ffdh_groups::get_group_name(&privkey)?;

        FFDHOperation::generate_keypair(group, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        ffdh_public_key_info(group, &mut pubkey)?;
        /* copy the calculated CKA_PUBLIC_KEY_INFO to the private key */
        privkey.ensure_slice(
            CKA_PUBLIC_KEY_INFO,
            pubkey.get_attr_as_bytes(CKA_PUBLIC_KEY_INFO)?,
        )?;

        Ok((pubkey, privkey))
    }
}

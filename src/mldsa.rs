// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use once_cell::sync::Lazy;
use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms, Sign, Verify, VerifySignature};
use crate::object::*;
use crate::ossl::mldsa;

/* See FIPS-204, 4. Parameter Sets */
pub const ML_DSA_44_SK_SIZE: usize = 2560;
pub const ML_DSA_44_PK_SIZE: usize = 1312;
pub const ML_DSA_65_SK_SIZE: usize = 4032;
pub const ML_DSA_65_PK_SIZE: usize = 1952;
pub const ML_DSA_87_SK_SIZE: usize = 4896;
pub const ML_DSA_87_PK_SIZE: usize = 2592;

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
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct MlDsaPubFactory {
    data: ObjectFactoryData,
}

impl MlDsaPubFactory {
    pub fn new() -> MlDsaPubFactory {
        let mut factory: MlDsaPubFactory = Default::default();

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
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        mldsa_pub_check_import(&mut obj)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for MlDsaPubFactory {}

impl PubKeyFactory for MlDsaPubFactory {}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPubFactory::new()));

fn mldsa_priv_check_import(obj: &Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    let has_seed = match obj.get_attr_as_bytes(CKA_SEED) {
        Ok(seed) => {
            if seed.len() != 32 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
            true
        }
        Err(_) => false,
    };
    let has_val = match obj.get_attr_as_bytes(CKA_VALUE) {
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
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
            }
            true
        }
        Err(_) => false,
    };
    if !has_seed && !has_val {
        return Err(CKR_TEMPLATE_INCOMPLETE)?;
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct MlDsaPrivFactory {
    data: ObjectFactoryData,
}

impl MlDsaPrivFactory {
    pub fn new() -> MlDsaPrivFactory {
        let mut factory: MlDsaPrivFactory = Default::default();

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

impl ObjectFactory for MlDsaPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        mldsa_priv_check_import(&mut obj)?;

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

impl CommonKeyFactory for MlDsaPrivFactory {}

impl PrivKeyFactory for MlDsaPrivFactory {
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

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlDsaPrivFactory::new()));

#[derive(Debug)]
struct MlDsaMechanism {
    info: CK_MECHANISM_INFO,
}

impl MlDsaMechanism {
    fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
        Box::new(MlDsaMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(ML_DSA_44_PK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(ML_DSA_87_PK_SIZE).unwrap(),
                flags: flags,
            },
        })
    }

    pub fn register_mechanisms(mechs: &mut Mechanisms) {
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
            mechs.add_mechanism(
                *ckm,
                Self::new_mechanism(CKF_SIGN | CKF_VERIFY),
            );
        }

        mechs.add_mechanism(
            CKM_ML_DSA_KEY_PAIR_GEN,
            Self::new_mechanism(CKF_GENERATE_KEY_PAIR),
        );
    }
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
            CKK_ML_DSA,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let param_set = match pubkey.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_ML_DSA_44 | CKP_ML_DSA_65 | CKP_ML_DSA_87 => p,
                _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
            },
            Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
        };

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
            CKK_ML_DSA,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !privkey.check_or_set_attr(Attribute::from_ulong(
            CKA_PARAMETER_SET,
            param_set,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        mldsa::generate_keypair(param_set, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    MlDsaMechanism::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_DSA),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_DSA),
        &PRIVATE_KEY_FACTORY,
    );
}

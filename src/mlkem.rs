// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

use once_cell::sync::Lazy;
use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::object::*;
use crate::ossl::mlkem;

/* See FIPS-203, 8. Parameter Sets */
pub const ML_KEM_512_EK_SIZE: usize = 800;
pub const ML_KEM_768_EK_SIZE: usize = 1184;
pub const ML_KEM_1024_EK_SIZE: usize = 1568;
pub const ML_KEM_512_DK_SIZE: usize = 1632;
pub const ML_KEM_768_DK_SIZE: usize = 2400;
pub const ML_KEM_1024_DK_SIZE: usize = 3168;

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
            _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
        },
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct MlKemPubFactory {
    data: ObjectFactoryData,
}

impl MlKemPubFactory {
    pub fn new() -> MlKemPubFactory {
        let mut factory: MlKemPubFactory = Default::default();

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
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        mlkem_pub_check_import(&mut obj)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }

    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }
}

impl CommonKeyFactory for MlKemPubFactory {}

impl PubKeyFactory for MlKemPubFactory {}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlKemPubFactory::new()));

fn mlkem_priv_check_import(obj: &Object) -> Result<()> {
    let paramset = match obj.get_attr_as_ulong(CKA_PARAMETER_SET) {
        Ok(p) => p,
        Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
    };
    let has_seed = match obj.get_attr_as_bytes(CKA_SEED) {
        Ok(seed) => {
            if seed.len() != 64 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
            true
        }
        Err(_) => false,
    };
    let has_val = match obj.get_attr_as_bytes(CKA_VALUE) {
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
pub struct MlKemPrivFactory {
    data: ObjectFactoryData,
}

impl MlKemPrivFactory {
    pub fn new() -> MlKemPrivFactory {
        let mut factory: MlKemPrivFactory = Default::default();

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
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        mlkem_priv_check_import(&mut obj)?;

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

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(MlKemPrivFactory::new()));

#[derive(Debug)]
struct MlKemMechanism {
    info: CK_MECHANISM_INFO,
}

impl MlKemMechanism {
    fn new_mechanism(flags: CK_FLAGS) -> Box<dyn Mechanism> {
        Box::new(MlKemMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(ML_KEM_512_EK_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(ML_KEM_1024_EK_SIZE).unwrap(),
                flags: flags,
            },
        })
    }

    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_ML_KEM,
            Self::new_mechanism(CKF_ENCAPSULATE | CKF_DECAPSULATE),
        );

        mechs.add_mechanism(
            CKM_ML_KEM_KEY_PAIR_GEN,
            Self::new_mechanism(CKF_GENERATE_KEY_PAIR),
        );
    }
}

impl Mechanism for MlKemMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
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
        if !pubkey.check_or_set_attr(Attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if !pubkey.check_or_set_attr(Attribute::from_ulong(
            CKA_KEY_TYPE,
            CKK_ML_KEM,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let param_set = match pubkey.get_attr_as_ulong(CKA_PARAMETER_SET) {
            Ok(p) => match p {
                CKP_ML_KEM_512 | CKP_ML_KEM_768 | CKP_ML_KEM_1024 => p,
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
            CKK_ML_KEM,
        ))? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        mlkem::generate_keypair(param_set, &mut pubkey, &mut privkey)?;
        default_key_attributes(&mut privkey, mech.mechanism)?;
        default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    MlKemMechanism::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_ML_KEM),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_ML_KEM),
        &PRIVATE_KEY_FACTORY,
    );
}

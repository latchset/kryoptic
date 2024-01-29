// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::object;
use super::{attr_element, bytes_attr_not_empty, err_rv};

use attribute::{from_bool, from_bytes};
use error::{KError, KResult};
use interface::*;
use object::{
    CommonKeyFactory, OAFlags, Object, ObjectAttr, ObjectFactories,
    ObjectFactory, ObjectType, PrivKeyFactory, PubKeyFactory,
};

use once_cell::sync::Lazy;
use std::fmt::Debug;

pub const MIN_EC_SIZE_BITS: usize = 256;
pub const MAX_EC_SIZE_BITS: usize = 521;

#[derive(Debug)]
pub struct ECCPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl ECCPubFactory {
    pub fn new() -> ECCPubFactory {
        let mut data: ECCPubFactory = ECCPubFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());
        data.attributes.push(attr_element!(CKA_EC_PARAMS; OAFlags::AlwaysRequired | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EC_POINT; OAFlags::RequiredOnCreate | OAFlags::UnsettableOnGenerate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for ECCPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let obj = self.default_object_create(template)?;

        bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
        bytes_attr_not_empty!(obj; CKA_EC_POINT);

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for ECCPubFactory {}

impl PubKeyFactory for ECCPubFactory {}

#[derive(Debug)]
pub struct ECCPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl ECCPrivFactory {
    pub fn new() -> ECCPrivFactory {
        let mut data: ECCPrivFactory = ECCPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());
        data.attributes.push(attr_element!(CKA_EC_PARAMS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::UnsettableOnGenerate | OAFlags::Unchangeable; from_bytes; val Vec::new()));

        /* default to private */
        let private = attr_element!(CKA_PRIVATE; OAFlags::Defval | OAFlags::ChangeOnCopy; from_bool; val true);
        match data
            .attributes
            .iter()
            .position(|x| x.get_type() == CKA_PRIVATE)
        {
            Some(idx) => data.attributes[idx] = private,
            None => data.attributes.push(private),
        }

        data
    }
}

impl ObjectFactory for ECCPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> KResult<Object> {
        let mut obj = self.default_object_create(template)?;

        ecc_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for ECCPrivFactory {}

impl PrivKeyFactory for ECCPrivFactory {
}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ECCPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(ECCPrivFactory::new()));

#[derive(Debug)]
struct EccMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for EccMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    // TODO wrap/derive
    fn sign_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Sign>> {
        if self.info.flags & CKF_SIGN != CKF_SIGN {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match key.check_key_ops(CKO_PRIVATE_KEY, CKK_EC, CKA_SIGN) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EccOperation::sign_new(mech, key, &self.info)?))
    }
    fn verify_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> KResult<Box<dyn Verify>> {
        if self.info.flags & CKF_VERIFY != CKF_VERIFY {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EccOperation::verify_new(
            mech, key, &self.info,
        )?))
    }

    fn generate_keypair(
        &self,
        _mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> KResult<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        if !pubkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !pubkey
            .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let mut privkey = PRIVATE_KEY_FACTORY
            .default_object_generate(prikey_template)?;
        if !privkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !privkey
            .check_or_set_attr(attribute::from_ulong(CKA_KEY_TYPE, CKK_EC))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let ec_params = match pubkey.get_attr_as_bytes(CKA_EC_PARAMS) {
            Ok(a) => a.clone(),
            Err(_) => {
                return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
            }
        };
        if !privkey
            .check_or_set_attr(attribute::from_bytes(CKA_EC_PARAMS, ec_params))?
        {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        EccOperation::generate_keypair(
            &mut pubkey,
            &mut privkey,
        )?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    mechs.add_mechanism(
        CKM_ECDSA,
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_ECDSA_SHA1,
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );

    mechs.add_mechanism(
        CKM_ECDSA_SHA256,
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_ECDSA_SHA384,
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    mechs.add_mechanism(
        CKM_ECDSA_SHA512,
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_SIGN | CKF_VERIFY,
            },
        }),
    );
    // TODO SHA3 mechs

    mechs.add_mechanism(
        CKM_EC_KEY_PAIR_GEN,
        Box::new(EccMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: MIN_EC_SIZE_BITS as CK_ULONG,
                ulMaxKeySize: MAX_EC_SIZE_BITS as CK_ULONG,
                flags: CKF_GENERATE_KEY_PAIR,
            },
        }),
    );
    // TODO DERIVE mechs

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC),
        &PUBLIC_KEY_FACTORY
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC),
        &PRIVATE_KEY_FACTORY
    );
}

include!("ossl/ecc.rs");

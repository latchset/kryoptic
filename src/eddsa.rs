// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::object;
use super::{attr_element, bytes_attr_not_empty, bytes_to_vec, err_rv};

use attribute::{from_bool, from_bytes};
use error::Result;
use interface::*;
use object::{
    CommonKeyFactory, OAFlags, Object, ObjectAttr, ObjectFactories,
    ObjectFactory, ObjectType, PrivKeyFactory, PubKeyFactory,
};

use once_cell::sync::Lazy;
use std::fmt::Debug;

use crate::ecc_misc::*;

const BITS_ED25519: usize = 255;
const BITS_ED448: usize = 448;

pub const MIN_EDDSA_SIZE_BITS: usize = BITS_ED25519;
pub const MAX_EDDSA_SIZE_BITS: usize = BITS_ED448;

// ASN.1 encoding of the OID
const OID_ED25519: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 112);
const OID_ED448: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 113);

// ASN.1 encoding of the curve name
const STRING_ED25519: &[u8] = &[
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35,
    0x31, 0x39,
];
const STRING_ED448: &[u8] = &[
    0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38,
];

fn oid_to_bits(oid: asn1::ObjectIdentifier) -> Result<usize> {
    match oid {
        OID_ED25519 => Ok(BITS_ED25519),
        OID_ED448 => Ok(BITS_ED448),
        _ => err_rv!(CKR_GENERAL_ERROR),
    }
}

fn curve_name_to_bits(name: asn1::PrintableString) -> Result<usize> {
    let asn1_name = match asn1::write_single(&name) {
        Ok(r) => r,
        Err(_) => return err_rv!(CKR_GENERAL_ERROR),
    };
    match asn1_name.as_slice() {
        STRING_ED25519 => Ok(BITS_ED25519),
        STRING_ED448 => Ok(BITS_ED448),
        _ => err_rv!(CKR_GENERAL_ERROR),
    }
}

#[derive(Debug)]
pub struct EDDSAPubFactory {
    attributes: Vec<ObjectAttr>,
}

impl EDDSAPubFactory {
    pub fn new() -> EDDSAPubFactory {
        let mut data: EDDSAPubFactory = EDDSAPubFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_public_key_attrs());
        data.attributes.push(attr_element!(CKA_EC_PARAMS; OAFlags::AlwaysRequired | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_EC_POINT; OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectFactory for EDDSAPubFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let obj = self.default_object_create(template)?;

        bytes_attr_not_empty!(obj; CKA_EC_PARAMS);
        bytes_attr_not_empty!(obj; CKA_EC_POINT);

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
    }
}

impl CommonKeyFactory for EDDSAPubFactory {}

impl PubKeyFactory for EDDSAPubFactory {}

#[derive(Debug)]
pub struct EDDSAPrivFactory {
    attributes: Vec<ObjectAttr>,
}

impl EDDSAPrivFactory {
    pub fn new() -> EDDSAPrivFactory {
        let mut data: EDDSAPrivFactory = EDDSAPrivFactory {
            attributes: Vec::new(),
        };
        data.attributes.append(&mut data.init_common_object_attrs());
        data.attributes
            .append(&mut data.init_common_storage_attrs());
        data.attributes.append(&mut data.init_common_key_attrs());
        data.attributes
            .append(&mut data.init_common_private_key_attrs());
        data.attributes.push(attr_element!(CKA_EC_PARAMS; OAFlags::RequiredOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));
        data.attributes.push(attr_element!(CKA_VALUE; OAFlags::Sensitive | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate | OAFlags::Unchangeable; from_bytes; val Vec::new()));

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

impl ObjectFactory for EDDSAPrivFactory {
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.default_object_create(template)?;

        eddsa_import(&mut obj)?;

        Ok(obj)
    }

    fn get_attributes(&self) -> &Vec<ObjectAttr> {
        &self.attributes
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
}

impl CommonKeyFactory for EDDSAPrivFactory {}

impl PrivKeyFactory for EDDSAPrivFactory {}

static PUBLIC_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(EDDSAPubFactory::new()));

static PRIVATE_KEY_FACTORY: Lazy<Box<dyn ObjectFactory>> =
    Lazy::new(|| Box::new(EDDSAPrivFactory::new()));

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
            return err_rv!(CKR_MECHANISM_INVALID);
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
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match key.check_key_ops(CKO_PUBLIC_KEY, CKK_EC_EDWARDS, CKA_VERIFY) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        Ok(Box::new(EddsaOperation::verify_new(mech, key, &self.info)?))
    }

    fn generate_keypair(
        &self,
        mech: &CK_MECHANISM,
        pubkey_template: &[CK_ATTRIBUTE],
        prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        let mut pubkey =
            PUBLIC_KEY_FACTORY.default_object_generate(pubkey_template)?;
        if !pubkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PUBLIC_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !pubkey.check_or_set_attr(attribute::from_ulong(
            CKA_KEY_TYPE,
            CKK_EC_EDWARDS,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let mut privkey =
            PRIVATE_KEY_FACTORY.default_object_generate(prikey_template)?;
        if !privkey.check_or_set_attr(attribute::from_ulong(
            CKA_CLASS,
            CKO_PRIVATE_KEY,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if !privkey.check_or_set_attr(attribute::from_ulong(
            CKA_KEY_TYPE,
            CKK_EC_EDWARDS,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let ec_params = match pubkey.get_attr_as_bytes(CKA_EC_PARAMS) {
            Ok(a) => a.clone(),
            Err(_) => {
                return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
            }
        };
        if !privkey.check_or_set_attr(attribute::from_bytes(
            CKA_EC_PARAMS,
            ec_params,
        ))? {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        EddsaOperation::generate_keypair(&mut pubkey, &mut privkey)?;
        object::default_key_attributes(&mut privkey, mech.mechanism)?;
        object::default_key_attributes(&mut pubkey, mech.mechanism)?;

        Ok((pubkey, privkey))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    EddsaOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_PUBLIC_KEY, CKK_EC_EDWARDS),
        &PUBLIC_KEY_FACTORY,
    );
    ot.add_factory(
        ObjectType::new(CKO_PRIVATE_KEY, CKK_EC_EDWARDS),
        &PRIVATE_KEY_FACTORY,
    );
}

include!("ossl/eddsa.rs");

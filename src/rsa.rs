// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::mechanism;
use super::object;
use super::{attr_element, bytes_attr_not_empty, err_rv};
use attribute::{from_bytes, from_ulong};
use error::{KError, KResult};
use interface::*;
use mechanism::*;
use object::{
    CommonKeyTemplate, Object, ObjectAttr, ObjectTemplate, ObjectTemplates,
    ObjectType, PrivKeyTemplate, PubKeyTemplate,
};
use std::fmt::Debug;

pub const MIN_RSA_SIZE_BITS: usize = 1024;
pub const MIN_RSA_SIZE_BYTES: usize = MIN_RSA_SIZE_BITS / 8;

#[derive(Debug)]
pub struct RSAPubTemplate {
    template: Vec<ObjectAttr>,
}

impl RSAPubTemplate {
    pub fn new() -> RSAPubTemplate {
        let mut data: RSAPubTemplate = RSAPubTemplate {
            template: Vec::new(),
        };
        data.init_common_object_attrs();
        data.init_common_storage_attrs();
        data.init_common_key_attrs();
        data.init_common_public_key_attrs();
        data.template.push(attr_element!(CKA_MODULUS; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_MODULUS_BITS; req false; def false; from_ulong; val 0));
        data.template.push(attr_element!(CKA_PUBLIC_EXPONENT; req true; def false; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectTemplate for RSAPubTemplate {
    fn create(&self, mut obj: Object) -> KResult<Object> {
        let mut attr_checker = self.template.clone();

        let mut ret =
            self.basic_object_attrs_checks(&mut obj, &mut attr_checker);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        ret = self.pubkey_create_attrs_checks(&mut obj, &mut attr_checker);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        match obj.get_attr_as_ulong(CKA_MODULUS_BITS) {
            Ok(_) => return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID),
            Err(e) => match e {
                KError::NotFound(_) => (),
                _ => return Err(e),
            },
        }
        if modulus.len() < MIN_RSA_SIZE_BYTES {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);

        Ok(obj)
    }

    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl CommonKeyTemplate for RSAPubTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl PubKeyTemplate for RSAPubTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

#[derive(Debug)]
pub struct RSAPrivTemplate {
    template: Vec<ObjectAttr>,
}

impl RSAPrivTemplate {
    pub fn new() -> RSAPrivTemplate {
        let mut data: RSAPrivTemplate = RSAPrivTemplate {
            template: Vec::new(),
        };
        data.init_common_object_attrs();
        data.init_common_storage_attrs();
        data.init_common_key_attrs();
        data.init_common_private_key_attrs();
        data.template.push(attr_element!(CKA_MODULUS; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PUBLIC_EXPONENT; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PRIVATE_EXPONENT; req true; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PRIME_1; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_PRIME_2; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_EXPONENT_1; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_EXPONENT_2; req false; def false; from_bytes; val Vec::new()));
        data.template.push(attr_element!(CKA_COEFFICIENT; req false; def false; from_bytes; val Vec::new()));
        data
    }
}

impl ObjectTemplate for RSAPrivTemplate {
    fn create(&self, mut obj: Object) -> KResult<Object> {
        let mut attr_checker = self.template.clone();

        let mut ret =
            self.basic_object_attrs_checks(&mut obj, &mut attr_checker);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        ret = self.privkey_create_attrs_checks(&mut obj, &mut attr_checker);
        if ret != CKR_OK {
            return err_rv!(ret);
        }

        let modulus = match obj.get_attr_as_bytes(CKA_MODULUS) {
            Ok(m) => m,
            Err(_) => return err_rv!(CKR_TEMPLATE_INCOMPLETE),
        };
        if modulus.len() < MIN_RSA_SIZE_BYTES {
            return err_rv!(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        bytes_attr_not_empty!(obj; CKA_PUBLIC_EXPONENT);
        bytes_attr_not_empty!(obj; CKA_PRIVATE_EXPONENT);

        Ok(obj)
    }

    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl CommonKeyTemplate for RSAPrivTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

impl PrivKeyTemplate for RSAPrivTemplate {
    fn get_template(&mut self) -> &mut Vec<ObjectAttr> {
        &mut self.template
    }
}

fn check_key_object(key: &Object, public: bool, op: CK_ULONG) -> KResult<()> {
    match key.get_attr_as_ulong(CKA_CLASS)? {
        CKO_PUBLIC_KEY => {
            if !public {
                return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
            }
        }
        CKO_PRIVATE_KEY => {
            if public {
                return err_rv!(CKR_KEY_TYPE_INCONSISTENT);
            }
        }
        _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
    }
    match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        CKK_RSA => (),
        _ => return err_rv!(CKR_KEY_TYPE_INCONSISTENT),
    }
    match key.get_attr_as_bool(op) {
        Ok(avail) => {
            if !avail {
                return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED);
            }
        }
        Err(_) => return err_rv!(CKR_KEY_FUNCTION_NOT_PERMITTED),
    }
    Ok(())
}

#[derive(Debug)]
struct RsaPKCSMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for RsaPKCSMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn encryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: Object,
    ) -> KResult<Box<dyn Operation>> {
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(&key, true, CKA_ENCRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        let op = RsaPKCSEncrypt {
            mech: mech.mechanism,
            key: key,
        };
        Ok(Box::new(op))
    }

    fn decryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: Object,
    ) -> KResult<Box<dyn Operation>> {
        if mech.mechanism != CKM_RSA_PKCS {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return err_rv!(CKR_MECHANISM_INVALID);
        }
        match check_key_object(&key, false, CKA_DECRYPT) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        let op = RsaPKCSDecrypt {
            mech: mech.mechanism,
            key: key,
        };
        Ok(Box::new(op))
    }
}

pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectTemplates) {
    mechs.add_mechanism(
        CKM_RSA_PKCS,
        Box::new(RsaPKCSMechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: 1024,
                ulMaxKeySize: 4096,
                flags: CKF_ENCRYPT | CKF_DECRYPT,
            },
        }),
    );

    ot.add_template(ObjectType::RSAPubKey, Box::new(RSAPubTemplate::new()));
    ot.add_template(ObjectType::RSAPrivKey, Box::new(RSAPrivTemplate::new()));
}

#[derive(Debug)]
struct RsaPKCSEncrypt {
    mech: CK_MECHANISM_TYPE,
    key: Object,
    /* TODO: whatever state is needed by crypto library */
}

impl Operation for RsaPKCSEncrypt {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
}

impl Encryption for RsaPKCSEncrypt {
    fn encrypt(_data: Vec<u8>) -> KResult<Vec<u8>> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_update(_data: Vec<u8>) -> KResult<Vec<u8>> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_final() -> KResult<Vec<u8>> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

#[derive(Debug)]
struct RsaPKCSDecrypt {
    mech: CK_MECHANISM_TYPE,
    key: Object,
    /* TODO: whatever state is needed by crypto library */
}

impl Operation for RsaPKCSDecrypt {
    fn mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mech
    }
}

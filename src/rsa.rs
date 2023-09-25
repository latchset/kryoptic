// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::attribute;
use super::error;
use super::interface;
use super::object;
use super::{attr_element, bytes_attr_not_empty, err_rv};
use attribute::{from_bytes, from_ulong};
use error::{KError, KResult};
use interface::*;
use object::{
    CommonKeyTemplate, Object, ObjectAttr, ObjectTemplate, PrivKeyTemplate,
    PubKeyTemplate,
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

// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::interface;
use super::attribute;
use super::error;
use interface::*;
use attribute::Attribute;
use error::{KResult, KError, CkRvError};

use serde::{Serialize, Deserialize};
use serde_json::{Map, Value};

macro_rules! bool_attribute {
    ($name:expr; from $map:expr; def $def:expr) => {
        {
            for a in $map {
                if a.get_type() == $name {
                    match a.to_bool() {
                        Ok(b) => return Ok(b),
                        Err(_) => (),
                    }
                }
            }
            Ok($def)
        }
    }
}

static SENSITIVE_CKK_RSA: [CK_ULONG; 6] = [
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
];

static SENSITIVE_CKK_EC: [CK_ULONG; 1] = [
    CKA_VALUE,
];

static SENSITIVE_CKK_DH: [CK_ULONG; 2] = [
    CKA_VALUE,
    CKA_VALUE_BITS,
];

static SENSITIVE_CKK_DSA: [CK_ULONG; 1] = [
    CKA_VALUE,
];

static SENSITIVE_CKK_GENERIC_SECRET: [CK_ULONG; 2] = [
    CKA_VALUE,
    CKA_VALUE_LEN,
];

static SENSITIVE: [(CK_ULONG, &[CK_ULONG]); 8] = [
    (CKK_RSA, &SENSITIVE_CKK_RSA),
    (CKK_EC, &SENSITIVE_CKK_EC),
    (CKK_EC_EDWARDS, &SENSITIVE_CKK_EC),
    (CKK_EC_MONTGOMERY, &SENSITIVE_CKK_EC),
    (CKK_DH, &SENSITIVE_CKK_DH),
    (CKK_X9_42_DH, &SENSITIVE_CKK_DH),
    (CKK_DSA, &SENSITIVE_CKK_DSA),
    (CKK_GENERIC_SECRET, &SENSITIVE_CKK_GENERIC_SECRET),
];

#[derive(Debug, Clone)]
pub struct Object {
    handle: interface::CK_OBJECT_HANDLE,
    attributes: Vec<Attribute>
}

impl Object {
    pub fn new() -> Object {
        Object {
            handle: 0,
            attributes: Vec::new(),
        }
    }

    pub fn get_handle(&self) -> interface::CK_OBJECT_HANDLE {
        self.handle
    }

    pub fn is_token(&self) -> KResult<bool> {
        bool_attribute!(interface::CKA_TOKEN; from &self.attributes; def false)
    }
    pub fn is_private(&self) -> KResult<bool> {
        bool_attribute!(interface::CKA_PRIVATE; from &self.attributes; def true)
    }
    pub fn is_modifiable(&self) -> KResult<bool> {
        bool_attribute!(interface::CKA_MODIFIABLE; from &self.attributes; def true)
    }
    pub fn is_destroyable(&self) -> KResult<bool> {
        bool_attribute!(interface::CKA_DESTROYABLE; from &self.attributes; def false)
    }
    fn set_attr(&mut self, a: Attribute) -> KResult<()> {
        let mut idx = self.attributes.len();
        for (i, elem) in self.attributes.iter().enumerate() {
            if a.get_type() == elem.get_type() {
                idx = i;
                break;
            }
        }
        if idx < self.attributes.len() {
            self.attributes[idx] = a;
        } else {
            self.attributes.push(a);
        }
        Ok(())
    }
    pub fn set_attr_from_ulong(&mut self, s: String, u: CK_ULONG) -> KResult<()> {
        let a = match attribute::from_string_ulong(s, u) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        self.set_attr(a)
    }
    pub fn set_attr_from_string(&mut self, s: String, v: String) -> KResult<()> {
        let a = match attribute::from_string_string(s, v) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        self.set_attr(a)
    }
    pub fn set_attr_from_bool(&mut self, s: String, b: bool) -> KResult<()> {
        let a = match attribute::from_string_bool(s, b) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        self.set_attr(a)
    }
    pub fn set_attr_from_bytes(&mut self, s: String, v: Vec<u8>) -> KResult<()> {
        let a = match attribute::from_string_bytes(s, v) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        self.set_attr(a)
    }

    pub fn match_template(&self, template: &[interface::CK_ATTRIBUTE]) -> bool {
        for ck_attr in template.iter() {
            let mut found = false;
            for attr in &self.attributes {
                found = attr.match_ck_attr(ck_attr);
                if found {
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }

    fn private_key_type(&self) -> Option<CK_ULONG> {
        let mut class: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
        let mut key_type: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
        for attr in &self.attributes {
            if attr.get_type() == CKA_CLASS {
                class = attr.to_ulong().ok()?;
                continue;
            }
            if attr.get_type() == CKA_KEY_TYPE {
                key_type = attr.to_ulong().ok()?;
            }
        }
        if class == CKO_PRIVATE_KEY {
            if key_type != CK_UNAVAILABLE_INFORMATION {
                return Some(key_type);
            }
        }
        None
    }

    fn needs_sensitivity_check(&self) -> Option<&[CK_ULONG]> {
        let kt = self.private_key_type()?;
        for tuple in SENSITIVE {
            if tuple.0 == kt {
                return Some(tuple.1);
            }
        }
        None
    }

    fn is_sensitive_attr(&self, id: CK_ULONG, sense: &[CK_ULONG]) -> bool {
        let mut sensitive = false;
        if !sense.contains(&id) {
            return false;
        }
        for attr in &self.attributes {
            if attr.get_type() == CKA_SENSITIVE {
                if attr.to_bool().unwrap_or(false) {
                    sensitive = true;
                } else {
                    return false;
                }
                continue;
            }
            if attr.get_type() == CKA_EXTRACTABLE {
                if !attr.to_bool().unwrap_or(true) {
                    sensitive = true;
                }
                continue;
            }
        }
        sensitive
    }

    pub fn fill_template(&self, template: &mut [CK_ATTRIBUTE]) -> KResult<()> {
        let sense = self.needs_sensitivity_check();
        let mut rv = CKR_OK;
        for elem in template.iter_mut() {
            if let Some(s) = sense {
                if self.is_sensitive_attr(elem.type_, s) {
                    elem.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_SENSITIVE;
                    continue;
                }
            }
            let mut found = false;
            for attr in &self.attributes {
                if attr.get_type() == elem.type_ {
                    found = true;
                    if elem.pValue.is_null() {
                        elem.ulValueLen = attr.get_value().len() as CK_ULONG;
                        break;
                    }
                    let val = attr.get_value();
                    if (elem.ulValueLen as usize) < val.len() {
                        elem.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        rv = interface::CKR_BUFFER_TOO_SMALL;
                        break;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(val.as_ptr(), elem.pValue as *mut _, val.len());
                    }
                    elem.ulValueLen = val.len() as CK_ULONG;
                    break;
                }
            }
            if !found {
                elem.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
        }
        if rv == CKR_OK {
            return Ok(());
        }
        Err(KError::RvError(CkRvError{rv: rv}))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonObject {
    handle: interface::CK_OBJECT_HANDLE,
    attributes: Map<String, Value>
}

pub fn objects_to_json(objs: &Vec<Object>) -> Vec<JsonObject> {
    let mut jobjs = Vec::new();

    for o in objs {
        let mut jo = JsonObject {
            handle: o.handle,
            attributes: Map::new()
        };
        for a in &o.attributes {
            jo.attributes.insert(a.name(), a.value());
        }
        jobjs.push(jo);
    }
    jobjs
}

pub fn json_to_objects(jobjs: &Vec<JsonObject>) -> Vec<Object> {
    let mut objs = Vec::new();

    for jo in jobjs {
        let mut o = Object {
            handle: jo.handle,
            attributes: Vec::new(),
        };
        for jk in jo.attributes.keys() {
            let a = match attribute::from_value(jk.clone(), jo.attributes.get(jk).unwrap()) {
                Ok(a) => a,
                Err(_) => continue,
            };
            o.attributes.push(a);
        }
        objs.push(o);
    }
    objs
}

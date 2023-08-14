// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::interface;
use super::attribute;
use super::error;
use attribute::Attribute;
use error::KResult;

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
        let mut idx = 0;
        while idx < self.attributes.len() {
            if a.get_type() == self.attributes[idx].get_type() {
                break;
            }
            idx += 1;
        }
        if idx < self.attributes.len() {
            self.attributes[idx] = a;
        } else {
            self.attributes.push(a);
        }
        Ok(())
    }
    pub fn set_attr_from_ulong(&mut self, s: String, u: interface::CK_ULONG) -> KResult<()> {
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

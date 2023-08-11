// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use core::fmt::Debug;

use super::interface;

use serde::{Serialize, Deserialize};
use serde_json::{json, Map, Value};

pub trait Object {
    fn get_handle(&self) -> interface::CK_OBJECT_HANDLE;
    fn get_class(&self) -> interface::CK_OBJECT_CLASS;
}

macro_rules! object_constructor {
    ($name:ty) => {
        impl Object for $name {
            fn get_handle(&self) -> interface::CK_OBJECT_HANDLE {
                self.handle
            }

            fn get_class(&self) -> interface::CK_OBJECT_CLASS {
                self.class
            }
        }
    }
}

impl Debug for dyn Object {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Something!")
    }
}

// TODO: HW Feature Objects

macro_rules! bool_attribute {
    ($name:expr; from $map:expr; def $def:expr) => {
        match $map.get($name) {
            Some(Value::Bool(b)) => *b,
            _ => $def
        }
    }
}

macro_rules! str_attribute {
    ($name:expr; from $map:expr) => {
        match $map.get($name) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None
        }
    }
}

pub trait Storage {
    fn is_token(&self) -> bool {
        false
    }
    fn is_private(&self) -> bool;
    fn is_modifiable(&self) -> bool {
        true
    }
    fn is_copyable(&self) -> bool {
        true
    }
    fn is_destroyable(&self) -> bool {
        true
    }
    fn get_label(&self) -> Option<String> {
        None
    }
    fn get_unique_id(&self) -> Option<String> {
        None
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyObject {
    handle: interface::CK_OBJECT_HANDLE,
    class: interface::CK_OBJECT_CLASS,
    key_type: interface::CK_KEY_TYPE,
    attributes: Map<String, Value>,
}

impl Storage for KeyObject {
    fn is_token(&self) -> bool {
        bool_attribute!("CKA_TOKEN"; from self.attributes; def false)
    }
    fn is_private(&self) -> bool {
        bool_attribute!("CKA_PRIVATE"; from self.attributes; def true)
    }
    fn is_modifiable(&self) -> bool {
        bool_attribute!("CKA_MODIFIABLE"; from self.attributes; def true)
    }
    fn is_destroyable(&self) -> bool {
        bool_attribute!("CKA_DESTROYABLE"; from self.attributes; def false)
    }
    fn get_label(&self) -> Option<String> {
        str_attribute!("CKA_LABEL"; from self.attributes)
    }
    fn get_unique_id(&self) -> Option<String> {
        str_attribute!("CKA_ID"; from self.attributes)
    }
}
object_constructor!(KeyObject);

impl KeyObject {
    pub fn new() -> KeyObject {
        KeyObject {
            handle: 0,
            class: interface::CKO_PUBLIC_KEY,
            key_type: interface::CKK_RSA,
            attributes: Map::new(),
        }
    }

    pub fn test_object() -> KeyObject {
        let mut o = KeyObject {
            handle: 1234,
            class: interface::CKO_PUBLIC_KEY,
            key_type: interface::CKK_RSA,
            attributes: Map::new(),
        };

        o.attributes.insert("CKA_TOKEN".to_string(), Value::Bool(true));
        o.attributes.insert("CKA_PRIVATE".to_string(), Value::Bool(false));
        o.attributes.insert("CKA_MODIFIABLE".to_string(), Value::Bool(false));
        o.attributes.insert("CKA_DESTROYABLE".to_string(), Value::Bool(false));
        o.attributes.insert("CKA_LABEL".to_string(), Value::String("Test RSA Key".to_string()));
        o.attributes.insert("CKA_ID".to_string(), Value::String("10000001".to_string()));
        o.attributes.insert("CKA_MODULUS".to_string(), Value::String("change me to base64 num".to_string()));
        o.attributes.insert("CKA_PUBLIC_EXPONENT".to_string(), Value::String("10000001".to_string()));

        o
    }
}

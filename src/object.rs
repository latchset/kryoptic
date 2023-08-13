// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use core::fmt::Debug;
use data_encoding::BASE64;

use super::interface;
use super::error;
use error::{KResult, KError, CkRvError, AttributeNotFound};

use serde::{Serialize, Deserialize};
use serde_json::{Map, Value, Number};

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
        write!(f, "FIXME!")
    }
}

// TODO: HW Feature Objects

macro_rules! bool_attribute {
    ($name:expr; from $map:expr; def $def:expr) => {
        match $map.get(&$name) {
            Some(Value::Bool(b)) => Ok(*b),
            None => Ok($def),
            _ => Err(KError::RvError(CkRvError{ rv: interface::CKR_ATTRIBUTE_TYPE_INVALID }))
        }
    };
    ($name:expr; from $map:expr) => {
        match $map.get(&$name) {
            Some(Value::Bool(b)) => Ok(*b),
            None => Err(KError::NotFound(AttributeNotFound{ s: $name})),
            _ => Err(KError::RvError(CkRvError{ rv: interface::CKR_ATTRIBUTE_TYPE_INVALID }))
        }
    };
}

macro_rules! str_attribute {
    ($name:expr; from $map:expr) => {
        match $map.get(&$name) {
            Some(Value::String(s)) => Ok(s.clone()),
            None => Err(KError::NotFound(AttributeNotFound{ s: $name})),
            _ => Err(KError::RvError(CkRvError{ rv: interface::CKR_ATTRIBUTE_TYPE_INVALID }))
        }
    }
}

macro_rules! bytes_attribute {
    ($name:expr; from $map:expr) => {
        match $map.get(&$name) {
            Some(Value::String(s)) => {
                let len = match BASE64.decode_len(s.len()) {
                    Ok(l) => l,
                    Err(_e) => return Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR })),
                };
                let mut output = vec![0; len];
                match BASE64.decode_mut(s.as_bytes(), &mut output) {
                    Ok(_) => Ok(output),
                    Err(_e) => Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR })),
                }
            },
            None => Err(KError::NotFound(AttributeNotFound{ s: $name})),
            _ => Err(KError::RvError(CkRvError{ rv: interface::CKR_ATTRIBUTE_TYPE_INVALID }))
        }
    }
}

macro_rules! ulong_set_attribute {
    ($name:expr; $value:expr; into $map:expr) => {
        {
            let old = match $map.insert($name, Value::Number(Number::from($value))) {
                Some(o) => o,
                None => Value::Null
            };
            Ok(old)
        }
    }
}

macro_rules! string_set_attribute {
    ($name:expr; $value:expr; into $map:expr) => {
        {
            let old = match $map.insert($name, Value::String($value)) {
                Some(o) => o,
                None => Value::Null
            };
            Ok(old)
        }
    }
}

macro_rules! bool_set_attribute {
    ($name:expr; $value:expr; into $map:expr) => {
        {
            let old = match $map.insert($name, Value::Bool($value)) {
                Some(o) => o,
                None => Value::Null
            };
            Ok(old)
        }
    }
}

macro_rules! bytes_set_attribute {
    ($name:expr; $value:expr; into $map:expr) => {
        {
            let sval = BASE64.encode($value.as_ref());
            let old = match $map.insert($name, Value::String(sval)) {
                Some(o) => o,
                None => Value::Null
            };
            Ok(old)
        }
    }
}

macro_rules! with {
    ($str:expr) => {
        {
            $str.to_string()
        }
    }
}

pub trait Storage {
    fn is_token(&self) -> KResult<bool> {
        Ok(false)
    }
    fn is_private(&self) -> KResult<bool>;
    fn is_modifiable(&self) -> KResult<bool> {
        Ok(true)
    }
    fn is_copyable(&self) -> KResult<bool> {
        Ok(true)
    }
    fn is_destroyable(&self) -> KResult<bool> {
        Ok(true)
    }
    fn get_label(&self) -> KResult<String> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn get_unique_id(&self) -> KResult<String> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn get_attr_as_string(&self, _s: String) -> KResult<String> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn get_attr_as_bool(&self, _s: String) -> KResult<bool> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn get_attr_as_bytes(&self, _s: String) -> KResult<Vec<u8>> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn set_attr_from_ulong(&mut self, _s: String, _u: interface::CK_ULONG) -> KResult<Value> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn set_attr_from_string(&mut self, _s: String, _v: String) -> KResult<Value> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn set_attr_from_bool(&mut self, _s: String, _b: bool) -> KResult<Value> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
    }
    fn set_attr_from_bytes(&mut self, _s: String, _u: Vec<u8>) -> KResult<Value> {
        Err(KError::RvError(CkRvError{ rv: interface::CKR_GENERAL_ERROR }))
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
    fn is_token(&self) -> KResult<bool> {
        bool_attribute!(with!("CKA_TOKEN"); from self.attributes; def false)
    }
    fn is_private(&self) -> KResult<bool> {
        bool_attribute!(with!("CKA_PRIVATE"); from self.attributes; def true)
    }
    fn is_modifiable(&self) -> KResult<bool> {
        bool_attribute!(with!("CKA_MODIFIABLE"); from self.attributes; def true)
    }
    fn is_destroyable(&self) -> KResult<bool> {
        bool_attribute!(with!("CKA_DESTROYABLE"); from self.attributes; def false)
    }
    fn get_label(&self) -> KResult<String> {
        str_attribute!(with!("CKA_LABEL"); from self.attributes)
    }
    fn get_unique_id(&self) ->  KResult<String>{
        str_attribute!(with!("CKA_ID"); from self.attributes)
    }
    fn get_attr_as_string(&self, s:String) -> KResult<String> {
        str_attribute!(s; from self.attributes)
    }
    fn get_attr_as_bool(&self, s:String) -> KResult<bool> {
        bool_attribute!(s; from self.attributes)
    }
    fn get_attr_as_bytes(&self, s: String) -> KResult<Vec<u8>> {
        bytes_attribute!(s; from self.attributes)
    }
    fn set_attr_from_ulong(&mut self, s: String, u: interface::CK_ULONG) -> KResult<Value> {
        ulong_set_attribute!(s; u; into self.attributes)
    }
    fn set_attr_from_string(&mut self, s: String, v: String) -> KResult<Value> {
        string_set_attribute!(s; v; into self.attributes)
    }
    fn set_attr_from_bool(&mut self, s: String, b: bool) -> KResult<Value> {
        bool_set_attribute!(s; b; into self.attributes)
    }
    fn set_attr_from_bytes(&mut self, s: String, u: Vec<u8>) -> KResult<Value> {
        bytes_set_attribute!(s; u; into self.attributes)
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

    pub fn match_template(&self, template: &[interface::CK_ATTRIBUTE]) -> bool {
        for attr in template.iter() {
            /* special attrs we store as native elements */
            match attr.type_ {
                interface::CKA_CLASS => match attr.to_ulong() {
                    Ok(aval) => {
                        if self.class == aval {
                            continue;
                        } else {
                            return false;
                        }
                    }
                    Err(_) => return false,
                },
                interface::CKA_KEY_TYPE => match attr.to_ulong() {
                    Ok(aval) => {
                        if self.key_type == aval {
                            continue;
                        } else {
                            return false;
                        }
                    }
                    Err(_) => return false,
                },
                _ => (),
            }
            /* all others */
            let elem = attrmap_element(attr.type_ as usize);
            match self.attributes.get(&elem.name.to_string()) {
                Some(Value::Bool(ebool)) => {
                    if elem.type_ != AttrType::BoolType {
                        return false;
                    }
                    match attr.to_bool() {
                        Ok(abool) => {
                            if *ebool != abool {
                                return false;
                            }
                        },
                        Err(_) => return false,
                    }
                },
                Some(Value::Number(eval)) => {
                    if elem.type_ != AttrType::NumType {
                        return false;
                    }
                    match attr.to_ulong() {
                        Ok(aval) => {
                            if eval.as_u64() != Some(aval as u64) {
                                return false;
                            }
                        },
                        Err(_) => return false,
                    }
                },
                Some(Value::String(estr)) => {
                    if elem.type_ == AttrType::BytesType {
                        let len = match BASE64.decode_len(estr.len()) {
                            Ok(l) => l,
                            Err(_) => return false,
                        };
                        let mut ebuf = vec![0; len];
                        match BASE64.decode_mut(estr.as_bytes(), &mut ebuf) {
                            Ok(_) => (),
                            Err(_) => return false,
                        };
                        let abuf = attr.to_buf().unwrap();
                        if abuf != ebuf {
                            return false;
                        }
                    } else if elem.type_ == AttrType::StringType {
                        match attr.to_string() {
                            Ok(astr) => {
                                if *estr != astr {
                                    return false;
                                }
                            },
                            Err(_) => return false,
                        }
                    }
                    return false;
                },
                _ => return false,
            }
        }
        true
    }
}

use interface::{CK_ATTRIBUTE, CK_ULONG, CK_BBOOL};
impl CK_ATTRIBUTE {
    pub fn to_ulong(self) -> KResult<CK_ULONG> {
        if self.ulValueLen != std::mem::size_of::<CK_ULONG>() as CK_ULONG {
            return Err(KError::RvError(error::CkRvError{rv: interface::CKR_ATTRIBUTE_VALUE_INVALID}));
        }
        let val: &[CK_ULONG] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, 1)
        };
        Ok(val[0])
    }
    pub fn to_bool(self) -> KResult<bool> {
        if self.ulValueLen != std::mem::size_of::<CK_BBOOL>() as CK_ULONG {
            return Err(KError::RvError(error::CkRvError{rv: interface::CKR_ATTRIBUTE_VALUE_INVALID}));
        }
        let val: &[CK_BBOOL] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, 1)
        };
        if val[0] == 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    }
    pub fn to_string(self) ->KResult<String> {
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, self.ulValueLen as usize)
        };
        let utf8str = match std::str::from_utf8(buf) {
            Ok(s) => s,
            Err(_) => return Err(KError::RvError(error::CkRvError{rv: interface::CKR_ATTRIBUTE_VALUE_INVALID})),
        };
        Ok(utf8str.to_string())
    }
    pub fn to_buf(self) ->KResult<Vec<u8>> {
        let buf: &[u8] = unsafe {
            std::slice::from_raw_parts(self.pValue as *const _, self.ulValueLen as usize)
        };
        Ok(buf.to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AttrType {
    BoolType,
    NumType,
    StringType,
    BytesType,
}

#[derive(Debug)]
struct Attrmap<'a> {
    name: &'a str,
    type_: AttrType,
}
#[derive(Debug)]
struct Attrelem {
    name: String,
    type_: AttrType,
}

static ATTRMAP: [Attrmap; 3] = [
    Attrmap { name: "CKA_CLASS", type_: AttrType::NumType },
    Attrmap { name: "CKA_TOKEN", type_: AttrType::BoolType },
    Attrmap { name: "CKA_PRIVATE", type_: AttrType::BoolType },
];

fn attrmap_element(id: usize) -> Attrelem {
    if id < ATTRMAP.len() {
        return Attrelem {
            name: ATTRMAP[id].name.to_string(),
            type_: ATTRMAP[id].type_,
        };
    }
    Attrelem {
        name: id.to_string(),
        type_: AttrType::BytesType,
    }
}

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This crate defines the Serde structures (`JsonObjects`, `JsonObject`,
//! `JsonTokenInfo`) used for serializing and deserializing token state,
//! objects, and user authentication information to/from a JSON file format.
//! It also includes helper functions for converting between PKCS#11
//! `Attribute`s and JSON values.

use std::collections::HashMap;
use std::fmt::Debug;

use crate::attribute::{AttrType, Attribute};
use crate::error::{Error, Result};
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::pkcs11::*;
use crate::storage::aci;
use crate::storage::format::StorageRaw;
use crate::storage::StorageTokenInfo;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, Map, Value};

/// Helper function to convert IO errors, specifically mapping `NotFound` to
/// `CKR_CRYPTOKI_NOT_INITIALIZED` for the storage loading case.
fn uninit(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        Error::ck_rv_from_error(CKR_CRYPTOKI_NOT_INITIALIZED, e)
    } else {
        Error::other_error(e)
    }
}

/// Serializable representation of a single PKCS#11 object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonObject {
    /// Map where keys are attribute names (e.g., "CKA_LABEL") and values
    /// are JSON representations of the attribute values.
    attributes: Map<String, Value>,
}

/// Serializable representation of the `StorageTokenInfo` structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonTokenInfo {
    /// Token label.
    label: String,
    /// Manufacturer ID.
    manufacturer: String,
    /// Token model description.
    model: String,
    /// Token serial number.
    serial: String,
    /// Token flags.
    flags: CK_ULONG,
}

/// Top-level structure representing the entire JSON database file content.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonObjects {
    /// Vector of stored token objects.
    objects: Vec<JsonObject>,
    /// Optional vector of stored user authentication objects (SO, User).
    users: Option<Vec<JsonObject>>,
    /// Optional stored token information.
    token: Option<JsonTokenInfo>,
}

impl JsonObjects {
    /// Loads json objects from a JSON database file
    pub fn load(filename: &str) -> Result<JsonObjects> {
        match std::fs::File::open(filename) {
            Ok(f) => Ok(from_reader::<std::fs::File, JsonObjects>(f)?),
            Err(e) => Err(uninit(e)),
        }
    }

    /// Populates a `StorageRaw` backend (typically an in-memory cache)
    /// with the data loaded from this `JsonObjects` instance (deserialized
    /// from a JSON file).
    pub fn prime_store(&self, store: &mut Box<dyn StorageRaw>) -> Result<()> {
        if let Some(t) = &self.token {
            let mut info = StorageTokenInfo {
                label: [0; 32],
                manufacturer: [0; 32],
                model: [0; 16],
                serial: [0; 16],
                flags: 0,
            };
            copy_sized_string(t.label.as_bytes(), &mut info.label);
            copy_sized_string(
                t.manufacturer.as_bytes(),
                &mut info.manufacturer,
            );
            copy_sized_string(t.model.as_bytes(), &mut info.model);
            copy_sized_string(t.serial.as_bytes(), &mut info.serial);
            info.flags = t.flags;
            store.store_token_info(&info)?;
        }
        if let Some(users) = &self.users {
            for ju in users {
                let mut uid = String::new();
                let mut info = aci::StorageAuthInfo::default();
                for (key, val) in &ju.attributes {
                    match key.as_str() {
                        "name" => match val.as_str() {
                            Some(s) => uid.push_str(s),
                            None => return Err(CKR_DEVICE_ERROR)?,
                        },
                        "default_pin" => match val.as_bool() {
                            Some(b) => info.default_pin = b,
                            None => return Err(CKR_DEVICE_ERROR)?,
                        },
                        "attempts" => match val.as_u64() {
                            Some(u) => {
                                info.cur_attempts = CK_ULONG::try_from(u)?
                            }
                            None => return Err(CKR_DEVICE_ERROR)?,
                        },
                        "data" => match val.as_str() {
                            Some(s) => {
                                let len = match BASE64.decode_len(s.len()) {
                                    Ok(l) => l,
                                    Err(_) => return Err(CKR_DEVICE_ERROR)?,
                                };
                                let mut v = vec![0; len];
                                match BASE64.decode_mut(s.as_bytes(), &mut v) {
                                    Ok(l) => v.resize(l, 0),
                                    Err(_) => return Err(CKR_DEVICE_ERROR)?,
                                }
                                info.user_data = Some(v);
                            }
                            None => return Err(CKR_DEVICE_ERROR)?,
                        },
                        _ => (), /* ignore unknown */
                    }
                }
                store.store_user(uid.as_str(), &info)?;
            }
        }
        for jo in &self.objects {
            let mut obj = Object::new(CK_UNAVAILABLE_INFORMATION);
            for (key, val) in &jo.attributes {
                let (id, atype) = AttrType::attr_name_to_id_type(key)?;
                let attr = match atype {
                    AttrType::BoolType => match val.as_bool() {
                        Some(b) => Attribute::from_bool(id, b),
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::NumType => match val.as_u64() {
                        Some(n) => Attribute::from_u64(id, n),
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::StringType => match val.as_str() {
                        Some(s) => Attribute::from_string(id, s.to_string()),
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::BytesType => match val.as_str() {
                        Some(s) => {
                            let len = match BASE64.decode_len(s.len()) {
                                Ok(l) => l,
                                Err(_) => return Err(CKR_GENERAL_ERROR)?,
                            };
                            let mut v = vec![0; len];
                            match BASE64.decode_mut(s.as_bytes(), &mut v) {
                                Ok(l) => {
                                    Attribute::from_bytes(id, v[0..l].to_vec())
                                }
                                Err(_) => return Err(CKR_GENERAL_ERROR)?,
                            }
                        }
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::UlongArrayType => match val.as_array() {
                        Some(a) => {
                            let mut v = Vec::<CK_ULONG>::with_capacity(a.len());
                            for elem in a.iter() {
                                match elem.as_u64() {
                                    Some(n) => v.push(CK_ULONG::try_from(n)?),
                                    None => {
                                        return Err(
                                            CKR_ATTRIBUTE_VALUE_INVALID,
                                        )?
                                    }
                                }
                            }
                            Attribute::from_ulong_array(id, v)
                        }
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::DateType => match val.as_str() {
                        Some(s) => {
                            if s.len() == 0 {
                                /* special case for default empty value */
                                Attribute::from_date_bytes(id, Vec::new())
                            } else {
                                Attribute::from_date(id, string_to_ck_date(&s)?)
                            }
                        }
                        None => return Err(CKR_ATTRIBUTE_VALUE_INVALID)?,
                    },
                    AttrType::DenyType => continue,
                    AttrType::IgnoreType => continue,
                };

                obj.set_attr(attr)?;
            }
            if obj.get_class() == CK_UNAVAILABLE_INFORMATION {
                return Err(CKR_GENERAL_ERROR)?;
            }
            store.store_obj(obj)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TransferStorage {
    objects: HashMap<String, Object>,
}

impl TransferStorage {
    pub fn new() -> Box<dyn StorageRaw> {
        Box::new(TransferStorage {
            objects: HashMap::new(),
        })
    }
}

impl StorageRaw for TransferStorage {
    fn search(&self, template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>> {
        let mut ret = Vec::<Object>::new();
        for (_, o) in self.objects.iter() {
            if o.match_template(template) {
                ret.push(o.clone());
            }
        }
        Ok(ret)
    }
    fn store_obj(&mut self, obj: Object) -> Result<()> {
        let uid = obj.get_attr_as_string(CKA_UNIQUE_ID)?;
        self.objects.insert(uid, obj);
        Ok(())
    }
}

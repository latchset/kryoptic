// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::{Error, Result};
use crate::interface::*;
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::storage::aci::StorageACI;
use crate::storage::format::{StdStorageFormat, StorageRaw};
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};

const TOKEN_INFO_UID: &str = "2";

pub fn token_info_uid() -> String {
    TOKEN_INFO_UID.to_string()
}

pub fn object_to_token_info(obj: &Object) -> Result<StorageTokenInfo> {
    if obj.get_attr_as_ulong(CKA_CLASS)? != KRO_TOKEN_DATA {
        return Err(CKR_TOKEN_NOT_RECOGNIZED)?;
    }
    let label = obj
        .get_attr_as_string(CKA_LABEL)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let manufacturer = obj
        .get_attr_as_string(KRA_MANUFACTURER_ID)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let model = obj
        .get_attr_as_string(KRA_MODEL)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let serial = obj
        .get_attr_as_string(KRA_SERIAL_NUMBER)
        .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?;
    let mut info = StorageTokenInfo {
        label: [0; 32],
        manufacturer: [0; 32],
        model: [0; 16],
        serial: [0; 16],
        flags: obj
            .get_attr_as_ulong(KRA_FLAGS)
            .map_err(|_| CKR_TOKEN_NOT_RECOGNIZED)?,
    };
    copy_sized_string(label.as_bytes(), &mut info.label);
    copy_sized_string(manufacturer.as_bytes(), &mut info.manufacturer);
    copy_sized_string(model.as_bytes(), &mut info.model);
    copy_sized_string(serial.as_bytes(), &mut info.serial);
    Ok(info)
}

pub fn token_info_to_object(
    info: &StorageTokenInfo,
    obj: &mut Object,
) -> Result<()> {
    obj.set_attr(Attribute::string_from_sized(CKA_LABEL, &info.label))?;
    obj.set_attr(Attribute::string_from_sized(
        KRA_MANUFACTURER_ID,
        &info.manufacturer,
    ))?;
    obj.set_attr(Attribute::string_from_sized(KRA_MODEL, &info.model))?;
    obj.set_attr(Attribute::string_from_sized(
        KRA_SERIAL_NUMBER,
        &info.serial,
    ))?;

    /* filter out runtime flags */
    let flags = info.flags
        & (CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED);
    obj.set_attr(Attribute::from_ulong(KRA_FLAGS, flags))?;
    Ok(())
}

#[derive(Debug)]
struct MemoryStorage {
    objects: HashMap<String, Object>,
}

impl StorageRaw for MemoryStorage {
    fn is_initialized(&self) -> Result<()> {
        if self.objects.len() != 0 {
            Ok(())
        } else {
            Err(CKR_CRYPTOKI_NOT_INITIALIZED)?
        }
    }
    fn db_reset(&mut self) -> Result<()> {
        self.objects.clear();
        Ok(())
    }
    fn open(&mut self) -> Result<()> {
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn fetch_by_uid(&self, uid: &String, _: &[CK_ATTRIBUTE]) -> Result<Object> {
        /* we always return all attributes regardless as it is cheap
         * and easy, the upper layers always filter out attributes as
         * needed anyway */
        match self.objects.get(uid) {
            Some(o) => Ok(o.clone()),
            None => Err(Error::not_found(uid.clone())),
        }
    }
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
    fn remove_by_uid(&mut self, uid: &String) -> Result<()> {
        self.objects.remove(uid);
        Ok(())
    }

    fn fetch_token_info(&self) -> Result<StorageTokenInfo> {
        let obj = self.fetch_by_uid(&token_info_uid(), &[])?;
        object_to_token_info(&obj)
    }

    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        let mut obj = Object::new();
        obj.set_attr(Attribute::from_string(CKA_UNIQUE_ID, token_info_uid()))?;
        obj.set_attr(Attribute::from_bool(CKA_TOKEN, true))?;
        obj.set_attr(Attribute::from_ulong(CKA_CLASS, KRO_TOKEN_DATA))?;
        token_info_to_object(info, &mut obj)?;
        self.store_obj(obj)
    }
}

pub fn raw_store() -> Box<dyn StorageRaw> {
    Box::new(MemoryStorage {
        objects: HashMap::new(),
    })
}

#[derive(Debug)]
pub struct MemoryDBInfo {
    db_type: &'static str,
}

impl StorageDBInfo for MemoryDBInfo {
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>> {
        let encrypt = match conf {
            Some(s) => match s.as_str() {
                "flags=encrypt" => true,
                _ => return Err(CKR_ARGUMENTS_BAD)?,
            },
            None => false,
        };
        let raw_store = raw_store();
        Ok(Box::new(StdStorageFormat::new(
            raw_store,
            StorageACI::new(encrypt),
        )))
    }

    fn dbtype(&self) -> &str {
        self.db_type
    }
}

pub static DBINFO: MemoryDBInfo = MemoryDBInfo { db_type: "memory" };

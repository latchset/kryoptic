// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::fmt::Debug;

use crate::error::{Error, Result};
use crate::interface::*;
use crate::object::Object;
use crate::storage::aci;
use crate::storage::format;
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};

#[derive(Debug)]
struct MemoryStorage {
    objects: HashMap<String, Object>,
    token_info: StorageTokenInfo,
    users: HashMap<String, aci::StorageAuthInfo>,
}

impl format::StorageRaw for MemoryStorage {
    fn is_initialized(&self) -> Result<()> {
        if self.token_info.flags & CKF_TOKEN_INITIALIZED != 0 {
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
        Ok(self.token_info.clone())
    }

    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        self.token_info.label = info.label;
        self.token_info.manufacturer = info.manufacturer;
        self.token_info.model = info.model;
        self.token_info.serial = info.serial;
        self.token_info.flags = info.flags;
        Ok(())
    }

    fn fetch_user(&self, uid: &str) -> Result<aci::StorageAuthInfo> {
        match self.users.get(uid) {
            Some(u) => Ok(u.clone()),
            None => Err(CKR_USER_PIN_NOT_INITIALIZED)?,
        }
    }

    fn store_user(
        &mut self,
        uid: &str,
        data: &aci::StorageAuthInfo,
    ) -> Result<()> {
        self.users.insert(uid.to_string(), data.clone());
        Ok(())
    }
}

pub fn raw_store() -> Box<dyn format::StorageRaw> {
    Box::new(MemoryStorage {
        objects: HashMap::new(),
        token_info: StorageTokenInfo::default(),
        users: HashMap::new(),
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
        Ok(Box::new(format::StdStorageFormat::new(
            raw_store,
            aci::StorageACI::new(encrypt),
        )))
    }

    fn dbtype(&self) -> &str {
        self.db_type
    }
}

pub static DBINFO: MemoryDBInfo = MemoryDBInfo { db_type: "memory" };

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::HashMap;
use std::fmt::Debug;

use crate::error::{Error, Result};
use crate::interface::*;
use crate::object::Object;
use crate::storage::aci::StorageACI;
use crate::storage::format::{StdStorageFormat, StorageRaw};
use crate::storage::{Storage, StorageDBInfo};

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
    fn fetch_by_uid(&self, uid: &String) -> Result<Object> {
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
}

pub fn raw_store() -> Box<dyn StorageRaw> {
    Box::new(MemoryStorage {
        objects: HashMap::new(),
    })
}

#[derive(Debug)]
pub struct MemoryDBInfo {
    db_type: &'static str,
    db_suffix: &'static str,
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

    fn dbsuffix(&self) -> &str {
        self.db_suffix
    }
}

pub static DBINFO: MemoryDBInfo = MemoryDBInfo {
    db_type: "memory",
    db_suffix: "",
};

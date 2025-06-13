// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides an in-memory storage backend implementation
//! (`MemoryStorage`) that fulfills the `StorageRaw` trait. It's primarily
//! used for testing, ephemeral tokens, or as a cache layer for other backends
//! (like JSON).

use std::collections::HashMap;
use std::fmt::Debug;

use crate::error::{Error, Result};
use crate::object::Object;
use crate::storage::aci;
use crate::storage::format;
use crate::storage::{Storage, StorageDBInfo, StorageTokenInfo};

use pkcs11::*;

/// In-memory implementation of the raw storage backend trait (`StorageRaw`).
/// Uses HashMaps to store objects and user authentication info.
#[derive(Debug)]
struct MemoryStorage {
    /// Map from internal UID (String) to the stored `Object`.
    objects: HashMap<String, Object>,
    /// Stored token information.
    token_info: StorageTokenInfo,
    /// Map from user ID ("SO" or "USER") to their authentication info.
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

/// Factory function to create a new boxed `MemoryStorage` instance.
pub fn raw_store() -> Box<dyn format::StorageRaw> {
    Box::new(MemoryStorage {
        objects: HashMap::new(),
        token_info: StorageTokenInfo::default(),
        users: HashMap::new(),
    })
}

/// Information provider for the in-memory storage backend discovery.
#[derive(Debug)]
pub struct MemoryDBInfo {
    /// The unique type name for this backend ("memory").
    db_type: &'static str,
}

impl StorageDBInfo for MemoryDBInfo {
    /// Creates a new in-memory storage instance, wrapping it in the standard
    /// ACI layer.  Optionally enables encryption via `conf` string
    /// "flags=encrypt".
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

    /// Returns the type name "memory".
    fn dbtype(&self) -> &str {
        self.db_type
    }
}

/// Static instance of the in-memory storage backend information provider.
pub static DBINFO: MemoryDBInfo = MemoryDBInfo { db_type: "memory" };

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a storage backend implementation that persists token
//! data, objects, and authentication information to a JSON file. It uses an
//! in-memory cache (`memory::raw_store`) for operations and synchronizes with
//! the JSON file on open and flush.

use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::storage::aci;
use crate::storage::format;
use crate::storage::{memory, Storage, StorageDBInfo, StorageTokenInfo};

mod objects {
    include!("json_objects.rs");
}
use objects::*;

/// Implements the `StorageRaw` trait using a JSON file for persistence.
///
/// Operations are primarily performed against an in-memory cache
/// (`memory::raw_store`). Data is loaded from the JSON file specified by
/// `filename` during `open()` and saved back during `flush()`.
#[derive(Debug)]
pub struct JsonStorage {
    /// Path to the JSON database file.
    filename: String,
    /// In-memory cache holding the currently loaded data.
    cache: Box<dyn format::StorageRaw>,
}

impl format::StorageRaw for JsonStorage {
    /// Delegates to the in-memory cache.
    fn is_initialized(&self) -> Result<()> {
        self.cache.is_initialized()
    }
    /// Resets the storage (currently not implemented).
    fn db_reset(&mut self) -> Result<()> {
        Ok(())
    }
    /// Loads data from the JSON file into the in-memory cache.
    fn open(&mut self) -> Result<()> {
        let token = JsonObjects::load(&self.filename)?;
        token.prime_store(&mut self.cache)
    }
    /// Saves the current state of the in-memory cache back to the JSON file.
    fn flush(&mut self) -> Result<()> {
        let token = JsonObjects::from_store(&mut self.cache);
        token.save(&self.filename)
    }
    /// Delegates to the in-memory cache.
    fn fetch_by_uid(
        &self,
        uid: &String,
        attrs: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        self.cache.fetch_by_uid(uid, attrs)
    }
    /// Delegates to the in-memory cache.
    fn search(&self, template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>> {
        self.cache.search(template)
    }
    /// Stores the object in the in-memory cache and flushes to the JSON file.
    fn store_obj(&mut self, obj: Object) -> Result<()> {
        self.cache.store_obj(obj)?;
        self.flush()
    }
    /// Removes the object from the in-memory cache and flushes to the JSON
    /// file.
    fn remove_by_uid(&mut self, uid: &String) -> Result<()> {
        self.cache.remove_by_uid(uid)?;
        self.flush()
    }
    /// Delegates to the in-memory cache.
    fn fetch_token_info(&self) -> Result<StorageTokenInfo> {
        self.cache.fetch_token_info()
    }
    /// Stores token info in the in-memory cache and flushes to the JSON file.
    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        self.cache.store_token_info(info)?;
        self.flush()
    }
    /// Delegates to the in-memory cache.
    fn fetch_user(&self, uid: &str) -> Result<aci::StorageAuthInfo> {
        self.cache.fetch_user(uid)
    }
    /// Stores user auth info in the in-memory cache and flushes to the JSON
    /// file.
    fn store_user(
        &mut self,
        uid: &str,
        data: &aci::StorageAuthInfo,
    ) -> Result<()> {
        self.cache.store_user(uid, data)?;
        self.flush()
    }
}

/// Information provider for the JSON storage backend discovery.
#[derive(Debug)]
pub struct JsonDBInfo {
    /// The unique type name for this backend ("json").
    db_type: &'static str,
}

impl StorageDBInfo for JsonDBInfo {
    /// Creates a new JSON storage instance, wrapping it in the standard ACI
    /// format layer. The `conf` parameter is expected to be the filename.
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>> {
        let raw_store = Box::new(JsonStorage {
            filename: match conf {
                Some(s) => s.clone(),
                None => String::from(""),
            },
            cache: memory::raw_store(),
        });
        Ok(Box::new(format::StdStorageFormat::new(
            raw_store,
            aci::StorageACI::new(true),
        )))
    }

    /// Returns the type name "json".
    fn dbtype(&self) -> &str {
        self.db_type
    }
}

/// Static instance of the JSON storage backend information provider.
pub static DBINFO: JsonDBInfo = JsonDBInfo { db_type: "json" };

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::storage::aci::StorageACI;
use crate::storage::format::{StdStorageFormat, StorageRaw};
use crate::storage::{memory, Storage, StorageDBInfo, StorageTokenInfo};

mod objects {
    include!("json_objects.rs");
}
use objects::*;

#[derive(Debug)]
pub struct JsonStorage {
    filename: String,
    cache: Box<dyn StorageRaw>,
}

impl StorageRaw for JsonStorage {
    fn is_initialized(&self) -> Result<()> {
        self.cache.is_initialized()
    }
    fn db_reset(&mut self) -> Result<()> {
        // TODO: reset not implemented yet
        Ok(())
    }
    fn open(&mut self) -> Result<()> {
        let token = JsonObjects::load(&self.filename)?;
        token.prime_store(&mut self.cache)
    }
    fn flush(&mut self) -> Result<()> {
        let token = JsonObjects::from_store(&mut self.cache);
        token.save(&self.filename)
    }
    fn fetch_by_uid(
        &self,
        uid: &String,
        attrs: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        self.cache.fetch_by_uid(uid, attrs)
    }
    fn search(&self, template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>> {
        self.cache.search(template)
    }
    fn store_obj(&mut self, obj: Object) -> Result<()> {
        self.cache.store_obj(obj)?;
        self.flush()
    }
    fn remove_by_uid(&mut self, uid: &String) -> Result<()> {
        self.cache.remove_by_uid(uid)?;
        self.flush()
    }
    fn fetch_token_info(&self) -> Result<StorageTokenInfo> {
        self.cache.fetch_token_info()
    }
    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()> {
        self.cache.store_token_info(info)
    }
}

#[derive(Debug)]
pub struct JsonDBInfo {
    db_type: &'static str,
}

impl StorageDBInfo for JsonDBInfo {
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>> {
        let raw_store = Box::new(JsonStorage {
            filename: match conf {
                Some(s) => s.clone(),
                None => String::from(""),
            },
            cache: memory::raw_store(),
        });
        Ok(Box::new(StdStorageFormat::new(
            raw_store,
            StorageACI::new(true),
        )))
    }

    fn dbtype(&self) -> &str {
        self.db_type
    }
}

pub static DBINFO: JsonDBInfo = JsonDBInfo { db_type: "json" };

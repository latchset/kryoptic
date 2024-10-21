// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::token::TokenFacilities;

use once_cell::sync::Lazy;

pub struct StorageTokenInfo {
    pub label: [CK_UTF8CHAR; 32usize],
    pub manufacturer: [CK_UTF8CHAR; 32usize],
    pub model: [CK_UTF8CHAR; 16usize],
    pub serial: [CK_CHAR; 16usize],
    pub flags: CK_FLAGS,
}

pub trait StorageDBInfo: Debug + Send + Sync {
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>>;
    fn dbtype(&self) -> &str;
    fn dbsuffix(&self) -> &str;
}

pub trait Storage: Debug + Send + Sync {
    fn open(&mut self) -> Result<StorageTokenInfo>;
    fn reinit(
        &mut self,
        facilities: &TokenFacilities,
    ) -> Result<StorageTokenInfo>;
    fn flush(&mut self) -> Result<()>;
    fn fetch(
        &self,
        faclities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        get_sensitive: bool,
    ) -> Result<Object>;
    fn store(
        &mut self,
        faclities: &mut TokenFacilities,
        obj: Object,
    ) -> Result<CK_OBJECT_HANDLE>;
    fn search(
        &self,
        faclities: &mut TokenFacilities,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>>;
    fn remove(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()>;
    fn load_token_info(&self) -> Result<StorageTokenInfo>;
    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()>;
    fn auth_user(
        &mut self,
        faclities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        flag: &mut CK_FLAGS,
        check_only: bool,
    ) -> Result<()>;
    fn unauth_user(&mut self, user_type: CK_USER_TYPE) -> Result<()>;
    fn set_user_pin(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
    ) -> Result<()>;
}

mod aci;
mod format;

#[cfg(feature = "jsondb")]
pub mod json;

#[cfg(feature = "memorydb")]
pub mod memory;

#[cfg(feature = "sqlitedb")]
pub mod sqlite;

static STORAGE_DBS: Lazy<Vec<&'static dyn StorageDBInfo>> = Lazy::new(|| {
    let mut v = Vec::<&'static dyn StorageDBInfo>::with_capacity(4);

    #[cfg(feature = "jsondb")]
    v.push(&json::DBINFO);

    #[cfg(feature = "memorydb")]
    v.push(&memory::DBINFO);

    #[cfg(feature = "sqlitedb")]
    v.push(&sqlite::DBINFO);

    v
});

pub fn suffix_to_type(name: &str) -> Result<&'static str> {
    for i in 0..STORAGE_DBS.len() {
        let suffix = STORAGE_DBS[i].dbsuffix();
        if suffix == "" {
            continue;
        }
        if name.ends_with(suffix) {
            return Ok(STORAGE_DBS[i].dbtype());
        }
    }
    Err(KRR_CONFIG_ERROR)?
}

pub fn new_storage(
    name: &str,
    conf: &Option<String>,
) -> Result<Box<dyn Storage>> {
    for i in 0..STORAGE_DBS.len() {
        if name == STORAGE_DBS[i].dbtype() {
            return STORAGE_DBS[i].new(conf);
        }
    }
    Err(CKR_TOKEN_NOT_RECOGNIZED)?
}

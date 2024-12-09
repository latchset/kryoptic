// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::token::TokenFacilities;

use once_cell::sync::Lazy;

#[cfg(feature = "fips")]
const TOKEN_LABEL: &str = "Kryoptic FIPS Token";
#[cfg(not(feature = "fips"))]
const TOKEN_LABEL: &str = "Kryoptic Soft Token";

const MANUFACTURER_ID: &str = "Kryoptic Project";

#[cfg(feature = "fips")]
const TOKEN_MODEL: &str = "FIPS-140-3 v1";
#[cfg(not(feature = "fips"))]
const TOKEN_MODEL: &str = "v1";

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
        attributes: &[CK_ATTRIBUTE],
    ) -> Result<Object>;
    fn store(
        &mut self,
        facilities: &mut TokenFacilities,
        obj: Object,
    ) -> Result<CK_OBJECT_HANDLE>;
    fn update(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()>;
    fn search(
        &self,
        facilities: &mut TokenFacilities,
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
        facilities: &TokenFacilities,
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
pub mod format;

#[cfg(feature = "jsondb")]
pub mod json;

#[cfg(feature = "memorydb")]
pub mod memory;

#[cfg(any(feature = "nssdb", feature = "sqlitedb"))]
mod sqlite_common;

#[cfg(feature = "sqlitedb")]
pub mod sqlite;

#[cfg(feature = "nssdb")]
pub mod nssdb;

static STORAGE_DBS: Lazy<Vec<&'static dyn StorageDBInfo>> = Lazy::new(|| {
    let mut v = Vec::<&'static dyn StorageDBInfo>::with_capacity(4);

    #[cfg(feature = "jsondb")]
    v.push(&json::DBINFO);

    #[cfg(feature = "memorydb")]
    v.push(&memory::DBINFO);

    #[cfg(feature = "sqlitedb")]
    v.push(&sqlite::DBINFO);

    #[cfg(feature = "nssdb")]
    v.push(&nssdb::DBINFO);

    v
});

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

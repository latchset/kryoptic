// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the storage backend interface (`Storage` trait) and
//! related structures for persisting token state, objects, and authentication
//! data. It also includes helpers for discovering and instantiating available
//! storage backend implementations (e.g., JSON, SQLite, NSS DB).

use std::fmt::Debug;

use crate::defaults;
use crate::error::Result;
use crate::misc::copy_sized_string;
use crate::object::Object;
use crate::pkcs11::*;
use crate::token::TokenFacilities;

use once_cell::sync::Lazy;

/// Structure holding basic token information stored persistently.
#[derive(Clone, Debug)]
pub struct StorageTokenInfo {
    pub label: [CK_UTF8CHAR; 32usize],
    pub manufacturer: [CK_UTF8CHAR; 32usize],
    pub model: [CK_UTF8CHAR; 16usize],
    pub serial: [CK_CHAR; 16usize],
    pub flags: CK_FLAGS,
}

impl Default for StorageTokenInfo {
    fn default() -> StorageTokenInfo {
        let mut def = StorageTokenInfo {
            label: [b' '; 32],
            manufacturer: [b' '; 32],
            model: [b' '; 16],
            serial: [b' '; 16],
            flags: 0,
        };
        copy_sized_string(defaults::TOKEN_LABEL.as_bytes(), &mut def.label);
        copy_sized_string(
            defaults::MANUFACTURER_ID.as_bytes(),
            &mut def.manufacturer,
        );
        copy_sized_string(defaults::TOKEN_MODEL.as_bytes(), &mut def.model);
        def
    }
}

/// Trait for discovering available storage database backend types.
///
/// Each backend implementation provides a static instance of this trait
/// (e.g., `sqlite::DBINFO`) which is registered in the
/// `STORAGE_DBS` list.
pub trait StorageDBInfo: Debug + Send + Sync {
    /// Creates a new instance of the storage backend.
    fn new(&self, conf: &Option<String>) -> Result<Box<dyn Storage>>;
    /// Returns the unique name identifying this storage backend type.
    fn dbtype(&self) -> &str;
}

/// The main trait defining the interface for persistent storage backends.
pub trait Storage: Debug + Send + Sync {
    /// Opens the storage backend, loading existing token information.
    /// Returns `CKR_CRYPTOKI_NOT_INITIALIZED` if the storage is uninitialized.
    fn open(&mut self) -> Result<StorageTokenInfo>;
    /// Reinitializes the storage backend, potentially deleting existing data.
    /// Returns the default token information structure.
    fn reinit(
        &mut self,
        facilities: &TokenFacilities,
    ) -> Result<StorageTokenInfo>;
    /// Flushes any pending changes to the persistent storage.
    fn flush(&mut self) -> Result<()>;
    /// Fetches an object from storage by its handle.
    /// Optionally retrieves only specific `attributes`.
    fn fetch(
        &self,
        faclities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        attributes: &[CK_ATTRIBUTE],
    ) -> Result<Object>;
    /// Stores a new token object (`CKA_TOKEN=true`) persistently.
    /// Assigns a unique internal ID (UID) and handle. Returns the handle.
    fn store(
        &mut self,
        facilities: &mut TokenFacilities,
        obj: Object,
    ) -> Result<CK_OBJECT_HANDLE>;
    /// Updates attributes of an existing token object in storage.
    /// The `template` contains only the attributes to be modified.
    fn update(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<()>;
    /// Searches for token objects matching the `template`.
    /// Returns a vector of matching object handles.
    fn search(
        &self,
        facilities: &mut TokenFacilities,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Vec<CK_OBJECT_HANDLE>>;
    /// Removes a token object from persistent storage by its handle.
    fn remove(
        &mut self,
        facilities: &TokenFacilities,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()>;
    /// Loads the token information (label, flags, etc.) from storage.
    fn load_token_info(&self) -> Result<StorageTokenInfo>;
    /// Stores updated token information to persistent storage.
    fn store_token_info(&mut self, info: &StorageTokenInfo) -> Result<()>;
    /// Authenticates a user (SO or User) against the stored PIN.
    /// Updates `flag` with PIN status (locked, final try, etc.).
    /// If `check_only` is true, does not change the token's logged-in state.
    fn auth_user(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        flag: &mut CK_FLAGS,
        check_only: bool,
    ) -> Result<()>;
    /// Clears the authenticated state for the specified user type.
    fn unauth_user(&mut self, user_type: CK_USER_TYPE) -> Result<()>;
    /// Sets or changes the PIN for the specified user type.
    /// Requires prior authentication if changing an existing PIN
    /// (handled by `Token::set_pin`).
    fn set_user_pin(
        &mut self,
        facilities: &TokenFacilities,
        user_type: CK_USER_TYPE,
        pin: &[u8],
    ) -> Result<()>;
}

pub mod aci;
pub mod format;

#[cfg(feature = "memorydb")]
pub mod memory;

#[cfg(any(feature = "nssdb", feature = "sqlitedb"))]
mod sqlite_common;

#[cfg(feature = "sqlitedb")]
pub mod sqlite;

#[cfg(feature = "nssdb")]
pub mod nssdb;

/// Static list of available storage database backend information providers.
/// Populated at runtime based on features enabled at compile time.
static STORAGE_DBS: Lazy<Vec<&'static dyn StorageDBInfo>> = Lazy::new(|| {
    let mut v = Vec::<&'static dyn StorageDBInfo>::with_capacity(4);

    #[cfg(feature = "memorydb")]
    v.push(&memory::DBINFO);

    #[cfg(feature = "sqlitedb")]
    v.push(&sqlite::DBINFO);

    #[cfg(feature = "nssdb")]
    v.push(&nssdb::DBINFO);

    v
});

/// Factory function to create a new storage backend instance.
///
/// Finds the appropriate backend based on the provided `name` string and
/// instantiates it using the optional configuration string `conf`.
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

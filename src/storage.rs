// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::error::Result;
use crate::interface::{CKR_TOKEN_NOT_RECOGNIZED, CK_ATTRIBUTE};
use crate::object::Object;

use std::fmt::Debug;

pub const SQLITEDB: &str = "sqlite";
pub const JSONDB: &str = "json";
pub const MEMORYDB: &str = "memory";

pub trait Storage: Debug + Send + Sync {
    fn open(&mut self, filename: &String) -> Result<()>;
    fn reinit(&mut self) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
    fn fetch_by_uid(&self, uid: &String) -> Result<Object>;
    fn store(&mut self, uid: &String, obj: Object) -> Result<()>;
    fn search(&self, template: &[CK_ATTRIBUTE]) -> Result<Vec<Object>>;
    fn remove_by_uid(&mut self, uid: &String) -> Result<()>;
}

pub mod json;
pub mod memory;
pub mod sqlite;

pub fn name_to_type(name: &str) -> Result<&'static str> {
    if name.ends_with(".sql") {
        Ok(SQLITEDB)
    } else if name.ends_with(".json") {
        Ok(JSONDB)
    } else {
        Err(CKR_TOKEN_NOT_RECOGNIZED)?
    }
}

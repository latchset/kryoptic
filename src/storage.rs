// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::error;
use super::interface;
use super::object;

use error::KResult;
use interface::CK_ATTRIBUTE;
use object::Object;

use std::fmt::Debug;

pub trait Storage: Debug + Send + Sync {
    fn open(&mut self, filename: &String) -> KResult<()>;
    fn reinit(&mut self) -> KResult<()>;
    fn flush(&mut self) -> KResult<()>;
    fn fetch_by_uid(&self, uid: &String) -> KResult<Object>;
    fn store(&mut self, uid: &String, obj: Object) -> KResult<()>;
    fn search(&self, template: &[CK_ATTRIBUTE]) -> KResult<Vec<Object>>;
    fn remove_by_uid(&mut self, uid: &String) -> KResult<()>;
}

pub mod json;
pub mod memory;
pub mod sqlite;

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
    fn flush(&self) -> KResult<()>;
    fn get_by_unique_id(&self, uid: &String) -> KResult<&Object>;
    fn get_by_unique_id_mut(&mut self, uid: &String) -> KResult<&mut Object>;
    fn store(&mut self, uid: String, obj: Object) -> KResult<()>;
    fn search(&self, template: &[CK_ATTRIBUTE]) -> Vec<&Object>;
    fn remove_by_unique_id(&mut self, uid: &String) -> KResult<()>;
    fn get_rough_size_by_unique_id(&self, uid: &String) -> KResult<usize>;
}

pub mod json;
pub mod memory;

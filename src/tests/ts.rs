// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::fmt::Debug;

use crate::error::Result;
use crate::interface::*;
use crate::object::Object;
use crate::storage::format::StorageRaw;

use std::collections::HashMap;

pub mod json {
    #![allow(dead_code)]
    #![allow(unused_attributes)]
    include!("../storage/json_objects.rs");
}

#[derive(Debug)]
pub struct TransferStorage {
    objects: HashMap<String, Object>,
}

impl TransferStorage {
    pub fn new() -> Box<dyn StorageRaw> {
        Box::new(TransferStorage {
            objects: HashMap::new(),
        })
    }
}

impl StorageRaw for TransferStorage {
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
}

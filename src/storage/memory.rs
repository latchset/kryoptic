// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::super::error;
use super::super::interface;
use super::super::object;
use std::collections::HashMap;

use super::Storage;

use super::super::{err_not_found, err_rv};
use error::{KError, KResult};
use interface::*;
use object::Object;

use std::fmt::Debug;

#[derive(Debug)]
struct MemoryStorage {
    objects: HashMap<String, Object>,
}

impl Storage for MemoryStorage {
    fn open(&mut self, _filename: &String) -> KResult<()> {
        return err_rv!(CKR_GENERAL_ERROR);
    }
    fn reinit(&mut self) -> KResult<()> {
        self.objects.clear();
        Ok(())
    }
    fn flush(&self) -> KResult<()> {
        Ok(())
    }
    fn get_by_unique_id(&self, uid: &String) -> KResult<&Object> {
        match self.objects.get(uid) {
            Some(o) => Ok(o),
            None => err_not_found! {uid.clone()},
        }
    }
    fn get_by_unique_id_mut(&mut self, uid: &String) -> KResult<&mut Object> {
        match self.objects.get_mut(uid) {
            Some(o) => Ok(o),
            None => err_not_found! {uid.clone()},
        }
    }
    fn store(&mut self, uid: String, obj: Object) -> KResult<()> {
        self.objects.insert(uid, obj);
        Ok(())
    }
    fn search(&self, template: &[CK_ATTRIBUTE]) -> Vec<&Object> {
        let mut ret = Vec::<&Object>::new();
        for (_, o) in self.objects.iter() {
            if o.match_template(template) {
                ret.push(o);
            }
        }
        ret
    }
    fn remove_by_unique_id(&mut self, uid: &String) -> KResult<()> {
        self.objects.remove(uid);
        Ok(())
    }
    fn get_rough_size_by_unique_id(&self, _uid: &String) -> KResult<usize> {
        // TODO
        Ok(1000)
    }
}

pub fn memory() -> Box<dyn Storage> {
    Box::new(MemoryStorage {
        objects: HashMap::new(),
    })
}

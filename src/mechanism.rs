// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::BTreeMap;

use super::err_rv;
use super::error;
use super::interface;
use super::object;
use error::{KError, KResult};
use interface::*;

use std::fmt::Debug;

pub trait Mechanism: Debug + Send + Sync {
    fn info(&self) -> &CK_MECHANISM_INFO;
    fn encryption_new(
        &self,
        _: &CK_MECHANISM,
        _: object::Object,
    ) -> KResult<Box<dyn Operation>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn decryption_new(
        &self,
        _: &CK_MECHANISM,
        _: object::Object,
    ) -> KResult<Box<dyn Operation>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
}

#[derive(Debug)]
pub struct Mechanisms {
    tree: BTreeMap<CK_MECHANISM_TYPE, Box<dyn Mechanism>>,
}

impl Mechanisms {
    pub fn new() -> Mechanisms {
        Mechanisms {
            tree: BTreeMap::new(),
        }
    }

    pub fn add_mechanism(
        &mut self,
        typ: CK_MECHANISM_TYPE,
        info: Box<dyn Mechanism>,
    ) {
        self.tree.insert(typ, info);
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn list(&self) -> Vec<CK_MECHANISM_TYPE> {
        self.tree.keys().cloned().collect()
    }

    pub fn info(&self, typ: CK_MECHANISM_TYPE) -> Option<&CK_MECHANISM_INFO> {
        match self.tree.get(&typ) {
            Some(m) => Some(m.info()),
            None => None,
        }
    }

    pub fn get(&self, typ: CK_MECHANISM_TYPE) -> KResult<&Box<dyn Mechanism>> {
        match self.tree.get(&typ) {
            Some(m) => Ok(m),
            None => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

pub trait Operation: Debug + Send + Sync {
    fn mechanism(&self) -> CK_MECHANISM_TYPE;
}

pub trait Encryption: Debug + Send + Sync {
    fn encrypt(data: Vec<u8>) -> KResult<Vec<u8>>;
    fn encrypt_update(data: Vec<u8>) -> KResult<Vec<u8>>;
    fn encrypt_final() -> KResult<Vec<u8>>;
}

pub trait Decryption: Debug + Send + Sync {
    fn decrypt(data: Vec<u8>) -> KResult<Vec<u8>>;
    fn decrypt_update(data: Vec<u8>) -> KResult<Vec<u8>>;
    fn decrypt_final() -> KResult<Vec<u8>>;
}

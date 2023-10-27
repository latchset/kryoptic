// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::BTreeMap;

use super::err_rv;
use super::error;
use super::interface;
use super::object;
use super::token;
use error::{KError, KResult};
use interface::*;
use object::ObjectTemplates;
use token::{TokenObjects, RNG};

use std::fmt::Debug;

pub trait Mechanism: Debug + Send + Sync {
    fn info(&self) -> &CK_MECHANISM_INFO;
    fn encryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> KResult<Box<dyn Encryption>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn decryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> KResult<Box<dyn Decryption>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn digest_new(&self, _: &CK_MECHANISM) -> KResult<Box<dyn Digest>> {
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

pub trait MechOperation: Debug + Send + Sync {
    fn mechanism(&self) -> CK_MECHANISM_TYPE;
    fn in_use(&self) -> bool;
    fn finalized(&self) -> bool;
}

pub trait Encryption: MechOperation {
    fn encrypt(
        &mut self,
        _rng: &mut RNG,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_update(
        &mut self,
        _rng: &mut RNG,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_final(
        &mut self,
        _rng: &mut RNG,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Decryption: MechOperation {
    fn decrypt(
        &mut self,
        _rng: &mut RNG,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decrypt_update(
        &mut self,
        _rng: &mut RNG,
        _cipher: CK_BYTE_PTR,
        _cipher_len: CK_ULONG,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decrypt_final(
        &mut self,
        _rng: &mut RNG,
        _plain: CK_BYTE_PTR,
        _plain_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait SearchOperation: Debug + Send + Sync {
    fn search(
        &mut self,
        _object_templates: &ObjectTemplates,
        _objects: &mut TokenObjects,
        _template: &[CK_ATTRIBUTE],
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn results(&mut self, _max: usize) -> KResult<Vec<CK_OBJECT_HANDLE>> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Digest: MechOperation {
    fn digest(
        &mut self,
        _data: &[u8],
        _digest: CK_BYTE_PTR,
        _digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn digest_update(&mut self, _data: &[u8]) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn digest_final(
        &mut self,
        _digest: CK_BYTE_PTR,
        _digest_len: CK_ULONG_PTR,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

#[derive(Debug)]
pub enum Operation {
    Empty,
    Search(Box<dyn SearchOperation>),
    Encryption(Box<dyn Encryption>),
    Decryption(Box<dyn Decryption>),
    Digest(Box<dyn Digest>),
}

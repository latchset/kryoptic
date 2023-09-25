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
use token::RNG;

use std::fmt::Debug;

pub trait Mechanism: Debug + Send + Sync {
    fn info(&self) -> &CK_MECHANISM_INFO;
    fn encryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> KResult<Box<dyn Operation>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn decryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
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

pub trait BaseOperation: Debug + Send + Sync {
    fn mechanism(&self) -> CK_MECHANISM_TYPE;
    fn used(&self) -> bool;
}

pub trait Encryption: Debug + Send + Sync {
    fn encrypt(
        &mut self,
        _rng: &mut RNG,
        _plain: &[u8],
        _cipher: &mut [u8],
        _inplace: bool,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_update(
        &mut self,
        _rng: &mut RNG,
        _plain: &[u8],
        _cipher: &mut [u8],
        _inplace: bool,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_final(
        &mut self,
        _rng: &mut RNG,
        _cipher: &mut [u8],
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Decryption: Debug + Send + Sync {
    fn decrypt(
        &mut self,
        _rng: &mut RNG,
        _cipher: &[u8],
        _plain: &mut [u8],
        _inplace: bool,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decrypt_update(
        &mut self,
        _rng: &mut RNG,
        _cipher: &[u8],
        _plain: &mut [u8],
        _inplace: bool,
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decrypt_final(
        &mut self,
        _rng: &mut RNG,
        _cipher: &mut [u8],
    ) -> KResult<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Operation: BaseOperation + Encryption + Decryption {}

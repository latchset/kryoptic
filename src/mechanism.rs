// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::BTreeMap;

use super::err_rv;
use super::error;
use super::interface;
use super::object;
use error::Result;
use interface::*;
use object::{Object, ObjectFactories, ObjectFactory};

use std::fmt::Debug;

pub trait Mechanism: Debug + Send + Sync {
    fn info(&self) -> &CK_MECHANISM_INFO;
    fn encryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> Result<Box<dyn Encryption>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn decryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> Result<Box<dyn Decryption>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn digest_new(&self, _: &CK_MECHANISM) -> Result<Box<dyn Digest>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn mac_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
        _: CK_FLAGS,
    ) -> Result<Box<dyn Mac>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn sign_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> Result<Box<dyn Sign>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }
    fn verify_new(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
    ) -> Result<Box<dyn Verify>> {
        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn generate_key(
        &self,
        _: &CK_MECHANISM,
        _: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn generate_keypair(
        &self,
        _: &CK_MECHANISM,
        _pubkey_template: &[CK_ATTRIBUTE],
        _prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn wrap_key(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
        _: &object::Object,
        _: &mut [u8],
        _: &Box<dyn ObjectFactory>,
    ) -> Result<usize> {
        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn unwrap_key(
        &self,
        _: &CK_MECHANISM,
        _: &object::Object,
        _: &[u8],
        _: &[CK_ATTRIBUTE],
        _: &Box<dyn ObjectFactory>,
    ) -> Result<Object> {
        err_rv!(CKR_MECHANISM_INVALID)
    }

    fn derive_operation(&self, _: &CK_MECHANISM) -> Result<Operation> {
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

    pub fn get(&self, typ: CK_MECHANISM_TYPE) -> Result<&Box<dyn Mechanism>> {
        match self.tree.get(&typ) {
            Some(m) => Ok(m),
            None => err_rv!(CKR_MECHANISM_INVALID),
        }
    }
}

pub trait MechOperation: Debug + Send + Sync {
    fn finalized(&self) -> bool;
    fn reset(&mut self) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        /* nothing needed by default */
        err_rv!(CKR_OK)
    }
    fn receives_objects(&mut self, _: &[&Object]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        None
    }
    /* used only in FIPS builds, for now */
    #[allow(dead_code)]
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE>;
}

pub trait Encryption: MechOperation {
    fn encrypt(&mut self, _plain: &[u8], _cipher: &mut [u8]) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encrypt_final(&mut self, _cipher: &mut [u8]) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn encryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Decryption: MechOperation {
    fn decrypt(&mut self, _cipher: &[u8], _plain: &mut [u8]) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decrypt_final(&mut self, _plain: &mut [u8]) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn decryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait SearchOperation: Debug + Send + Sync {
    fn finalized(&self) -> bool;
    fn results(&mut self, _max: usize) -> Result<Vec<CK_OBJECT_HANDLE>> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Digest: MechOperation {
    fn digest(&mut self, _data: &[u8], _digest: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn digest_update(&mut self, _data: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn digest_final(&mut self, _digest: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn digest_len(&self) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Mac: MechOperation {
    /* not used in FIPS builds */
    #[allow(dead_code)]
    fn mac(&mut self, _data: &[u8], _digest: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn mac_update(&mut self, _data: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn mac_final(&mut self, _digest: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn mac_len(&self) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Sign: MechOperation {
    fn sign(&mut self, _data: &[u8], _signature: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn sign_update(&mut self, _data: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn sign_final(&mut self, _signature: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn signature_len(&self) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Verify: MechOperation {
    fn verify(&mut self, _data: &[u8], _signature: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn verify_update(&mut self, _data: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn verify_final(&mut self, _signature: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }

    fn signature_len(&self) -> Result<usize> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

pub trait Derive: MechOperation {
    fn derive(
        &mut self,
        _: &object::Object,
        _: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Vec<Object>> {
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
    Sign(Box<dyn Sign>),
    Verify(Box<dyn Verify>),
    Derive(Box<dyn Derive>),
}

impl Operation {
    pub fn finalized(&self) -> bool {
        match self {
            Operation::Empty => true,
            Operation::Search(op) => op.finalized(),
            Operation::Encryption(op) => op.finalized(),
            Operation::Decryption(op) => op.finalized(),
            Operation::Digest(op) => op.finalized(),
            Operation::Sign(op) => op.finalized(),
            Operation::Verify(op) => op.finalized(),
            Operation::Derive(op) => op.finalized(),
        }
    }
}

pub trait DRBG: Debug + Send + Sync {
    fn init(
        &mut self,
        _entropy: &[u8],
        _nonce: &[u8],
        _pers: &[u8],
    ) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn reseed(&mut self, _entropy: &[u8], _addtl: &[u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
    fn generate(&mut self, _addtl: &[u8], _output: &mut [u8]) -> Result<()> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::collections::BTreeMap;

use crate::error::Result;
use crate::interface::*;
use crate::object::{Object, ObjectFactories, ObjectFactory};

use std::fmt::Debug;

pub trait Mechanism: Debug + Send + Sync {
    fn info(&self) -> &CK_MECHANISM_INFO;
    fn encryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn Encryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }
    fn decryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn Decryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }
    fn digest_new(&self, _: &CK_MECHANISM) -> Result<Box<dyn Digest>> {
        Err(CKR_MECHANISM_INVALID)?
    }
    fn mac_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: CK_FLAGS,
    ) -> Result<Box<dyn Mac>> {
        Err(CKR_MECHANISM_INVALID)?
    }
    fn sign_new(&self, _: &CK_MECHANISM, _: &Object) -> Result<Box<dyn Sign>> {
        Err(CKR_MECHANISM_INVALID)?
    }
    fn verify_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn Verify>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn generate_key(
        &self,
        _: &CK_MECHANISM,
        _: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn generate_keypair(
        &self,
        _: &CK_MECHANISM,
        _pubkey_template: &[CK_ATTRIBUTE],
        _prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn wrap_key(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: &Object,
        _: &mut [u8],
        _: &Box<dyn ObjectFactory>,
    ) -> Result<usize> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn unwrap_key(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: &[u8],
        _: &[CK_ATTRIBUTE],
        _: &Box<dyn ObjectFactory>,
    ) -> Result<Object> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn derive_operation(&self, _: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn msg_encryption_op(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn MsgEncryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn msg_decryption_op(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn MsgDecryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn encapsulate(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: &Box<dyn ObjectFactory>,
        _: &[CK_ATTRIBUTE],
        _: &mut [u8],
    ) -> Result<(Object, usize)> {
        Err(CKR_MECHANISM_INVALID)?
    }

    fn decapsulate(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: &Box<dyn ObjectFactory>,
        _: &[CK_ATTRIBUTE],
        _: &[u8],
    ) -> Result<Object> {
        Err(CKR_MECHANISM_INVALID)?
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
            None => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

pub trait MechOperation: Debug + Send + Sync {
    fn finalized(&self) -> bool;
    fn reset(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        /* nothing needed by default */
        Err(CKR_OK)?
    }
    fn receives_objects(&mut self, _: &[&Object]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
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
        Err(CKR_GENERAL_ERROR)?
    }
    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn encrypt_final(&mut self, _cipher: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn encryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Decryption: MechOperation {
    fn decrypt(&mut self, _cipher: &[u8], _plain: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn decrypt_final(&mut self, _plain: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn decryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait SearchOperation: Debug + Send + Sync {
    fn finalized(&self) -> bool;
    fn results(&mut self, _max: usize) -> Result<Vec<CK_OBJECT_HANDLE>> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Digest: MechOperation {
    fn digest(&mut self, _data: &[u8], _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn digest_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn digest_final(&mut self, _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn digest_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Mac: MechOperation {
    /* not used in FIPS builds */
    #[allow(dead_code)]
    fn mac(&mut self, _data: &[u8], _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    #[allow(dead_code)]
    fn mac_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    #[allow(dead_code)]
    fn mac_final(&mut self, _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    #[allow(dead_code)]
    fn mac_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Sign: MechOperation {
    fn sign(&mut self, _data: &[u8], _signature: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn sign_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn sign_final(&mut self, _signature: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn signature_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Verify: MechOperation {
    fn verify(&mut self, _data: &[u8], _signature: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn verify_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn verify_final(&mut self, _signature: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn signature_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Derive: MechOperation {
    fn derive(
        &mut self,
        _: &Object,
        _: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait MessageOperation: MechOperation {
    fn busy(&self) -> bool;
    fn finalize(&mut self) -> Result<()> {
        Err(CKR_OPERATION_NOT_INITIALIZED)?
    }
}

pub trait MsgEncryption: MessageOperation {
    fn msg_encrypt(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _adata: &[u8],
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_encrypt_begin(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _aad: &[u8],
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_encrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_encrypt_final(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_encryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait MsgDecryption: MessageOperation {
    fn msg_decrypt(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _adata: &[u8],
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_decrypt_begin(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _aad: &[u8],
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_decrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_decrypt_final(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    fn msg_decryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait DRBG: Debug + Send + Sync {
    fn init(
        &mut self,
        _entropy: &[u8],
        _nonce: &[u8],
        _pers: &[u8],
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn reseed(&mut self, _entropy: &[u8], _addtl: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
    fn generate(&mut self, _addtl: &[u8], _output: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
}

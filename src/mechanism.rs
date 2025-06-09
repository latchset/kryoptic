// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

//! This module defines the core traits and structures for managing PKCS#11
//! cryptographic mechanisms. It includes the central `Mechanism` trait that
//! all specific mechanism implementations must adhere to, defining interfaces
//! for various operations like encryption, signing, key generation,
//! derivation, etc.
//! It also provides the `Mechanisms` registry for discovering and accessing
//! available mechanism implementations, along with traits representing active
//! cryptographic operations (e.g., `Encryption`, `Sign`, `Derive`).

use std::collections::BTreeMap;
use std::fmt::Debug;

use crate::error::Result;
use crate::object::{Object, ObjectFactories, ObjectFactory};

use pkcs11::*;

pub trait Mechanism: Debug + Send + Sync {
    /// Returns a reference to the mechanism info
    fn info(&self) -> &CK_MECHANISM_INFO;

    /// Initializes an Encryption Operation
    fn encryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn Encryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a Decryption Operation
    fn decryption_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn Decryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a Digest Operation
    fn digest_new(&self, _: &CK_MECHANISM) -> Result<Box<dyn Digest>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a raw Mac Operation
    ///
    /// This interface is made available for internal cross-module use
    /// and is not directly exposed via PKCS #11 APIs.
    fn mac_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: CK_FLAGS,
    ) -> Result<Box<dyn Mac>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a Sign Operation
    fn sign_new(&self, _: &CK_MECHANISM, _: &Object) -> Result<Box<dyn Sign>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a Verify Operation
    fn verify_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn Verify>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Executes a Symmetric Key Generation operation
    fn generate_key(
        &self,
        _: &CK_MECHANISM,
        _: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Executes an Asymmetric Key Pair Generation operation
    fn generate_keypair(
        &self,
        _: &CK_MECHANISM,
        _pubkey_template: &[CK_ATTRIBUTE],
        _prikey_template: &[CK_ATTRIBUTE],
    ) -> Result<(Object, Object)> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Wraps a key with a wrapping key
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

    /// Unwraps a key with a wrapping key
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

    /// Initializes a Derive Operation
    fn derive_operation(&self, _: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a Message-Encryption Operation
    fn msg_encryption_op(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn MsgEncryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Initializes a Message-Decryption Operation
    fn msg_decryption_op(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
    ) -> Result<Box<dyn MsgDecryption>> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Key Encapsulation function
    #[cfg(feature = "pkcs11_3_2")]
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

    /// Get expected length of the encapsulated ciphertext for given key
    ///
    /// Returns the size in bytes or Err if the key does not support this operation
    #[cfg(feature = "pkcs11_3_2")]
    fn encapsulate_ciphertext_len(&self, _: &Object) -> Result<usize> {
        Err(CKR_MECHANISM_INVALID)?
    }

    /// Key Decapsulation function
    #[cfg(feature = "pkcs11_3_2")]
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

    /// Initializes a Verify-Signature Operation
    ///
    /// This is identivaly to a Verify operation except that the signature
    /// to be verified is provided at initialization time and not a
    /// finalization time
    #[cfg(feature = "pkcs11_3_2")]
    fn verify_signature_new(
        &self,
        _: &CK_MECHANISM,
        _: &Object,
        _: &[u8],
    ) -> Result<Box<dyn VerifySignature>> {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Object holding a B-Tree with all registered mechanism
#[derive(Debug)]
pub struct Mechanisms {
    tree: BTreeMap<CK_MECHANISM_TYPE, Box<dyn Mechanism>>,
}

impl Mechanisms {
    /// Creates a new mechanism register
    pub fn new() -> Mechanisms {
        Mechanisms {
            tree: BTreeMap::new(),
        }
    }

    /// Add a mechanism to the mechanism register
    pub fn add_mechanism(
        &mut self,
        typ: CK_MECHANISM_TYPE,
        info: Box<dyn Mechanism>,
    ) {
        self.tree.insert(typ, info);
    }

    /// Size of the mechanism register
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns a list of all the registered mechanism types
    pub fn list(&self) -> Vec<CK_MECHANISM_TYPE> {
        self.tree.keys().cloned().collect()
    }

    /// Returns the info structure associated with a mechanism
    pub fn info(&self, typ: CK_MECHANISM_TYPE) -> Option<&CK_MECHANISM_INFO> {
        match self.tree.get(&typ) {
            Some(m) => Some(m.info()),
            None => None,
        }
    }

    /// Gets a reference to a mechanism registry entry by mechanism type
    pub fn get(&self, typ: CK_MECHANISM_TYPE) -> Result<&Box<dyn Mechanism>> {
        match self.tree.get(&typ) {
            Some(m) => Ok(m),
            None => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

pub trait MechOperation: Debug + Send + Sync {
    /// Report if the operation was finalized
    fn finalized(&self) -> bool;

    /// Reset the internal state of an operation
    fn reset(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Function to query if the mechanism needs to be provided
    /// additional objects from the store.
    ///
    /// This is typically implemented only for Key Derivation operations
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        /* nothing needed by default */
        Err(CKR_OK)?
    }

    /// Function to provide to the Operation references to the
    /// objects requested by the `requires_objects()` method.
    fn receives_objects(&mut self, _: &[&Object]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns an indicator of whether the operation is considered
    /// FIPS Approved Some(true) or Not-approved Some(false).
    ///
    /// May return None is the status has not been determined yet
    /// during multi-part operations
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        None
    }

    /// Returns the mechanism associated with the operation
    #[allow(dead_code)]
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE>;
}

pub trait Encryption: MechOperation {
    /// One-step encryption function
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns except when
    /// the function returns a `CKR_BUFFER_TOO_SMALL` error.
    fn encrypt(&mut self, _plain: &[u8], _cipher: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds plain text into the encryption operation, and,
    /// depending on the cipher mode, may return cipher text.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards
    /// except when the function returns a `CKR_BUFFER_TOO_SMALL` error.
    fn encrypt_update(
        &mut self,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Depending on the cipher mode, may return additional cipher text.
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards except when the function
    /// returns a `CKR_BUFFER_TOO_SMALL` error.
    fn encrypt_final(&mut self, _cipher: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the expected size of the cipher text that will be
    /// returned by the next encryption operation assuming a specific
    /// plain text length and internal state.
    ///
    /// The final parameter when `true` indicates the assumption is
    /// that the next operation to be called is either a one-step
    /// `encrypt` or a multi-part finalization `encyrpt_final`.
    fn encryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Decryption: MechOperation {
    /// One-step decryption function
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns except when
    /// the function returns a `CKR_BUFFER_TOO_SMALL` error.
    fn decrypt(&mut self, _cipher: &[u8], _plain: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds cipher text into the decryption operation, and,
    /// depending on the cipher mode, may return plain text.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards
    /// except when the function returns a `CKR_BUFFER_TOO_SMALL` error.
    fn decrypt_update(
        &mut self,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Depending on the cipher mode, may return additional plain text.
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards except when the function
    /// returns a `CKR_BUFFER_TOO_SMALL` error.
    fn decrypt_final(&mut self, _plain: &mut [u8]) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
    /// Returns the expected size of the plain text that will be
    /// returned by the next decryption operation assuming a specific
    /// cipher text length and internal state.
    ///
    /// The final parameter when `true` indicates the assumption is
    /// that the next operation to be called is either a one-step
    /// `decrypt` or a multi-part finalization `decyrpt_final`.
    fn decryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait SearchOperation: Debug + Send + Sync {
    /// Report if the operation was finalized
    fn finalized(&self) -> bool;

    /// Returns a vector of object handles from the search
    /// operation results, a maximum size must be indicated.
    fn results(&mut self, _max: usize) -> Result<Vec<CK_OBJECT_HANDLE>> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Digest: MechOperation {
    /// One-step digest function
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns.
    fn digest(&mut self, _data: &[u8], _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds data into the digest operation.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards.
    fn digest_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Returns the computed digest, the buffer must be large
    /// enough to receive the generated output
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards.
    fn digest_final(&mut self, _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the size of the digest that will be generated
    ///
    /// This should be used to ensure a correctly sized buffer
    /// is provided to the `digest` or `digest_final` functions.
    fn digest_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

/* not used in FIPS builds */
pub trait Mac: MechOperation {
    /// One-step MAC function
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns.
    #[allow(dead_code)]
    fn mac(&mut self, _data: &[u8], _digest: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds data into the MAC operation.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards.
    #[allow(dead_code)]
    fn mac_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Returns the computed MAC, the buffer must be large
    /// enough to receive the generated output
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards.
    #[allow(dead_code)]
    fn mac_final(&mut self, _mac: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the size of the MAC that will be generated
    ///
    /// This should be used to ensure a correctly sized buffer
    /// is provided to the `mac` or `mac_final` functions.
    #[allow(dead_code)]
    fn mac_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Sign: MechOperation {
    /// One-step signature function
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns.
    fn sign(&mut self, _data: &[u8], _signature: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds data into the signature operation.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards.
    fn sign_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Returns the computed signature, the buffer must be large
    /// enough to receive the generated output
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards.
    fn sign_final(&mut self, _signature: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the size of the signature that will be generated
    ///
    /// This should be used to ensure a correctly sized buffer
    /// is provided to the `sign` or `sign_final` functions.
    fn signature_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Verify: MechOperation {
    /// One-step verification function
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns.
    fn verify(&mut self, _data: &[u8], _signature: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds data into the verification operation.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards.
    fn verify_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Verifies that the provided signature matches.
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards.
    fn verify_final(&mut self, _signature: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the size of the expected signature
    ///
    /// Can be used to verify that the signature buffer is of the
    /// correct size before calling the verification functions
    fn signature_len(&self) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait Derive: MechOperation {
    /// Executes a Key Derivation Operation and returns one or
    /// more key objects in a vector
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
    /// Indicates whether a multi-part operation is in progress
    fn busy(&self) -> bool;

    /// Indicates whether the operation has been finalized
    fn finalize(&mut self) -> Result<()> {
        Err(CKR_OPERATION_NOT_INITIALIZED)?
    }
}

pub trait MsgEncryption: MessageOperation {
    /// One-step Message Encryption function
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards
    /// except when a function returns a `CKR_BUFFER_TOO_SMALL` error.
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

    /// Begins a multi-part encryption operation
    ///
    /// Only multi-part functions can be called afterwards until
    /// the multi-part message encryption is finalized.
    fn msg_encrypt_begin(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _aad: &[u8],
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds plain text into the message encryption operation, and,
    /// depending on the cipher mode, may return cipher text.
    fn msg_encrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Depending on the cipher mode, may return additional cipher text
    /// or additional data.
    ///
    /// The message encryption is completed and a new one may begin
    /// afterwards.
    fn msg_encrypt_final(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _plain: &[u8],
        _cipher: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the expected size of the cipher text that will be
    /// returned by the next encryption operation assuming a specific
    /// plain text length and internal state.
    ///
    /// The final parameter when `true` indicates the assumption is
    /// that the next operation to be called is either a one-step
    /// `msg_encrypt` or a multi-part finalization `msg_encyrpt_final`.
    fn msg_encryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait MsgDecryption: MessageOperation {
    /// One-step Message Decryption function
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards
    /// except when a function returns a `CKR_BUFFER_TOO_SMALL` error.
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

    /// Begins a multi-part decryption operation
    ///
    /// Only multi-part functions can be called afterwards until
    /// the multi-part message decryption is finalized.
    fn msg_decrypt_begin(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _aad: &[u8],
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds cipher text into the message decryption operation, and,
    /// depending on the cipher mode, may return plain text.
    fn msg_decrypt_next(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Depending on the cipher mode, may return additional plain text
    /// or additional data.
    ///
    /// The message decryption is completed and a new one may begin
    /// afterwards.
    fn msg_decrypt_final(
        &mut self,
        _param: CK_VOID_PTR,
        _paramlen: CK_ULONG,
        _cipher: &[u8],
        _plain: &mut [u8],
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns the expected size of the plain text that will be
    /// returned by the next decryption operation assuming a specific
    /// plain text length and internal state.
    ///
    /// The final parameter when `true` indicates the assumption is
    /// that the next operation to be called is either a one-step
    /// `msg_decrypt` or a multi-part finalization `msg_decyrpt_final`.
    fn msg_decryption_len(
        &mut self,
        _data_len: usize,
        _final: bool,
    ) -> Result<usize> {
        Err(CKR_GENERAL_ERROR)?
    }
}

pub trait DRBG: Debug + Send + Sync {
    /// Initializes an internal DRBG
    fn init(
        &mut self,
        _entropy: &[u8],
        _nonce: &[u8],
        _pers: &[u8],
    ) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Request re-seeding of the internal DRBG
    fn reseed(&mut self, _entropy: &[u8], _addtl: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Returns random data in the output buffer
    fn generate(&mut self, _addtl: &[u8], _output: &mut [u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
}

#[cfg(feature = "pkcs11_3_2")]
pub trait VerifySignature: MechOperation {
    /// One-step verifySignature function
    ///
    /// This is analogous to [Verify::verify] except that it lacks an argument
    /// for the signature which is instead provided at initialization as an
    /// argument to [Mechanism::verify_signature_new].
    ///
    /// The operation is finalized and no other function can be
    /// called successfully once this function returns.
    fn verify(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part update function
    ///
    /// Feeds data into the verification operation.
    ///
    /// If any error occurs the whole operation is finalized and
    /// no other function can be called successfully afterwards.
    fn verify_update(&mut self, _data: &[u8]) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }

    /// Multi-part finalization function
    ///
    /// Verifies that the signature provided during the operation
    /// initialization matches the computed one.
    ///
    /// The operation is finalized and no other function can be
    /// called successfully afterwards.
    fn verify_final(&mut self) -> Result<()> {
        Err(CKR_GENERAL_ERROR)?
    }
}

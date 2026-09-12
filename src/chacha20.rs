// Copyright 2026 Alexandre Laroche
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for ChaCha20 and
//! ChaCha20-Poly1305 as defined in
//! [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439): _ChaCha20 and
//! Poly1305 for IETF Protocols_.
//!
//! Only the IETF parameter layout is supported: a 96-bit nonce (and, for
//! `CKM_CHACHA20`, a 32-bit block counter) -- the shape OpenSSL's
//! `EncAlg::ChaCha20`/`EncAlg::ChaCha20Poly1305` ciphers expect. PKCS#11
//! v3.0's alternative, original (64-bit-nonce/64-bit-counter) layout for
//! `CKM_CHACHA20` is not implemented.
//!
//! `CKM_CHACHA20_POLY1305` also implements message-mode
//! (`C_MessageEncryptInit`/`C_EncryptMessage`/`C_EncryptMessageNext`/
//! `C_MessageEncryptFinal` and their decrypt counterparts), since that is
//! how real-world consumers (e.g. pkcs11-provider, for TLS record
//! encryption) actually drive it.
//!
//! Neither mechanism is included in the `fips` feature bundle: ChaCha20
//! and ChaCha20-Poly1305 are not NIST/FIPS-approved algorithms (unlike
//! AES-GCM/CCM), so they are excluded the same way `hotp` already is --
//! by simply never appearing in the `fips` feature's dependency list,
//! rather than needing a `#[cfg(not(feature = "fips"))]` guard on top of
//! that (a FIPS build never combines extra, non-approved features on
//! its own).

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::mechanism::*;
use crate::object::*;
use crate::ossl::chacha20::*;
use crate::pkcs11::*;

/// ChaCha20 key size (256 bits), fixed by RFC 8439.
pub const CHACHA20_KEY_SIZE: usize = 32;

/// Object that holds ChaCha20 Mechanisms
///
/// `CKM_CHACHA20_POLY1305` gets its own entry, with the extra
/// `CKF_MESSAGE_ENCRYPT`/`CKF_MESSAGE_DECRYPT`/`CKF_MULTI_MESSAGE` flags:
/// message-mode (`C_MessageEncryptInit`/`C_EncryptMessage`/...) is how
/// real-world PKCS#11 consumers (e.g. pkcs11-provider, for TLS record
/// encryption) actually drive AEAD ciphers, reusing one initialized cipher
/// context across many independently-nonced messages -- mirroring how
/// `CKM_AES_GCM`/`CKM_AES_CCM` get a separate, message-flagged entry from
/// AES's other, non-AEAD modes. Plain `CKM_CHACHA20` has no such use case
/// and keeps classic `CKF_ENCRYPT`/`CKF_DECRYPT` only.
pub(crate) static CHACHA20_MECHS: LazyLock<[Box<dyn Mechanism>; 3]> =
    LazyLock::new(|| {
        [
            Box::new(ChaCha20Mechanism::new(CKF_ENCRYPT | CKF_DECRYPT)),
            Box::new(ChaCha20Mechanism::new(
                CKF_ENCRYPT
                    | CKF_DECRYPT
                    | CKF_MESSAGE_ENCRYPT
                    | CKF_MESSAGE_DECRYPT
                    | CKF_MULTI_MESSAGE,
            )),
            Box::new(ChaCha20Mechanism::new(CKF_GENERATE)),
        ]
    });

/// The ChaCha20 Key Factory facility.
static CHACHA20_KEY_FACTORY: LazyLock<Box<dyn ObjectFactory>> =
    LazyLock::new(|| Box::new(ChaCha20KeyFactory::new()));

/// Registers all implemented ChaCha20 Mechanisms and Factories
pub fn register(mechs: &mut Mechanisms, ot: &mut ObjectFactories) {
    ChaChaOperation::register_mechanisms(mechs);

    ot.add_factory(
        ObjectType::new(CKO_SECRET_KEY, CKK_CHACHA20),
        &(*CHACHA20_KEY_FACTORY),
    );
}

/// Specialized factory for objects of class `CKO_SECRET_KEY` and
/// `CKA_KEY_TYPE` of value `CKK_CHACHA20`.
///
/// [ChaCha20 secret key objects](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203478)
/// (Version 3.1)
///
/// Unlike AES, ChaCha20 has a single fixed key size (256 bits), so this
/// factory rejects any other length rather than selecting among several.
#[derive(Debug)]
pub struct ChaCha20KeyFactory {
    data: ObjectFactoryData,
}

impl ChaCha20KeyFactory {
    fn new() -> ChaCha20KeyFactory {
        let mut factory: ChaCha20KeyFactory = ChaCha20KeyFactory {
            data: ObjectFactoryData::new(CKO_SECRET_KEY),
        };

        factory.add_common_secret_key_attrs();

        let attributes = factory.data.get_attributes_mut();

        attributes.push(attr_element!(
            CKA_VALUE; OAFlags::Defval | OAFlags::Sensitive
            | OAFlags::RequiredOnCreate | OAFlags::SettableOnlyOnCreate;
            Attribute::from_bytes; val Vec::new()));
        attributes.push(attr_element!(
            CKA_VALUE_LEN; OAFlags::RequiredOnGenerate;
            Attribute::from_bytes; val Vec::new()));

        factory.data.finalize();

        factory
    }
}

impl ObjectFactory for ChaCha20KeyFactory {
    /// Creation of ChaCha20 keys uses the default generic secret creation
    /// code and additionally ensures the key is exactly 256 bits.
    fn create(&self, template: &[CK_ATTRIBUTE]) -> Result<Object> {
        let mut obj = self.key_create(template)?;
        let len = self.get_key_buffer_len(&obj)?;
        if len != CHACHA20_KEY_SIZE {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        obj.ensure_ulong(CKA_VALUE_LEN, CK_ULONG::try_from(len)?)?;

        Ok(obj)
    }

    fn get_data(&self) -> &ObjectFactoryData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut ObjectFactoryData {
        &mut self.data
    }

    fn as_key_factory(&self) -> Result<&dyn KeyFactory> {
        Ok(self)
    }

    fn as_secret_key_factory(&self) -> Result<&dyn SecretKeyFactory> {
        Ok(self)
    }
}

impl KeyFactory for ChaCha20KeyFactory {
    fn export_for_wrapping(&self, key: &Object) -> Result<Vec<u8>> {
        SecretKeyFactory::default_export_for_wrapping(self, key)
    }

    fn import_from_wrapped(
        &self,
        data: Vec<u8>,
        template: &[CK_ATTRIBUTE],
    ) -> Result<Object> {
        if data.len() != CHACHA20_KEY_SIZE {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        SecretKeyFactory::default_import_from_wrapped(self, data, template)
    }
}

impl SecretKeyFactory for ChaCha20KeyFactory {
    /// Helper that checks the key is correctly formed for a ChaCha20 key
    /// object (exactly 256 bits).
    fn set_key(&self, obj: &mut Object, key: Vec<u8>) -> Result<()> {
        if key.len() != CHACHA20_KEY_SIZE {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        self.set_key_len(obj, CHACHA20_KEY_SIZE)?;
        Ok(())
    }

    /// ChaCha20 has a single fixed key size (256 bits).
    fn recommend_key_size(&self, max: usize) -> Result<usize> {
        if max >= CHACHA20_KEY_SIZE {
            Ok(CHACHA20_KEY_SIZE)
        } else {
            Err(CKR_KEY_SIZE_RANGE)?
        }
    }
}

/// The Generic ChaCha20 Mechanism object
///
/// Implements access to the Mechanisms functions applicable to ChaCha20
/// and ChaCha20-Poly1305. The mechanism function returns an allocated
/// [ChaChaOperation] object for operations that need to keep data around
/// until they complete.
#[derive(Debug)]
pub(crate) struct ChaCha20Mechanism {
    info: CK_MECHANISM_INFO,
}

impl ChaCha20Mechanism {
    pub fn new(flags: CK_FLAGS) -> ChaCha20Mechanism {
        ChaCha20Mechanism {
            info: CK_MECHANISM_INFO {
                ulMinKeySize: CK_ULONG::try_from(CHACHA20_KEY_SIZE).unwrap(),
                ulMaxKeySize: CK_ULONG::try_from(CHACHA20_KEY_SIZE).unwrap(),
                flags: flags,
            },
        }
    }
}

impl Mechanism for ChaCha20Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn encryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Encryption>> {
        if self.info.flags & CKF_ENCRYPT != CKF_ENCRYPT {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        key.check_key_ops(CKO_SECRET_KEY, CKK_CHACHA20, CKA_ENCRYPT)?;
        Ok(Box::new(ChaChaOperation::encrypt_new(mech, key)?))
    }

    fn decryption_new(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn Decryption>> {
        if self.info.flags & CKF_DECRYPT != CKF_DECRYPT {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        key.check_key_ops(CKO_SECRET_KEY, CKK_CHACHA20, CKA_DECRYPT)?;
        Ok(Box::new(ChaChaOperation::decrypt_new(mech, key)?))
    }

    /// Implements the ChaCha20 Key generation mechanism (`CKM_CHACHA20_KEY_GEN`)
    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        _: &ObjectFactories,
    ) -> Result<Object> {
        if mech.mechanism != CKM_CHACHA20_KEY_GEN {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        let mut key = CHACHA20_KEY_FACTORY
            .as_key_factory()?
            .key_generate(template)?;
        key.ensure_ulong(CKA_CLASS, CKO_SECRET_KEY)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;
        key.ensure_ulong(CKA_KEY_TYPE, CKK_CHACHA20)
            .map_err(|_| CKR_TEMPLATE_INCONSISTENT)?;

        default_secret_key_generate(&mut key)?;
        default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }

    fn msg_encryption_op(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn MsgEncryption>> {
        if self.info.flags & CKF_MESSAGE_ENCRYPT == 0 {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        key.check_key_ops(CKO_SECRET_KEY, CKK_CHACHA20, CKA_ENCRYPT)?;
        Ok(Box::new(ChaChaOperation::msg_encrypt_init(mech, key)?))
    }

    fn msg_decryption_op(
        &self,
        mech: &CK_MECHANISM,
        key: &Object,
    ) -> Result<Box<dyn MsgDecryption>> {
        if self.info.flags & CKF_MESSAGE_DECRYPT == 0 {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        key.check_key_ops(CKO_SECRET_KEY, CKK_CHACHA20, CKA_DECRYPT)?;
        Ok(Box::new(ChaChaOperation::msg_decrypt_init(mech, key)?))
    }
}

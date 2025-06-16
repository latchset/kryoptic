// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides a coherent abstraction over the OpenSSL key
//! deriveation apis

use std::ffi::{c_int, c_uint, CStr};

use crate::bindings::*;
use crate::digest::{digest_to_string, DigestAlg};
use crate::{cstr, trace_ossl, Error, ErrorKind, OsslContext, OsslParam};

/// Wrapper around OpenSSL's `EVP_KDF_CTX`, managing its lifecycle.
#[derive(Debug)]
struct EvpKdfCtx {
    ptr: *mut EVP_KDF_CTX,
}

/// Methods for creating (from a named KDF) and accessing `EvpKdfCtx`.
impl EvpKdfCtx {
    /// Instantiates a new Kdf context
    fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpKdfCtx, Error> {
        let arg = unsafe {
            EVP_KDF_fetch(ctx.ptr(), name.as_ptr(), std::ptr::null_mut())
        };
        if arg.is_null() {
            trace_ossl!("EVP_KDF_fetch()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let ptr = unsafe { EVP_KDF_CTX_new(arg) };
        unsafe {
            EVP_KDF_free(arg);
        }
        if ptr.is_null() {
            trace_ossl!("EVP_KDF_CTX_new()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpKdfCtx { ptr })
    }

    /// calls the derive function with the provided paramters
    fn derive(
        &mut self,
        params: &OsslParam,
        output: &mut [u8],
    ) -> Result<(), Error> {
        let ret = unsafe {
            EVP_KDF_derive(
                self.ptr,
                output.as_mut_ptr(),
                output.len(),
                params.as_ptr(),
            )
        };
        if ret != 1 {
            trace_ossl!("EVP_KDF_derive()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }
}

impl Drop for EvpKdfCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_KDF_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpKdfCtx {}
unsafe impl Sync for EvpKdfCtx {}

/// HKDF Mode options
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HkdfMode {
    ExtractAndExpand,
    ExtractOnly,
    ExpandOnly,
}

/// Higher level wrapper for HKDF Derive operation
#[derive(Debug)]
pub struct HkdfDerive<'a> {
    /// The OpenSSL KDF context (`EVP_KDF_CTX`).
    ctx: EvpKdfCtx,
    /// the derivation mode
    mode: c_int,
    /// the requested digest function
    digest: DigestAlg,
    /// input keying material
    key: Option<&'a [u8]>,
    /// optional salt value (a non-secret random value)
    salt: Option<&'a [u8]>,
    /// optional context and application specific information
    info: Option<&'a [u8]>,
}

impl<'a> HkdfDerive<'a> {
    /// Instantiates a new HKDF context
    pub fn new(
        ctx: &OsslContext,
        digest: DigestAlg,
    ) -> Result<HkdfDerive<'a>, Error> {
        Ok(HkdfDerive {
            ctx: EvpKdfCtx::new(ctx, cstr!(OSSL_KDF_NAME_HKDF))?,
            mode: EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND as c_int,
            digest: digest,
            key: None,
            salt: None,
            info: None,
        })
    }

    /// Change HKDF mode
    pub fn set_mode(&mut self, mode: HkdfMode) {
        self.mode = match mode {
            HkdfMode::ExtractAndExpand => EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
            HkdfMode::ExtractOnly => EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
            HkdfMode::ExpandOnly => EVP_KDF_HKDF_MODE_EXPAND_ONLY,
        } as c_int;
    }

    /// Set the derivation key
    pub fn set_key(&mut self, key: &'a [u8]) {
        self.key = Some(key);
    }

    /// Set the salt (optional)
    pub fn set_salt(&mut self, salt: &'a [u8]) {
        self.salt = Some(salt);
    }

    /// Set additional Info (optional)
    pub fn set_info(&mut self, info: &'a [u8]) {
        self.info = Some(info);
    }

    /// Perform the derive operation based on the parameters set on the context
    /// The key parameter must have been set
    /// Returns the output in the provided output buffer
    pub fn derive(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let mut params = OsslParam::with_capacity(5);
        params.zeroize = true;
        params.add_const_c_string(
            cstr!(OSSL_KDF_PARAM_DIGEST),
            digest_to_string(self.digest),
        )?;
        params.add_int(cstr!(OSSL_KDF_PARAM_MODE), &self.mode)?;

        match &self.key {
            Some(k) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_KEY), k)?,
            None => return Err(Error::new(ErrorKind::KeyError)),
        }
        match &self.salt {
            Some(s) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_SALT), s)?,
            None => (),
        }
        match &self.info {
            Some(i) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_INFO), i)?,
            None => (),
        }
        params.finalize();

        self.ctx.derive(&params, output)
    }
}

/// Higher level wrapper for Pbkdf2 Derive operation
#[derive(Debug)]
pub struct Pbkdf2Derive<'a> {
    /// The OpenSSL KDF context (`EVP_KDF_CTX`).
    ctx: EvpKdfCtx,
    /// The digest used
    digest: DigestAlg,
    /// number of desired iterations
    iter: c_uint,
    /// the password to derive from
    password: Option<&'a [u8]>,
    /// an optional salt
    salt: Option<&'a [u8]>,
}

impl<'a> Pbkdf2Derive<'a> {
    /// Instantiates a new Pbkdf2 context
    pub fn new(
        ctx: &OsslContext,
        digest: DigestAlg,
    ) -> Result<Pbkdf2Derive<'a>, Error> {
        Ok(Pbkdf2Derive {
            ctx: EvpKdfCtx::new(ctx, cstr!(OSSL_KDF_NAME_PBKDF2))?,
            digest: digest,
            iter: 10000,
            password: None,
            salt: None,
        })
    }

    /// Set the desired iterations count
    pub fn set_iterations(&mut self, iterations: usize) {
        self.iter = c_uint::try_from(iterations).unwrap();
    }

    /// Set the password
    pub fn set_password(&mut self, password: &'a [u8]) {
        self.password = Some(password);
    }

    /// Set the salt
    pub fn set_salt(&mut self, salt: &'a [u8]) {
        self.salt = Some(salt);
    }

    /// Perform the derive operation based on the parameters set on the context
    /// The key parameter must have been set
    /// Returns the output in the provided output buffer
    pub fn derive(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let mut params = OsslParam::with_capacity(4);
        params.zeroize = true;
        params.add_const_c_string(
            cstr!(OSSL_KDF_PARAM_DIGEST),
            digest_to_string(self.digest),
        )?;
        params.add_uint(cstr!(OSSL_KDF_PARAM_ITER), &self.iter)?;
        match &self.password {
            Some(p) => {
                params.add_octet_slice(cstr!(OSSL_KDF_PARAM_PASSWORD), p)?
            }
            None => return Err(Error::new(ErrorKind::KeyError)),
        }
        match &self.salt {
            Some(s) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_SALT), s)?,
            None => (),
        }
        params.finalize();

        self.ctx.derive(&params, output)
    }
}

/// KBKDF Mode options
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KbkdfMode {
    Counter,
    Feedback,
}

/// KBKDF Mac Type (Hmac or Cmac)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KbkdfMac {
    HmacSha1,
    HmacSha2_224,
    HmacSha2_256,
    HmacSha2_384,
    HmacSha2_512,
    HmacSha2_512_224,
    HmacSha2_512_256,
    HmacSha3_224,
    HmacSha3_256,
    HmacSha3_384,
    HmacSha3_512,
    CmacAes128,
    CmacAes192,
    CmacAes256,
}

/// Allowed Counter length values
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KbkdfCounterLen {
    Len8b,
    Len16b,
    Len24b,
    Len32b,
}

/// Higher level wrapper for KBKDF Derive operation
#[derive(Debug)]
pub struct KbkdfDerive<'a> {
    /// The OpenSSL KDF context (`EVP_KDF_CTX`).
    ctx: EvpKdfCtx,
    /// The kind of Mac
    mac: KbkdfMac,
    /// The desired mode
    mode: KbkdfMode,
    /// The counter len (only 8, 16, 24, 32 supported)
    counter_len: c_int,
    /// Whether to add a separator (only 0 or 1)
    separator: c_int,
    /// Whether the Fixed Input Data length is added (only 0 or 1)
    fixed_len: c_int,
    /// The derivation key
    key: Option<&'a [u8]>,
    /// Info (context) string
    info: Option<&'a [u8]>,
    /// Salt (label) string
    salt: Option<&'a [u8]>,
    /// Seed for feedback mode
    seed: Option<&'a [u8]>,
}

impl<'a> KbkdfDerive<'a> {
    /// Instantiates a new HKDF context
    pub fn new(
        ctx: &OsslContext,
        mac: KbkdfMac,
        mode: KbkdfMode,
    ) -> Result<KbkdfDerive<'a>, Error> {
        Ok(KbkdfDerive {
            ctx: EvpKdfCtx::new(ctx, cstr!(OSSL_KDF_NAME_KBKDF))?,
            mac: mac,
            mode: mode,
            counter_len: 32,
            separator: 1,
            fixed_len: 1,
            key: None,
            info: None,
            salt: None,
            seed: None,
        })
    }

    /// Set the derivation key
    pub fn set_key(&mut self, key: &'a [u8]) {
        self.key = Some(key);
    }

    /// Set the counter length in bits
    pub fn set_counter_len(
        &mut self,
        bits: KbkdfCounterLen,
    ) -> Result<(), Error> {
        if !cfg!(ossl_v320) {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        self.counter_len = match bits {
            KbkdfCounterLen::Len8b => 8,
            KbkdfCounterLen::Len16b => 16,
            KbkdfCounterLen::Len24b => 24,
            KbkdfCounterLen::Len32b => 32,
        };
        Ok(())
    }

    /// Set whether a separator byte should be used
    pub fn use_separator(&mut self, b: bool) {
        self.separator = match b {
            true => 1,
            false => 0,
        }
    }

    /// Set whether the Counter length should be added at all
    pub fn use_fixed_len(&mut self, b: bool) {
        self.fixed_len = match b {
            true => 1,
            false => 0,
        }
    }

    /// Set info (context)
    pub fn set_info(&mut self, info: &'a [u8]) {
        self.info = Some(info);
    }

    /// Set salt (label)
    pub fn set_salt(&mut self, salt: &'a [u8]) {
        self.salt = Some(salt);
    }

    /// Set seed
    pub fn set_seed(&mut self, seed: &'a [u8]) {
        self.seed = Some(seed);
    }

    /// Perform the derive operation based on the parameters set on the context
    /// The key parameter must have been set
    /// Returns the output in the provided output buffer
    pub fn derive(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let mut params = OsslParam::with_capacity(10);
        params.zeroize = true;
        params.add_const_c_string(
            cstr!(OSSL_KDF_PARAM_MAC),
            match self.mac {
                KbkdfMac::CmacAes128
                | KbkdfMac::CmacAes192
                | KbkdfMac::CmacAes256 => c"CMAC",
                _ => c"HMAC",
            },
        )?;
        match self.mac {
            KbkdfMac::HmacSha1 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA1),
            )?,
            KbkdfMac::HmacSha2_224 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA2_224),
            )?,
            KbkdfMac::HmacSha2_256 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA2_256),
            )?,
            KbkdfMac::HmacSha2_384 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA2_384),
            )?,
            KbkdfMac::HmacSha2_512 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA2_512),
            )?,
            KbkdfMac::HmacSha2_512_224 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA2_512_224),
            )?,
            KbkdfMac::HmacSha2_512_256 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA2_512_256),
            )?,
            KbkdfMac::HmacSha3_224 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA3_224),
            )?,
            KbkdfMac::HmacSha3_256 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA3_256),
            )?,
            KbkdfMac::HmacSha3_384 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA3_384),
            )?,
            KbkdfMac::HmacSha3_512 => params.add_const_c_string(
                cstr!(OSSL_KDF_PARAM_DIGEST),
                cstr!(OSSL_DIGEST_NAME_SHA3_512),
            )?,
            KbkdfMac::CmacAes128 => params
                .add_const_c_string(cstr!(OSSL_KDF_PARAM_CIPHER), c"AES128")?,
            KbkdfMac::CmacAes192 => params
                .add_const_c_string(cstr!(OSSL_KDF_PARAM_CIPHER), c"AES192")?,
            KbkdfMac::CmacAes256 => params
                .add_const_c_string(cstr!(OSSL_KDF_PARAM_CIPHER), c"AES256")?,
        }

        params.add_const_c_string(
            cstr!(OSSL_KDF_PARAM_MODE),
            match self.mode {
                KbkdfMode::Counter => c"counter",
                KbkdfMode::Feedback => c"feedback",
            },
        )?;

        #[cfg(ossl_v320)]
        params.add_int(cstr!(OSSL_KDF_PARAM_KBKDF_R), &self.counter_len)?;

        params.add_int(
            cstr!(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR),
            &self.separator,
        )?;
        params.add_int(cstr!(OSSL_KDF_PARAM_KBKDF_USE_L), &self.fixed_len)?;

        match &self.key {
            Some(k) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_KEY), k)?,
            None => return Err(Error::new(ErrorKind::KeyError)),
        }
        match &self.info {
            Some(i) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_INFO), i)?,
            None => (),
        }
        match &self.salt {
            Some(s) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_SALT), s)?,
            None => (),
        }
        match &self.seed {
            Some(s) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_SEED), s)?,
            None => (),
        }
        params.finalize();

        self.ctx.derive(&params, output)
    }
}

/// SshKDF derivation purpose
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SshKdfPurpose {
    InitialIVClientToServer,
    InitialIVServerToClient,
    EncryptioKeyClientToServer,
    EncryptioKeyServerToClient,
    IntegrityKeyClientToServer,
    IntegrityKeyServerToClient,
}

/// Higher level wrapper for SSHKDF Derive operation
#[derive(Debug)]
pub struct SshkdfDerive<'a> {
    /// The OpenSSL KDF context (`EVP_KDF_CTX`).
    ctx: EvpKdfCtx,
    /// The purpose determines what type is generated
    purpose: &'static CStr,
    /// The digest function
    digest: DigestAlg,
    /// The key to derive from
    key: Option<&'a [u8]>,
    /// The SSH Exchange Hash
    hash: Option<&'a [u8]>,
    /// The SSH session id
    session: Option<&'a [u8]>,
}

impl<'a> SshkdfDerive<'a> {
    /// Instantiates a new SSHKDF context
    pub fn new(
        ctx: &OsslContext,
        digest: DigestAlg,
    ) -> Result<SshkdfDerive<'a>, Error> {
        Ok(SshkdfDerive {
            ctx: EvpKdfCtx::new(ctx, cstr!(OSSL_KDF_NAME_SSHKDF))?,
            digest: digest,
            purpose: c"A",
            key: None,
            hash: None,
            session: None,
        })
    }

    /// Sets the SSHKDF type of key we want (purpose)
    pub fn set_purpose(&mut self, purpose: SshKdfPurpose) {
        self.purpose = match purpose {
            SshKdfPurpose::InitialIVClientToServer => c"A",
            SshKdfPurpose::InitialIVServerToClient => c"B",
            SshKdfPurpose::EncryptioKeyClientToServer => c"C",
            SshKdfPurpose::EncryptioKeyServerToClient => c"D",
            SshKdfPurpose::IntegrityKeyClientToServer => c"E",
            SshKdfPurpose::IntegrityKeyServerToClient => c"F",
        }
    }

    /// Set the derivation key
    pub fn set_key(&mut self, key: &'a [u8]) {
        self.key = Some(key);
    }

    /// Set the exchange hash
    pub fn set_hash(&mut self, hash: &'a [u8]) {
        self.hash = Some(hash);
    }

    /// Set session id
    pub fn set_session(&mut self, session: &'a [u8]) {
        self.session = Some(session);
    }

    /// Perform the derive operation based on the parameters set on the context
    /// The key parameter must have been set
    /// Returns the output in the provided output buffer
    pub fn derive(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let mut params = OsslParam::with_capacity(5);
        params.zeroize = true;
        params.add_const_c_string(
            cstr!(OSSL_KDF_PARAM_DIGEST),
            digest_to_string(self.digest),
        )?;

        match &self.key {
            Some(k) => params.add_octet_slice(cstr!(OSSL_KDF_PARAM_KEY), k)?,
            None => return Err(Error::new(ErrorKind::KeyError)),
        }
        match &self.hash {
            Some(h) => params
                .add_octet_slice(cstr!(OSSL_KDF_PARAM_SSHKDF_XCGHASH), h)?,
            None => (),
        }
        params.add_const_c_string(
            cstr!(OSSL_KDF_PARAM_SSHKDF_TYPE),
            self.purpose,
        )?;
        match &self.session {
            Some(s) => params
                .add_octet_slice(cstr!(OSSL_KDF_PARAM_SSHKDF_SESSION_ID), s)?,
            None => (),
        }
        params.finalize();

        self.ctx.derive(&params, output)
    }
}

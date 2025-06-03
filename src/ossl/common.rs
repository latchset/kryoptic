// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module provides common utilities, wrappers, and constants for interacting
//! with the OpenSSL library (`libcrypto`) via its C API, primarily focusing on
//! the EVP (high-level) interface and parameter handling (`OSSL_PARAM`).

use std::borrow::Cow;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr};

use crate::error::{Error, Result};
use crate::interface::*;
#[cfg(feature = "ecc")]
use crate::kasn1::oid;
use crate::misc::*;
#[cfg(any(feature = "ecc", feature = "rsa"))]
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::get_libctx;

#[cfg(feature = "ecc")]
use crate::ec::get_oid_from_obj;
#[cfg(feature = "ecdsa")]
use crate::ossl::ecdsa;
#[cfg(feature = "eddsa")]
use crate::ossl::eddsa;
#[cfg(feature = "ffdh")]
use crate::ossl::ffdh;
#[cfg(feature = "mldsa")]
use crate::ossl::mldsa;
#[cfg(feature = "mlkem")]
use crate::ossl::mlkem;
#[cfg(feature = "ec_montgomery")]
use crate::ossl::montgomery as ecm;
#[cfg(feature = "rsa")]
use crate::ossl::rsa;

/// Wrapper around OpenSSL's `EVP_MD`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMd {
    ptr: *mut EVP_MD,
}

/// Methods for creating and accessing `EvpMd`.
impl EvpMd {
    pub fn new(name: *const c_char) -> Result<EvpMd> {
        let ptr =
            unsafe { EVP_MD_fetch(get_libctx(), name, std::ptr::null_mut()) };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_fetch()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpMd { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MD`.
    pub unsafe fn as_ptr(&self) -> *const EVP_MD {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_MD`.
    #[allow(dead_code)]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MD {
        self.ptr
    }
}

impl Drop for EvpMd {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpMd {}
unsafe impl Sync for EvpMd {}

/// Wrapper around OpenSSL's `EVP_MD_CTX`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMdCtx {
    ptr: *mut EVP_MD_CTX,
}

/// Methods for creating and accessing `EvpMdCtx`.
impl EvpMdCtx {
    pub fn new() -> Result<EvpMdCtx> {
        let ptr = unsafe { EVP_MD_CTX_new() };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_ctx_new()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpMdCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MD_CTX`.
    #[allow(dead_code)]
    pub unsafe fn as_ptr(&self) -> *const EVP_MD_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_MD_CTX`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MD_CTX {
        self.ptr
    }
}

impl Drop for EvpMdCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpMdCtx {}
unsafe impl Sync for EvpMdCtx {}

/// Wrapper around OpenSSL's `EVP_CIPHER`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpCipher {
    ptr: *mut EVP_CIPHER,
}

/// Methods for creating and accessing `EvpCipher`.
impl EvpCipher {
    pub fn new(name: *const c_char) -> Result<EvpCipher> {
        let ptr = unsafe {
            EVP_CIPHER_fetch(get_libctx(), name, std::ptr::null_mut())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_CIPHER_fetch()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpCipher { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_CIPHER`.
    pub unsafe fn as_ptr(&self) -> *const EVP_CIPHER {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_CIPHER`.
    #[allow(dead_code)]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_CIPHER {
        self.ptr
    }
}

impl Drop for EvpCipher {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpCipher {}
unsafe impl Sync for EvpCipher {}

/// Wrapper around OpenSSL's `EVP_CIPHER_CTX`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpCipherCtx {
    ptr: *mut EVP_CIPHER_CTX,
}

/// Methods for creating and accessing `EvpCipherCtx`.
impl EvpCipherCtx {
    pub fn new() -> Result<EvpCipherCtx> {
        let ptr = unsafe { EVP_CIPHER_CTX_new() };
        if ptr.is_null() {
            trace_ossl!("EVP_CIPHER_ctx_new()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpCipherCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_CIPHER_CTX`.
    #[allow(dead_code)]
    pub unsafe fn as_ptr(&self) -> *const EVP_CIPHER_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_CIPHER_CTX`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_CIPHER_CTX {
        self.ptr
    }
}

impl Drop for EvpCipherCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpCipherCtx {}
unsafe impl Sync for EvpCipherCtx {}

/// Wrapper around OpenSSL's `EVP_KDF_CTX`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpKdfCtx {
    ptr: *mut EVP_KDF_CTX,
}

/// Methods for creating (from a named KDF) and accessing `EvpKdfCtx`.
impl EvpKdfCtx {
    pub fn new(name: *const c_char) -> Result<EvpKdfCtx> {
        let arg = unsafe {
            EVP_KDF_fetch(get_libctx(), name, std::ptr::null_mut()) // [cite: 31]
        };
        if arg.is_null() {
            trace_ossl!("EVP_KDF_fetch()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let ptr = unsafe { EVP_KDF_CTX_new(arg) };
        unsafe {
            EVP_KDF_free(arg);
        }
        if ptr.is_null() {
            trace_ossl!("EVP_KDF_CTX_new()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpKdfCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_KDF_CTX`.
    #[allow(dead_code)]
    pub unsafe fn as_ptr(&self) -> *const EVP_KDF_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_KDF_CTX`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_KDF_CTX {
        self.ptr
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

/// Wrapper around OpenSSL's `EVP_MAC_CTX`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMacCtx {
    ptr: *mut EVP_MAC_CTX,
}

/// Methods for creating (from a named MAC) and accessing `EvpMacCtx`.
impl EvpMacCtx {
    pub fn new(name: *const c_char) -> Result<EvpMacCtx> {
        let arg =
            unsafe { EVP_MAC_fetch(get_libctx(), name, std::ptr::null_mut()) };
        if arg.is_null() {
            trace_ossl!("EVP_MAC_fetch()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let ptr = unsafe { EVP_MAC_CTX_new(arg) };
        unsafe {
            EVP_MAC_free(arg);
        }
        if ptr.is_null() {
            trace_ossl!("EVP_MAC_CTX_new()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpMacCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MAC_CTX`.
    #[allow(dead_code)]
    pub unsafe fn as_ptr(&self) -> *const EVP_MAC_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_MAC_CTX`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut EVP_MAC_CTX {
        self.ptr
    }
}

impl Drop for EvpMacCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_MAC_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpMacCtx {}
unsafe impl Sync for EvpMacCtx {}

/// Wrapper around OpenSSL's `EVP_PKEY_CTX`, managing its lifecycle.
/// Used for various public key algorithm operations (key generation, signing,
/// encryption context setup, etc.).
#[cfg(any(feature = "ecc", feature = "rsa"))]
#[derive(Debug)]
pub struct EvpPkeyCtx {
    ptr: *mut EVP_PKEY_CTX,
}

/// Methods for creating and accessing `EvpPkeyCtx`.
#[cfg(any(feature = "ecc", feature = "rsa"))]
impl EvpPkeyCtx {
    /// Fecthes an algorithm by name and returns a wrapper `EvpPkeyCtx`
    /// Or fails with `CKR_DEVICE_ERROR`
    pub fn new(name: *const c_char) -> Result<EvpPkeyCtx> {
        let ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(get_libctx(), name, std::ptr::null())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_PKEY_CTX_new_from_name()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Creates an `EvpPkeyCtx` from an existing raw pointer (takes ownership).
    pub unsafe fn from_ptr(ptr: *mut EVP_PKEY_CTX) -> Result<EvpPkeyCtx> {
        if ptr.is_null() {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Returns a const pointer to the underlying `EVP_PKEY_CTX`.
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const EVP_PKEY_CTX {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_PKEY_CTX`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY_CTX {
        self.ptr
    }
}

#[cfg(any(feature = "ecc", feature = "rsa"))]
impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.ptr);
        }
    }
}

#[cfg(any(feature = "ecc", feature = "rsa"))]
unsafe impl Send for EvpPkeyCtx {}
#[cfg(any(feature = "ecc", feature = "rsa"))]
unsafe impl Sync for EvpPkeyCtx {}

/// Wrapper around OpenSSL's `EVP_PKEY`, representing a generic public or
/// private key. Manages the key's lifecycle.
#[cfg(any(feature = "ecc", feature = "rsa"))]
#[derive(Debug)]
pub struct EvpPkey {
    ptr: *mut EVP_PKEY,
}

#[cfg(any(feature = "ecc", feature = "rsa"))]
impl EvpPkey {
    /// Creates an `EvpPkey` from key material provided via `OSSL_PARAM`s.
    ///
    /// Used for importing public or private keys based on their components
    /// (e.g., modulus/exponent for RSA, curve/point for EC).
    pub fn fromdata(
        pkey_name: *const c_char,
        pkey_type: u32,
        params: &OsslParam,
    ) -> Result<EvpPkey> {
        let mut ctx = EvpPkeyCtx::new(pkey_name)?;
        let res = unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata_init()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_fromdata(
                ctx.as_mut_ptr(),
                &mut pkey,
                pkey_type as i32,
                params.as_ptr() as *mut OSSL_PARAM,
            )
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Exports key material components into an `OsslParam` structure.
    ///
    /// The `selection` argument specifies which components to export
    /// (e.g., public, private, parameters).
    pub fn todata(&self, selection: u32) -> Result<OsslParam> {
        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        if unsafe {
            EVP_PKEY_todata(self.ptr, c_int::try_from(selection)?, &mut params)
        } != 1
        {
            trace_ossl!("EVP_PKEY_todata()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        OsslParam::from_ptr(params)
    }

    /// Allow to get parameters from a key.
    /// The caller must preallocate the payloads with enough space to
    /// receive the data, which is copied into the parameters.
    pub fn get_params(&self, params: &mut OsslParam) -> Result<()> {
        if unsafe { EVP_PKEY_get_params(self.ptr, params.as_mut_ptr()) } != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(())
    }

    /// Generates a new key pair based on provided algorithm name and
    /// parameters.
    ///
    /// The parameters (`OsslParam`) specify details like key size or curve
    /// name.
    pub fn generate(
        pkey_name: *const c_char,
        params: &OsslParam,
    ) -> Result<EvpPkey> {
        let mut ctx = EvpPkeyCtx::new(pkey_name)?;
        let res = unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_keygen_init()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let res = unsafe {
            EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_CTX_set_params()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(ctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_generate()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Creates a new `EvpPkeyCtx` associated with this `EvpPkey`.
    ///
    /// Used to prepare for operations using this specific key.
    pub fn new_ctx(&mut self) -> Result<EvpPkeyCtx> {
        /* this function takes care of checking for NULL */
        unsafe {
            EvpPkeyCtx::from_ptr(
                /* this function will use refcounting to keep EVP_PKEY
                 * alive for the lifetime of the context, so it is ok
                 * to not use rust lifetimes here */
                EVP_PKEY_CTX_new_from_pkey(
                    get_libctx(),
                    self.as_mut_ptr(),
                    std::ptr::null_mut(),
                ),
            )
        }
    }

    /// Returns a const pointer to the underlying `EVP_PKEY`.
    pub fn as_ptr(&self) -> *const EVP_PKEY {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_PKEY`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY {
        self.ptr
    }

    /// Creates an `EvpPkey` (public or private) from a PKCS#11 `Object`.
    ///
    /// Extracts necessary attributes from the `Object` based on its
    /// `CKA_KEY_TYPE` and `class` (public/private), converts them into
    /// `OSSL_PARAM`s using algorithm-specific helpers, and then calls
    /// `EvpPkey::fromdata`.
    fn from_object(obj: &Object, class: CK_OBJECT_CLASS) -> Result<EvpPkey> {
        let key_class = match class {
            CKO_PUBLIC_KEY => EVP_PKEY_PUBLIC_KEY,
            CKO_PRIVATE_KEY => EVP_PKEY_PRIVATE_KEY,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };
        let key_type = obj.get_attr_as_ulong(CKA_KEY_TYPE)?;
        let (name, params) = match key_type {
            #[cfg(feature = "ecdsa")]
            CKK_EC => ecdsa::ecc_object_to_params(obj, class)?,
            #[cfg(feature = "eddsa")]
            CKK_EC_EDWARDS => eddsa::eddsa_object_to_params(obj, class)?,
            #[cfg(feature = "ec_montgomery")]
            CKK_EC_MONTGOMERY => ecm::ecm_object_to_params(obj, class)?,
            #[cfg(feature = "ffdh")]
            CKK_DH => ffdh::ffdh_object_to_params(obj, class)?,
            #[cfg(feature = "rsa")]
            CKK_RSA => rsa::rsa_object_to_params(obj, class)?,
            #[cfg(feature = "mlkem")]
            CKK_ML_KEM => mlkem::mlkem_object_to_params(obj, class)?,
            #[cfg(feature = "mldsa")]
            CKK_ML_DSA => mldsa::mldsa_object_to_params(obj, class)?,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
        };
        Self::fromdata(name, key_class, &params)
    }

    /// Creates a public `EvpPkey` from a PKCS#11 `Object`.
    #[allow(dead_code)]
    pub fn pubkey_from_object(obj: &Object) -> Result<EvpPkey> {
        Self::from_object(obj, CKO_PUBLIC_KEY)
    }

    /// Creates a private `EvpPkey` from a PKCS#11 `Object`.
    #[allow(dead_code)]
    pub fn privkey_from_object(obj: &Object) -> Result<EvpPkey> {
        Self::from_object(obj, CKO_PRIVATE_KEY)
    }

    /// Gets the key size in bits. Handles FIPS provider differences.
    #[cfg(not(feature = "fips"))]
    pub fn get_bits(&self) -> Result<usize> {
        let ret = unsafe { EVP_PKEY_get_bits(self.ptr) };
        if ret == 0 {
            return Err(CKR_KEY_INDIGESTIBLE)?;
        }
        Ok(usize::try_from(ret)?)
    }
    #[cfg(feature = "fips")]
    pub fn get_bits(&self) -> Result<usize> {
        /* EVP_PKEY_get_bits() not available in libfips.a */
        let mut bits: c_int = 0;
        let ret = unsafe {
            EVP_PKEY_get_int_param(
                self.ptr,
                name_as_char(OSSL_PKEY_PARAM_BITS),
                &mut bits,
            )
        };
        if ret == 0 {
            return Err(CKR_KEY_INDIGESTIBLE)?;
        }
        Ok(usize::try_from(bits)?)
    }
}

#[cfg(any(feature = "ecc", feature = "rsa"))]
impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.ptr);
        }
    }
}

#[cfg(any(feature = "ecc", feature = "rsa"))]
unsafe impl Send for EvpPkey {}
#[cfg(any(feature = "ecc", feature = "rsa"))]
unsafe impl Sync for EvpPkey {}

pub const CIPHER_NAME_AES128: &[u8; 7] = b"AES128\0";
pub const CIPHER_NAME_AES192: &[u8; 7] = b"AES192\0";
pub const CIPHER_NAME_AES256: &[u8; 7] = b"AES256\0";

/// Utility function to cast a Rust byte slice (`&[u8]`) to a C-style
/// null-terminated string pointer (`*const c_char`).
pub fn name_as_char(name: &[u8]) -> *const c_char {
    name.as_ptr() as *const c_char
}

/// Wrapper around OpenSSL's `BIGNUM` type for handling large numbers.
/// Manages the lifecycle and provides conversion methods.
#[derive(Debug)]
struct BigNum {
    bn: *const BIGNUM,
}

impl BigNum {
    /// Allocates a new BIGNUM from a vector of bytes with the binary
    /// representation of the number in big endian byte order (most
    /// significant byte first).
    ///
    /// Returns a wrapped `BigNum` or `CKR_DEVICE_ERROR` if the import
    /// fails.
    pub fn from_bigendian_vec(v: &Vec<u8>) -> Result<BigNum> {
        let bn = unsafe {
            BN_bin2bn(
                v.as_ptr() as *mut u8,
                c_int::try_from(v.len())?,
                std::ptr::null_mut(),
            )
        };
        if bn.is_null() {
            trace_ossl!("BN_bin2bn()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(BigNum {
            bn: bn as *const BIGNUM,
        })
    }

    /// Calculates the minimum number of bytes needed to represent the `BIGNUM`.
    pub fn len(&self) -> Result<usize> {
        let x = unsafe { (BN_num_bits(self.bn) + 7) / 8 };
        Ok(usize::try_from(x)?)
    }

    /// Creates a `BigNum` by extracting it from an `OSSL_PARAM`.
    pub fn from_param(p: *const OSSL_PARAM) -> Result<BigNum> {
        let mut bn: *mut BIGNUM = std::ptr::null_mut();
        if unsafe { OSSL_PARAM_get_BN(p, &mut bn) } != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        Ok(BigNum {
            bn: bn as *const BIGNUM,
        })
    }

    /// Converts the `BIGNUM` to a byte vector in native-endian format, padded
    /// to the required length. Primarily used internally for constructing
    /// `OSSL_PARAM`s.
    pub fn to_native_vec(&self) -> Result<Vec<u8>> {
        let mut v = vec![0u8; self.len()?];
        if v.len() == 0 {
            v.push(0);
        }
        if unsafe {
            BN_bn2nativepad(self.bn, v.as_mut_ptr(), c_int::try_from(v.len())?)
        } < 1
        {
            trace_ossl!("BN_bn2nativepad()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(v)
    }

    /// Converts the `BIGNUM` to a byte vector in big-endian format (standard
    /// external representation).
    pub fn to_bigendian_vec(&self) -> Result<Vec<u8>> {
        let len = self.len()?;
        let mut v = vec![0u8; self.len()?];
        let ret = unsafe { BN_bn2bin(self.bn, v.as_mut_ptr()) };
        if usize::try_from(ret)? != len {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(v)
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        unsafe {
            BN_free(self.bn as *mut BIGNUM);
        }
    }
}

/// A safe builder and manager for OpenSSL `OSSL_PARAM` arrays.
///
/// `OSSL_PARAM` is the primary way to pass detailed parameters (like key
/// components, algorithm settings) to many OpenSSL 3.0+ EVP functions.
///
/// This struct handles memory management (including optional zeroization) and
/// lifetime complexities when constructing these arrays from Rust types.
#[derive(Debug)]
pub struct OsslParam<'a> {
    /// Storage for owned byte buffers backing some parameters.
    v: Vec<Vec<u8>>,
    /// The actual `OSSL_PARAM` array, potentially borrowed or owned.
    p: Cow<'a, [OSSL_PARAM]>,
    /// Flag indicating if the construction of the params has been finalized
    finalized: bool,
    /// Flag indicating the storage buffer should be zeroized on drop
    pub zeroize: bool,
    /// Flag indicating `p` contains an owned pointer we are responsible
    /// for freeing
    pub freeptr: bool,
    /// Use an enum to hold references to data we need to keep around as
    /// a pointer to their datais stored in the OSSL_PARAM array
    br: Vec<BorrowedReference<'a>>,
}

impl Drop for OsslParam<'_> {
    fn drop(&mut self) {
        if self.zeroize {
            while let Some(mut elem) = self.v.pop() {
                zeromem(elem.as_mut_slice());
            }
        }
        if self.freeptr {
            unsafe {
                OSSL_PARAM_free(self.p.as_ref().as_ptr() as *mut OSSL_PARAM);
            }
        }
    }
}

impl<'a> OsslParam<'a> {
    /// Creates a new, empty `OsslParam` builder.
    #[allow(dead_code)]
    pub fn new() -> OsslParam<'a> {
        Self::with_capacity(0)
    }

    /// Creates a new, empty `OsslParam` builder with a specific initial
    /// capacity.
    pub fn with_capacity(capacity: usize) -> OsslParam<'a> {
        OsslParam {
            v: Vec::new(),
            p: Cow::Owned(Vec::with_capacity(capacity + 1)),
            finalized: false,
            zeroize: false,
            freeptr: false,
            br: Vec::new(),
        }
    }

    /// Creates an `OsslParam` instance by borrowing an existing `OSSL_PARAM`
    /// array from OpenSSL. Takes ownership of the pointer and marks it to be
    /// freed on drop.
    #[allow(dead_code)]
    pub fn from_ptr(ptr: *mut OSSL_PARAM) -> Result<OsslParam<'static>> {
        if ptr.is_null() {
            return Err(CKR_DEVICE_ERROR)?;
        }
        /* get num of elements */
        let mut nelem = 0;
        let mut counter = ptr;
        unsafe {
            while !(*counter).key.is_null() {
                nelem += 1;
                counter = counter.offset(1);
            }
        }
        /* Mark as finalized as no changes are allowed to imported params */
        Ok(OsslParam {
            v: Vec::new(),
            p: Cow::Borrowed(unsafe {
                std::slice::from_raw_parts(ptr, nelem + 1)
            }),
            finalized: true,
            zeroize: false,
            freeptr: true,
            br: Vec::new(),
        })
    }

    /// Creates an empty, finalized `OsslParam` array (contains only the end
    /// marker).
    #[allow(dead_code)]
    pub fn empty() -> OsslParam<'static> {
        let mut p = OsslParam {
            v: Vec::new(),
            p: Cow::Owned(Vec::with_capacity(1)),
            finalized: false,
            zeroize: false,
            freeptr: false,
            br: Vec::new(),
        };
        p.finalize();
        p
    }

    /// Adds a BIGNUM parameter from a big-endian byte vector.
    ///
    /// Handles the necessary conversions for OpenSSL's native-endian BIGNUM
    /// representation within `OSSL_PARAM`.
    pub fn add_bn(&mut self, key: *const c_char, v: &Vec<u8>) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        /* need to go through all these functions because,
         * BN_bin2bn() takes a Big Endian number,
         * but BN_bn2nativepad() later will convert it to
         * native endianness, ensuring the buffer we pass in
         * is in the correct order for openssl ...
         */
        let bn = BigNum::from_bigendian_vec(v)?;
        let container = bn.to_native_vec()?;
        let param = unsafe {
            OSSL_PARAM_construct_BN(
                key,
                byte_ptr!(container.as_ptr()),
                container.len(),
            )
        };
        self.v.push(container);
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Adds a UTF-8 string parameter using a borrowed byte vector reference.
    #[allow(dead_code)]
    pub fn add_utf8_string(
        &mut self,
        key: *const c_char,
        v: &'a Vec<u8>,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key,
                void_ptr!(v.as_ptr()) as *mut c_char,
                0,
            )
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Vector(v));
        Ok(())
    }

    /// Adds a UTF-8 string parameter using an owned byte vector.
    #[allow(dead_code)]
    pub fn add_owned_utf8_string(
        &mut self,
        key: *const c_char,
        mut v: Vec<u8>,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key,
                void_ptr!(v.as_mut_ptr()) as *mut c_char,
                0,
            )
        };
        self.v.push(v);
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Adds an empty sized string to receive values from queries like
    /// get_params()
    pub fn add_empty_utf8_string(
        &mut self,
        key: *const c_char,
        len: usize,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let mut v = vec![0u8; len];
        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key,
                void_ptr!(v.as_mut_ptr()) as *mut c_char,
                len,
            )
        };
        self.v.push(v);
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Adds a UTF-8 string parameter using a borrowed C string pointer.
    ///
    /// Assumes `key` and `val` point to valid, null-terminated C strings.
    /// The caller must ensure their lifetimes exceed the `OsslParam`'s usage.
    ///
    /// Should only be used with actual const strings.
    #[allow(dead_code)]
    pub fn add_const_c_string(
        &mut self,
        key: *const c_char,
        val: *const c_char,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() || val == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(key, val as *mut c_char, 0)
        };
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Adds an octet string (byte array) parameter using a borrowed byte
    /// vector reference.
    ///
    /// The caller must ensure their lifetimes exceed the `OsslParam`'s usage.
    #[allow(dead_code)]
    pub fn add_octet_string(
        &mut self,
        key: *const c_char,
        v: &'a Vec<u8>,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_octet_string(
                key,
                void_ptr!(v.as_ptr()),
                v.len(),
            )
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Vector(v));
        Ok(())
    }

    /// Adds an octet string (byte array) parameter using an owned byte vector.
    #[allow(dead_code)]
    pub fn add_owned_octet_string(
        &mut self,
        key: *const c_char,
        v: Vec<u8>,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_octet_string(
                key,
                void_ptr!(v.as_ptr()),
                v.len(),
            )
        };
        self.v.push(v);
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Adds a `size_t` parameter using a borrowed reference.
    ///
    /// The caller must ensure the lifetime of `val` exceeds the `OsslParam`'s
    /// usage.
    #[allow(dead_code)]
    pub fn add_size_t(
        &mut self,
        key: *const c_char,
        val: &'a usize,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_size_t(key, val as *const _ as *mut usize)
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Usize(val));
        Ok(())
    }

    /// Adds a `c_uint` parameter using a borrowed reference.
    ///
    /// The caller must ensure the lifetime of `val` exceeds the `OsslParam`'s
    /// usage.
    #[allow(dead_code)]
    pub fn add_uint(
        &mut self,
        key: *const c_char,
        val: &'a c_uint,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_uint(key, val as *const _ as *mut c_uint)
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Uint(val));
        Ok(())
    }

    /// Adds a `c_int` parameter using a borrowed reference.
    ///
    /// The caller must ensure the lifetime of `val` exceeds the `OsslParam`'s
    /// usage.
    #[allow(dead_code)]
    pub fn add_int(
        &mut self,
        key: *const c_char,
        val: &'a c_int,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let param = unsafe {
            OSSL_PARAM_construct_int(key, val as *const _ as *mut c_int)
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Int(val));
        Ok(())
    }

    /// Adds an `c_uint` parameter using an owned value.
    #[allow(dead_code)]
    pub fn add_owned_uint(
        &mut self,
        key: *const c_char,
        val: c_uint,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let v = val.to_ne_bytes().to_vec();

        let param = unsafe {
            OSSL_PARAM_construct_uint(
                key,
                v.as_ptr() as *const _ as *mut c_uint,
            )
        };
        self.v.push(v);
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Adds an `c_uint` parameter using an owned value.
    #[allow(dead_code)]
    pub fn add_owned_int(
        &mut self,
        key: *const c_char,
        val: c_int,
    ) -> Result<()> {
        if self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }

        if key == std::ptr::null() {
            return Err(CKR_GENERAL_ERROR)?;
        }

        let v = val.to_ne_bytes().to_vec();

        let param = unsafe {
            OSSL_PARAM_construct_int(key, v.as_ptr() as *const _ as *mut c_int)
        };
        self.v.push(v);
        self.p.to_mut().push(param);
        Ok(())
    }

    /// Finalizes the `OSSL_PARAM` array by adding the end marker.
    ///
    /// Must be called before `as_ptr` or `as_mut_ptr` can be safely used.
    pub fn finalize(&mut self) {
        if !self.finalized {
            self.p.to_mut().push(unsafe { OSSL_PARAM_construct_end() });
            self.finalized = true;
        }
    }

    /// Returns a const pointer to the finalized `OSSL_PARAM` array.
    ///
    /// Panics if the array has not been finalized.
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.p.as_ref().as_ptr()
    }

    /// Returns a mutable pointer to the finalized `OSSL_PARAM` array.
    ///
    /// Panics if the array has not been finalized.
    #[allow(dead_code)]
    pub fn as_mut_ptr(&mut self) -> *mut OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.p.to_mut().as_mut_ptr()
    }

    /// Gets the value of an integer parameter by its key name.
    #[allow(dead_code)]
    pub fn get_int(&self, key: *const c_char) -> Result<c_int> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let mut val: c_int = 0;
        let res = unsafe { OSSL_PARAM_get_int(p, &mut val) };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_int()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(val)
    }

    /// Gets the value of a long parameter by its key name.
    #[allow(dead_code)]
    pub fn get_long(&self, key: *const c_char) -> Result<c_long> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let mut val: c_long = 0;
        let res = unsafe { OSSL_PARAM_get_long(p, &mut val) };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_long()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(val)
    }

    /// Gets the value of a BIGNUM parameter by its key name as a big-endian
    /// byte vector.
    pub fn get_bn(&self, key: *const c_char) -> Result<Vec<u8>> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let bn = BigNum::from_param(p)?;
        bn.to_bigendian_vec()
    }

    /// Gets the value of an octet string parameter by its key name as a byte
    /// slice.
    #[allow(dead_code)]
    pub fn get_octet_string(&self, key: *const c_char) -> Result<&'a [u8]> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            let keyname =
                unsafe { String::from(CStr::from_ptr(key).to_str().unwrap()) };
            return Err(Error::not_found(keyname));
        }
        let mut buf: *const c_void = std::ptr::null_mut();
        let mut buf_len: usize = 0;
        let res = unsafe {
            OSSL_PARAM_get_octet_string_ptr(p, &mut buf, &mut buf_len)
        };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_octet_string_ptr()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let octet =
            unsafe { std::slice::from_raw_parts(buf as *const u8, buf_len) };
        Ok(octet)
    }

    /// Gets a UTF8 String as vector, this includes the terminating NUL
    #[allow(dead_code)]
    pub fn get_utf8_string_as_vec(
        &self,
        key: *const c_char,
    ) -> Result<Vec<u8>> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            let keyname =
                unsafe { String::from(CStr::from_ptr(key).to_str().unwrap()) };
            return Err(Error::not_found(keyname));
        }
        let mut ptr: *const c_char = std::ptr::null_mut();
        let res = unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &mut ptr) };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_utf8_string_ptr()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        let s = unsafe { CStr::from_ptr(ptr) };
        Ok(s.to_bytes_with_nul().to_vec())
    }

    /// Checks if a parameter with the given key name exists in the array.
    #[allow(dead_code)]
    pub fn has_param(&self, key: *const c_char) -> Result<bool> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

/// Maps a PKCS#11 mechanism type involving a hash to the corresponding
/// OpenSSL digest name string (e.g., `CKM_SHA256_RSA_PKCS` -> `"SHA256"`).
pub fn mech_type_to_digest_name(mech: CK_MECHANISM_TYPE) -> *const c_char {
    (match mech {
        CKM_SHA1_RSA_PKCS
        | CKM_ECDSA_SHA1
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA_1_HMAC
        | CKM_SHA_1_HMAC_GENERAL
        | CKM_SHA_1 => OSSL_DIGEST_NAME_SHA1.as_ptr(),
        CKM_SHA224_RSA_PKCS
        | CKM_ECDSA_SHA224
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA224_HMAC
        | CKM_SHA224_HMAC_GENERAL
        | CKM_SHA224 => OSSL_DIGEST_NAME_SHA2_224.as_ptr(),
        CKM_SHA256_RSA_PKCS
        | CKM_ECDSA_SHA256
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA256_HMAC
        | CKM_SHA256_HMAC_GENERAL
        | CKM_SHA256 => OSSL_DIGEST_NAME_SHA2_256.as_ptr(),
        CKM_SHA384_RSA_PKCS
        | CKM_ECDSA_SHA384
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA384_HMAC
        | CKM_SHA384_HMAC_GENERAL
        | CKM_SHA384 => OSSL_DIGEST_NAME_SHA2_384.as_ptr(),
        CKM_SHA512_RSA_PKCS
        | CKM_ECDSA_SHA512
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA512_HMAC
        | CKM_SHA512_HMAC_GENERAL
        | CKM_SHA512 => OSSL_DIGEST_NAME_SHA2_512.as_ptr(),
        CKM_SHA3_224_RSA_PKCS
        | CKM_ECDSA_SHA3_224
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_224_HMAC
        | CKM_SHA3_224_HMAC_GENERAL
        | CKM_SHA3_224 => OSSL_DIGEST_NAME_SHA3_224.as_ptr(),
        CKM_SHA3_256_RSA_PKCS
        | CKM_ECDSA_SHA3_256
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_256_HMAC
        | CKM_SHA3_256_HMAC_GENERAL
        | CKM_SHA3_256 => OSSL_DIGEST_NAME_SHA3_256.as_ptr(),
        CKM_SHA3_384_RSA_PKCS
        | CKM_ECDSA_SHA3_384
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_384_HMAC
        | CKM_SHA3_384_HMAC_GENERAL
        | CKM_SHA3_384 => OSSL_DIGEST_NAME_SHA3_384.as_ptr(),
        CKM_SHA3_512_RSA_PKCS
        | CKM_ECDSA_SHA3_512
        | CKM_SHA3_512_RSA_PKCS_PSS
        | CKM_SHA3_512_HMAC
        | CKM_SHA3_512_HMAC_GENERAL
        | CKM_SHA3_512 => OSSL_DIGEST_NAME_SHA3_512.as_ptr(),
        CKM_SHA512_224_HMAC | CKM_SHA512_224_HMAC_GENERAL | CKM_SHA512_224 => {
            OSSL_DIGEST_NAME_SHA2_512_224.as_ptr()
        }
        CKM_SHA512_256_HMAC | CKM_SHA512_256_HMAC_GENERAL | CKM_SHA512_256 => {
            OSSL_DIGEST_NAME_SHA2_512_256.as_ptr()
        }
        _ => std::ptr::null(),
    }) as *const c_char
}

#[cfg(feature = "ecc")]
pub static EC_NAME: &[u8; 3] = b"EC\0";
#[cfg(all(feature = "ecc", feature = "fips"))]
pub static ECDSA_NAME: &[u8; 6] = b"ECDSA\0";

/* Curve names as used in OpenSSL */
#[cfg(feature = "ecc")]
const NAME_SECP256R1: &[u8] = b"prime256v1\0";
#[cfg(feature = "ecc")]
const NAME_SECP384R1: &[u8] = b"secp384r1\0";
#[cfg(feature = "ecc")]
const NAME_SECP521R1: &[u8] = b"secp521r1\0";
#[cfg(feature = "ecc")]
const NAME_ED25519: &[u8] = b"ED25519\0";
#[cfg(feature = "ecc")]
const NAME_ED448: &[u8] = b"ED448\0";
#[cfg(feature = "ecc")]
const NAME_X25519: &[u8] = b"X25519\0";
#[cfg(feature = "ecc")]
const NAME_X448: &[u8] = b"X448\0";

/// Maps an ASN.1 Object Identifier for an EC curve to the OpenSSL curve name
/// string.
#[cfg(feature = "ecc")]
fn oid_to_ossl_name(oid: &asn1::ObjectIdentifier) -> Result<&'static [u8]> {
    match oid {
        &oid::EC_SECP256R1 => Ok(NAME_SECP256R1),
        &oid::EC_SECP384R1 => Ok(NAME_SECP384R1),
        &oid::EC_SECP521R1 => Ok(NAME_SECP521R1),
        &oid::ED25519_OID => Ok(NAME_ED25519),
        &oid::ED448_OID => Ok(NAME_ED448),
        &oid::X25519_OID => Ok(NAME_X25519),
        &oid::X448_OID => Ok(NAME_X448),
        _ => Err(CKR_GENERAL_ERROR)?,
    }
}

/// Gets the OpenSSL curve name string associated with a PKCS#11 EC key `Object`.
#[cfg(feature = "ecc")]
pub fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    oid_to_ossl_name(&get_oid_from_obj(key)?)
}

/// Securely zeroizes a memory slice using `OPENSSL_cleanse`.
pub fn zeromem(mem: &mut [u8]) {
    unsafe {
        OPENSSL_cleanse(void_ptr!(mem.as_mut_ptr()), mem.len());
    }
}

/// Wrapper around OpenSSL's `EVP_SIGNATURE`, used for ML-DSA operations.
#[cfg(feature = "mldsa")]
pub struct EvpSignature {
    ptr: *mut EVP_SIGNATURE,
}

#[cfg(feature = "mldsa")]
impl EvpSignature {
    /// Creates a new `EvpSignature` instance by fetching it by name.
    pub fn new(name: *const c_char) -> Result<EvpSignature> {
        let ptr: *mut EVP_SIGNATURE = unsafe {
            EVP_SIGNATURE_fetch(get_libctx(), name, std::ptr::null_mut())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_SIGNATURE_fetch()");
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpSignature { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_SIGNATURE`.
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const EVP_SIGNATURE {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_SIGNATURE`.
    pub fn as_mut_ptr(&mut self) -> *mut EVP_SIGNATURE {
        self.ptr
    }
}

#[cfg(feature = "mldsa")]
impl Drop for EvpSignature {
    fn drop(&mut self) {
        unsafe {
            EVP_SIGNATURE_free(self.ptr);
        }
    }
}

#[cfg(all(feature = "log", feature = "fips"))]
fn ossl_err_stack() -> String {
    /* there is no external error management with fips builds */
    "".to_string()
}

#[cfg(all(feature = "log", not(feature = "fips")))]
fn ossl_err_stack() -> String {
    // Use a mem bio to "print out" the error stack
    let mut bio = std::ptr::null_mut();
    let bio_method = unsafe { BIO_s_mem() };
    if !bio_method.is_null() {
        bio = unsafe { BIO_new(bio_method) };
    }
    if bio.is_null() {
        return "Failed to fetch OpenSSL Error Stack".to_string();
    }
    unsafe { ERR_print_errors(bio) };

    /* retrieve the mem bio data as a long string, with embedded \n */
    let mut raw_mem: *mut c_char = std::ptr::null_mut();
    let raw_len = unsafe {
        BIO_ctrl(bio, BIO_CTRL_INFO as c_int, 0, void_ptr!(&mut raw_mem))
    };

    /* copy this buffer to a vector so we can turn it into a Rust String */
    let mut vec = bytes_to_vec!(raw_mem, raw_len);
    // remove final newline if any
    while vec[vec.len() - 1] == b'\n' {
        let _ = vec.pop();
    }
    match String::from_utf8(vec) {
        Ok(s) => s,
        Err(e) => format!("Failed to parse OpenSSL Error Stack: [{:?}]", e),
    }
}

macro_rules! trace_ossl {
    ($name:expr) => {
        #[cfg(feature = "log")]
        {
            use log::error;
            error!(
                "{}:{}: {} failed: [{}]",
                file!(),
                line!(),
                $name,
                ossl_err_stack()
            );
        }
    };
}
pub(crate) use trace_ossl;

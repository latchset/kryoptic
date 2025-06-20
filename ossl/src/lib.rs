// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This package provides common utilities, wrappers, and constants for interacting
//! with the OpenSSL library (`libcrypto`) via its C API, primarily focusing on
//! the EVP (high-level) interface and parameter handling (`OSSL_PARAM`).

/// Part of this module is automatically generated by bindgen from the OpenSSL
/// Headers and includes a selection of functions and other items needed to
/// access the libcrypto/libfips functions needed.
pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/ossl_bindings.rs"));
}

use std::borrow::Cow;
use std::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void, CStr};

use crate::bindings::*;

pub mod asymcipher;
pub mod cipher;
pub mod derive;
pub mod digest;
pub mod mac;
pub mod rand;
pub mod signature;

#[cfg(feature = "fips")]
pub mod fips;

/// Convenience macro to type cast any pointer into a mutable void
/// NOTE(1): bindgen always turns void pointers to mutable ones, but in most
/// cases the pointed data nor the pointer itself are mutated, so this casts
/// any pointer regardless of its original mutability.
/// NOTE(2): we do not wrap in unsafe{} because often this macro is invoked
/// from an unsafe{} code block.
///
/// This macro is UNSAFE, use carefully.
macro_rules! void_ptr {
    ($ptr:expr) => {
        $ptr as *const _ as *mut ::std::ffi::c_void
    };
}
pub(crate) use void_ptr;

macro_rules! cstr {
    ($str:expr) => {
        unsafe {
            ::std::ffi::CStr::from_ptr(
                $str.as_ptr() as *const ::std::ffi::c_char
            )
        }
    };
}
pub(crate) use cstr;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ErrorKind {
    /// OpenSSL returned a NULL ptr as an error
    NullPtr,
    /// OpenSSL returned a 0 c_int as an error
    OsslError,
    /// A falure resulting from wrong key usage
    KeyError,
    /// A warpper error
    WrapperError,
    /// A buffer is not of the correct size
    BufferSize,
    /// An optional argument is required or has a bad value
    BadArg,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(k: ErrorKind) -> Error {
        Error { kind: k }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<std::num::TryFromIntError> for Error {
    /// Maps an integer conversion error to a generic error
    fn from(_error: std::num::TryFromIntError) -> Error {
        Error::new(ErrorKind::WrapperError)
    }
}

impl From<std::io::Error> for Error {
    /// Maps an io error to a generic error
    fn from(_error: std::io::Error) -> Error {
        Error::new(ErrorKind::WrapperError)
    }
}

#[cfg(all(feature = "log", feature = "fips"))]
pub fn ossl_err_stack() -> String {
    /* there is no external error management with fips builds */
    "".to_string()
}

#[cfg(all(feature = "log", not(feature = "fips")))]
pub fn ossl_err_stack() -> String {
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

    if raw_mem.is_null() || raw_len == 0 {
        return "Failed to get error from OpenSSL's Error Stack".to_string();
    }

    /* copy this buffer to a vector so we can turn it into a Rust String */
    let mut vec = vec![0u8; raw_len as usize];
    unsafe {
        std::ptr::copy_nonoverlapping(
            raw_mem as *const u8,
            vec.as_mut_ptr(),
            vec.len(),
        );
    }

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
                crate::ossl_err_stack()
            );
        }
    };
}
pub(crate) use trace_ossl;

/// A structure representing the main crypto library context
pub struct OsslContext {
    context: *mut OSSL_LIB_CTX,
}

impl OsslContext {
    pub fn new_lib_ctx() -> OsslContext {
        OsslContext {
            context: unsafe { OSSL_LIB_CTX_new() },
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_ctx(ctx: *mut OSSL_LIB_CTX) -> OsslContext {
        OsslContext { context: ctx }
    }

    pub fn ptr(&self) -> *mut OSSL_LIB_CTX {
        self.context
    }
}

unsafe impl Send for OsslContext {}
unsafe impl Sync for OsslContext {}

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
    /// Returns a wrapped `BigNum` or an error if the import fails.
    pub fn from_bigendian_vec(v: &Vec<u8>) -> Result<BigNum, Error> {
        let bn = unsafe {
            BN_bin2bn(
                v.as_ptr() as *mut u8,
                c_int::try_from(v.len())?,
                std::ptr::null_mut(),
            )
        };
        if bn.is_null() {
            trace_ossl!("BN_bin2bn()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(BigNum {
            bn: bn as *const BIGNUM,
        })
    }

    /// Calculates the minimum number of bytes needed to represent the `BIGNUM`.
    pub fn len(&self) -> Result<usize, Error> {
        let x = unsafe { (BN_num_bits(self.bn) + 7) / 8 };
        Ok(usize::try_from(x)?)
    }

    /// Creates a `BigNum` by extracting it from an `OSSL_PARAM`.
    pub fn from_param(p: *const OSSL_PARAM) -> Result<BigNum, Error> {
        let mut bn: *mut BIGNUM = std::ptr::null_mut();
        if unsafe { OSSL_PARAM_get_BN(p, &mut bn) } != 1 {
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(BigNum {
            bn: bn as *const BIGNUM,
        })
    }

    /// Converts the `BIGNUM` to a byte vector in native-endian format, padded
    /// to the required length. Primarily used internally for constructing
    /// `OSSL_PARAM`s.
    pub fn to_native_vec(&self) -> Result<Vec<u8>, Error> {
        let mut v = vec![0u8; self.len()?];
        if v.len() == 0 {
            v.push(0);
        }
        let ret = unsafe {
            BN_bn2nativepad(self.bn, v.as_mut_ptr(), c_int::try_from(v.len())?)
        };
        if ret < 1 {
            trace_ossl!("BN_bn2nativepad()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(v)
    }

    /// Converts the `BIGNUM` to a byte vector in big-endian format (standard
    /// external representation).
    pub fn to_bigendian_vec(&self) -> Result<Vec<u8>, Error> {
        let len = self.len()?;
        let mut v = vec![0u8; self.len()?];
        let ret = unsafe { BN_bn2bin(self.bn, v.as_mut_ptr()) };
        if usize::try_from(ret)? != len {
            return Err(Error::new(ErrorKind::WrapperError));
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

/// Helper container to keep references around in structure that deal with
/// FFI structures that reference pointers, like arrays of CK_ATTRIBUTEs and
/// OSSL_PARAMs
#[derive(Debug)]
#[allow(dead_code)]
pub enum BorrowedReference<'a> {
    CharBool(&'a c_uchar),
    Int(&'a c_int),
    Slice(&'a [u8]),
    Vector(&'a Vec<u8>),
    Uint(&'a c_uint),
    Ulong(&'a c_ulong),
    Usize(&'a usize),
}

/// A safe builder and manager for OpenSSL `OSSL_PARAM` arrays.
///
/// `OSSL_PARAM` is the primary way to pass detailed parameters (like key
/// components, algorithm settings) to many OpenSSL 3+ EVP functions.
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
    /// a pointer to their data is stored in the OSSL_PARAM array
    br: Vec<BorrowedReference<'a>>,
}

impl Drop for OsslParam<'_> {
    fn drop(&mut self) {
        if self.zeroize {
            while let Some(mut v) = self.v.pop() {
                unsafe {
                    OPENSSL_cleanse(void_ptr!(v.as_mut_ptr()), v.len());
                }
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
    pub fn from_ptr(ptr: *mut OSSL_PARAM) -> Result<OsslParam<'static>, Error> {
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
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
    pub fn add_bn(&mut self, key: &CStr, v: &Vec<u8>) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
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
                key.as_ptr(),
                void_ptr!(container.as_ptr()) as *mut u8,
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
        key: &CStr,
        v: &'a Vec<u8>,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key.as_ptr(),
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
        key: &CStr,
        mut v: Vec<u8>,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key.as_ptr(),
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
        key: &CStr,
        len: usize,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let mut v = vec![0u8; len];
        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key.as_ptr(),
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
        key: &CStr,
        val: &CStr,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key.as_ptr(),
                val.as_ptr() as *mut c_char,
                0,
            )
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
        key: &CStr,
        v: &'a Vec<u8>,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_octet_string(
                key.as_ptr(),
                void_ptr!(v.as_ptr()),
                v.len(),
            )
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Vector(v));
        Ok(())
    }

    pub fn add_octet_slice(
        &mut self,
        key: &CStr,
        s: &'a [u8],
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_octet_string(
                key.as_ptr(),
                void_ptr!(s.as_ptr()),
                s.len(),
            )
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Slice(s));
        Ok(())
    }

    /// Adds an octet string (byte array) parameter using an owned byte vector.
    #[allow(dead_code)]
    pub fn add_owned_octet_string(
        &mut self,
        key: &CStr,
        v: Vec<u8>,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_octet_string(
                key.as_ptr(),
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
        key: &CStr,
        val: &'a usize,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_size_t(
                key.as_ptr(),
                val as *const _ as *mut usize,
            )
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
        key: &CStr,
        val: &'a c_uint,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_uint(
                key.as_ptr(),
                val as *const _ as *mut c_uint,
            )
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
    pub fn add_int(&mut self, key: &CStr, val: &'a c_int) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let param = unsafe {
            OSSL_PARAM_construct_int(
                key.as_ptr(),
                val as *const _ as *mut c_int,
            )
        };
        self.p.to_mut().push(param);
        self.br.push(BorrowedReference::Int(val));
        Ok(())
    }

    /// Adds an `c_uint` parameter using an owned value.
    #[allow(dead_code)]
    pub fn add_owned_uint(
        &mut self,
        key: &CStr,
        val: c_uint,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let v = val.to_ne_bytes().to_vec();

        let param = unsafe {
            OSSL_PARAM_construct_uint(
                key.as_ptr(),
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
        key: &CStr,
        val: c_int,
    ) -> Result<(), Error> {
        if self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }

        let v = val.to_ne_bytes().to_vec();

        let param = unsafe {
            OSSL_PARAM_construct_int(
                key.as_ptr(),
                v.as_ptr() as *const _ as *mut c_int,
            )
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

    /// Internal functions to convert an immutable reference to a mutable
    /// pointer. This is only used for interfaces that bindgen automatically
    /// mark as mutable but we know the interface contract means the pointer
    /// is effectively a const.
    unsafe fn int_mut_ptr(&self) -> *mut OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.p.as_ref().as_ptr() as *mut OSSL_PARAM
    }

    /// Gets the value of an integer parameter by its key name.
    #[allow(dead_code)]
    pub fn get_int(&self, key: &CStr) -> Result<c_int, Error> {
        if !self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let p = unsafe { OSSL_PARAM_locate(self.int_mut_ptr(), key.as_ptr()) };
        if p.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut val: c_int = 0;
        let res = unsafe { OSSL_PARAM_get_int(p, &mut val) };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_int()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(val)
    }

    /// Gets the value of a long parameter by its key name.
    #[allow(dead_code)]
    pub fn get_long(&self, key: &CStr) -> Result<c_long, Error> {
        if !self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let p = unsafe { OSSL_PARAM_locate(self.int_mut_ptr(), key.as_ptr()) };
        if p.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut val: c_long = 0;
        let res = unsafe { OSSL_PARAM_get_long(p, &mut val) };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_long()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(val)
    }

    /// Gets the value of a BIGNUM parameter by its key name as a big-endian
    /// byte vector.
    pub fn get_bn(&self, key: &CStr) -> Result<Vec<u8>, Error> {
        if !self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let p = unsafe { OSSL_PARAM_locate(self.int_mut_ptr(), key.as_ptr()) };
        if p.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let bn = BigNum::from_param(p)?;
        bn.to_bigendian_vec()
    }

    /// Gets the value of an octet string parameter by its key name as a byte
    /// slice.
    #[allow(dead_code)]
    pub fn get_octet_string(&self, key: &CStr) -> Result<&'a [u8], Error> {
        if !self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let p = unsafe { OSSL_PARAM_locate(self.int_mut_ptr(), key.as_ptr()) };
        if p.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut buf: *const c_void = std::ptr::null_mut();
        let mut buf_len: usize = 0;
        let res = unsafe {
            OSSL_PARAM_get_octet_string_ptr(p, &mut buf, &mut buf_len)
        };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_octet_string_ptr()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let octet =
            unsafe { std::slice::from_raw_parts(buf as *const u8, buf_len) };
        Ok(octet)
    }

    /// Gets a UTF8 String as vector, this includes the terminating NUL
    #[allow(dead_code)]
    pub fn get_utf8_string_as_vec(&self, key: &CStr) -> Result<Vec<u8>, Error> {
        if !self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let p = unsafe { OSSL_PARAM_locate(self.int_mut_ptr(), key.as_ptr()) };
        if p.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
        }
        let mut ptr: *const c_char = std::ptr::null_mut();
        let res = unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &mut ptr) };
        if res != 1 {
            trace_ossl!("OSSL_PARAM_get_utf8_string_ptr()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let s = unsafe { CStr::from_ptr(ptr) };
        Ok(s.to_bytes_with_nul().to_vec())
    }

    /// Checks if a parameter with the given key name exists in the array.
    #[allow(dead_code)]
    pub fn has_param(&self, key: &CStr) -> Result<bool, Error> {
        if !self.finalized {
            return Err(Error::new(ErrorKind::WrapperError));
        }
        let p = unsafe { OSSL_PARAM_locate(self.int_mut_ptr(), key.as_ptr()) };
        Ok(!p.is_null())
    }

    /// Returns the number of elements in the array, excluding the terminating
    /// null element
    ///
    /// Panics if the array has not been finalized.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.p.as_ref().len() - 1
    }
}

/// Wrapper around OpenSSL's `EVP_MD`, managing its lifecycle.
#[derive(Debug)]
pub struct EvpMd {
    ptr: *mut EVP_MD,
}

/// Methods for creating and accessing `EvpMd`.
impl EvpMd {
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpMd, Error> {
        let ptr = unsafe {
            EVP_MD_fetch(ctx.ptr(), name.as_ptr(), std::ptr::null_mut())
        };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_fetch()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpMd { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MD`.
    pub unsafe fn as_ptr(&self) -> *const EVP_MD {
        self.ptr
    }

    /// Returns a mutable pointer to the underlying `EVP_MD`.
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
    pub fn new() -> Result<EvpMdCtx, Error> {
        let ptr = unsafe { EVP_MD_CTX_new() };
        if ptr.is_null() {
            trace_ossl!("EVP_MD_ctx_new()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpMdCtx { ptr })
    }

    /// Returns a const pointer to the underlying `EVP_MD_CTX`.
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

/// Wrapper around OpenSSL's `EVP_PKEY_CTX`, managing its lifecycle.
/// Used for various public key algorithm operations (key generation, signing,
/// encryption context setup, etc.).
#[derive(Debug)]
pub struct EvpPkeyCtx {
    ptr: *mut EVP_PKEY_CTX,
}

/// Methods for creating and accessing `EvpPkeyCtx`.
impl EvpPkeyCtx {
    /// Fecthes an algorithm by name and returns a wrapper `EvpPkeyCtx`
    pub fn new(ctx: &OsslContext, name: &CStr) -> Result<EvpPkeyCtx, Error> {
        let ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(
                ctx.ptr(),
                name.as_ptr(),
                std::ptr::null(),
            )
        };
        if ptr.is_null() {
            trace_ossl!("EVP_PKEY_CTX_new_from_name()");
            return Err(Error::new(ErrorKind::NullPtr));
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    /// Creates an `EvpPkeyCtx` from an existing raw pointer (takes ownership).
    pub unsafe fn from_ptr(
        ptr: *mut EVP_PKEY_CTX,
    ) -> Result<EvpPkeyCtx, Error> {
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::NullPtr));
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

impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkeyCtx {}
unsafe impl Sync for EvpPkeyCtx {}

#[derive(Debug)]
pub enum EvpPkeyType {
    /* DH */
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
    Modp2048,
    Modp3072,
    Modp4096,
    Modp6144,
    Modp8192,
    /* Ecc */
    P256,
    P384,
    P521,
    Ed25519,
    Ed448,
    X25519,
    X448,
    /* ML */
    Mldsa44,
    Mldsa65,
    Mldsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
    /* RSA */
    Rsa(usize, Vec<u8>),
}

fn pkey_type_to_params(
    pt: EvpPkeyType,
) -> Result<(&'static CStr, OsslParam<'static>), Error> {
    let mut params = OsslParam::new();
    let name = match pt {
        EvpPkeyType::Ffdhe2048 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe2048",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe3072 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe3072",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe4096 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe4096",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe6144 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe6144",
            )?;
            c"DH"
        }
        EvpPkeyType::Ffdhe8192 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"ffdhe8192",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp2048 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_2048",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp3072 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_3072",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp4096 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_4096",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp6144 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_6144",
            )?;
            c"DH"
        }
        EvpPkeyType::Modp8192 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"modp_8192",
            )?;
            c"DH"
        }
        EvpPkeyType::P256 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"prime256v1",
            )?;
            c"EC"
        }
        EvpPkeyType::P384 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"secp384r1",
            )?;
            c"EC"
        }
        EvpPkeyType::P521 => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                c"secp521r1",
            )?;
            c"EC"
        }
        EvpPkeyType::Ed25519 => c"ED25519",
        EvpPkeyType::Ed448 => c"ED448",
        EvpPkeyType::X25519 => c"X25519",
        EvpPkeyType::X448 => c"X448",
        EvpPkeyType::Mldsa44 => c"ML-DSA-44",
        EvpPkeyType::Mldsa65 => c"ML-DSA-65",
        EvpPkeyType::Mldsa87 => c"ML-DSA-87",
        EvpPkeyType::MlKem512 => c"ML-KEM-512",
        EvpPkeyType::MlKem768 => c"ML-KEM-768",
        EvpPkeyType::MlKem1024 => c"ML-KEM-1024",
        EvpPkeyType::Rsa(size, exp) => {
            params.add_bn(cstr!(OSSL_PKEY_PARAM_RSA_E), &exp)?;
            params.add_owned_uint(
                cstr!(OSSL_PKEY_PARAM_RSA_BITS),
                c_uint::try_from(size)?,
            )?;
            c"RSA"
        }
    };
    params.finalize();
    Ok((name, params))
}

/// Wrapper around OpenSSL's `EVP_PKEY`, representing a generic public or
/// private key. Manages the key's lifecycle.
#[derive(Debug)]
pub struct EvpPkey {
    ptr: *mut EVP_PKEY,
}

impl EvpPkey {
    /// Creates an `EvpPkey` from key material provided via `OSSL_PARAM`s.
    ///
    /// Used for importing public or private keys based on their components
    /// (e.g., modulus/exponent for RSA, curve/point for EC).
    pub fn fromdata(
        ctx: &OsslContext,
        pkey_name: &CStr,
        pkey_type: u32,
        params: &OsslParam,
    ) -> Result<EvpPkey, Error> {
        let mut pctx = EvpPkeyCtx::new(ctx, pkey_name)?;
        let res = unsafe { EVP_PKEY_fromdata_init(pctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe {
            EVP_PKEY_fromdata(
                pctx.as_mut_ptr(),
                &mut pkey,
                pkey_type as i32,
                params.as_ptr() as *mut OSSL_PARAM,
            )
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_fromdata()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Exports key material components into an `OsslParam` structure.
    ///
    /// The `selection` argument specifies which components to export
    /// (e.g., public, private, parameters).
    pub fn todata(&self, selection: u32) -> Result<OsslParam, Error> {
        let mut params: *mut OSSL_PARAM = std::ptr::null_mut();
        let ret = unsafe {
            EVP_PKEY_todata(self.ptr, c_int::try_from(selection)?, &mut params)
        };
        if ret != 1 {
            trace_ossl!("EVP_PKEY_todata()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        OsslParam::from_ptr(params)
    }

    /// Allow to get parameters from a key.
    /// The caller must preallocate the payloads with enough space to
    /// receive the data, which is copied into the parameters.
    pub fn get_params(&self, params: &mut OsslParam) -> Result<(), Error> {
        if unsafe { EVP_PKEY_get_params(self.ptr, params.as_mut_ptr()) } != 1 {
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(())
    }

    /// Generates a new key pair based on provided algorithm name and
    /// parameters.
    ///
    /// The parameters (`OsslParam`) specify details like key size or curve
    /// name.
    pub fn generate(
        ctx: &OsslContext,
        pkey_type: EvpPkeyType,
    ) -> Result<EvpPkey, Error> {
        let (name, params) = pkey_type_to_params(pkey_type)?;
        let mut pctx = EvpPkeyCtx::new(ctx, name)?;
        let res = unsafe { EVP_PKEY_keygen_init(pctx.as_mut_ptr()) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_keygen_init()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let res = unsafe {
            EVP_PKEY_CTX_set_params(pctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            trace_ossl!("EVP_PKEY_CTX_set_params()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(pctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            trace_ossl!("EVP_PKEY_generate()");
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(EvpPkey { ptr: pkey })
    }

    /// Creates a new `EvpPkeyCtx` associated with this `EvpPkey`.
    ///
    /// Used to prepare for operations using this specific key.
    pub fn new_ctx(&mut self, ctx: &OsslContext) -> Result<EvpPkeyCtx, Error> {
        /* this function takes care of checking for NULL */
        unsafe {
            EvpPkeyCtx::from_ptr(
                /* this function will use refcounting to keep EVP_PKEY
                 * alive for the lifetime of the context, so it is ok
                 * to not use rust lifetimes here */
                EVP_PKEY_CTX_new_from_pkey(
                    ctx.ptr(),
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

    /// Gets the key size in bits. Handles FIPS provider differences.
    #[cfg(not(feature = "fips"))]
    pub fn get_bits(&self) -> Result<usize, Error> {
        let ret = unsafe { EVP_PKEY_get_bits(self.ptr) };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(ret)?)
    }
    #[cfg(feature = "fips")]
    pub fn get_bits(&self) -> Result<usize, Error> {
        /* EVP_PKEY_get_bits() not available in libfips.a */
        let mut bits: c_int = 0;
        let ret = unsafe {
            EVP_PKEY_get_int_param(
                self.ptr,
                OSSL_PKEY_PARAM_BITS.as_ptr() as *const c_char,
                &mut bits,
            )
        };
        if ret == 0 {
            /* TODO: may want to return a special error
             * for unsupported keys */
            return Err(Error::new(ErrorKind::OsslError));
        }
        Ok(usize::try_from(bits)?)
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkey {}
unsafe impl Sync for EvpPkey {}

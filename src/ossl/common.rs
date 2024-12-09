// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::borrow::Cow;
use std::ffi::{c_char, c_int, c_uint, c_void};

use crate::error::Result;
use crate::interface::*;
use crate::kasn1::oid;
use crate::object::Object;
use crate::ossl::bindings::*;
use crate::ossl::get_libctx;
use crate::{byte_ptr, void_ptr};

#[cfg(feature = "ecc")]
use crate::ec::get_oid_from_obj;
#[cfg(feature = "ecdsa")]
use crate::ossl::ecdsa;
#[cfg(feature = "eddsa")]
use crate::ossl::eddsa;
#[cfg(feature = "ec_montgomery")]
use crate::ossl::montgomery as ecm;
#[cfg(feature = "rsa")]
use crate::ossl::rsa;

use asn1;
use zeroize::Zeroize;

macro_rules! ptr_wrapper_struct {
    ($name:ident; $ctx:ident) => {
        #[derive(Debug)]
        pub struct $name {
            ptr: *mut $ctx,
        }
    };
}

macro_rules! ptr_wrapper_returns {
    ($ossl:ident) => {
        #[allow(dead_code)]
        pub unsafe fn as_ptr(&self) -> *const $ossl {
            self.ptr
        }

        #[allow(dead_code)]
        pub unsafe fn as_mut_ptr(&mut self) -> *mut $ossl {
            self.ptr
        }
    };
}

macro_rules! ptr_wrapper_tail {
    ($name:ident; $free:ident) => {
        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    $free(self.ptr);
                }
            }
        }

        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}
    };
}

macro_rules! ptr_wrapper {
    (ctx; $up:ident; $mix:ident) => {
        paste::paste! {
            /* EVP_XX_CTX */
            ptr_wrapper_struct!([<Evp $mix Ctx>]; [<EVP_ $up _CTX>]);

            impl [<Evp $mix Ctx>] {
                pub fn new() -> Result<[<Evp $mix Ctx>]> {
                    let ptr = unsafe {
                        [<EVP_ $up _CTX_new>]()
                    };
                    if ptr.is_null() {
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                    Ok([<Evp $mix Ctx>] { ptr: ptr })
                }

                ptr_wrapper_returns!([<EVP_ $up _CTX>]);
            }

            ptr_wrapper_tail!([<Evp $mix Ctx>]; [<EVP_ $up _CTX_free>]);

            /* EVP_XX */
            ptr_wrapper_struct!([<Evp $mix >]; [<EVP_ $up >]);

            impl [<Evp $mix >] {
                pub fn new(name: *const c_char) -> Result<[<Evp $mix >]> {
                    let ptr = unsafe {
                        [<EVP_ $up _fetch>](
                            get_libctx(), name, std::ptr::null_mut()
                        )
                    };
                    if ptr.is_null() {
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                    Ok([<Evp $mix >] { ptr: ptr })
                }

                ptr_wrapper_returns!([<EVP_ $up >]);
            }

            ptr_wrapper_tail!([<Evp $mix >]; [<EVP_ $up _free>]);
        }
    };

    (ctx_from_name; $up:ident; $mix:ident) => {
        paste::paste! {
            ptr_wrapper_struct!([<Evp $mix Ctx>]; [<EVP_ $up _CTX>]);

            impl [<Evp $mix Ctx>] {
                pub fn new(
                    name: *const c_char
                ) -> Result<[<Evp $mix Ctx>]> {
                    let arg = unsafe {
                        [<EVP_ $up _fetch>](
                            get_libctx(), name, std::ptr::null_mut()
                        )
                    };
                    if arg.is_null() {
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                    let ptr = unsafe {
                        /* This is safe and requires no lifetimes because
                         * all _CTX_new() functions in OpenSSL take a
                         * reference on the argument */
                        [<EVP_ $up _CTX_new>](arg)
                    };
                    unsafe {
                        [<EVP_ $up _free>](arg);
                    }
                    if ptr.is_null() {
                        return Err(CKR_DEVICE_ERROR)?;
                    }
                    Ok([<Evp $mix Ctx>] { ptr: ptr })
                }

                ptr_wrapper_returns!([<EVP_ $up _CTX>]);
            }

            ptr_wrapper_tail!([<Evp $mix Ctx>]; [<EVP_ $up _CTX_free>]);
        }
    };
}

ptr_wrapper!(ctx; MD; Md);
ptr_wrapper!(ctx; CIPHER; Cipher);

ptr_wrapper!(ctx_from_name; KDF; Kdf);
ptr_wrapper!(ctx_from_name; MAC; Mac);

#[derive(Debug)]
pub struct EvpPkeyCtx {
    ptr: *mut EVP_PKEY_CTX,
}

impl EvpPkeyCtx {
    pub fn new(name: *const c_char) -> Result<EvpPkeyCtx> {
        let ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(get_libctx(), name, std::ptr::null())
        };
        if ptr.is_null() {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    pub unsafe fn from_ptr(ptr: *mut EVP_PKEY_CTX) -> Result<EvpPkeyCtx> {
        if ptr.is_null() {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const EVP_PKEY_CTX {
        self.ptr
    }

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
pub struct EvpPkey {
    ptr: *mut EVP_PKEY,
}

impl EvpPkey {
    pub fn fromdata(
        pkey_name: *const c_char,
        pkey_type: u32,
        params: &OsslParam,
    ) -> Result<EvpPkey> {
        let mut ctx = EvpPkeyCtx::new(pkey_name)?;
        let res = unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) };
        if res != 1 {
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
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkey { ptr: pkey })
    }

    pub fn generate(
        pkey_name: *const c_char,
        params: &OsslParam,
    ) -> Result<EvpPkey> {
        let mut ctx = EvpPkeyCtx::new(pkey_name)?;
        let res = unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let res = unsafe {
            EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(ctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(EvpPkey { ptr: pkey })
    }

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

    pub fn as_ptr(&self) -> *const EVP_PKEY {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut EVP_PKEY {
        self.ptr
    }

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
            #[cfg(feature = "rsa")]
            CKK_RSA => rsa::rsa_object_to_params(obj, class)?,
            _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
        };
        Self::fromdata(name, key_class, &params)
    }

    pub fn pubkey_from_object(obj: &Object) -> Result<EvpPkey> {
        Self::from_object(obj, CKO_PUBLIC_KEY)
    }

    pub fn privkey_from_object(obj: &Object) -> Result<EvpPkey> {
        Self::from_object(obj, CKO_PRIVATE_KEY)
    }

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

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.ptr);
        }
    }
}

unsafe impl Send for EvpPkey {}
unsafe impl Sync for EvpPkey {}

pub const CIPHER_NAME_AES128: &[u8; 7] = b"AES128\0";
pub const CIPHER_NAME_AES192: &[u8; 7] = b"AES192\0";
pub const CIPHER_NAME_AES256: &[u8; 7] = b"AES256\0";

pub fn name_as_char(name: &[u8]) -> *const c_char {
    name.as_ptr() as *const c_char
}

pub fn bn_num_bytes(a: *const BIGNUM) -> usize {
    let x = unsafe { (BN_num_bits(a) + 7) / 8 };
    usize::try_from(x).unwrap()
}

#[derive(Debug)]
pub struct OsslParam<'a> {
    v: Vec<Vec<u8>>,
    p: Cow<'a, [OSSL_PARAM]>,
    finalized: bool,
    pub zeroize: bool,
}

impl Drop for OsslParam<'_> {
    fn drop(&mut self) {
        if self.zeroize {
            while let Some(mut elem) = self.v.pop() {
                elem.zeroize();
            }
        }
    }
}

impl<'a> OsslParam<'a> {
    #[allow(dead_code)]
    pub fn new() -> OsslParam<'static> {
        Self::with_capacity(0)
    }

    pub fn with_capacity(capacity: usize) -> OsslParam<'static> {
        OsslParam {
            v: Vec::new(),
            p: Cow::Owned(Vec::with_capacity(capacity + 1)),
            finalized: false,
            zeroize: false,
        }
    }

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
        })
    }

    #[allow(dead_code)]
    pub fn empty() -> OsslParam<'static> {
        let mut p = OsslParam {
            v: Vec::new(),
            p: Cow::Owned(Vec::with_capacity(1)),
            finalized: false,
            zeroize: false,
        };
        p.finalize();
        p
    }

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
        let bn = unsafe {
            BN_bin2bn(
                v.as_ptr() as *mut u8,
                c_int::try_from(v.len())?,
                std::ptr::null_mut(),
            )
        };
        if bn.is_null() {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let mut size = usize::try_from((unsafe { BN_num_bits(bn) } + 7) / 8)?;
        if size == 0 {
            size += 1;
        }
        let mut container = vec![0u8; size];
        if unsafe {
            BN_bn2nativepad(
                bn,
                container.as_mut_ptr(),
                c_int::try_from(container.len())?,
            )
        } < 1
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
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
        Ok(())
    }

    #[allow(dead_code)]
    pub fn add_owned_utf8_string(
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
            OSSL_PARAM_construct_utf8_string(
                key,
                void_ptr!(v.as_ptr()) as *mut c_char,
                0,
            )
        };
        self.v.push(v);
        self.p.to_mut().push(param);
        Ok(())
    }

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
        Ok(())
    }

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
        Ok(())
    }

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
        Ok(())
    }

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
        Ok(())
    }

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

    pub fn finalize(&mut self) {
        if !self.finalized {
            self.p.to_mut().push(unsafe { OSSL_PARAM_construct_end() });
            self.finalized = true;
        }
    }

    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.p.as_ref().as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.p.to_mut().as_mut_ptr()
    }

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
            return Err(CKR_DEVICE_ERROR)?;
        }
        Ok(val)
    }

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
        let mut bn: *mut BIGNUM = std::ptr::null_mut();
        if unsafe { OSSL_PARAM_get_BN(p, &mut bn) } != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let len = bn_num_bytes(bn as *const BIGNUM);
        let mut vec = Vec::<u8>::with_capacity(len);
        if len
            != usize::try_from(unsafe {
                BN_bn2bin(
                    bn as *const BIGNUM,
                    vec.as_mut_ptr() as *mut std::os::raw::c_uchar,
                )
            })?
        {
            return Err(CKR_DEVICE_ERROR)?;
        }
        unsafe {
            vec.set_len(len);
        }
        Ok(vec)
    }

    pub fn get_octet_string(&self, key: *const c_char) -> Result<&'a [u8]> {
        if !self.finalized {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return Err(CKR_GENERAL_ERROR)?;
        }
        let mut buf: *const c_void = std::ptr::null_mut();
        let mut buf_len: usize = 0;
        let res = unsafe {
            OSSL_PARAM_get_octet_string_ptr(p, &mut buf, &mut buf_len)
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }
        let octet =
            unsafe { std::slice::from_raw_parts(buf as *const u8, buf_len) };
        Ok(octet)
    }
}

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
        _ => std::ptr::null(),
    }) as *const c_char
}

pub static EC_NAME: &[u8; 3] = b"EC\0";
#[cfg(feature = "fips")]
pub static ECDSA_NAME: &[u8; 6] = b"ECDSA\0";

/* Curve names as used in OpenSSL */
const NAME_SECP256R1: &[u8] = b"prime256v1\0";
const NAME_SECP384R1: &[u8] = b"secp384r1\0";
const NAME_SECP521R1: &[u8] = b"secp521r1\0";
const NAME_ED25519: &[u8] = b"ED25519\0";
const NAME_ED448: &[u8] = b"ED448\0";
const NAME_X25519: &[u8] = b"X25519\0";
const NAME_X448: &[u8] = b"X448\0";

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

#[cfg(feature = "ecc")]
pub fn get_ossl_name_from_obj(key: &Object) -> Result<&'static [u8]> {
    oid_to_ossl_name(&get_oid_from_obj(key)?)
}

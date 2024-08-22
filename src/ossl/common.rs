// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::{byte_ptr, void_ptr};

use interface::*;

use core::ffi::{c_int, c_uint};
use std::borrow::Cow;

macro_rules! ptr_wrapper_struct {
    ($name:ident; $ossl:ident) => {
        #[derive(Debug)]
        pub struct $name {
            ptr: *mut $ossl,
        }
    };
}

macro_rules! ptr_wrapper_returns {
    ($ossl:ident) => {
        pub unsafe fn as_ptr(&self) -> *const $ossl {
            self.ptr
        }

        pub unsafe fn as_mut_ptr(&mut self) -> *mut $ossl {
            self.ptr
        }
    };
}

macro_rules! ptr_wrapper_tail {
    ($name:ident; $free:expr) => {
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
    (ctx; $name:ident; $ossl:ident; $newctx:ident; $free:expr) => {
        ptr_wrapper_struct!($name; $ossl);

        impl $name {
            pub fn new() -> KResult<$name> {
                let ptr = unsafe {
                    $newctx()
                };
                if ptr.is_null() {
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                Ok($name { ptr: ptr })
            }

            ptr_wrapper_returns!($ossl);
        }

        ptr_wrapper_tail!($name; $free);
    };

    (ctx_from_name; $name:ident; $ossl:ident; $newctx:ident; $free:expr; $in_ossl:ident; $in_fetch:ident; $in_free:ident) => {
        ptr_wrapper_struct!($name; $ossl);

        impl $name {
            pub fn new(name: *const c_char) -> KResult<$name> {
                let arg = unsafe {
                    $in_fetch(get_libctx(), name, std::ptr::null_mut())
                };
                if arg.is_null() {
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                let ptr = unsafe {
                    /* This is safe and requires no lifetimes because all _CTX_new()
                     * functions in OpenSSL take a reference on the argument */
                    $newctx(arg)
                };
                unsafe {
                    $in_free(arg);
                }
                if ptr.is_null() {
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                Ok($name { ptr: ptr })
            }

            ptr_wrapper_returns!($ossl);
        }

        ptr_wrapper_tail!($name; $free);
    };

    (fetch; $name:ident; $ossl:ident; $fetch:ident; $free:expr) => {
        ptr_wrapper_struct!($name; $ossl);

        impl $name {
            pub fn new(name: *const c_char) -> KResult<$name> {
                let ptr = unsafe {
                    $fetch(get_libctx(), name, std::ptr::null_mut())
                };
                if ptr.is_null() {
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                Ok($name { ptr: ptr })
            }

            ptr_wrapper_returns!($ossl);
        }

        ptr_wrapper_tail!($name; $free);
    }
}

ptr_wrapper!(ctx; EvpMdCtx; EVP_MD_CTX; EVP_MD_CTX_new; EVP_MD_CTX_free);
ptr_wrapper!(ctx; EvpCipherCtx; EVP_CIPHER_CTX; EVP_CIPHER_CTX_new; EVP_CIPHER_CTX_free);

ptr_wrapper!(ctx_from_name; EvpKdfCtx; EVP_KDF_CTX; EVP_KDF_CTX_new; EVP_KDF_CTX_free; EvpKdf; EVP_KDF_fetch; EVP_KDF_free);
ptr_wrapper!(ctx_from_name; EvpMacCtx; EVP_MAC_CTX; EVP_MAC_CTX_new; EVP_MAC_CTX_free; EvpMac; EVP_MAC_fetch; EVP_MAC_free);

ptr_wrapper!(fetch; EvpMd; EVP_MD; EVP_MD_fetch; EVP_MD_free);
ptr_wrapper!(fetch; EvpCipher; EVP_CIPHER; EVP_CIPHER_fetch; EVP_CIPHER_free);

#[derive(Debug)]
pub struct EvpPkeyCtx {
    ptr: *mut EVP_PKEY_CTX,
}

impl EvpPkeyCtx {
    pub fn new(name: *const c_char) -> KResult<EvpPkeyCtx> {
        let ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(get_libctx(), name, std::ptr::null())
        };
        if ptr.is_null() {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

    pub unsafe fn from_ptr(ptr: *mut EVP_PKEY_CTX) -> KResult<EvpPkeyCtx> {
        if ptr.is_null() {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(EvpPkeyCtx { ptr: ptr })
    }

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
    ) -> KResult<EvpPkey> {
        let mut ctx = EvpPkeyCtx::new(pkey_name)?;
        let res = unsafe { EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
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
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(EvpPkey { ptr: pkey })
    }

    pub fn generate(
        pkey_name: *const c_char,
        params: &OsslParam,
    ) -> KResult<EvpPkey> {
        let mut ctx = EvpPkeyCtx::new(pkey_name)?;
        let res = unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let res = unsafe {
            EVP_PKEY_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut pkey: *mut EVP_PKEY = std::ptr::null_mut();
        let res = unsafe { EVP_PKEY_generate(ctx.as_mut_ptr(), &mut pkey) };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(EvpPkey { ptr: pkey })
    }

    pub fn new_ctx(&mut self) -> KResult<EvpPkeyCtx> {
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
pub const MAC_NAME_CMAC: &[u8; 5] = b"CMAC\0";
pub const MAC_NAME_HMAC: &[u8; 5] = b"HMAC\0";

pub fn name_as_char(name: &[u8]) -> *const c_char {
    name.as_ptr() as *const c_char
}

pub fn bn_num_bytes(a: *const BIGNUM) -> usize {
    let x = unsafe { (BN_num_bits(a) + 7) / 8 };
    x as usize
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

    pub fn from_ptr(ptr: *mut OSSL_PARAM) -> KResult<OsslParam<'static>> {
        if ptr.is_null() {
            return err_rv!(CKR_DEVICE_ERROR);
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
                std::slice::from_raw_parts(ptr, (nelem + 1) as usize)
            }),
            finalized: true,
            zeroize: false,
        })
    }

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

    pub fn add_bn(&mut self, key: *const c_char, v: &Vec<u8>) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
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
                v.len() as i32,
                std::ptr::null_mut(),
            )
        };
        if bn.is_null() {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut size = unsafe { (BN_num_bits(bn) + 7) / 8 } as usize;
        if size == 0 {
            size += 1;
        }
        let mut container = vec![0u8; size];
        if unsafe {
            BN_bn2nativepad(
                bn,
                container.as_mut_ptr(),
                container.len() as c_int,
            )
        } < 1
        {
            return err_rv!(CKR_DEVICE_ERROR);
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

    pub fn add_utf8_string(
        &mut self,
        key: *const c_char,
        v: &'a Vec<u8>,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key,
                void_ptr!(v.as_ptr()) as *mut i8,
                0,
            )
        };
        self.p.to_mut().push(param);
        Ok(())
    }

    pub fn add_owned_utf8_string(
        &mut self,
        key: *const c_char,
        v: Vec<u8>,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key,
                void_ptr!(v.as_ptr()) as *mut i8,
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
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() || val == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let param =
            unsafe { OSSL_PARAM_construct_utf8_string(key, val as *mut i8, 0) };
        self.p.to_mut().push(param);
        Ok(())
    }

    pub fn add_octet_string(
        &mut self,
        key: *const c_char,
        v: &'a Vec<u8>,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
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

    pub fn add_size_t(
        &mut self,
        key: *const c_char,
        val: &'a usize,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
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
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
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
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let param = unsafe {
            OSSL_PARAM_construct_int(key, val as *const _ as *mut c_int)
        };
        self.p.to_mut().push(param);
        Ok(())
    }

    pub fn add_owned_uint(
        &mut self,
        key: *const c_char,
        val: c_uint,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
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

    pub fn add_owned_int(
        &mut self,
        key: *const c_char,
        val: c_int,
    ) -> KResult<()> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        if key == std::ptr::null() {
            return err_rv!(CKR_GENERAL_ERROR);
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

    pub fn get_int(&self, key: *const c_char) -> KResult<c_int> {
        if !self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut val: c_int = 0;
        let res = unsafe { OSSL_PARAM_get_int(p, &mut val) };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        Ok(val)
    }

    pub fn get_bn(&self, key: *const c_char) -> KResult<Vec<u8>> {
        if !self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut bn: *mut BIGNUM = std::ptr::null_mut();
        if unsafe { OSSL_PARAM_get_BN(p, &mut bn) } != 1 {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let len = bn_num_bytes(bn as *const BIGNUM);
        let mut vec = Vec::<u8>::with_capacity(len);
        if unsafe {
            BN_bn2bin(
                bn as *const BIGNUM,
                vec.as_mut_ptr() as *mut std::os::raw::c_uchar,
            ) as usize
        } != len
        {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        unsafe {
            vec.set_len(len);
        }
        Ok(vec)
    }

    pub fn get_octet_string(&self, key: *const c_char) -> KResult<&'a [u8]> {
        if !self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let p = unsafe {
            OSSL_PARAM_locate(self.p.as_ref().as_ptr() as *mut OSSL_PARAM, key)
        };
        if p.is_null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut buf: *const c_void = std::ptr::null_mut();
        let mut buf_len: usize = 0;
        let res = unsafe {
            OSSL_PARAM_get_octet_string_ptr(p, &mut buf, &mut buf_len)
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
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

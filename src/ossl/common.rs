// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::object;

use interface::*;

macro_rules! ptr_wrapper {
    ($name:ident; $ossl:ident; $free:expr) => {
        #[derive(Debug)]
        pub struct $name {
            ptr: *mut $ossl,
        }

        impl $name {
            pub fn from_ptr(ptr: *mut $ossl) -> KResult<$name> {
                if ptr.is_null() {
                    return err_rv!(CKR_DEVICE_ERROR);
                }
                Ok($name { ptr: ptr })
            }

            pub fn empty() -> $name {
                $name {
                    ptr: std::ptr::null_mut(),
                }
            }

            pub fn as_ptr(&self) -> *const $ossl {
                self.ptr
            }

            pub fn as_mut_ptr(&mut self) -> *mut $ossl {
                self.ptr
            }
        }

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

ptr_wrapper!(EvpMd; EVP_MD; EVP_MD_free);
ptr_wrapper!(EvpPkey; EVP_PKEY; EVP_PKEY_free);
ptr_wrapper!(EvpPkeyCtx; EVP_PKEY_CTX; EVP_PKEY_CTX_free);
ptr_wrapper!(EvpMdCtx; EVP_MD_CTX; EVP_MD_CTX_free);
ptr_wrapper!(BigNum; BIGNUM; BN_free);
ptr_wrapper!(EvpCipherCtx; EVP_CIPHER_CTX; EVP_CIPHER_CTX_free);
ptr_wrapper!(EvpCipher; EVP_CIPHER; EVP_CIPHER_free);

pub fn name_as_char(name: &[u8]) -> *const c_char {
    name.as_ptr() as *const c_char
}

pub fn bn_num_bytes(a: *const BIGNUM) -> usize {
    let x = unsafe { (BN_num_bits(a) + 7) / 8 };
    x as usize
}

#[derive(Debug)]
pub struct OsslParam {
    v: Vec<Vec<u8>>,
    p: Vec<OSSL_PARAM>,
    finalized: bool,
    zeroize: bool,
    imported: bool,
    ptr: *mut OSSL_PARAM,
    nelem: usize,
}

impl Drop for OsslParam {
    fn drop(&mut self) {
        if self.zeroize {
            while let Some(mut vec) = self.v.pop() {
                vec.zeroize();
            }
        }
    }
}

impl OsslParam {
    pub fn new() -> OsslParam {
        Self::with_capacity(0)
    }

    pub fn with_capacity(capacity: usize) -> OsslParam {
        OsslParam {
            v: Vec::new(),
            p: Vec::with_capacity(capacity),
            finalized: false,
            imported: false,
            zeroize: false,
            ptr: std::ptr::null_mut(),
            nelem: 0,
        }
    }

    pub fn from_ptr(ptr: *mut OSSL_PARAM) -> KResult<OsslParam> {
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
        Ok(OsslParam {
            v: Vec::new(),
            p: Vec::new(),
            finalized: true,
            imported: true,
            zeroize: false,
            ptr: ptr,
            nelem: nelem,
        })
    }

    pub fn empty() -> OsslParam {
        OsslParam {
            v: Vec::new(),
            p: Vec::new(),
            finalized: true,
            imported: true,
            zeroize: false,
            ptr: std::ptr::null_mut(),
            nelem: 0,
        }
    }

    pub fn set_zeroize(mut self) -> OsslParam {
        if !self.imported {
            self.zeroize = true;
        }
        self
    }

    pub fn add_bn(
        mut self,
        key: *const c_char,
        v: &Vec<u8>,
    ) -> KResult<OsslParam> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

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
        let mut param =
            unsafe { OSSL_PARAM_construct_BN(key, std::ptr::null_mut(), 0) };
        /* calculate needed size */
        unsafe {
            OSSL_PARAM_set_BN(&mut param, bn);
        }
        let mut container = Vec::<u8>::with_capacity(param.return_size);
        container.resize(param.return_size, 0);
        param.data = container.as_mut_ptr() as *mut std::os::raw::c_void;
        param.data_size = container.len();
        unsafe {
            OSSL_PARAM_set_BN(&mut param, bn);
        }
        self.v.push(container);
        self.p.push(param);
        Ok(self)
    }

    pub fn add_bn_from_obj(
        self,
        obj: &object::Object,
        attr: CK_ATTRIBUTE_TYPE,
        key: *const c_char,
    ) -> KResult<OsslParam> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let val = match obj.get_attr_as_bytes(attr) {
            Ok(v) => v,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        self.add_bn(key, val)
    }

    pub fn add_utf8_string(
        mut self,
        key: *const c_char,
        v: &Vec<u8>,
    ) -> KResult<OsslParam> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let mut container = v.clone();
        let param = unsafe {
            OSSL_PARAM_construct_utf8_string(
                key,
                container.as_mut_ptr() as *mut i8,
                0,
            )
        };
        self.v.push(container);
        self.p.push(param);
        Ok(self)
    }

    pub fn add_octet_string(
        mut self,
        key: *const c_char,
        v: &Vec<u8>,
    ) -> KResult<OsslParam> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let mut container = v.clone();
        let param = unsafe {
            OSSL_PARAM_construct_octet_string(
                key,
                container.as_mut_ptr() as *mut std::os::raw::c_void,
                container.len(),
            )
        };
        self.v.push(container);
        self.p.push(param);
        Ok(self)
    }

    pub fn add_size_t(
        mut self,
        key: *const c_char,
        val: usize,
    ) -> KResult<OsslParam> {
        if self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }

        let container = val.to_ne_bytes().to_vec();
        unsafe {
            OSSL_PARAM_construct_size_t(key, container.as_ptr() as *mut usize);
        }
        self.v.push(container);
        Ok(self)
    }

    pub fn finalize(mut self) -> OsslParam {
        if self.finalized {
            return self;
        }
        self.p.push(unsafe { OSSL_PARAM_construct_end() });
        self.finalized = true;
        self.ptr = self.p.as_mut_ptr();
        self.nelem = self.p.len() - 1;
        self
    }

    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut OSSL_PARAM {
        if !self.finalized {
            panic!("Unfinalized OsslParam");
        }
        self.ptr
    }

    pub fn get_bn(&self, key: *const c_char) -> KResult<Vec<u8>> {
        if !self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let p = unsafe { OSSL_PARAM_locate(self.ptr, key) };
        if p.is_null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let mut bn: *mut BIGNUM = std::ptr::null_mut();
        if unsafe { OSSL_PARAM_get_BN(p, &mut bn) } != 1 {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let big_num = BigNum::from_ptr(bn)?;
        let len = bn_num_bytes(big_num.as_ptr());
        let mut vec = Vec::<u8>::with_capacity(len);
        if unsafe {
            BN_bn2bin(
                big_num.as_ptr(),
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

    pub fn get_octet_string(&self, key: *const c_char) -> KResult<Vec<u8>> {
        if !self.finalized {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        let p = unsafe { OSSL_PARAM_locate(self.ptr, key) };
        if p.is_null() {
            return err_rv!(CKR_GENERAL_ERROR);
        }
        // get length
        let mut buf_len = 0;
        let res = unsafe {
            OSSL_PARAM_get_octet_string(
                p,
                std::ptr::null_mut(),
                0,
                &mut buf_len,
            )
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        let mut octet = Vec::with_capacity(buf_len);
        let buf_ptr = &mut octet.as_ptr();
        let res = unsafe {
            OSSL_PARAM_get_octet_string(
                p,
                buf_ptr as *mut _ as *mut *mut std::os::raw::c_void,
                buf_len,
                &mut buf_len,
            )
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }
        unsafe {
            octet.set_len(buf_len);
        }
        Ok(octet)
    }
}

pub fn empty_private_key() -> EvpPkey {
    EvpPkey::empty()
}

pub fn empty_public_key() -> EvpPkey {
    EvpPkey::empty()
}

pub fn mech_type_to_digest_name(mech: CK_MECHANISM_TYPE) -> *const c_char {
    (match mech {
        CKM_SHA1_RSA_PKCS
        | CKM_ECDSA_SHA1
        | CKM_SHA1_RSA_PKCS_PSS
        | CKM_SHA_1 => OSSL_DIGEST_NAME_SHA1.as_ptr(),
        CKM_SHA224_RSA_PKCS
        | CKM_ECDSA_SHA224
        | CKM_SHA224_RSA_PKCS_PSS
        | CKM_SHA224 => OSSL_DIGEST_NAME_SHA2_224.as_ptr(),
        CKM_SHA256_RSA_PKCS
        | CKM_ECDSA_SHA256
        | CKM_SHA256_RSA_PKCS_PSS
        | CKM_SHA256 => OSSL_DIGEST_NAME_SHA2_256.as_ptr(),
        CKM_SHA384_RSA_PKCS
        | CKM_ECDSA_SHA384
        | CKM_SHA384_RSA_PKCS_PSS
        | CKM_SHA384 => OSSL_DIGEST_NAME_SHA2_384.as_ptr(),
        CKM_SHA512_RSA_PKCS
        | CKM_ECDSA_SHA512
        | CKM_SHA512_RSA_PKCS_PSS
        | CKM_SHA512 => OSSL_DIGEST_NAME_SHA2_512.as_ptr(),
        CKM_SHA3_224_RSA_PKCS
        | CKM_ECDSA_SHA3_224
        | CKM_SHA3_224_RSA_PKCS_PSS
        | CKM_SHA3_224 => OSSL_DIGEST_NAME_SHA3_224.as_ptr(),
        CKM_SHA3_256_RSA_PKCS
        | CKM_ECDSA_SHA3_256
        | CKM_SHA3_256_RSA_PKCS_PSS
        | CKM_SHA3_256 => OSSL_DIGEST_NAME_SHA3_256.as_ptr(),
        CKM_SHA3_384_RSA_PKCS
        | CKM_ECDSA_SHA3_384
        | CKM_SHA3_384_RSA_PKCS_PSS
        | CKM_SHA3_384 => OSSL_DIGEST_NAME_SHA3_384.as_ptr(),
        CKM_SHA3_512_RSA_PKCS
        | CKM_ECDSA_SHA3_512
        | CKM_SHA3_512_RSA_PKCS_PSS
        | CKM_SHA3_512 => OSSL_DIGEST_NAME_SHA3_512.as_ptr(),
        _ => std::ptr::null(),
    }) as *const c_char
}

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
ptr_wrapper!(OsslParam; OSSL_PARAM; OSSL_PARAM_free);

pub fn bn_num_bytes(a: *const BIGNUM) -> usize {
    let x = unsafe { (BN_num_bits(a) + 7) / 8 };
    x as usize
}

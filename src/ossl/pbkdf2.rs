// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use core::ffi::c_uint;

impl PBKDF2 {
    fn derive(&self, _: &Mechanisms, len: usize) -> KResult<Vec<u8>> {
        let params = OsslParam::with_capacity(4)
            .set_zeroize()
            .add_octet_string(
                name_as_char(OSSL_KDF_PARAM_PASSWORD),
                self.pass.get_attr_as_bytes(CKA_VALUE)?,
            )?
            .add_octet_string(name_as_char(OSSL_KDF_PARAM_SALT), &self.salt)?
            .add_uint(name_as_char(OSSL_KDF_PARAM_ITER), self.iter as c_uint)?
            .add_const_c_string(
                name_as_char(OSSL_KDF_PARAM_DIGEST),
                mech_type_to_digest_name(self.prf),
            )?
            .finalize();

        let mut kdf = match EvpKdf::from_ptr(unsafe {
            EVP_KDF_fetch(
                get_libctx(),
                name_as_char(OSSL_KDF_NAME_PBKDF2),
                std::ptr::null(),
            )
        }) {
            Ok(ek) => ek,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };
        let mut kctx = match EvpKdfCtx::from_ptr(unsafe {
            EVP_KDF_CTX_new(kdf.as_mut_ptr())
        }) {
            Ok(ekc) => ekc,
            Err(_) => return err_rv!(CKR_DEVICE_ERROR),
        };

        let mut dkm = vec![0u8; len];
        let res = unsafe {
            EVP_KDF_derive(
                kctx.as_mut_ptr(),
                dkm.as_mut_ptr(),
                dkm.len(),
                params.as_ptr(),
            )
        };
        if res != 1 {
            return err_rv!(CKR_DEVICE_ERROR);
        }

        Ok(dkm)
    }
}

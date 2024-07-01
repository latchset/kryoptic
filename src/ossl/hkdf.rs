// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(not(feature = "fips"))]
use {super::ossl, ossl::*};

impl Derive for HKDFOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> KResult<(Object, usize)> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        self.verify_key(key, self.prflen)?;

        if self.salt.len() == 0 {
            match self.salt_type {
                CKF_HKDF_SALT_KEY => return err_rv!(CKR_GENERAL_ERROR),
                _ => return err_rv!(CKR_MECHANISM_PARAM_INVALID),
            }
        }

        let (mut obj, keysize) = if self.emit_data_obj {
            self.data_object_and_secret_size(template, objfactories)
        } else {
            self.key_object_and_secret_size(key, template, objfactories)
        }?;

        if !self.expand && keysize != self.prflen {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }
        if keysize == 0 || keysize > (u32::MAX as usize) {
            return err_rv!(CKR_KEY_SIZE_RANGE);
        }

        let mode = if self.extract {
            if self.expand {
                EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
            } else {
                EVP_KDF_HKDF_MODE_EXTRACT_ONLY
            }
        } else {
            EVP_KDF_HKDF_MODE_EXPAND_ONLY
        };

        let mut params = OsslParam::with_capacity(5)
            .set_zeroize()
            .add_octet_string(
                name_as_char(OSSL_KDF_PARAM_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?,
            )?
            .add_const_c_string(
                name_as_char(OSSL_KDF_PARAM_DIGEST),
                mech_type_to_digest_name(self.prf),
            )?
            .add_int(name_as_char(OSSL_KDF_PARAM_MODE), mode as c_int)?;

        if self.salt.len() > 0 {
            params = params.add_octet_string(
                name_as_char(OSSL_KDF_PARAM_SALT),
                &self.salt,
            )?;
        }

        if self.info.len() > 0 {
            params = params.add_octet_string(
                name_as_char(OSSL_KDF_PARAM_INFO),
                &self.info,
            )?;
        }
        params = params.finalize();

        let mut kctx = EvpKdfCtx::new(name_as_char(OSSL_KDF_NAME_HKDF))?;
        let mut dkm = vec![0u8; keysize];
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

        obj.set_attr(from_bytes(CKA_VALUE, dkm))?;

        Ok((obj, 0))
    }

    fn derive_additional_key(
        &mut self,
    ) -> KResult<(Object, CK_OBJECT_HANDLE_PTR)> {
        err_rv!(CKR_GENERAL_ERROR)
    }
}

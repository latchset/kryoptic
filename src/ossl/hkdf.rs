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
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        self.verify_key(key, self.prflen)?;

        if self.salt.len() == 0 {
            match self.salt_type {
                CKF_HKDF_SALT_KEY => return Err(CKR_GENERAL_ERROR)?,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            }
        }

        let (mut obj, keysize) = if self.emit_data_obj {
            misc::common_derive_data_object(template, objfactories, self.prflen)
        } else {
            misc::common_derive_key_object(
                key,
                template,
                objfactories,
                self.prflen,
            )
        }?;

        if !self.expand && keysize != self.prflen {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if keysize == 0 || keysize > usize::try_from(u32::MAX)? {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let mode = if self.extract {
            if self.expand {
                c_int::try_from(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND)?
            } else {
                c_int::try_from(EVP_KDF_HKDF_MODE_EXTRACT_ONLY)?
            }
        } else {
            c_int::try_from(EVP_KDF_HKDF_MODE_EXPAND_ONLY)?
        };

        let mut params = OsslParam::with_capacity(5);
        params.zeroize = true;
        params.add_octet_string(
            name_as_char(OSSL_KDF_PARAM_KEY),
            key.get_attr_as_bytes(CKA_VALUE)?,
        )?;
        params.add_const_c_string(
            name_as_char(OSSL_KDF_PARAM_DIGEST),
            mech_type_to_digest_name(self.prf),
        )?;
        params.add_int(name_as_char(OSSL_KDF_PARAM_MODE), &mode)?;

        if self.salt.len() > 0 {
            params.add_octet_string(
                name_as_char(OSSL_KDF_PARAM_SALT),
                &self.salt,
            )?;
        }

        if self.info.len() > 0 {
            params.add_octet_string(
                name_as_char(OSSL_KDF_PARAM_INFO),
                &self.info,
            )?;
        }
        params.finalize();

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
            return Err(CKR_DEVICE_ERROR)?;
        }

        #[cfg(feature = "fips")]
        {
            self.fips_approved =
                fips::indicators::check_kdf_fips_indicators(&mut kctx)?;
        }

        obj.set_attr(from_bytes(CKA_VALUE, dkm))?;

        Ok(vec![obj])
    }
}

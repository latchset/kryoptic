// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

impl Derive for SSHKDFOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return err_rv!(CKR_OPERATION_NOT_INITIALIZED);
        }
        self.finalized = true;

        key.check_key_ops(CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKA_DERIVE)?;

        let (mut dobj, value_len) = if self.is_data {
            misc::common_derive_data_object(template, objfactories, 0)
        } else {
            misc::common_derive_key_object(key, template, objfactories, 0)
        }?;
        if value_len == 0 || value_len > (u32::MAX as usize) {
            return err_rv!(CKR_TEMPLATE_INCONSISTENT);
        }

        let sshkdf_type = vec![self.key_type, 0u8];
        let mut params = OsslParam::with_capacity(5);
        params.zeroize = true;
        params.add_const_c_string(
            name_as_char(OSSL_ALG_PARAM_DIGEST),
            mech_type_to_digest_name(self.prf),
        )?;
        params.add_octet_string(
            name_as_char(OSSL_KDF_PARAM_KEY),
            key.get_attr_as_bytes(CKA_VALUE)?,
        )?;
        params.add_octet_string(
            name_as_char(OSSL_KDF_PARAM_SSHKDF_XCGHASH),
            &self.exchange_hash,
        )?;
        params.add_octet_string(
            name_as_char(OSSL_KDF_PARAM_SSHKDF_SESSION_ID),
            &self.session_id,
        )?;
        params.add_utf8_string(
            name_as_char(OSSL_KDF_PARAM_SSHKDF_TYPE),
            &sshkdf_type,
        )?;
        params.finalize();

        let mut kctx = EvpKdfCtx::new(name_as_char(OSSL_KDF_NAME_SSHKDF))?;
        let mut dkm = vec![0u8; value_len];
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

        self.fips_approved =
            fips::indicators::check_kdf_fips_indicators(&mut kctx)?;

        dobj.set_attr(from_bytes(CKA_VALUE, dkm))?;
        Ok(vec![dobj])
    }
}

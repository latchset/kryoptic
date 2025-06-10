// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::attribute::Attribute;
use crate::error::Result;
use crate::hash;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc;
use crate::object::{Object, ObjectFactories};
use crate::ossl::common::*;
use crate::ossl::fips::*;
use crate::{bytes_to_vec, cast_params};

use ossl::bindings::*;
use ossl::{EvpKdfCtx, OsslParam};
use pkcs11::vendor::KR_SSHKDF_PARAMS;
use pkcs11::*;

#[derive(Debug)]
pub struct SSHKDFOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    key_type: u8,
    exchange_hash: Vec<u8>,
    session_id: Vec<u8>,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
    is_data: bool,
}

impl SSHKDFOperation {
    pub fn new(mech: &CK_MECHANISM) -> Result<SSHKDFOperation> {
        let params = cast_params!(mech, KR_SSHKDF_PARAMS);

        if !hash::is_valid_hash(params.prfHashMechanism) {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let is_data = match params.derivedKeyType {
            0x41 => true,  /* A */
            0x42 => true,  /* B */
            0x43 => false, /* C */
            0x44 => false, /* D */
            0x45 => false, /* E */
            0x46 => false, /* F */
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        Ok(SSHKDFOperation {
            mech: mech.mechanism,
            finalized: false,
            prf: params.prfHashMechanism,
            key_type: params.derivedKeyType,
            exchange_hash: bytes_to_vec!(
                params.pExchangeHash,
                params.ulExchangeHashLen
            ),
            session_id: bytes_to_vec!(params.pSessionId, params.ulSessionIdLen),
            #[cfg(feature = "fips")]
            fips_approved: None,
            is_data: is_data,
        })
    }
}

impl MechOperation for SSHKDFOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approved
    }
}

impl Derive for SSHKDFOperation {
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

        key.check_key_ops(CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKA_DERIVE)?;

        let (mut dobj, value_len) = if self.is_data {
            misc::common_derive_data_object(template, objfactories, 0)
        } else {
            misc::common_derive_key_object(key, template, objfactories, 0)
        }?;
        if value_len == 0 || value_len > usize::try_from(u32::MAX)? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
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

        #[cfg(feature = "fips")]
        fips_approval_prep_check();

        let mut kctx =
            EvpKdfCtx::new(osslctx(), name_as_char(OSSL_KDF_NAME_SSHKDF))?;
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
            return Err(CKR_DEVICE_ERROR)?;
        }

        #[cfg(feature = "fips")]
        fips_approval_finalize(&mut self.fips_approved);

        dobj.set_attr(Attribute::from_bytes(CKA_VALUE, dkm))?;
        Ok(vec![dobj])
    }
}

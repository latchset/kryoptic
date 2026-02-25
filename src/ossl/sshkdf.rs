// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::attribute::Attribute;
use crate::error::Result;
use crate::hash::is_valid_hash;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::{
    bytes_to_slice, cast_params, common_derive_data_object,
    common_derive_key_object,
};
use crate::object::{Object, ObjectFactories};
use crate::ossl::common::{mech_type_to_digest_alg, osslctx};
use crate::pkcs11::vendor::KR_SSHKDF_PARAMS;
use crate::pkcs11::*;

use ossl::derive::{SshKdfPurpose, SshkdfDerive};

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

#[derive(Debug)]
pub struct SSHKDFOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    purpose: SshKdfPurpose,
    exchange_hash: &'static [u8], /* TODO: static -> a */
    session_id: &'static [u8],    /* TODO: static -> a */
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

impl SSHKDFOperation {
    pub fn new(mech: &CK_MECHANISM) -> Result<SSHKDFOperation> {
        let params = cast_params!(mech, KR_SSHKDF_PARAMS);

        if !is_valid_hash(params.prfHashMechanism) {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let purpose = match params.derivedKeyType {
            b'A' => SshKdfPurpose::InitialIVClientToServer,
            b'B' => SshKdfPurpose::InitialIVServerToClient,
            b'C' => SshKdfPurpose::EncryptioKeyClientToServer,
            b'D' => SshKdfPurpose::EncryptioKeyServerToClient,
            b'E' => SshKdfPurpose::IntegrityKeyClientToServer,
            b'F' => SshKdfPurpose::IntegrityKeyServerToClient,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        Ok(SSHKDFOperation {
            mech: mech.mechanism,
            finalized: false,
            prf: params.prfHashMechanism,
            purpose: purpose,
            exchange_hash: bytes_to_slice!(
                params.pExchangeHash,
                params.ulExchangeHashLen,
                u8
            ),
            session_id: bytes_to_slice!(
                params.pSessionId,
                params.ulSessionIdLen,
                u8
            ),
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
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
        self.fips_approval.approval()
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

        let (mut dobj, value_len) = match self.purpose {
            SshKdfPurpose::InitialIVClientToServer
            | SshKdfPurpose::InitialIVServerToClient => {
                common_derive_data_object(template, objfactories, 0)?
            }
            _ => common_derive_key_object(key, template, objfactories, 0)?,
        };
        if value_len == 0 || value_len > usize::try_from(u32::MAX)? {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let mut kdf =
            SshkdfDerive::new(osslctx(), mech_type_to_digest_alg(self.prf)?)?;
        kdf.set_purpose(self.purpose);
        kdf.set_key(key.get_attr_as_bytes(CKA_VALUE)?.as_slice());
        kdf.set_hash(self.exchange_hash);
        kdf.set_session(self.session_id);

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut dkm = vec![0u8; value_len];
        kdf.derive(&mut dkm)?;

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        dobj.set_attr(Attribute::from_bytes(CKA_VALUE, dkm))?;
        Ok(vec![dobj])
    }
}

// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements Simple Key Derivation Functions (KDF)

use std::fmt::Debug;

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::mechanism::*;
use crate::misc::{bytes_to_vec, cast_params};
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::pkcs11::*;

#[cfg(feature = "fips")]
use ossl::fips::FipsApproval;

#[cfg(feature = "fips")]
use crate::fips::indicators::is_key_approved;

/// Represents the information about a key we use to derive other keys.
///
/// This is extracted at one place to be able to safely zeroize the
/// key value, rather than exporting it and keeping it around for
/// longer time
#[derive(Debug)]
struct KeyInfo {
    /// Value of the key `CKA_SENSITIVE` attribute
    sensitive: bool,
    /// Value of the key `CKA_EXTRACTABLE` attribute
    extractable: bool,
    /// Value of the key `CKA_ALWAYS_SENSITIVE` attribute
    always_sensitive: bool,
    /// Value of the key `CKA_NEVER_EXTRACTABLE` attribute
    never_extractable: bool,
    /// Value of the key itself (`CKA_VALUE` attribute)
    value: Vec<u8>,
}

impl Drop for KeyInfo {
    fn drop(&mut self) {
        ossl::zeromem(self.value.as_mut_slice());
    }
}

impl KeyInfo {
    /// Create a new key info from the given kkey `Object`
    pub fn new_from_object(obj: &Object) -> Result<KeyInfo> {
        Ok(KeyInfo {
            sensitive: obj.is_sensitive(),
            extractable: obj.is_extractable(),
            always_sensitive: obj.is_always_sensitive(),
            never_extractable: obj.is_never_extractable(),
            value: obj.get_attr_as_bytes(CKA_VALUE)?.clone(),
        })
    }
}

/// Represents a Simple Key Derivation Function (KDF) operation
///
/// This handles mechanisms like `CKM_CONCATENATE_*`, and
/// `CKM_XOR_BASE_AND_DATA`.
#[derive(Debug)]
pub struct SimpleKDFOperation {
    /// Tracks if the derive operation has been completed
    finalized: bool,
    /// The specific PKCS#11 Simple KDF mechanism being used
    mech: CK_MECHANISM_TYPE,
    /// The additional key handle in CKM_CONCATENATE_BASE_AND_KEY
    key_handle: Option<[CK_OBJECT_HANDLE; 1]>,
    /// The additional key in CKM_CONCATENATE_BASE_AND_KEY
    key_info: Option<KeyInfo>,
    /// The additional data to concatenate
    data: Option<Vec<u8>>,
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

unsafe impl Send for SimpleKDFOperation {}
unsafe impl Sync for SimpleKDFOperation {}

impl SimpleKDFOperation {
    /// Creates a new Simple KDF operation based on the provided mechanism
    ///
    /// Dispatches to specific constructors based on the mechanism type.
    pub fn new(mech: &CK_MECHANISM) -> Result<SimpleKDFOperation> {
        match mech.mechanism {
            CKM_CONCATENATE_BASE_AND_KEY => {
                let object_handle = cast_params!(mech, CK_OBJECT_HANDLE);
                Ok(SimpleKDFOperation {
                    finalized: false,
                    mech: mech.mechanism,
                    key_handle: Some([object_handle]),
                    key_info: None,
                    data: None,
                    #[cfg(feature = "fips")]
                    fips_approval: FipsApproval::init(),
                })
            }
            CKM_CONCATENATE_BASE_AND_DATA
            | CKM_CONCATENATE_DATA_AND_BASE
            | CKM_XOR_BASE_AND_DATA => {
                let params = cast_params!(mech, CK_KEY_DERIVATION_STRING_DATA);

                let data = bytes_to_vec!(params.pData, params.ulLen);
                if data.len() < 1 {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                Ok(SimpleKDFOperation {
                    finalized: false,
                    mech: mech.mechanism,
                    key_handle: None,
                    key_info: None,
                    data: Some(data),
                    #[cfg(feature = "fips")]
                    fips_approval: FipsApproval::init(),
                })
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

impl MechOperation for SimpleKDFOperation {
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
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if let Some(h) = &self.key_handle {
            return Ok(h);
        }
        Err(CKR_OK)?
    }
    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if objs.len() != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.key_info = Some(KeyInfo::new_from_object(objs[0])?);

        #[cfg(feature = "fips")]
        self.fips_approval.set(is_key_approved(objs[0], CKF_DERIVE));

        Ok(())
    }
}

impl Derive for SimpleKDFOperation {
    /// Performs the appropriate Simple KDF derivation based on the mechanism used
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

        key.check_key_ops(
            CKO_SECRET_KEY,
            CK_UNAVAILABLE_INFORMATION,
            CKA_DERIVE,
        )?;
        let base_key_info = KeyInfo::new_from_object(key)?;

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &CKO_SECRET_KEY);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &CKK_GENERIC_SECRET);

        let other_data_len = match self.mech {
            CKM_CONCATENATE_BASE_AND_KEY => {
                let another_key_info = match &self.key_info {
                    Some(k) => k,
                    None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                };

                if base_key_info.sensitive || another_key_info.sensitive {
                    tmpl.add_bool(CKA_SENSITIVE, &CK_TRUE);
                }
                if !base_key_info.extractable || !another_key_info.extractable {
                    tmpl.add_bool(CKA_EXTRACTABLE, &CK_FALSE);
                }
                if base_key_info.always_sensitive
                    && another_key_info.always_sensitive
                {
                    tmpl.add_bool(CKA_ALWAYS_SENSITIVE, &CK_TRUE);
                }
                if base_key_info.never_extractable
                    && another_key_info.never_extractable
                {
                    tmpl.add_bool(CKA_NEVER_EXTRACTABLE, &CK_TRUE);
                }
                another_key_info.value.len()
            }
            CKM_CONCATENATE_BASE_AND_DATA
            | CKM_CONCATENATE_DATA_AND_BASE
            | CKM_XOR_BASE_AND_DATA => {
                if base_key_info.sensitive {
                    tmpl.add_bool(CKA_SENSITIVE, &CK_TRUE);
                }
                if !base_key_info.extractable {
                    tmpl.add_bool(CKA_EXTRACTABLE, &CK_FALSE);
                }
                if base_key_info.always_sensitive {
                    tmpl.add_bool(CKA_ALWAYS_SENSITIVE, &CK_TRUE);
                }
                if base_key_info.never_extractable {
                    tmpl.add_bool(CKA_NEVER_EXTRACTABLE, &CK_TRUE);
                }
                match &self.data {
                    Some(d) => d.len(),
                    None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                }
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };

        let outlen = if self.mech == CKM_XOR_BASE_AND_DATA {
            std::cmp::min(base_key_info.value.len(), other_data_len)
        } else {
            base_key_info.value.len() + other_data_len
        };

        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;

        // check the length is compatible with the key type. Add default if missing
        let keylen = match tmpl.find_attr(CKA_VALUE_LEN) {
            Some(a) => usize::try_from(a.to_ulong()?)?,
            None => {
                match factory
                    .as_secret_key_factory()?
                    .recommend_key_size(outlen)
                {
                    Ok(len) => len,
                    Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
                }
            }
        };

        if keylen > outlen {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let mut secret = Vec::with_capacity(outlen);
        match self.mech {
            CKM_CONCATENATE_BASE_AND_KEY => {
                secret.extend_from_slice(&base_key_info.value);
                if let Some(k) = &self.key_info {
                    secret.extend_from_slice(&k.value);
                } else {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                secret.resize(keylen, 0);
            }
            CKM_CONCATENATE_BASE_AND_DATA => {
                secret.extend_from_slice(&base_key_info.value);
                if let Some(d) = &self.data {
                    secret.extend_from_slice(&d);
                } else {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                secret.resize(keylen, 0);
            }
            CKM_CONCATENATE_DATA_AND_BASE => {
                if let Some(d) = &self.data {
                    secret.extend_from_slice(&d);
                } else {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                secret.extend_from_slice(&base_key_info.value);
                secret.resize(keylen, 0);
            }
            CKM_XOR_BASE_AND_DATA => {
                if let Some(d) = &self.data {
                    secret.extend_from_slice(&d);
                } else {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                secret
                    .iter_mut()
                    .zip(base_key_info.value.iter())
                    .for_each(|(k, b)| *k ^= *b);
                secret.resize(keylen, 0);
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }

        let mut tmpl = CkAttrs::from(template);
        tmpl.zeroize = true;
        // ownership of the secret is taken by the `tmpl` here.
        tmpl.add_vec(CKA_VALUE, secret)?;
        let mut obj = factory.create(tmpl.as_slice())?;

        default_key_attributes(&mut obj, self.mech)?;

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(vec![obj])
    }
}

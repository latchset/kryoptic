// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements Simple Key Derivation Functions (KDF)

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::mechanism::*;
use crate::misc::{bytes_to_vec, cast_params};
use crate::object::{Object, ObjectFactories, ObjectType};
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
    /// The bit offset for CKM_EXTRACT_KEY_FROM_KEY
    bit_offset: Option<CK_ULONG>,
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
                    bit_offset: None,
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
                    bit_offset: None,
                    #[cfg(feature = "fips")]
                    fips_approval: FipsApproval::init(),
                })
            }
            CKM_EXTRACT_KEY_FROM_KEY => {
                let params = cast_params!(mech, CK_EXTRACT_PARAMS);
                Ok(SimpleKDFOperation {
                    finalized: false,
                    mech: mech.mechanism,
                    key_handle: None,
                    key_info: None,
                    data: None,
                    bit_offset: Some(params),
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
        let factory =
            objfactories.get_obj_factory_from_key_template(tmpl.as_slice())?;
        let mut dkey =
            factory.as_key_factory()?.key_derive(tmpl.as_slice(), key)?;

        let other_data_len = match self.mech {
            CKM_CONCATENATE_BASE_AND_KEY => {
                let another_key_info = match &self.key_info {
                    Some(k) => k,
                    None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                };

                let mut sensitive =
                    base_key_info.sensitive || another_key_info.sensitive;
                if !sensitive {
                    match tmpl.find_attr(CKA_SENSITIVE) {
                        Some(b) => sensitive = b.to_bool()?,
                        None => (),
                    };
                }
                dkey.set_attr(Attribute::from_bool(CKA_SENSITIVE, sensitive))?;
                let mut extractable =
                    base_key_info.extractable && another_key_info.extractable;
                if extractable {
                    match tmpl.find_attr(CKA_EXTRACTABLE) {
                        Some(b) => extractable = b.to_bool()?,
                        None => (),
                    };
                }
                dkey.set_attr(Attribute::from_bool(
                    CKA_EXTRACTABLE,
                    extractable,
                ))?;
                let always_sensitive = base_key_info.always_sensitive
                    && another_key_info.always_sensitive;
                dkey.set_attr(Attribute::from_bool(
                    CKA_ALWAYS_SENSITIVE,
                    always_sensitive,
                ))?;
                let never_extractable = base_key_info.never_extractable
                    && another_key_info.never_extractable;
                dkey.set_attr(Attribute::from_bool(
                    CKA_NEVER_EXTRACTABLE,
                    never_extractable,
                ))?;
                another_key_info.value.len()
            }
            CKM_CONCATENATE_BASE_AND_DATA
            | CKM_CONCATENATE_DATA_AND_BASE
            | CKM_XOR_BASE_AND_DATA => match &self.data {
                Some(d) => d.len(),
                None => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            },
            CKM_EXTRACT_KEY_FROM_KEY => 0,
            _ => return Err(CKR_MECHANISM_INVALID)?,
        };

        let outlen = match self.mech {
            CKM_XOR_BASE_AND_DATA => {
                std::cmp::min(base_key_info.value.len(), other_data_len)
            }
            CKM_EXTRACT_KEY_FROM_KEY => base_key_info.value.len(),
            _ => base_key_info.value.len() + other_data_len,
        };

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

        if self.mech == CKM_EXTRACT_KEY_FROM_KEY {
            let bit_offset =
                self.bit_offset.ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            let required_bits = keylen * 8;
            let available_bits = base_key_info.value.len() * 8;
            if (required_bits > available_bits)
                || (bit_offset + 7) / 8 > available_bits as CK_ULONG
            {
                return Err(CKR_TEMPLATE_INCONSISTENT)?;
            }
        } else if keylen > outlen {
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
            CKM_EXTRACT_KEY_FROM_KEY => {
                let bit_offset =
                    self.bit_offset.ok_or(CKR_MECHANISM_PARAM_INVALID)?
                        as usize;
                secret.resize(keylen, 0);

                /* TODO: optimize this using u128::rotate_left() */
                let bit_shift = bit_offset % 8;
                let base_byte = (bit_offset - bit_shift) / 8;

                for i in 0..keylen {
                    let first_half = base_key_info.value
                        [(base_byte + i) % outlen]
                        << bit_shift;
                    let second_half = base_key_info.value
                        [(base_byte + i + 1) % outlen]
                        >> (8 - bit_shift);
                    secret[i] = first_half | second_half;
                }
            }
            _ => return Err(CKR_MECHANISM_INVALID)?,
        }

        factory
            .as_secret_key_factory()?
            .set_key(&mut dkey, secret)?;

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        Ok(vec![dkey])
    }
}

enum AttrSource {
    DefaultBool(&'static CK_BBOOL),
    CopyFrom(CK_ATTRIBUTE_TYPE),
}

struct PubkeyAttrRule {
    pub_attr: CK_ATTRIBUTE_TYPE,
    source: AttrSource,
}

macro_rules! attr_init {
    ($attr:expr => false) => {
        PubkeyAttrRule {
            pub_attr: $attr,
            source: AttrSource::DefaultBool(&CK_FALSE),
        }
    };
    ($attr:expr => true) => {
        PubkeyAttrRule {
            pub_attr: $attr,
            source: AttrSource::DefaultBool(&CK_TRUE),
        }
    };
    ($attr:expr => $src:expr) => {
        PubkeyAttrRule {
            pub_attr: $attr,
            source: AttrSource::CopyFrom($src),
        }
    };
}

const PUBKEY_ATTR_DEFAULTS: &[PubkeyAttrRule] = &[
    attr_init!(CKA_TOKEN => false),
    attr_init!(CKA_PRIVATE => false),
    attr_init!(CKA_MODIFIABLE => true),
    // The following are specified in 6.43.8 as defaults, but elsewhere it
    // says they can never be set in a template, and they are fully handled
    // internally by our object creation code. We leave them here commented
    // to avoid later attempts at "fixing" this list. Some of these
    // attributes, furthermore, exists only for private keys and not public
    // keys in our implementation.
    // attr_init!(CKA_LOCAL => false),
    // attr_init!(CKA_SENSITIVE => false),
    // attr_init!(CKA_ALWAYS_SENSITIVE => false),
    // attr_init!(CKA_EXTRACTABLE => true),
    // attr_init!(CKA_NEVER_EXTRACTABLE => false),
    attr_init!(CKA_COPYABLE => true),
    attr_init!(CKA_DESTROYABLE => false),
    attr_init!(CKA_ENCRYPT => CKA_DECRYPT),
    attr_init!(CKA_VERIFY => CKA_SIGN),
    attr_init!(CKA_VERIFY_RECOVER => CKA_SIGN_RECOVER),
    attr_init!(CKA_WRAP => CKA_UNWRAP),
    attr_init!(CKA_DERIVE => CKA_DERIVE),
    attr_init!(CKA_ID => CKA_ID),
    attr_init!(CKA_START_DATE => CKA_START_DATE),
    attr_init!(CKA_END_DATE => CKA_END_DATE),
    attr_init!(CKA_SUBJECT => CKA_SUBJECT),
    attr_init!(CKA_PUBLIC_KEY_INFO => CKA_PUBLIC_KEY_INFO),
    // We need to handle this manually post-facto because the object
    // creation rules prohibit adding this to the template
    // attr_init!(CKA_KEY_GEN_MECHANISM => CKA_KEY_GEN_MECHANISM),

    // This is not handled yet, setting it will always result in an error
    // attr_init!(CKA_TRUSTED => CKA_TRUSTED),

    // Not mentioned in 6.43.8 but necessary for ML-KEM
    attr_init!(CKA_ENCAPSULATE => CKA_DECAPSULATE),
];

/// Represents a public key from private key derivation operation
#[derive(Debug)]
pub struct PubFromPrivOperation {
    finalized: bool,
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

unsafe impl Send for PubFromPrivOperation {}
unsafe impl Sync for PubFromPrivOperation {}

impl PubFromPrivOperation {
    /// Creates a new public key from private key derivation operation
    pub fn new(mech: &CK_MECHANISM) -> Result<Self> {
        if mech.mechanism != CKM_PUB_KEY_FROM_PRIV_KEY {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        // This mechanism has no parameters
        if !mech.pParameter.is_null() || mech.ulParameterLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        Ok(PubFromPrivOperation {
            finalized: false,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }
}

impl MechOperation for PubFromPrivOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(CKM_PUB_KEY_FROM_PRIV_KEY)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
    #[cfg(feature = "fips")]
    fn fips_approved(&self) -> Option<bool> {
        self.fips_approval.approval()
    }
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        Err(CKR_OK)?
    }
    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if !objs.is_empty() {
            Err(CKR_GENERAL_ERROR)?
        }
        Ok(())
    }
}

impl Derive for PubFromPrivOperation {
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

        // key must be a private key
        // It does not need to allow derivation, as this is a pseudo
        // mechanism that is alaways usable for any private key
        if !key.is_private() {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }

        let key_type = match key.get_attr_as_ulong(CKA_KEY_TYPE) {
            Ok(k) => k,
            Err(_) => return Err(CKR_KEY_HANDLE_INVALID)?,
        };

        let mut pub_tmpl = CkAttrs::from(template);

        // Ensure class and key type are set correctly.
        // If template has them, they must be correct. If not, we add them.
        if let Some(attr) = pub_tmpl.get_ulong(CKA_CLASS)? {
            if attr != CKO_PUBLIC_KEY {
                return Err(CKR_TEMPLATE_INCONSISTENT)?;
            }
        } else {
            pub_tmpl.add_ulong(CKA_CLASS, &CKO_PUBLIC_KEY);
        }
        if let Some(val) = pub_tmpl.get_ulong(CKA_KEY_TYPE)? {
            if val != key_type {
                return Err(CKR_TEMPLATE_INCONSISTENT)?;
            }
        } else {
            pub_tmpl.add_ulong(CKA_KEY_TYPE, &key_type);
        }

        // Apply rules for default values or copying from private key
        for rule in PUBKEY_ATTR_DEFAULTS {
            match rule.source {
                AttrSource::DefaultBool(val) => {
                    pub_tmpl.add_missing_bool(rule.pub_attr, val);
                }
                AttrSource::CopyFrom(priv_attr) => {
                    if let Some(attr) = key.get_attr(priv_attr) {
                        pub_tmpl.add_missing_slice(
                            rule.pub_attr,
                            attr.get_value().as_slice(),
                        )?;
                    }
                }
            }
        }

        let pubtype = ObjectType::new(CKO_PUBLIC_KEY, key_type);
        let key_factory =
            objfactories.get_factory(pubtype)?.as_public_key_factory()?;
        let mut pub_key = key_factory.pub_from_private(key, pub_tmpl)?;

        if let Some(attr) = key.get_attr(CKA_KEY_GEN_MECHANISM) {
            pub_key.set_attr(attr.clone())?;
        }

        Ok(vec![pub_key])
    }
}

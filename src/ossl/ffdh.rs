// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements FFDH (Finite Field Diffie-Hellman) key generation
//! and derivation functionality according to PKCS#11 standards using the
//! OpenSSL APIs.

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::ffdh::FFDHMechanism;
use crate::ffdh_groups::{get_group_name, group_prime, DHGroupName};
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::pkey::{EvpPkey, EvpPkeyType, FfdhData, PkeyData};
use ossl::OsslParam;
use pkcs11::*;

/* This is the smallest AES key size, anything smaller then this
 * is worthless as a shared secret */
const MIN_KEYLEN: usize = 16;

fn group_to_pkey_type(group: DHGroupName) -> Result<EvpPkeyType> {
    Ok(match group {
        DHGroupName::FFDHE2048 => EvpPkeyType::Ffdhe2048,
        DHGroupName::FFDHE3072 => EvpPkeyType::Ffdhe3072,
        DHGroupName::FFDHE4096 => EvpPkeyType::Ffdhe4096,
        DHGroupName::FFDHE6144 => EvpPkeyType::Ffdhe6144,
        DHGroupName::FFDHE8192 => EvpPkeyType::Ffdhe8192,
        DHGroupName::MODP2048 => EvpPkeyType::Modp2048,
        DHGroupName::MODP3072 => EvpPkeyType::Modp3072,
        DHGroupName::MODP4096 => EvpPkeyType::Modp4096,
        DHGroupName::MODP6144 => EvpPkeyType::Modp6144,
        DHGroupName::MODP8192 => EvpPkeyType::Modp8192,
    })
}

/// Converts a PKCS#11 DH key `Object` into an `EvpPkey`.
///
/// Extracts the relevant key components (group name, public or private value)
/// based on the object `class` and populates a `FfdhData` structure suitable
/// for creating an `EvpPkey`.
pub fn ffdh_object_to_pkey(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<EvpPkey> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }

    let pkey_type = match get_group_name(key) {
        Ok(g) => group_to_pkey_type(g)?,
        Err(e) => return Err(Error::ck_rv_from_error(CKR_KEY_INDIGESTIBLE, e)),
    };

    match kclass {
        CKO_PUBLIC_KEY => Ok(EvpPkey::import(
            osslctx(),
            pkey_type,
            PkeyData::Ffdh(FfdhData {
                pubkey: Some(key.get_attr_as_bytes(CKA_VALUE)?.clone()),
                prikey: None,
            }),
        )?),
        CKO_PRIVATE_KEY => Ok(EvpPkey::import(
            osslctx(),
            pkey_type,
            PkeyData::Ffdh(FfdhData {
                pubkey: None,
                prikey: Some(key.get_attr_as_bytes(CKA_VALUE)?.clone()),
            }),
        )?),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }
}

/// Represents an active FFDH key derivation operation.
#[derive(Debug)]
pub struct FFDHOperation {
    /// The specific FFDH mechanism type (e.g., CKM_DH_PKCS_DERIVE).
    mech: CK_MECHANISM_TYPE,
    /// Peer's public key point data.
    public: Vec<u8>,
    /// Flag indicating if the derivation has been finalized.
    finalized: bool,
}

impl FFDHOperation {
    /// Creates a new `FFDHOperation` instance.
    pub fn derive_new<'a>(
        mechanism: CK_MECHANISM_TYPE,
        peerpub: Vec<u8>,
    ) -> Result<FFDHOperation> {
        if peerpub.len() == 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        Ok(FFDHOperation {
            finalized: false,
            mech: mechanism,
            public: peerpub,
        })
    }

    /// Generates an FFDH key pair using OpenSSL.
    ///
    /// Takes mutable references to pre-created public and private key
    /// `Object`s, generates the key pair, and populates the CKA_VALUE
    /// attributes for both the private and public key objects.
    pub fn generate_keypair(
        group: DHGroupName,
        pubkey: &mut Object,
        privkey: &mut Object,
    ) -> Result<()> {
        let pkey = EvpPkey::generate(osslctx(), group_to_pkey_type(group)?)?;

        let ffdh = match pkey.export()? {
            PkeyData::Ffdh(f) => f,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        /* Set Public Key */
        if let Some(key) = ffdh.pubkey {
            pubkey.check_or_set_attr(Attribute::from_bytes(
                CKA_PRIME,
                group_prime(group)?,
            ))?;

            pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* Set Private Key */
        if let Some(key) = ffdh.prikey {
            privkey.check_or_set_attr(Attribute::from_bytes(
                CKA_PRIME,
                group_prime(group)?,
            ))?;
            privkey.set_attr(Attribute::from_ulong(
                CKA_VALUE_BITS,
                CK_ULONG::try_from(key.len() * 8)?,
            ))?;
            privkey.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
    }

    /// Actual implementation of mechanism registration
    pub fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(CKM_DH_PKCS_DERIVE, FFDHMechanism::new(CKF_DERIVE));
        mechs.add_mechanism(
            CKM_DH_PKCS_KEY_PAIR_GEN,
            FFDHMechanism::new(CKF_GENERATE_KEY_PAIR),
        );
    }
}

impl MechOperation for FFDHOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for FFDHOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _mechanism: &Mechanisms,
        objectfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        let mut pkey = privkey_from_object(key)?;
        let params = OsslParam::empty();

        let factory =
            objectfactories.get_obj_factory_from_key_template(template)?;

        let mut ctx = pkey.new_ctx(osslctx())?;
        let res = unsafe {
            EVP_PKEY_derive_init_ex(ctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* Import peer key */
        let mut peer = pkey.make_peer(osslctx(), self.public.as_slice())?;

        let res = unsafe {
            EVP_PKEY_derive_set_peer(ctx.as_mut_ptr(), peer.as_mut_ptr())
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut secret_len = 0usize;
        let res = unsafe {
            EVP_PKEY_derive(
                ctx.as_mut_ptr(),
                std::ptr::null_mut(),
                &mut secret_len,
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut secret = vec![0u8; secret_len];
        let res = unsafe {
            EVP_PKEY_derive(
                ctx.as_mut_ptr(),
                secret.as_mut_ptr(),
                &mut secret_len,
            )
        };
        if res != 1 || secret_len < MIN_KEYLEN {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let keylen = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(attr) => {
                let len = usize::try_from(attr.to_ulong()?)?;
                if len > secret_len {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                len
            }
            None => secret_len,
        };

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_owned_slice(
            CKA_VALUE,
            &secret[(secret_len - keylen)..secret_len],
        )?;
        tmpl.zeroize = true;
        let mut obj = factory.create(tmpl.as_slice())?;

        default_key_attributes(&mut obj, self.mech)?;
        Ok(vec![obj])
    }
}

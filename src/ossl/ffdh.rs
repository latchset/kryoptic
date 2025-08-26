// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements FFDH (Finite Field Diffie-Hellman) key generation
//! and derivation functionality according to PKCS#11 standards using the
//! OpenSSL APIs.

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::ffdh_groups::{get_group_name, group_prime, DHGroupName};
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::ossl::common::{osslctx, privkey_from_object};
use crate::pkcs11::*;

use ossl::derive::FfdhDerive;
use ossl::pkey::{EvpPkey, EvpPkeyType, FfdhData, PkeyData};
use ossl::OsslSecret;

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
            None,
        )?),
        CKO_PRIVATE_KEY => Ok(EvpPkey::import(
            osslctx(),
            pkey_type,
            PkeyData::Ffdh(FfdhData {
                pubkey: None,
                prikey: Some(OsslSecret::from_vec(
                    key.get_attr_as_bytes(CKA_VALUE)?.clone(),
                )),
            }),
            None,
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
        if peerpub.is_empty() {
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
        let pkey =
            EvpPkey::generate(osslctx(), group_to_pkey_type(group)?, None)?;

        let mut ffdh = match pkey.export()? {
            PkeyData::Ffdh(f) => f,
            _ => return Err(CKR_GENERAL_ERROR)?,
        };

        /* Set Public Key */
        if let Some(key) = ffdh.pubkey.take() {
            pubkey.check_or_set_attr(Attribute::from_bytes(
                CKA_PRIME,
                group_prime(group)?,
            ))?;

            pubkey.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        /* Set Private Key */
        if let Some(key) = ffdh.prikey.take() {
            privkey.check_or_set_attr(Attribute::from_bytes(
                CKA_PRIME,
                group_prime(group)?,
            ))?;
            privkey.set_attr(Attribute::from_ulong(
                CKA_VALUE_BITS,
                CK_ULONG::try_from(key.len() * 8)?,
            ))?;
            privkey.set_attr(Attribute::from_bytes(CKA_VALUE, key.to_vec()))?;
        } else {
            return Err(CKR_DEVICE_ERROR)?;
        }

        Ok(())
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

        let factory =
            objectfactories.get_obj_factory_from_key_template(template)?;

        let mut pkey = privkey_from_object(key)?;
        let mut peer =
            pkey.make_peer(osslctx(), self.public.as_slice(), None)?;
        let mut ffdh = FfdhDerive::new(osslctx(), &mut pkey)?;

        let pkey_size = pkey.get_size()?;
        let req_len = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(attr) => {
                let len = usize::try_from(attr.to_ulong()?)?;
                if len > pkey_size {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                len
            }
            None => match factory
                .as_secret_key_factory()?
                .recommend_key_size(pkey_size)
            {
                Ok(len) => len,
                Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
            },
        };

        ffdh.set_outlen(req_len)?;
        let mut secret = OsslSecret::new(req_len);

        let outlen = ffdh.derive(&mut peer, &mut secret)?;
        if outlen != req_len {
            if req_len != pkey_size {
                return Err(CKR_GENERAL_ERROR)?;
            }
            /* FFDH maximum secret length is not fully deterministic and can
             * vary slightly. The maximum length may have been requested
             * because no CKA_VALUE_LEN was found and recommend_key_size()
             * may just reflect back the key size when the underlying key can
             * be of any length. Recheck if that is the case and accept the
             * shorter secret if so */
            let ret = match factory
                .as_secret_key_factory()?
                .recommend_key_size(outlen)
            {
                Ok(len) => {
                    if outlen == len {
                        Ok(())
                    } else {
                        Err(CKR_TEMPLATE_INCONSISTENT)?
                    }
                }
                Err(_) => Err(CKR_TEMPLATE_INCONSISTENT)?,
            };
            match ret {
                Ok(()) => {
                    secret.reduce(outlen, 0)?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_vec(CKA_VALUE, secret.to_vec())?;
        tmpl.zeroize = true;
        let mut obj = factory.create(tmpl.as_slice())?;

        default_key_attributes(&mut obj, self.mech)?;
        Ok(vec![obj])
    }
}

// Copyright 2025 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements FFDH (Finite Field Diffie-Hellman) key generation
//! and derivation functionality according to PKCS#11 standards using the
//! OpenSSL APIs.

use std::ffi::CStr;
use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::{Error, Result};
use crate::ffdh::FFDHMechanism;
use crate::ffdh_groups::{get_group_name, DHGroupName, FFDHE2048};
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::ossl::common::*;

use ossl::bindings::*;
use ossl::pkey::{EvpPkey, EvpPkeyType};
use ossl::OsslParam;
use pkcs11::*;

/// Names as understood by OpenSSL
const FFDHE2048_NAME: &CStr = c"ffdhe2048";
const FFDHE3072_NAME: &CStr = c"ffdhe3072";
const FFDHE4096_NAME: &CStr = c"ffdhe4096";
const FFDHE6144_NAME: &CStr = c"ffdhe6144";
const FFDHE8192_NAME: &CStr = c"ffdhe8192";
const MODP_2048_NAME: &CStr = c"modp_2048";
const MODP_3072_NAME: &CStr = c"modp_3072";
const MODP_4096_NAME: &CStr = c"modp_4096";
const MODP_6144_NAME: &CStr = c"modp_6144";
const MODP_8192_NAME: &CStr = c"modp_8192";

static DH_NAME: &CStr = c"DH";

/* This is the smallest AES key size, anything smaller then this
 * is worthless as a shared secret */
const MIN_KEYLEN: usize = 16;

fn group_to_ossl_name(group: DHGroupName) -> Result<&'static CStr> {
    Ok(match group {
        DHGroupName::FFDHE2048 => FFDHE2048_NAME,
        DHGroupName::FFDHE3072 => FFDHE3072_NAME,
        DHGroupName::FFDHE4096 => FFDHE4096_NAME,
        DHGroupName::FFDHE6144 => FFDHE6144_NAME,
        DHGroupName::FFDHE8192 => FFDHE8192_NAME,
        DHGroupName::MODP2048 => MODP_2048_NAME,
        DHGroupName::MODP3072 => MODP_3072_NAME,
        DHGroupName::MODP4096 => MODP_4096_NAME,
        DHGroupName::MODP6144 => MODP_6144_NAME,
        DHGroupName::MODP8192 => MODP_8192_NAME,
    })
}

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

pub fn get_group_name_from_key(key: &EvpPkey) -> Result<Vec<u8>> {
    let mut params = OsslParam::with_capacity(1);
    /* All group names have the same string length */
    params.add_empty_utf8_string(
        cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
        FFDHE2048.len(),
    )?;
    params.finalize();
    key.get_params(&mut params)?;
    Ok(params
        .get_utf8_string(cstr!(OSSL_PKEY_PARAM_GROUP_NAME))?
        .to_bytes_with_nul()
        .to_vec())
}

/// Converts a PKCS#11 DH key `Object` into OpenSSL parameters (`OsslParam`).
///
/// Extracts the relevant key components (prime, base, public or private value)
/// based on the object `class` and populates an `OsslParam` structure suitable
/// for creating an OpenSSL `EvpPkey`.
pub fn ffdh_object_to_params(
    key: &Object,
    class: CK_OBJECT_CLASS,
) -> Result<(&'static CStr, OsslParam)> {
    let kclass = key.get_attr_as_ulong(CKA_CLASS)?;
    if kclass != class {
        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
    }

    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;

    params.add_const_c_string(
        cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
        match get_group_name(key) {
            Ok(g) => group_to_ossl_name(g)?,
            Err(e) => {
                return Err(Error::ck_rv_from_error(CKR_KEY_INDIGESTIBLE, e))
            }
        },
    )?;

    match kclass {
        CKO_PUBLIC_KEY => {
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_PUB_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
            )?;
        }
        CKO_PRIVATE_KEY => {
            params.add_bn(
                cstr!(OSSL_PKEY_PARAM_PRIV_KEY),
                key.get_attr_as_bytes(CKA_VALUE)?.as_slice(),
            )?;
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    }

    params.finalize();

    Ok((DH_NAME, params))
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

    /// Creates an OpenSSL `EvpPkey` representing the peer's public key.
    ///
    /// Uses the provided local `key` object to determine the curve group
    /// and constructs the peer key using the supplied public key bytes.
    fn make_peer_key(&self, key: &EvpPkey) -> Result<EvpPkey> {
        let group_name = get_group_name_from_key(key)?;
        let mut params = OsslParam::with_capacity(2);
        params.add_const_c_string(
            cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
            cstr!(group_name.as_slice()),
        )?;
        params
            .add_bn(cstr!(OSSL_PKEY_PARAM_PUB_KEY), self.public.as_slice())?;
        params.finalize();

        Ok(EvpPkey::fromdata(
            osslctx(),
            DH_NAME,
            EVP_PKEY_PUBLIC_KEY,
            &params,
        )?)
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
        let evp_pkey =
            EvpPkey::generate(osslctx(), group_to_pkey_type(group)?)?;

        let params = evp_pkey.todata(EVP_PKEY_KEYPAIR)?;

        /* Public Key */
        pubkey.check_or_set_attr(Attribute::from_bytes(
            CKA_PRIME,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_FFC_P))?,
        ))?;
        pubkey.set_attr(Attribute::from_bytes(
            CKA_VALUE,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_PUB_KEY))?,
        ))?;

        /* Private Key */
        privkey.check_or_set_attr(Attribute::from_bytes(
            CKA_PRIME,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_FFC_P))?,
        ))?;
        privkey.set_attr(Attribute::from_bytes(
            CKA_VALUE,
            params.get_bn(cstr!(OSSL_PKEY_PARAM_PRIV_KEY))?,
        ))?;

        if params.has_param(cstr!(OSSL_PKEY_PARAM_DH_PRIV_LEN))? {
            privkey.set_attr(Attribute::from_ulong(
                CKA_VALUE_BITS,
                CK_ULONG::try_from(
                    params.get_long(cstr!(OSSL_PKEY_PARAM_DH_PRIV_LEN))?,
                )? * 8,
            ))?;
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
        let mut peer = self.make_peer_key(&pkey)?;

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

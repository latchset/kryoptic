// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

//! This module implements ECDH (Elliptic Curve Diffie-Hellman) key derivation
//! functionalities according to PKCS#11 standards (CKM_ECDH1_DERIVE,
//! CKM_ECDH1_COFACTOR_DERIVE) using the OpenSSL EVP_PKEY_derive API.

use std::borrow::Cow;

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::bytes_to_vec;
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::ossl::common::{
    cstr, get_ossl_name_from_obj, osslctx, privkey_from_object, EC_NAME,
};

use ossl::bindings::{
    EVP_PKEY_PUBLIC_KEY, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_PUB_KEY,
};
use ossl::derive::EcdhDerive;
use ossl::digest::DigestAlg;
use ossl::{EvpPkey, OsslParam};
use pkcs11::*;

/// Maps a PKCS#11 EC KDF type (`CK_EC_KDF_TYPE`) to the corresponding
/// ossl DigestAlg
fn kdf_type_to_digest_alg(mech: CK_EC_KDF_TYPE) -> Result<DigestAlg> {
    match mech {
        CKD_SHA1_KDF => Ok(DigestAlg::Sha1),
        CKD_SHA224_KDF => Ok(DigestAlg::Sha2_224),
        CKD_SHA256_KDF => Ok(DigestAlg::Sha2_256),
        CKD_SHA384_KDF => Ok(DigestAlg::Sha2_384),
        CKD_SHA512_KDF => Ok(DigestAlg::Sha2_512),
        CKD_SHA3_224_KDF => Ok(DigestAlg::Sha3_224),
        CKD_SHA3_256_KDF => Ok(DigestAlg::Sha3_256),
        CKD_SHA3_384_KDF => Ok(DigestAlg::Sha3_384),
        CKD_SHA3_512_KDF => Ok(DigestAlg::Sha3_512),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }
}

/// Creates an OpenSSL `EvpPkey` representing the peer's public key.
///
/// Uses the provided local `key` object to determine the curve group and
/// constructs the peer key using the supplied public point (`ec_point`) bytes
/// via `OSSL_PARAM`s.
fn make_peer_key(key: &Object, ec_point: &Vec<u8>) -> Result<EvpPkey> {
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;

    let name = match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        #[cfg(feature = "ecdsa")]
        CKK_EC => {
            params.add_const_c_string(
                cstr!(OSSL_PKEY_PARAM_GROUP_NAME),
                get_ossl_name_from_obj(key)?,
            )?;
            EC_NAME
        }
        #[cfg(feature = "ec_montgomery")]
        CKK_EC_MONTGOMERY => get_ossl_name_from_obj(key)?,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };

    params.add_octet_string(cstr!(OSSL_PKEY_PARAM_PUB_KEY), ec_point)?;
    params.finalize();

    Ok(EvpPkey::fromdata(
        osslctx(),
        name,
        EVP_PKEY_PUBLIC_KEY,
        &params,
    )?)
}

/// Represents an active ECDH key derivation operation.
#[derive(Debug)]
pub struct ECDHOperation {
    /// The specific ECDH mechanism type (e.g., CKM_ECDH1_DERIVE).
    mech: CK_MECHANISM_TYPE,
    /// The Key Derivation Function to apply (e.g., CKD_NULL, CKD_SHA256_KDF).
    kdf: CK_EC_KDF_TYPE,
    /// Peer's public key point data.
    public: Vec<u8>,
    /// Optional shared data for the KDF.
    shared: Option<Vec<u8>>,
    /// Flag indicating if the derivation has been finalized.
    finalized: bool,
}

impl ECDHOperation {
    /// Creates a new `ECDHOperation` instance.
    ///
    /// Parses the `CK_ECDH1_DERIVE_PARAMS` from the mechanism, validates them,
    /// and stores the necessary parameters.
    pub fn derive_new<'a>(
        mechanism: CK_MECHANISM_TYPE,
        params: CK_ECDH1_DERIVE_PARAMS,
    ) -> Result<ECDHOperation> {
        if params.kdf == CKD_NULL {
            if params.pSharedData != std::ptr::null_mut()
                || params.ulSharedDataLen != 0
            {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
        }
        if params.pPublicData == std::ptr::null_mut()
            || params.ulPublicDataLen == 0
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let shared =
            if !params.pSharedData.is_null() || params.ulSharedDataLen > 0 {
                Some(bytes_to_vec!(params.pSharedData, params.ulSharedDataLen))
            } else {
                None
            };

        Ok(ECDHOperation {
            finalized: false,
            mech: mechanism,
            kdf: params.kdf,
            shared: shared,
            public: bytes_to_vec!(params.pPublicData, params.ulPublicDataLen),
        })
    }
}

impl MechOperation for ECDHOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.mech)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }
}

impl Derive for ECDHOperation {
    /// Performs the ECDH key derivation.
    ///
    /// Sets up the OpenSSL derivation context using the local private `key`,
    /// imports the peer's public key point (`self.public`), performs the ECDH
    /// derivation (potentially using cofactor mode), applies the specified KDF
    /// (`self.kdf`) if needed, and creates the derived key object using the
    /// template.
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

        let mut pkey = privkey_from_object(key)?;
        let mut ecdh = EcdhDerive::new(osslctx(), &mut pkey)?;

        if self.mech == CKM_ECDH1_COFACTOR_DERIVE {
            ecdh.set_cofactor_mode(Some(true));
        }

        let factory =
            objfactories.get_obj_factory_from_key_template(template)?;

        let raw_max = (pkey.get_bits()? + 7) / 8;
        /* the raw ECDH results have length of bit field length */
        let keylen = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(a) => {
                let value_len = usize::try_from(a.to_ulong()?)?;
                if self.kdf == CKD_NULL && value_len > raw_max {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                value_len
            }
            None => {
                /* X9.63 does not have any maximum size */
                if self.kdf != CKD_NULL {
                    return Err(CKR_TEMPLATE_INCONSISTENT)?;
                }
                match factory
                    .as_secret_key_factory()?
                    .recommend_key_size(raw_max)
                {
                    Ok(len) => len,
                    Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
                }
            }
        };

        /* these do not apply to the raw ECDH */
        match self.kdf {
            CKD_SHA1_KDF | CKD_SHA224_KDF | CKD_SHA256_KDF | CKD_SHA384_KDF
            | CKD_SHA512_KDF | CKD_SHA3_224_KDF | CKD_SHA3_256_KDF
            | CKD_SHA3_384_KDF | CKD_SHA3_512_KDF => {
                ecdh.set_x963_kdf_type(true);
                ecdh.set_digest(kdf_type_to_digest_alg(self.kdf)?);
                if let Some(ukm) = &self.shared {
                    ecdh.set_ukm(ukm.as_slice());
                }
                ecdh.set_outlen(keylen)?;
            }
            CKD_NULL => (),
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }

        let ec_point = {
            if self.public.len() > (2 * raw_max) + 1 {
                /* try to see if it is a DER encoded point */
                match asn1::parse_single::<&[u8]>(self.public.as_slice()) {
                    Ok(pt) => Cow::Owned(pt.to_vec()),
                    Err(_) => return Err(CKR_MECHANISM_PARAM_INVALID)?,
                }
            } else {
                Cow::Borrowed(&self.public)
            }
        };

        let mut secret = vec![0u8; keylen];
        let outlen = ecdh.derive(
            &mut make_peer_key(key, &ec_point)?,
            secret.as_mut_slice(),
        )?;

        if outlen < keylen {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_vec(CKA_VALUE, secret)?;
        tmpl.zeroize = true;
        let mut obj = factory.create(tmpl.as_slice())?;

        default_key_attributes(&mut obj, self.mech)?;
        Ok(vec![obj])
    }
}

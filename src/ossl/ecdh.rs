// Copyright 2023 - 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use core::ffi::{c_char, c_int, c_uint};
use std::borrow::Cow;

use crate::attribute::CkAttrs;
use crate::error::Result;
use crate::interface::*;
use crate::mechanism::*;
use crate::misc::bytes_to_vec;
use crate::object::{default_key_attributes, Object, ObjectFactories};
use crate::ossl::bindings::*;
use crate::ossl::common::*;

fn kdf_type_to_hash_mech(mech: CK_EC_KDF_TYPE) -> Result<CK_MECHANISM_TYPE> {
    match mech {
        CKD_SHA1_KDF => Ok(CKM_SHA_1),
        CKD_SHA224_KDF => Ok(CKM_SHA224),
        CKD_SHA256_KDF => Ok(CKM_SHA256),
        CKD_SHA384_KDF => Ok(CKM_SHA384),
        CKD_SHA512_KDF => Ok(CKM_SHA512),
        CKD_SHA3_224_KDF => Ok(CKM_SHA3_224),
        CKD_SHA3_256_KDF => Ok(CKM_SHA3_256),
        CKD_SHA3_384_KDF => Ok(CKM_SHA3_384),
        CKD_SHA3_512_KDF => Ok(CKM_SHA3_512),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }
}

fn make_peer_key(key: &Object, ec_point: &Vec<u8>) -> Result<EvpPkey> {
    let mut params = OsslParam::with_capacity(2);
    params.zeroize = true;

    let name = match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        #[cfg(feature = "ecdsa")]
        CKK_EC => {
            params.add_const_c_string(
                name_as_char(OSSL_PKEY_PARAM_GROUP_NAME),
                name_as_char(get_ossl_name_from_obj(key)?),
            )?;
            EC_NAME
        }
        #[cfg(feature = "ec_montgomery")]
        CKK_EC_MONTGOMERY => get_ossl_name_from_obj(key)?,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
    };

    params.add_octet_string(name_as_char(OSSL_PKEY_PARAM_PUB_KEY), ec_point)?;
    params.finalize();

    EvpPkey::fromdata(name_as_char(name), EVP_PKEY_PUBLIC_KEY, &params)
}

#[derive(Debug)]
pub struct ECDHOperation {
    mech: CK_MECHANISM_TYPE,
    kdf: CK_EC_KDF_TYPE,
    public: Vec<u8>,
    shared: Vec<u8>,
    finalized: bool,
}

impl ECDHOperation {
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

        Ok(ECDHOperation {
            finalized: false,
            mech: mechanism,
            kdf: params.kdf,
            shared: bytes_to_vec!(params.pSharedData, params.ulSharedDataLen),
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

        let mode: c_int = if self.mech == CKM_ECDH1_COFACTOR_DERIVE {
            1
        } else {
            -1
        };
        let outlen: c_uint;

        let mut pkey = EvpPkey::privkey_from_object(key)?;

        let mut params = OsslParam::with_capacity(5);
        params.zeroize = true;
        params.add_int(
            name_as_char(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE),
            &mode,
        )?;

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
                params.add_const_c_string(
                    name_as_char(OSSL_EXCHANGE_PARAM_KDF_TYPE),
                    OSSL_KDF_NAME_X963KDF.as_ptr() as *const c_char,
                )?;
                params.add_const_c_string(
                    name_as_char(OSSL_EXCHANGE_PARAM_KDF_DIGEST),
                    mech_type_to_digest_name(kdf_type_to_hash_mech(self.kdf)?),
                )?;
                if self.shared.len() > 0 {
                    params.add_octet_string(
                        name_as_char(OSSL_EXCHANGE_PARAM_KDF_UKM),
                        &self.shared,
                    )?;
                }
                outlen = c_uint::try_from(keylen)?;
                params.add_uint(
                    name_as_char(OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
                    &outlen,
                )?;
            }
            CKD_NULL => (),
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }

        params.finalize();

        let mut ctx = pkey.new_ctx()?;
        let res = unsafe {
            EVP_PKEY_derive_init_ex(ctx.as_mut_ptr(), params.as_ptr())
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
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

        /* Import peer key */
        let mut peer = make_peer_key(key, &ec_point)?;

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
        if secret_len < keylen {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        let mut secret = vec![0u8; secret_len];
        let res = unsafe {
            EVP_PKEY_derive(
                ctx.as_mut_ptr(),
                secret.as_mut_ptr(),
                &mut secret_len,
            )
        };
        if res != 1 {
            return Err(CKR_DEVICE_ERROR)?;
        }

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_owned_slice(CKA_VALUE, &secret[(secret_len - keylen)..])?;
        tmpl.zeroize = true;
        let mut obj = factory.create(tmpl.as_slice())?;

        default_key_attributes(&mut obj, self.mech)?;
        Ok(vec![obj])
    }
}

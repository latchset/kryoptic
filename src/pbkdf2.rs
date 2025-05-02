// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanisms for the Password Based Key
//! Derivation Function v2 as defined in [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018)
//! Section 5.2

use std::fmt::Debug;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::hmac;
use crate::interface::*;
use crate::mechanism::{Mechanism, Mechanisms};
use crate::misc::{bytes_to_vec, cast_params};
use crate::object::{default_key_attributes, Object, ObjectFactories};

#[cfg(not(feature = "fips"))]
use crate::native::pbkdf2::pbkdf2_derive;

#[cfg(feature = "fips")]
use crate::ossl::pbkdf2::pbkdf2_derive;

pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    PBKDF2Mechanism::register_mechanisms(mechs);
}

#[derive(Debug)]
struct PBKDF2Mechanism {
    info: CK_MECHANISM_INFO,
}

impl PBKDF2Mechanism {
    fn register_mechanisms(mechs: &mut Mechanisms) {
        mechs.add_mechanism(
            CKM_PKCS5_PBKD2,
            Box::new(PBKDF2Mechanism {
                info: CK_MECHANISM_INFO {
                    ulMinKeySize: 0,
                    ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
                    flags: CKF_GENERATE,
                },
            }),
        );
    }

    fn mock_password_object(&self, key: Vec<u8>) -> Result<Object> {
        let mut obj = Object::new();
        obj.set_zeroize();
        obj.set_attr(Attribute::from_ulong(CKA_CLASS, CKO_SECRET_KEY))?;
        obj.set_attr(Attribute::from_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET))?;
        obj.set_attr(Attribute::from_ulong(
            CKA_VALUE_LEN,
            CK_ULONG::try_from(key.len())?,
        ))?;
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, key))?;
        obj.set_attr(Attribute::from_bool(CKA_DERIVE, true))?;
        Ok(obj)
    }
}

/* PKCS#11 in their infinite wisdom decided to implement this
 * derivation as a mechanism key gen operation.
 * Key Gen in Kryoptic does not go through an Operation trait,
 * but we still want to be able to do both openssl and native
 * backends, so we encapsulate the derivation function in a
 * small function and make implementations in the relevant
 * files for FIPS/non-FIPS */

impl Mechanism for PBKDF2Mechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn generate_key(
        &self,
        mech: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Object> {
        if self.info.flags & CKF_GENERATE != CKF_GENERATE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        if mech.mechanism != CKM_PKCS5_PBKD2 {
            return Err(CKR_MECHANISM_INVALID)?;
        }

        let params = cast_params!(mech, CK_PKCS5_PBKD2_PARAMS2);

        /* all the mechanism we support require this,
         * if we ever add GOST support we'll have to add data */
        if params.pPrfData != std::ptr::null_mut() || params.ulPrfDataLen != 0 {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }

        let prf = match params.prf {
            CKP_PKCS5_PBKD2_HMAC_SHA1 => CKM_SHA_1_HMAC,
            CKP_PKCS5_PBKD2_HMAC_SHA224 => CKM_SHA224_HMAC,
            CKP_PKCS5_PBKD2_HMAC_SHA256 => CKM_SHA256_HMAC,
            CKP_PKCS5_PBKD2_HMAC_SHA384 => CKM_SHA384_HMAC,
            CKP_PKCS5_PBKD2_HMAC_SHA512 => CKM_SHA512_HMAC,
            CKP_PKCS5_PBKD2_HMAC_SHA512_224 => CKM_SHA512_224_HMAC,
            CKP_PKCS5_PBKD2_HMAC_SHA512_256 => CKM_SHA512_256_HMAC,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };
        let pass = self.mock_password_object(bytes_to_vec!(
            params.pPassword,
            params.ulPasswordLen
        ))?;
        let salt = match params.saltSource {
            CKZ_SALT_SPECIFIED => {
                if params.pSaltSourceData == std::ptr::null_mut()
                    || params.ulSaltSourceDataLen == 0
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                bytes_to_vec!(
                    params.pSaltSourceData,
                    params.ulSaltSourceDataLen
                )
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };
        let iter = usize::try_from(params.iterations)?;

        /* check early that we have key class and type defined */
        let factory =
            objfactories.get_obj_factory_from_key_template(template)?;

        let keylen = match template.iter().find(|x| x.type_ == CKA_VALUE_LEN) {
            Some(a) => usize::try_from(a.to_ulong()?)?,
            None => {
                let max = hmac::hmac_size(prf);
                if max == usize::try_from(CK_UNAVAILABLE_INFORMATION)? {
                    return Err(CKR_MECHANISM_INVALID)?;
                }
                match factory.as_secret_key_factory()?.recommend_key_size(max) {
                    Ok(len) => len,
                    Err(_) => return Err(CKR_TEMPLATE_INCONSISTENT)?,
                }
            }
        };

        let dkm = pbkdf2_derive(mechanisms, prf, &pass, &salt, iter, keylen)?;

        let mut tmpl = CkAttrs::from(template);
        tmpl.add_vec(CKA_VALUE, dkm)?;
        tmpl.zeroize = true;

        let mut key = factory.create(tmpl.as_slice())?;
        default_key_attributes(&mut key, mech.mechanism)?;
        Ok(key)
    }
}

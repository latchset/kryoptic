// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use core::ffi::c_int;
use std::fmt::Debug;

use crate::attribute::from_bytes;
use crate::error::Result;
use crate::hash::INVALID_HASH_SIZE;
use crate::hmac::hmac_size;
use crate::interface::*;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc;
use crate::object::{Object, ObjectFactories};
use crate::ossl::bindings::*;
use crate::ossl::common::*;
#[cfg(feature = "fips")]
use crate::ossl::fips::*;
use crate::{bytes_to_slice, cast_params};

#[derive(Debug)]
pub struct HKDFOperation {
    mech: CK_MECHANISM_TYPE,
    finalized: bool,
    extract: bool,
    expand: bool,
    prf: CK_MECHANISM_TYPE,
    prflen: usize,
    salt_type: CK_ULONG,
    salt_key: [CK_OBJECT_HANDLE; 1],
    salt: Vec<u8>,
    info: Vec<u8>,
    emit_data_obj: bool,
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl HKDFOperation {
    fn verify_key(&self, key: &Object, matchlen: usize) -> Result<()> {
        if let Ok(class) = key.get_attr_as_ulong(CKA_CLASS) {
            match class {
                CKO_SECRET_KEY => {
                    if let Ok(kt) = key.get_attr_as_ulong(CKA_KEY_TYPE) {
                        match kt {
                            CKK_GENERIC_SECRET | CKK_HKDF => key
                                .check_key_ops(
                                    CKO_SECRET_KEY,
                                    CK_UNAVAILABLE_INFORMATION,
                                    CKA_DERIVE,
                                )?,
                            _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
                        }
                    } else {
                        return Err(CKR_KEY_TYPE_INCONSISTENT)?;
                    }
                }
                CKO_DATA => {
                    /* HKDF also allow a DATA object as input key ... */
                    if !self.extract
                        || self.salt_type == CKF_HKDF_SALT_NULL
                        || self.salt.len() == 0
                    {
                        return Err(CKR_MECHANISM_PARAM_INVALID)?;
                    }
                }
                _ => return Err(CKR_KEY_HANDLE_INVALID)?,
            }
        } else {
            return Err(CKR_KEY_HANDLE_INVALID)?;
        }

        if matchlen > 0 {
            let keylen = match key.get_attr_as_ulong(CKA_VALUE_LEN) {
                Ok(len) => usize::try_from(len)?,
                Err(_) => match key.get_attr_as_bytes(CKA_VALUE) {
                    Ok(v) => v.len(),
                    Err(_) => 0,
                },
            };
            if keylen == 0 {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
        }

        Ok(())
    }

    pub fn new(mech: &CK_MECHANISM) -> Result<HKDFOperation> {
        let params = cast_params!(mech, CK_HKDF_PARAMS);
        if params.bExtract == CK_FALSE && params.bExpand == CK_FALSE {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        if params.bExtract != CK_FALSE
            && params.ulSaltLen > 0
            && params.pSalt == std::ptr::null_mut()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        if params.bExpand != CK_FALSE
            && params.ulInfoLen > 0
            && params.pInfo == std::ptr::null_mut()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let hmaclen = match hmac_size(params.prfHashMechanism) {
            INVALID_HASH_SIZE => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            x => x,
        };
        let salt = match params.ulSaltType {
            CKF_HKDF_SALT_NULL => {
                if params.ulSaltLen > 0 || params.pSalt != std::ptr::null_mut()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    vec![0u8; hmaclen]
                }
            }
            CKF_HKDF_SALT_DATA => {
                if params.ulSaltLen == 0 || params.pSalt == std::ptr::null_mut()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    bytes_to_slice!(params.pSalt, params.ulSaltLen, u8).to_vec()
                }
            }
            CKF_HKDF_SALT_KEY => {
                /* a len of 0 indicates a key object is needed.
                 * the salt must be set via [requires/receives]_objects()
                 * if not derive() will error */
                Vec::new()
            }
            _ => {
                if params.bExtract != CK_FALSE {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    Vec::new()
                }
            }
        };

        Ok(HKDFOperation {
            mech: mech.mechanism,
            finalized: false,
            extract: params.bExtract != CK_FALSE,
            expand: params.bExpand != CK_FALSE,
            prf: params.prfHashMechanism,
            prflen: hmaclen,
            salt_type: params.ulSaltType,
            salt_key: [params.hSaltKey],
            salt: salt,
            info: bytes_to_slice!(params.pInfo, params.ulInfoLen, u8).to_vec(),
            emit_data_obj: mech.mechanism == CKM_HKDF_DATA,
            #[cfg(feature = "fips")]
            fips_approved: None,
        })
    }
}

impl MechOperation for HKDFOperation {
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
    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if self.salt_type == CKF_HKDF_SALT_KEY {
            return Ok(&self.salt_key);
        } else {
            /* we are good, no need to even send a vector */
            return Err(CKR_OK)?;
        }
    }
    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if objs.len() != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.verify_key(objs[0], 0)?;
        if let Ok(salt) = objs[0].get_attr_as_bytes(CKA_VALUE) {
            self.salt.clone_from(salt);
            Ok(())
        } else {
            Err(CKR_KEY_HANDLE_INVALID)?
        }
    }
}
impl Derive for HKDFOperation {
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

        self.verify_key(key, self.prflen)?;

        if self.salt.len() == 0 && self.extract {
            match self.salt_type {
                CKF_HKDF_SALT_KEY => return Err(CKR_GENERAL_ERROR)?,
                _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
            }
        }

        let (mut obj, keysize) = if self.emit_data_obj {
            misc::common_derive_data_object(template, objfactories, self.prflen)
        } else {
            misc::common_derive_key_object(
                key,
                template,
                objfactories,
                self.prflen,
            )
        }?;

        if !self.expand && keysize != self.prflen {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if keysize == 0 || keysize > usize::try_from(u32::MAX)? {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let mode = if self.extract {
            if self.expand {
                c_int::try_from(EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND)?
            } else {
                c_int::try_from(EVP_KDF_HKDF_MODE_EXTRACT_ONLY)?
            }
        } else {
            c_int::try_from(EVP_KDF_HKDF_MODE_EXPAND_ONLY)?
        };

        let mut params = OsslParam::with_capacity(5);
        params.zeroize = true;
        params.add_octet_string(
            name_as_char(OSSL_KDF_PARAM_KEY),
            key.get_attr_as_bytes(CKA_VALUE)?,
        )?;
        params.add_const_c_string(
            name_as_char(OSSL_KDF_PARAM_DIGEST),
            mech_type_to_digest_name(self.prf),
        )?;
        params.add_int(name_as_char(OSSL_KDF_PARAM_MODE), &mode)?;

        if self.extract && self.salt.len() > 0 {
            params.add_octet_string(
                name_as_char(OSSL_KDF_PARAM_SALT),
                &self.salt,
            )?;
        }

        if self.info.len() > 0 {
            params.add_octet_string(
                name_as_char(OSSL_KDF_PARAM_INFO),
                &self.info,
            )?;
        }
        params.finalize();

        let mut kctx = EvpKdfCtx::new(name_as_char(OSSL_KDF_NAME_HKDF))?;
        let mut dkm = vec![0u8; keysize];
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
        {
            self.fips_approved = check_kdf_fips_indicators(&mut kctx)?;
        }

        obj.set_attr(from_bytes(CKA_VALUE, dkm))?;

        Ok(vec![obj])
    }
}

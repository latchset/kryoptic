// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

//! This module implements the HMAC-based Key Derivation Function (HKDF)
//! mechanism (CKM_HKDF) as specified in RFC 5869 and PKCS#11 v3.0+,
//! using the OpenSSL EVP_KDF interface.

use core::ffi::c_int;
use std::fmt::Debug;

use crate::attribute::Attribute;
use crate::error::Result;
use crate::hash::INVALID_HASH_SIZE;
use crate::hmac::hmac_size;
use crate::interface::*;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::*;
use crate::object::{Object, ObjectFactories};
use crate::ossl::bindings::*;
use crate::ossl::common::*;
#[cfg(feature = "fips")]
use crate::ossl::fips::*;

/// Represents an active HKDF operation state.
#[derive(Debug)]
pub struct HKDFOperation {
    /// The specific HKDF mechanism type (CKM_HKDF or CKM_HKDF_DATA).
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the derive operation has been completed.
    finalized: bool,
    /// Flag indicating if the extract phase should be performed.
    extract: bool,
    /// Flag indicating if the expand phase should be performed.
    expand: bool,
    /// The underlying PRF hash mechanism (e.g., CKM_SHA256).
    prf: CK_MECHANISM_TYPE,
    /// The output length of the PRF hash in bytes.
    prflen: usize,
    /// Type of salt provided (NULL, DATA, or KEY handle).
    salt_type: CK_ULONG,
    /// Key handle if salt type is CKF_HKDF_SALT_KEY.
    salt_key: [CK_OBJECT_HANDLE; 1],
    /// Salt data (either provided directly or loaded from salt_key).
    salt: Vec<u8>,
    /// Optional info/context data for the expand phase.
    info: Vec<u8>,
    /// Flag indicating if the output should be a CKO_DATA object.
    emit_data_obj: bool,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approved: Option<bool>,
}

impl HKDFOperation {
    /// Verifies if the input keying material (IKM) object is suitable.
    ///
    /// Allows CKO_SECRET_KEY (CKK_GENERIC_SECRET or CKK_HKDF) with
    /// CKA_DERIVE=true. Also allows CKO_DATA if salt is explicitly provided
    /// (not NULL or KEY). Optionally checks if the key length matches an
    /// expected length (`matchlen`).
    fn verify_key(&self, key: &Object, matchlen: usize) -> Result<()> {
        match key.get_attr_as_ulong(CKA_CLASS) {
            Ok(class) => {
                match class {
                    CKO_SECRET_KEY => {
                        match key.get_attr_as_ulong(CKA_KEY_TYPE) {
                            Ok(kt) => match kt {
                                CKK_GENERIC_SECRET | CKK_HKDF => key
                                    .check_key_ops(
                                        CKO_SECRET_KEY,
                                        CK_UNAVAILABLE_INFORMATION,
                                        CKA_DERIVE,
                                    )?,
                                _ => return Err(CKR_KEY_TYPE_INCONSISTENT)?,
                            },
                            _ => {
                                return Err(CKR_KEY_TYPE_INCONSISTENT)?;
                            }
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
            }
            _ => {
                return Err(CKR_KEY_HANDLE_INVALID)?;
            }
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

    /// Creates a new `HKDFOperation` instance.
    ///
    /// Parses the `CK_HKDF_PARAMS` from the mechanism, validates them,
    /// determines the PRF length, and stores the initial state.
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
        match objs[0].get_attr_as_bytes(CKA_VALUE) {
            Ok(salt) => {
                self.salt.clone_from(salt);
                Ok(())
            }
            _ => Err(CKR_KEY_HANDLE_INVALID)?,
        }
    }
}
impl Derive for HKDFOperation {
    /// Performs the HKDF key derivation (Extract and/or Expand phases).
    ///
    /// Verifies the input keying material (`key`) and salt (if needed).
    /// Sets up and executes the OpenSSL `EVP_KDF_derive` function with the
    /// appropriate HKDF parameters. Creates the derived key or data object.
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
            common_derive_data_object(template, objfactories, self.prflen)
        } else {
            common_derive_key_object(key, template, objfactories, self.prflen)
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

        #[cfg(feature = "fips")]
        fips_approval_prep_check();

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
        fips_approval_finalize(&mut self.fips_approved);

        obj.set_attr(Attribute::from_bytes(CKA_VALUE, dkm))?;

        Ok(vec![obj])
    }
}

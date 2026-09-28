// Copyright 2026
// See LICENSE.txt file for terms

//! This module implements the HMAC-based Key Derivation Function (HKDF)
//! mechanism (CKM_HKDF) as specified in RFC 5869 and PKCS#11 v3.0+,
//! using AWS-LC's classic `HKDF`/`HKDF_extract`/`HKDF_expand` API (via
//! `awslc::hkdf::HkdfDerive`). Mirrors `crate::ossl::hkdf`.

use crate::attribute::Attribute;
use crate::awslc::common::mech_type_to_digest_alg;
use crate::error::Result;
use crate::hash::INVALID_HASH_SIZE;
use crate::hmac::hmac_size;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::{
    bytes_to_slice, bytes_to_vec, common_derive_data_object,
    common_derive_key_object,
};
use crate::object::{Object, ObjectFactories};
use crate::pkcs11::*;

use crate::lowlevel::hkdf::{HkdfDerive, HkdfMode};

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

/// Represents an active HKDF operation state.
#[derive(Debug)]
pub struct HKDFOperation {
    /// The specific HKDF mechanism type (CKM_HKDF or CKM_HKDF_DATA).
    mech: CK_MECHANISM_TYPE,
    /// Flag indicating if the derive operation has been completed.
    finalized: bool,
    /// Selected HKDF mode
    mode: HkdfMode,
    /// The underlying PRF hash mechanism (e.g., CKM_SHA256).
    prf: CK_MECHANISM_TYPE,
    /// The output length of the PRF hash in bytes.
    prflen: usize,
    /// Type of salt provided (NULL, DATA, or KEY handle).
    salt_type: CK_ULONG,
    /// Key handle if salt type is CKF_HKDF_SALT_KEY.
    salt_key: [CK_OBJECT_HANDLE; 1],
    /// Salt data (either provided directly or loaded from salt_key).
    salt: Option<Vec<u8>>,
    /// Optional info/context data for the expand phase.
    info: Option<&'static [u8]>, /* FIXME: static -> a */
    /// Flag indicating if the output should be a CKO_DATA object.
    emit_data_obj: bool,
    /// FIPS approval status for the operation.
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
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
                        if self.mode == HkdfMode::ExpandOnly
                            || self.salt_type == CKF_HKDF_SALT_NULL
                            || self.salt.is_none()
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
        let params = mech.get_parameters::<CK_HKDF_PARAMS>()?;
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
                    Some(vec![0u8; hmaclen])
                }
            }
            CKF_HKDF_SALT_DATA => {
                if params.ulSaltLen == 0 || params.pSalt == std::ptr::null_mut()
                {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    Some(bytes_to_vec(params.pSalt, params.ulSaltLen as usize))
                }
            }
            CKF_HKDF_SALT_KEY => {
                /* will have to be provided later via calls to
                 * `MechOperation::receives_objects` */
                None
            }
            _ => {
                if params.bExtract != CK_FALSE {
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                } else {
                    None
                }
            }
        };

        Ok(HKDFOperation {
            mech: mech.mechanism,
            finalized: false,
            mode: if params.bExtract == CK_TRUE {
                if params.bExpand == CK_TRUE {
                    HkdfMode::ExtractAndExpand
                } else {
                    HkdfMode::ExtractOnly
                }
            } else {
                HkdfMode::ExpandOnly
            },
            prf: params.prfHashMechanism,
            prflen: hmaclen,
            salt_type: params.ulSaltType,
            salt_key: [params.hSaltKey],
            salt: salt,
            info: if params.ulInfoLen > 0 {
                Some(bytes_to_slice(
                    params.pInfo as *const u8,
                    params.ulInfoLen as usize,
                ))
            } else {
                None
            },
            emit_data_obj: mech.mechanism == CKM_HKDF_DATA,
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
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
        self.fips_approval.approval()
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
                self.salt = Some(salt.clone());
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
    /// Sets up and executes AWS-LC's classic HKDF API with the appropriate
    /// HKDF parameters. Creates the derived key or data object.
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

        if self.salt.is_none() && self.mode != HkdfMode::ExpandOnly {
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

        if self.mode == HkdfMode::ExtractOnly && keysize != self.prflen {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        if keysize == 0 || keysize > usize::try_from(u32::MAX)? {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let mut kdf = HkdfDerive::new(mech_type_to_digest_alg(self.prf)?)?;
        kdf.set_mode(self.mode);
        kdf.set_key(key.get_attr_as_bytes(CKA_VALUE)?.as_slice());
        if let Some(s) = &self.salt {
            kdf.set_salt(s);
        }
        if let Some(i) = &self.info {
            kdf.set_info(i);
        }

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut dkm = vec![0u8; keysize];
        kdf.derive(&mut dkm)?;

        #[cfg(feature = "fips")]
        self.fips_approval.finalize();

        obj.set_attr(Attribute::from_bytes(CKA_VALUE, dkm))?;

        Ok(vec![obj])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::CkAttrs;
    use crate::mechanism::{Mechanism, Mechanisms};
    use crate::object::ObjectFactories;

    // RFC 5869 Test Case 1 (SHA-256) -- same vector used at the
    // `awslc/src/hkdf.rs` primitive layer; reused here to
    // cross-check that the full `Mechanism`/`Derive` trait dispatch (this
    // file's `HKDFOperation`, `CK_HKDF_PARAMS` parsing, object
    // construction) wires the primitive correctly end to end, not just
    // that it returns *some* bytes.
    const IKM: [u8; 22] = [0x0b; 22];
    const SALT: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c,
    ];
    const INFO: [u8; 10] =
        [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    const EXPECTED_PRK: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d,
        0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    ];
    const EXPECTED_OKM: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
        0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
        0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    fn no_param_mech(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        }
    }

    /// Registers the real, backend-agnostic HKDF mechanisms/factories
    /// (`crate::hkdf::register`, untouched by this task) plus the generic
    /// object factory registrations (`crate::object::factory::register`)
    /// needed to generate IKM/salt key objects and to build the derived
    /// CKO_SECRET_KEY/CKO_DATA output objects -- exactly as production
    /// `C_Initialize`/`C_DeriveKey` reach them, and via the exact same
    /// `crate::ossl::hkdf::HKDFOperation` path `src/hkdf.rs` uses (which,
    /// under the `awslc` feature, resolves via `use awslc as ossl;` in
    /// `src/lib.rs` to this file's `HKDFOperation`).
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::object::factory::register(&mut mechs, &mut ot);
        crate::hkdf::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

    /// Builds a `CKO_SECRET_KEY`/`CKK_GENERIC_SECRET` object holding
    /// exactly `value` as `CKA_VALUE`, importing (via the real
    /// `ObjectFactories::create` dispatch, matching how `C_CreateObject`
    /// reaches the same factory) rather than generating so the exact
    /// RFC 5869 test vectors can be used as key material.
    fn import_secret(ot: &ObjectFactories, value: &[u8]) -> Object {
        let mut tmpl = CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_SECRET_KEY).unwrap();
        tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
            .unwrap();
        tmpl.add_owned_slice(CKA_VALUE, value).unwrap();
        tmpl.add_owned_bool(CKA_DERIVE, CK_TRUE).unwrap();
        tmpl.add_owned_bool(CKA_EXTRACTABLE, CK_TRUE).unwrap();
        tmpl.add_owned_bool(CKA_SENSITIVE, CK_FALSE).unwrap();
        ot.create(tmpl.as_slice()).unwrap()
    }

    fn derive_secret_template(value_len: usize) -> CkAttrs<'static> {
        let mut tmpl = CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_SECRET_KEY).unwrap();
        tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
            .unwrap();
        tmpl.add_owned_ulong(CKA_VALUE_LEN, value_len as CK_ULONG)
            .unwrap();
        tmpl.add_owned_bool(CKA_SENSITIVE, CK_FALSE).unwrap();
        tmpl.add_owned_bool(CKA_EXTRACTABLE, CK_TRUE).unwrap();
        tmpl
    }

    fn data_template(value_len: usize) -> CkAttrs<'static> {
        let mut tmpl = CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_DATA).unwrap();
        tmpl.add_owned_ulong(CKA_VALUE_LEN, value_len as CK_ULONG)
            .unwrap();
        tmpl
    }

    /// Full round trip through the real `Mechanisms::get(CKM_HKDF_DERIVE)`
    /// -> `derive_operation` -> `Derive::derive` path (not just the
    /// `awslc::hkdf` primitive layer), matching RFC 5869 Test Case 1
    /// exactly -- both the salt and info are supplied as `CKF_HKDF_SALT_
    /// DATA`/`pInfo`, and the mode is Extract-and-Expand (the common
    /// case), producing a `CKO_SECRET_KEY`.
    #[test]
    fn extract_and_expand_matches_rfc5869_and_emits_secret_key() {
        let (mechs, ot) = registered();
        let ikm = import_secret(&ot, &IKM);

        let params = CK_HKDF_PARAMS {
            bExtract: CK_TRUE,
            bExpand: CK_TRUE,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_DATA,
            pSalt: SALT.as_ptr() as *mut u8,
            ulSaltLen: SALT.len() as CK_ULONG,
            hSaltKey: CK_INVALID_HANDLE,
            pInfo: INFO.as_ptr() as *mut u8,
            ulInfoLen: INFO.len() as CK_ULONG,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_HKDF_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };

        let entry = mechs.get(CKM_HKDF_DERIVE).unwrap();
        let mut op = entry.derive_operation(&mech).unwrap();

        let tmpl = derive_secret_template(EXPECTED_OKM.len());
        let objs = op.derive(&ikm, tmpl.as_slice(), &mechs, &ot).unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(
            objs[0].get_attr_as_ulong(CKA_CLASS).unwrap(),
            CKO_SECRET_KEY
        );
        assert_eq!(
            objs[0].get_attr_as_bytes(CKA_VALUE).unwrap().as_slice(),
            &EXPECTED_OKM[..]
        );

        // finalized: a second derive() call must fail
        let err = op.derive(&ikm, tmpl.as_slice(), &mechs, &ot).unwrap_err();
        assert_eq!(err.rv(), CKR_OPERATION_NOT_INITIALIZED);
    }

    /// `CKM_HKDF_DATA` performs the identical derivation as `CKM_HKDF_
    /// DERIVE` but must emit a `CKO_DATA` object instead of a
    /// `CKO_SECRET_KEY` -- exercises `emit_data_obj`/`common_derive_data_
    /// object`.
    #[test]
    fn hkdf_data_matches_rfc5869_and_emits_data_object() {
        let (mechs, ot) = registered();
        let ikm = import_secret(&ot, &IKM);

        let params = CK_HKDF_PARAMS {
            bExtract: CK_TRUE,
            bExpand: CK_TRUE,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_DATA,
            pSalt: SALT.as_ptr() as *mut u8,
            ulSaltLen: SALT.len() as CK_ULONG,
            hSaltKey: CK_INVALID_HANDLE,
            pInfo: INFO.as_ptr() as *mut u8,
            ulInfoLen: INFO.len() as CK_ULONG,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_HKDF_DATA,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };

        let entry = mechs.get(CKM_HKDF_DATA).unwrap();
        let mut op = entry.derive_operation(&mech).unwrap();

        let tmpl = data_template(EXPECTED_OKM.len());
        let objs = op.derive(&ikm, tmpl.as_slice(), &mechs, &ot).unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].get_attr_as_ulong(CKA_CLASS).unwrap(), CKO_DATA);
        assert_eq!(
            objs[0].get_attr_as_bytes(CKA_VALUE).unwrap().as_slice(),
            &EXPECTED_OKM[..]
        );
    }

    /// Extract-only mode (`bExtract=true, bExpand=false`) must produce
    /// exactly the RFC 5869 PRK, and the output length is pinned to the
    /// PRF's own output size regardless of any `CKA_VALUE_LEN` requested
    /// (`HkdfMode::ExtractOnly && keysize != self.prflen` check).
    #[test]
    fn extract_only_matches_rfc5869_prk() {
        let (mechs, ot) = registered();
        let ikm = import_secret(&ot, &IKM);

        let params = CK_HKDF_PARAMS {
            bExtract: CK_TRUE,
            bExpand: CK_FALSE,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_DATA,
            pSalt: SALT.as_ptr() as *mut u8,
            ulSaltLen: SALT.len() as CK_ULONG,
            hSaltKey: CK_INVALID_HANDLE,
            pInfo: std::ptr::null_mut(),
            ulInfoLen: 0,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_HKDF_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };

        let entry = mechs.get(CKM_HKDF_DERIVE).unwrap();
        let mut op = entry.derive_operation(&mech).unwrap();

        // No CKA_VALUE_LEN (but CKA_CLASS/CKA_KEY_TYPE are still required
        // by `ObjectFactories::derive_key_from_template`): falls back to
        // the PRF's own length (32).
        let mut tmpl = CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_SECRET_KEY).unwrap();
        tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
            .unwrap();
        tmpl.add_owned_bool(CKA_SENSITIVE, CK_FALSE).unwrap();
        tmpl.add_owned_bool(CKA_EXTRACTABLE, CK_TRUE).unwrap();
        let objs = op.derive(&ikm, tmpl.as_slice(), &mechs, &ot).unwrap();
        assert_eq!(
            objs[0].get_attr_as_bytes(CKA_VALUE).unwrap().as_slice(),
            &EXPECTED_PRK[..]
        );

        // A mismatched CKA_VALUE_LEN must be rejected in Extract-only mode.
        let (mechs2, ot2) = registered();
        let ikm2 = import_secret(&ot2, &IKM);
        let mut op2 = mechs2
            .get(CKM_HKDF_DERIVE)
            .unwrap()
            .derive_operation(&mech)
            .unwrap();
        let bad_tmpl = derive_secret_template(16);
        let err = op2
            .derive(&ikm2, bad_tmpl.as_slice(), &mechs2, &ot2)
            .unwrap_err();
        assert_eq!(err.rv(), CKR_TEMPLATE_INCONSISTENT);
    }

    /// Expand-only mode (`bExtract=false, bExpand=true`) starting from the
    /// RFC 5869 PRK as the input key must reproduce the RFC 5869 OKM.
    #[test]
    fn expand_only_matches_rfc5869_okm() {
        let (mechs, ot) = registered();
        let prk = import_secret(&ot, &EXPECTED_PRK);

        let params = CK_HKDF_PARAMS {
            bExtract: CK_FALSE,
            bExpand: CK_TRUE,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_NULL,
            pSalt: std::ptr::null_mut(),
            ulSaltLen: 0,
            hSaltKey: CK_INVALID_HANDLE,
            pInfo: INFO.as_ptr() as *mut u8,
            ulInfoLen: INFO.len() as CK_ULONG,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_HKDF_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };

        let entry = mechs.get(CKM_HKDF_DERIVE).unwrap();
        let mut op = entry.derive_operation(&mech).unwrap();

        let tmpl = derive_secret_template(EXPECTED_OKM.len());
        let objs = op.derive(&prk, tmpl.as_slice(), &mechs, &ot).unwrap();
        assert_eq!(
            objs[0].get_attr_as_bytes(CKA_VALUE).unwrap().as_slice(),
            &EXPECTED_OKM[..]
        );
    }

    /// `CKF_HKDF_SALT_KEY`: the salt isn't known at construction time --
    /// `HKDFOperation::new` must leave `self.salt == None` and report the
    /// salt key handle via `requires_objects`; the caller (in production,
    /// `Token`/`fn_derive_key`) is then responsible for resolving that
    /// handle to an `Object` and calling `receives_objects`, which must
    /// populate `self.salt` from the key's `CKA_VALUE` before `derive()`
    /// can proceed. This is the one part of the reference with real
    /// control-flow complexity, and is exercised directly (not through a
    /// full `TestToken`) so the `HKDFOperation`-level contract itself is
    /// pinned down.
    #[test]
    fn salt_via_key_handle_matches_rfc5869_and_requires_objects_first() {
        let (mechs, ot) = registered();
        let ikm = import_secret(&ot, &IKM);
        let salt_key = import_secret(&ot, &SALT);

        const FAKE_SALT_HANDLE: CK_OBJECT_HANDLE = 0xdead_beef;
        let params = CK_HKDF_PARAMS {
            bExtract: CK_TRUE,
            bExpand: CK_TRUE,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_KEY,
            pSalt: std::ptr::null_mut(),
            ulSaltLen: 0,
            hSaltKey: FAKE_SALT_HANDLE,
            pInfo: INFO.as_ptr() as *mut u8,
            ulInfoLen: INFO.len() as CK_ULONG,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_HKDF_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };

        let entry = mechs.get(CKM_HKDF_DERIVE).unwrap();
        let mut op = entry.derive_operation(&mech).unwrap();

        // Before receives_objects: requires_objects must report exactly
        // the salt key handle from CK_HKDF_PARAMS::hSaltKey.
        assert_eq!(op.requires_objects().unwrap(), &[FAKE_SALT_HANDLE]);

        // Attempting to derive before the salt has been supplied must
        // fail (CKR_GENERAL_ERROR per HKDFOperation::derive's
        // CKF_HKDF_SALT_KEY branch), not silently treat salt as empty.
        let tmpl = derive_secret_template(EXPECTED_OKM.len());
        let premature =
            op.derive(&ikm, tmpl.as_slice(), &mechs, &ot).unwrap_err();
        assert_eq!(premature.rv(), CKR_GENERAL_ERROR);

        // A fresh operation, this time properly supplying the salt object
        // via receives_objects before deriving.
        let mut op = mechs
            .get(CKM_HKDF_DERIVE)
            .unwrap()
            .derive_operation(&mech)
            .unwrap();
        op.receives_objects(&[&salt_key]).unwrap();

        let objs = op.derive(&ikm, tmpl.as_slice(), &mechs, &ot).unwrap();
        assert_eq!(
            objs[0].get_attr_as_bytes(CKA_VALUE).unwrap().as_slice(),
            &EXPECTED_OKM[..],
            "salt supplied via CKF_HKDF_SALT_KEY must produce the same \
             RFC 5869 OKM as the equivalent CKF_HKDF_SALT_DATA salt"
        );
    }

    /// A non-derive key object (e.g. missing CKA_DERIVE) supplied as the
    /// salt-key object via `receives_objects` must be rejected by
    /// `verify_key`, not silently accepted.
    #[test]
    fn salt_via_key_handle_rejects_non_derivable_salt_key() {
        let (mechs, ot) = registered();

        let mut tmpl = CkAttrs::new();
        tmpl.add_owned_ulong(CKA_CLASS, CKO_SECRET_KEY).unwrap();
        tmpl.add_owned_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
            .unwrap();
        tmpl.add_owned_slice(CKA_VALUE, &SALT).unwrap();
        tmpl.add_owned_bool(CKA_DERIVE, CK_FALSE).unwrap();
        tmpl.add_owned_bool(CKA_EXTRACTABLE, CK_TRUE).unwrap();
        tmpl.add_owned_bool(CKA_SENSITIVE, CK_FALSE).unwrap();
        let non_derivable = ot.create(tmpl.as_slice()).unwrap();

        let params = CK_HKDF_PARAMS {
            bExtract: CK_TRUE,
            bExpand: CK_TRUE,
            prfHashMechanism: CKM_SHA256,
            ulSaltType: CKF_HKDF_SALT_KEY,
            pSalt: std::ptr::null_mut(),
            ulSaltLen: 0,
            hSaltKey: 1,
            pInfo: std::ptr::null_mut(),
            ulInfoLen: 0,
        };
        let mech = CK_MECHANISM {
            mechanism: CKM_HKDF_DERIVE,
            pParameter: &params as *const _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
        };
        let mut op = mechs
            .get(CKM_HKDF_DERIVE)
            .unwrap()
            .derive_operation(&mech)
            .unwrap();

        let err = op.receives_objects(&[&non_derivable]).unwrap_err();
        assert_eq!(err.rv(), CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
}

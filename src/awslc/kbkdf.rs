// Copyright 2026
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 mechanism interface for the counter
//! mode of NIST SP 800-108's KBKDF, using AWS-LC's `KBKDF_ctr_hmac()`.
//! Mirrors `crate::ossl::kbkdf`'s `Sp800Operation`, with one deliberate
//! narrowing: `KBKDF_ctr_hmac()` hardcodes a 32-bit big-endian counter and
//! only supports HMAC as the PRF (see `awslc/src/kbkdf.rs`), unlike
//! `ossl-backend`'s OpenSSL KBKDF provider, which also supports 8/16/24-bit
//! counters and a CMAC PRF. Configurations outside AWS-LC's fixed layout
//! are rejected with `CKR_MECHANISM_PARAM_INVALID`, the same convention
//! `crate::ossl::kbkdf` already uses for its own OpenSSL-imposed
//! limitations (e.g. rejecting little-endian counters). Feedback mode
//! (`CKM_SP800_108_FEEDBACK_KDF`) has no AWS-LC primitive at all and is
//! rejected outright at operation-creation time, the same way this file's
//! dispatcher (`crate::sp800_108`) already rejects
//! `CKM_SP800_108_DOUBLE_PIPELINE_KDF`.
//!
//! Note: `crate::sp800_108`'s dispatcher chooses between this module and
//! `crate::native::sp800_108` based on the `fips` feature, not on which
//! backend (`ossl-backend`/`awslc`/`awslc-fips`) is active. Under plain
//! (non-FIPS) `awslc`, `fips` is off, so `crate::native::sp800_108` -- a
//! pure-Rust implementation -- is used instead, and everything in this
//! file goes entirely unreferenced (hence the compiler's own "never used"
//! warnings on its items in that configuration). This mirrors
//! `ossl-backend`'s pre-existing behavior and is not a bug.

use crate::attribute::Attribute;
use crate::awslc::common::mech_type_to_digest_alg;
use crate::error::Result;
use crate::mechanism::{Derive, MechOperation, Mechanisms};
use crate::misc::struct_to_slice;
use crate::object::{Object, ObjectFactories};
use crate::pkcs11::*;
use crate::sp800_108::{verify_prf_key, Sp800Params};

#[cfg(feature = "fips")]
use crate::fips::FipsApproval;

/// Builds the flat `info` buffer AWS-LC's `KBKDF_ctr_hmac()` expects,
/// assembling `Label || 0x00 (if separator used) || Context || [L] (if
/// used)` by hand -- exactly the fixed-input construction SP 800-108r1
/// §4.1 specifies following the (AWS-LC-internal, not part of this
/// buffer) 32-bit counter, and exactly what OpenSSL's KBKDF provider does
/// internally for `crate::ossl::kbkdf` via its separate salt/info/
/// use-separator/use-l parameters.
fn prep_counter_kdf(
    sparams: &Vec<Sp800Params>,
    out_len: usize,
) -> Result<Vec<u8>> {
    if sparams.len() < 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }

    /* Counter, [Label], [0x00], [Context], [Len] */
    match &sparams[0] {
        Sp800Params::Iteration(i) => {
            if !i.defined {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            if i.le {
                /* AWS-LC limitation: only big-endian */
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            if i.bits != 32 {
                /* AWS-LC limitation: KBKDF_ctr_hmac() hardcodes a
                 * 32-bit counter, unlike OpenSSL's KBKDF provider */
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
        }
        _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
    }

    let mut label: Option<&[u8]> = None;
    let mut separator = false;
    let mut context: Option<&[u8]> = None;
    let mut dkmlen = false;

    for idx in 1..sparams.len() {
        match &sparams[idx] {
            Sp800Params::ByteArray(v) => {
                if context.is_some() {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if separator {
                    /* separator set, this is a Context */
                    context = Some(v.as_slice());
                } else {
                    /* check if separator */
                    if v.len() == 1 && v[0] == 0 {
                        separator = true;
                    } else {
                        if label.is_some() {
                            /* label set and no separator, this is a
                             * Context */
                            context = Some(v.as_slice());
                        } else {
                            label = Some(v.as_slice());
                        }
                    }
                }
            }
            Sp800Params::DKMLength(v) => {
                if dkmlen {
                    /* already set, bail out */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                if v.le
                    || v.bits != 32
                    || v.method != CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS
                {
                    /* AWS-LC/OpenSSL limitations */
                    return Err(CKR_MECHANISM_PARAM_INVALID)?;
                }
                dkmlen = true;
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        }
    }

    let mut info = Vec::<u8>::new();
    if let Some(l) = label {
        info.extend_from_slice(l);
    }
    if separator {
        info.push(0u8);
    }
    if let Some(c) = context {
        info.extend_from_slice(c);
    }
    if dkmlen {
        let l_bits = u32::try_from(out_len)
            .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?
            .checked_mul(8)
            .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
        info.extend_from_slice(&l_bits.to_be_bytes());
    }
    Ok(info)
}

fn get_segment_size(
    mechanisms: &Mechanisms,
    hmac: CK_MECHANISM_TYPE,
) -> Result<usize> {
    let mech = CK_MECHANISM {
        mechanism: match hmac {
            CKM_SHA_1_HMAC => CKM_SHA_1,
            CKM_SHA224_HMAC => CKM_SHA224,
            CKM_SHA256_HMAC => CKM_SHA256,
            CKM_SHA384_HMAC => CKM_SHA384,
            CKM_SHA512_HMAC => CKM_SHA512,
            CKM_SHA3_224_HMAC => CKM_SHA3_224,
            CKM_SHA3_256_HMAC => CKM_SHA3_256,
            CKM_SHA3_384_HMAC => CKM_SHA3_384,
            CKM_SHA3_512_HMAC => CKM_SHA3_512,
            CKM_SHA512_224_HMAC => CKM_SHA512_224,
            CKM_SHA512_256_HMAC => CKM_SHA512_256,
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        },
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    mechanisms
        .get(mech.mechanism)?
        .digest_new(&mech)?
        .digest_len()
}

fn key_to_segment_size(key: usize, segment: usize) -> usize {
    ((key + segment - 1) / segment) * segment
}

#[derive(Debug)]
pub struct Sp800Operation {
    mech: CK_MECHANISM_TYPE,
    prf: CK_MECHANISM_TYPE,
    finalized: bool,
    params: Vec<Sp800Params>,
    addl_drv_keys: Vec<CK_DERIVED_KEY>,
    #[cfg(feature = "fips")]
    fips_approval: FipsApproval,
}

unsafe impl Send for Sp800Operation {}
unsafe impl Sync for Sp800Operation {}
impl Sp800Operation {
    pub fn counter_kdf_new(
        params: CK_SP800_108_KDF_PARAMS,
    ) -> Result<Sp800Operation> {
        let data_params = struct_to_slice(
            params.pDataParams as *const CK_PRF_DATA_PARAM,
            params.ulNumberOfDataParams as usize,
        )?;
        let addl_drv_keys = struct_to_slice(
            params.pAdditionalDerivedKeys as *const CK_DERIVED_KEY,
            params.ulAdditionalDerivedKeys as usize,
        )?;
        Ok(Sp800Operation {
            mech: CKM_SP800_108_COUNTER_KDF,
            prf: params.prfType,
            finalized: false,
            params: Sp800Params::parse_data_params(&data_params)?,
            addl_drv_keys: addl_drv_keys.to_vec(),
            #[cfg(feature = "fips")]
            fips_approval: FipsApproval::init(),
        })
    }

    pub fn feedback_kdf_new(
        _params: CK_SP800_108_FEEDBACK_KDF_PARAMS,
    ) -> Result<Sp800Operation> {
        /* AWS-LC has no feedback-mode KBKDF primitive at all -- rejected
         * here at operation-creation time, the same way this dispatcher
         * (crate::sp800_108) already rejects
         * CKM_SP800_108_DOUBLE_PIPELINE_KDF. */
        Err(CKR_MECHANISM_INVALID)?
    }
}

impl MechOperation for Sp800Operation {
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
}

impl Derive for Sp800Operation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        mechanisms: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        if self.finalized {
            return Err(CKR_OPERATION_NOT_INITIALIZED)?;
        }
        self.finalized = true;

        verify_prf_key(self.prf, key)?;

        let digest = match self.prf {
            #[cfg(not(feature = "no_sha1"))]
            CKM_SHA_1_HMAC => mech_type_to_digest_alg(self.prf)?,
            CKM_SHA224_HMAC | CKM_SHA256_HMAC | CKM_SHA384_HMAC
            | CKM_SHA512_HMAC | CKM_SHA512_224_HMAC | CKM_SHA512_256_HMAC
            | CKM_SHA3_224_HMAC | CKM_SHA3_256_HMAC | CKM_SHA3_384_HMAC
            | CKM_SHA3_512_HMAC => mech_type_to_digest_alg(self.prf)?,
            /* AWS-LC limitation: KBKDF_ctr_hmac() only supports HMAC,
             * unlike OpenSSL's KBKDF provider which also accepts a CMAC
             * PRF (CKM_AES_CMAC) -- rejected here along with any other
             * PRF this backend doesn't recognize. */
            _ => return Err(CKR_MECHANISM_PARAM_INVALID)?,
        };

        let mut segment = 1;
        if self.addl_drv_keys.len() > 0 {
            /* need the mechanism to compute the segment size as
             * KBKDF_ctr_hmac() will just return a linear buffer, that we
             * need to split in segments as the spec requires */
            segment = get_segment_size(mechanisms, self.prf)?;
        }

        let obj = objfactories.derive_key_from_template(key, template)?;
        let keysize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(size) => usize::try_from(size)?,
            Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
        };
        if keysize == 0 || keysize > usize::try_from(u32::MAX)? {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let mut keys =
            Vec::<Object>::with_capacity(1 + self.addl_drv_keys.len());
        keys.push(obj);

        let mut slen = key_to_segment_size(keysize, segment);

        /* additional keys */
        for ak in &self.addl_drv_keys {
            let tmpl = struct_to_slice(
                ak.pTemplate,
                usize::try_from(ak.ulAttributeCount)
                    .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
            )?;
            let obj = match objfactories.derive_key_from_template(key, &tmpl) {
                Ok(o) => o,
                Err(e) => {
                    /* mark the handle as invalid, unless the caller passed
                     * a null phKey (CK_DERIVED_KEY::phKey is a plain
                     * caller-supplied pointer, not validated by
                     * struct_to_slice, which only checks the outer array
                     * pointer -- writing through a null one here would be
                     * undefined behavior). */
                    if !ak.phKey.is_null() {
                        unsafe {
                            core::ptr::write(ak.phKey, CK_INVALID_HANDLE);
                        }
                    }
                    return Err(e);
                }
            };
            let aksize = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
                Ok(n) => usize::try_from(n)?,
                Err(_) => return Err(CKR_TEMPLATE_INCOMPLETE)?,
            };
            if aksize == 0 || aksize > usize::try_from(u32::MAX)? {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
            /* increment size in segment steps */
            slen += key_to_segment_size(aksize, segment);
            keys.push(obj);
        }

        /* Deliberately after derived-key-object creation above (unlike
         * crate::ossl::kbkdf's equivalent, which validates before creating
         * objects): AWS-LC's KBKDF_ctr_hmac() requires L (the total output
         * length) pre-embedded in the info buffer, and L is only known
         * once the derived key object(s) exist to report their sizes. */
        let info = prep_counter_kdf(&self.params, slen)?;
        let key_bytes = key.get_attr_as_bytes(CKA_VALUE)?.as_slice();

        #[cfg(feature = "fips")]
        self.fips_approval.clear();

        let mut dkm = vec![0u8; slen];
        crate::lowlevel::kbkdf::kbkdf_ctr_hmac(
            digest,
            key_bytes,
            info.as_slice(),
            &mut dkm,
        )?;

        #[cfg(feature = "fips")]
        self.fips_approval.update();

        let mut cursor = 0;
        for key in &mut keys {
            let keysize =
                usize::try_from(key.get_attr_as_ulong(CKA_VALUE_LEN)?)?;
            key.set_attr(Attribute::from_bytes(
                CKA_VALUE,
                dkm[cursor..(cursor + keysize)].to_vec(),
            ))?;
            cursor += key_to_segment_size(keysize, segment);
        }
        Ok(keys)
    }
}

#[cfg(all(test, feature = "fips"))]
mod tests {
    use super::*;
    use crate::attribute::CkAttrs;
    use crate::mechanism::Mechanisms;
    use crate::object::ObjectFactories;

    /// Registers the generic object factories (`crate::object::factory::
    /// register`) needed to import IKM and build the derived key object,
    /// mirroring `crate::awslc::hkdf`'s own test module's `registered()`.
    /// `Mechanisms` is otherwise unused here since `derive()` only
    /// consults it when additional derived keys are requested, which this
    /// test does not exercise.
    fn registered() -> (Mechanisms, ObjectFactories) {
        let mut mechs = Mechanisms::new();
        let mut ot = ObjectFactories::new();
        crate::object::factory::register(&mut mechs, &mut ot);
        (mechs, ot)
    }

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

    /// Constructs a real `Sp800Operation` via `counter_kdf_new` (the same
    /// entry point `crate::sp800_108`'s mechanism dispatch uses) for the
    /// 32-bit-counter/HMAC-SHA256 configuration AWS-LC's `KBKDF_ctr_hmac()`
    /// supports, runs a real `derive()`, and asserts `fips_approved()`
    /// directly on the operation object -- unlike
    /// `crate::tests::kdfs::test_sp800_kdf_awslc_ctr_hmac`'s
    /// `check_validation(session, 1)`, which currently passes purely from
    /// `FIPS_CHECKS.mechs`'s static table fallback (a `None` result from
    /// `fips_approved()` maps to `true` there) regardless of whether this
    /// operation's own approval wiring does anything at all. This test
    /// fails without `Sp800Operation`'s `fips_approved()` override (the
    /// trait default returns `None`, not `Some(true)`).
    #[test]
    fn counter_kdf_ctr_hmac_marks_operation_fips_approved() {
        let (mechs, ot) = registered();
        let key = import_secret(&ot, &[0x42u8; 16]);

        let mut counter_format = CK_SP800_108_COUNTER_FORMAT {
            bLittleEndian: 0,
            ulWidthInBits: 32,
        };
        let mut data_params = [CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_ITERATION_VARIABLE,
            pValue: &mut counter_format as *mut _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>()
                as CK_ULONG,
        }];
        let params = CK_SP800_108_KDF_PARAMS {
            prfType: CKM_SHA256_HMAC,
            ulNumberOfDataParams: data_params.len() as CK_ULONG,
            pDataParams: data_params.as_mut_ptr(),
            ulAdditionalDerivedKeys: 0,
            pAdditionalDerivedKeys: std::ptr::null_mut(),
        };

        let mut op = Sp800Operation::counter_kdf_new(params).unwrap();

        let tmpl = derive_secret_template(16);
        let objs = op.derive(&key, tmpl.as_slice(), &mechs, &ot).unwrap();
        assert_eq!(objs.len(), 1);

        assert_eq!(op.fips_approved(), Some(true));
    }
}

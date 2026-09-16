// Copyright 2026 Alexandre Laroche
// See LICENSE.txt file for terms

//! This module implements the PKCS#11 v3.0 IKE-derive mechanism family --
//! `CKM_IKE_PRF_DERIVE`, `CKM_IKE1_PRF_DERIVE`, `CKM_IKE1_EXTENDED_DERIVE`,
//! and `CKM_IKE2_PRF_PLUS_DERIVE` -- the IKEv1 ([RFC
//! 2409](https://www.rfc-editor.org/rfc/rfc2409) SS5/Appendix B) and IKEv2
//! ([RFC 7296](https://www.rfc-editor.org/rfc/rfc7296) SS2.13) key-derivation
//! constructions. All four reduce to plain HMAC over a documented
//! concatenation of inputs; this module is the PKCS#11-facing parameter
//! parsing and mechanism dispatch.
//!
//! `CKM_IKE1_EXTENDED_DERIVE`'s Appendix B chain always runs the PRF to
//! produce its output. Some implementations shortcut a request no longer
//! than the input key to a plain subset of that key when no extra keying
//! material (`gxy`/extra data) was supplied; the PKCS#11 v3.0 mechanism
//! description does not call for that shortcut, so it is not reproduced
//! here -- every call runs the documented `K1 = prf(K, [gxy][extra])`,
//! `Kn = prf(K, K(n-1)[gxy][extra])` chain.

use std::fmt::Debug;
use std::sync::LazyLock;

use crate::attribute::{Attribute, CkAttrs};
use crate::error::Result;
use crate::hash::INVALID_HASH_SIZE;
use crate::hmac::hmac_size;
use crate::mechanism::{Derive, Mac, MechOperation, Mechanism, Mechanisms};
use crate::misc::{bytes_to_vec, common_derive_key_object, zeromem};
use crate::native::hmac::HMACOperation;
use crate::object::{Object, ObjectFactories};
use crate::pkcs11::*;

/// Object that holds the Mechanism for the IKE-derive family
static IKE_MECH: LazyLock<Box<dyn Mechanism>> = LazyLock::new(|| {
    Box::new(IkeMechanism {
        info: CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: CK_ULONG::try_from(u32::MAX).unwrap(),
            flags: CKF_DERIVE,
        },
    })
});

/// Registers all IKE-derive-family mechanisms
pub fn register(mechs: &mut Mechanisms, _: &mut ObjectFactories) {
    for ckm in &[
        CKM_IKE_PRF_DERIVE,
        CKM_IKE1_PRF_DERIVE,
        CKM_IKE1_EXTENDED_DERIVE,
        CKM_IKE2_PRF_PLUS_DERIVE,
    ] {
        mechs.add_mechanism(*ckm, &IKE_MECH);
    }
}

fn prf_len(prf_mech: CK_MECHANISM_TYPE) -> Result<usize> {
    match hmac_size(prf_mech) {
        INVALID_HASH_SIZE => Err(CKR_MECHANISM_PARAM_INVALID)?,
        len => Ok(len),
    }
}

/// Returns the PKCS#11 key type that corresponds to the given HMAC mechanism.
fn prf_key_type(prf_mech: CK_MECHANISM_TYPE) -> Result<CK_KEY_TYPE> {
    match prf_mech {
        CKM_SHA_1_HMAC => Ok(CKK_SHA_1_HMAC),
        CKM_SHA224_HMAC => Ok(CKK_SHA224_HMAC),
        CKM_SHA256_HMAC => Ok(CKK_SHA256_HMAC),
        CKM_SHA384_HMAC => Ok(CKK_SHA384_HMAC),
        CKM_SHA512_HMAC => Ok(CKK_SHA512_HMAC),
        CKM_SHA3_224_HMAC => Ok(CKK_SHA3_224_HMAC),
        CKM_SHA3_256_HMAC => Ok(CKK_SHA3_256_HMAC),
        CKM_SHA3_384_HMAC => Ok(CKK_SHA3_384_HMAC),
        CKM_SHA3_512_HMAC => Ok(CKK_SHA3_512_HMAC),
        CKM_SHA512_224_HMAC => Ok(CKK_SHA512_224_HMAC),
        CKM_SHA512_256_HMAC => Ok(CKK_SHA512_256_HMAC),
        _ => Err(CKR_MECHANISM_PARAM_INVALID)?,
    }
}

/// Strictly checks that `key` is exactly the HMAC key type matching
/// `prf_mech`. Used for the **base key** passed to `derive()`, where the spec
/// requires the specific type and does NOT admit `CKK_GENERIC_SECRET`.
fn require_prf_base_key_type(
    mech: CK_MECHANISM_TYPE,
    key: &Object,
) -> Result<()> {
    let expected = prf_key_type(mech)?;
    if key.get_attr_as_ulong(CKA_KEY_TYPE)? == expected {
        Ok(())
    } else {
        Err(CKR_KEY_TYPE_INCONSISTENT)?
    }
}

fn prf(
    hmac: &mut HMACOperation,
    parts: &[&[u8]],
    out: &mut [u8],
) -> Result<()> {
    if hmac.finalized() {
        hmac.reset()?;
    }
    for part in parts {
        hmac.mac_update(part)?;
    }
    hmac.mac_final(out)
}

/// Shared setup for every IKE derive operation: checks and sets `finalized`,
/// validates the input key against the PRF mechanism, and calls
/// `common_derive_key_object`. If `default_key_type` is `Some`, adds it to
/// the template as a missing `CKA_KEY_TYPE` default before key object
/// creation. Returns the partially-constructed output object and key size.
fn ike_derive_setup(
    finalized: &mut bool,
    prf_mech: CK_MECHANISM_TYPE,
    key: &Object,
    template: &[CK_ATTRIBUTE],
    objfactories: &ObjectFactories,
    default_len: usize,
    default_key_type: Option<CK_KEY_TYPE>,
) -> Result<(Object, usize)> {
    if *finalized {
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }
    *finalized = true;
    if let Some(kt) = default_key_type {
        let default_class = CKO_SECRET_KEY;
        let mut tmpl = CkAttrs::from(template);
        tmpl.add_missing_ulong(CKA_CLASS, &default_class);
        tmpl.add_missing_ulong(CKA_KEY_TYPE, &kt);
        let mut obj =
            objfactories.derive_key_from_template(key, tmpl.as_slice())?;
        let value_len = match obj.get_attr_as_ulong(CKA_VALUE_LEN) {
            Ok(val) => usize::try_from(val)?,
            Err(_) => {
                if default_len == 0 {
                    return Err(CKR_TEMPLATE_INCOMPLETE)?;
                }
                obj.set_attr(Attribute::from_ulong(
                    CKA_VALUE_LEN,
                    CK_ULONG::try_from(default_len)?,
                ))?;
                default_len
            }
        };
        Ok((obj, value_len))
    } else {
        common_derive_key_object(key, template, objfactories, default_len)
    }
}

/// Object that represents the IKE-derive-family mechanism
#[derive(Debug)]
struct IkeMechanism {
    info: CK_MECHANISM_INFO,
}

impl Mechanism for IkeMechanism {
    fn info(&self) -> &CK_MECHANISM_INFO {
        &self.info
    }

    fn derive_operation(&self, mech: &CK_MECHANISM) -> Result<Box<dyn Derive>> {
        if self.info.flags & CKF_DERIVE != CKF_DERIVE {
            return Err(CKR_MECHANISM_INVALID)?;
        }
        match mech.mechanism {
            CKM_IKE_PRF_DERIVE => Ok(Box::new(IkePrfOperation::new(mech)?)),
            CKM_IKE1_PRF_DERIVE => Ok(Box::new(Ike1PrfOperation::new(mech)?)),
            CKM_IKE1_EXTENDED_DERIVE => {
                Ok(Box::new(Ike1ExtendedOperation::new(mech)?))
            }
            CKM_IKE2_PRF_PLUS_DERIVE => {
                Ok(Box::new(Ike2PrfPlusOperation::new(mech)?))
            }
            _ => Err(CKR_MECHANISM_INVALID)?,
        }
    }
}

/// Returns `None` when ptr is null and len is 0 (absent); errors on
/// inconsistent null+nonzero or nonnull+zero.
fn opt_bytes(ptr: *mut CK_BYTE, len: CK_ULONG) -> Result<Option<Vec<u8>>> {
    match (ptr.is_null(), len) {
        (true, 0) => Ok(None),
        (true, _) | (false, 0) => Err(CKR_MECHANISM_PARAM_INVALID)?,
        (false, _) => {
            Ok(Some(bytes_to_vec(ptr as *const u8, usize::try_from(len)?)))
        }
    }
}

/// Validates that both pointers are non-null, that each length is at least
/// `min_each`, then returns `a || b` as a single owned buffer.
fn check_ni_nr(
    p_a: *mut CK_BYTE,
    len_a: CK_ULONG,
    p_b: *mut CK_BYTE,
    len_b: CK_ULONG,
    min_each: usize,
) -> Result<Vec<u8>> {
    let la = usize::try_from(len_a)?;
    let lb = usize::try_from(len_b)?;
    if p_a.is_null() || la < min_each || p_b.is_null() || lb < min_each {
        return Err(CKR_MECHANISM_PARAM_INVALID)?;
    }
    let mut out = Vec::with_capacity(la + lb);
    out.extend_from_slice(unsafe {
        std::slice::from_raw_parts(p_a as *const u8, la)
    });
    out.extend_from_slice(unsafe {
        std::slice::from_raw_parts(p_b as *const u8, lb)
    });
    Ok(out)
}

/// The `CKM_IKE_PRF_DERIVE` operation.
///
/// Per its own PKCS#11 v3.0 description, this returns one of three things,
/// selected by `bDataAsKey`/`bRekey` (mutually exclusive):
///   1. `prf(Ni||Nr, inKey)`            (`bDataAsKey = true`,  `bRekey = false`)
///   2. `prf(inKey, Ni||Nr)`            (`bDataAsKey = false`, `bRekey = false`)
///   3. `prf(inKey, newKey||Ni||Nr)`    (`bDataAsKey = false`, `bRekey = true`)
///
/// Case 1 is IKEv1/IKEv2's SKEYID/SKEYSEED from the shared secret `g^ir`;
/// case 2 is IKEv1's SKEYID from a pre-shared key; case 3 is IKEv2's rekey
/// SKEYSEED from the old `SK_d` and the new `g^ir`. The output is always
/// exactly one PRF block long, regardless of any requested length.
#[derive(Debug)]
struct IkePrfOperation {
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    prf_len: usize,
    data_as_key: bool,
    ni_nr: Vec<u8>, // Ni||Nr pre-concatenated, min 16 bytes each
    new_key_handle: CK_OBJECT_HANDLE, // CK_INVALID_HANDLE when not rekey
    new_key: Option<Vec<u8>>,
}

impl IkePrfOperation {
    fn new(mech: &CK_MECHANISM) -> Result<IkePrfOperation> {
        let params = mech.get_parameters::<CK_IKE_PRF_DERIVE_PARAMS>()?;
        let data_as_key = params.bDataAsKey != CK_FALSE;
        let rekey = params.bRekey != CK_FALSE;
        if data_as_key && rekey {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let new_key_handle = if rekey {
            if params.hNewKey == CK_INVALID_HANDLE {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            params.hNewKey
        } else {
            CK_INVALID_HANDLE
        };
        Ok(IkePrfOperation {
            finalized: false,
            prf: params.prfMechanism,
            prf_len: prf_len(params.prfMechanism)?,
            data_as_key,
            // Ni and Nr must be present (non-null) and each at least 128 bits.
            ni_nr: check_ni_nr(
                params.pNi,
                params.ulNiLen,
                params.pNr,
                params.ulNrLen,
                16,
            )?,
            new_key_handle,
            new_key: None,
        })
    }
}

impl Drop for IkePrfOperation {
    fn drop(&mut self) {
        zeromem(&mut self.ni_nr);
        if let Some(ref mut v) = self.new_key {
            zeromem(v);
        }
    }
}

impl MechOperation for IkePrfOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(CKM_IKE_PRF_DERIVE)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if self.new_key_handle != CK_INVALID_HANDLE {
            Ok(std::slice::from_ref(&self.new_key_handle))
        } else {
            Err(CKR_OK)?
        }
    }

    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if objs.len() != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        // §6.64.3: hNewKey must be of type CKK_GENERIC_SECRET.
        if objs[0].get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        self.new_key = Some(objs[0].get_attr_as_bytes(CKA_VALUE)?.clone());
        Ok(())
    }
}

impl Derive for IkePrfOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        // §6.64.3: when bDataAsKey TRUE the base key must be CKK_GENERIC_SECRET;
        // when FALSE it must be the specific HMAC type (generic secret excluded).
        if self.data_as_key {
            if key.get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
                return Err(CKR_KEY_TYPE_INCONSISTENT)?;
            }
        } else {
            require_prf_base_key_type(self.prf, key)?;
        }

        let default_key_type = prf_key_type(self.prf)?;
        let (mut obj, keysize) = ike_derive_setup(
            &mut self.finalized,
            self.prf,
            key,
            template,
            objfactories,
            self.prf_len,
            Some(default_key_type),
        )?;

        let key_bytes = key.get_attr_as_bytes(CKA_VALUE)?;
        let mut out = vec![0u8; self.prf_len];
        if self.data_as_key {
            // prf(Ni||Nr, inKey): Ni||Nr is the HMAC key, inKey is the data.
            let mut hmac = HMACOperation::internal(
                self.prf,
                self.ni_nr.clone(),
                self.prf_len,
            )?;
            prf(&mut hmac, &[key_bytes], &mut out)?;
        } else {
            let mut hmac = HMACOperation::internal(
                self.prf,
                key_bytes.to_vec(),
                self.prf_len,
            )?;
            if self.new_key_handle != CK_INVALID_HANDLE {
                let new_key =
                    self.new_key.as_deref().ok_or(CKR_GENERAL_ERROR)?;
                prf(&mut hmac, &[new_key, &self.ni_nr], &mut out)?;
            } else {
                prf(&mut hmac, &[self.ni_nr.as_slice()], &mut out)?;
            }
        }

        if keysize != out.len() {
            return Err(CKR_TEMPLATE_INCONSISTENT)?;
        }
        obj.set_attr(Attribute::from_bytes(CKA_VALUE, out))?;
        Ok(vec![obj])
    }
}

/// The `CKM_IKE1_PRF_DERIVE` operation: `prf(inKey, [prevKey||] gxy||CKY_I||
/// CKY_R||keyNumber)` (RFC 2409 SS5). Used to derive IKEv1's SKEYID_d/_a/_e
/// in sequence, each keyed off the previous one via `prevKey`. The output
/// is truncated to the requested length, which must not exceed one PRF
/// block.
#[derive(Debug)]
struct Ike1PrfOperation {
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    prf_len: usize,
    // handles[0] = hKeygxy; handles[1] = hPrevKey or CK_INVALID_HANDLE
    handles: [CK_OBJECT_HANDLE; 2],
    keygxy: Option<Vec<u8>>,
    prev_key: Option<Vec<u8>>,
    cky: Vec<u8>, // CKY_I || CKY_R concatenated
    key_number: u8,
}

impl Ike1PrfOperation {
    fn new(mech: &CK_MECHANISM) -> Result<Ike1PrfOperation> {
        let params = mech.get_parameters::<CK_IKE1_PRF_DERIVE_PARAMS>()?;
        if params.hKeygxy == CK_INVALID_HANDLE {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        let has_prev_key = params.bHasPrevKey != CK_FALSE;
        let prev_handle = if has_prev_key {
            if params.hPrevKey == CK_INVALID_HANDLE {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            params.hPrevKey
        } else {
            CK_INVALID_HANDLE
        };
        Ok(Ike1PrfOperation {
            finalized: false,
            prf: params.prfMechanism,
            prf_len: prf_len(params.prfMechanism)?,
            handles: [params.hKeygxy, prev_handle],
            keygxy: None,
            prev_key: None,
            // ISAKMP cookies must be present and at least 8 bytes each.
            cky: check_ni_nr(
                params.pCKYi,
                params.ulCKYiLen,
                params.pCKYr,
                params.ulCKYrLen,
                8,
            )?,
            key_number: params.keyNumber,
        })
    }
}

impl Drop for Ike1PrfOperation {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.keygxy {
            zeromem(v);
        }
        if let Some(ref mut v) = self.prev_key {
            zeromem(v);
        }
    }
}

impl MechOperation for Ike1PrfOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(CKM_IKE1_PRF_DERIVE)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if self.handles[1] != CK_INVALID_HANDLE {
            Ok(&self.handles)
        } else {
            Ok(&self.handles[..1])
        }
    }

    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        let expected = if self.handles[1] != CK_INVALID_HANDLE {
            2
        } else {
            1
        };
        if objs.len() != expected {
            return Err(CKR_GENERAL_ERROR)?;
        }
        // §6.64.4: hKeygxy must be of type CKK_GENERIC_SECRET.
        if objs[0].get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        self.keygxy = Some(objs[0].get_attr_as_bytes(CKA_VALUE)?.clone());
        if self.handles[1] != CK_INVALID_HANDLE {
            self.prev_key = Some(objs[1].get_attr_as_bytes(CKA_VALUE)?.clone());
        }
        Ok(())
    }
}

impl Derive for Ike1PrfOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        // §6.64.4: base key must be the specific HMAC type (generic secret excluded).
        require_prf_base_key_type(self.prf, key)?;
        // §6.64.4: CKA_KEY_TYPE must be specified in the template.
        if !template.iter().any(|a| a.type_ == CKA_KEY_TYPE) {
            return Err(CKR_TEMPLATE_INCOMPLETE)?;
        }

        let (mut obj, keysize) = ike_derive_setup(
            &mut self.finalized,
            self.prf,
            key,
            template,
            objfactories,
            self.prf_len,
            None,
        )?;

        let gxy = match &self.keygxy {
            Some(v) => v.as_slice(),
            None => return Err(CKR_GENERAL_ERROR)?,
        };
        let key_number = [self.key_number];
        let mut parts: Vec<&[u8]> = Vec::with_capacity(4);
        if let Some(pk) = &self.prev_key {
            parts.push(pk);
        }
        parts.push(gxy);
        parts.push(&self.cky);
        parts.push(&key_number);

        if keysize > self.prf_len {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }
        let key_bytes = key.get_attr_as_bytes(CKA_VALUE)?;
        let mut hmac = HMACOperation::internal(
            self.prf,
            key_bytes.to_vec(),
            self.prf_len,
        )?;
        let mut out = vec![0u8; self.prf_len];
        prf(&mut hmac, &parts, &mut out)?;
        obj.set_attr(Attribute::from_bytes(
            CKA_VALUE,
            out[..keysize].to_vec(),
        ))?;
        Ok(vec![obj])
    }
}

/// The `CKM_IKE1_EXTENDED_DERIVE` operation: RFC 2409 Appendix B's key
/// expansion, `K1 = prf(K, [gxy][extra])` (or `prf(K, 0)` if neither is
/// present), `Kn = prf(K, K(n-1)[gxy][extra])`, concatenated and truncated
/// to the requested length. Unlike `CKM_IKE_PRF_DERIVE`/`CKM_IKE1_PRF_DERIVE`
/// there is no PRF-derived default length -- the caller must request one.
#[derive(Debug)]
struct Ike1ExtendedOperation {
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    prf_len: usize,
    keygxy_handle: CK_OBJECT_HANDLE,
    keygxy: Option<Vec<u8>>,
    extra_data: Option<Vec<u8>>,
}

impl Ike1ExtendedOperation {
    fn new(mech: &CK_MECHANISM) -> Result<Ike1ExtendedOperation> {
        let params = mech.get_parameters::<CK_IKE1_EXTENDED_DERIVE_PARAMS>()?;
        let keygxy_handle = if params.bHasKeygxy != CK_FALSE {
            if params.hKeygxy == CK_INVALID_HANDLE {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            params.hKeygxy
        } else {
            CK_INVALID_HANDLE
        };
        Ok(Ike1ExtendedOperation {
            finalized: false,
            prf: params.prfMechanism,
            prf_len: prf_len(params.prfMechanism)?,
            keygxy_handle,
            keygxy: None,
            extra_data: opt_bytes(params.pExtraData, params.ulExtraDataLen)?,
        })
    }
}

impl Drop for Ike1ExtendedOperation {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.keygxy {
            zeromem(v);
        }
        if let Some(ref mut v) = self.extra_data {
            zeromem(v);
        }
    }
}

impl MechOperation for Ike1ExtendedOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(CKM_IKE1_EXTENDED_DERIVE)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if self.keygxy_handle != CK_INVALID_HANDLE {
            Ok(std::slice::from_ref(&self.keygxy_handle))
        } else {
            Err(CKR_OK)?
        }
    }

    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if objs.len() != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        // §6.64.6: hKeygxy must be of type CKK_GENERIC_SECRET.
        if objs[0].get_attr_as_ulong(CKA_KEY_TYPE)? != CKK_GENERIC_SECRET {
            return Err(CKR_KEY_TYPE_INCONSISTENT)?;
        }
        self.keygxy = Some(objs[0].get_attr_as_bytes(CKA_VALUE)?.clone());
        Ok(())
    }
}

impl Derive for Ike1ExtendedOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        // §6.64.6: K must be the specific HMAC type (generic secret excluded).
        require_prf_base_key_type(self.prf, key)?;
        let (mut obj, keysize) = ike_derive_setup(
            &mut self.finalized,
            self.prf,
            key,
            template,
            objfactories,
            0,
            Some(CKK_GENERIC_SECRET),
        )?;
        if keysize == 0 {
            return Err(CKR_TEMPLATE_INCOMPLETE)?;
        }
        // PKCS#11 v3.0 §6.64.6: CKA_VALUE_LEN <= 255 * prf output size.
        if keysize > 255 * self.prf_len {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let key_bytes = key.get_attr_as_bytes(CKA_VALUE)?;
        let gxy: Option<&[u8]> = self.keygxy.as_deref();
        let extra: Option<&[u8]> = self.extra_data.as_deref();
        let zero = [0u8];

        let mut hmac = HMACOperation::internal(
            self.prf,
            key_bytes.to_vec(),
            self.prf_len,
        )?;
        // Single reusable output buffer; kn tracks the previous block.
        let mut block = vec![0u8; self.prf_len];

        // K1 = prf(K, [gxy][extra]) or prf(K, 0x00) when both absent.
        {
            let mut parts: Vec<&[u8]> = Vec::with_capacity(2);
            if let Some(g) = gxy {
                parts.push(g);
            }
            if let Some(e) = extra {
                parts.push(e);
            }
            if parts.is_empty() {
                parts.push(&zero);
            }
            prf(&mut hmac, &parts, &mut block)?;
        }

        let mut dkm = Vec::with_capacity(keysize);
        dkm.extend_from_slice(&block);
        let mut kn = block.clone(); // kn = K1

        // Kn = prf(K, K(n-1)[gxy][extra])
        while dkm.len() < keysize {
            let mut parts: Vec<&[u8]> = Vec::with_capacity(3);
            parts.push(&kn);
            if let Some(g) = gxy {
                parts.push(g);
            }
            if let Some(e) = extra {
                parts.push(e);
            }
            prf(&mut hmac, &parts, &mut block)?;
            dkm.extend_from_slice(&block);
            kn.copy_from_slice(&block);
        }
        dkm.truncate(keysize);

        obj.set_attr(Attribute::from_bytes(CKA_VALUE, dkm))?;
        Ok(vec![obj])
    }
}

/// The `CKM_IKE2_PRF_PLUS_DERIVE` operation: RFC 7296 SS2.13's `prf+`,
/// `T1 = prf(K, S||0x01)`, `Tn = prf(K, T(n-1)||S||n)` where `S` is
/// `seedKey||seedData`, concatenated and truncated to the requested length.
/// Like `CKM_IKE1_EXTENDED_DERIVE` there is no PRF-derived default length.
#[derive(Debug)]
struct Ike2PrfPlusOperation {
    finalized: bool,
    prf: CK_MECHANISM_TYPE,
    prf_len: usize,
    seed_key_handle: CK_OBJECT_HANDLE,
    seed_key: Option<Vec<u8>>,
    seed_data: Option<Vec<u8>>,
}

impl Ike2PrfPlusOperation {
    fn new(mech: &CK_MECHANISM) -> Result<Ike2PrfPlusOperation> {
        let params = mech.get_parameters::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>()?;
        let seed_key_handle = if params.bHasSeedKey != CK_FALSE {
            if params.hSeedKey == CK_INVALID_HANDLE {
                return Err(CKR_MECHANISM_PARAM_INVALID)?;
            }
            params.hSeedKey
        } else {
            CK_INVALID_HANDLE
        };
        let seed_data = opt_bytes(params.pSeedData, params.ulSeedDataLen)?;
        if seed_key_handle == CK_INVALID_HANDLE && seed_data.is_none() {
            return Err(CKR_MECHANISM_PARAM_INVALID)?;
        }
        Ok(Ike2PrfPlusOperation {
            finalized: false,
            prf: params.prfMechanism,
            prf_len: prf_len(params.prfMechanism)?,
            seed_key_handle,
            seed_key: None,
            seed_data,
        })
    }
}

impl Drop for Ike2PrfPlusOperation {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.seed_key {
            zeromem(v);
        }
        if let Some(ref mut v) = self.seed_data {
            zeromem(v);
        }
    }
}

impl MechOperation for Ike2PrfPlusOperation {
    fn mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(CKM_IKE2_PRF_PLUS_DERIVE)
    }

    fn finalized(&self) -> bool {
        self.finalized
    }

    fn requires_objects(&self) -> Result<&[CK_OBJECT_HANDLE]> {
        if self.seed_key_handle != CK_INVALID_HANDLE {
            Ok(std::slice::from_ref(&self.seed_key_handle))
        } else {
            Err(CKR_OK)?
        }
    }

    fn receives_objects(&mut self, objs: &[&Object]) -> Result<()> {
        if objs.len() != 1 {
            return Err(CKR_GENERAL_ERROR)?;
        }
        self.seed_key = Some(objs[0].get_attr_as_bytes(CKA_VALUE)?.clone());
        Ok(())
    }
}

impl Derive for Ike2PrfPlusOperation {
    fn derive(
        &mut self,
        key: &Object,
        template: &[CK_ATTRIBUTE],
        _: &Mechanisms,
        objfactories: &ObjectFactories,
    ) -> Result<Vec<Object>> {
        // §6.64.7: base key must be the specific HMAC type (generic secret excluded).
        require_prf_base_key_type(self.prf, key)?;
        let (mut obj, keysize) = ike_derive_setup(
            &mut self.finalized,
            self.prf,
            key,
            template,
            objfactories,
            0,
            Some(CKK_GENERIC_SECRET),
        )?;
        if keysize == 0 {
            return Err(CKR_TEMPLATE_INCOMPLETE)?;
        }
        // RFC 7296 §2.13 limits prf+ to 255 blocks.
        if keysize > 255 * self.prf_len {
            return Err(CKR_KEY_SIZE_RANGE)?;
        }

        let key_bytes = key.get_attr_as_bytes(CKA_VALUE)?;
        let seed_key: Option<&[u8]> = self.seed_key.as_deref();
        let seed_data: Option<&[u8]> = self.seed_data.as_deref();

        let mut hmac = HMACOperation::internal(
            self.prf,
            key_bytes.to_vec(),
            self.prf_len,
        )?;
        // Single reusable output buffer; tn tracks the previous block.
        let mut block = vec![0u8; self.prf_len];

        // T1 = prf(K, [seedKey][seedData]||0x01)
        {
            let counter_byte = [1u8];
            let mut parts: Vec<&[u8]> = Vec::with_capacity(3);
            if let Some(s) = seed_key {
                parts.push(s);
            }
            if let Some(d) = seed_data {
                parts.push(d);
            }
            parts.push(&counter_byte);
            prf(&mut hmac, &parts, &mut block)?;
        }

        let mut dkm = Vec::with_capacity(keysize);
        dkm.extend_from_slice(&block);
        let mut tn = block.clone(); // tn = T1

        // Tn = prf(K, T(n-1)||[seedKey][seedData]||n)
        let mut counter: u8 = 1;
        while dkm.len() < keysize {
            if counter == 255 {
                return Err(CKR_KEY_SIZE_RANGE)?;
            }
            counter += 1;
            let counter_byte = [counter];
            let mut parts: Vec<&[u8]> = Vec::with_capacity(4);
            parts.push(&tn);
            if let Some(s) = seed_key {
                parts.push(s);
            }
            if let Some(d) = seed_data {
                parts.push(d);
            }
            parts.push(&counter_byte);
            prf(&mut hmac, &parts, &mut block)?;
            dkm.extend_from_slice(&block);
            tn.copy_from_slice(&block);
        }
        dkm.truncate(keysize);

        obj.set_attr(Attribute::from_bytes(CKA_VALUE, dkm))?;
        Ok(vec![obj])
    }
}

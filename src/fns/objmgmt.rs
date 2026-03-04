// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Object Management functions
//!
//! This module contains the implementation of the Object Management functions
//! as defined in the PKCS#11 specification.

use crate::config;
use crate::error::Result;
use crate::log_debug;
use crate::mechanism::SearchOperation;
use crate::pkcs11::vendor::KRY_UNSPEC;
use crate::pkcs11::*;
use crate::{fail_if_cka_token_true, STATE};

#[cfg(feature = "fips")]
use crate::fips;

#[inline(always)]
fn create_object(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object_handle: CK_OBJECT_HANDLE_PTR,
) -> Result<()> {
    if template.is_null() || object_handle.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    #[cfg(not(feature = "fips"))]
    let session = rstate.get_session(s_handle)?;
    #[cfg(feature = "fips")]
    let mut session = {
        let mut s = rstate.get_session_mut(s_handle)?;
        /* ensure we reset the fips indicator which may be left dirty by
         * a previous operation */
        s.reset_fips_indicator();
        s
    };
    let cnt = usize::try_from(count).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let tmpl: &mut [CK_ATTRIBUTE] =
        unsafe { std::slice::from_raw_parts_mut(template, cnt) };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }

    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    fips::check_key_template(tmpl, rstate.get_fips_behavior(slot_id)?)?;

    let mut token = rstate.get_token_from_slot_mut(slot_id)?;

    let key_handle = token.create_object(s_handle, tmpl)?;

    #[cfg(feature = "fips")]
    {
        let mut key = token.get_object_by_handle(key_handle)?;
        /* ignore if not a key */
        match key.get_attr_as_ulong(CKA_KEY_TYPE) {
            /* check as if the key were generated, the same considerations
             * as for key generation apply here, so we use the the same
             * mechanism that would be used if this key was generated */
            Ok(key_type) => {
                let mechanism = match key_type {
                    CKK_AES => CKM_AES_KEY_GEN,
                    CKK_GENERIC_SECRET => CKM_GENERIC_SECRET_KEY_GEN,
                    CKK_HKDF => CKM_HKDF_KEY_GEN,
                    CKK_RSA => CKM_RSA_PKCS_KEY_PAIR_GEN,
                    CKK_EC => CKM_EC_KEY_PAIR_GEN,
                    CKK_EC_EDWARDS => CKM_EC_EDWARDS_KEY_PAIR_GEN,
                    CKK_ML_DSA => CKM_ML_DSA_KEY_PAIR_GEN,
                    CKK_ML_KEM => CKM_ML_KEM_KEY_PAIR_GEN,
                    CKK_SLH_DSA => CKM_SLH_DSA_KEY_PAIR_GEN,
                    _ => CK_UNAVAILABLE_INFORMATION,
                };
                session.set_fips_indicator(fips::indicators::is_approved(
                    mechanism,
                    CKF_GENERATE,
                    None,
                    Some(&mut key),
                ));
            }
            Err(_) => (),
        }
    }

    unsafe {
        core::ptr::write(object_handle as *mut _, key_handle);
    }

    Ok(())
}

/// Implementation of C_CreateObject function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203283](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203283)

pub extern "C" fn fn_create_object(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    object_handle: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_CreateObject: s_handle={} template={:?} count={} object_handle={:?}",
        s_handle,
        template,
        count,
        object_handle
    );
    let rv = match create_object(s_handle, template, count, object_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_CreateObject: ret={}", rv);
    rv
}

#[inline(always)]
fn copy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> Result<()> {
    if ph_new_object.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    let cnt = usize::try_from(count).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let tmpl: &mut [CK_ATTRIBUTE] = if cnt > 0 {
        if template.is_null() {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        unsafe { std::slice::from_raw_parts_mut(template, cnt) }
    } else {
        &mut []
    };
    if !session.is_writable() {
        fail_if_cka_token_true(tmpl)?;
    }
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;

    /* TODO: return CKR_ACTION_PROHIBITED instead of CKR_USER_NOT_LOGGED_IN ? */
    let oh = token.copy_object(s_handle, o_handle, tmpl)?;

    unsafe {
        *ph_new_object = oh;
    }

    Ok(())
}

/// Implementation of C_CopyObject function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203284](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203284)

pub extern "C" fn fn_copy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_new_object: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_CopyObject: s_handle={} o_handle={} template={:?} count={} ph_new_object={:?}",
        s_handle,
        o_handle,
        template,
        count,
        ph_new_object
    );
    let rv =
        match copy_object(s_handle, o_handle, template, count, ph_new_object) {
            Ok(()) => CKR_OK,
            Err(e) => e.rv(),
        };
    log_debug!("C_CopyObject: ret={}", rv);
    rv
}

#[inline(always)]
fn destroy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    /* TODO: return CKR_ACTION_PROHIBITED instead of CKR_USER_NOT_LOGGED_IN ? */
    let obj = token.get_object_by_handle(o_handle)?;
    if obj.is_token() && !session.is_writable() {
        return Err(CKR_ACTION_PROHIBITED)?;
    }
    token.destroy_object(o_handle)
}

/// Implementation of C_DestroyObject function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203285](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203285)
pub extern "C" fn fn_destroy_object(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_DestroyObject: s_handle={} o_handle={}",
        s_handle,
        o_handle
    );
    let rv = match destroy_object(s_handle, o_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DestroyObject: ret={}", rv);
    rv
}

#[inline(always)]
fn get_object_size(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> Result<()> {
    if size.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let token = rstate.get_token_from_session(s_handle)?;
    let len = CK_ULONG::try_from(token.get_object_size(o_handle)?)
        .map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *size = len }
    Ok(())
}

/// Implementation of C_GetObjectSize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203286](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203286)

pub extern "C" fn fn_get_object_size(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    size: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_GetObjectSize: s_handle={} o_handle={} size={:?}",
        s_handle,
        o_handle,
        size
    );
    let rv = match get_object_size(s_handle, o_handle, size) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetObjectSize: ret={}", rv);
    rv
}

#[inline(always)]
fn get_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<()> {
    let cnt = usize::try_from(count).map_err(|_| CKR_ARGUMENTS_BAD)?;
    if cnt > 0 && template.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let mut tmpl: &mut [CK_ATTRIBUTE] = if cnt > 0 {
        unsafe { std::slice::from_raw_parts_mut(template, cnt) }
    } else {
        &mut []
    };

    /* must do this before we lock STATE or risk deadlocking in tests with
     * a parallel thread calling fn_initialize() */
    #[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
    let der_encode_ec_point = {
        let conf = crate::CONFIG.rlock()?;
        /* enable the whole thing only if we need to convert to backwards
         * compatible DER encoding */
        match conf.ec_point_encoding {
            config::EcPointEncoding::Der => true,
            _ => false,
        }
    };

    #[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
    let input_ec_point_len = {
        if der_encode_ec_point {
            match tmpl.iter().find(|a| a.type_ == CKA_EC_POINT) {
                Some(a) => usize::try_from(a.ulValueLen)
                    .map_err(|_| CKR_ARGUMENTS_BAD)?,
                None => 0,
            }
        } else {
            0
        }
    };

    let rstate = STATE.rlock()?;
    let mut token = rstate.get_token_from_session_mut(s_handle)?;
    let result = match token.get_object_attrs(o_handle, &mut tmpl) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };

    #[cfg(any(feature = "eddsa", feature = "ec_montgomery"))]
    if der_encode_ec_point {
        use crate::ec::{point_buf_to_der, point_len_to_der};

        match tmpl.iter_mut().find(|a| a.type_ == CKA_EC_POINT) {
            Some(a) => {
                if a.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                    /* do not touch this */
                    if result != CKR_OK {
                        return Err(result)?;
                    }
                    return Ok(());
                }
                let buflen = usize::try_from(a.ulValueLen)
                    .map_err(|_| CKR_GENERAL_ERROR)?;
                if a.pValue == std::ptr::null_mut() {
                    let len = point_len_to_der(buflen);
                    if len != buflen {
                        a.ulValueLen = CK_ULONG::try_from(len)
                            .map_err(|_| CKR_GENERAL_ERROR)?;
                    }
                } else {
                    let buf: &mut [u8] = unsafe {
                        std::slice::from_raw_parts_mut(
                            a.pValue as *mut u8,
                            buflen,
                        )
                    };
                    let out = point_buf_to_der(buf, input_ec_point_len)?;
                    if let Some(v) = out {
                        if v.len() > input_ec_point_len {
                            return Err(CKR_GENERAL_ERROR)?;
                        }
                        unsafe {
                            /* update buffer with the DER encoded version */
                            std::ptr::copy_nonoverlapping(
                                v.as_ptr(),
                                a.pValue as *mut u8,
                                v.len(),
                            );
                        }
                        a.ulValueLen = CK_ULONG::try_from(v.len())
                            .map_err(|_| CKR_GENERAL_ERROR)?;
                    }
                }
            }
            None => (),
        }
    }

    if result != CKR_OK {
        return Err(result)?;
    }
    Ok(())
}

/// Implementation of C_GetAttributeValue function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203287](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203287)

pub extern "C" fn fn_get_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_GetAttributeValue: s_handle={} o_handle={} template={:?} count={}",
        s_handle,
        o_handle,
        template,
        count
    );
    let rv = match get_attribute_value(s_handle, o_handle, template, count) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetAttributeValue: ret={}", rv);
    rv
}

#[inline(always)]
fn set_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let obj = token.get_object_by_handle(o_handle)?;
    if obj.is_token() {
        if !token.is_logged_in(KRY_UNSPEC) {
            return Err(CKR_USER_NOT_LOGGED_IN)?;
        }
        if !session.is_writable() {
            return Err(CKR_SESSION_READ_ONLY)?;
        }
    }
    let cnt = usize::try_from(count).map_err(|_| CKR_ARGUMENTS_BAD)?;
    if cnt > 0 && template.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let mut tmpl: &mut [CK_ATTRIBUTE] = if cnt > 0 {
        unsafe { std::slice::from_raw_parts_mut(template, cnt) }
    } else {
        &mut []
    };
    token.set_object_attrs(o_handle, &mut tmpl)
}

/// Implementation of C_SetAttributeValue function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203288](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203288)

pub extern "C" fn fn_set_attribute_value(
    s_handle: CK_SESSION_HANDLE,
    o_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_SetAttributeValue: s_handle={} o_handle={} template={:?} count={}",
        s_handle,
        o_handle,
        template,
        count
    );
    let rv = match set_attribute_value(s_handle, o_handle, template, count) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SetAttributeValue: ret={}", rv);
    rv
}

#[inline(always)]
fn find_objects_init(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let cnt = usize::try_from(count).map_err(|_| CKR_ARGUMENTS_BAD)?;
    if cnt > 0 && template.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let tmpl: &mut [CK_ATTRIBUTE] = if cnt > 0 {
        unsafe { std::slice::from_raw_parts_mut(template, cnt) }
    } else {
        &mut []
    };
    session.new_search_operation(&mut token, tmpl)
}

/// Implementation of C_FindObjectsInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203289](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203289)

pub extern "C" fn fn_find_objects_init(
    s_handle: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_FindObjectsInit: s_handle={} template={:?} count={}",
        s_handle,
        template,
        count
    );
    let rv = match find_objects_init(s_handle, template, count) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_FindObjectsInit: ret={}", rv);
    rv
}

#[inline(always)]
fn find_objects(
    s_handle: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    pul_object_count: CK_ULONG_PTR,
) -> Result<()> {
    if ph_object.is_null() || pul_object_count.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn SearchOperation>()?;
    let moc =
        usize::try_from(max_object_count).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let handles = operation.results(moc)?;
    let hlen = handles.len();
    if hlen > 0 {
        let mut idx = 0;
        while idx < hlen {
            let offset = isize::try_from(idx).map_err(|_| CKR_GENERAL_ERROR)?;
            unsafe {
                *ph_object.offset(offset) = handles[idx];
            }
            idx += 1;
        }
    }
    let poc = CK_ULONG::try_from(hlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe {
        *pul_object_count = poc;
    }
    Ok(())
}

/// Implementation of C_FindObjects function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203290](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203290)

pub extern "C" fn fn_find_objects(
    s_handle: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    max_object_count: CK_ULONG,
    pul_object_count: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_FindObjects: s_handle={} ph_object={:?} max_object_count={} pul_object_count={:?}",
        s_handle,
        ph_object,
        max_object_count,
        pul_object_count
    );
    let rv = match find_objects(
        s_handle,
        ph_object,
        max_object_count,
        pul_object_count,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_FindObjects: ret={}", rv);
    rv
}

#[inline(always)]
fn find_objects_final(s_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    session.cancel_operation::<dyn SearchOperation>()
}

/// Implementation of C_FindObjectsFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203291](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203291)

pub extern "C" fn fn_find_objects_final(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    log_debug!("C_FindObjectsFinal: s_handle={}", s_handle);
    let rv = match find_objects_final(s_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_FindObjectsFinal: ret={}", rv);
    rv
}

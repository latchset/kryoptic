// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Signing and Verification functions
//!
//! This module contains the implementation of the Signing and Verification functions
//! as defined in the PKCS#11 specification.

use std::sync::RwLockWriteGuard;

use crate::check_allowed_mechs;
use crate::error::Result;
use crate::log_debug;
use crate::mechanism::{Sign, Verify, VerifySignature};
use crate::pkcs11::*;
use crate::session::Session;
use crate::STATE;

#[cfg(feature = "fips")]
use crate::{finalize_fips_approval, init_fips_approval};

#[inline(always)]
fn sign_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn Sign>()?;
        return Ok(());
    }
    session.check_no_op::<dyn Sign>()?;

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_SIGN == CKF_SIGN {
        let operation = mech.sign_new(mechanism, &key)?;
        session.set_operation::<dyn Sign>(operation, key.always_auth());

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_SIGN, &key);

        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_SignInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203321](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203321)

pub extern "C" fn fn_sign_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_SignInit: s_handle={} mechptr={:?} key_handle={}",
        s_handle,
        mechptr,
        key_handle
    );
    let rv = match sign_init(s_handle, mechptr, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SignInit: ret={}", rv);
    rv
}

#[inline(always)]
fn sign(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    psignature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> Result<()> {
    if pdata.is_null() || pul_signature_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Sign>()?;
    let signature_len = operation.signature_len()?;
    let sig_len =
        CK_ULONG::try_from(signature_len).map_err(|_| CKR_GENERAL_ERROR)?;
    if psignature.is_null() {
        unsafe {
            *pul_signature_len = sig_len;
        }
        return Ok(());
    }
    unsafe {
        if *pul_signature_len < sig_len {
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }
    }
    let dlen = usize::try_from(data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };

    operation.sign(data, signature)?;
    unsafe {
        *pul_signature_len = sig_len;
    }

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_Sign function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203322](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203322)

pub extern "C" fn fn_sign(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    psignature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_Sign: s_handle={} pdata={:?} data_len={} psignature={:?} pul_signature_len={:?}",
        s_handle,
        pdata,
        data_len,
        psignature,
        pul_signature_len
    );
    let rv =
        match sign(s_handle, pdata, data_len, psignature, pul_signature_len) {
            Ok(()) => CKR_OK,
            Err(e) => e.rv(),
        };
    log_debug!("C_Sign: ret={}", rv);
    rv
}

/// Helper to perform "sign_update" in multiple places,

pub(crate) fn internal_sign_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    let operation = session.get_operation::<dyn Sign>()?;
    let plen = usize::try_from(part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.sign_update(data)
}

#[inline(always)]
fn sign_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    if part.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    internal_sign_update(&mut session, part, part_len)
}

/// Implementation of C_SignUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203323](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203323)

pub extern "C" fn fn_sign_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_SignUpdate: s_handle={} part={:?} part_len={}",
        s_handle,
        part,
        part_len
    );
    let rv = match sign_update(s_handle, part, part_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SignUpdate: ret={}", rv);
    rv
}

#[inline(always)]
fn sign_final(
    s_handle: CK_SESSION_HANDLE,
    psignature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> Result<()> {
    if pul_signature_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Sign>()?;
    let signature_len = operation.signature_len()?;
    let sig_len =
        CK_ULONG::try_from(signature_len).map_err(|_| CKR_GENERAL_ERROR)?;
    if psignature.is_null() {
        unsafe {
            *pul_signature_len = sig_len;
        }
        return Ok(());
    }
    unsafe {
        if *pul_signature_len < sig_len {
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }
    }
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };
    operation.sign_final(signature)?;
    unsafe {
        *pul_signature_len = sig_len;
    }

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_SignFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203324](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203324)

pub extern "C" fn fn_sign_final(
    s_handle: CK_SESSION_HANDLE,
    psignature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_SignFinal: s_handle={} psignature={:?} pul_signature_len={:?}",
        s_handle,
        psignature,
        pul_signature_len
    );
    let rv = match sign_final(s_handle, psignature, pul_signature_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SignFinal: ret={}", rv);
    rv
}

/// Implementation of C_SignRecoverInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203325](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203325)

pub extern "C" fn fn_sign_recover_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignRecover function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203326](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203326)

pub extern "C" fn fn_sign_recover(
    _session: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[inline(always)]
fn verify_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn Verify>()?;
        return Ok(());
    }
    session.check_no_op::<dyn Verify>()?;
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_VERIFY == CKF_VERIFY {
        let operation = mech.verify_new(mechanism, &key)?;
        session.set_operation::<dyn Verify>(operation, false);

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_VERIFY, &key);

        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_VerifyInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203334](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203334)

pub extern "C" fn fn_verify_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_VerifyInit: s_handle={} mechptr={:?} key_handle={}",
        s_handle,
        mechptr,
        key_handle
    );
    let rv = match verify_init(s_handle, mechptr, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifyInit: ret={}", rv);
    rv
}

#[inline(always)]
fn verify(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    psignature: CK_BYTE_PTR,
    psignature_len: CK_ULONG,
) -> Result<()> {
    if pdata.is_null() || psignature.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Verify>()?;
    let signature_len = operation.signature_len()?;
    let sig_len =
        CK_ULONG::try_from(signature_len).map_err(|_| CKR_GENERAL_ERROR)?;
    if psignature_len != sig_len {
        return Err(CKR_SIGNATURE_LEN_RANGE)?;
    }
    let dlen = usize::try_from(data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let signature: &[u8] =
        unsafe { std::slice::from_raw_parts(psignature, signature_len) };
    operation.verify(data, signature)?;

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_Verify function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203335](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203335)

pub extern "C" fn fn_verify(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    psignature: CK_BYTE_PTR,
    psignature_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_Verify: s_handle={} pdata={:?} data_len={} psignature={:?} psignature_len={}",
        s_handle,
        pdata,
        data_len,
        psignature,
        psignature_len
    );
    let rv = match verify(s_handle, pdata, data_len, psignature, psignature_len)
    {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Verify: ret={}", rv);
    rv
}

/// Helper to perform "verify_update" in multiple places,

pub(crate) fn internal_verify_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    let operation = session.get_operation::<dyn Verify>()?;
    let plen = usize::try_from(part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.verify_update(data)
}

#[inline(always)]
fn verify_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    if part.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    internal_verify_update(&mut session, part, part_len)
}

/// Implementation of C_VerifyUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203336](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203336)

pub extern "C" fn fn_verify_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_VerifyUpdate: s_handle={} part={:?} part_len={}",
        s_handle,
        part,
        part_len
    );
    let rv = match verify_update(s_handle, part, part_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifyUpdate: ret={}", rv);
    rv
}

#[inline(always)]
fn verify_final(
    s_handle: CK_SESSION_HANDLE,
    psignature: CK_BYTE_PTR,
    psignature_len: CK_ULONG,
) -> Result<()> {
    if psignature.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Verify>()?;
    let signature_len = operation.signature_len()?;
    let sig_len =
        CK_ULONG::try_from(signature_len).map_err(|_| CKR_GENERAL_ERROR)?;
    if psignature_len != sig_len {
        return Err(CKR_SIGNATURE_LEN_RANGE)?;
    }
    let signature: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(psignature, signature_len) };
    operation.verify_final(signature)?;

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_VerifyFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203337](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203337)

pub extern "C" fn fn_verify_final(
    s_handle: CK_SESSION_HANDLE,
    psignature: CK_BYTE_PTR,
    psignature_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_VerifyFinal: s_handle={} psignature={:?} psignature_len={}",
        s_handle,
        psignature,
        psignature_len
    );
    let rv = match verify_final(s_handle, psignature, psignature_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifyFinal: ret={}", rv);
    rv
}

/// Implementation of C_VerifyRecoverInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203338](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203338)

pub extern "C" fn fn_verify_recover_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyRecover function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203339](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203339)

pub extern "C" fn fn_verify_recover(
    _session: CK_SESSION_HANDLE,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_MessageSignInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203328](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203328)

pub extern "C" fn fn_message_sign_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignMessage function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203329](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203329)

pub extern "C" fn fn_sign_message(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignMessageBegin function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203330](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203330)

pub extern "C" fn fn_sign_message_begin(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SignMessageNext function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203331](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203331)

pub extern "C" fn fn_sign_message_next(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_MessageSignFinal function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203332](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203332)

pub extern "C" fn fn_message_sign_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_MessageVerifyInit function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203341](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203341)

pub extern "C" fn fn_message_verify_init(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyMessage function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203342](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203342)

pub extern "C" fn fn_verify_message(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyMessageBegin function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203343](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203343)

pub extern "C" fn fn_verify_message_begin(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_VerifyMessageNext function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203344](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203344)

pub extern "C" fn fn_verify_message_next(
    _session: CK_SESSION_HANDLE,
    _parameter: CK_VOID_PTR,
    _parameter_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_MessageVerifyFinal function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203345](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203345)

pub extern "C" fn fn_message_verify_final(
    _session: CK_SESSION_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[inline(always)]
fn verify_signature_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    key_handle: CK_OBJECT_HANDLE,
    psignature: *mut CK_BYTE,
    psignature_len: CK_ULONG,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn VerifySignature>()?;
        return Ok(());
    }
    session.check_no_op::<dyn VerifySignature>()?;
    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    match check_allowed_mechs(mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_VERIFY != CKF_VERIFY {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let sig_len =
        usize::try_from(psignature_len).map_err(|_| CKR_GENERAL_ERROR)?;
    let signature: &[u8] =
        unsafe { std::slice::from_raw_parts(psignature, sig_len) };
    let operation = mech.verify_signature_new(mechanism, &key, signature)?;
    session.set_operation::<dyn VerifySignature>(operation, false);

    #[cfg(feature = "fips")]
    init_fips_approval(session, mechanism.mechanism, CKF_VERIFY, &key);

    Ok(())
}

/// Implementation of C_VerifySignatureInit
///
/// Version 3.2 Specification: [Link TBD]

pub extern "C" fn fn_verify_signature_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: *mut CK_MECHANISM,
    key_handle: CK_OBJECT_HANDLE,
    psignature: *mut CK_BYTE,
    psignature_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_VerifySignatureInit: s_handle={} mechptr={:?} key_handle={} psignature={:?} psignature_len={}",
        s_handle,
        mechptr,
        key_handle,
        psignature,
        psignature_len
    );
    let rv = match verify_signature_init(
        s_handle,
        mechptr,
        key_handle,
        psignature,
        psignature_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifySignatureInit: ret={}", rv);
    rv
}

#[inline(always)]
fn verify_signature(
    s_handle: CK_SESSION_HANDLE,
    pdata: *mut CK_BYTE,
    data_len: CK_ULONG,
) -> Result<()> {
    if pdata.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn VerifySignature>()?;
    let dlen = usize::try_from(data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    operation.verify(data)?;

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_VerifySignature
///
/// Version 3.2 Specification: [Link TBD]

pub extern "C" fn fn_verify_signature(
    s_handle: CK_SESSION_HANDLE,
    pdata: *mut CK_BYTE,
    data_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_VerifySignature: s_handle={} pdata={:?} data_len={}",
        s_handle,
        pdata,
        data_len
    );
    let rv = match verify_signature(s_handle, pdata, data_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifySignature: ret={}", rv);
    rv
}

#[inline(always)]
fn verify_signature_update(
    s_handle: CK_SESSION_HANDLE,
    part: *mut CK_BYTE,
    part_len: CK_ULONG,
) -> Result<()> {
    if part.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn VerifySignature>()?;
    let plen = usize::try_from(part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.verify_update(data)
}

/// Implementation of C_VerifySignatureUpdate
///
/// Version 3.2 Specification: [Link TBD]

pub extern "C" fn fn_verify_signature_update(
    s_handle: CK_SESSION_HANDLE,
    part: *mut CK_BYTE,
    part_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_VerifySignatureUpdate: s_handle={} part={:?} part_len={}",
        s_handle,
        part,
        part_len
    );
    let rv = match verify_signature_update(s_handle, part, part_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifySignatureUpdate: ret={}", rv);
    rv
}

#[inline(always)]
fn verify_signature_final(s_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn VerifySignature>()?;
    operation.verify_final()?;

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_VerifySignatureFinal
///
/// Version 3.2 Specification: [Link TBD]

pub extern "C" fn fn_verify_signature_final(
    s_handle: CK_SESSION_HANDLE,
) -> CK_RV {
    log_debug!("C_VerifySignatureFinal: s_handle={}", s_handle);
    let rv = match verify_signature_final(s_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_VerifySignatureFinal: ret={}", rv);
    rv
}

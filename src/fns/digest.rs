// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Message digesting functions
//!
//! This module contains the implementation of the Message Digesting functions
//! as defined in the PKCS#11 specification.

use std::sync::RwLockWriteGuard;

use crate::error::Result;
use crate::fns::log_debug;
use crate::mechanism::Digest;
use crate::pkcs11::*;
use crate::session::Session;
use crate::STATE;

#[cfg(feature = "fips")]
use crate::{finalize_fips_approval, init_fips_approval};

#[inline(always)]
fn digest_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;

    if mechptr.is_null() {
        session.cancel_operation::<dyn Digest>()?;
        return Ok(());
    }
    session.check_no_op::<dyn Digest>()?;

    let mechanism: &CK_MECHANISM = unsafe { &*mechptr };
    let token = rstate.get_token_from_slot(session.get_slot_id())?;
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_DIGEST == CKF_DIGEST {
        let operation = mech.digest_new(mechanism)?;
        session.set_operation::<dyn Digest>(operation, false);
        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_DigestInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203315)

pub extern "C" fn fn_digest_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
) -> CK_RV {
    log_debug!("C_DigestInit: s_handle={} mechptr={:?}", s_handle, mechptr);
    let rv = match digest_init(s_handle, mechptr) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DigestInit: ret={}", rv);
    rv
}

#[inline(always)]
fn digest(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> Result<()> {
    if pdata.is_null() || pul_digest_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Digest>()?;
    let digest_len = operation.digest_len()?;
    let dgst_len =
        CK_ULONG::try_from(digest_len).map_err(|_| CKR_GENERAL_ERROR)?;

    if pdigest.is_null() {
        unsafe {
            *pul_digest_len = dgst_len;
        }
        return Ok(());
    }
    unsafe {
        if *pul_digest_len < dgst_len {
            *pul_digest_len = dgst_len;
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }
    }
    let dlen = usize::try_from(data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let digest: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(pdigest, digest_len) };
    operation.digest(data, digest)?;

    unsafe {
        *pul_digest_len = dgst_len;
    }

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_Digest function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203316](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203316)

pub extern "C" fn fn_digest(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_Digest: s_handle={} pdata={:?} data_len={} pdigest={:?} pul_digest_len={:?}",
        s_handle,
        pdata,
        data_len,
        pdigest,
        pul_digest_len
    );
    let rv = match digest(s_handle, pdata, data_len, pdigest, pul_digest_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Digest: ret={}", rv);
    rv
}

/// Helper to perform "digest_update" in multiple places,
pub(crate) fn internal_digest_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    let operation = session.get_operation::<dyn Digest>()?;
    let plen = usize::try_from(part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
    operation.digest_update(data)
}

#[inline(always)]
fn digest_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> Result<()> {
    if part.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    internal_digest_update(&mut session, part, part_len)
}

/// Implementation of C_DigestUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203317](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203317)

pub extern "C" fn fn_digest_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_DigestUpdate: s_handle={} part={:?} part_len={}",
        s_handle,
        part,
        part_len
    );
    let rv = match digest_update(s_handle, part, part_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DigestUpdate: ret={}", rv);
    rv
}

#[inline(always)]
fn digest_key(
    s_handle: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let slot_id = session.get_slot_id();
    let operation = session.get_operation::<dyn Digest>()?;
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    if key.get_attr_as_ulong(CKA_CLASS)? != CKO_SECRET_KEY {
        return Err(CKR_KEY_HANDLE_INVALID)?;
    }
    match key.get_attr_as_ulong(CKA_KEY_TYPE)? {
        CKK_GENERIC_SECRET | CKK_AES => (),
        _ => return Err(CKR_KEY_INDIGESTIBLE)?,
    };
    let data = key.get_attr_as_bytes(CKA_VALUE)?;
    operation.digest_update(data)?;

    #[cfg(feature = "fips")]
    {
        /* need to do this last as we need to drop operation
         * before we can pass session mutably to a caller */
        let mech = operation.mechanism()?;
        init_fips_approval(session, mech, CKF_DIGEST, &key);
    }
    Ok(())
}

/// Implementation of C_DigestKey function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203318)

pub extern "C" fn fn_digest_key(
    s_handle: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_DigestKey: s_handle={} key_handle={}",
        s_handle,
        key_handle
    );
    let rv = match digest_key(s_handle, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DigestKey: ret={}", rv);
    rv
}

#[inline(always)]
fn digest_final(
    s_handle: CK_SESSION_HANDLE,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> Result<()> {
    if pul_digest_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Digest>()?;
    let digest_len = operation.digest_len()?;
    let dgst_len =
        CK_ULONG::try_from(digest_len).map_err(|_| CKR_GENERAL_ERROR)?;

    if pdigest.is_null() {
        unsafe {
            *pul_digest_len = dgst_len;
        }
        return Ok(());
    }
    unsafe {
        if *pul_digest_len < dgst_len {
            *pul_digest_len = dgst_len;
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }
    }
    let digest: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(pdigest, digest_len) };
    operation.digest_final(digest)?;

    unsafe {
        *pul_digest_len = dgst_len;
    }

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_DigestFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203319](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203319)

pub extern "C" fn fn_digest_final(
    s_handle: CK_SESSION_HANDLE,
    pdigest: CK_BYTE_PTR,
    pul_digest_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DigestFinal: s_handle={} pdigest={:?} pul_digest_len={:?}",
        s_handle,
        pdigest,
        pul_digest_len
    );
    let rv = match digest_final(s_handle, pdigest, pul_digest_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DigestFinal: ret={}", rv);
    rv
}

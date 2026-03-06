// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Encryption and Decryption functions
//!
//! This module contains the implementation of the Encryption and Decryption functions
//! as defined in the PKCS#11 specification.

use std::sync::RwLockWriteGuard;

use crate::check_allowed_mechs;
use crate::error::Result;
use crate::log_debug;
use crate::mechanism::{Decryption, Encryption, MsgDecryption, MsgEncryption};
use crate::pkcs11::*;
use crate::session::Session;
use crate::STATE;

#[cfg(feature = "fips")]
use crate::{finalize_fips_approval, init_fips_approval};

#[inline(always)]
fn encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn Encryption>()?;
        return Ok(());
    }
    session.check_no_op::<dyn Encryption>()?;

    let mechanism = CK_MECHANISM::from_ptr(mechptr);
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;

    match check_allowed_mechs(&mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }

    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_ENCRYPT == CKF_ENCRYPT {
        let operation = mech.encryption_new(&mechanism, &key)?;
        session.set_operation::<dyn Encryption>(operation, false);

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_ENCRYPT, &key);

        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_EncryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203293)

pub extern "C" fn fn_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_EncryptInit: s_handle={} mechptr={:?} key_handle={}",
        s_handle,
        mechptr,
        key_handle
    );
    let rv = match encrypt_init(s_handle, mechptr, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncryptInit: ret={}", rv);
    rv
}

#[inline(always)]
fn encrypt(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> Result<()> {
    if pdata.is_null() || pul_encrypted_data_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Encryption>()?;
    let dlen = usize::try_from(data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    if encrypted_data.is_null() {
        let encryption_len =
            CK_ULONG::try_from(operation.encryption_len(dlen, true)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_encrypted_data_len = encryption_len;
        }
        return Ok(());
    }
    let data: &[u8] = unsafe { std::slice::from_raw_parts(pdata, dlen) };
    let penclen = unsafe { *pul_encrypted_data_len as CK_ULONG };
    let enclen = usize::try_from(penclen).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let encdata: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(encrypted_data, enclen) };
    let outlen = operation.encrypt(data, encdata)?;
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_encrypted_data_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_Encrypt function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203294)

pub extern "C" fn fn_encrypt(
    s_handle: CK_SESSION_HANDLE,
    pdata: CK_BYTE_PTR,
    data_len: CK_ULONG,
    encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_Encrypt: s_handle={} pdata={:?} data_len={} encrypted_data={:?} pul_encrypted_data_len={:?}",
        s_handle,
        pdata,
        data_len,
        encrypted_data,
        pul_encrypted_data_len
    );
    let rv = match encrypt(
        s_handle,
        pdata,
        data_len,
        encrypted_data,
        pul_encrypted_data_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Encrypt: ret={}", rv);
    rv
}

/// Helper to perform "encrypt_update" in multiple places,

pub(crate) fn internal_encrypt_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let operation = session.get_operation::<dyn Encryption>()?;
    let plen = usize::try_from(part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let len = if encrypted_part.is_null() {
        operation.encryption_len(plen, false)?
    } else {
        let data: &[u8] = unsafe { std::slice::from_raw_parts(part, plen) };
        let penclen = unsafe { *pul_encrypted_part_len as CK_ULONG };
        let enclen = usize::try_from(penclen).map_err(|_| CKR_ARGUMENTS_BAD)?;
        let encpart: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(encrypted_part, enclen) };
        operation.encrypt_update(data, encpart)?
    };
    let cklen = CK_ULONG::try_from(len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    unsafe { *pul_encrypted_part_len = cklen };
    Ok(())
}

#[inline(always)]
fn encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> Result<()> {
    if part.is_null() || pul_encrypted_part_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    internal_encrypt_update(
        &mut session,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    )
}

/// Implementation of C_EncryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203295](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203295)

pub extern "C" fn fn_encrypt_update(
    s_handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
    encrypted_part: CK_BYTE_PTR,
    pul_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_EncryptUpdate: s_handle={} part={:?} part_len={} encrypted_part={:?} pul_encrypted_part_len={:?}",
        s_handle,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len
    );
    let rv = match encrypt_update(
        s_handle,
        part,
        part_len,
        encrypted_part,
        pul_encrypted_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncryptUpdate: ret={}", rv);
    rv
}

#[inline(always)]
fn encrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    if last_encrypted_part.is_null() && pul_last_encrypted_part_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Encryption>()?;
    if last_encrypted_part.is_null() {
        let encryption_len =
            CK_ULONG::try_from(operation.encryption_len(0, true)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_last_encrypted_part_len = encryption_len;
        }
        return Ok(());
    }
    let penclen = unsafe { *pul_last_encrypted_part_len as CK_ULONG };
    let enclen = usize::try_from(penclen).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let enclast: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(last_encrypted_part, enclen) };
    let outlen = operation.encrypt_final(enclast)?;
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_last_encrypted_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_EncryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203296](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203296)

pub extern "C" fn fn_encrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_encrypted_part: CK_BYTE_PTR,
    pul_last_encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_EncryptFinal: s_handle={} last_encrypted_part={:?} pul_last_encrypted_part_len={:?}",
        s_handle,
        last_encrypted_part,
        pul_last_encrypted_part_len
    );
    let rv = match encrypt_final(
        s_handle,
        last_encrypted_part,
        pul_last_encrypted_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncryptFinal: ret={}", rv);
    rv
}

#[inline(always)]
fn decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn Decryption>()?;
        return Ok(());
    }
    session.check_no_op::<dyn Decryption>()?;
    let mechanism = CK_MECHANISM::from_ptr(mechptr);
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    match check_allowed_mechs(&mechanism, &key) {
        CKR_OK => (),
        err => return Err(err)?,
    }
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_DECRYPT == CKF_DECRYPT {
        let operation = mech.decryption_new(&mechanism, &key)?;
        session.set_operation::<dyn Decryption>(operation, key.always_auth());

        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_DECRYPT, &key);

        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_DecryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203304)

pub extern "C" fn fn_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_DecryptInit: s_handle={} mechptr={:?} key_handle={}",
        s_handle,
        mechptr,
        key_handle
    );
    let rv = match decrypt_init(s_handle, mechptr, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptInit: ret={}", rv);
    rv
}

#[inline(always)]
fn decrypt(
    s_handle: CK_SESSION_HANDLE,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> Result<()> {
    if encrypted_data.is_null() || pul_data_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Decryption>()?;
    let elen =
        usize::try_from(encrypted_data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    if data.is_null() {
        let decryption_len =
            CK_ULONG::try_from(operation.decryption_len(elen, true)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_data_len = decryption_len;
        }
        return Ok(());
    }
    let enc: &[u8] =
        unsafe { std::slice::from_raw_parts(encrypted_data, elen) };
    let pdlen = unsafe { *pul_data_len as CK_ULONG };
    let dlen = usize::try_from(pdlen).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let ddata: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(data, dlen) };
    let outlen = operation.decrypt(enc, ddata)?;
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_data_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_Decrypt function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203305)

pub extern "C" fn fn_decrypt(
    s_handle: CK_SESSION_HANDLE,
    encrypted_data: CK_BYTE_PTR,
    encrypted_data_len: CK_ULONG,
    data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_Decrypt: s_handle={} encrypted_data={:?} encrypted_data_len={} data={:?} pul_data_len={:?}",
        s_handle,
        encrypted_data,
        encrypted_data_len,
        data,
        pul_data_len
    );
    let rv = match decrypt(
        s_handle,
        encrypted_data,
        encrypted_data_len,
        data,
        pul_data_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Decrypt: ret={}", rv);
    rv
}

/// Helper to perform "decrypt_update" in multiple places,

pub(crate) fn internal_decrypt_update(
    session: &mut RwLockWriteGuard<'_, Session>,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> Result<()> {
    let operation = session.get_operation::<dyn Decryption>()?;
    let elen =
        usize::try_from(encrypted_part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let len = if part.is_null() {
        operation.decryption_len(elen, false)?
    } else {
        let enc: &[u8] =
            unsafe { std::slice::from_raw_parts(encrypted_part, elen) };
        let pplen = unsafe { *pul_part_len as CK_ULONG };
        let plen = usize::try_from(pplen).map_err(|_| CKR_ARGUMENTS_BAD)?;
        let dpart: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(part, plen) };
        operation.decrypt_update(enc, dpart)?
    };
    let cklen = CK_ULONG::try_from(len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    unsafe { *pul_part_len = cklen };
    Ok(())
}

#[inline(always)]
fn decrypt_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> Result<()> {
    if encrypted_part.is_null() || pul_part_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    internal_decrypt_update(
        &mut session,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    )
}

/// Implementation of C_DecryptUpdate function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203306](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203306)

pub extern "C" fn fn_decrypt_update(
    s_handle: CK_SESSION_HANDLE,
    encrypted_part: CK_BYTE_PTR,
    encrypted_part_len: CK_ULONG,
    part: CK_BYTE_PTR,
    pul_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DecryptUpdate: s_handle={} encrypted_part={:?} encrypted_part_len={} part={:?} pul_part_len={:?}",
        s_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len
    );
    let rv = match decrypt_update(
        s_handle,
        encrypted_part,
        encrypted_part_len,
        part,
        pul_part_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptUpdate: ret={}", rv);
    rv
}

#[inline(always)]
fn decrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> Result<()> {
    if last_part.is_null() && pul_last_part_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn Decryption>()?;
    if last_part.is_null() {
        let decryption_len =
            CK_ULONG::try_from(operation.decryption_len(0, true)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_last_part_len = decryption_len;
        }
        return Ok(());
    }
    let pplen = unsafe { *pul_last_part_len as CK_ULONG };
    let plen = usize::try_from(pplen).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let dlast: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(last_part, plen) };
    let outlen = operation.decrypt_final(dlast)?;
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_last_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_DecryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203307](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203307)

pub extern "C" fn fn_decrypt_final(
    s_handle: CK_SESSION_HANDLE,
    last_part: CK_BYTE_PTR,
    pul_last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DecryptFinal: s_handle={} last_part={:?} pul_last_part_len={:?}",
        s_handle,
        last_part,
        pul_last_part_len
    );
    let rv = match decrypt_final(s_handle, last_part, pul_last_part_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptFinal: ret={}", rv);
    rv
}

#[inline(always)]
fn message_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn MsgEncryption>()?;
        return Ok(());
    }
    session.check_no_op::<dyn MsgEncryption>()?;
    let mechanism = CK_MECHANISM::from_ptr(mechptr);
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    match check_allowed_mechs(&mechanism, &key) {
        CKR_OK => {}
        err => return Err(err)?,
    }
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_MESSAGE_ENCRYPT != 0 {
        let operation = mech.msg_encryption_op(&mechanism, &key)?;
        session.set_operation::<dyn MsgEncryption>(operation, false);
        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_ENCRYPT, &key);

        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_MessageEncryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203298](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203298)

pub extern "C" fn fn_message_encrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_MessageEncryptInit: s_handle={} mechptr={:?} key_handle={}",
        s_handle,
        mechptr,
        key_handle
    );
    let rv = match message_encrypt_init(s_handle, mechptr, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_MessageEncryptInit: ret={}", rv);
    rv
}

#[inline(always)]
fn encrypt_message(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    plaintext: CK_BYTE_PTR,
    plaintext_len: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    pul_ciphertext_len: CK_ULONG_PTR,
) -> Result<()> {
    if parameter.is_null()
        || parameter_len == 0
        || plaintext.is_null()
        || plaintext_len == 0
        || pul_ciphertext_len.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let alen =
        usize::try_from(associated_data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let plen = usize::try_from(plaintext_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let pclen = unsafe { *pul_ciphertext_len as CK_ULONG };
    let clen = usize::try_from(pclen).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn MsgEncryption>()?;
    if operation.busy() {
        return Err(CKR_OPERATION_ACTIVE)?;
    }

    if ciphertext.is_null() {
        let retlen =
            CK_ULONG::try_from(operation.msg_encryption_len(plen, false)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_ciphertext_len = retlen;
        }
        return Ok(());
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    let plain: &[u8] = unsafe { std::slice::from_raw_parts(plaintext, plen) };
    let cipher: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(ciphertext, clen) };

    let outlen = operation.msg_encrypt(
        parameter,
        parameter_len,
        adata,
        plain,
        cipher,
    )?;
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_ciphertext_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_EncryptMessage function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203299](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203299)

pub extern "C" fn fn_encrypt_message(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    plaintext: CK_BYTE_PTR,
    plaintext_len: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    pul_ciphertext_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_EncryptMessage: s_handle={} parameter={:?} parameter_len={} associated_data={:?} associated_data_len={} plaintext={:?} plaintext_len={} ciphertext={:?} pul_ciphertext_len={:?}",
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len,
        plaintext,
        plaintext_len,
        ciphertext,
        pul_ciphertext_len
    );
    let rv = match encrypt_message(
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len,
        plaintext,
        plaintext_len,
        ciphertext,
        pul_ciphertext_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncryptMessage: ret={}", rv);
    rv
}

#[inline(always)]
fn encrypt_message_begin(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
) -> Result<()> {
    if parameter.is_null() || parameter_len == 0 {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let alen =
        usize::try_from(associated_data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    session.reset_fips_indicator();

    let operation = session.get_operation::<dyn MsgEncryption>()?;
    if operation.busy() {
        return Err(CKR_OPERATION_ACTIVE)?;
    }

    let token = rstate.get_token_from_slot_mut(slot_id)?;
    let mechanism = operation.mechanism()?;
    let mech = token.get_mechanisms().get(mechanism)?;
    if mech.info().flags & CKF_MULTI_MESSAGE == 0 {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    operation.msg_encrypt_begin(parameter, parameter_len, adata)
}

/// Implementation of C_EncryptMessageBegin function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203300](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203300)

pub extern "C" fn fn_encrypt_message_begin(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_EncryptMessageBegin: s_handle={} parameter={:?} parameter_len={} associated_data={:?} associated_data_len={}",
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len
    );
    let rv = match encrypt_message_begin(
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncryptMessageBegin: ret={}", rv);
    rv
}

#[inline(always)]
fn encrypt_message_next(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    plaintext_part: CK_BYTE_PTR,
    plaintext_part_len: CK_ULONG,
    ciphertext_part: CK_BYTE_PTR,
    pul_ciphertext_part_len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> Result<()> {
    if parameter.is_null()
        || parameter_len == 0
        || plaintext_part.is_null()
        || plaintext_part_len == 0
        || pul_ciphertext_part_len.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let plen =
        usize::try_from(plaintext_part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let pclen = unsafe { *pul_ciphertext_part_len as CK_ULONG };
    let clen = usize::try_from(pclen).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let fin = match flags {
        CKF_END_OF_MESSAGE => true,
        0 => false,
        _ => return Err(CKR_ARGUMENTS_BAD)?,
    };

    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn MsgEncryption>()?;
    if !operation.busy() {
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    if ciphertext_part.is_null() {
        let retlen =
            CK_ULONG::try_from(operation.msg_encryption_len(plen, fin)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_ciphertext_part_len = retlen;
        }
        return Ok(());
    }

    let plain: &[u8] =
        unsafe { std::slice::from_raw_parts(plaintext_part, plen) };
    let cipher: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(ciphertext_part, clen) };

    let outlen = match fin {
        false => operation.msg_encrypt_next(
            parameter,
            parameter_len,
            plain,
            cipher,
        )?,
        true => operation.msg_encrypt_final(
            parameter,
            parameter_len,
            plain,
            cipher,
        )?,
    };
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_ciphertext_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_EncryptMessageNext function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203301](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203301)

pub extern "C" fn fn_encrypt_message_next(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    plaintext_part: CK_BYTE_PTR,
    plaintext_part_len: CK_ULONG,
    ciphertext_part: CK_BYTE_PTR,
    pul_ciphertext_part_len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    log_debug!(
        "C_EncryptMessageNext: s_handle={} parameter={:?} parameter_len={} plaintext_part={:?} plaintext_part_len={} ciphertext_part={:?} pul_ciphertext_part_len={:?} flags={}",
        s_handle,
        parameter,
        parameter_len,
        plaintext_part,
        plaintext_part_len,
        ciphertext_part,
        pul_ciphertext_part_len,
        flags
    );
    let rv = match encrypt_message_next(
        s_handle,
        parameter,
        parameter_len,
        plaintext_part,
        plaintext_part_len,
        ciphertext_part,
        pul_ciphertext_part_len,
        flags,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_EncryptMessageNext: ret={}", rv);
    rv
}

#[inline(always)]
fn message_encrypt_final(s_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn MsgEncryption>()?;
    operation.finalize()
}

/// Implementation of C_MessageEncryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203302](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203302)

pub extern "C" fn fn_message_encrypt_final(
    s_handle: CK_SESSION_HANDLE,
) -> CK_RV {
    log_debug!("C_MessageEncryptFinal: s_handle={}", s_handle);
    let rv = match message_encrypt_final(s_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_MessageEncryptFinal: ret={}", rv);
    rv
}

#[inline(always)]
fn message_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if mechptr.is_null() {
        session.cancel_operation::<dyn MsgDecryption>()?;
        return Ok(());
    }
    session.check_no_op::<dyn MsgDecryption>()?;
    let mechanism = CK_MECHANISM::from_ptr(mechptr);
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let key = token.get_object_by_handle(key_handle)?;
    match check_allowed_mechs(&mechanism, &key) {
        CKR_OK => (),

        err => return Err(err)?,
    }
    let mech = token.get_mechanisms().get(mechanism.mechanism)?;
    if mech.info().flags & CKF_MESSAGE_DECRYPT != 0 {
        let operation = mech.msg_decryption_op(&mechanism, &key)?;
        session.set_operation::<dyn MsgDecryption>(operation, false);
        #[cfg(feature = "fips")]
        init_fips_approval(session, mechanism.mechanism, CKF_DECRYPT, &key);

        Ok(())
    } else {
        Err(CKR_MECHANISM_INVALID)?
    }
}

/// Implementation of C_MessageDecryptInit function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203309](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203309)

pub extern "C" fn fn_message_decrypt_init(
    s_handle: CK_SESSION_HANDLE,
    mechptr: CK_MECHANISM_PTR,
    key_handle: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_MessageDecryptInit: s_handle={} mechptr={:?} key_handle={}",
        s_handle,
        mechptr,
        key_handle
    );
    let rv = match message_decrypt_init(s_handle, mechptr, key_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_MessageDecryptInit: ret={}", rv);
    rv
}

#[inline(always)]
fn decrypt_message(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    ciphertext_len: CK_ULONG,
    plaintext: CK_BYTE_PTR,
    pul_plaintext_len: CK_ULONG_PTR,
) -> Result<()> {
    if parameter.is_null()
        || parameter_len == 0
        || ciphertext.is_null()
        || ciphertext_len == 0
        || pul_plaintext_len.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let alen =
        usize::try_from(associated_data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let clen =
        usize::try_from(ciphertext_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let pplen = unsafe { *pul_plaintext_len as CK_ULONG };
    let plen = usize::try_from(pplen).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn MsgDecryption>()?;
    if operation.busy() {
        return Err(CKR_OPERATION_ACTIVE)?;
    }

    if plaintext.is_null() {
        let retlen =
            CK_ULONG::try_from(operation.msg_decryption_len(clen, false)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_plaintext_len = retlen;
        }
        return Ok(());
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    let cipher: &[u8] = unsafe { std::slice::from_raw_parts(ciphertext, clen) };
    let plain: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(plaintext, plen) };

    let outlen = operation.msg_decrypt(
        parameter,
        parameter_len,
        adata,
        cipher,
        plain,
    )?;
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_plaintext_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

/// Implementation of C_DecryptMessage function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203310](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203310)

pub extern "C" fn fn_decrypt_message(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
    ciphertext: CK_BYTE_PTR,
    ciphertext_len: CK_ULONG,
    plaintext: CK_BYTE_PTR,
    pul_plaintext_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_DecryptMessage: s_handle={} parameter={:?} parameter_len={} associated_data={:?} associated_data_len={} ciphertext={:?} ciphertext_len={} plaintext={:?} pul_plaintext_len={:?}",
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len,
        ciphertext,
        ciphertext_len,
        plaintext,
        pul_plaintext_len
    );
    let rv = match decrypt_message(
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len,
        ciphertext,
        ciphertext_len,
        plaintext,
        pul_plaintext_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptMessage: ret={}", rv);
    rv
}

#[inline(always)]
fn decrypt_message_begin(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
) -> Result<()> {
    if parameter.is_null() || parameter_len == 0 {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let alen =
        usize::try_from(associated_data_len).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let slot_id = session.get_slot_id();

    #[cfg(feature = "fips")]
    session.reset_fips_indicator();

    let operation = session.get_operation::<dyn MsgDecryption>()?;
    if operation.busy() {
        return Err(CKR_OPERATION_ACTIVE)?;
    }

    let token = rstate.get_token_from_slot_mut(slot_id)?;
    let mechanism = operation.mechanism()?;
    let mech = token.get_mechanisms().get(mechanism)?;
    if mech.info().flags & CKF_MULTI_MESSAGE == 0 {
        return Err(CKR_MECHANISM_INVALID)?;
    }

    let adata: &[u8] = if associated_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(associated_data, alen) }
    };
    operation.msg_decrypt_begin(parameter, parameter_len, adata)
}

/// Implementation of C_DecryptMessageBegin function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203311](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203311)

pub extern "C" fn fn_decrypt_message_begin(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    associated_data: CK_BYTE_PTR,
    associated_data_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_DecryptMessageBegin: s_handle={} parameter={:?} parameter_len={} associated_data={:?} associated_data_len={}",
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len
    );
    let rv = match decrypt_message_begin(
        s_handle,
        parameter,
        parameter_len,
        associated_data,
        associated_data_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptMessageBegin: ret={}", rv);
    rv
}

#[inline(always)]
fn decrypt_message_next(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    ciphertext_part: CK_BYTE_PTR,
    ciphertext_part_len: CK_ULONG,
    plaintext_part: CK_BYTE_PTR,
    pul_plaintext_part_len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> Result<()> {
    if parameter.is_null()
        || parameter_len == 0
        || ciphertext_part.is_null()
        || ciphertext_part_len == 0
        || pul_plaintext_part_len.is_null()
    {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let clen =
        usize::try_from(ciphertext_part_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let pplen = unsafe { *pul_plaintext_part_len as CK_ULONG };
    let plen = usize::try_from(pplen).map_err(|_| CKR_ARGUMENTS_BAD)?;

    let fin = match flags {
        CKF_END_OF_MESSAGE => true,
        0 => false,
        _ => return Err(CKR_ARGUMENTS_BAD)?,
    };

    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn MsgDecryption>()?;
    if !operation.busy() {
        return Err(CKR_OPERATION_NOT_INITIALIZED)?;
    }

    if plaintext_part.is_null() {
        let retlen =
            CK_ULONG::try_from(operation.msg_decryption_len(clen, fin)?)
                .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_plaintext_part_len = retlen;
        }
        return Ok(());
    }

    let cipher: &[u8] =
        unsafe { std::slice::from_raw_parts(ciphertext_part, clen) };
    let plain: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(plaintext_part, plen) };

    let outlen = match fin {
        false => operation.msg_decrypt_next(
            parameter,
            parameter_len,
            cipher,
            plain,
        )?,
        true => operation.msg_decrypt_final(
            parameter,
            parameter_len,
            cipher,
            plain,
        )?,
    };
    let retlen = CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe { *pul_plaintext_part_len = retlen };

    #[cfg(feature = "fips")]
    {
        let approved = operation.fips_approved();
        finalize_fips_approval(session, approved);
    }
    Ok(())
}

pub extern "C" fn fn_decrypt_message_next(
    s_handle: CK_SESSION_HANDLE,
    parameter: CK_VOID_PTR,
    parameter_len: CK_ULONG,
    ciphertext_part: CK_BYTE_PTR,
    ciphertext_part_len: CK_ULONG,
    plaintext_part: CK_BYTE_PTR,
    pul_plaintext_part_len: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    log_debug!(
        "C_DecryptMessageNext: s_handle={} parameter={:?} parameter_len={} ciphertext_part={:?} ciphertext_part_len={} plaintext_part={:?} pul_plaintext_part_len={:?} flags={}",
        s_handle,
        parameter,
        parameter_len,
        ciphertext_part,
        ciphertext_part_len,
        plaintext_part,
        pul_plaintext_part_len,
        flags
    );
    let rv = match decrypt_message_next(
        s_handle,
        parameter,
        parameter_len,
        ciphertext_part,
        ciphertext_part_len,
        plaintext_part,
        pul_plaintext_part_len,
        flags,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_DecryptMessageNext: ret={}", rv);
    rv
}

#[inline(always)]
fn message_decrypt_final(s_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let operation = session.get_operation::<dyn MsgDecryption>()?;
    operation.finalize()
}

/// Implementation of C_MessageDecryptFinal function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203313](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203313)

pub extern "C" fn fn_message_decrypt_final(
    s_handle: CK_SESSION_HANDLE,
) -> CK_RV {
    log_debug!("C_MessageDecryptFinal: s_handle={}", s_handle);
    let rv = match message_decrypt_final(s_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_MessageDecryptFinal: ret={}", rv);
    rv
}

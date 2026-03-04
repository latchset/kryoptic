// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Session Management functions
//!
//! This module contains the implementation of the Session Management functions
//! as defined in the PKCS#11 specification.

use crate::error::Result;
use crate::log_debug;
use crate::mechanism::{
    Decryption, Digest, Encryption, MsgDecryption, MsgEncryption,
    SearchOperation, Sign, Verify,
};
use crate::misc::bytes_to_slice;
use crate::object::Object;
use crate::pkcs11::*;
use crate::STATE;

#[inline(always)]
fn open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> Result<()> {
    if ph_session.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let mut wstate = STATE.wlock()?;
    let token = wstate.get_token_from_slot(slot_id)?;
    let mut user_type = CK_UNAVAILABLE_INFORMATION;
    if token.is_logged_in(CKU_SO) {
        if flags & CKF_RW_SESSION == 0 {
            return Err(CKR_SESSION_READ_WRITE_SO_EXISTS)?;
        }
        user_type = CKU_SO;
    } else if token.is_logged_in(CKU_USER) {
        user_type = CKU_USER;
    }
    drop(token);
    let handle = wstate.new_session(slot_id, user_type, flags)?;
    unsafe {
        core::ptr::write(ph_session as *mut _, handle);
    }
    Ok(())
}

/// Implementation of C_OpenSession function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203272](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203272)
pub extern "C" fn fn_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    application: CK_VOID_PTR,
    notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    log_debug!(
        "C_OpenSession: slot_id={} flags={} application={:?} notify={:?} ph_session={:?}",
        slot_id,
        flags,
        application,
        notify,
        ph_session
    );
    let rv = match open_session(slot_id, flags, application, notify, ph_session)
    {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_OpenSession: ret={}", rv);
    rv
}

#[inline(always)]
fn close_session(s_handle: CK_SESSION_HANDLE) -> Result<()> {
    let mut wstate = STATE.wlock()?;
    let mut token = wstate.get_token_from_session_mut(s_handle)?;
    token.drop_session_objects(s_handle);
    drop(token);
    wstate.drop_session(s_handle)?;
    Ok(())
}

/// Implementation of C_CloseSession function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203273](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203273)
pub extern "C" fn fn_close_session(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    log_debug!("C_CloseSession: s_handle={}", s_handle);
    let rv = match close_session(s_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_CloseSession: ret={}", rv);
    rv
}

#[inline(always)]
fn close_all_sessions(slot_id: CK_SLOT_ID) -> Result<()> {
    let mut wstate = STATE.wlock()?;
    let dropped_sessions = wstate.drop_all_sessions_slot(slot_id)?;
    let mut token = wstate.get_token_from_slot_mut(slot_id)?;
    for handle in dropped_sessions {
        token.drop_session_objects(handle);
    }
    /* The spec requires the token to logout once the last session is closed */
    token.logout();
    Ok(())
}

/// Implementation of C_CloseAllSessions function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203274](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203274)
pub extern "C" fn fn_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    log_debug!("C_CloseAllSessions: slot_id={}", slot_id);
    let rv = match close_all_sessions(slot_id) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_CloseAllSessions: ret={}", rv);
    rv
}

#[inline(always)]
fn get_session_info(
    s_handle: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> Result<()> {
    if info.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    unsafe {
        core::ptr::write(info as *mut _, *session.get_session_info());
    }
    Ok(())
}

/// Implementation of C_GetSessionInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203275](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203275)
pub extern "C" fn fn_get_session_info(
    s_handle: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    log_debug!("C_GetSessionInfo: s_handle={} info={:?}", s_handle, info);
    let rv = match get_session_info(s_handle, info) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetSessionInfo: ret={}", rv);
    rv
}

#[inline(always)]
fn get_operation_state(
    s_handle: CK_SESSION_HANDLE,
    operation_state: CK_BYTE_PTR,
    pul_operation_state_len: CK_ULONG_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    if operation_state.is_null() {
        if pul_operation_state_len.is_null() {
            return Err(CKR_ARGUMENTS_BAD)?;
        }
        let state_len = CK_ULONG::try_from(session.state_size()?)
            .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *pul_operation_state_len = state_len;
        }
        return Ok(());
    }
    let state_len = if pul_operation_state_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    } else {
        usize::try_from(unsafe { *pul_operation_state_len })
            .map_err(|_| CKR_ARGUMENTS_BAD)?
    };

    let state: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(operation_state, state_len) };
    let slot_id = session.get_slot_id();
    let token = rstate.get_token_from_slot(slot_id)?;
    let outlen = session.state_save(token.get_mechanisms(), state)?;
    unsafe {
        *pul_operation_state_len =
            CK_ULONG::try_from(outlen).map_err(|_| CKR_GENERAL_ERROR)?
    };
    Ok(())
}

/// Implementation of C_GetOperationState function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203277](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203277)
pub extern "C" fn fn_get_operation_state(
    s_handle: CK_SESSION_HANDLE,
    operation_state: CK_BYTE_PTR,
    pul_operation_state_len: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_GetOperationState: s_handle={} operation_state={:?} pul_operation_state_len={:?}",
        s_handle,
        operation_state,
        pul_operation_state_len
    );
    let rv = match get_operation_state(
        s_handle,
        operation_state,
        pul_operation_state_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetOperationState: ret={}", rv);
    rv
}

#[inline(always)]
fn set_operation_state(
    s_handle: CK_SESSION_HANDLE,
    operation_state: CK_BYTE_PTR,
    operation_state_len: CK_ULONG,
    encryption_key: CK_OBJECT_HANDLE,
    authentication_key: CK_OBJECT_HANDLE,
) -> Result<()> {
    if encryption_key != CK_INVALID_HANDLE {
        return Err(CKR_KEY_NOT_NEEDED)?;
    }
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let state_len =
        usize::try_from(operation_state_len).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let state: &[u8] =
        unsafe { std::slice::from_raw_parts(operation_state, state_len) };
    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;

    let mut key: Option<Object> = None;
    if authentication_key != CK_INVALID_HANDLE {
        key = Some(token.get_object_by_handle(authentication_key)?);
    }
    session.state_restore(token.get_mechanisms(), state, key.as_ref())?;
    Ok(())
}

/// Implementation of C_SetOperationState function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203278](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203278)
pub extern "C" fn fn_set_operation_state(
    s_handle: CK_SESSION_HANDLE,
    operation_state: CK_BYTE_PTR,
    operation_state_len: CK_ULONG,
    encryption_key: CK_OBJECT_HANDLE,
    authentication_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    log_debug!(
        "C_SetOperationState: s_handle={} operation_state={:?} operation_state_len={} encryption_key={} authentication_key={}",
        s_handle,
        operation_state,
        operation_state_len,
        encryption_key,
        authentication_key
    );
    let rv = match set_operation_state(
        s_handle,
        operation_state,
        operation_state_len,
        encryption_key,
        authentication_key,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SetOperationState: ret={}", rv);
    rv
}

#[inline(always)]
fn login(
    s_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    let slot_id = session.get_slot_id();
    /* avoid deadlock later when we change all sessions */
    drop(session);
    if user_type == CKU_SO {
        if rstate.has_ro_sessions(slot_id)? {
            return Err(CKR_SESSION_READ_ONLY_EXISTS)?;
        }
    }
    let vpin = unsafe { bytes_to_slice(pin as *const u8, pin_len as usize) };
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    if user_type == CKU_CONTEXT_SPECIFIC {
        let session = rstate.get_session_mut(s_handle)?;
        match session.check_login_status() {
            Err(e) => match e.rv() {
                CKR_USER_NOT_LOGGED_IN => (),
                _ => return Err(CKR_OPERATION_NOT_INITIALIZED)?,
            },
            Ok(()) => return Err(CKR_OPERATION_NOT_INITIALIZED)?,
        }
    }

    let result = token.login(user_type, &vpin);

    if user_type == CKU_CONTEXT_SPECIFIC {
        match result {
            CKR_OK => {
                let mut session = rstate.get_session_mut(s_handle)?;
                session.set_login_ok();
            }
            CKR_PIN_LOCKED => {
                token.logout();
                let _ = rstate.invalidate_session_states(slot_id);
            }
            _ => (),
        }
        if result != CKR_OK {
            return Err(result)?;
        }
        Ok(())
    } else {
        match result {
            CKR_OK => match rstate.change_session_states(slot_id, user_type) {
                Ok(()) => Ok(()),
                Err(e) => {
                    token.logout();
                    let _ = rstate.invalidate_session_states(slot_id);
                    Err(e)?
                }
            },
            err => Err(err)?,
        }
    }
}

/// Implementation of C_Login function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203279](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203279)
pub extern "C" fn fn_login(
    s_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_Login: s_handle={} user_type={} pin={:?} pin_len={}",
        s_handle,
        user_type,
        pin,
        pin_len
    );
    let rv = match login(s_handle, user_type, pin, pin_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Login: ret={}", rv);
    rv
}

#[inline(always)]
fn logout(s_handle: CK_SESSION_HANDLE) -> Result<()> {
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    let slot_id = session.get_slot_id();
    /* avoid deadlock later when we change all sessions */
    drop(session);
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let ret = token.logout();
    if ret == CKR_OK {
        let _ = rstate.invalidate_session_states(slot_id);
    }
    if ret != CKR_OK {
        return Err(ret)?;
    }
    Ok(())
}

/// Implementation of C_Logout function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203281](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203281)
pub extern "C" fn fn_logout(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    log_debug!("C_Logout: s_handle={}", s_handle);
    let rv = match logout(s_handle) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Logout: ret={}", rv);
    rv
}

#[inline(always)]
fn login_user(
    _s_handle: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
    _username: CK_UTF8CHAR_PTR,
    _username_len: CK_ULONG,
) -> Result<()> {
    Err(CKR_FUNCTION_NOT_SUPPORTED)?
}

/// Implementation of C_LoginUser function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203280](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203280)
pub extern "C" fn fn_login_user(
    s_handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    username: CK_UTF8CHAR_PTR,
    username_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_LoginUser: s_handle={} user_type={} pin={:?} pin_len={} username={:?} username_len={}",
        s_handle,
        user_type,
        pin,
        pin_len,
        username,
        username_len
    );
    let rv = match login_user(
        s_handle,
        user_type,
        pin,
        pin_len,
        username,
        username_len,
    ) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_LoginUser: ret={}", rv);
    rv
}

#[inline(always)]
fn session_cancel(s_handle: CK_SESSION_HANDLE, flags: CK_FLAGS) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut session = rstate.get_session_mut(s_handle)?;
    let mut res = CKR_OK;

    if flags & CKF_MESSAGE_ENCRYPT != 0 {
        if session.cancel_operation::<dyn MsgEncryption>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_MESSAGE_DECRYPT != 0 {
        if session.cancel_operation::<dyn MsgDecryption>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_MESSAGE_SIGN != 0 {
        /* TODO */
        res = CKR_OPERATION_CANCEL_FAILED;
    }
    if flags & CKF_MESSAGE_VERIFY != 0 {
        /* TODO */
        res = CKR_OPERATION_CANCEL_FAILED;
    }
    if flags & CKF_FIND_OBJECTS != 0 {
        if session.cancel_operation::<dyn SearchOperation>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_ENCRYPT != 0 {
        if session.cancel_operation::<dyn Encryption>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_DECRYPT != 0 {
        if session.cancel_operation::<dyn Decryption>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_DIGEST != 0 {
        if session.cancel_operation::<dyn Digest>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_SIGN != 0 {
        if session.cancel_operation::<dyn Sign>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if flags & CKF_VERIFY != 0 {
        if session.cancel_operation::<dyn Verify>().is_err() {
            res = CKR_OPERATION_CANCEL_FAILED;
        }
    }
    if res != CKR_OK {
        Err(res)?
    }
    Ok(())
}

/// Implementation of C_SessionCancel function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203276](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203276)
pub extern "C" fn fn_session_cancel(
    s_handle: CK_SESSION_HANDLE,
    flags: CK_FLAGS,
) -> CK_RV {
    log_debug!("C_SessionCancel: s_handle={} flags={}", s_handle, flags);
    let rv = match session_cancel(s_handle, flags) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SessionCancel: ret={}", rv);
    rv
}

#[inline(always)]
fn get_session_validation_flags(
    s_handle: CK_SESSION_HANDLE,
    flags_type: CK_SESSION_VALIDATION_FLAGS_TYPE,
    pflags: CK_FLAGS_PTR,
) -> Result<()> {
    if pflags.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let flags: CK_FLAGS = if flags_type != CKS_LAST_VALIDATION_OK {
        0
    } else {
        let rstate = STATE.rlock()?;
        let session = rstate.get_session(s_handle)?;

        session.get_last_validation_flags()
    };
    unsafe { *pflags = flags };
    Ok(())
}

/// Implementation of C_GetSessionValidationFlags
///
/// Version 3.2 Specification: [Link TBD]
pub extern "C" fn fn_get_session_validation_flags(
    s_handle: CK_SESSION_HANDLE,
    flags_type: CK_SESSION_VALIDATION_FLAGS_TYPE,
    pflags: CK_FLAGS_PTR,
) -> CK_RV {
    log_debug!(
        "C_GetSessionValidationFlags: s_handle={} flags_type={} pflags={:?}",
        s_handle,
        flags_type,
        pflags
    );
    let rv = match get_session_validation_flags(s_handle, flags_type, pflags) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetSessionValidationFlags: ret={}", rv);
    rv
}

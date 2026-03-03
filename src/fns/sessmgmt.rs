// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Session Management functions
//!
//! This module contains the implementation of the Session Management functions
//! as defined in the PKCS#11 specification.

use crate::mechanism::{
    Decryption, Digest, Encryption, MsgDecryption, MsgEncryption,
    SearchOperation, Sign, Verify,
};
use crate::misc::bytes_to_slice;
use crate::pkcs11::*;
use crate::{
    cast_or_ret, global_rlock, global_wlock, object, res_or_ret, ret_to_rv,
    STATE,
};

/// Implementation of C_OpenSession function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203272](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203272)
pub extern "C" fn fn_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    let mut wstate = global_wlock!((*STATE));
    let token = res_or_ret!(wstate.get_token_from_slot(slot_id));
    let mut user_type = CK_UNAVAILABLE_INFORMATION;
    if token.is_logged_in(CKU_SO) {
        if flags & CKF_RW_SESSION == 0 {
            return CKR_SESSION_READ_WRITE_SO_EXISTS;
        }
        user_type = CKU_SO;
    } else if token.is_logged_in(CKU_USER) {
        user_type = CKU_USER;
    }
    drop(token);
    let handle = res_or_ret!(wstate.new_session(slot_id, user_type, flags));
    unsafe {
        core::ptr::write(ph_session as *mut _, handle);
    }
    CKR_OK
}

/// Implementation of C_CloseSession function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203273](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203273)
pub extern "C" fn fn_close_session(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut wstate = global_wlock!((*STATE));
    let mut token = res_or_ret!(wstate.get_token_from_session_mut(s_handle));
    token.drop_session_objects(s_handle);
    drop(token);
    let _ = res_or_ret!(wstate.drop_session(s_handle));
    CKR_OK
}

/// Implementation of C_CloseAllSessions function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203274](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203274)
pub extern "C" fn fn_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    let mut wstate = global_wlock!((*STATE));
    let dropped_sessions = res_or_ret!(wstate.drop_all_sessions_slot(slot_id));
    let mut token = res_or_ret!(wstate.get_token_from_slot_mut(slot_id));
    for handle in dropped_sessions {
        token.drop_session_objects(handle);
    }
    /* The spec requires the token to logout once the last session is closed */
    token.logout();
    CKR_OK
}

/// Implementation of C_GetSessionInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203275](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203275)
pub extern "C" fn fn_get_session_info(
    s_handle: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));
    unsafe {
        core::ptr::write(info as *mut _, *session.get_session_info());
    }
    CKR_OK
}

/// Implementation of C_GetOperationState function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203277](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203277)
pub extern "C" fn fn_get_operation_state(
    s_handle: CK_SESSION_HANDLE,
    operation_state: CK_BYTE_PTR,
    pul_operation_state_len: CK_ULONG_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    if operation_state.is_null() {
        if pul_operation_state_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let state_len = cast_or_ret!(
            CK_ULONG from res_or_ret!(session.state_size())
        );
        unsafe {
            *pul_operation_state_len = state_len;
        }
        return CKR_OK;
    }
    let state_len = cast_or_ret!(
        usize from unsafe { *pul_operation_state_len } => CKR_ARGUMENTS_BAD
    );
    let state: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(operation_state, state_len) };
    let slot_id = session.get_slot_id();
    let token = res_or_ret!(rstate.get_token_from_slot(slot_id));
    let outlen = res_or_ret!(session.state_save(token.get_mechanisms(), state));
    unsafe { *pul_operation_state_len = cast_or_ret!(CK_ULONG from outlen) };
    CKR_OK
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
    if encryption_key != CK_INVALID_HANDLE {
        return CKR_KEY_NOT_NEEDED;
    }
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
    let state_len = cast_or_ret!(
        usize from operation_state_len => CKR_ARGUMENTS_BAD
    );
    let state: &[u8] =
        unsafe { std::slice::from_raw_parts(operation_state, state_len) };
    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));

    let mut key: Option<object::Object> = None;
    if authentication_key != CK_INVALID_HANDLE {
        key = Some(res_or_ret!(token.get_object_by_handle(authentication_key)));
    }
    ret_to_rv!(session.state_restore(
        token.get_mechanisms(),
        state,
        key.as_ref()
    ))
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
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));
    let slot_id = session.get_slot_id();
    /* avoid deadlock later when we change all sessions */
    drop(session);
    if user_type == CKU_SO {
        if res_or_ret!(rstate.has_ro_sessions(slot_id)) {
            return CKR_SESSION_READ_ONLY_EXISTS;
        }
    }
    let vpin = bytes_to_slice!(pin, pin_len, u8);
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    if user_type == CKU_CONTEXT_SPECIFIC {
        let session = res_or_ret!(rstate.get_session_mut(s_handle));
        match session.check_login_status() {
            Err(e) => match e.rv() {
                CKR_USER_NOT_LOGGED_IN => (),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            },
            Ok(()) => return CKR_OPERATION_NOT_INITIALIZED,
        }
    }

    let result = token.login(user_type, &vpin);

    if user_type == CKU_CONTEXT_SPECIFIC {
        match result {
            CKR_OK => {
                let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
                session.set_login_ok();
            }
            CKR_PIN_LOCKED => {
                token.logout();
                let _ = rstate.invalidate_session_states(slot_id);
            }
            _ => (),
        }
        result
    } else {
        match result {
            CKR_OK => match rstate.change_session_states(slot_id, user_type) {
                Ok(()) => CKR_OK,
                Err(e) => {
                    token.logout();
                    let _ = rstate.invalidate_session_states(slot_id);
                    e.rv()
                }
            },
            err => err,
        }
    }
}

/// Implementation of C_Logout function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203281](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203281)
pub extern "C" fn fn_logout(s_handle: CK_SESSION_HANDLE) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));
    let slot_id = session.get_slot_id();
    /* avoid deadlock later when we change all sessions */
    drop(session);
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let ret = token.logout();
    if ret == CKR_OK {
        let _ = rstate.invalidate_session_states(slot_id);
    }
    ret
}

/// Implementation of C_LoginUser function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203280](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203280)
pub extern "C" fn fn_login_user(
    _session: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
    _username: CK_UTF8CHAR_PTR,
    _username_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// Implementation of C_SessionCancel function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203276](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203276)
pub extern "C" fn fn_session_cancel(
    s_handle: CK_SESSION_HANDLE,
    flags: CK_FLAGS,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let mut session = res_or_ret!(rstate.get_session_mut(s_handle));
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
    res
}

/// Implementation of C_GetSessionValidationFlags
///
/// Version 3.2 Specification: [Link TBD]
pub extern "C" fn fn_get_session_validation_flags(
    s_handle: CK_SESSION_HANDLE,
    flags_type: CK_SESSION_VALIDATION_FLAGS_TYPE,
    pflags: CK_FLAGS_PTR,
) -> CK_RV {
    let flags: CK_FLAGS = if flags_type != CKS_LAST_VALIDATION_OK {
        0
    } else {
        let rstate = global_rlock!((*STATE));
        let session = res_or_ret!(rstate.get_session(s_handle));

        session.get_last_validation_flags()
    };
    unsafe { *pflags = flags };
    CKR_OK
}

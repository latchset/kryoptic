// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Slot and Token management functions
//!
//! This module contains the implementation of the Slot and Token management
//! functions as defined in the PKCS#11 specification.

use crate::misc::{bytes_to_slice, bytes_to_vec};
use crate::pkcs11::vendor::KRY_UNSPEC;
use crate::pkcs11::*;
use crate::{
    cast_or_ret, global_rlock, ok_or_ret, res_or_ret, ret_to_rv, STATE,
};

/// Implementation of C_GetSlotList function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203262](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203262)
pub extern "C" fn fn_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let slotids = global_rlock!((*STATE)).get_slots_ids();
    let silen = cast_or_ret!(CK_ULONG from slotids.len());
    if slot_list.is_null() {
        unsafe {
            *count = silen;
        }
        return CKR_OK;
    }
    unsafe {
        let num: CK_ULONG = *count;
        if num < silen {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    for (udx, slotid) in slotids.iter().enumerate() {
        let idx = cast_or_ret!(isize from udx);
        unsafe {
            core::ptr::write(slot_list.offset(idx), *slotid);
        }
    }
    unsafe {
        *count = silen;
    }
    CKR_OK
}

/// Implementation of C_GetSlotInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203263](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203263)
pub extern "C" fn fn_get_slot_info(
    slot_id: CK_SLOT_ID,
    info: CK_SLOT_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let slot = match rstate.get_slot(slot_id) {
        Ok(s) => s,
        Err(e) => return e.rv(),
    };
    let slotinfo = slot.get_slot_info();
    unsafe {
        core::ptr::write(info as *mut _, *slotinfo);
    }
    CKR_OK
}

/// Implementation of C_GetTokenInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203264](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203264)
pub extern "C" fn fn_get_token_info(
    slot_id: CK_SLOT_ID,
    info: CK_TOKEN_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let slot = match rstate.get_slot(slot_id) {
        Ok(s) => s,
        Err(e) => return e.rv(),
    };
    let tokinfo = slot.get_token_info();
    unsafe {
        core::ptr::write(info as *mut _, tokinfo);
    }
    CKR_OK
}

/// Implementation of C_GetMechanismList function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203266](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203266)
pub extern "C" fn fn_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let rstate = global_rlock!((*STATE));
    let token = res_or_ret!(rstate.get_token_from_slot(slot_id));
    if mechanism_list.is_null() {
        let cnt = cast_or_ret!(CK_ULONG from token.get_mechs_num());
        unsafe {
            *count = cnt;
        }
        return CKR_OK;
    }
    let mechs = token.get_mechs_list();
    let num = cast_or_ret!(
        usize from unsafe { *count as CK_ULONG } => CKR_ARGUMENTS_BAD
    );
    if num < mechs.len() {
        return CKR_BUFFER_TOO_SMALL;
    }
    for (udx, mech) in mechs.iter().enumerate() {
        let idx = cast_or_ret!(isize from udx);
        unsafe {
            core::ptr::write(mechanism_list.offset(idx), *mech);
        }
    }
    let cnt = cast_or_ret!(CK_ULONG from mechs.len());
    unsafe {
        *count = cnt;
    }
    CKR_OK
}

/// Implementation of C_GetMechanismInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203267](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203267)
pub extern "C" fn fn_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    typ: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let token = res_or_ret!(rstate.get_token_from_slot(slot_id));
    let mech = res_or_ret!(token.get_mech_info(typ));
    unsafe {
        core::ptr::write(info as *mut _, *mech);
    }
    CKR_OK
}

/// Implementation of C_InitToken function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203268](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203268)
pub extern "C" fn fn_init_token(
    slot_id: CK_SLOT_ID,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    if res_or_ret!(rstate.has_sessions(slot_id)) {
        return CKR_SESSION_EXISTS;
    }
    let vpin = bytes_to_slice!(pin, pin_len, u8);
    let vlabel: Vec<u8> = if label.is_null() {
        vec![0x20u8; 32]
    } else {
        bytes_to_vec!(label, 32)
    };
    let mut token =
        res_or_ret!(rstate.get_token_from_slot_mut_nochecks(slot_id));
    match ret_to_rv!(token.initialize(&vpin, &vlabel)) {
        CKR_OK => CKR_OK,
        CKR_PIN_LOCKED => CKR_PIN_LOCKED,
        CKR_PIN_INCORRECT => CKR_PIN_INCORRECT,
        CKR_PIN_INVALID => CKR_PIN_INVALID,
        CKR_PIN_EXPIRED => CKR_PIN_EXPIRED,
        _ => CKR_GENERAL_ERROR,
    }
}

/// Implementation of C_InitPIN function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203269](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203269)
pub extern "C" fn fn_init_pin(
    s_handle: CK_SESSION_HANDLE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let mut token = res_or_ret!(rstate.get_token_from_session_mut(s_handle));
    if !token.is_logged_in(CKU_SO) {
        return CKR_USER_NOT_LOGGED_IN;
    }

    let vpin = bytes_to_slice!(pin, pin_len, u8);

    ret_to_rv!(token.set_pin(CKU_USER, &vpin, &vec![0u8; 0]))
}

/// Implementation of C_SetPIN function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203270](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203270)
pub extern "C" fn fn_set_pin(
    s_handle: CK_SESSION_HANDLE,
    old_pin: CK_UTF8CHAR_PTR,
    old_len: CK_ULONG,
    new_pin: CK_UTF8CHAR_PTR,
    new_len: CK_ULONG,
) -> CK_RV {
    let rstate = global_rlock!((*STATE));
    let session = res_or_ret!(rstate.get_session(s_handle));
    if !session.is_writable() {
        return CKR_SESSION_READ_ONLY;
    }
    let vpin = bytes_to_slice!(new_pin, new_len, u8);
    let vold = bytes_to_slice!(old_pin, old_len, u8);

    if vpin.len() == 0 || vold.len() == 0 {
        return CKR_PIN_INVALID;
    }

    let slot_id = session.get_slot_id();
    let mut token = res_or_ret!(rstate.get_token_from_slot_mut(slot_id));
    let do_logout = if token.is_logged_in(KRY_UNSPEC) {
        false
    } else {
        ok_or_ret!(token.login(CKU_USER, &vold));
        true
    };

    let ret =
        ret_to_rv!(token.set_pin(CK_UNAVAILABLE_INFORMATION, &vpin, &vold));

    if do_logout {
        let _ = token.logout();
    }

    ret
}

/// Implementation of C_WaitForSlotEvent function (Not Implemented Yet)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203265](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203265)
pub extern "C" fn fn_wait_for_slot_event(
    _flags: CK_FLAGS,
    _slot: CK_SLOT_ID_PTR,
    _rserved: CK_VOID_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

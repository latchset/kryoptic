// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! Slot and Token management functions
//!
//! This module contains the implementation of the Slot and Token management
//! functions as defined in the PKCS#11 specification.

use crate::error::Result;
use crate::log_debug;
use crate::misc::{bytes_to_slice, bytes_to_vec};
use crate::pkcs11::vendor::KRY_UNSPEC;
use crate::pkcs11::*;
use crate::STATE;

#[inline(always)]
fn get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> Result<()> {
    if count.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let slotids = STATE.rlock()?.get_slots_ids();
    let silen =
        CK_ULONG::try_from(slotids.len()).map_err(|_| CKR_GENERAL_ERROR)?;

    if slot_list.is_null() {
        unsafe {
            *count = silen;
        }
        return Ok(());
    }
    unsafe {
        let num: CK_ULONG = *count;
        if num < silen {
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }
    }
    for (udx, slotid) in slotids.iter().enumerate() {
        let idx = isize::try_from(udx).map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            core::ptr::write(slot_list.offset(idx), *slotid);
        }
    }
    unsafe {
        *count = silen;
    }
    Ok(())
}

/// Implementation of C_GetSlotList function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203262](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203262)
pub extern "C" fn fn_get_slot_list(
    token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_GetSlotList: token_present={} slot_list={:?} count={:?}",
        token_present,
        slot_list,
        count
    );
    let rv = match get_slot_list(token_present, slot_list, count) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetSlotList: ret={}", rv);
    rv
}

#[inline(always)]
fn get_slot_info(slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> Result<()> {
    if info.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    let slot = rstate.get_slot(slot_id)?;
    let slotinfo = slot.get_slot_info();
    unsafe {
        core::ptr::write(info as *mut _, *slotinfo);
    }
    Ok(())
}

/// Implementation of C_GetSlotInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203263](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203263)
pub extern "C" fn fn_get_slot_info(
    slot_id: CK_SLOT_ID,
    info: CK_SLOT_INFO_PTR,
) -> CK_RV {
    log_debug!("C_GetSlotInfo: slot_id={} info={:?}", slot_id, info);
    let rv = match get_slot_info(slot_id, info) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetSlotInfo: ret={}", rv);
    rv
}

#[inline(always)]
fn get_token_info(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> Result<()> {
    if info.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }

    let rstate = STATE.rlock()?;
    let slot = rstate.get_slot(slot_id)?;
    let tokinfo = slot.get_token_info();
    unsafe {
        core::ptr::write(info as *mut _, tokinfo);
    }
    Ok(())
}

/// Implementation of C_GetTokenInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203264](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203264)
pub extern "C" fn fn_get_token_info(
    slot_id: CK_SLOT_ID,
    info: CK_TOKEN_INFO_PTR,
) -> CK_RV {
    log_debug!("C_GetTokenInfo: slot_id={} info={:?}", slot_id, info);
    let rv = match get_token_info(slot_id, info) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetTokenInfo: ret={}", rv);
    rv
}

#[inline(always)]
fn get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> Result<()> {
    if count.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let token = rstate.get_token_from_slot(slot_id)?;
    if mechanism_list.is_null() {
        let cnt = CK_ULONG::try_from(token.get_mechs_num())
            .map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            *count = cnt;
        }
        return Ok(());
    }
    let mechs = token.get_mechs_list();
    let num = unsafe { *count };
    if (num as usize) < mechs.len() {
        return Err(CKR_BUFFER_TOO_SMALL)?;
    }
    for (udx, mech) in mechs.iter().enumerate() {
        let idx = isize::try_from(udx).map_err(|_| CKR_GENERAL_ERROR)?;
        unsafe {
            core::ptr::write(mechanism_list.offset(idx), *mech);
        }
    }
    let cnt = CK_ULONG::try_from(mechs.len()).map_err(|_| CKR_GENERAL_ERROR)?;
    unsafe {
        *count = cnt;
    }
    Ok(())
}

/// Implementation of C_GetMechanismList function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203266](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203266)
pub extern "C" fn fn_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    log_debug!(
        "C_GetMechanismList: slot_id={} mechanism_list={:?} count={:?}",
        slot_id,
        mechanism_list,
        count
    );
    let rv = match get_mechanism_list(slot_id, mechanism_list, count) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetMechanismList: ret={}", rv);
    rv
}

#[inline(always)]
fn get_mechanism_info(
    slot_id: CK_SLOT_ID,
    typ: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> Result<()> {
    if info.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let rstate = STATE.rlock()?;
    let token = rstate.get_token_from_slot(slot_id)?;
    let mech = token.get_mech_info(typ)?;
    unsafe {
        core::ptr::write(info as *mut _, *mech);
    }
    Ok(())
}

/// Implementation of C_GetMechanismInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203267](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203267)
pub extern "C" fn fn_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    typ: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    log_debug!(
        "C_GetMechanismInfo: slot_id={} typ={} info={:?}",
        slot_id,
        typ,
        info
    );
    let rv = match get_mechanism_info(slot_id, typ, info) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetMechanismInfo: ret={}", rv);
    rv
}

#[inline(always)]
fn init_token(
    slot_id: CK_SLOT_ID,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
    label: CK_UTF8CHAR_PTR,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    if rstate.has_sessions(slot_id)? {
        return Err(CKR_SESSION_EXISTS)?;
    }
    let vpin = bytes_to_slice!(pin, pin_len, u8);
    let vlabel: Vec<u8> = if label.is_null() {
        vec![0x20u8; 32]
    } else {
        bytes_to_vec!(label, 32)
    };
    let mut token = rstate.get_token_from_slot_mut_nochecks(slot_id)?;
    match token.initialize(&vpin, &vlabel) {
        Ok(()) => Ok(()),
        Err(e) => match e.rv() {
            CKR_OK => Ok(()),
            CKR_PIN_LOCKED => Err(CKR_PIN_LOCKED)?,
            CKR_PIN_INCORRECT => Err(CKR_PIN_INCORRECT)?,
            CKR_PIN_INVALID => Err(CKR_PIN_INVALID)?,
            CKR_PIN_EXPIRED => Err(CKR_PIN_EXPIRED)?,
            _ => Err(CKR_GENERAL_ERROR)?,
        },
    }
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
    log_debug!(
        "C_InitToken: slot_id={} pin={:?} pin_len={} label={:?}",
        slot_id,
        pin,
        pin_len,
        label
    );
    let rv = match init_token(slot_id, pin, pin_len, label) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_InitToken: ret={}", rv);
    rv
}

#[inline(always)]
fn init_pin(
    s_handle: CK_SESSION_HANDLE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let mut token = rstate.get_token_from_session_mut(s_handle)?;
    if !token.is_logged_in(CKU_SO) {
        return Err(CKR_USER_NOT_LOGGED_IN)?;
    }

    let vpin = bytes_to_slice!(pin, pin_len, u8);

    token.set_pin(CKU_USER, &vpin, &vec![0u8; 0])
}

/// Implementation of C_InitPIN function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203269](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203269)
pub extern "C" fn fn_init_pin(
    s_handle: CK_SESSION_HANDLE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_InitPIN: s_handle={} pin={:?} pin_len={}",
        s_handle,
        pin,
        pin_len
    );
    let rv = match init_pin(s_handle, pin, pin_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_InitPIN: ret={}", rv);
    rv
}

#[inline(always)]
fn set_pin(
    s_handle: CK_SESSION_HANDLE,
    old_pin: CK_UTF8CHAR_PTR,
    old_len: CK_ULONG,
    new_pin: CK_UTF8CHAR_PTR,
    new_len: CK_ULONG,
) -> Result<()> {
    let rstate = STATE.rlock()?;
    let session = rstate.get_session(s_handle)?;
    if !session.is_writable() {
        return Err(CKR_SESSION_READ_ONLY)?;
    }
    let vpin = bytes_to_slice!(new_pin, new_len, u8);
    let vold = bytes_to_slice!(old_pin, old_len, u8);

    if vpin.len() == 0 || vold.len() == 0 {
        return Err(CKR_PIN_INVALID)?;
    }

    let slot_id = session.get_slot_id();
    let mut token = rstate.get_token_from_slot_mut(slot_id)?;
    let do_logout = if token.is_logged_in(KRY_UNSPEC) {
        false
    } else {
        let rv = token.login(CKU_USER, &vold);
        if rv != CKR_OK {
            return Err(rv)?;
        }
        true
    };

    let ret = token.set_pin(CK_UNAVAILABLE_INFORMATION, &vpin, &vold);

    if do_logout {
        let _ = token.logout();
    }

    ret
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
    log_debug!(
        "C_SetPIN: s_handle={} old_pin={:?} old_len={} new_pin={:?} new_len={}",
        s_handle,
        old_pin,
        old_len,
        new_pin,
        new_len
    );
    let rv = match set_pin(s_handle, old_pin, old_len, new_pin, new_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SetPIN: ret={}", rv);
    rv
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

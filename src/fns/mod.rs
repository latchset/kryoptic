// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! PKCS#11 Functions implementation
//!
//! This module and its submodules contain the implementation of the various
//! PKCS#11 functions exported via the Function List.

use crate::error::Result;
use crate::pkcs11::*;
use crate::{get_random_data, random_add_seed, STATE};

pub mod digest;
pub mod dualcrypto;
pub mod encryption;
pub mod general;
pub mod keymgmt;
pub mod objmgmt;
pub mod sessmgmt;
pub mod signing;
pub mod stmgmt;

macro_rules! log_debug {
    ($($arg:tt)+) => (
        #[cfg(feature = "log")]
        log::debug!($($arg)+);
    )
}
pub(crate) use log_debug;

pub(crate) fn fail_if_cka_token_true(template: &[CK_ATTRIBUTE]) -> Result<()> {
    for ck_attr in template.iter() {
        if ck_attr.type_ == CKA_TOKEN {
            if ck_attr.to_bool()? {
                return Err(CKR_SESSION_READ_ONLY)?;
            }
        }
    }
    Ok(())
}

#[inline(always)]
fn seed_random(
    s_handle: CK_SESSION_HANDLE,
    seed: CK_BYTE_PTR,
    seed_len: CK_ULONG,
) -> Result<()> {
    /* check session is valid */
    drop(STATE.rlock()?.get_session(s_handle)?);
    let len = usize::try_from(seed_len).map_err(|_| CKR_GENERAL_ERROR)?;
    let data: &[u8] = unsafe { std::slice::from_raw_parts(seed, len) };
    random_add_seed(data)
}

/// Implementation of C_SeedRandom function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203358](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203358)
pub extern "C" fn fn_seed_random(
    s_handle: CK_SESSION_HANDLE,
    seed: CK_BYTE_PTR,
    seed_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_SeedRandom: s_handle={} seed={:?} seed_len={}",
        s_handle,
        seed,
        seed_len
    );
    let rv = match seed_random(s_handle, seed, seed_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_SeedRandom: ret={}", rv);
    rv
}

#[inline(always)]
fn generate_random(
    s_handle: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> Result<()> {
    /* check session is valid */
    drop(STATE.rlock()?.get_session(s_handle)?);
    let rndlen = usize::try_from(random_len).map_err(|_| CKR_GENERAL_ERROR)?;
    let data: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(random_data, rndlen) };
    get_random_data(data)
}

/// Implementation of C_GeneateRandom function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203359](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203359)
pub extern "C" fn fn_generate_random(
    s_handle: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    log_debug!(
        "C_GenerateRandom: s_handle={} random_data={:?} random_len={}",
        s_handle,
        random_data,
        random_len
    );
    let rv = match generate_random(s_handle, random_data, random_len) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GenerateRandom: ret={}", rv);
    rv
}

/// Implementation of C_GetFunctionStatus function
/// (Legacy function. Always returns `CKR_FUNCTION_NOT_PARALLEL`)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203361](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203361)

pub extern "C" fn fn_get_function_status(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

/// Implementation of C_CancelFunction function
/// (Legacy function. Always returns `CKR_FUNCTION_NOT_PARALLEL`)
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203362](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203362)

pub extern "C" fn fn_cancel_function(_session: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

pub extern "C" fn fn_async_complete(
    _s_handle: CK_SESSION_HANDLE,
    _function_name: *mut CK_UTF8CHAR,
    _result: *mut CK_ASYNC_DATA,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn fn_async_get_id(
    _s_handle: CK_SESSION_HANDLE,
    _function_name: *mut CK_UTF8CHAR,
    _operation_id: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn fn_async_join(
    _s_handle: CK_SESSION_HANDLE,
    _function_name: *mut CK_UTF8CHAR,
    _operation_id: CK_ULONG,
    _data: *mut CK_BYTE,
    _data_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

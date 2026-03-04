// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! PKCS#11 Functions implementation
//!
//! This module and its submodules contain the implementation of the various
//! PKCS#11 functions exported via the Function List.

use crate::pkcs11::*;
use crate::{get_random_data, random_add_seed};

pub mod digest;
pub mod dualcrypto;
pub mod encryption;
pub mod general;
pub mod keymgmt;
pub mod objmgmt;
pub mod sessmgmt;
pub mod signing;
pub mod stmgmt;

/// Macro to convert a `Result<()>` into a `CK_RV`, returning `CKR_OK` on Ok.
macro_rules! ret_to_rv {
    ($ret:expr) => {
        match $ret {
            Ok(()) => CKR_OK,
            Err(e) => e.rv(),
        }
    };
}
pub(crate) use ret_to_rv;

/// Macro to unwrap a `Result<T>` or cause the function to return its `CK_RV`
/// error code.
macro_rules! res_or_ret {
    ($ret:expr) => {
        match $ret {
            Ok(x) => x,
            Err(e) => return e.rv(),
        }
    };
}
pub(crate) use res_or_ret;

/// Macro to check if a `CK_RV` is `CKR_OK`, otherwise cause the function to
/// return the error code.
macro_rules! ok_or_ret {
    ($ret:expr) => {
        match $ret {
            CKR_OK => (),
            err => return err,
        }
    };
}
pub(crate) use ok_or_ret;

/// Macro for `try_from` conversions, return the data in the proper format or
/// causes the function to return a specified or general error on failure.
macro_rules! cast_or_ret {
    ($type:tt from $val:expr) => {{
        match $type::try_from($val) {
            Ok(cast) => cast,
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
    ($type:tt from $val:expr => $err:expr) => {{
        match $type::try_from($val) {
            Ok(cast) => cast,
            Err(_) => return $err,
        }
    }};
}
pub(crate) use cast_or_ret;

/// Macro to acquire a read lock on a global `RwLock<T>`. One variant checks
/// the initialization status and the other explicitly does not (generally
/// used during initialization).
macro_rules! global_rlock {
    ($GLOBAL:expr) => {
        match $GLOBAL.read() {
            Ok(r) => {
                if (!r.is_initialized()) {
                    return CKR_CRYPTOKI_NOT_INITIALIZED;
                }
                r
            }
            Err(_) => return CKR_GENERAL_ERROR,
        }
    };
    (noinitcheck; $GLOBAL:expr) => {{
        match $GLOBAL.read() {
            Ok(r) => r,
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
}
pub(crate) use global_rlock;

/// Macro to acquire a write lock on a global `RwLock<T>`. One variant checks
/// the initialization status and the other explicitly does not (generally
/// used during initialization).
macro_rules! global_wlock {
    ($GLOBAL:expr) => {{
        match $GLOBAL.write() {
            Ok(w) => {
                if (!w.is_initialized()) {
                    return CKR_CRYPTOKI_NOT_INITIALIZED;
                }
                w
            }
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
    (noinitcheck; $GLOBAL:expr) => {{
        match $GLOBAL.write() {
            Ok(w) => w,
            Err(_) => return CKR_GENERAL_ERROR,
        }
    }};
}
pub(crate) use global_wlock;

macro_rules! check_op_empty_or_fail {
    ($sess:expr; $op:ident; $ptr:expr) => {
        if $ptr.is_null() {
            res_or_ret!($sess.cancel_operation::<dyn $op>());
            return CKR_OK;
        }
        res_or_ret!($sess.check_no_op::<dyn $op>());
    };
}
pub(crate) use check_op_empty_or_fail;

/// Implementation of C_SeedRandom function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203358](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203358)
pub extern "C" fn fn_seed_random(
    s_handle: CK_SESSION_HANDLE,
    seed: CK_BYTE_PTR,
    seed_len: CK_ULONG,
) -> CK_RV {
    /* check session is valid */
    drop(res_or_ret!(
        global_rlock!((*crate::STATE)).get_session(s_handle)
    ));
    let len = cast_or_ret!(usize from seed_len);
    let data: &[u8] = unsafe { std::slice::from_raw_parts(seed, len) };
    ret_to_rv!(random_add_seed(data))
}

/// Implementation of C_GeneateRandom function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203359](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203359)
pub extern "C" fn fn_generate_random(
    s_handle: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    /* check session is valid */
    drop(res_or_ret!(
        global_rlock!((*crate::STATE)).get_session(s_handle)
    ));
    let rndlen = cast_or_ret!(usize from random_len);
    let data: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(random_data, rndlen) };
    ret_to_rv!(get_random_data(data))
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

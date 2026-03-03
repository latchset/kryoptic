// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! PKCS#11 Functions implementation
//!
//! This module and its submodules contain the implementation of the various
//! PKCS#11 functions exported via the Function List.

pub mod general;
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

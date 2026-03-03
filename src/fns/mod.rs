// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! PKCS#11 Functions implementation
//!
//! This module and its submodules contain the implementation of the various
//! PKCS#11 functions exported via the Function List.

pub mod general;

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

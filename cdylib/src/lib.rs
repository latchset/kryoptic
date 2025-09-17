// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#![warn(missing_docs)]

//! This is the Kryoptic shared object
//!
//! A cryptographic software token using the PKCS#11 standard API

use kryoptic_lib::pkcs11::*;
use kryoptic_lib::{
    fn_get_function_list, fn_get_interface, fn_get_interface_list,
};

/// Public export symbol to access [kryoptic::fn_get_function_list]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(fnlist: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    fn_get_function_list(fnlist)
}

/// Public export symbol to access [kryoptic::fn_get_interface]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetInterface(
    interface_name: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    fn_get_interface(interface_name, version, interface, flags)
}

/// Public export symbol to access [kryoptic::fn_get_interface_list]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetInterfaceList(
    interfaces_list: CK_INTERFACE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    fn_get_interface_list(interfaces_list, count)
}

/// Implementation of the OpenSSL provider initialization function
///
/// This function allows OpenSSL to use this module as an OpenSSL FIPS
/// provider

#[cfg(feature = "fips")]
#[no_mangle]
pub extern "C" fn OSSL_provider_init(
    handle: *const ::ossl::bindings::OSSL_CORE_HANDLE,
    in_: *const ::ossl::bindings::OSSL_DISPATCH,
    out: *mut *const ::ossl::bindings::OSSL_DISPATCH,
    provctx: *mut *mut ::std::ffi::c_void,
) -> ::std::ffi::c_int {
    unsafe {
        ::ossl::bindings::OSSL_provider_init_int(handle, in_, out, provctx)
    }
}

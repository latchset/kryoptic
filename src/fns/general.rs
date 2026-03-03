// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! General Purpose functions
//!
//! This module contains the implementation of the General Purpose functions
//! as defined in the PKCS#11 specification.

use std::ffi::{c_char, CStr};

use crate::config::Config;
use crate::pkcs11::*;
use crate::slot::Slot;
use crate::{cast_or_ret, global_wlock, res_or_ret};

/// Implementation of C_Initialize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203255](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203255)

pub extern "C" fn fn_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    let mut gconf = global_wlock!(noinitcheck; (*crate::CONFIG));

    let mut ret: CK_RV = CKR_OK;

    /* Before loading the default config see if there is a cutsom config
     * provided via reserved arg pointer */
    if !_init_args.is_null() {
        let args = unsafe { *(_init_args as *const CK_C_INITIALIZE_ARGS) };

        if !args.pReserved.is_null() {
            let reserved =
                unsafe { CStr::from_ptr(args.pReserved as *const _) };
            let init_arg = match reserved.to_str() {
                Ok(s) => s,
                Err(_) => return CKR_ARGUMENTS_BAD,
            };
            res_or_ret!(gconf.conf.from_init_args(init_arg));
        }
    }

    if gconf.conf.slots.is_empty() {
        match Config::default_config() {
            Ok(conf) => gconf.conf = conf,
            Err(_) => return CKR_TOKEN_NOT_PRESENT,
        }
    }

    gconf.conf.load_env_vars_overrides();

    let mut wstate = global_wlock!(noinitcheck; (*crate::STATE));
    if wstate.is_initialized() {
        ret = CKR_CRYPTOKI_ALREADY_INITIALIZED;
    } else {
        wstate.initialize();
    }

    /* create slots for any new slot specified in the configuration
     * that has not been created yet, new slots can be added via
     * init args so we check this every time */
    for slot in &gconf.conf.slots {
        let slotnum = cast_or_ret!(CK_SLOT_ID from slot.slot);
        match wstate.add_slot(slotnum, res_or_ret!(Slot::new(slot))) {
            Ok(_) => (),
            Err(e) => {
                ret = e.rv();
                if ret != CKR_CRYPTOKI_ALREADY_INITIALIZED {
                    return ret;
                }
            }
        }
    }

    ret
}

/// Implementation of C_Finalize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203256](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203256)

pub extern "C" fn fn_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    let ret = global_wlock!((*crate::STATE)).finalize();
    let mut gconf = global_wlock!(noinitcheck; (*crate::CONFIG));
    gconf.conf = Config::new();
    ret
}

/// Implementation of C_GetInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203257](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203257)

pub extern "C" fn fn_get_info(info: CK_INFO_PTR) -> CK_RV {
    unsafe {
        *info = crate::MODULE_INFO;
    }
    CKR_OK
}

/// Provides access to the functions defined in the API specification
///
/// The vtable returned by this function includes a version specifier as
/// the first element of this table. This version number determines the
/// length and contents of the rest of the vtable.
///
/// Often for backwards compatibility reasons the table returned by this
/// function is the table specified in PKCS#11 v2.40.
///
/// While access to later versions of the table is deferred to the
/// `C_GeInterfaceList` function available starting with version 3.0 of the
/// specification.
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203258](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203258)

pub extern "C" fn fn_get_function_list(
    fnlist: CK_FUNCTION_LIST_PTR_PTR,
) -> CK_RV {
    unsafe {
        *fnlist = &crate::FNLIST_240 as *const _ as *mut _;
    };
    CKR_OK
}

/// Provides access to the list of interfaces defined by this implementation
///
/// Starting with PKCS#11 version 3.0 modules provide a list of interfaces
/// that can be fetched. Each interface provides a name and a pointer to a
/// vtable containing the functions defined for that interface.
/// Additionally flags are returned as well.
/// Custom interfaces can be defined by any vendor by specifying a custom
/// interface name. The name \"PKCS 11\" is reserved for official standard
/// interfaces.
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203259](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203259)

pub extern "C" fn fn_get_interface_list(
    interfaces_list: CK_INTERFACE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let iflen = cast_or_ret!(CK_ULONG from (*crate::INTERFACE_SET).len());
    if interfaces_list.is_null() {
        unsafe {
            *count = iflen;
        }
        return CKR_OK;
    }
    unsafe {
        if *count < iflen {
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    for i in 0..(*crate::INTERFACE_SET).len() {
        let offset = cast_or_ret!(isize from i);
        unsafe {
            core::ptr::write(
                interfaces_list.offset(offset) as *mut CK_INTERFACE,
                *((*crate::INTERFACE_SET)[i].interface),
            );
        }
    }
    unsafe {
        *count = iflen;
    }
    CKR_OK
}

/// Returns a specific interface identified by name and version
///
/// Applications that wants to immediately access a specific interface name,
/// optionally a specific version too.
/// The `interface` argument returns the pointer to the requested vtable
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203260](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203260)

pub extern "C" fn fn_get_interface(
    interface_name: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if interface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    /* currently flags is always 0 */
    if flags != 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let ver: CK_VERSION = if version.is_null() {
        crate::IMPLEMENTED_VERSION
    } else {
        unsafe { *version }
    };

    let request_name: *const CK_UTF8CHAR = if interface_name.is_null() {
        crate::INTERFACE_NAME_STD_NUL.as_ptr()
    } else {
        interface_name
    };

    for intf in (*crate::INTERFACE_SET).iter() {
        let found: bool = unsafe {
            let name = (*intf.interface).pInterfaceName as *const c_char;
            libc::strcmp(request_name as *const c_char, name) == 0
        };

        if found {
            if ver.major != intf.version.major {
                continue;
            }
            if ver.minor != intf.version.minor {
                continue;
            }
            unsafe { *interface = intf.interface as *mut _ }
            return CKR_OK;
        }
    }

    CKR_ARGUMENTS_BAD
}

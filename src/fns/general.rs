// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

//! General Purpose functions
//!
//! This module contains the implementation of the General Purpose functions
//! as defined in the PKCS#11 specification.

use std::ffi::{c_char, CStr};

use crate::config::Config;
use crate::error::Result;
use crate::log_debug;
use crate::pkcs11::*;
use crate::slot::Slot;
use crate::STATE;

#[inline(always)]
fn initialize(init_args: CK_VOID_PTR) -> Result<()> {
    let mut conf = crate::CONFIG.wlock()?;

    /* Before loading the default config see if there is a cutsom config
     * provided via reserved arg pointer */
    if !init_args.is_null() {
        let args = unsafe { *(init_args as *const CK_C_INITIALIZE_ARGS) };

        if !args.pReserved.is_null() {
            let reserved =
                unsafe { CStr::from_ptr(args.pReserved as *const _) };
            let init_arg = match reserved.to_str() {
                Ok(s) => s,
                Err(_) => return Err(CKR_ARGUMENTS_BAD)?,
            };
            conf.from_init_args(init_arg)?;
        }
    }

    if conf.slots.is_empty() {
        match Config::default_config() {
            Ok(defconf) => *conf = defconf,
            Err(_) => return Err(CKR_TOKEN_NOT_PRESENT)?,
        }
    }

    conf.load_env_vars_overrides();

    let mut wstate = STATE.wlock_noinitcheck()?;
    let mut already_init = false;

    if wstate.is_initialized() {
        already_init = true;
    } else {
        wstate.initialize();
    }

    /* create slots for any new slot specified in the configuration
     * that has not been created yet, new slots can be added via
     * init args so we check this every time */
    for slot in &conf.slots {
        let slotnum =
            CK_SLOT_ID::try_from(slot.slot).map_err(|_| CKR_GENERAL_ERROR)?;
        match Slot::new(slot) {
            Ok(s) => match wstate.add_slot(slotnum, s) {
                Ok(_) => (),
                Err(e) => {
                    let rv = e.rv();
                    if rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
                        return Err(e)?;
                    }
                    already_init = true;
                }
            },
            Err(e) => return Err(e)?,
        }
    }

    if already_init {
        return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED)?;
    }

    Ok(())
}

/// Implementation of C_Initialize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203255](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203255)

pub extern "C" fn fn_initialize(init_args: CK_VOID_PTR) -> CK_RV {
    log_debug!("C_Initialize: init_args={:?}", init_args);
    let rv = match initialize(init_args) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Initialize: ret={}", rv);
    rv
}

#[inline(always)]
fn finalize(_reserved: CK_VOID_PTR) -> Result<()> {
    let ret = STATE.wlock()?.finalize();
    let mut conf = crate::CONFIG.wlock()?;
    *conf = Config::new();
    if ret != CKR_OK {
        return Err(ret)?;
    }
    Ok(())
}

/// Implementation of C_Finalize function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203256](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203256)

pub extern "C" fn fn_finalize(reserved: CK_VOID_PTR) -> CK_RV {
    log_debug!("C_Finalize: reserved={:?}", reserved);
    let rv = match finalize(reserved) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_Finalize: ret={}", rv);
    rv
}

#[inline(always)]
fn get_info(info: CK_INFO_PTR) -> Result<()> {
    if info.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    unsafe {
        *info = crate::MODULE_INFO;
    }
    Ok(())
}

/// Implementation of C_GetInfo function
///
/// Version 3.1 Specification: [https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203257](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html#_Toc111203257)

pub extern "C" fn fn_get_info(info: CK_INFO_PTR) -> CK_RV {
    log_debug!("C_GetInfo: info={:?}", info);
    let rv = match get_info(info) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetInfo: ret={}", rv);
    rv
}

#[inline(always)]
fn get_function_list(fnlist: CK_FUNCTION_LIST_PTR_PTR) -> Result<()> {
    if fnlist.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    unsafe {
        *fnlist = &crate::FNLIST_240 as *const _ as *mut _;
    };
    Ok(())
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
    log_debug!("C_GetFunctionList: fnlist={:?}", fnlist);
    let rv = match get_function_list(fnlist) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetFunctionList: ret={}", rv);
    rv
}

#[inline(always)]
fn get_interface_list(
    interfaces_list: CK_INTERFACE_PTR,
    count: CK_ULONG_PTR,
) -> Result<()> {
    if count.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    let iflen = CK_ULONG::try_from((*crate::INTERFACE_SET).len())
        .map_err(|_| CKR_GENERAL_ERROR)?;

    if interfaces_list.is_null() {
        unsafe {
            *count = iflen;
        }
        return Ok(());
    }
    unsafe {
        if *count < iflen {
            return Err(CKR_BUFFER_TOO_SMALL)?;
        }
    }
    for i in 0..(*crate::INTERFACE_SET).len() {
        let offset = isize::try_from(i).map_err(|_| CKR_GENERAL_ERROR)?;
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
    Ok(())
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
    log_debug!(
        "C_GetInterfaceList: interfaces_list={:?} count={:?}",
        interfaces_list,
        count
    );
    let rv = match get_interface_list(interfaces_list, count) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetInterfaceList: ret={}", rv);
    rv
}

#[inline(always)]
fn get_interface(
    interface_name: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> Result<()> {
    if interface.is_null() {
        return Err(CKR_ARGUMENTS_BAD)?;
    }
    /* currently flags is always 0 */
    if flags != 0 {
        return Err(CKR_ARGUMENTS_BAD)?;
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
            return Ok(());
        }
    }

    Err(CKR_ARGUMENTS_BAD)?
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
    log_debug!(
        "C_GetInterface: interface_name={:?} version={:?} interface={:?} flags={}",
        interface_name,
        version,
        interface,
        flags
    );
    let rv = match get_interface(interface_name, version, interface, flags) {
        Ok(()) => CKR_OK,
        Err(e) => e.rv(),
    };
    log_debug!("C_GetInterface: ret={}", rv);
    rv
}

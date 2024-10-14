// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::env;

use crate::tests::*;

use serial_test::{parallel, serial};

fn test_token(name: &str) {
    let mut testtokn = TestToken::new(name, true);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(value) => {
                let mut args = testtokn.make_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

fn test_token_env(name: &str) {
    let mut testtokn = TestToken::new(name, true);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = testtokn.make_empty_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::set_var("KRYOPTIC_CONF", testtokn.make_init_string());
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

fn test_token_null_args(name: &str) {
    let mut testtokn = TestToken::new(name, true);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                env::set_var("KRYOPTIC_CONF", testtokn.make_init_string());
                let ret = init_fn(std::ptr::null_mut());
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[serial]
fn test_token_datadir() {
    let testdir = "test/kryoptic";
    std::fs::create_dir_all(testdir).unwrap();
    let name = format!("{}/{}", testdir, DEFAULT_CONF_NAME);
    let mut testtokn = TestToken::new(&name, true);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = testtokn.make_empty_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::remove_var("KRYOPTIC_CONF");
                env::set_var("XDG_DATA_HOME", "test");
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_token_json() {
    test_token("test_token.json");
    test_token_env("test_token.json");
    test_token_null_args("test_token.json");
}

#[test]
#[parallel]
fn test_token_sql() {
    test_token("test_token.sql");
    test_token_env("test_token.sql");
    test_token_null_args("test_token.sql");
}

#[test]
#[parallel]
fn test_interface_null() {
    let mut testtokn = TestToken::new("test_interface_null.sql", true);
    testtokn.setup_db(None);

    /* NULL interface name and NULL version -- the module should return default one */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let result = C_GetInterface(
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST_3_0 =
            *(iface.pFunctionList as CK_FUNCTION_LIST_3_0_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = testtokn.make_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_pkcs11() {
    let mut testtokn = TestToken::new("test_interface_pkcs11.sql", true);
    testtokn.setup_db(None);

    /* NULL version -- the module should return default one */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let result = C_GetInterface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        std::ptr::null_mut(),
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST_3_0 =
            *(iface.pFunctionList as CK_FUNCTION_LIST_3_0_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = testtokn.make_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_pkcs11_version3() {
    let mut testtokn =
        TestToken::new("test_interface_pkcs11_version3.sql", true);
    testtokn.setup_db(None);

    /* Get the specific version 3.0 */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let mut version = { CK_VERSION { major: 3, minor: 0 } };
    let result = C_GetInterface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        &mut version,
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST_3_0 =
            *(iface.pFunctionList as CK_FUNCTION_LIST_3_0_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = testtokn.make_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_pkcs11_version240() {
    let mut testtokn =
        TestToken::new("test_interface_pkcs11_version240.sql", true);
    testtokn.setup_db(None);

    /* Get the specific version 2.40 */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let mut version = {
        CK_VERSION {
            major: 2,
            minor: 40,
        }
    };
    let result = C_GetInterface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        &mut version,
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST =
            *(iface.pFunctionList as CK_FUNCTION_LIST_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = testtokn.make_init_args();
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_invalid_name() {
    /* Try to get in valid name */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let result = C_GetInterface(
        "MyPKCS 12\0".as_ptr() as CK_UTF8CHAR_PTR,
        std::ptr::null_mut(),
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_ARGUMENTS_BAD);
}

#[test]
#[parallel]
fn test_interface_invalid_version() {
    /* Try to get in valid name */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let mut version = {
        CK_VERSION {
            major: 2,
            minor: 99,
        }
    };
    let result = C_GetInterface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        &mut version,
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_ARGUMENTS_BAD);
}

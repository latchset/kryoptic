// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::env;

use crate::tests::*;

use serial_test::{parallel, serial};

fn test_token_setup(name: &str) -> TestToken {
    let dbpath = format!("{}/{}", TESTDIR, name);
    let mut testtokn = TestToken::new(dbpath, true);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(value) => {
                let mut args =
                    testtokn.make_init_args(Some(testtokn.make_init_string()));
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn
}

fn test_token_env(testtokn: &TestToken, confname: &str) {
    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = testtokn.make_init_args(None);
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::set_var("KRYOPTIC_CONF", confname);
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }
}

fn test_token_null_args(confname: &str) {
    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                env::set_var("KRYOPTIC_CONF", confname);
                let ret = init_fn(std::ptr::null_mut());
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }
}

#[test]
#[serial]
fn test_token_datadir() {
    let basedir = format!("{}/datadirtest", TESTDIR);
    let confdir = format!("{}/kryoptic", basedir);
    let confname = format!("{}/{}", confdir, config::DEFAULT_CONF_NAME);
    let dbpath = format!("{}/token.sql", confdir);
    std::fs::create_dir_all(confdir).unwrap();

    let mut testtokn = TestToken::new(dbpath, true);
    testtokn.make_config_file(&confname);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = testtokn.make_init_args(None);
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::remove_var("KRYOPTIC_CONF");
                env::set_var("XDG_CONFIG_HOME", basedir);
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
    let mut testtokn = test_token_setup("test_token.json");
    let confname = format!("{}/test_token_json.conf", TESTDIR);
    testtokn.make_config_file(&confname);
    test_token_env(&testtokn, &confname);
    test_token_null_args(&confname);
    testtokn.finalize();
}

#[test]
#[parallel]
fn test_token_sql() {
    let mut testtokn = test_token_setup("test_token.sql");
    let confname = format!("{}/test_token_sqlite.conf", TESTDIR);
    testtokn.make_config_file(&confname);
    test_token_env(&testtokn, &confname);
    test_token_null_args(&confname);
    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_null() {
    let dbpath = format!("{}/{}", TESTDIR, "test_interface_null.sql");
    let mut testtokn = TestToken::new(dbpath, true);
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
                let mut args =
                    testtokn.make_init_args(Some(testtokn.make_init_string()));
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
    let dbpath = format!("{}/{}", TESTDIR, "test_interface_pkcs11.sql");
    let mut testtokn = TestToken::new(dbpath, true);
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
                let mut args =
                    testtokn.make_init_args(Some(testtokn.make_init_string()));
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
    let dbpath =
        format!("{}/{}", TESTDIR, "test_interface_pkcs11_version3.sql");
    let mut testtokn = TestToken::new(dbpath, true);
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
                let mut args =
                    testtokn.make_init_args(Some(testtokn.make_init_string()));
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
    let dbpath =
        format!("{}/{}", TESTDIR, "test_interface_pkcs11_version240.sql");
    let mut testtokn = TestToken::new(dbpath, true);
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
                let mut args =
                    testtokn.make_init_args(Some(testtokn.make_init_string()));
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

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::fmt::Write as _;
use std::io::Write;

use crate::tests::*;

use serial_test::{parallel, serial};

#[cfg(any(feature = "jsondb", feature = "sqlitedb"))]
fn test_token_setup(name: &str) -> TestToken {
    let mut testtokn = TestToken::new(String::from(name));
    testtokn.setup_db(None);
    testtokn
}

#[cfg(any(feature = "jsondb", feature = "sqlitedb"))]
fn test_token_env(suffix: &str) {
    let dbname = format!("test_token_env{}", suffix);
    let mut testtokn = test_token_setup(&dbname);
    let confname = format!("{}/test_token_env{}.conf", TESTDIR, suffix);
    testtokn.make_config_file(&confname);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = TestToken::make_init_args(None);
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::set_var("KRYOPTIC_CONF", confname);
                let ret = force_load_config();
                assert_eq!(ret, CKR_OK);
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                env::remove_var("KRYOPTIC_CONF");
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[cfg(any(feature = "jsondb", feature = "sqlitedb"))]
fn test_token_null_args(suffix: &str) {
    let dbname = format!("test_token_nullargs{}", suffix);
    let mut testtokn = test_token_setup(&dbname);
    let confname = format!("{}/test_token_nullargs{}.conf", TESTDIR, suffix);
    testtokn.make_config_file(&confname);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                env::set_var("KRYOPTIC_CONF", confname);
                let ret = force_load_config();
                assert_eq!(ret, CKR_OK);
                let ret = init_fn(std::ptr::null_mut());
                env::remove_var("KRYOPTIC_CONF");
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
    let basedir = format!("{}/datadirtest", TESTDIR);
    let confdir = format!("{}/kryoptic", basedir);
    let confname = format!("{}/{}", confdir, config::DEFAULT_CONF_NAME);
    let dbname = String::from("token");
    std::fs::create_dir_all(confdir).unwrap();

    let mut testtokn = TestToken::new(dbname);
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
                let mut args = TestToken::make_init_args(None);
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::remove_var("KRYOPTIC_CONF");
                env::set_var("XDG_CONFIG_HOME", basedir);
                let ret = force_load_config();
                assert_eq!(ret, CKR_OK);
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                env::remove_var("XDG_CONFIG_HOME");
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[cfg(feature = "jsondb")]
#[test]
#[serial]
fn test_token_json() {
    test_token_env(".json");
    test_token_null_args(".json");
}

#[cfg(feature = "sqlitedb")]
#[test]
#[serial]
fn test_token_sql() {
    test_token_env(".sql");
    test_token_null_args(".sql");
}

#[test]
#[parallel]
fn test_interface_null() {
    let dbname = String::from("test_interface_null");
    let mut testtokn = TestToken::new(dbname);
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
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
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
    let dbname = String::from("test_interface_pkcs11");
    let mut testtokn = TestToken::new(dbname);
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
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
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
    let dbname = String::from("test_interface_pkcs11_version3");
    let mut testtokn = TestToken::new(dbname);
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
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
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
    let dbname = String::from("test_interface_pkcs11_version240");
    let mut testtokn = TestToken::new(dbname);
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
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
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

#[test]
#[serial]
fn test_config_multiple_tokens() {
    let name = String::from("test_config_multiple");
    let confname = format!("{}/{}.conf", TESTDIR, name);
    let dbs = [
        #[cfg(feature = "memorydb")]
        (
            "memory",
            String::from("flags=encrypt"), // TODO fix and test unencrypted memory!
            "TOKEN 1",
        ),
        #[cfg(feature = "jsondb")]
        ("json", format!("{}/{}.json", TESTDIR, name), "TOKEN 2"),
        #[cfg(feature = "sqlitedb")]
        ("sqlite", format!("{}/{}.sql", TESTDIR, name), "TOKEN 3"),
        #[cfg(feature = "nssdb")]
        (
            "nssdb",
            format!("configDir={}/{}", TESTDIR, name),
            "TOKEN 4",
        ),
    ];
    let mut config = String::new();
    let mut tokens = Vec::<TestToken>::new();
    for db in &dbs {
        let mut token =
            TestToken::new_type(String::from(db.0), db.1.clone(), name.clone());
        token.setup_db(None);
        /* here we hand code a config file.
         * to ensure changes in the toml crate do not break the format */
        write!(
            &mut config,
            "[[slots]]\nslot = {}\ndbtype = \"{}\"\ndbargs = \"{}\"\ndescription = \"{}\"\n",
            token.get_slot(),
            db.0,
            db.1,
            db.2
        )
        .unwrap();
        tokens.push(token);
    }

    /* write out the config */
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&confname)
        .unwrap();
    file.write(config.as_bytes()).unwrap();

    /* try to init this token now */
    let mut args = TestToken::make_init_args(None);
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { env::set_var("KRYOPTIC_CONF", confname) };
    let ret = force_load_config();
    assert_eq!(ret, CKR_OK);
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { env::remove_var("KRYOPTIC_CONF") };
    assert_eq!(ret, CKR_OK);

    /* check slots and tokens */
    for tok in &tokens {
        let mut info = CK_SLOT_INFO::default();
        let ret =
            fn_get_slot_info(tok.get_slot(), &mut info as CK_SLOT_INFO_PTR);
        assert_eq!(ret, CKR_OK);
        let desc = std::str::from_utf8(&info.slotDescription).unwrap();
        assert_eq!(desc.starts_with("TOKEN "), true);
    }
}

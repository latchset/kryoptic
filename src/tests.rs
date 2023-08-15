// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use std::ffi::CString;
use super::*;

struct TestData<'a> {
    filename: Option<&'a str>
}

fn test_setup(filename: &str) {
    let test_token = serde_json::json!({
        "objects": [{
            "handle": 4030201,
            "attributes": {
                "CKA_CLASS": 2,
                "CKA_KEY_TYPE": 0,
                "CKA_DESTROYABLE": false,
                "CKA_ID": "AQ==",
                "CKA_LABEL": "Test RSA Key",
                "CKA_MODIFIABLE": false,
                "CKA_MODULUS": "AQIDBAUGBwg=",
                "CKA_PRIVATE": false,
                "CKA_PUBLIC_EXPONENT": "AQAB",
                "CKA_TOKEN": true
            }
        }]
    });
    let file = std::fs::File::create(filename).unwrap();
    serde_json::to_writer_pretty(file, &test_token).unwrap();
}

fn test_init_args(filename: &str) -> CK_C_INITIALIZE_ARGS {
    CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: 0,
        pReserved: CString::new(filename).unwrap().into_raw() as *mut std::ffi::c_void,
    }
}


fn test_cleanup(filename: &str) {
    std::fs::remove_file(filename).unwrap_or(());
}

impl Drop for TestData<'_> {
    fn drop(&mut self) {
        if let Some(f) = self.filename {
            test_cleanup(f);
        }
    }
}

#[test]
fn test_token() {

    let testdata = TestData {
        filename: Some("test_token.json"),
    };
    test_setup(testdata.filename.unwrap());

    let mut plist :CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list :CK_FUNCTION_LIST = *plist;
        match list.C_Initialize{
            Some(value) => {
                let mut args = test_init_args(testdata.filename.unwrap());
                let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!()
        }
    }
}

#[test]
fn test_init_fini() {
    let testdata = TestData {
        filename: Some("test_init_fini.json"),
    };
    test_setup(testdata.filename.unwrap());

    let mut args = test_init_args(testdata.filename.unwrap());
    let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

#[test]
fn test_random() {
    let testdata = TestData {
        filename: Some("test_random.json"),
    };
    test_setup(testdata.filename.unwrap());

    let mut args = test_init_args(testdata.filename.unwrap());
    let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut handle);
    assert_eq!(ret, CKR_OK);
    let mut data: &[u8] = &mut [0, 0, 0, 0];
    ret = fn_generate_random(handle, data.as_ptr() as *mut u8, data.len() as CK_ULONG);
    assert_eq!(ret, CKR_OK);
    assert_ne!(data, &[0, 0, 0, 0]);
    ret = fn_close_session(handle);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

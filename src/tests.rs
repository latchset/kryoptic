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
            "handle": 1,
            "attributes": {
                "CKA_UNIQUE_ID": "1",
                "CKA_CLASS": 4,
                "CKA_KEY_TYPE": 16,
                "CKA_LABEL": "User PIN",
                "CKA_VALUE": "MTIzNDU2Nzg=",
            }
        }, {
            "handle": 4030201,
            "attributes": {
                "CKA_UNIQUE_ID": "2",
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
        }, {
            "handle": 4030202,
            "attributes": {
                "CKA_UNIQUE_ID": "3",
                "CKA_CLASS": 3,
                "CKA_KEY_TYPE": 0,
                "CKA_DESTROYABLE": false,
                "CKA_ID": "AQ==",
                "CKA_LABEL": "Test RSA Key",
                "CKA_MODIFIABLE": false,
                "CKA_MODULUS": "AQIDBAUGBwg=",
                "CKA_PRIVATE": true,
                "CKA_SENSITIVE": true,
                "CKA_EXTRACTABLE": false,
                "CKA_PUBLIC_EXPONENT": "AQAB",
                "CKA_PRIVATE_EXPONENT": "AQAD",
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

#[test]
fn test_login() {
    let testdata = TestData {
        filename: Some("test_login.json"),
    };
    test_setup(testdata.filename.unwrap());

    let mut args = test_init_args(testdata.filename.unwrap());
    let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut handle);
    assert_eq!(ret, CKR_OK);

    let mut info = CK_SESSION_INFO {
        slotID: CK_UNAVAILABLE_INFORMATION,
        state: CK_UNAVAILABLE_INFORMATION,
        flags: 0,
        ulDeviceError: 0,
    };
    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);

    let mut handle2: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(0, CKF_SERIAL_SESSION|CKF_RW_SESSION, std::ptr::null_mut(), None, &mut handle2);
    assert_eq!(ret, CKR_OK);
    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    /* login */
    let pin = "12345678";
    ret = fn_login(handle, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
    assert_eq!(ret, CKR_OK);

    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS);

    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);

    ret = fn_login(handle, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
    assert_eq!(ret, CKR_USER_ALREADY_LOGGED_IN);

    ret = fn_logout(handle2);
    assert_eq!(ret, CKR_OK);

    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);

    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    ret = fn_logout(handle);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    ret = fn_close_session(handle);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(handle2);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

#[test]
fn test_get_attr() {
    let testdata = TestData {
        filename: Some("test_get_attr.json"),
    };
    test_setup(testdata.filename.unwrap());

    let mut args = test_init_args(testdata.filename.unwrap());
    let mut args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(0, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &mut handle);
    assert_eq!(ret, CKR_OK);

    let mut template = CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };

    /* public key data */
    let mut o_handle: CK_ULONG = 4030201;

    ret = fn_get_attribute_value(handle, o_handle, &mut template, 1);
    assert_eq!(ret, CKR_OK);
    assert_ne!(template.ulValueLen, 0);

    let data: &mut [u8] = &mut [0; 128];
    template.pValue = data.as_ptr() as *mut std::ffi::c_void;
    template.ulValueLen = 128;

    ret = fn_get_attribute_value(handle, o_handle, &mut template, 1);
    assert_eq!(ret, CKR_OK);
    let size = template.ulValueLen as usize;
    let value = std::str::from_utf8(&data[0..size]).unwrap();
    assert_eq!(value, "Test RSA Key");

    template.ulValueLen = 1;
    ret = fn_get_attribute_value(handle, o_handle, &mut template, 1);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);

    /* private key data */

    o_handle = 4030202;
    template.type_ = CKA_PRIVATE_EXPONENT;
    template.ulValueLen = 128;
    ret = fn_get_attribute_value(handle, o_handle, &mut template, 1);
    assert_eq!(ret, CKR_OBJECT_HANDLE_INVALID);

    /* login */
    let pin = "12345678";
    ret = fn_login(handle, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
    assert_eq!(ret, CKR_OK);

    ret = fn_get_attribute_value(handle, o_handle, &mut template, 1);
    assert_eq!(ret, CKR_ATTRIBUTE_SENSITIVE);

    template.type_ = CKA_PUBLIC_EXPONENT;
    template.ulValueLen = 128;
    ret = fn_get_attribute_value(handle, o_handle, &mut template, 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template.ulValueLen, 3);

    ret = fn_logout(handle);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(handle);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

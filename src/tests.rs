// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

use super::*;
use std::ffi::CString;

const CK_ULONG_SIZE: usize = std::mem::size_of::<CK_ULONG>();
const CK_BBOOL_SIZE: usize = std::mem::size_of::<CK_BBOOL>();
macro_rules! make_attribute {
    ($type:expr, $value:expr, $length:expr) => {
        CK_ATTRIBUTE {
            type_: $type,
            pValue: $value as CK_VOID_PTR,
            ulValueLen: $length as CK_ULONG,
        }
    };
}

struct TestData<'a> {
    filename: Option<&'a str>,
}

fn test_setup(filename: &str) {
    let test_token = serde_json::json!({
        "objects": [{
            "attributes": {
                "CKA_UNIQUE_ID": "0",
                "CKA_CLASS": 4,
                "CKA_KEY_TYPE": 16,
                "CKA_LABEL": "SO PIN",
                "CKA_VALUE": "MTIzNDU2Nzg=",
                "CKA_TOKEN": true
            }
        }, {
            "attributes": {
                "CKA_UNIQUE_ID": "1",
                "CKA_CLASS": 4,
                "CKA_KEY_TYPE": 16,
                "CKA_LABEL": "User PIN",
                "CKA_VALUE": "MTIzNDU2Nzg=",
                "CKA_TOKEN": true
            }
        }, {
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
        pReserved: CString::new(filename).unwrap().into_raw()
            as *mut std::ffi::c_void,
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

    let mut plist: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = C_GetFunctionList(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(value) => {
                let mut args = test_init_args(testdata.filename.unwrap());
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_eq!(ret, CKR_OK)
            }
            None => todo!(),
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
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
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
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);
    let data: &[u8] = &mut [0, 0, 0, 0];
    ret = fn_generate_random(
        handle,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
    );
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
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    let mut handle: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut handle,
    );
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
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);
    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        handle,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_get_session_info(handle, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS);

    ret = fn_get_session_info(handle2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);

    ret = fn_login(
        handle,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
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
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    let mut template = Vec::<CK_ATTRIBUTE>::new();
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    ));
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    template.clear();
    template.push(make_attribute!(CKA_LABEL, std::ptr::null_mut(), 0));

    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_ne!(template[0].ulValueLen, 0);

    let data: &mut [u8] = &mut [0; 128];
    template[0].pValue = data.as_ptr() as *mut std::ffi::c_void;
    template[0].ulValueLen = 128;

    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let size = template[0].ulValueLen as usize;
    let value = std::str::from_utf8(&data[0..size]).unwrap();
    assert_eq!(value, "Test RSA Key");

    template[0].ulValueLen = 1;
    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);

    /* private key data */
    template.clear();
    handle = CK_INVALID_HANDLE;
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("3").unwrap().into_raw(),
        1
    ));
    /* first try should not find it */
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    assert_eq!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* after login should find it */
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    template.clear();
    template.push(make_attribute!(
        CKA_PRIVATE_EXPONENT,
        (&mut [0; 128]).as_ptr(),
        128
    ));

    /* should fail for sensitive attributes */
    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_SENSITIVE);

    /* and succeed for public ones */
    template[0].type_ = CKA_PUBLIC_EXPONENT;
    template[0].ulValueLen = 128;
    ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, 3);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

#[test]
fn test_create_objects() {
    let testdata = TestData {
        filename: Some("test_create_objects.json"),
    };
    test_setup(testdata.filename.unwrap());

    let mut args = test_init_args(testdata.filename.unwrap());
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    let mut class = CKO_DATA;
    let application = "test";
    let data = "payload";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(application).unwrap().into_raw(),
            application.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data).unwrap().into_raw(),
            data.len()
        ),
    ];

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut intoken: CK_BBOOL = CK_TRUE;
    template.push(make_attribute!(
        CKA_TOKEN,
        &mut intoken as *mut _,
        CK_BBOOL_SIZE
    ));

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    let login_session = session;

    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    class = CKO_CERTIFICATE;
    let mut ctype = CKC_X_509;
    let mut trusted: CK_BBOOL = CK_FALSE;
    let ignored = "ignored";
    let bogus = "bogus";
    template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_CERTIFICATE_TYPE,
            &mut ctype as *mut _,
            CK_ULONG_SIZE
        ),
        make_attribute!(CKA_TRUSTED, &mut trusted as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_CHECK_VALUE, ignored.as_ptr(), 42),
        make_attribute!(CKA_SUBJECT, bogus.as_ptr(), bogus.len()),
        make_attribute!(CKA_VALUE, bogus.as_ptr(), bogus.len()),
    ];

    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

#[test]
fn test_init_token() {
    let testdata = TestData {
        filename: Some("test_init_token.json"),
    };
    /* skip setup, we are creating an unitiliaized token */

    let mut args = test_init_args(testdata.filename.unwrap());
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    let mut ro_session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;

    /* init once */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        0,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    /* verify wrong SO PIN fails */
    let bad_value = "SO Bad Value";
    ret = fn_init_token(
        0,
        CString::new(bad_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_PIN_INCORRECT);

    /* re-init */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        0,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    /* login as so */
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);
    ret = fn_login(
        session,
        CKU_SO,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* change so pin */
    let new_pin = "New SO Pin Value";
    ret = fn_set_pin(
        session,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* try to open ro_session and fail */
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(ret, CKR_SESSION_READ_WRITE_SO_EXISTS);

    /* logout and retry */
    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_open_session(
        0,
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut ro_session,
    );
    assert_eq!(ret, CKR_OK);

    /* try to change pin and fail with ro_session */
    ret = fn_set_pin(
        ro_session,
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    /* try to login again and fail because of ro_session exists */
    ret = fn_login(
        session,
        CKU_SO,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_SESSION_READ_ONLY_EXISTS);

    /* try again after closing ro_session */
    ret = fn_close_session(ro_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_login(
        session,
        CKU_SO,
        CString::new(new_pin).unwrap().into_raw() as *mut u8,
        new_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* set user pin */
    let user_pin = "User PIN Value";
    ret = fn_init_pin(
        session,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* try to log in as user and fail because SO active */
    ret = fn_login(
        session,
        CKU_USER,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

    /* retry user login after logout */
    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_login(
        session,
        CKU_USER,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* change user pin as user */
    let new_user_pin = "New User PIN Value";
    ret = fn_set_pin(
        session,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
        CString::new(new_user_pin).unwrap().into_raw() as *mut u8,
        new_user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);

    /* change back user pin after logout */
    ret = fn_set_pin(
        session,
        CString::new(new_user_pin).unwrap().into_raw() as *mut u8,
        new_user_pin.len() as CK_ULONG,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);
    ret = fn_finalize(std::ptr::null_mut());
    assert_eq!(ret, CKR_OK);
}

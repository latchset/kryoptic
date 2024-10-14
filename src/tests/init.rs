// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

#[cfg(feature = "fips")]
use crate::fips::indicators::KRF_FIPS;
use crate::tests::*;

use serial_test::{parallel, serial};

#[test]
#[parallel]
fn test_init_token() {
    let mut testtokn = TestToken::new("test_init_token.sql", true);

    let mut args = testtokn.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);
    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    let mut ro_session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    let label = "Init Test";
    let mut label32 = [0x20u8; 32];
    label32[..label.len()].copy_from_slice(label.as_bytes());

    /* init once */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        testtokn.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    /* verify wrong SO PIN fails */
    let bad_value = "SO Bad Value";
    ret = fn_init_token(
        testtokn.get_slot(),
        CString::new(bad_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_PIN_INCORRECT);

    /* re-init */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        testtokn.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        label32.as_mut_ptr(),
    );
    assert_eq!(ret, CKR_OK);

    /* Check label */
    let mut token_info = CK_TOKEN_INFO::default();
    ret = fn_get_token_info(testtokn.get_slot(), &mut token_info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(token_info.label, label32);

    /* login as so */
    ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );

    #[cfg(feature = "fips")]
    {
        let mut handle: [CK_ULONG; 1] = [CK_INVALID_HANDLE];
        let template =
            make_attr_template(&[(CKA_CLASS, CKO_VALIDATION)], &[], &[]);
        let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
        assert_eq!(ret, CKR_OK);
        let mut count: CK_ULONG = 0;
        let ret = fn_find_objects(session, handle.as_mut_ptr(), 1, &mut count);
        assert_eq!(ret, CKR_OK);
        assert_eq!(count, 1);
        assert_ne!(handle[0], CK_INVALID_HANDLE);
        let ret = fn_find_objects_final(session);
        assert_eq!(ret, CKR_OK);

        let mut vtype: CK_ULONG = 0;
        let mut vversion: Vec<u8> = vec![0u8; 2];
        let mut vlevel: CK_ULONG = 0;
        let mut vflag: CK_ULONG = 0;
        let mut vauth: CK_ULONG = 0;
        let mut extract_template = make_ptrs_template(&[
            (CKA_VALIDATION_TYPE, void_ptr!(&mut vtype), CK_ULONG_SIZE),
            (
                CKA_VALIDATION_VERSION,
                void_ptr!(vversion.as_mut_ptr()),
                vversion.len(),
            ),
            (CKA_VALIDATION_LEVEL, void_ptr!(&mut vlevel), CK_ULONG_SIZE),
            (CKA_VALIDATION_FLAG, void_ptr!(&mut vflag), CK_ULONG_SIZE),
            (
                CKA_VALIDATION_AUTHORITY_TYPE,
                void_ptr!(&mut vauth),
                CK_ULONG_SIZE,
            ),
        ]);
        let ret = fn_get_attribute_value(
            session,
            handle[0],
            extract_template.as_mut_ptr(),
            extract_template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(vtype, CKV_TYPE_SOFTWARE);
        assert_eq!(vversion, vec![3u8, 0u8]);
        assert_eq!(vlevel, 1);
        assert_eq!(vflag, KRF_FIPS);
        assert_eq!(vauth, CKV_AUTHORITY_TYPE_NIST_CMVP);
    }

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
        testtokn.get_slot(),
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
        testtokn.get_slot(),
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

    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

fn test_re_init_token_common(db: &str) {
    let mut testtokn = TestToken::new(db, true);

    let mut args = testtokn.make_init_args();
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let mut ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    /* init once */
    let pin_value = "SO Pin Value";
    ret = fn_init_token(
        testtokn.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_finalize(std::ptr::null_mut() as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[serial]
fn test_re_init_token_json() {
    test_re_init_token_common("test_reinit_token.json")
}

#[test]
#[serial]
fn test_re_init_token_sql() {
    test_re_init_token_common("test_reinit_token.sql")
}

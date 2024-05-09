// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_session_objects() {
    let mut testtokn = TestToken::initialized("test_session_objects.sql", None);

    let mut login_session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    let mut ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION,
        std::ptr::null_mut(),
        None,
        &mut login_session,
    );
    assert_eq!(ret, CKR_OK);

    /* login */
    let pin = "12345678";
    ret = fn_login(
        login_session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut session: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    /* ephemeral session object */
    let mut class = CKO_DATA;
    let app1 = "app1";
    let data1 = "session data";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(app1).unwrap().into_raw(),
            app1.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data1).unwrap().into_raw(),
            data1.len()
        ),
    ];

    let mut handle1: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle1,
    );
    assert_eq!(ret, CKR_OK);

    /* store in token object */
    let mut intoken: CK_BBOOL = CK_TRUE;
    let app2 = "app2";
    let data2 = "token data";
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(
            CKA_APPLICATION,
            CString::new(app2).unwrap().into_raw(),
            app2.len()
        ),
        make_attribute!(
            CKA_VALUE,
            CString::new(data2).unwrap().into_raw(),
            data2.len()
        ),
        make_attribute!(CKA_TOKEN, &mut intoken as *mut _, CK_BBOOL_SIZE),
    ];

    let mut handle2: CK_ULONG = CK_INVALID_HANDLE;
    ret = fn_create_object(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    /* check that the session object handle invalid now */
    template.clear();
    template.push(make_attribute!(CKA_VALUE, std::ptr::null_mut(), 0));

    ret = fn_get_attribute_value(session, handle1, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OBJECT_HANDLE_INVALID);

    /* check that the session object is gone */
    template.clear();
    template.push(make_attribute!(
        CKA_APPLICATION,
        CString::new(app1).unwrap().into_raw(),
        app1.len()
    ));

    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle1, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* check that the token object is there */
    template.clear();
    template.push(make_attribute!(
        CKA_APPLICATION,
        CString::new(app2).unwrap().into_raw(),
        app2.len()
    ));

    handle2 = CK_INVALID_HANDLE;
    ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects(session, &mut handle2, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle2, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_logout(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(login_session);
    assert_eq!(ret, CKR_OK);
    ret = fn_close_session(session);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

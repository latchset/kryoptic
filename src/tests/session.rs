// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
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
    let app1 = "app1";
    let handle1 = ret_or_panic!(import_object(
        session,
        CKO_DATA,
        &[],
        &[
            (CKA_APPLICATION, app1.as_bytes()),
            (CKA_VALUE, "session data".as_bytes())
        ],
        &[],
    ));

    /* store in token object */
    let app2 = "app2";
    let _ = ret_or_panic!(import_object(
        session,
        CKO_DATA,
        &[],
        &[
            (CKA_APPLICATION, app2.as_bytes()),
            (CKA_VALUE, "token data".as_bytes())
        ],
        &[(CKA_TOKEN, true)],
    ));

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
    let mut template =
        make_ptrs_template(&[(CKA_VALUE, std::ptr::null_mut(), 0)]);

    ret = fn_get_attribute_value(session, handle1, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OBJECT_HANDLE_INVALID);

    /* check that the session object is gone */
    let template =
        make_attr_template(&[], &[(CKA_APPLICATION, app1.as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut handle1 = CK_INVALID_HANDLE;
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle1, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* check that the token object is there */
    let template =
        make_attr_template(&[], &[(CKA_APPLICATION, app2.as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut handle2 = CK_INVALID_HANDLE;
    let mut count: CK_ULONG = 0;
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

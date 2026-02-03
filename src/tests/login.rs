// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_login_close() {
    let mut testtokn = TestToken::initialized("test_login_close", None);

    /* Run this twice and make sure the second call does not return ALREADY_LOGGED_IN */
    for _ in 0..2 {
        let session = testtokn.get_session(true);

        let mut info = CK_SESSION_INFO {
            slotID: CK_UNAVAILABLE_INFORMATION,
            state: CK_UNAVAILABLE_INFORMATION,
            flags: 0,
            ulDeviceError: 0,
        };
        let ret = fn_get_session_info(session, &mut info);
        assert_eq!(ret, CKR_OK);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

        /* login */
        let pin = "12345678";
        let ret = fn_login(
            session,
            CKU_USER,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        let ret = fn_get_session_info(session, &mut info);
        assert_eq!(ret, CKR_OK);
        assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);

        /* close session should reset the login state */
        testtokn.close_session();
    }
}

#[test]
#[parallel]
fn test_login_close_all() {
    let mut testtokn = TestToken::initialized("test_login_close_all", None);

    let mut session = CK_INVALID_HANDLE;
    let ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session,
    );
    assert_eq!(ret, CKR_OK);

    let mut info = CK_SESSION_INFO {
        slotID: CK_UNAVAILABLE_INFORMATION,
        state: CK_UNAVAILABLE_INFORMATION,
        flags: 0,
        ulDeviceError: 0,
    };
    let ret = fn_get_session_info(session, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    /* login */
    let pin = "12345678";
    let ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_get_session_info(session, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);

    /* close session should reset the login state */
    let ret = fn_close_all_sessions(testtokn.get_slot());
    assert_eq!(ret, CKR_OK);

    let session = testtokn.get_session(true);
    let mut info = CK_SESSION_INFO {
        slotID: CK_UNAVAILABLE_INFORMATION,
        state: CK_UNAVAILABLE_INFORMATION,
        flags: 0,
        ulDeviceError: 0,
    };
    let ret = fn_get_session_info(session, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);
}

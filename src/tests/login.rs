// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;

fn test_login(name: &str) {
    let mut testtokn = TestToken::initialized(name, None);
    let session = testtokn.get_session(false);

    let mut info = CK_SESSION_INFO {
        slotID: CK_UNAVAILABLE_INFORMATION,
        state: CK_UNAVAILABLE_INFORMATION,
        flags: 0,
        ulDeviceError: 0,
    };
    let ret = fn_get_session_info(session, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);

    let mut session2: CK_SESSION_HANDLE = CK_UNAVAILABLE_INFORMATION;
    let ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session2,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_get_session_info(session2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    let pin_flags_mask = CKF_SO_PIN_TO_BE_CHANGED
        | CKF_SO_PIN_LOCKED
        | CKF_SO_PIN_FINAL_TRY
        | CKF_SO_PIN_COUNT_LOW
        | CKF_USER_PIN_TO_BE_CHANGED
        | CKF_USER_PIN_LOCKED
        | CKF_USER_PIN_FINAL_TRY
        | CKF_USER_PIN_COUNT_LOW;

    /* check pin flags */
    let mut token_info = CK_TOKEN_INFO::default();
    let ret = fn_get_token_info(testtokn.get_slot(), &mut token_info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(token_info.flags & pin_flags_mask, 0);

    /* fail login first */
    let pin = "87654321";
    let ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_ne!(ret, CKR_OK);

    /* check pin flags */
    let mut token_info = CK_TOKEN_INFO::default();
    let ret = fn_get_token_info(testtokn.get_slot(), &mut token_info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(token_info.flags & pin_flags_mask, 0);

    /* fail a few more time to brig the count to low */
    for _ in 1..7 {
        let pin = "87654321";
        let ret = fn_login(
            session,
            CKU_USER,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_ne!(ret, CKR_OK);
    }

    /* check pin flags */
    let mut token_info = CK_TOKEN_INFO::default();
    let ret = fn_get_token_info(testtokn.get_slot(), &mut token_info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(token_info.flags & pin_flags_mask, CKF_USER_PIN_COUNT_LOW);

    /* login */
    let pin = "12345678";
    let ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* check pin flags */
    let mut token_info = CK_TOKEN_INFO::default();
    let ret = fn_get_token_info(testtokn.get_slot(), &mut token_info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(token_info.flags & pin_flags_mask, 0);

    let ret = fn_get_session_info(session, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_USER_FUNCTIONS);

    let ret = fn_get_session_info(session2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_USER_FUNCTIONS);

    let ret = fn_login(
        session,
        CKU_USER,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_USER_ALREADY_LOGGED_IN);

    let ret = fn_logout(session2);
    assert_eq!(ret, CKR_OK);

    let ret = fn_get_session_info(session, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RO_PUBLIC_SESSION);

    let ret = fn_get_session_info(session2, &mut info);
    assert_eq!(ret, CKR_OK);
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);

    let ret = fn_logout(session);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    let ret = fn_close_session(session2);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_login_json() {
    test_login("test_login.json");
}

#[test]
#[parallel]
fn test_login_sql() {
    test_login("test_login.sql");
}

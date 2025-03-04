// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_session_objects() {
    let mut testtokn = TestToken::initialized("test_session_objects", None);

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

    let app2 = "app2";
    let mut expect_count = 0;
    if testtokn.dbtype != "nssdb" {
        /* store in token object */
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
        expect_count = 1;
    }

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
    assert_eq!(count, expect_count);
    if count > 0 {
        assert_ne!(handle2, CK_INVALID_HANDLE);
    }
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

#[test]
#[parallel]
#[cfg(feature = "aes")]
fn test_operations() {
    let mut testtokn = TestToken::initialized("test_operations", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* generate a key that can be used to start an operation */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_VALUE_LEN, 16),],
        &[],
        &[(CKA_TOKEN, false), (CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    let mut data = [0xAu8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    /* begin 2 operations in parallel */

    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* ensure both work */

    let mut enc: [u8; 16] = [0; 16];
    let mut enc_len: CK_ULONG = 16;
    let ret = fn_encrypt_update(
        session,
        data.as_mut_ptr(),
        data.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut dec: [u8; 16] = [0; 16];
    let mut dec_len: CK_ULONG = 16;
    let ret = fn_decrypt_update(
        session,
        enc.as_mut_ptr(),
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OK);

    /* cancel both operations at once */
    let ret = fn_session_cancel(session, CKF_ENCRYPT | CKF_DECRYPT);
    assert_eq!(ret, CKR_OK);

    /* ensure both stopped working */
    let ret = fn_encrypt_update(
        session,
        data.as_mut_ptr(),
        data.len() as CK_ULONG,
        enc.as_mut_ptr(),
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    let ret = fn_decrypt_update(
        session,
        enc.as_mut_ptr(),
        enc_len,
        dec.as_mut_ptr(),
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    testtokn.finalize();
}

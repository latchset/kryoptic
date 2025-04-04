// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
#[cfg(feature = "rsa")]
fn test_get_attr() {
    let mut testtokn = TestToken::initialized(
        "test_get_attr",
        Some("testdata/test_basic_rsa.json"),
    );
    let session = testtokn.get_session(false);

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let mut template =
        make_ptrs_template(&[(CKA_LABEL, std::ptr::null_mut(), 0)]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_ne!(template[0].ulValueLen, 0);

    let data: &mut [u8] = &mut [0; 128];
    let mut template =
        make_ptrs_template(&[(CKA_LABEL, void_ptr!(data.as_mut_ptr()), 128)]);

    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let size = template[0].ulValueLen as usize;
    let value = std::str::from_utf8(&data[0..size]).unwrap();
    assert_eq!(value, "Test RSA Key");

    template[0].ulValueLen = 1;
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);

    /* private key data */
    handle = CK_INVALID_HANDLE;
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    /* first try should not find it */
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    assert_eq!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* login */
    testtokn.login();

    /* after login should find it */
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let mut e = [0u8; 128];
    let mut template = make_ptrs_template(&[(
        CKA_PRIVATE_EXPONENT,
        void_ptr!(e.as_mut_ptr()),
        e.len(),
    )]);

    /* should fail for sensitive attributes */
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_SENSITIVE);

    /* and succeed for public ones */
    let mut template = make_ptrs_template(&[(
        CKA_PUBLIC_EXPONENT,
        void_ptr!(e.as_mut_ptr()),
        e.len(),
    )]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, 3);

    /* Invalid attributes for RSA keys should report as such in both rv and length */
    let mut template =
        make_ptrs_template(&[(CKA_EC_POINT, std::ptr::null_mut(), 0)]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_TYPE_INVALID);
    assert_eq!(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);

    /* Valid attributes that are not present should report this only in length */
    let mut template = make_ptrs_template(&[(
        CKA_ALLOWED_MECHANISMS,
        std::ptr::null_mut(),
        0,
    )]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);

    testtokn.finalize();
}

#[test]
#[parallel]
#[cfg(feature = "rsa")]
fn test_set_attr_rsa() {
    let mut testtokn = TestToken::initialized(
        "test_set_attr",
        Some("testdata/test_basic_rsa.json"),
    );
    let session = testtokn.get_session(false);

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let label = "new label";
    let template = make_ptrs_template(&[(
        CKA_LABEL,
        void_ptr!(label.as_ptr()),
        label.as_bytes().len(),
    )]);
    let ret =
        fn_set_attribute_value(session, handle, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    testtokn.login();

    let ret =
        fn_set_attribute_value(session, handle, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    /* Open second, read-write, session. Keep the first around to make
     * sure the token does not logout */
    let mut session2 = CK_INVALID_HANDLE;
    let ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session2,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_set_attribute_value(
        session2,
        handle,
        template.as_ptr() as *mut _,
        1,
    );
    assert_eq!(ret, CKR_OK);

    let unique = "unsettable";
    let template = make_ptrs_template(&[(
        CKA_UNIQUE_ID,
        void_ptr!(unique.as_ptr()),
        unique.as_bytes().len(),
    )]);

    let ret = fn_set_attribute_value(
        session2,
        handle,
        template.as_ptr() as *mut _,
        1,
    );
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    let ret = fn_close_session(session2);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

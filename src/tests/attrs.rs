// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_get_attr() {
    let mut testtokn = TestToken::initialized("test_get_attr.sql", None);
    let session = testtokn.get_session(false);

    let mut template = Vec::<CK_ATTRIBUTE>::new();
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    ));
    let ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    template.clear();
    template.push(make_attribute!(CKA_LABEL, std::ptr::null_mut(), 0));

    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_ne!(template[0].ulValueLen, 0);

    let data: &mut [u8] = &mut [0; 128];
    template[0].pValue = data.as_ptr() as *mut std::ffi::c_void;
    template[0].ulValueLen = 128;

    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let size = template[0].ulValueLen as usize;
    let value = std::str::from_utf8(&data[0..size]).unwrap();
    assert_eq!(value, "Test RSA Key");

    template[0].ulValueLen = 1;
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
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
    let ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
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
    let ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    template.clear();
    template.push(make_attribute!(
        CKA_PRIVATE_EXPONENT,
        (&mut [0; 128]).as_ptr(),
        128
    ));

    /* should fail for sensitive attributes */
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_SENSITIVE);

    /* and succeed for public ones */
    template[0].type_ = CKA_PUBLIC_EXPONENT;
    template[0].ulValueLen = 128;
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, 3);

    testtokn.finalize();
}

#[test]
fn test_set_attr() {
    let mut testtokn = TestToken::initialized("test_set_attr.sql", None);
    let session = testtokn.get_session(false);

    let mut template = Vec::<CK_ATTRIBUTE>::new();
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        CString::new("2").unwrap().into_raw(),
        1
    ));
    let ret = fn_find_objects_init(session, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let label = "new label";
    template.clear();
    template.push(make_attribute!(CKA_LABEL, label.as_ptr(), label.len()));
    let ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    testtokn.login();

    let ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    let session = testtokn.get_session(true);

    let ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);

    let unique = "unsettable";
    template.clear();
    template.push(make_attribute!(
        CKA_UNIQUE_ID,
        unique.as_ptr(),
        unique.len()
    ));

    let ret = fn_set_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    testtokn.finalize();
}

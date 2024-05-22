// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_create_ec_objects() {
    let mut testtokn =
        TestToken::initialized("test_create_ec_objects.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let point = hex::decode(
        "041B803BF0586DECF25616E879B0399AA3DAAB60916FC76C9B6C687FC1454C\
         BA90D5F15AEB36E7070CFFB4966499B71B389453C0075203FA047D4F3E4434\
         3EDC84FB793BF1B8CA94DD3F293AFBE68E3BE93F1245BE9FB71BE3C50F1263\
         BC12D516",
    )
    .expect("Failed to decode hex point");
    let params =
        hex::decode("06052B81040022").expect("Failed to decode hex params");
    let _ = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_EC)],
        &[
            (CKA_LABEL, "EC Public Signature Key".as_bytes()),
            (CKA_EC_POINT, point.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_VERIFY, true)]
    ));

    /* Private EC key */
    let value = hex::decode(
        "4A77D1245D2C4751FF178040CC9E527B4D6CBB067B8FB01265B854FA581FD6\
         2DADC706025CBF515D80FD226F8F552F34",
    )
    .expect("Failed to decode value");
    let _ = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_EC)],
        &[
            (CKA_LABEL, "EC Private Signature Key".as_bytes()),
            (CKA_VALUE, value.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_SIGN, true)]
    ));

    testtokn.finalize();
}

#[test]
fn test_ecc_operations() {
    let mut testtokn = TestToken::initialized(
        "test_ecc_operations.sql",
        Some("testdata/test_ecc_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "11".as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    let data = "plaintext";
    let sign: [u8; 64] = [0; 64];
    let mut sign_len: CK_ULONG = 64;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 64);

    /* a second invocation should return an error */
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "10".as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* P-521 private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "13".as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    let data = "plaintext";
    let sign: [u8; 132] = [0; 132];
    let mut sign_len: CK_ULONG = 132;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 132);

    /* a second invocation should return an error */
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "12".as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

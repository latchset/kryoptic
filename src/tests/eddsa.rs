// Copyright 2024 Simo Sorce, Jakub Jelen
// See LICENSE.txt file for terms

use super::tests;
#[cfg(not(feature = "fips"))]
use tests::*;

#[cfg(not(feature = "fips"))]
use serial_test::parallel;

/* TODO enable for FIPS when our OpenSSL will include EdDSA in FIPS module */

#[test]
#[parallel]
#[cfg(not(feature = "fips"))]
fn test_create_eddsa_objects() {
    let mut testtokn =
        TestToken::initialized("test_create_eddsa_objects.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Test Vectors for Ed25519ctx */
    let point = hex::decode(
        "0420dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
    )
    .expect("Failed to decode hex point");
    let params = hex::decode("130c656477617264733235353139")
        .expect("Failed to decode hex params");
    let public_handle = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
        &[
            (CKA_LABEL, "Ed25519 Public Signature Key".as_bytes()),
            (CKA_EC_POINT, point.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_VERIFY, true)]
    ));

    /* Private EC key */
    let value = hex::decode(
        "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
    )
    .expect("Failed to decode value");
    let private_handle = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_EDWARDS)],
        &[
            (CKA_LABEL, "Ed25519 Private Signature Key".as_bytes()),
            (CKA_VALUE, value.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_SIGN, true)]
    ));

    let ctx = hex::decode("666f6f").expect("Failed to decode context");

    let params: CK_EDDSA_PARAMS = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        pContextData: ctx.as_ptr() as *mut CK_BYTE,
        ulContextDataLen: ctx.len() as u64,
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: void_ptr!(&params),
        ulParameterLen: sizeof!(CK_EDDSA_PARAMS),
    };
    let ret = fn_sign_init(session, &mut mechanism, private_handle);
    assert_eq!(ret, CKR_OK);

    let data = hex::decode("f726936d19c800494e3fdaff20b276a8")
        .expect("Failed to decode data");
    let sign: [u8; 64] = [0; 64];
    let mut sign_len: CK_ULONG = 64;
    let ret = fn_sign(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 64);
    let signature = hex::decode(
        "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a\
         8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
    )
    .expect("failed to decode expected signature");
    assert_eq!(signature, sign);

    let ret = fn_verify_init(session, &mut mechanism, public_handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
#[cfg(not(feature = "fips"))]
fn test_eddsa_operations() {
    let mut testtokn = TestToken::initialized(
        "test_eddsa_operations.sql",
        Some("testdata/test_eddsa_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Ed25519 private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "21".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init without parameters*/
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    /* 2 st Test vector from rfc8032 */
    let data = "\x72";
    let sign: [u8; 64] = [0; 64];
    let mut sign_len: CK_ULONG = 64;
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 64);

    let signature = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
        085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    )
    .expect("failed to decode expected signature");
    assert_eq!(signature, sign);

    /* a second invocation should return an error */
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "20".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Ed448 */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "23".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* sign init without parameters fails */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    /* the ed448 requires params */
    let params: CK_EDDSA_PARAMS = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        pContextData: std::ptr::null_mut(),
        ulContextDataLen: 0,
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_EDDSA_PARAMS),
    };
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    let ret = fn_sign_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    /* 2nd Test vector from rfc8032 for Ed448 */
    let data = "\x03";
    let sign: [u8; 114] = [0; 114];
    let mut sign_len: CK_ULONG = 114;
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 114);
    let signature = hex::decode(
        "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435\
         2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb\
         cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f\
         f3348ab21aa4adafd1d234441cf807c03a00",
    )
    .expect("failed to decode expected signature");
    assert_eq!(signature, sign);

    /* a second invocation should return an error */
    let ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that signature verification works */
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "22".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);
}

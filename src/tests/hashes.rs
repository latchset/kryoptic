// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_hashes_digest() {
    let mut testtokn = TestToken::initialized(
        "test_hashes.sql",
        Some("testdata/test_hashes.json"),
    );
    let session = testtokn.get_session(false);

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "2".as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 32] = [0; 32];
    let mut value: [u8; 32] = [0; 32];
    let mut template = make_ptrs_template(&[
        (CKA_VALUE, void_ptr!(value.as_mut_ptr()), value.len()),
        (CKA_OBJECT_ID, void_ptr!(hash.as_mut_ptr()), hash.len()),
    ]);
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 32] = [0; 32];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* update digest */
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    ret = fn_digest_update(session, value.as_mut_ptr(), value_len);
    assert_eq!(ret, CKR_OK);

    let mut digest2_len: CK_ULONG = 0;
    ret = fn_digest_final(session, std::ptr::null_mut(), &mut digest2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(digest_len, digest2_len);

    let mut digest2: [u8; 32] = [0; 32];
    ret = fn_digest_final(session, digest2.as_mut_ptr(), &mut digest2_len);
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 384 ==== */

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "3".as_bytes())], &[]);
    ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 48] = [0; 48];
    let mut value: [u8; 48] = [0; 48];
    let mut template = make_ptrs_template(&[
        (CKA_VALUE, void_ptr!(value.as_mut_ptr()), value.len()),
        (CKA_OBJECT_ID, void_ptr!(hash.as_mut_ptr()), hash.len()),
    ]);
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 48] = [0; 48];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 512 ==== */

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "4".as_bytes())], &[]);
    ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 64] = [0; 64];
    let mut value: [u8; 64] = [0; 64];
    let mut template = make_ptrs_template(&[
        (CKA_VALUE, void_ptr!(value.as_mut_ptr()), value.len()),
        (CKA_OBJECT_ID, void_ptr!(hash.as_mut_ptr()), hash.len()),
    ]);
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA512,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 64] = [0; 64];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    /* ==== SHA 1 ==== */

    /* get test data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "5".as_bytes())], &[]);
    ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut hash: [u8; 20] = [0; 20];
    let mut value: [u8; 20] = [0; 20];
    let mut template = make_ptrs_template(&[
        (CKA_VALUE, void_ptr!(value.as_mut_ptr()), value.len()),
        (CKA_OBJECT_ID, void_ptr!(hash.as_mut_ptr()), hash.len()),
    ]);
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as u64,
    );
    assert_eq!(ret, CKR_OK);

    let value_len = template[0].ulValueLen;

    /* one shot digest */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA_1,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_digest_init(session, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let mut digest: [u8; 20] = [0; 20];
    let mut digest_len: CK_ULONG = digest.len() as CK_ULONG;
    ret = fn_digest(
        session,
        value.as_mut_ptr(),
        value_len,
        digest.as_mut_ptr(),
        &mut digest_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(hash, digest);

    testtokn.finalize();
}

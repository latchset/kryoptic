// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

struct TestCase {
    value: Vec<u8>,
    result: Vec<u8>,
}

/* name in CKA_APPLICATION
 * value in CKA_VALUE
 * result in CKA_OBJECT_ID
 * additional value (like an IV) in CKA_LABEL as a Base64 encoded text
 */

fn get_test_case_data(session: CK_SESSION_HANDLE, name: &str) -> TestCase {
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_APPLICATION, name.as_bytes())], &[]);
    let mut ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* get values */
    let mut template = make_ptrs_template(&[
        (CKA_VALUE, std::ptr::null_mut(), 0),
        (CKA_OBJECT_ID, std::ptr::null_mut(), 0),
    ]);
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut tc = TestCase {
        value: vec![0; template[0].ulValueLen as usize],
        result: vec![0; template[1].ulValueLen as usize],
    };
    template[0].pValue = void_ptr!(tc.value.as_mut_ptr());
    template[1].pValue = void_ptr!(tc.result.as_mut_ptr());
    ret = fn_get_attribute_value(
        session,
        handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    tc
}

#[cfg(feature = "rsa")]
#[test]
#[parallel]
fn test_rsa_signatures() {
    /* Test Vectors from python cryptography's pkcs1v15sign-vectors.txt */
    let mut testtokn = TestToken::initialized(
        "test_rsa_signatures.sql",
        Some("testdata/test_sign_verify.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* ### CKM_RSA_PKCS ### */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_RSA_PKCS");
    let pri_key_handle =
        match get_test_key_handle(session, "Example 15", CKO_PRIVATE_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };
    let pub_key_handle =
        match get_test_key_handle(session, "Example 15", CKO_PUBLIC_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA1_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        pub_key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result = match sig_gen(
        session,
        pri_key_handle,
        &mut testcase.value,
        &mut mechanism,
    ) {
        Ok(r) => r,
        Err(e) => panic!("f{e}"),
    };
    assert_eq!(testcase.result, result);

    let result = match sig_gen_multipart(
        session,
        pri_key_handle,
        &mut testcase.value,
        &mut mechanism,
    ) {
        Ok(r) => r,
        Err(e) => panic!("f{e}"),
    };
    assert_eq!(testcase.result, result);

    testtokn.finalize();
}

#[cfg(feature = "ecdsa")]
#[test]
#[parallel]
fn test_ecc_signatures() {
    /* Test Vectors from python cryptography's pkcs1v15sign-vectors.txt */
    let mut testtokn = TestToken::initialized(
        "test_ecc_signatures.sql",
        Some("testdata/test_sign_verify.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* ### CKM_ECDSA ### */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_ECDSA_SHA512");
    let pri_key_handle = match get_test_key_handle(
        session,
        "FIPS_186-3/SigGen: [P-521,SHA-512]",
        CKO_PRIVATE_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };
    let pub_key_handle = match get_test_key_handle(
        session,
        "FIPS_186-3/SigGen: [P-521,SHA-512]",
        CKO_PUBLIC_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA512,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        pub_key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let mut result = match sig_gen(
        session,
        pri_key_handle,
        &mut testcase.value,
        &mut mechanism,
    ) {
        Ok(r) => r,
        Err(e) => panic!("f{e}"),
    };
    // the ECDSA is non-deterministic -- we can not just compare the signature, but we can verify
    let ret = sig_verify(
        session,
        pub_key_handle,
        &mut testcase.value,
        &mut result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[cfg(feature = "hmac")]
#[test]
#[parallel]
fn test_hmac_signatures() {
    /* Test Vectors from python cryptography's pkcs1v15sign-vectors.txt */
    let mut testtokn = TestToken::initialized(
        "test_hmac_signatures.sql",
        Some("testdata/test_sign_verify.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* ### HMACs ### */

    /* get test keys */
    let key_handle =
        match get_test_key_handle(session, "HMAC Test Key", CKO_SECRET_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };

    /* ### SHA-1 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA_1_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA_1_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA256 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA256_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA384 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA384_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA512 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA512_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA512_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* ### SHA3 256 HMAC ### */

    /* get test keys */
    let key_handle = match get_test_key_handle(
        session,
        "HMAC SHA-3-256 Test Key",
        CKO_SECRET_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };

    /* get test data */
    let mut testcase = get_test_case_data(session, "CKM_SHA3_256_HMAC");

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA3_256_HMAC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let ret = sig_verify(
        session,
        key_handle,
        &mut testcase.value,
        &mut testcase.result,
        &mut mechanism,
    );
    assert_eq!(ret, CKR_OK);

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

    /* check different HMAC fails due to key being specific to HMAC */
    mechanism.mechanism = CKM_SHA256_HMAC;
    let result =
        sig_gen(session, key_handle, &mut testcase.value, &mut mechanism);
    assert!(result.is_err());

    testtokn.finalize();
}

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_rsa_operations() {
    let mut testtokn = TestToken::initialized(
        "test_rsa_operations.sql",
        Some("testdata/test_rsa_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* public key data */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
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

    /* encrypt init */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    /* a second invocation should return an error */
    ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OPERATION_ACTIVE);

    let data = "plaintext";
    let enc: [u8; 512] = [0; 512];
    let mut enc_len: CK_ULONG = 512;
    ret = fn_encrypt(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(enc_len, 256);

    /* a second invocation should return an error */
    ret = fn_encrypt(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        enc.as_ptr() as *mut _,
        &mut enc_len,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* test that decryption returns the same data back */
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

    ret = fn_decrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_OK);

    let dec: [u8; 512] = [0; 512];
    let mut dec_len: CK_ULONG = 512;
    ret = fn_decrypt(
        session,
        enc.as_ptr() as *mut u8,
        enc_len,
        dec.as_ptr() as *mut u8,
        &mut dec_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(data.as_bytes(), &dec[..dec_len as usize]);

    /* RSA PKCS Sig */
    let pri_key_handle = match get_test_key_handle(
        session,
        "SigVer15_186-3.rsp [mod = 2048]",
        CKO_PRIVATE_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };
    let pub_key_handle = match get_test_key_handle(
        session,
        "SigVer15_186-3.rsp [mod = 2048]",
        CKO_PUBLIC_KEY,
    ) {
        Ok(k) => k,
        Err(e) => panic!("{}", e),
    };
    let testname = "SigVer15_186-3.rsp SHAAlg = SHA256 1660";
    let mut msg = match get_test_data(session, testname, "msg") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };
    let mut sig = match get_test_data(session, testname, "sig") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret =
        sig_verify(session, pub_key_handle, &mut msg, &mut sig, &mut mechanism);
    assert_eq!(ret, CKR_OK);

    let result = ret_or_panic!(sig_gen(
        session,
        pri_key_handle,
        &mut msg,
        &mut mechanism
    ));
    assert_eq!(sig, result);

    /* RSA PKCS PSS Sig */
    let pri_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "SigVerPSS_186-3.rsp [mod = 3072]",
        CKO_PRIVATE_KEY,
    ));
    let pub_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "SigVerPSS_186-3.rsp [mod = 3072]",
        CKO_PUBLIC_KEY,
    ));
    let testname = "SigVerPSS_186-3.rsp SHAAlg = SHA384 2514";
    let msg = match get_test_data(session, testname, "msg") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };
    let sig = match get_test_data(session, testname, "sig") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };
    let salt = match get_test_data(session, testname, "salt") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };

    let params = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA384,
        mgf: CKG_MGF1_SHA384,
        sLen: salt.len() as CK_ULONG,
    };

    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA384_RSA_PKCS_PSS,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
            as CK_ULONG,
    };

    let ret = sig_verify(session, pub_key_handle, &msg, &sig, &mechanism);
    assert_eq!(ret, CKR_OK);

    let signed =
        ret_or_panic!(sig_gen(session, pri_key_handle, &msg, &mechanism));
    /* PSS is non deterministic because saltlen > 0,
     * so we can compare the result
     * assert_eq!(sig, result); */
    assert_eq!(sig.len(), signed.len());
    /* but we can verify again to ensure signing produced
     * something usable */
    let ret = sig_verify(session, pub_key_handle, &msg, &signed, &mechanism);
    assert_eq!(ret, CKR_OK);

    /* RSA PKCS Enc */
    let pri_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "pkcs1v15crypt-vectors.txt - Example 15: A 2048-bit RSA key pair",
        CKO_PRIVATE_KEY,
    ));
    let pub_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "pkcs1v15crypt-vectors.txt - Example 15: A 2048-bit RSA key pair",
        CKO_PUBLIC_KEY,
    ));
    let testname =
        "pkcs1v15crypt-vectors.txt - PKCS#1 v1.5 Encryption Example 15.20";
    let msg = match get_test_data(session, testname, "msg") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };
    let enc = match get_test_data(session, testname, "enc") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };

    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let result =
        ret_or_panic!(decrypt(session, pri_key_handle, &enc, &mechanism));
    assert_eq!(msg, result);

    let encrypted =
        ret_or_panic!(encrypt(session, pub_key_handle, &msg, &mechanism));
    /* can't really compare the data because padding contains random
     * octets so each encryption produces a different output */
    assert_eq!(enc.len(), encrypted.len());
    /* but we can decrypt again to ensure encryption produced
     * something usable */
    let result =
        ret_or_panic!(decrypt(session, pri_key_handle, &encrypted, &mechanism));
    assert_eq!(msg, result);

    /* RSA PKCS OAEP Enc */
    let pri_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "oaep-sha512-sha512.txt - First Key Example",
        CKO_PRIVATE_KEY,
    ));
    let pub_key_handle = ret_or_panic!(get_test_key_handle(
        session,
        "oaep-sha512-sha512.txt - First Key Example",
        CKO_PUBLIC_KEY,
    ));
    let testname =
        "oaep-sha512-sha512.txt - First Key Example - OAEP Example 1 alg=sha512 mgf1=sha512";
    let msg = match get_test_data(session, testname, "msg") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };
    let enc = match get_test_data(session, testname, "enc") {
        Ok(vec) => vec,
        Err(ret) => return assert_eq!(ret, CKR_OK),
    };

    let params = CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA512,
        mgf: CKG_MGF1_SHA512,
        source: CKZ_DATA_SPECIFIED,
        pSourceData: std::ptr::null_mut(),
        ulSourceDataLen: 0,
    };

    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        pParameter: &params as *const _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
            as CK_ULONG,
    };

    let result =
        ret_or_panic!(decrypt(session, pri_key_handle, &enc, &mechanism));
    assert_eq!(msg, result);

    let encrypted =
        ret_or_panic!(encrypt(session, pub_key_handle, &msg, &mechanism));
    /* can't really compare the data because padding contains random
     * octets so each encryption produces a different output */
    assert_eq!(enc.len(), encrypted.len());
    /* but we can decrypt again to ensure encryption produced
     * something usable */
    let result =
        ret_or_panic!(decrypt(session, pri_key_handle, &encrypted, &mechanism));
    assert_eq!(msg, result);

    /* RSA PKCS Wrap */
    /* RSA PKCS OAEP Wrap */

    testtokn.finalize();
}

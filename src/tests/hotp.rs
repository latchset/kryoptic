// Copyright 2026 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

fn generate_otp(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mech = CK_MECHANISM {
        mechanism: CKM_HOTP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let otp_buf =
        sig_gen(session, key, &[], &mech).expect("HOTP generation failed");

    let sig_info =
        unsafe { &*(otp_buf.as_ptr() as *const CK_OTP_SIGNATURE_INFO) };
    let p_params = sig_info.pParams;
    let p_value = unsafe { (*p_params).pValue };
    let ul_value_len = unsafe { (*p_params).ulValueLen };
    unsafe {
        std::slice::from_raw_parts(p_value as *const u8, ul_value_len as usize)
    }
    .to_vec()
}

fn verify_otp(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    otp: &[u8],
) -> CK_RV {
    let mech = CK_MECHANISM {
        mechanism: CKM_HOTP,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    sig_verify(session, key, &[], otp, &mech)
}

fn generate_totp(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    counter: u64,
) -> Vec<u8> {
    let mut counter_bytes = counter.to_be_bytes();
    let mut param = CK_OTP_PARAM {
        type_: CK_OTP_COUNTER,
        pValue: counter_bytes.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: 8,
    };
    let mut params = CK_OTP_PARAMS {
        pParams: &mut param,
        ulCount: 1,
    };
    let mech = CK_MECHANISM {
        mechanism: CKM_HOTP,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
    };
    let otp_buf =
        sig_gen(session, key, &[], &mech).expect("TOTP generation failed");

    let sig_info =
        unsafe { &*(otp_buf.as_ptr() as *const CK_OTP_SIGNATURE_INFO) };
    let p_params = sig_info.pParams;
    let p_value = unsafe { (*p_params).pValue };
    let ul_value_len = unsafe { (*p_params).ulValueLen };
    unsafe {
        std::slice::from_raw_parts(p_value as *const u8, ul_value_len as usize)
    }
    .to_vec()
}

fn verify_totp(
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    counter: u64,
    otp: &[u8],
) -> CK_RV {
    let mut counter_bytes = counter.to_be_bytes();
    let mut param = CK_OTP_PARAM {
        type_: CK_OTP_COUNTER,
        pValue: counter_bytes.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: 8,
    };
    let mut params = CK_OTP_PARAMS {
        pParams: &mut param,
        ulCount: 1,
    };
    let mech = CK_MECHANISM {
        mechanism: CKM_HOTP,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_OTP_PARAMS>() as CK_ULONG,
    };
    sig_verify(session, key, &[], otp, &mech)
}

#[test]
#[parallel]
fn test_hotp() {
    let mut testtokn = TestToken::initialized("test_hotp", None);
    let session = testtokn.get_session(true);

    testtokn.login();

    // 1. Generate HOTP key
    let hotp_key_client = generate_key(
        session,
        CKM_HOTP_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[
            (CKA_CLASS, CKO_OTP_KEY),
            (CKA_KEY_TYPE, CKK_HOTP),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false),
            (CKA_SIGN, true),
            (CKA_VERIFY, true),
        ],
    )
    .expect("HOTP key generation failed");

    // 2. Export HOTP key
    let exported_key = extract_key_value(session, hotp_key_client)
        .expect("HOTP key extraction failed");

    // 3. Generate some OTPs (tokens) with hotp_key_client
    let otp1 = generate_otp(session, hotp_key_client);
    let otp2 = generate_otp(session, hotp_key_client);
    let otp3 = generate_otp(session, hotp_key_client);
    let otp4 = generate_otp(session, hotp_key_client); // skipped for look-ahead
    let otp5 = generate_otp(session, hotp_key_client);

    let mut otps = vec![&otp1, &otp2, &otp3, &otp4, &otp5];
    otps.sort();
    otps.dedup();
    assert_eq!(
        otps.len(),
        5,
        "All OTPs returned by the client key must be different"
    );

    // 4. Create a new token using the saved one
    let hotp_key_server = import_object(
        session,
        CKO_OTP_KEY,
        &[(CKA_KEY_TYPE, CKK_HOTP)],
        &[(CKA_VALUE, &exported_key)],
        &[(CKA_SIGN, true), (CKA_VERIFY, true)],
    )
    .expect("Importing HOTP key failed");

    // 6. Verify the tokens generated on the first one
    let ret = verify_otp(session, hotp_key_server, &otp1);
    assert_eq!(ret, CKR_OK, "Verification of OTP1 failed");

    let ret = verify_otp(session, hotp_key_server, &otp2);
    assert_eq!(ret, CKR_OK, "Verification of OTP2 failed");

    // 7. Look-ahead verification (leaving gaps)
    let ret = verify_otp(session, hotp_key_server, &otp5);
    assert_eq!(ret, CKR_OK, "Look-ahead verification of OTP5 failed");

    // Trying to reuse an older OTP should fail
    let ret = verify_otp(session, hotp_key_server, &otp3);
    assert_eq!(ret, CKR_SIGNATURE_INVALID, "Reused OTP should be invalid");

    testtokn.finalize();
}

#[cfg(not(feature = "no_sha1"))]
#[test]
#[parallel]
fn test_hotp_vectors() {
    let mut testtokn = TestToken::initialized("test_hotp_vectors", None);
    let session = testtokn.get_session(true);

    testtokn.login();

    // Test vectors from RFC 4226, Appendix D
    let secret = b"12345678901234567890";

    let hotp_key = import_object(
        session,
        CKO_OTP_KEY,
        &[(CKA_KEY_TYPE, CKK_HOTP)],
        &[(CKA_VALUE, secret)],
        &[(CKA_SIGN, true), (CKA_VERIFY, true)],
    )
    .expect("Importing HOTP key failed");

    let expected_otps = vec![
        "755224", "287082", "359152", "969429", "338314", "254676", "287922",
        "162583", "399871", "520489",
    ];

    for expected in expected_otps {
        let otp = generate_otp(session, hotp_key);
        let otp_str = std::str::from_utf8(&otp).unwrap();
        assert_eq!(otp_str, expected);
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_totp_vectors() {
    let mut testtokn = TestToken::initialized("test_totp_vectors", None);
    let session = testtokn.get_session(true);

    testtokn.login();

    // Test vectors from RFC 6238, Appendix B
    let times: [(u64, &str, &str); 6] = [
        (1, "46119246", "90693936"),
        (37037036, "68084774", "25091201"),
        (37037037, "67062674", "99943326"),
        (41152263, "91819424", "93441116"),
        (66666666, "90698825", "38618901"),
        (666666666, "77737706", "47863826"),
    ];

    // SHA-256 (32 bytes secret)
    let secret_sha256 = b"12345678901234567890123456789012";

    let key_sha256 = import_object(
        session,
        CKO_OTP_KEY,
        &[
            (CKA_KEY_TYPE, CKK_HOTP),
            (CKA_OTP_LENGTH, 8),
            (CKA_OTP_COUNTER_REQUIREMENT, CK_OTP_PARAM_OPTIONAL),
        ],
        &[(CKA_VALUE, secret_sha256)],
        &[(CKA_SIGN, true), (CKA_VERIFY, true)],
    )
    .expect("Importing SHA-256 HOTP key failed");

    for &(counter, expected_sha256, _) in &times {
        let otp = generate_totp(session, key_sha256, counter);
        let otp_str = std::str::from_utf8(&otp).unwrap();
        assert_eq!(otp_str, expected_sha256);
        let ret = verify_totp(session, key_sha256, counter, &otp);
        assert_eq!(ret, CKR_OK);
    }

    // SHA-512 (64 bytes secret)
    let secret_sha512 =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    let key_sha512 = import_object(
        session,
        CKO_OTP_KEY,
        &[
            (CKA_KEY_TYPE, CKK_HOTP),
            (CKA_OTP_LENGTH, 8),
            (CKA_OTP_COUNTER_REQUIREMENT, CK_OTP_PARAM_OPTIONAL),
        ],
        &[(CKA_VALUE, secret_sha512)],
        &[(CKA_SIGN, true), (CKA_VERIFY, true)],
    )
    .expect("Importing SHA-512 HOTP key failed");

    for &(counter, _, expected_sha512) in &times {
        let otp = generate_totp(session, key_sha512, counter);
        let otp_str = std::str::from_utf8(&otp).unwrap();
        assert_eq!(otp_str, expected_sha512);
        let ret = verify_totp(session, key_sha512, counter, &otp);
        assert_eq!(ret, CKR_OK);
    }

    testtokn.finalize();
}

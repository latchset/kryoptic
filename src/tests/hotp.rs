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

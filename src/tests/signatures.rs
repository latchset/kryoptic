// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

struct TestCase {
    value: Vec<u8>,
    result: Vec<u8>,
}

fn get_test_case_data(name: &str) -> TestCase {
    match name {
        "CKM_RSA_PKCS" => {
            TestCase {
                value: hex::decode(
                    "6504921a97cd57aa8f3863dc32e1f2d0b57aff63106e59f6afc3f9726b459388\
                     bae16b3e224f6aa7f4f471f13606eda6e1f1ac2b4df9ef8de921c07c2f4c8598\
                     d7a3d6ec4b368cb85ce61a74338221118a303e821c0f277b591af6795f50c402\
                     26127a2efacce4662fd7076c109eb59b18005e7165f6294a6976436ee397774e"
                )
                .expect("failed to decode value"),
                result: hex::decode(
                    "335ffadc0b1b8bd2b1eb670dd246e76dcccdc955a1687a15f74aa3e1596ebd43\
                     e607c640525f89dda95809cfd065f1be4e4a249477d24f400d4d4c9438a0af95\
                     b26b28b416e42aa950e2a52851b52132048f1b1ce944322fc99c1aabb49b7fae\
                     4c2f0fef674b50adee3bbb5c6c33822b608e4b9577275ca20c710af9fc41b1c0\
                     1d9c0ff6f0d8324dc08e1a76e232d8feaa06c73bbf64053bea35f1c528b27227\
                     64822ef1ff06246e75a9a22a10da4ea84fc2441bea24b35506f8447fcf69093c\
                     5d21ab0305cce2c7ea9ffac357c664b491fc55f2919ec490c38accbab378c252\
                     ac2df3845acff575ec7524cd2f586cca1497c74f24b299d6d6254c8cdb1d227d"
                )
                .expect("failed to decode result"),
            }
        },
        "CKM_ECDSA_SHA512" => {
            TestCase {
                value: hex::decode(
                    "9ecd500c60e701404922e58ab20cc002651fdee7cbc9336adda33e4c1088fab1\
                     964ecb7904dc6856865d6c8e15041ccf2d5ac302e99d346ff2f686531d255216\
                     78d4fd3f76bbf2c893d246cb4d7693792fe18172108146853103a51f824acc62\
                     1cb7311d2463c3361ea707254f2b052bc22cb8012873dcbb95bf1a5cc53ab89f"
                )
                .expect("failed to decode value"),
                result: hex::decode(
                    "004de826ea704ad10bc0f7538af8a3843f284f55c8b946af9235af5af74f2b76\
                     e099e4bc72fd79d28a380f8d4b4c919ac290d248c37983ba05aea42e2dd79fdd\
                     33e80087488c859a96fea266ea13bf6d114c429b163be97a57559086edb64aed\
                     4a18594b46fb9efc7fd25d8b2de8f09ca0587f54bd287299f47b2ff124aac566\
                     e8ee3b43"
                )
                .expect("failed to decode result"),
            }
        },
        #[cfg(not(feature = "no_sha1"))]
        "CKM_SHA_1_HMAC" => {
            TestCase {
                value: hex::decode("48656c6c6f205348412d3120484d4143")
                .expect("failed to decode value"),
                result: hex::decode("f7ac5f5288543bd9b92c73c9dce1dd1ed565761d")
                .expect("failed to decode result"),
            }
        },
        "CKM_SHA256_HMAC" => {
            TestCase {
                value: hex::decode("48656c6c6f2053484132353620484d4143")
                .expect("failed to decode value"),
                result:hex::decode(
                    "22efc054a9ff430ab7837a06b61027a0b736b62a5c1ffe4b7615520853c9efeb"
                )
                .expect("failed to decode result"),
            }
        },
        "CKM_SHA384_HMAC" => {
            TestCase {
                value: hex::decode("48656c6c6f2053484133383420484d4143")
                .expect("failed to decode value"),
                result:hex::decode(
                    "458b092405af19a3a38f5fd9213956a38024db45f1d14b317349b6e80b4de72a\
                     7cbc79a0aaf3d2c0dc23e25f344b683c"
                )
                .expect("failed to decode result"),
            }
        },
        "CKM_SHA512_HMAC" => {
            TestCase {
                value: hex::decode("48656c6c6f2053484135313220484d4143")
                .expect("failed to decode value"),
                result:hex::decode(
                    "605956482181d6c991e65c3f50b82a007c724292b0c0a4a6aa6fe0605cb3e658\
                     367609984878d0d1c5b07add13942a262df380a26e57f88bff03702f769f6d86"
                )
                .expect("failed to decode result"),
            }
        },
        "CKM_SHA3_256_HMAC" => {
            TestCase {
                value: hex::decode(
                    "53616d706c65206d65737361676520666f72206b65796c656e3c626c6f636b6c\
                     656e"
                )
                .expect("failed to decode value"),
                result:hex::decode(
                    "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"
                )
                .expect("failed to decode result"),
            }
        },
        _ => panic!("Unknown test case {}", name),
    }
}

#[cfg(feature = "rsa")]
#[test]
#[parallel]
fn test_rsa_signatures() {
    /* Test Vector from NIST's test vectors:
     * http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-2rsatestvectors.zip
     */
    let mut testtokn = TestToken::initialized(
        "test_rsa_signatures",
        Some("testdata/test_sign_verify_rsa.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* ### CKM_RSA_PKCS ### */

    /* get test data */
    let mut testcase = get_test_case_data("CKM_RSA_PKCS");
    #[allow(unused_variables)]
    let pri_key_handle =
        match get_test_key_handle(session, "SigGen15_186-2", CKO_PRIVATE_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };
    let pub_key_handle =
        match get_test_key_handle(session, "SigGen15_186-2", CKO_PUBLIC_KEY) {
            Ok(k) => k,
            Err(e) => panic!("{}", e),
        };

    /* verify test vector */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
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
        "test_ecc_signatures",
        Some("testdata/test_sign_verify_ecdsa.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    /* ### CKM_ECDSA ### */

    /* get test data */
    let mut testcase = get_test_case_data("CKM_ECDSA_SHA512");
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
        "test_hmac_signatures",
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

    #[cfg(not(feature = "no_sha1"))]
    {
        /* ### SHA-1 HMAC */

        /* get test data */
        let mut testcase = get_test_case_data("CKM_SHA_1_HMAC");

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

        let result = match sig_gen(
            session,
            key_handle,
            &mut testcase.value,
            &mut mechanism,
        ) {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
        assert_eq!(testcase.result, result);
    }

    /* ### SHA256 HMAC */

    /* get test data */
    let mut testcase = get_test_case_data("CKM_SHA256_HMAC");

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
    let mut testcase = get_test_case_data("CKM_SHA384_HMAC");

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
    let mut testcase = get_test_case_data("CKM_SHA512_HMAC");

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
    let mut testcase = get_test_case_data("CKM_SHA3_256_HMAC");

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

    /* check SignatureVerify API too */
    let ret = sig_verifysig(
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

#[cfg(feature = "hmac")]
#[test]
#[parallel]
fn test_hmac_save_restore() {
    let mut testtokn = TestToken::initialized(
        "test_hmac_save_restore",
        Some("testdata/test_sign_verify.json"),
    );
    let session = testtokn.get_session(false);

    /* login */
    testtokn.login();

    let mut data1 = b"some initial data for hmac".to_vec();
    let mut data2 = b"and some more data for hmac".to_vec();

    let mechs = vec![
        ("SHA256-HMAC", CKM_SHA256_HMAC, "HMAC Test Key"),
        ("SHA384-HMAC", CKM_SHA384_HMAC, "HMAC Test Key"),
        ("SHA512-HMAC", CKM_SHA512_HMAC, "HMAC Test Key"),
        (
            "SHA3-256-HMAC",
            CKM_SHA3_256_HMAC,
            "HMAC SHA-3-256 Test Key",
        ),
    ];

    for (mech_name, mech_type, key_name) in mechs {
        // Get key handle
        let key_handle =
            match get_test_key_handle(session, key_name, CKO_SECRET_KEY) {
                Ok(k) => k,
                Err(e) => panic!("{}", e),
            };

        // Init signing
        let mut mechanism = CK_MECHANISM {
            mechanism: mech_type,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut ret = fn_sign_init(session, &mut mechanism, key_handle);
        assert_eq!(ret, CKR_OK, "C_SignInit failed for {}", mech_name);

        // Update with first part
        ret = fn_sign_update(
            session,
            data1.as_mut_ptr(),
            data1.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK, "C_SignUpdate(1) failed for {}", mech_name);

        // Save state
        let mut state_len: CK_ULONG = 0;
        ret = fn_get_operation_state(
            session,
            std::ptr::null_mut(),
            &mut state_len,
        );
        #[cfg(not(feature = "ossl400"))]
        if ret == CKR_STATE_UNSAVEABLE {
            println!(
                "Mechanism {} does not support save/restore, skipping",
                mech_name
            );
            // Cancel operation
            _ = fn_sign_init(session, std::ptr::null_mut(), CK_INVALID_HANDLE);
            continue;
        }
        assert_eq!(
            ret, CKR_OK,
            "C_GetOperationState(len) failed for {} with 0x{:08x}",
            mech_name, ret
        );

        let mut state = vec![0u8; state_len as usize];
        ret =
            fn_get_operation_state(session, state.as_mut_ptr(), &mut state_len);
        assert_eq!(
            ret, CKR_OK,
            "C_GetOperationState(save) failed for {} with 0x{:08x}",
            mech_name, ret
        );
        state.resize(state_len as usize, 0);

        // Continue original operation
        ret = fn_sign_update(
            session,
            data2.as_mut_ptr(),
            data2.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK, "C_SignUpdate(2) failed for {}", mech_name);

        // Finalize and get signature1
        let mut sig1_len: CK_ULONG = 0;
        ret = fn_sign_final(session, std::ptr::null_mut(), &mut sig1_len);
        assert_eq!(ret, CKR_OK, "C_SignFinal(len) failed for {}", mech_name);

        let mut signature1 = vec![0u8; sig1_len as usize];
        ret = fn_sign_final(session, signature1.as_mut_ptr(), &mut sig1_len);
        assert_eq!(ret, CKR_OK, "C_SignFinal(get) failed for {}", mech_name);
        signature1.resize(sig1_len as usize, 0);

        // Restore state
        ret = fn_set_operation_state(
            session,
            state.as_mut_ptr(),
            state.len() as CK_ULONG,
            CK_INVALID_HANDLE, // hEncryptionKey
            key_handle,        // hAuthenticationKey
        );
        assert_eq!(
            ret, CKR_OK,
            "C_SetOperationState failed for {} with 0x{:08x}",
            mech_name, ret
        );

        // Continue restored operation
        ret = fn_sign_update(
            session,
            data2.as_mut_ptr(),
            data2.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK, "C_SignUpdate(3) failed for {}", mech_name);

        // Finalize and get signature2
        let mut sig2_len: CK_ULONG = 0;
        ret = fn_sign_final(session, std::ptr::null_mut(), &mut sig2_len);
        assert_eq!(ret, CKR_OK, "C_SignFinal(len2) failed for {}", mech_name);

        let mut signature2 = vec![0u8; sig2_len as usize];
        ret = fn_sign_final(session, signature2.as_mut_ptr(), &mut sig2_len);
        assert_eq!(ret, CKR_OK, "C_SignFinal(get2) failed for {}", mech_name);
        signature2.resize(sig2_len as usize, 0);

        // Compare signatures
        assert_eq!(
            signature1, signature2,
            "Signatures do not match for {}",
            mech_name
        );
    }

    testtokn.finalize();
}

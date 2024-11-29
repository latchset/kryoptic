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
                    "f45d55f35551e975d6a8dc7ea9f488593940cc75694a278f27e578a163d839b3\
                     4040841808cf9c58c9b8728bf5f9ce8ee811ea91714f47bab92d0f6d5a26fcfe\
                     ea6cd93b910c0a2c963e64eb1823f102753d41f0335910ad3a977104f1aaf6c3\
                     742716a9755d11b8eed690477f445c5d27208b2e284330fa3d301423fa7f2d08\
                     6e0ad0b892b9db544e456d3f0dab85d953c12d340aa873eda727c8a649db7fa6\
                     3740e25e9af1533b307e61329993110e95194e039399c3824d24c51f22b26bde\
                     1024cd395958a2dfeb4816a6e8adedb50b1f6b56d0b3060ff0f1c4cb0d0e001d\
                     d59d73be12"
                )
                .expect("failed to decode value"),
                result: hex::decode(
                    "b75a5466b65d0f300ef53833f2175c8a347a3804fc63451dc902f0b71f908345\
                     9ed37a5179a3b723a53f1051642d77374c4c6c8dbb1ca20525f5c9f32db77695\
                     3556da31290e22197482ceb69906c46a758fb0e7409ba801077d2a0a20eae7d1\
                     d6d392ab4957e86b76f0652d68b83988a78f26e11172ea609bf849fbbd78ad7e\
                     dce21de662a081368c040607cee29db0627227f44963ad171d2293b633a392e3\
                     31dca54fe3082752f43f63c161b447a4c65a6875670d5f6600fcc860a1caeb0a\
                     88f8fdec4e564398a5c46c87f68ce07001f6213abe0ab5625f87d19025f08d81\
                     dac7bd4586bc9382191f6d2880f6227e5df3eed21e7792d249480487f3655261"
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
    /* Test Vectors from python cryptography's pkcs1v15sign-vectors.txt */
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

    let result =
        match sig_gen(session, key_handle, &mut testcase.value, &mut mechanism)
        {
            Ok(r) => r,
            Err(e) => panic!("f{e}"),
        };
    assert_eq!(testcase.result, result);

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

// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_create_ec_montgomery_objects() {
    let mut testtokn =
        TestToken::initialized("test_create_ec_montgomery_objects.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let point = hex::decode(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    )
    .expect("Failed to decode hex point");
    let params = hex::decode("130a63757276653235353139")
        .expect("Failed to decode hex params");
    let _ = ret_or_panic!(import_object(
        session,
        CKO_PUBLIC_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_MONTGOMERY)],
        &[
            (CKA_LABEL, "EC Montgomery Public Key".as_bytes()),
            (CKA_EC_POINT, point.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_DERIVE, true)]
    ));

    /* Private EC key */
    let value = hex::decode(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    )
    .expect("Failed to decode value");
    let _ = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_MONTGOMERY)],
        &[
            (CKA_LABEL, "EC Montgomery Private Key".as_bytes()),
            (CKA_VALUE, value.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_DERIVE, true)]
    ));

    testtokn.finalize();
}

#[derive(Debug)]
struct TestUnit<'a> {
    curve: &'a str,
    ec_params: &'a str,
    a_priv: &'a str,
    a_pub: &'a str,
    b_priv: &'a str,
    b_pub: &'a str,
    secret: &'a str,
}

/* Test vectors from
 * https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
 */
#[test]
#[parallel]
fn test_ec_montgomery_derive_x25519() {
    test_ec_montgomery_derive(TestUnit {
        curve: "x25519",
        ec_params: "130a63757276653235353139",
        a_priv:
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        a_pub:
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        b_priv:
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        b_pub:
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        secret:
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    })
}

#[test]
#[parallel]
fn test_ec_montgomery_derive_x448() {
    test_ec_montgomery_derive(TestUnit {
        curve: "x448",
        ec_params: "13086375727665343438",
        a_priv: concat!(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9ba",
            "f574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        ),
        a_pub: concat!(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9",
            "bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        ),
        b_priv: concat!(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c1",
            "20bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        ),
        b_pub: concat!(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b97",
            "2fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        ),
        secret: concat!(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b5",
            "6fd2464c335543936521c24403085d59a449a5037514a879d"
        ),
    })
}

fn test_ec_montgomery_derive(t: TestUnit) {
    let dbname = format!("test_ec_montgomery_derive_{}.sql", t.curve);
    let mut testtokn = TestToken::initialized(&dbname, None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    // Alice's Public key
    let mut alice_point =
        hex::decode(t.a_pub).expect("Failed to decode hex point");
    let params = hex::decode(t.ec_params).expect("Failed to decode hex params");

    /* Alice's Private key */
    let alice_value =
        hex::decode(t.a_priv).expect("Failed to decode alice's value");
    let alice_handle = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_MONTGOMERY)],
        &[
            (CKA_LABEL, "Alice's EC Montgomery Private Key".as_bytes()),
            (CKA_VALUE, alice_value.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_DERIVE, true)]
    ));

    /* Bob's Private key */
    let bob_value =
        hex::decode(t.b_priv).expect("Failed to decode bob's value");
    let mut bob_point =
        hex::decode(t.b_pub).expect("Failed to decode bob's point");
    let bob_handle = ret_or_panic!(import_object(
        session,
        CKO_PRIVATE_KEY,
        &[(CKA_KEY_TYPE, CKK_EC_MONTGOMERY)],
        &[
            (CKA_LABEL, "Bob's EC Montgomery Private Key".as_bytes()),
            (CKA_VALUE, bob_value.as_slice()),
            (CKA_EC_PARAMS, params.as_slice()),
        ],
        &[(CKA_DERIVE, true)]
    ));

    /* derive plain key without shared data */
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL,
        ulSharedDataLen: 0,
        pSharedData: std::ptr::null_mut(),
        ulPublicDataLen: bob_point.len() as CK_ULONG,
        pPublicData: bob_point.as_mut_ptr(),
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_ECDH1_DERIVE_PARAMS),
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_EXTRACTABLE, true),
        ],
    );

    let ref_value =
        hex::decode(t.secret).expect("Failed to decode expected shared secret");

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        alice_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut value = vec![0u8; 32];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value.as_mut_ptr()),
        value.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        s_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, ref_value[(ref_value.len() - 32)..]);

    /* Do the same on the Bob's side */
    params.pPublicData = alice_point.as_mut_ptr();
    // the size matches

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        bob_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut value = vec![0u8; 32];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value.as_mut_ptr()),
        value.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        s_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, ref_value[(ref_value.len() - 32)..]);

    /* Test the derived key works */
    /* Data need to be exactly one block in size for CBC */
    let data = "0123456789ABCDEF";
    let iv = "FEDCBA0987654321";
    let enc = ret_or_panic!(encrypt(
        session,
        s_handle,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_AES_CBC,
            pParameter: void_ptr!(iv.as_bytes()),
            ulParameterLen: iv.len() as CK_ULONG,
        }
    ));
    assert_eq!(enc.len(), 16);

    let dec = ret_or_panic!(decrypt(
        session,
        s_handle,
        enc.as_slice(),
        &CK_MECHANISM {
            mechanism: CKM_AES_CBC,
            pParameter: void_ptr!(iv.as_bytes()),
            ulParameterLen: iv.len() as CK_ULONG,
        }
    ));
    assert_eq!(dec.len(), data.len());
    assert_eq!(data.as_bytes(), dec.as_slice());

    /* Invalid parameters: Missing peer public key */
    params.ulPublicDataLen = 0;
    params.pPublicData = std::ptr::null_mut();

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        alice_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);
    params.ulPublicDataLen = bob_point.len() as CK_ULONG;
    params.pPublicData = bob_point.as_mut_ptr();

    /* Invalid parameters: Shared data are not supported for NULL KDF */
    let shared = "shared data";
    params.ulSharedDataLen = shared.len() as CK_ULONG;
    params.pSharedData = shared.as_ptr() as *mut u8;

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        alice_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);
    params.ulSharedDataLen = 0;
    params.pSharedData = std::ptr::null_mut();

    /* Invalid parameters: Blake kdf */
    params.kdf = CKD_BLAKE2B_160_KDF;

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        alice_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);
    params.kdf = CKD_NULL;

    /* Without the explicit CKA_VALUE_LEN -- we should get "reasonable default" for AES */
    let derive_template = make_attr_template(
        &[(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_AES)],
        &[],
        &[(CKA_EXTRACTABLE, true)],
    );
    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        alice_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut value = vec![0u8; 32];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(value.as_mut_ptr()),
        value.len(),
    )]);

    let ret = fn_get_attribute_value(
        session,
        s_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, ref_value[(ref_value.len() - 32)..]);

    /* With GENERIC_SECRET and explicit CKA_VALUE_LEN larger than field size we should fail */
    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, ref_value.len() as CK_ULONG + 1),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true)],
    );
    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        alice_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

    testtokn.finalize();
}

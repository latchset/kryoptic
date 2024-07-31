// Copyright 2024 Jakub Jelen
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_ecc_derive_plain() {
    let mut testtokn = TestToken::initialized(
        "test_ecc_derive_plain.sql",
        Some("testdata/test_ecc_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "11".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* Peer key */
    let _peer_value = hex::decode(
        "d40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b2\
         10",
    )
    .expect("Failed to decode peer value");
    let mut peer_point = hex::decode(
        "04fbcea7c2827e0e8085d7707b23a3728823ea6f4878b24747fb4fd2842d40\
         6c732393c85f1f710c5afc115a39ba7e18abe03f19c9d4bb3d47d19468b818\
         efa535",
    )
    .expect("Failed to decode peer point");

    /* derive plain key without shared data */
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL,
        ulSharedDataLen: 0,
        pSharedData: std::ptr::null_mut(),
        ulPublicDataLen: peer_point.len() as CK_ULONG,
        pPublicData: peer_point.as_mut_ptr(),
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
            (CKA_VALUE_LEN, 16),
        ],
        &[],
        &[
            (CKA_ENCRYPT, true),
            (CKA_DECRYPT, true),
            (CKA_EXTRACTABLE, true),
        ],
    );

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    let ref_value_full = vec![
        186, 179, 219, 18, 36, 16, 87, 231, 229, 85, 23, 245, 17, 193, 75, 68,
        151, 166, 60, 146, 170, 220, 133, 80, 238, 161, 66, 67, 154, 193, 225,
        209,
    ];

    let mut value = vec![0u8; 16];
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
    assert_eq!(value, ref_value_full[(ref_value_full.len() - 16)..]);

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
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);
    params.ulPublicDataLen = peer_point.len() as CK_ULONG;
    params.pPublicData = peer_point.as_mut_ptr();

    /* Invalid parameters: Shared data are not supported for NULL KDF */
    let shared = "shared data";
    params.ulSharedDataLen = shared.len() as CK_ULONG;
    params.pSharedData = shared.as_ptr() as *mut u8;

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        handle,
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
        handle,
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
        handle,
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
    assert_eq!(value, ref_value_full[(ref_value_full.len() - 32)..]);

    /* With GENERIC_SECRET and explicit CKA_VALUE_LEN larger than field size we should fail */
    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 33),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true)],
    );
    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

    /* A DER encoded public point should still work */
    let der_octet =
        kasn1::DerEncOctetString::new(peer_point.as_slice()).unwrap();
    let mut der_point = asn1::write_single(&der_octet).unwrap();

    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL,
        ulSharedDataLen: 0,
        pSharedData: std::ptr::null_mut(),
        ulPublicDataLen: der_point.len() as CK_ULONG,
        pPublicData: der_point.as_mut_ptr(),
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_ECDH1_DERIVE_PARAMS),
    };
    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 16),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true)],
    );
    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_ecc_derive_x963() {
    /* derive with shared data and X9.63 KDF (and cofactor) */
    let mut testtokn = TestToken::initialized(
        "test_ecc_derive_x963.sql",
        Some("testdata/test_ecc_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "11".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* Peer key */
    let _peer_value = hex::decode(
        "d40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b2\
         10",
    )
    .expect("Failed to decode peer value");
    let mut peer_point = hex::decode(
        "04fbcea7c2827e0e8085d7707b23a3728823ea6f4878b24747fb4fd2842d40\
         6c732393c85f1f710c5afc115a39ba7e18abe03f19c9d4bb3d47d19468b818\
         efa535",
    )
    .expect("Failed to decode peer point");

    let shared = "shared data";
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_SHA512_KDF,
        ulSharedDataLen: shared.len() as CK_ULONG,
        pSharedData: shared.as_ptr() as *mut u8,
        ulPublicDataLen: peer_point.len() as CK_ULONG,
        pPublicData: peer_point.as_mut_ptr(),
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDH1_COFACTOR_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_ECDH1_DERIVE_PARAMS),
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true)],
    );

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_ecc_derive_nist() {
    /* derive with shared data and NIST KDF not supported now */
    let mut testtokn = TestToken::initialized(
        "test_ecc_derive_nist.sql",
        Some("testdata/test_ecc_operations.json"),
    );
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* private key */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let template =
        make_attr_template(&[], &[(CKA_UNIQUE_ID, "11".as_bytes())], &[]);
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* Peer key */
    let _peer_value = hex::decode(
        "d40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b2\
         10",
    )
    .expect("Failed to decode peer value");
    let mut peer_point = hex::decode(
        "04fbcea7c2827e0e8085d7707b23a3728823ea6f4878b24747fb4fd2842d40\
         6c732393c85f1f710c5afc115a39ba7e18abe03f19c9d4bb3d47d19468b818\
         efa535",
    )
    .expect("Failed to decode peer point");

    let shared = "shared data";
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_SHA384_KDF_SP800,
        ulSharedDataLen: shared.len() as CK_ULONG,
        pSharedData: shared.as_ptr() as *mut u8,
        ulPublicDataLen: peer_point.len() as CK_ULONG,
        pPublicData: peer_point.as_mut_ptr(),
    };
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDH1_COFACTOR_DERIVE,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: sizeof!(CK_ECDH1_DERIVE_PARAMS),
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 32),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true)],
    );

    let mut s_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut mechanism,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut s_handle,
    );
    assert_eq!(ret, CKR_MECHANISM_PARAM_INVALID);

    testtokn.finalize();
}

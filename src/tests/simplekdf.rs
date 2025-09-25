// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_concatenate_kdf_token() {
    let mut testtokn = TestToken::initialized("concatente_kdf_token", None);
    let session = testtokn.get_session(true);

    testtokn.login();

    test_concatenate_kdf(session, true);
    testtokn.finalize();
}

#[test]
#[parallel]
fn test_concatenate_kdf_session() {
    let mut testtokn = TestToken::initialized("concatente_kdf_session", None);
    let session = testtokn.get_session(false);

    test_concatenate_kdf(session, false);
    testtokn.finalize();
}

fn test_concatenate_kdf(session: CK_ULONG, token: bool) {
    // Import test keys from the specification
    // These keys are too small to match FIPS requirements
    let base_key = hex::decode("01234567").unwrap();
    let base_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, base_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false)
        ],
    ));

    let another_key = hex::decode("89abcdef").unwrap();
    let another_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, another_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false)
        ],
    ));

    // Concatenate base and key
    let params = another_key_handle;
    let paramslen = sizeof!(CK_OBJECT_HANDLE);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_BASE_AND_KEY,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false),
            (CKA_TOKEN, token),
        ],
    );
    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    let exp_value = hex::decode("0123456789abcdef").unwrap();
    if let Some(err) = check_attributes(
        session,
        dk_handle,
        &[(CKA_VALUE_LEN, 8)],
        &[(CKA_VALUE, &exp_value)],
        &[
            (CKA_TOKEN, token),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false),
            (CKA_NEVER_EXTRACTABLE, false),
            (CKA_ALWAYS_SENSITIVE, false),
        ],
    ) {
        panic!("{}", err);
    }

    // Concatenate base and key, override extractable + sensitive attributes
    let sensitive_derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[
            (CKA_EXTRACTABLE, false),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, token),
        ],
    );
    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        sensitive_derive_template.as_ptr() as *mut _,
        sensitive_derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    if let Some(err) = check_attributes(
        session,
        dk_handle,
        &[(CKA_VALUE_LEN, 8)],
        &[], // can't check the value anymore
        &[
            (CKA_TOKEN, token),
            (CKA_EXTRACTABLE, false),
            (CKA_SENSITIVE, true),
            (CKA_NEVER_EXTRACTABLE, false),
            (CKA_ALWAYS_SENSITIVE, false),
        ],
    ) {
        panic!("{}", err);
    }

    // Concatenate base and data
    let data = hex::decode("89abcdef").unwrap();
    let params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as *mut _,
        ulLen: data.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_KEY_DERIVATION_STRING_DATA);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_BASE_AND_DATA,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    let exp_value = hex::decode("0123456789abcdef").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

    // Concatenate data and base
    let data = hex::decode("89abcdef").unwrap();
    let params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as *mut _,
        ulLen: data.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_KEY_DERIVATION_STRING_DATA);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_DATA_AND_BASE,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    let exp_value = hex::decode("89abcdef01234567").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

    // XOR key and data
    let data = hex::decode("89abcdef").unwrap();
    let params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as *mut _,
        ulLen: data.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_KEY_DERIVATION_STRING_DATA);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_XOR_BASE_AND_DATA,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    let exp_value = hex::decode("88888888").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

    // Extract key from key
    let base_key =
        vec![0b0011_0010u8, 0b1001_1111u8, 0b1000_0100u8, 0b1010_1001u8];
    let base_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, base_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false)
        ],
    ));
    let params: CK_EXTRACT_PARAMS = 21;
    let paramslen = sizeof!(CK_EXTRACT_PARAMS);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_EXTRACT_KEY_FROM_KEY,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };
    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 2),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true), (CKA_SENSITIVE, false)],
    );
    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    let exp_value = vec![0b1001_0101u8, 0b0010_0110u8];
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);
}

#[test]
#[parallel]
fn test_concatenate_kdf_fips() {
    let mut testtokn = TestToken::initialized("concatente_kdf_fips", None);
    let session = testtokn.get_session(false);

    // Import larger keys to satisfy FIPS requirements for generic secret.
    // FIPS wants at least 112 b = 14 B
    let base_key = hex::decode("000102030405060708090a0b0c0d").unwrap();
    let base_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, base_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false)
        ],
    ));

    let another_key = hex::decode("00102030405060708090a0b0c0d0").unwrap();
    let another_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, another_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false)
        ],
    ));

    // Concatenate base and key
    let params = another_key_handle;
    let paramslen = sizeof!(CK_OBJECT_HANDLE);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_BASE_AND_KEY,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true), (CKA_SENSITIVE, false)],
    );
    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    let exp_value =
        hex::decode("000102030405060708090a0b0c0d00102030405060708090a0b0c0d0")
            .unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);
    assert_eq!(check_validation(session, 1), true);
    assert_eq!(check_object_validation(session, dk_handle, 1), true);

    // Concatenate base and data
    let data = hex::decode("0e0f").unwrap();
    let params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as *mut _,
        ulLen: data.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_KEY_DERIVATION_STRING_DATA);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_BASE_AND_DATA,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 1), true);
    assert_eq!(check_object_validation(session, dk_handle, 1), true);

    let exp_value = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

    // Concatenate data and base
    let data = hex::decode("0e0f").unwrap();
    let params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as *mut _,
        ulLen: data.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_KEY_DERIVATION_STRING_DATA);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_DATA_AND_BASE,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 1), true);
    assert_eq!(check_object_validation(session, dk_handle, 1), true);

    let exp_value = hex::decode("0e0f000102030405060708090a0b0c0d").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

    // XOR key and data
    let data = hex::decode("00102030405060708090a0b0c0d0").unwrap();
    let params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as *mut _,
        ulLen: data.len() as CK_ULONG,
    };
    let paramslen = sizeof!(CK_KEY_DERIVATION_STRING_DATA);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_XOR_BASE_AND_DATA,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(check_validation(session, 1), true);
    assert_eq!(check_object_validation(session, dk_handle, 1), true);

    let exp_value = hex::decode("00112233445566778899aabbccdd").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

    // Concatenate base with short key
    let shorter_key = hex::decode("ff").unwrap();
    let shorter_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, shorter_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false)
        ],
    ));

    let params = shorter_key_handle;
    let paramslen = sizeof!(CK_OBJECT_HANDLE);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_BASE_AND_KEY,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        &[(CKA_EXTRACTABLE, true), (CKA_SENSITIVE, false)],
    );
    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    let exp_value = hex::decode("000102030405060708090a0b0c0dff").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);
    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_concatenate_kdf_attributes() {
    let mut testtokn =
        TestToken::initialized("concatente_kdf_attributes", None);
    let session = testtokn.get_session(false);

    let base_key = hex::decode("01234567").unwrap();
    let base_key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, base_key.as_slice()),],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false),
        ],
    ));
    // sanity check the always/never attributes are stored properly
    if let Some(err) = check_attributes(
        session,
        base_key_handle,
        &[(CKA_VALUE_LEN, 4)],
        &[],
        &[
            (CKA_LOCAL, false),
            (CKA_EXTRACTABLE, true),
            (CKA_SENSITIVE, false),
            (CKA_NEVER_EXTRACTABLE, false),
            (CKA_ALWAYS_SENSITIVE, false),
        ],
    ) {
        panic!("{}", err);
    }

    /* generate the other key to get ALWAYS_SENSITIVE and NEVER_EXTRACTABLE attributes */
    let another_key_handle = ret_or_panic!(generate_key(
        session,
        CKM_GENERIC_SECRET_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET), (CKA_VALUE_LEN, 4)],
        &[],
        &[
            (CKA_DERIVE, true),
            (CKA_EXTRACTABLE, false),
            (CKA_SENSITIVE, true),
        ], // defaults
    ));
    // sanity check the always/never attributes are stored properly
    if let Some(err) = check_attributes(
        session,
        another_key_handle,
        &[(CKA_VALUE_LEN, 4)],
        &[],
        &[
            (CKA_LOCAL, true),
            (CKA_EXTRACTABLE, false),
            (CKA_SENSITIVE, true),
            (CKA_NEVER_EXTRACTABLE, true),
            (CKA_ALWAYS_SENSITIVE, true),
        ],
    ) {
        panic!("{}", err);
    }

    // Concatenate base and key
    let params = another_key_handle;
    let paramslen = sizeof!(CK_OBJECT_HANDLE);
    let derive_mech = CK_MECHANISM {
        mechanism: CKM_CONCATENATE_BASE_AND_KEY,
        pParameter: void_ptr!(&params),
        ulParameterLen: paramslen,
    };

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        ],
        &[],
        // ignored as one of the keys is sensitive + non-extractable
        &[(CKA_EXTRACTABLE, true), (CKA_SENSITIVE, false)],
    );
    let mut dk_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &derive_mech as *const _ as CK_MECHANISM_PTR,
        base_key_handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut dk_handle,
    );
    assert_eq!(ret, CKR_OK);
    // make sure the non-extractable and sensitive attributes are propagated
    // to derived key, regardless the derive template
    // Do not check the value as it is not extractable
    if let Some(err) = check_attributes(
        session,
        dk_handle,
        &[(CKA_VALUE_LEN, 8)],
        &[],
        &[
            (CKA_LOCAL, false),
            (CKA_EXTRACTABLE, false),
            (CKA_SENSITIVE, true),
            (CKA_NEVER_EXTRACTABLE, false),
            (CKA_ALWAYS_SENSITIVE, false),
        ],
    ) {
        panic!("{}", err);
    }

    assert_eq!(check_validation(session, 0), true);
    assert_eq!(check_object_validation(session, dk_handle, 0), true);

    testtokn.finalize();
}

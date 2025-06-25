// Copyright 2025 Jakub Jelen
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_concatenate_kdf() {
    let mut testtokn = TestToken::initialized("concatente_kdf", None);
    let session = testtokn.get_session(false);

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

    let exp_value = hex::decode("0123456789abcdef").unwrap();
    let value = ret_or_panic!(extract_key_value(session, dk_handle));
    assert_eq!(value, exp_value);

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

    let exp_value = hex::decode("88888888").unwrap();
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

    let exp_value = hex::decode("00112233445566778899aabbccdd").unwrap();
    let exp_value_len = 14;
    let value =
        ret_or_panic!(extract_key_value(session, dk_handle, exp_value_len));
    assert_eq!(value, exp_value);
}

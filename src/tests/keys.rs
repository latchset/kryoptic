// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use tests::*;

#[test]
fn test_key() {
    let mut testtokn = TestToken::initialized("test_key.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generic Secret */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_GENERIC_SECRET;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_WRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_UNWRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    let mut ret = fn_generate_key(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle,
    );
    assert_eq!(ret, CKR_OK);

    /* RSA key pair */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pubkey = CK_INVALID_HANDLE;
    let mut prikey = CK_INVALID_HANDLE;

    let mut len: CK_ULONG = 2048;
    let mut pub_template = vec![
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_VERIFY, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_MODULUS_BITS, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_WRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];
    let mut class = CKO_PRIVATE_KEY;
    let mut ktype = CKK_RSA;
    let mut pri_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_PRIVATE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SIGN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_UNWRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut pubkey,
        &mut prikey,
    );
    assert_eq!(ret, CKR_OK);

    let mut sig_mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut sig_mechanism, prikey);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 256] = [0; 256];
    let mut sign_len: CK_ULONG = 256;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 256);

    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Wrap RSA key in AES */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped = vec![0u8; 65536];
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    ret = fn_wrap_key(
        session,
        &mut mechanism,
        handle,
        prikey,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut prikey2 = CK_INVALID_HANDLE;
    ret = fn_unwrap_key(
        session,
        &mut mechanism,
        handle,
        wrapped.as_mut_ptr(),
        wrapped_len,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut prikey2,
    );
    assert_eq!(ret, CKR_OK);

    /* Test the unwrapped key can be used */
    ret = fn_sign_init(session, &mut sig_mechanism, prikey2);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 256] = [0; 256];
    let mut sign_len: CK_ULONG = 256;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 256);

    /* And signature verified by the original public key */
    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Wrap AES Key in RSA PKCS */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    ret = fn_wrap_key(
        session,
        &mut mechanism,
        pubkey,
        handle,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    /* need to unwrap the key with a template that
     * will work for an encryption operation */
    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut handle2 = CK_INVALID_HANDLE;
    ret = fn_unwrap_key(
        session,
        &mut mechanism,
        prikey,
        wrapped.as_mut_ptr(),
        wrapped_len,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut handle2,
    );
    assert_eq!(ret, CKR_OK);

    /* test the unwrapped key works */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    ret = fn_encrypt_init(session, &mut mechanism, handle2);
    assert_eq!(ret, CKR_OK);

    /* init is sufficient to ensure the key is well formed,
     * terminate current operation */
    ret = fn_encrypt_init(session, std::ptr::null_mut(), handle2);
    assert_eq!(ret, CKR_OK);

    /* RSA 4k key pair */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pubkey = CK_INVALID_HANDLE;
    let mut prikey = CK_INVALID_HANDLE;

    let mut len: CK_ULONG = 4096;
    let mut pub_template = vec![
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_VERIFY, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_MODULUS_BITS, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_WRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];
    let mut class = CKO_PRIVATE_KEY;
    let mut ktype = CKK_RSA;
    let mut pri_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_PRIVATE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SIGN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_UNWRAP, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut pubkey,
        &mut prikey,
    );
    assert_eq!(ret, CKR_OK);

    let mut sig_mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut sig_mechanism, prikey);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 512] = [0; 512];
    let mut sign_len: CK_ULONG = 512;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 512);

    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* EC key pair */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_EC_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut pubkey = CK_INVALID_HANDLE;
    let mut prikey = CK_INVALID_HANDLE;

    let mut truebool = CK_TRUE;
    let ec_params_hex = "06052B81040022"; // secp384r1
    let ec_params =
        hex::decode(ec_params_hex).expect("Failed to decode hex ec_params");
    let mut ktype = CKK_EC;
    let mut class = CKO_PUBLIC_KEY;
    let mut pub_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VERIFY, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EC_PARAMS,
            ec_params.as_ptr() as *mut std::ffi::c_void,
            ec_params.len()
        ),
    ];
    let mut class = CKO_PRIVATE_KEY;
    let mut pri_template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_PRIVATE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SENSITIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_SIGN, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_EXTRACTABLE,
            &mut truebool as *mut _,
            CK_BBOOL_SIZE
        ),
    ];

    ret = fn_generate_key_pair(
        session,
        &mut mechanism,
        pub_template.as_mut_ptr(),
        pub_template.len() as CK_ULONG,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut pubkey,
        &mut prikey,
    );
    assert_eq!(ret, CKR_OK);

    let mut sig_mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ECDSA_SHA256,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    ret = fn_sign_init(session, &mut sig_mechanism, prikey);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 96] = [0; 96];
    let mut sign_len: CK_ULONG = 96;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 96);

    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Wrap EC key in AES */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped = vec![0u8; 65536];
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    ret = fn_wrap_key(
        session,
        &mut mechanism,
        handle,
        prikey,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut prikey2 = CK_INVALID_HANDLE;
    ret = fn_unwrap_key(
        session,
        &mut mechanism,
        handle,
        wrapped.as_mut_ptr(),
        wrapped_len,
        pri_template.as_mut_ptr(),
        pri_template.len() as CK_ULONG,
        &mut prikey2,
    );
    assert_eq!(ret, CKR_OK);

    /* Test the unwrapped key can be used */
    ret = fn_sign_init(session, &mut sig_mechanism, prikey2);
    assert_eq!(ret, CKR_OK);

    let data = "plaintext";
    let sign: [u8; 96] = [0; 96];
    let mut sign_len: CK_ULONG = 96;
    ret = fn_sign(
        session,
        CString::new(data).unwrap().into_raw() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut _,
        &mut sign_len,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(sign_len, 96);

    /* And signature verified by the original public key */
    ret = fn_verify_init(session, &mut sig_mechanism, pubkey);
    assert_eq!(ret, CKR_OK);

    ret = fn_verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as CK_ULONG,
        sign.as_ptr() as *mut u8,
        sign_len,
    );
    assert_eq!(ret, CKR_OK);

    /* Test key derivation */
    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_ENCRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
        make_attribute!(CKA_DECRYPT, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut counter_format = CK_SP800_108_COUNTER_FORMAT {
        bLittleEndian: 0,
        ulWidthInBits: 8,
    };

    let mut data_params = [CK_PRF_DATA_PARAM {
        type_: CK_SP800_108_ITERATION_VARIABLE,
        pValue: &mut counter_format as *mut _ as CK_VOID_PTR,
        ulValueLen: std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>()
            as CK_ULONG,
    }];

    let mut params = CK_SP800_108_KDF_PARAMS {
        prfType: CKM_SHA3_384_HMAC,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SP800_108_COUNTER_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_KDF_PARAMS>()
            as CK_ULONG,
    };

    let mut handle3 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle3,
    );
    assert_eq!(ret, CKR_OK);

    /* try again but derive additional keys */
    let mut handle4 = CK_INVALID_HANDLE;
    let mut handle5 = CK_UNAVAILABLE_INFORMATION;
    let mut handle6 = CK_UNAVAILABLE_INFORMATION;
    let mut addl_keys = [
        CK_DERIVED_KEY {
            pTemplate: derive_template.as_ptr() as *mut _,
            ulAttributeCount: derive_template.len() as CK_ULONG,
            phKey: &mut handle5,
        },
        CK_DERIVED_KEY {
            pTemplate: derive_template.as_ptr() as *mut _,
            ulAttributeCount: derive_template.len() as CK_ULONG,
            phKey: &mut handle6,
        },
    ];
    params.ulAdditionalDerivedKeys = 2;
    params.pAdditionalDerivedKeys = addl_keys.as_mut_ptr();
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle4,
    );
    assert_eq!(ret, CKR_OK);

    /* check each key */
    let mut val: CK_ULONG = 0;
    let attrtmpl = [make_attribute!(
        CKA_VALUE_LEN,
        &mut val as *mut _,
        CK_ULONG_SIZE
    )];

    ret = fn_get_attribute_value(
        session,
        handle3,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    ret = fn_get_attribute_value(
        session,
        handle4,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    ret = fn_get_attribute_value(
        session,
        handle5,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    ret = fn_get_attribute_value(
        session,
        handle6,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    /* Test Sp800 108 feedback key derivation */
    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_GENERIC_SECRET;
    let mut len: CK_ULONG = 1234;
    let mut truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut counter_format = CK_SP800_108_COUNTER_FORMAT {
        bLittleEndian: 0,
        ulWidthInBits: 32,
    };

    let mut data_params = [
        CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_ITERATION_VARIABLE,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        },
        CK_PRF_DATA_PARAM {
            type_: CK_SP800_108_COUNTER,
            pValue: &mut counter_format as *mut _ as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_SP800_108_COUNTER_FORMAT>()
                as CK_ULONG,
        },
    ];

    /* openssl requires 32 bit IV here */
    #[cfg(feature = "fips")]
    let mut iv = [123u8; 32];

    #[cfg(not(feature = "fips"))]
    let mut iv = [1u8; 5];

    let mut params = CK_SP800_108_FEEDBACK_KDF_PARAMS {
        prfType: CKM_SHA256_HMAC,
        ulNumberOfDataParams: data_params.len() as CK_ULONG,
        pDataParams: data_params.as_mut_ptr(),
        ulIVLen: iv.len() as CK_ULONG,
        pIV: iv.as_mut_ptr(),
        ulAdditionalDerivedKeys: 0,
        pAdditionalDerivedKeys: std::ptr::null_mut(),
    };

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SP800_108_FEEDBACK_KDF,
        pParameter: &mut params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>()
            as CK_ULONG,
    };

    let mut handle7 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle7,
    );
    assert_eq!(ret, CKR_OK);

    /* Test AES_ECB/AES_CBC Key derivation */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 32;
    let mut truebool = CK_TRUE;
    let mut template = vec![
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let mut aeskey = CK_INVALID_HANDLE;
    ret = fn_generate_key(
        session,
        &mut mechanism,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
        &mut aeskey,
    );
    assert_eq!(ret, CKR_OK);

    let mut class = CKO_SECRET_KEY;
    let mut ktype = CKK_AES;
    let mut len: CK_ULONG = 16;
    let mut truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &mut class as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &mut ktype as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &mut len as *mut _, CK_ULONG_SIZE),
        make_attribute!(CKA_DERIVE, &mut truebool as *mut _, CK_BBOOL_SIZE),
    ];

    let data = "derive keys data";
    let mut derive_params = CK_KEY_DERIVATION_STRING_DATA {
        pData: data.as_ptr() as CK_BYTE_PTR,
        ulLen: data.len() as CK_ULONG,
    };
    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_AES_ECB_ENCRYPT_DATA,
        pParameter: &mut derive_params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_KEY_DERIVATION_STRING_DATA>()
            as CK_ULONG,
    };

    let mut aeskey2 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut aeskey2,
    );
    assert_eq!(ret, CKR_OK);

    let mut derive_params = CK_AES_CBC_ENCRYPT_DATA_PARAMS {
        iv: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        pData: data.as_ptr() as CK_BYTE_PTR,
        length: data.len() as CK_ULONG,
    };
    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_AES_CBC_ENCRYPT_DATA,
        pParameter: &mut derive_params as *mut _ as CK_VOID_PTR,
        ulParameterLen: std::mem::size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>()
            as CK_ULONG,
    };

    let mut aeskey3 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey2,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut aeskey3,
    );
    assert_eq!(ret, CKR_OK);

    /* Test Hash based derivation */

    /* No length or type */
    let class = CKO_SECRET_KEY;
    let truebool = CK_TRUE;
    let derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SHA256_KEY_DERIVATION,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut hashkey1 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut hashkey1,
    );
    assert_eq!(ret, CKR_OK);

    let mut extract_template = [CK_ATTRIBUTE {
        type_: CKA_VALUE,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    }];

    ret = fn_get_attribute_value(
        session,
        hashkey1,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 32);

    /* Key len too big */
    let mut keylen: CK_ULONG = 42;
    let mut derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &keylen as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut hashkey2 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey2,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

    /* Valid Key len defined */
    keylen = 22;
    derive_template[1].pValue = &keylen as *const _ as CK_VOID_PTR;
    let mut hashkey2 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey2,
    );
    assert_eq!(ret, CKR_OK);

    extract_template[0].ulValueLen = 0;

    ret = fn_get_attribute_value(
        session,
        hashkey2,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 22);

    /* No length but key type defined */
    let ktype = CKK_AES;
    let derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &ktype as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_SHA512_KEY_DERIVATION,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut hashkey3 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut hashkey3,
    );
    assert_eq!(ret, CKR_OK);

    extract_template[0].ulValueLen = 0;

    ret = fn_get_attribute_value(
        session,
        hashkey3,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 32);

    /* Key type define and incompatible length */
    keylen = 42;
    let mut derive_template = [
        make_attribute!(CKA_CLASS, &class as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_KEY_TYPE, &ktype as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_VALUE_LEN, &keylen as *const _, CK_ULONG_SIZE),
        make_attribute!(CKA_EXTRACTABLE, &truebool as *const _, CK_BBOOL_SIZE),
    ];

    let mut hashkey4 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey4,
    );
    assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

    /* Key type and length defined */
    keylen = 32;
    derive_template[2].pValue = &keylen as *const _ as CK_VOID_PTR;
    let mut hashkey4 = CK_INVALID_HANDLE;
    ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut hashkey4,
    );
    assert_eq!(ret, CKR_OK);

    extract_template[0].ulValueLen = 0;

    ret = fn_get_attribute_value(
        session,
        hashkey4,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, 32);

    testtokn.finalize();
}

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_secret_key() {
    let mut testtokn = TestToken::initialized("test_secret_key", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Generic Secret */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_GENERIC_SECRET_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET), (CKA_VALUE_LEN, 16),],
        &[],
        &[
            (CKA_WRAP, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    /* check some attributes */
    if let Some(err) = check_attributes(
        session,
        handle,
        &[(CKA_KEY_GEN_MECHANISM, CKM_GENERIC_SECRET_KEY_GEN)],
        &[],
        &[(CKA_LOCAL, true)],
    ) {
        panic!("{}", err);
    }

    /* Test CKA_ALLOWED_MECHANISMS */

    let allowed = CKM_AES_ECB.to_ne_bytes();
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_AES), (CKA_VALUE_LEN, 16),],
        &[(CKA_ALLOWED_MECHANISMS, &allowed)],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true),],
    ));

    /* Test disallowed mech fails */
    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_CBC,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let ret = fn_encrypt_init(session, &mut mechanism, handle);
    assert_eq!(ret, CKR_MECHANISM_INVALID);

    /* Now check that init with allowed mech succeeds */
    let data = "0123456789ABCDEF";
    let _ = ret_or_panic!(encrypt(
        session,
        handle,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_AES_ECB,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));

    testtokn.finalize();
}

#[cfg(feature = "rsa")]
#[test]
#[parallel]
fn test_rsa_key() {
    let mut testtokn = TestToken::initialized("test_rsa_key", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* RSA key pair */
    let (pubkey, prikey) = ret_or_panic!(generate_key_pair(
        session,
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        &[(CKA_MODULUS_BITS, 2048)],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_VERIFY, true), (CKA_WRAP, true),],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA),],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_DECRYPT, true),
            (CKA_SIGN, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        prikey,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));
    assert_eq!(sig.len(), 256);

    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            pubkey,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_SHA256_RSA_PKCS,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    /* Wrap RSA key in AES */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_GENERIC_SECRET_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET), (CKA_VALUE_LEN, 16),],
        &[],
        &[
            (CKA_WRAP, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped = vec![0u8; 65536];
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    let mut ret = fn_wrap_key(
        session,
        &mut mechanism,
        handle,
        prikey,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut pri_template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_DECRYPT, true),
            (CKA_SIGN, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    );

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
    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        prikey2,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));
    assert_eq!(sig.len(), 256);

    /* And signature verified by the original public key */
    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            pubkey,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_SHA256_RSA_PKCS,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    #[cfg(not(feature = "fips"))]
    {
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
        let mut template = make_attr_template(
            &[
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_KEY_TYPE, CKK_AES),
                (CKA_VALUE_LEN, 16),
            ],
            &[],
            &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
        );

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
    }

    /* RSA 4k key pair */
    let (pubkey, prikey) = ret_or_panic!(generate_key_pair(
        session,
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        &[(CKA_MODULUS_BITS, 4096)],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_VERIFY, true), (CKA_WRAP, true),],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA),],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_DECRYPT, true),
            (CKA_SIGN, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        prikey,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));
    assert_eq!(sig.len(), 512);

    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            pubkey,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_SHA256_RSA_PKCS,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    testtokn.finalize();
}

#[cfg(feature = "ecdsa")]
#[test]
#[parallel]
fn test_ecc_key() {
    let mut testtokn = TestToken::initialized("test_ecc_key", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* EC key pair */
    let ec_params = hex::decode(
        "06052B81040022", // secp384r1
    )
    .expect("Failed to decode hex ec_params");

    let (pubkey, prikey) = ret_or_panic!(generate_key_pair(
        session,
        CKM_EC_KEY_PAIR_GEN,
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_EC),],
        &[(CKA_EC_PARAMS, ec_params.as_slice())],
        &[(CKA_VERIFY, true)],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC),],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_SIGN, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        prikey,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_ECDSA_SHA256,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));
    assert_eq!(sig.len(), 96);

    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            pubkey,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_ECDSA_SHA256,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    /* Wrap EC key in AES */
    let handle = ret_or_panic!(generate_key(
        session,
        CKM_GENERIC_SECRET_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET), (CKA_VALUE_LEN, 16),],
        &[],
        &[
            (CKA_WRAP, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    let mut mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let mut wrapped = vec![0u8; 65536];
    let mut wrapped_len = wrapped.len() as CK_ULONG;

    let mut ret = fn_wrap_key(
        session,
        &mut mechanism,
        handle,
        prikey,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );
    assert_eq!(ret, CKR_OK);

    let mut pri_template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC)],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_SIGN, true),
            (CKA_UNWRAP, true),
            (CKA_EXTRACTABLE, true),
        ],
    );

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
    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        prikey2,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_ECDSA_SHA256,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));
    assert_eq!(sig.len(), 96);

    /* And signature verified by the original public key */
    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            pubkey,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_ECDSA_SHA256,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    /* Test CKA_ALWAYS_AUTHENTICATE */

    let ec_params = hex::decode(
        "06052B81040022", // secp384r1
    )
    .expect("Failed to decode hex ec_params");

    let (_pubkey, prikey) = ret_or_panic!(generate_key_pair(
        session,
        CKM_EC_KEY_PAIR_GEN,
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_EC),],
        &[(CKA_EC_PARAMS, ec_params.as_slice())],
        &[(CKA_VERIFY, true)],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC),],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_SIGN, true),
            (CKA_EXTRACTABLE, true),
            (CKA_ALWAYS_AUTHENTICATE, true),
        ],
    ));

    let data = "plaintext";

    /* attempt context specific login w/o op should fail */
    let pin = "12345678";
    let ret = fn_login(
        session,
        CKU_CONTEXT_SPECIFIC,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OPERATION_NOT_INITIALIZED);

    /* first initialize a private key operation */
    let ret = fn_sign_init(
        session,
        &CK_MECHANISM {
            mechanism: CKM_ECDSA_SHA256,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        } as *const _ as CK_MECHANISM_PTR,
        prikey,
    );
    assert_eq!(ret, CKR_OK);

    /* any other op w/o authentication should fail */
    let mut siglen: CK_ULONG = 0;
    let ret = fn_sign(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut siglen,
    );
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    if testtokn.dbtype != "nssdb" {
        /* attempt context specific login (wrong pin) */
        let pin = "AAAAAAAA";
        let ret = fn_login(
            session,
            CKU_CONTEXT_SPECIFIC,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_PIN_INCORRECT);
    }

    /* retry op w/o authentication should still fail */
    let mut siglen: CK_ULONG = 0;
    let ret = fn_sign(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut siglen,
    );
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* attempt context specific login (right pin) */
    let pin = "12345678";
    let ret = fn_login(
        session,
        CKU_CONTEXT_SPECIFIC,
        pin.as_ptr() as *mut _,
        pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* retry op with authentication should succeed */
    let mut siglen: CK_ULONG = 0;
    let ret = fn_sign(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        std::ptr::null_mut(),
        &mut siglen,
    );
    assert_eq!(ret, CKR_OK);

    let mut signature: Vec<u8> = vec![0; siglen as usize];
    let ret = fn_sign(
        session,
        byte_ptr!(data),
        data.len() as CK_ULONG,
        signature.as_mut_ptr(),
        &mut siglen,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[cfg(all(feature = "eddsa", not(feature = "fips")))]
#[test]
#[parallel]
fn test_eddsa_key() {
    let mut testtokn = TestToken::initialized("test_eddsa_key", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* Ed25519 key pair */
    let ec_params = hex::decode(
        "130c656477617264733235353139", // edwards25519
    )
    .expect("Failed to decode hex ec_params");

    let (pubkey, prikey) = ret_or_panic!(generate_key_pair(
        session,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_EC_EDWARDS),],
        &[(CKA_EC_PARAMS, ec_params.as_slice())],
        &[(CKA_VERIFY, true)],
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC_EDWARDS),],
        &[],
        &[
            (CKA_PRIVATE, true),
            (CKA_SENSITIVE, true),
            (CKA_TOKEN, true),
            (CKA_SIGN, true),
            (CKA_EXTRACTABLE, true),
        ],
    ));

    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        prikey,
        data.as_bytes(),
        &CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        },
    ));
    assert_eq!(sig.len(), 64);

    assert_eq!(
        CKR_OK,
        sig_verify(
            session,
            pubkey,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_EDDSA,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    testtokn.finalize();
}

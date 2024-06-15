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
}

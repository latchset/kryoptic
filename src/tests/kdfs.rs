// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use super::tests;
use itertools::Itertools;
use tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_sp800_kdf() {
    let mut testtokn = TestToken::initialized("test_sp800_kdf.sql", None);
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
        &[(CKA_DERIVE, true),],
    ));

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_VALUE_LEN, 16),
        ],
        &[],
        &[(CKA_ENCRYPT, true), (CKA_DECRYPT, true)],
    );

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
    let ret = fn_derive_key(
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
    let ret = fn_derive_key(
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
    let attrtmpl = make_ptrs_template(&[(
        CKA_VALUE_LEN,
        void_ptr!(&mut val),
        CK_ULONG_SIZE,
    )]);

    let ret = fn_get_attribute_value(
        session,
        handle3,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    let ret = fn_get_attribute_value(
        session,
        handle4,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    let ret = fn_get_attribute_value(
        session,
        handle5,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    val = 0;
    let ret = fn_get_attribute_value(
        session,
        handle6,
        attrtmpl.as_ptr() as *mut _,
        attrtmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(val, 16);

    /* Test Sp800 108 feedback key derivation */
    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            (CKA_VALUE_LEN, 1234),
        ],
        &[],
        &[(CKA_DERIVE, true)],
    );

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
    let ret = fn_derive_key(
        session,
        &mut derive_mech,
        handle,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut handle7,
    );
    assert_eq!(ret, CKR_OK);
}

#[test]
#[parallel]
fn test_aes_enc_kdf() {
    let mut testtokn = TestToken::initialized("test_aes_enc_kdf.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let aeskey = ret_or_panic!(generate_key(
        session,
        CKM_AES_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_AES), (CKA_VALUE_LEN, 32),],
        &[],
        &[(CKA_DERIVE, true)],
    ));

    let derive_template = make_attr_template(
        &[
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_VALUE_LEN, 16),
        ],
        &[],
        &[(CKA_DERIVE, true)],
    );

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
    let ret = fn_derive_key(
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
    let ret = fn_derive_key(
        session,
        &mut derive_mech,
        aeskey2,
        derive_template.as_ptr() as *mut _,
        derive_template.len() as CK_ULONG,
        &mut aeskey3,
    );
    assert_eq!(ret, CKR_OK);
}

#[test]
#[parallel]
fn test_hash_kdf() {
    let mut testtokn = TestToken::initialized("test_hash_kdf.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    /* run tests with multiple keys */
    for kopt in [
        (CKM_GENERIC_SECRET_KEY_GEN, CKK_GENERIC_SECRET, 16),
        (CKM_AES_KEY_GEN, CKK_AES, 32),
    ] {
        /* New Key */
        let key_handle = ret_or_panic!(generate_key(
            session,
            kopt.0,
            std::ptr::null_mut(),
            0,
            &[(CKA_KEY_TYPE, kopt.1), (CKA_VALUE_LEN, kopt.2),],
            &[],
            &[(CKA_DERIVE, true),],
        ));

        /* Test Hash based derivation iwith multiple hashes */
        for hopt in [
            (CKM_SHA1_KEY_DERIVATION, 20),
            (CKM_SHA224_KEY_DERIVATION, 28),
            (CKM_SHA256_KEY_DERIVATION, 32),
            (CKM_SHA384_KEY_DERIVATION, 48),
            (CKM_SHA512_KEY_DERIVATION, 64),
            (CKM_SHA3_224_KEY_DERIVATION, 28),
            (CKM_SHA3_256_KEY_DERIVATION, 32),
            (CKM_SHA3_384_KEY_DERIVATION, 48),
            (CKM_SHA3_512_KEY_DERIVATION, 64),
        ] {
            /* No length or type */
            let derive_template = make_attr_template(
                &[(CKA_CLASS, CKO_SECRET_KEY)],
                &[],
                &[(CKA_EXTRACTABLE, true)],
            );

            let mut derive_mech = CK_MECHANISM {
                mechanism: hopt.0,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };

            let mut hashkey1 = CK_INVALID_HANDLE;
            let ret = fn_derive_key(
                session,
                &mut derive_mech,
                key_handle,
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

            let ret = fn_get_attribute_value(
                session,
                hashkey1,
                extract_template.as_mut_ptr(),
                extract_template.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);
            assert_eq!(extract_template[0].ulValueLen, hopt.1);

            /* Key len too big */
            let derive_template = make_attr_template(
                &[(CKA_CLASS, CKO_SECRET_KEY), (CKA_VALUE_LEN, hopt.1 + 10)],
                &[],
                &[(CKA_EXTRACTABLE, true)],
            );

            let mut hashkey2 = CK_INVALID_HANDLE;
            let ret = fn_derive_key(
                session,
                &mut derive_mech,
                key_handle,
                derive_template.as_ptr() as *mut _,
                derive_template.len() as CK_ULONG,
                &mut hashkey2,
            );
            assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

            /* Valid Key len defined */
            let derive_template = make_attr_template(
                &[(CKA_CLASS, CKO_SECRET_KEY), (CKA_VALUE_LEN, hopt.1 - 10)],
                &[],
                &[(CKA_EXTRACTABLE, true)],
            );
            let mut hashkey2 = CK_INVALID_HANDLE;
            let ret = fn_derive_key(
                session,
                &mut derive_mech,
                key_handle,
                derive_template.as_ptr() as *mut _,
                derive_template.len() as CK_ULONG,
                &mut hashkey2,
            );
            assert_eq!(ret, CKR_OK);

            extract_template[0].ulValueLen = 0;

            let ret = fn_get_attribute_value(
                session,
                hashkey2,
                extract_template.as_mut_ptr(),
                extract_template.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);
            assert_eq!(extract_template[0].ulValueLen, hopt.1 - 10);

            /* No length but key type defined */
            let derive_template = make_attr_template(
                &[(CKA_CLASS, CKO_SECRET_KEY), (CKA_KEY_TYPE, CKK_AES)],
                &[],
                &[(CKA_EXTRACTABLE, true)],
            );
            let mut hashkey3 = CK_INVALID_HANDLE;
            let ret = fn_derive_key(
                session,
                &mut derive_mech,
                key_handle,
                derive_template.as_ptr() as *mut _,
                derive_template.len() as CK_ULONG,
                &mut hashkey3,
            );
            assert_eq!(ret, CKR_OK);

            extract_template[0].ulValueLen = 0;

            let len = match hopt.0 {
                CKM_SHA1_KEY_DERIVATION => 16,
                CKM_SHA224_KEY_DERIVATION | CKM_SHA3_224_KEY_DERIVATION => 24,
                _ => 32,
            };

            let ret = fn_get_attribute_value(
                session,
                hashkey3,
                extract_template.as_mut_ptr(),
                extract_template.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);
            assert_eq!(extract_template[0].ulValueLen, len);
        }

        /* Key type define and incompatible length */
        let mut derive_mech = CK_MECHANISM {
            mechanism: CKM_SHA256_KEY_DERIVATION,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let derive_template = make_attr_template(
            &[
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_KEY_TYPE, CKK_AES),
                (CKA_VALUE_LEN, 42),
            ],
            &[],
            &[(CKA_EXTRACTABLE, true)],
        );

        let mut hashkey4 = CK_INVALID_HANDLE;
        let ret = fn_derive_key(
            session,
            &mut derive_mech,
            key_handle,
            derive_template.as_ptr() as *mut _,
            derive_template.len() as CK_ULONG,
            &mut hashkey4,
        );
        assert_eq!(ret, CKR_TEMPLATE_INCONSISTENT);

        /* Key type and length defined */
        let derive_template = make_attr_template(
            &[
                (CKA_CLASS, CKO_SECRET_KEY),
                (CKA_KEY_TYPE, CKK_AES),
                (CKA_VALUE_LEN, 32),
            ],
            &[],
            &[(CKA_EXTRACTABLE, true)],
        );
        let mut hashkey4 = CK_INVALID_HANDLE;
        let ret = fn_derive_key(
            session,
            &mut derive_mech,
            key_handle,
            derive_template.as_ptr() as *mut _,
            derive_template.len() as CK_ULONG,
            &mut hashkey4,
        );
        assert_eq!(ret, CKR_OK);

        let mut extract_template =
            make_ptrs_template(&[(CKA_VALUE, std::ptr::null_mut(), 0)]);

        let ret = fn_get_attribute_value(
            session,
            hashkey4,
            extract_template.as_mut_ptr(),
            extract_template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(extract_template[0].ulValueLen, 32);
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_hkdf() {
    let mut testtokn = TestToken::initialized("test_hkdf.sql", None);
    let session = testtokn.get_session(true);

    /* login */
    testtokn.login();

    let derive_hash = CKM_SHA256;
    /* length of input keys must match hash size */
    for kopt in [
        (CKM_GENERIC_SECRET_KEY_GEN, CKK_GENERIC_SECRET, 32),
        (CKM_HKDF_KEY_GEN, CKK_HKDF, 32),
    ] {
        /* New Key */
        let key_handle = ret_or_panic!(generate_key(
            session,
            kopt.0,
            std::ptr::null_mut(),
            0,
            &[(CKA_KEY_TYPE, kopt.1), (CKA_VALUE_LEN, kopt.2),],
            &[],
            &[(CKA_DERIVE, true),],
        ));

        /* Salt Key */
        let salt_handle = ret_or_panic!(generate_key(
            session,
            kopt.0,
            std::ptr::null_mut(),
            0,
            &[(CKA_KEY_TYPE, kopt.1), (CKA_VALUE_LEN, kopt.2),],
            &[],
            &[(CKA_DERIVE, true),],
        ));

        let salt_data = "SALT";
        let info_data = "INFO";

        /* Test as many combinations of params as we can */
        let derive_type = [CKM_HKDF_DERIVE, CKM_HKDF_DATA].into_iter();
        let derive_mode =
            [(true, true), (true, false), (false, true)].into_iter();
        let derive_salt_type =
            [CKF_HKDF_SALT_NULL, CKF_HKDF_SALT_DATA, CKF_HKDF_SALT_KEY]
                .into_iter();
        let derive_use_info = [true, false].into_iter();

        for (((mech, mode), salt_type), use_info) in derive_type
            .cartesian_product(derive_mode)
            .cartesian_product(derive_salt_type)
            .cartesian_product(derive_use_info)
        {
            if mech == CKM_HKDF_DATA
                && (mode.0 == false || salt_type == CKF_HKDF_SALT_NULL)
            {
                continue;
            }

            let (obj_class, mut derive_template) = match mech {
                CKM_HKDF_DERIVE => (
                    CKO_SECRET_KEY,
                    make_attr_template(
                        &[
                            (CKA_CLASS, CKO_SECRET_KEY),
                            (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                        ],
                        &[],
                        &[(CKA_EXTRACTABLE, true)],
                    ),
                ),
                CKM_HKDF_DATA => (
                    CKO_DATA,
                    make_attr_template(
                        &[(CKA_CLASS, CKO_DATA), (CKA_VALUE_LEN, 32)],
                        &[],
                        &[],
                    ),
                ),
                _ => panic!("Bad test data"),
            };

            let hkdf_params = CK_HKDF_PARAMS {
                bExtract: if mode.0 { CK_TRUE } else { CK_FALSE },
                bExpand: if mode.1 { CK_TRUE } else { CK_FALSE },
                prfHashMechanism: derive_hash,
                ulSaltType: salt_type,
                pSalt: match salt_type {
                    CKF_HKDF_SALT_NULL => std::ptr::null_mut(),
                    CKF_HKDF_SALT_DATA => byte_ptr!(salt_data.as_ptr()),
                    CKF_HKDF_SALT_KEY => std::ptr::null_mut(),
                    _ => panic!("Bad test data"),
                },
                ulSaltLen: match salt_type {
                    CKF_HKDF_SALT_NULL => 0,
                    CKF_HKDF_SALT_DATA => salt_data.len() as CK_ULONG,
                    CKF_HKDF_SALT_KEY => 0,
                    _ => panic!("Bad test data"),
                },
                hSaltKey: salt_handle,
                pInfo: match use_info {
                    true => byte_ptr!(info_data.as_ptr()),
                    false => std::ptr::null_mut(),
                },
                ulInfoLen: match use_info {
                    true => info_data.len() as CK_ULONG,
                    false => 0,
                },
            };

            let mut derive_mech = CK_MECHANISM {
                mechanism: mech,
                pParameter: void_ptr!(&hkdf_params),
                ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>()
                    as CK_ULONG,
            };

            let mut drv_handle = CK_INVALID_HANDLE;
            let ret = fn_derive_key(
                session,
                &mut derive_mech,
                key_handle,
                derive_template.as_mut_ptr(),
                derive_template.len() as CK_ULONG,
                &mut drv_handle,
            );
            assert_eq!(ret, CKR_OK);

            let mut class: CK_ULONG = CK_UNAVAILABLE_INFORMATION;
            let mut extract_template = make_ptrs_template(&[
                (CKA_CLASS, void_ptr!(&mut class), CK_ULONG_SIZE),
                (CKA_VALUE, std::ptr::null_mut(), 0),
            ]);

            let ret = fn_get_attribute_value(
                session,
                drv_handle,
                extract_template.as_mut_ptr(),
                extract_template.len() as CK_ULONG,
            );
            assert_eq!(ret, CKR_OK);
            assert_eq!(class, obj_class);
            assert_eq!(extract_template[1].ulValueLen, 32);
        }
    }

    /* hkdf-generated.txt
     * A 1200 byte HKDF vector built for https://github.com/pyca/cryptography
     * Created with OpenSSL and verified against a Go implementation
     */

    let hash = CKM_SHA256;
    let ikm = [0x0b; 22];
    let len = 1200;
    let okm = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d\
         2d9d201395faa4b61a96c8b2fb61057244b36c6ddd287f634795e7d80d5fe2\
         6bfc36def6dc129c29271a0eb7ab14bd2ca88259f8a3a92ac2ec0e3e4fa046\
         a4b90b137ce44a2105152c2db1480a0ac2e999db47e000833856093a641da0\
         82a94429eccf5143b1780234baacfa9d89b850473f2c678f7caa96b00efdac\
         e2d71fd42412465308f2374960b6c3c35d3eaaea0b8f7e595fa9cc5db25a91\
         bc0120bad6223b25e378f514686eedfc9f102e045868e64ab02f1c021868b4\
         e6686e295a10a94524e8730d79b4d3f890c387763a19a248577e9aad8e23ba\
         2bacfc9230fb144a7730d3ceaf799d1de1032951dc1fddea17f96981fbf6b0\
         5e4878df782b497f60c3eb4cff0c249d8c1bbeabca6e66c71cc79314f2bfc7\
         58dd41c9872cbb461e17cff0002a9fdee546953f98dde7d4aa828a68f4ccd9\
         50d371d1eb3839219bfdb9ef911d3602d78bd2f6a970a6c437763c81821e13\
         1325fa77fc8963a021b87caa8e35ad2a37f2237a2143c1966817e4da9912a2\
         013cd7239c5fad2e4599f9ce20bcd8cd0ff1516f9f2496ecce94ccd82cde5c\
         9ef120bbaf640d6292d6916d40d99d9d4657dd2fdf2d4e5a5bbb27446ed58a\
         3d637d0811c555273b0fd3699161acb58205fe6cfd45245249a7ecfc4c3d06\
         68de270e6962d1d19fffa4b8df099cd4022cb0df18ffcffff5b046f0fc082e\
         d16f99b416b7bbd4982ad0afc8b1dc332a8058729065538dbe9422b795a887\
         af9c5d50ee85a60871be14c7f2d1111f197378d99065fb89a0f57b73427927\
         98963f00910e5fad47a64477f41c07ac6058e01932502eb6faa88a6cc21e11\
         5b8e3ddfae8fdcaab60d13d808f3206b4e9da8bd4ae1108b2a01d256a02c91\
         31ea0f6203c8c6e55ec7ae16bb19cf3239490085713679e7c304ce254e2897\
         c0fd3bc97263a562fe161dcf6d21e841eb2266aa1cfaaaf6fc094111ad4b2e\
         4d8e05b50854ae5de83d81842c689a55b1be7d575ac50e81d7708c262c1f70\
         452884c7714abef03b88b85a41e895a0e7529b8d631e5e77583175c80e86e4\
         5802763eaba0471d11fc885b34fa4b5309a9fe49a5215d4aa21041c53a30a1\
         e97250f6445ce537bb3efb1fa17f141db69c7d97ab48cb34c33bef0ded5d4c\
         320fe554a0faea353a5579cb08f072565bbd49d167186f39a298a553f320bb\
         89eaee54151b08deef49b7b630af62b4d7be1f4965a53c67e7d3e34a6d8263\
         ee86f44dfbe019cbe8e3bd4ed0cda06985127ff8d1794e6321891a950f329a\
         ca2b36b16f8a2bb910b1206a5c238ef079df12ecb0f0f7e3e4f8a64bfd23b5\
         7e9d286a1c8d2e9290d9a4f1d20ec100aac7dc90783cb2ecfd69d71a91dcc3\
         913494ebf7a7a00d1051102d7f268e761855b985c2599350f15ee0d4093244\
         113185bc7031d2431ccd9391fcd58a85e068458b644ed265b3f103852a2d7b\
         bf0d2c1d7c02e30ff1ec552f09bc60e36393391cec05926009520af12d9638\
         7cc55b9553e79da8b2eb9303ecf15bb289530c3d65c4cc5a68f8ece60a3752\
         2fe3d0e6ba4ddfb560a45717456cf91c5dc5b8117da68bc49968ec1e35852b\
         bc54e554fb839b35f6c3b5c09530855d8691fc0f126f67346f949bd813a6db\
         44c513d1e61b8c8789eb9e823d1a38862dca1c5331da",
    )
    .expect("Failed to decode hex value");

    let key_handle = ret_or_panic!(import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[(CKA_VALUE, ikm.as_slice())],
        &[(CKA_DERIVE, true)],
    ));

    let mut derive_template = make_attr_template(
        &[(CKA_CLASS, CKO_DATA), (CKA_VALUE_LEN, len)],
        &[],
        &[],
    );

    let hkdf_params = CK_HKDF_PARAMS {
        bExtract: CK_TRUE,
        bExpand: CK_TRUE,
        prfHashMechanism: hash,
        ulSaltType: CKF_HKDF_SALT_NULL,
        pSalt: std::ptr::null_mut(),
        ulSaltLen: 0,
        hSaltKey: CK_INVALID_HANDLE,
        pInfo: std::ptr::null_mut(),
        ulInfoLen: 0,
    };

    let mut derive_mech = CK_MECHANISM {
        mechanism: CKM_HKDF_DATA,
        pParameter: void_ptr!(&hkdf_params),
        ulParameterLen: std::mem::size_of::<CK_HKDF_PARAMS>() as CK_ULONG,
    };

    let mut drv_handle = CK_INVALID_HANDLE;
    let ret = fn_derive_key(
        session,
        &mut derive_mech,
        key_handle,
        derive_template.as_mut_ptr(),
        derive_template.len() as CK_ULONG,
        &mut drv_handle,
    );
    assert_eq!(ret, CKR_OK);

    let mut result = vec![0u8; len as usize];
    let mut extract_template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(result.as_mut_ptr()),
        len as usize,
    )]);

    let ret = fn_get_attribute_value(
        session,
        drv_handle,
        extract_template.as_mut_ptr(),
        extract_template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(extract_template[0].ulValueLen, len);
    assert_eq!(result, okm);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_pbkdf2() {
    let mut testtokn = TestToken::initialized("test_pbkdf2.sql", None);
    let session = testtokn.get_session(false);

    testtokn.login();

    /* RFC 6070 Test Vectors */
    /* plus test that an empty password also works */
    for test in [
        #[cfg(not(feature = "fips"))]
        #[cfg(feature = "slow")]
        (
            "password",
            "salt",
            1,
            hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap(),
        ),
        #[cfg(not(feature = "fips"))]
        #[cfg(feature = "slow")]
        (
            "password",
            "salt",
            2,
            hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").unwrap(),
        ),
        #[cfg(not(feature = "fips"))]
        #[cfg(feature = "slow")]
        (
            "password",
            "salt",
            4096,
            hex::decode("4b007901b765489abead49d926f721d065a429c1").unwrap(),
        ),
        #[cfg(feature = "slow")]
        (
            "password",
            "salt",
            16777216,
            hex::decode("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984").unwrap(),
        ),
        /* the only vector that passes all FIPS size requirements for salt
         * and iteration count */
        (
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            hex::decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
                .unwrap(),
        ),
        #[cfg(not(feature = "fips"))]
        (
            "pass\0word",
            "sa\0lt",
            4096,
            hex::decode("56fa6aa75548099dcc37d7f03425e0c3").unwrap(),
        ),
        #[cfg(not(feature = "fips"))]
        (
            "",
            "salt",
            1024,
            hex::decode("372bd05001b6ca2a4668e7f4f219204b").unwrap(),
        ),
    ] {
        let params = CK_PKCS5_PBKD2_PARAMS2 {
            saltSource: CKZ_DATA_SPECIFIED,
            pSaltSourceData: void_ptr!(test.1.as_ptr()),
            ulSaltSourceDataLen: test.1.len() as CK_ULONG,
            iterations: test.2,
            prf: CKP_PKCS5_PBKD2_HMAC_SHA1,
            pPrfData: std::ptr::null_mut(),
            ulPrfDataLen: 0,
            pPassword: test.0.as_ptr() as *const _ as *mut _,
            ulPasswordLen: test.0.len() as CK_ULONG,
        };

        let handle = ret_or_panic!(generate_key(
            session,
            CKM_PKCS5_PBKD2,
            void_ptr!(&params),
            std::mem::size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
            &[
                (CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                (CKA_VALUE_LEN, test.3.len() as CK_ULONG),
            ],
            &[],
            &[
                (CKA_WRAP, true),
                (CKA_UNWRAP, true),
                (CKA_EXTRACTABLE, true),
            ],
        ));

        let mut result = vec![0u8; test.3.len()];
        let mut extract_template = make_ptrs_template(&[(
            CKA_VALUE,
            void_ptr!(result.as_mut_ptr()),
            result.len(),
        )]);

        let ret = fn_get_attribute_value(
            session,
            handle,
            extract_template.as_mut_ptr(),
            extract_template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(result, test.3);
    }

    testtokn.finalize();
}

// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
#[cfg(feature = "rsa")]
fn test_get_attr() {
    let mut testtokn = TestToken::initialized(
        "test_get_attr",
        Some("testdata/test_basic_rsa.json"),
    );
    let session = testtokn.get_session(false);

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let mut template =
        make_ptrs_template(&[(CKA_LABEL, std::ptr::null_mut(), 0)]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_ne!(template[0].ulValueLen, 0);

    let data: &mut [u8] = &mut [0; 128];
    let mut template =
        make_ptrs_template(&[(CKA_LABEL, void_ptr!(data.as_mut_ptr()), 128)]);

    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    let size = template[0].ulValueLen as usize;
    let value = std::str::from_utf8(&data[0..size]).unwrap();
    assert_eq!(value, "Test RSA Key");

    template[0].ulValueLen = 1;
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_BUFFER_TOO_SMALL);

    /* private key data */
    handle = CK_INVALID_HANDLE;
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    /* first try should not find it */
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 0);
    assert_eq!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* login */
    testtokn.login();

    /* after login should find it */
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let mut e = [0u8; 128];
    let mut template = make_ptrs_template(&[(
        CKA_PRIVATE_EXPONENT,
        void_ptr!(e.as_mut_ptr()),
        e.len(),
    )]);

    /* should fail for sensitive attributes */
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_SENSITIVE);

    /* and succeed for public ones */
    let mut template = make_ptrs_template(&[(
        CKA_PUBLIC_EXPONENT,
        void_ptr!(e.as_mut_ptr()),
        e.len(),
    )]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, 3);

    /* Invalid attributes for RSA keys should report as such in both rv and length */
    let mut template =
        make_ptrs_template(&[(CKA_EC_POINT, std::ptr::null_mut(), 0)]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_TYPE_INVALID);
    assert_eq!(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);

    /* Absent attributes are CKR_ATTRIBUTE_TYPE_INVALID,
     * even if valid for the object type in general (PKCS#11 5.7.5 case 2) */
    let mut template = make_ptrs_template(&[(
        CKA_ALLOWED_MECHANISMS,
        std::ptr::null_mut(),
        0,
    )]);
    let ret = fn_get_attribute_value(session, handle, template.as_mut_ptr(), 1);
    assert_eq!(ret, CKR_ATTRIBUTE_TYPE_INVALID);
    assert_eq!(template[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);

    testtokn.finalize();
}

#[test]
#[parallel]
#[cfg(feature = "rsa")]
fn test_set_attr_rsa() {
    let mut testtokn = TestToken::initialized(
        "test_set_attr",
        Some("testdata/test_basic_rsa.json"),
    );
    let session = testtokn.get_session(false);

    let mut handle: CK_ULONG = CK_INVALID_HANDLE;

    /* public key data */
    let template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY)],
        &[(CKA_ID, "\x01".as_bytes())],
        &[],
    );
    let ret = fn_find_objects_init(session, template.as_ptr() as *mut _, 2);
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    let label = "new label";
    let template = make_ptrs_template(&[(
        CKA_LABEL,
        void_ptr!(label.as_ptr()),
        label.as_bytes().len(),
    )]);
    let ret =
        fn_set_attribute_value(session, handle, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_USER_NOT_LOGGED_IN);

    /* login */
    testtokn.login();

    let ret =
        fn_set_attribute_value(session, handle, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_SESSION_READ_ONLY);

    /* Open second, read-write, session. Keep the first around to make
     * sure the token does not logout */
    let mut session2 = CK_INVALID_HANDLE;
    let ret = fn_open_session(
        testtokn.get_slot(),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        None,
        &mut session2,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_set_attribute_value(
        session2,
        handle,
        template.as_ptr() as *mut _,
        1,
    );
    assert_eq!(ret, CKR_OK);

    let unique = "unsettable";
    let template = make_ptrs_template(&[(
        CKA_UNIQUE_ID,
        void_ptr!(unique.as_ptr()),
        unique.as_bytes().len(),
    )]);

    let ret = fn_set_attribute_value(
        session2,
        handle,
        template.as_ptr() as *mut _,
        1,
    );
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    let flag: CK_ULONG = 0x03;
    let template = make_ptrs_template(&[(
        CKA_OBJECT_VALIDATION_FLAGS,
        void_ptr!(std::ptr::addr_of!(flag)),
        std::mem::size_of::<CK_ULONG>(),
    )]);

    let ret = fn_set_attribute_value(
        session2,
        handle,
        template.as_ptr() as *mut _,
        1,
    );
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    let ret = fn_close_session(session2);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_template_null_ptr() {
    let mut testtokn = TestToken::initialized("test_template_null_ptr", None);
    let session = testtokn.get_session(true);

    // ptr is null, len > 0 -> CKR_ARGUMENTS_BAD
    let ret = fn_find_objects_init(session, std::ptr::null_mut(), 1);
    assert_eq!(ret, CKR_ARGUMENTS_BAD);

    // ptr is null, len == 0 -> CKR_OK
    let ret = fn_find_objects_init(session, std::ptr::null_mut(), 0);
    assert_eq!(ret, CKR_OK);
    let _ = fn_find_objects_final(session);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_unchangeable_attributes() {
    let mut testtokn =
        TestToken::initialized("test_unchangeable_attributes", None);
    let session = testtokn.get_session(true);
    testtokn.login();

    // Generic Secret Key has CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, and CKA_VALUE
    let key = ret_or_panic!(generate_key(
        session,
        CKM_GENERIC_SECRET_KEY_GEN,
        std::ptr::null_mut(),
        0,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET), (CKA_VALUE_LEN, 16)],
        &[(CKA_LABEL, b"test secret key")],
        &[
            (CKA_TOKEN, false),
            (CKA_SENSITIVE, false),
            (CKA_COPYABLE, true),
            (CKA_EXTRACTABLE, true),
            (CKA_MODIFIABLE, true)
        ],
    ));

    // Verify original attributes
    let mut class: CK_OBJECT_CLASS = 0;
    let mut key_type: CK_KEY_TYPE = 0;
    let mut value_len: CK_ULONG = 0;
    let mut template = make_ptrs_template(&[
        (
            CKA_CLASS,
            void_ptr!(&mut class),
            std::mem::size_of::<CK_OBJECT_CLASS>(),
        ),
        (
            CKA_KEY_TYPE,
            void_ptr!(&mut key_type),
            std::mem::size_of::<CK_KEY_TYPE>(),
        ),
        (
            CKA_VALUE_LEN,
            void_ptr!(&mut value_len),
            std::mem::size_of::<CK_ULONG>(),
        ),
    ]);
    let ret = fn_get_attribute_value(session, key, template.as_mut_ptr(), 3);
    assert_eq!(ret, CKR_OK);
    assert_eq!(class, CKO_SECRET_KEY);
    assert_eq!(key_type, CKK_GENERIC_SECRET);
    assert_eq!(value_len, 16);

    let orig_val = ret_or_panic!(extract_key_value(session, key));

    // Test C_SetAttributeValue: CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_VALUE cannot be changed
    let mut new_class = CKO_DATA;
    let template = make_ptrs_template(&[(
        CKA_CLASS,
        void_ptr!(&mut new_class),
        std::mem::size_of::<CK_OBJECT_CLASS>(),
    )]);
    let ret =
        fn_set_attribute_value(session, key, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    let mut new_key_type = CKK_AES;
    let template = make_ptrs_template(&[(
        CKA_KEY_TYPE,
        void_ptr!(&mut new_key_type),
        std::mem::size_of::<CK_KEY_TYPE>(),
    )]);
    let ret =
        fn_set_attribute_value(session, key, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    let mut new_value_len: CK_ULONG = 32;
    let template = make_ptrs_template(&[(
        CKA_VALUE_LEN,
        void_ptr!(&mut new_value_len),
        std::mem::size_of::<CK_ULONG>(),
    )]);
    let ret =
        fn_set_attribute_value(session, key, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

    let new_val = [0xAAu8; 16];
    let template = make_ptrs_template(&[(
        CKA_VALUE,
        void_ptr!(new_val.as_ptr()),
        new_val.len(),
    )]);
    let ret =
        fn_set_attribute_value(session, key, template.as_ptr() as *mut _, 1);
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
    assert_eq!(ret_or_panic!(extract_key_value(session, key)), orig_val);

    // Test C_CopyObject: CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN cannot be changed via template
    for attr_type in [CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN] {
        let template = make_attr_template(&[(attr_type, 999)], &[], &[]);
        let mut copied: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        let ret = fn_copy_object(
            session,
            key,
            template.as_ptr() as *mut _,
            template.len() as CK_ULONG,
            &mut copied,
        );
        assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
        assert_eq!(copied, CK_INVALID_HANDLE);
    }

    // Test C_CopyObject: CKA_VALUE cannot be changed via template
    let template = make_attr_template(&[], &[(CKA_VALUE, &new_val)], &[]);
    let mut copied: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        key,
        template.as_ptr() as *mut _,
        template.len() as CK_ULONG,
        &mut copied,
    );
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
    assert_eq!(copied, CK_INVALID_HANDLE);

    let template = make_attr_template(
        &[
            (CKA_CLASS, CKO_DATA),
            (CKA_KEY_TYPE, CKK_AES),
            (CKA_VALUE_LEN, 32),
        ],
        &[(CKA_VALUE, &new_val)],
        &[],
    );
    let mut copied: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        key,
        template.as_ptr() as *mut _,
        template.len() as CK_ULONG,
        &mut copied,
    );
    assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
    assert_eq!(copied, CK_INVALID_HANDLE);

    // Valid copy works and retains original unchangeable attributes
    let template =
        make_attr_template(&[], &[(CKA_LABEL, b"copied secret key")], &[]);
    let mut copied: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
    let ret = fn_copy_object(
        session,
        key,
        template.as_ptr() as *mut _,
        template.len() as CK_ULONG,
        &mut copied,
    );
    assert_eq!(ret, CKR_OK);
    assert_ne!(copied, CK_INVALID_HANDLE);

    let mut copied_class: CK_OBJECT_CLASS = 0;
    let mut copied_key_type: CK_KEY_TYPE = 0;
    let mut copied_value_len: CK_ULONG = 0;
    let mut template = make_ptrs_template(&[
        (
            CKA_CLASS,
            void_ptr!(&mut copied_class),
            std::mem::size_of::<CK_OBJECT_CLASS>(),
        ),
        (
            CKA_KEY_TYPE,
            void_ptr!(&mut copied_key_type),
            std::mem::size_of::<CK_KEY_TYPE>(),
        ),
        (
            CKA_VALUE_LEN,
            void_ptr!(&mut copied_value_len),
            std::mem::size_of::<CK_ULONG>(),
        ),
    ]);
    let ret = fn_get_attribute_value(session, copied, template.as_mut_ptr(), 3);
    assert_eq!(ret, CKR_OK);
    assert_eq!(copied_class, CKO_SECRET_KEY);
    assert_eq!(copied_key_type, CKK_GENERIC_SECRET);
    assert_eq!(copied_value_len, 16);
    assert_eq!(ret_or_panic!(extract_key_value(session, copied)), orig_val);

    // Also test with AES key if AES feature is enabled
    #[cfg(feature = "aes")]
    {
        let aes_key = ret_or_panic!(generate_key(
            session,
            CKM_AES_KEY_GEN,
            std::ptr::null_mut(),
            0,
            &[(CKA_KEY_TYPE, CKK_AES), (CKA_VALUE_LEN, 16)],
            &[(CKA_LABEL, b"aes key")],
            &[
                (CKA_TOKEN, false),
                (CKA_COPYABLE, true),
                (CKA_MODIFIABLE, true)
            ],
        ));

        for attr in [CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN] {
            let mut val: CK_ULONG = 999;
            let template = make_ptrs_template(&[(
                attr,
                void_ptr!(&mut val),
                std::mem::size_of::<CK_ULONG>(),
            )]);
            let ret = fn_set_attribute_value(
                session,
                aes_key,
                template.as_ptr() as *mut _,
                1,
            );
            assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

            let template = make_attr_template(&[(attr, 999)], &[], &[]);
            let mut copied_aes: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
            let ret = fn_copy_object(
                session,
                aes_key,
                template.as_ptr() as *mut _,
                template.len() as CK_ULONG,
                &mut copied_aes,
            );
            assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
            assert_eq!(copied_aes, CK_INVALID_HANDLE);
        }

        let new_aes_val = [0xBBu8; 16];
        let template = make_ptrs_template(&[(
            CKA_VALUE,
            void_ptr!(new_aes_val.as_ptr()),
            new_aes_val.len(),
        )]);
        let ret = fn_set_attribute_value(
            session,
            aes_key,
            template.as_ptr() as *mut _,
            1,
        );
        assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

        let template =
            make_attr_template(&[], &[(CKA_VALUE, &new_aes_val)], &[]);
        let mut copied_aes: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        let ret = fn_copy_object(
            session,
            aes_key,
            template.as_ptr() as *mut _,
            template.len() as CK_ULONG,
            &mut copied_aes,
        );
        assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
        assert_eq!(copied_aes, CK_INVALID_HANDLE);
    }

    // Also test with ChaCha20 key if ChaCha20 feature is enabled
    #[cfg(feature = "chacha20")]
    {
        let chacha_key = ret_or_panic!(generate_key(
            session,
            CKM_CHACHA20_KEY_GEN,
            std::ptr::null_mut(),
            0,
            &[(CKA_KEY_TYPE, CKK_CHACHA20), (CKA_VALUE_LEN, 32)],
            &[(CKA_LABEL, b"chacha key")],
            &[
                (CKA_TOKEN, false),
                (CKA_COPYABLE, true),
                (CKA_MODIFIABLE, true)
            ],
        ));

        for attr in [CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN] {
            let mut val: CK_ULONG = 999;
            let template = make_ptrs_template(&[(
                attr,
                void_ptr!(&mut val),
                std::mem::size_of::<CK_ULONG>(),
            )]);
            let ret = fn_set_attribute_value(
                session,
                chacha_key,
                template.as_ptr() as *mut _,
                1,
            );
            assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

            let template = make_attr_template(&[(attr, 999)], &[], &[]);
            let mut copied_chacha: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
            let ret = fn_copy_object(
                session,
                chacha_key,
                template.as_ptr() as *mut _,
                template.len() as CK_ULONG,
                &mut copied_chacha,
            );
            assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
            assert_eq!(copied_chacha, CK_INVALID_HANDLE);
        }

        let new_chacha_val = [0xCCu8; 32];
        let template = make_ptrs_template(&[(
            CKA_VALUE,
            void_ptr!(new_chacha_val.as_ptr()),
            new_chacha_val.len(),
        )]);
        let ret = fn_set_attribute_value(
            session,
            chacha_key,
            template.as_ptr() as *mut _,
            1,
        );
        assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);

        let template =
            make_attr_template(&[], &[(CKA_VALUE, &new_chacha_val)], &[]);
        let mut copied_chacha: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        let ret = fn_copy_object(
            session,
            chacha_key,
            template.as_ptr() as *mut _,
            template.len() as CK_ULONG,
            &mut copied_chacha,
        );
        assert_eq!(ret, CKR_ATTRIBUTE_READ_ONLY);
        assert_eq!(copied_chacha, CK_INVALID_HANDLE);
    }

    testtokn.finalize();
}

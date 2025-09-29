// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::{parallel, serial};

#[test]
#[parallel]
fn test_nssdb_token() {
    let name = String::from("test_nssdb");
    let datadir = "testdata/nssdbdir";
    let destdir = format!("{}/{}", TESTDIR, name);

    let dbargs = format!("configDir={}", destdir);
    let dbtype = "nssdb";

    /* allocates a unique slotid to use in the tests */
    let mut testtokn =
        TestToken::new_type(String::from(dbtype), String::from(""), name);

    /* Do this after TestToken::new() otherwise the data
     * is wiped away by the initialization code */
    std::fs::create_dir_all(destdir.clone()).unwrap();
    assert!(std::fs::copy(
        format!("{}/cert9.db", datadir),
        format!("{}/cert9.db", destdir),
    )
    .is_ok());
    assert!(std::fs::copy(
        format!("{}/key4.db", datadir),
        format!("{}/key4.db", destdir),
    )
    .is_ok());
    assert!(std::fs::copy(
        format!("{}/pkcs11.txt", datadir),
        format!("{}/pkcs11.txt", destdir),
    )
    .is_ok());

    /* pre-populate conf so we get the correct slot number assigned */
    let mut slot = config::Slot::with_db(dbtype, Some(dbargs.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);
    assert_eq!(ret, CKR_OK);

    let mut args = TestToken::make_init_args(Some(dbargs.clone()));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    /* check slots and token */
    let mut info = CK_SLOT_INFO::default();
    let ret =
        fn_get_slot_info(testtokn.get_slot(), &mut info as CK_SLOT_INFO_PTR);
    assert_eq!(ret, CKR_OK);
    let desc = std::str::from_utf8(&info.slotDescription).unwrap();
    assert_eq!(desc.starts_with("Kryoptic Slot"), true);

    let session = testtokn.get_session(false);

    /* find one public key object */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_RSA)],
        &[],
        &[],
    );
    let ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* find one object with explicit empty label */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(&[], &[(CKA_LABEL, &[])], &[]);
    let ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    testtokn.logout();

    testtokn.finalize();
}

#[test]
#[parallel]
#[cfg(feature = "mldsa")]
fn test_nssdb_token_mldsa() {
    let name = String::from("test_nssdb_token_mldsa");
    let datadir = "testdata/nssdbdir2";
    let destdir = format!("{}/{}", TESTDIR, name);

    let dbargs = format!("configDir={}", destdir);
    let dbtype = "nssdb";

    /* allocates a unique slotid to use in the tests */
    let mut testtokn =
        TestToken::new_type(String::from(dbtype), String::from(""), name);

    /* Do this after TestToken::new() otherwise the data
     * is wiped away by the initialization code */
    std::fs::create_dir_all(destdir.clone()).unwrap();
    assert!(std::fs::copy(
        format!("{}/cert9.db", datadir),
        format!("{}/cert9.db", destdir),
    )
    .is_ok());
    assert!(std::fs::copy(
        format!("{}/key4.db", datadir),
        format!("{}/key4.db", destdir),
    )
    .is_ok());
    assert!(std::fs::copy(
        format!("{}/pkcs11.txt", datadir),
        format!("{}/pkcs11.txt", destdir),
    )
    .is_ok());

    /* pre-populate conf so we get the correct slot number assigned */
    let mut slot = config::Slot::with_db(dbtype, Some(dbargs.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);
    assert_eq!(ret, CKR_OK);

    let mut args = TestToken::make_init_args(Some(dbargs.clone()));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    /* check slots and token */
    let mut info = CK_SLOT_INFO::default();
    let ret =
        fn_get_slot_info(testtokn.get_slot(), &mut info as CK_SLOT_INFO_PTR);
    assert_eq!(ret, CKR_OK);
    let desc = std::str::from_utf8(&info.slotDescription).unwrap();
    assert_eq!(desc.starts_with("Kryoptic Slot"), true);

    let user_pin = "1234";
    let session = testtokn.get_session(true);

    /* try to login as user */
    let ret = fn_login(
        session,
        CKU_USER,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    /* find the private key object */
    let mut privkey: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_ML_DSA)],
        &[],
        &[],
    );
    let ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut privkey, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(privkey, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* test that the key works */
    let mechanism: CK_MECHANISM = CK_MECHANISM {
        mechanism: CKM_ML_DSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let msg = hex::decode(
        "1E5A78AD64DF229AA22FD794EC0E82D0F69953118C09D134DFA20F1CC64A3671",
    )
    .expect("failed to decode test input");
    let signature =
        ret_or_panic!(sig_gen(session, privkey, msg.as_slice(), &mechanism));

    /* find the public key object */
    let mut pubkey: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_ML_DSA)],
        &[],
        &[],
    );
    let ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut pubkey, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(pubkey, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* test that the key works */
    let ret = sig_verify(
        session,
        pubkey,
        msg.as_slice(),
        signature.as_slice(),
        &mechanism,
    );
    assert_eq!(ret, CKR_OK);

    testtokn.logout();

    testtokn.finalize();
}

// This test must be run serially as it changes global configuration
#[test]
#[serial]
fn test_nssdb_init_token() {
    let name = String::from("test_nssdb_init_token");
    let datadir = format!("{}/{}", TESTDIR, name);

    let dbargs = format!("configDir={}", datadir);
    let dbtype = "nssdb";

    let mut testtokn =
        TestToken::new_type(String::from(dbtype), String::from(""), name);

    /* pre-populate conf so we get the correct slot number assigned */
    let mut slot = config::Slot::with_db(dbtype, Some(dbargs.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);

    assert_eq!(ret, CKR_OK);
    let mut args = TestToken::make_init_args(Some(dbargs.clone()));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    /* init once (NSSDB ignores SO pin) */
    let pin_value = "Unused";
    let ret = fn_init_token(
        testtokn.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    let session = testtokn.get_session(true);

    /* NSS allows SO login w/o PIN only to set the initial User PIN */
    let ret = fn_login(session, CKU_SO, &mut [] as *mut u8, 0);
    assert_eq!(ret, CKR_OK);

    /* set user pin */
    let user_pin = "User PIN Value";
    let ret = fn_init_pin(
        session,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);

    /* try to login as user */
    let ret = fn_login(
        session,
        CKU_USER,
        CString::new(user_pin).unwrap().into_raw() as *mut u8,
        user_pin.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    #[cfg(feature = "fips")]
    /* Set default NSSDB Behavior for this test */
    let saved_config = {
        let slot_id = testtokn.get_slot();
        let mut save = config::FipsBehavior::default();
        let ret = get_fips_behavior(slot_id, &mut save);
        assert_eq!(ret, CKR_OK);
        let ret = set_fips_behavior(
            slot_id,
            config::FipsBehavior {
                keys_always_sensitive: true,
            },
        );
        assert_eq!(ret, CKR_OK);
        save
    };

    /* In FIPS mode by NSSDB databases enforce keys are
     * always sensitive, so import with CKA_SENSITIVE = false
     * will result in an error */

    /* import a key on the token */
    #[allow(unused_variables)]
    let handle = match import_object(
        session,
        CKO_SECRET_KEY,
        &[(CKA_KEY_TYPE, CKK_GENERIC_SECRET)],
        &[
            (CKA_VALUE, "Secret".as_bytes()),
            (CKA_LABEL, "Test Generic Secret".as_bytes()),
        ],
        &[
            (CKA_TOKEN, true),
            (CKA_SENSITIVE, false),
            (CKA_EXTRACTABLE, true),
            (CKA_DERIVE, true),
        ],
    ) {
        Ok(h) => {
            #[cfg(feature = "fips")]
            panic!("Should not be able to set CKA_SENSITIVE to false, but got handle {h}");
            #[cfg(not(feature = "fips"))]
            h
        }
        Err(e) => {
            #[cfg(feature = "fips")]
            if e.rv() != CKR_ATTRIBUTE_VALUE_INVALID {
                panic!("Incorrect error in fips mode: {e}")
            } else {
                CK_INVALID_HANDLE
            }
            #[cfg(not(feature = "fips"))]
            panic!("Failed to import key: {e}");
        }
    };

    #[cfg(not(feature = "fips"))]
    {
        /* fetch value */
        let mut template =
            make_ptrs_template(&[(CKA_VALUE, std::ptr::null_mut(), 0)]);
        let ret = fn_get_attribute_value(
            session,
            handle,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(template[0].ulValueLen, 6);
        let mut value = vec![0u8; 6];
        template[0].pValue = void_ptr!(value.as_mut_ptr());
        let ret = fn_get_attribute_value(
            session,
            handle,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);
        assert_eq!(value.as_slice(), "Secret".as_bytes());

        let ret = fn_destroy_object(session, handle);
        assert_eq!(ret, CKR_OK);
    }

    #[cfg(feature = "fips")]
    {
        /* Restore default FIPS  Behavior */
        let ret = set_fips_behavior(testtokn.get_slot(), saved_config);
        assert_eq!(ret, CKR_OK);
    }

    /* add a public object to ensure attributes are handled correctly
     * CKA_VALUE is encrypted only for private objects */
    let cert_handle = ret_or_panic!(import_object(
        session,
        CKO_CERTIFICATE,
        &[(CKA_CERTIFICATE_TYPE, CKC_X_509)],
        &[
            (CKA_CHECK_VALUE, "ignored".as_bytes()),
            (CKA_SUBJECT, "subject".as_bytes()),
            (CKA_VALUE, "value".as_bytes())
        ],
        &[(CKA_TOKEN, true), (CKA_TRUSTED, false)],
    ));

    /* Read the cert back */
    let mut template =
        make_ptrs_template(&[(CKA_VALUE, std::ptr::null_mut(), 0)]);
    let ret = fn_get_attribute_value(
        session,
        cert_handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen, 5);
    let mut value = vec![0u8; 5];
    template[0].pValue = void_ptr!(value.as_mut_ptr());
    let ret = fn_get_attribute_value(
        session,
        cert_handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value.as_slice(), "value".as_bytes());

    let ret = fn_logout(session);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_nssdb_init_token_params() {
    let name = String::from("test_nssdb_init_token_params");
    let datadir = format!("{}/{}", TESTDIR, name);

    let dbargs = format!(
        "configDir={} \
         manufacturerID=<My Kryoptic> \
         libraryDescription='My Library' \
         cryptoTokenDescription=\"My token description\" \
         dbTokenDescription=(db Token Description) \
         cryptoSlotDescription=[my slot description] \
         flags=passwordRequired",
        datadir
    );
    let dbtype = "nssdb";

    let mut testtokn =
        TestToken::new_type(String::from(dbtype), String::from(""), name);

    /* pre-populate conf so we get the correct slot number assigned */
    let mut slot = config::Slot::with_db(dbtype, Some(dbargs.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);

    assert_eq!(ret, CKR_OK);
    let mut args = TestToken::make_init_args(Some(dbargs.clone()));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    /* init once (NSSDB ignores SO pin) */
    let pin_value = "Unused";
    let ret = fn_init_token(
        testtokn.get_slot(),
        CString::new(pin_value).unwrap().into_raw() as *mut u8,
        pin_value.len() as CK_ULONG,
        std::ptr::null_mut(),
    );
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_nssdb_key_cache() {
    let name = String::from("test_nssdb_key_cache");
    let datadir = "testdata/nssdbdir";
    let destdir = format!("{}/{}", TESTDIR, name);

    let dbargs = format!("configDir={}", destdir);
    let dbtype = "nssdb";

    /* allocates a unique slotid to use in the tests */
    let mut testtokn =
        TestToken::new_type(String::from(dbtype), String::from(""), name);

    /* Do this after TestToken::new() otherwise the data
     * is wiped away by the initialization code */
    std::fs::create_dir_all(destdir.clone()).unwrap();
    assert!(std::fs::copy(
        format!("{}/cert9.db", datadir),
        format!("{}/cert9.db", destdir),
    )
    .is_ok());
    assert!(std::fs::copy(
        format!("{}/key4.db", datadir),
        format!("{}/key4.db", destdir),
    )
    .is_ok());
    assert!(std::fs::copy(
        format!("{}/pkcs11.txt", datadir),
        format!("{}/pkcs11.txt", destdir),
    )
    .is_ok());

    /* pre-populate conf so we get the correct slot number assigned */
    let mut slot = config::Slot::with_db(dbtype, Some(dbargs.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);
    assert_eq!(ret, CKR_OK);

    let mut args = TestToken::make_init_args(Some(dbargs.clone()));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_eq!(ret, CKR_OK);

    let _ = testtokn.get_session(false);
    for _ in 0..1000 {
        testtokn.login();
        testtokn.logout();
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_nssdb_derive_key() {
    use crate::kasn1::pkcs::PBKDF2Params;
    use crate::kasn1::pkcs::HMAC_SHA_256_ALG;
    use crate::storage::nssdb::ci::derive_key_test;
    use crate::storage::nssdb::ci::KeyOp;
    use crate::storage::nssdb::ci::KeysWithCaching;
    use crate::token::Handles;
    use crate::token::TokenFacilities;

    let mut facilities = TokenFacilities {
        mechanisms: Mechanisms::new(),
        factories: ObjectFactories::new(),
        handles: Handles::new(),
    };
    register_all(&mut facilities.mechanisms, &mut facilities.factories);
    let mut key_cache = KeysWithCaching::default();
    key_cache.set_key(vec![42u8; 32]);

    for t in 0..100 {
        let salt: [u8; 32] = [t as u8; 32];
        let params = PBKDF2Params {
            salt: &salt,
            iteration_count: 10000,
            key_length: Some(32),
            prf: Box::new(HMAC_SHA_256_ALG),
        };

        let _ = derive_key_test(
            &facilities,
            &key_cache,
            &params,
            KeyOp::Encryption,
        )
        .unwrap();
    }
}

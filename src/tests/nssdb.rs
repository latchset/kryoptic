// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_nssdb_token() {
    let datadir = "testdata/nssdbdir";
    let destdir = format!("{}/test_nssdb", TESTDIR);

    let dbpath = format!("configDir={}", destdir);
    let dbtype = "nssdb";
    let dbname = format!("{}:{}", dbtype, dbpath);

    /* allocates a unique slotid to use in the tests */
    let mut testtokn = TestToken::new(dbname);

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
    let mut slot = config::Slot::with_db(dbtype, Some(dbpath.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);
    assert_eq!(ret, CKR_OK);

    let mut args = TestToken::make_init_args(Some(dbpath.clone()));
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

    /* find specific key object */
    static KEY1_MODULUS_HEX: &str =
        "d7c85f173b517e5c4dd970f372576b949868a195571cc9c8c30c4d82b08eea84\
         698abab36801e6c9b6d29556aa71e8e4976c5103389d94be85f2d0342d9c9402\
         0c2c8e1eec2709306e8678e2f832aff125622f124533a1c1cbba9334ca797309\
         8b84d33581b67e8250ddf56f9091f7d4b619f8ad6721f1c62413caf2e158c1cb\
         ba6c7c3c6ce4fc67cf1c867b16963e9a2f68830f664ee15a698f4b3d771f20ec\
         d35fc074fd35e0faf0ca1c88c232b69828656325fed888ac9ffbf57f2c7d9d86\
         cc47d33afdab34263384896a18eb2fbd61946480cf58748baa903f5147349cd3\
         1b757f9703e6c7c75599e1ca6b24cc50238b89baa3e02ea0604f4bc36d7ff37b";
    let key1_modulus = hex::decode(KEY1_MODULUS_HEX).unwrap();
    let key1_id: &[u8; 2] = b"\0\0";

    let mut pub_handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_RSA)],
        &[(CKA_ID, key1_id)],
        &[],
    );
    let ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut pub_handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(pub_handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* have to login here, private keys can be found only if logged in */
    testtokn.login();

    /* find one private key object */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC)],
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

    /* find one private key object */
    let mut handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC)],
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

    /* fetch public key RSA modulus */
    let mut template =
        make_ptrs_template(&[(CKA_MODULUS, std::ptr::null_mut(), 0)]);
    let ret = fn_get_attribute_value(
        session,
        pub_handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(template[0].ulValueLen as usize, key1_modulus.len());
    let mut value = vec![0u8; template[0].ulValueLen as usize];
    template[0].pValue = void_ptr!(value.as_mut_ptr());
    let ret = fn_get_attribute_value(
        session,
        pub_handle,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(value, key1_modulus);

    /* Find private key */
    let mut pri_handle: CK_ULONG = CK_INVALID_HANDLE;
    let mut template = make_attr_template(
        &[(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)],
        &[(CKA_ID, key1_id)],
        &[],
    );
    let ret = fn_find_objects_init(
        session,
        template.as_mut_ptr(),
        template.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);
    let mut count: CK_ULONG = 0;
    let ret = fn_find_objects(session, &mut pri_handle, 1, &mut count);
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    assert_ne!(pri_handle, CK_INVALID_HANDLE);
    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    /* Sign with RSA Key to verify key was properly decrypted */
    let data = "plaintext";
    let sig = ret_or_panic!(sig_gen(
        session,
        pri_handle,
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
            pub_handle,
            data.as_bytes(),
            sig.as_slice(),
            &CK_MECHANISM {
                mechanism: CKM_SHA256_RSA_PKCS,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        )
    );

    testtokn.logout();

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_nssdb_init_token() {
    let datadir = format!("{}/{}", TESTDIR, "test_nssdb_init_token");

    let dbpath = format!("configDir={}", datadir);
    let dbtype = "nssdb";
    let dbname = format!("{}:{}", dbtype, dbpath);

    let mut testtokn = TestToken::new(dbname);

    /* pre-populate conf so we get the correct slot number assigned */
    let mut slot = config::Slot::with_db(dbtype, Some(dbpath.clone()));
    slot.slot = u32::try_from(testtokn.get_slot()).unwrap();
    let ret = add_slot(slot);

    assert_eq!(ret, CKR_OK);
    let mut args = TestToken::make_init_args(Some(dbpath.clone()));
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

    testtokn.finalize();
}

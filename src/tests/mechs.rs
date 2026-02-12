// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use crate::tests::*;

use serial_test::parallel;

#[test]
#[parallel]
fn test_get_mechs() {
    let mut testtokn = TestToken::initialized("test_get_mechs", None);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(true, count > 4);
    #[cfg(feature = "no_sha1")]
    {
        let mut sha1_found = 0;
        let sha1_list = [
            CKM_SHA1_RSA_PKCS,
            CKM_SHA1_RSA_X9_31,
            CKM_SHA1_RSA_PKCS_PSS,
            CKM_DSA_SHA1,
            CKM_SHA_1,
            CKM_SHA_1_HMAC,
            CKM_SHA_1_HMAC_GENERAL,
            CKM_SSL3_SHA1_MAC,
            CKM_SHA1_KEY_DERIVATION,
            CKM_PBE_SHA1_CAST128_CBC,
            CKM_PBE_SHA1_RC4_128,
            CKM_PBE_SHA1_RC4_40,
            CKM_PBE_SHA1_DES3_EDE_CBC,
            CKM_PBE_SHA1_DES2_EDE_CBC,
            CKM_PBE_SHA1_RC2_128_CBC,
            CKM_PBE_SHA1_RC2_40_CBC,
            CKM_PBA_SHA1_WITH_SHA1_HMAC,
            CKM_ECDSA_SHA1,
            CKM_SHA_1_KEY_GEN,
            CKM_PBE_SHA1_CAST128_CBC,
        ];
        for mech in &mechs {
            if sha1_list.contains(mech) {
                sha1_found += 1;
            }
        }
        assert_eq!(sha1_found, 0);
    }
    let mut info: CK_MECHANISM_INFO = Default::default();
    let ret = fn_get_mechanism_info(testtokn.get_slot(), mechs[0], &mut info);
    assert_eq!(ret, CKR_OK);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_allow_mechs() {
    let dbname = String::from("test_allow_mechs");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);
    let confname = format!("{}/test_allow_mechs.conf", TESTDIR);
    testtokn.make_config_file(
        &confname,
        Some(vec![String::from("CKM_AES_KEY_GEN")]),
    );

    let mut args =
        TestToken::make_init_args(Some(format!("kryoptic_conf={}", confname)));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(count, 1);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(mechs[0], CKM_AES_KEY_GEN);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_deny_mechs() {
    let dbname = String::from("test_deny_mechs");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);
    let confname = format!("{}/test_deny_mechs.conf", TESTDIR);
    testtokn.make_config_file(
        &confname,
        Some(vec![String::from("DENY"), String::from("CKM_AES_KEY_GEN")]),
    );

    let mut args =
        TestToken::make_init_args(Some(format!("kryoptic_conf={}", confname)));
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);

    let mut count: CK_ULONG = 0;
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        std::ptr::null_mut(),
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    let mut mechs: Vec<CK_MECHANISM_TYPE> = vec![0; count as usize];
    let ret = fn_get_mechanism_list(
        testtokn.get_slot(),
        mechs.as_mut_ptr() as CK_MECHANISM_TYPE_PTR,
        &mut count,
    );
    assert_eq!(ret, CKR_OK);
    assert_eq!(mechs.contains(&CKM_AES_KEY_GEN), false);

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_mechanism_objects() {
    let mut testtokn = TestToken::initialized("test_mechanism_objects", None);
    let session = testtokn.get_session(true);

    let mut tmpl = make_attr_template(&[(CKA_CLASS, CKO_MECHANISM)], &[], &[]);

    let ret = fn_find_objects_init(
        session,
        tmpl.as_mut_ptr(),
        tmpl.len() as CK_ULONG,
    );
    assert_eq!(ret, CKR_OK);

    let mut handles = Vec::<CK_OBJECT_HANDLE>::with_capacity(64);
    let mut count = 64;
    while count == 64 {
        let mut ph = [CK_INVALID_HANDLE; 64];
        let ret = fn_find_objects(session, ph.as_mut_ptr(), 64, &mut count);
        assert_eq!(ret, CKR_OK);
        if count > 0 {
            handles.extend_from_slice(&ph[..count as usize]);
        }
    }

    let ret = fn_find_objects_final(session);
    assert_eq!(ret, CKR_OK);

    assert!(handles.len() > 0, "No mechanism objects found");

    for mech_type in [
        #[cfg(feature = "rsa")]
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        #[cfg(feature = "hash")]
        CKM_SHA256,
        CKM_GENERIC_SECRET_KEY_GEN,
    ] {
        let mut search_tmpl = make_attr_template(
            &[(CKA_CLASS, CKO_MECHANISM), (CKA_MECHANISM_TYPE, mech_type)],
            &[],
            &[],
        );

        let ret = fn_find_objects_init(
            session,
            search_tmpl.as_mut_ptr(),
            search_tmpl.len() as CK_ULONG,
        );
        assert_eq!(ret, CKR_OK);

        let mut found_handle = CK_INVALID_HANDLE;
        let mut found_count = 0;
        let ret =
            fn_find_objects(session, &mut found_handle, 1, &mut found_count);
        assert_eq!(ret, CKR_OK);
        assert_eq!(found_count, 1);

        let ret = fn_find_objects_final(session);
        assert_eq!(ret, CKR_OK);
    }

    testtokn.finalize();
}

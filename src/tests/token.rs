// Copyright 2024 Simo Sorce
// See LICENSE.txt file for terms

use std::env;
use std::fmt::Write as _;
use std::io::Write;

use crate::tests::*;

#[cfg(feature = "sqlitedb")]
use crate::storage::StorageDBInfo;
#[cfg(feature = "sqlitedb")]
use crate::Token;

use serial_test::{parallel, serial};

#[cfg(feature = "sqlitedb")]
fn test_token_setup(name: &str) -> TestToken<'_> {
    let mut testtokn = TestToken::new(String::from(name));
    testtokn.setup_db(None);
    testtokn
}

#[cfg(feature = "sqlitedb")]
fn test_token_env(suffix: &str) {
    let dbname = format!("test_token_env{}", suffix);
    let mut testtokn = test_token_setup(&dbname);
    let confname = format!("{}/test_token_env{}.conf", TESTDIR, suffix);
    testtokn.make_config_file(&confname, None, None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = fn_get_function_list(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = TestToken::make_init_args(None);
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::set_var("KRYOPTIC_CONF", confname);
                let ret = force_load_config();
                assert_eq!(ret, CKR_OK);
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                env::remove_var("KRYOPTIC_CONF");
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[cfg(feature = "sqlitedb")]
fn test_token_null_args(suffix: &str) {
    let dbname = format!("test_token_nullargs{}", suffix);
    let mut testtokn = test_token_setup(&dbname);
    let confname = format!("{}/test_token_nullargs{}.conf", TESTDIR, suffix);
    testtokn.make_config_file(&confname, None, None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = fn_get_function_list(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                env::set_var("KRYOPTIC_CONF", confname);
                let ret = force_load_config();
                assert_eq!(ret, CKR_OK);
                let ret = init_fn(std::ptr::null_mut());
                env::remove_var("KRYOPTIC_CONF");
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[serial]
fn test_token_datadir() {
    let basedir = format!("{}/datadirtest", TESTDIR);
    let confdir = format!("{}/kryoptic", basedir);
    let confname = format!("{}/{}", confdir, config::DEFAULT_CONF_NAME);
    let dbname = String::from("token");
    std::fs::create_dir_all(confdir).unwrap();

    let mut testtokn = TestToken::new(dbname);
    testtokn.make_config_file(&confname, None, None);
    testtokn.setup_db(None);

    let mut plist: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
    let pplist = &mut plist;
    let result = fn_get_function_list(&mut *pplist);
    assert_eq!(result, 0);
    unsafe {
        let list: CK_FUNCTION_LIST = *plist;
        match list.C_Initialize {
            Some(init_fn) => {
                let mut args = TestToken::make_init_args(None);
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                env::remove_var("KRYOPTIC_CONF");
                env::set_var("XDG_CONFIG_HOME", basedir);
                let ret = force_load_config();
                assert_eq!(ret, CKR_OK);
                let ret = init_fn(args_ptr as *mut std::ffi::c_void);
                env::remove_var("XDG_CONFIG_HOME");
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[cfg(feature = "sqlitedb")]
#[test]
#[serial]
fn test_token_sql() {
    test_token_env(".sql");
    test_token_null_args(".sql");
}

#[test]
#[parallel]
fn test_interface_null() {
    let dbname = String::from("test_interface_null");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);

    /* NULL interface name and NULL version -- the module should return default one */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let result = fn_get_interface(
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST_3_0 =
            *(iface.pFunctionList as CK_FUNCTION_LIST_3_0_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_pkcs11() {
    let dbname = String::from("test_interface_pkcs11");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);

    /* NULL version -- the module should return default one */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let result = fn_get_interface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        std::ptr::null_mut(),
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST_3_0 =
            *(iface.pFunctionList as CK_FUNCTION_LIST_3_0_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_pkcs11_version3() {
    let dbname = String::from("test_interface_pkcs11_version3");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);

    /* Get the specific version 3.0 */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let mut version = { CK_VERSION { major: 3, minor: 0 } };
    let result = fn_get_interface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        &mut version,
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST_3_0 =
            *(iface.pFunctionList as CK_FUNCTION_LIST_3_0_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_pkcs11_version240() {
    let dbname = String::from("test_interface_pkcs11_version240");
    let mut testtokn = TestToken::new(dbname);
    testtokn.setup_db(None);

    /* Get the specific version 2.40 */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let mut version = {
        CK_VERSION {
            major: 2,
            minor: 40,
        }
    };
    let result = fn_get_interface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        &mut version,
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_OK);
    unsafe {
        let iface: CK_INTERFACE = *piface;
        let list: CK_FUNCTION_LIST =
            *(iface.pFunctionList as CK_FUNCTION_LIST_PTR);
        match list.C_Initialize {
            Some(value) => {
                let mut args = TestToken::make_init_args(Some(
                    testtokn.make_init_string(),
                ));
                let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
                let ret = value(args_ptr as *mut std::ffi::c_void);
                assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);
            }
            None => todo!(),
        }
    }

    testtokn.finalize();
}

#[test]
#[parallel]
fn test_interface_invalid_name() {
    /* Try to get in valid name */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let result = fn_get_interface(
        "MyPKCS 12\0".as_ptr() as CK_UTF8CHAR_PTR,
        std::ptr::null_mut(),
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_ARGUMENTS_BAD);
}

#[test]
#[parallel]
fn test_interface_invalid_version() {
    /* Try to get in valid name */
    let mut piface: *mut CK_INTERFACE = std::ptr::null_mut();
    let ppiface = &mut piface;
    let mut version = {
        CK_VERSION {
            major: 2,
            minor: 99,
        }
    };
    let result = fn_get_interface(
        "PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
        &mut version,
        &mut *ppiface,
        0,
    );
    assert_eq!(result, CKR_ARGUMENTS_BAD);
}

/// Storage-persistence regression test: an RSA key pair generated by
/// whichever crypto backend is active must survive a real close (dropping
/// the `Token`) and reopen (`Token::new` against the same on-disk
/// database) cycle, not just live for the duration of the `Token`
/// instance that created it -- and the reloaded key must still be
/// cryptographically usable, not merely present as inert stored bytes.
///
/// Deliberately drives `crate::token::Token` directly (the same pattern
/// `test_every_advertised_mechanism_has_a_real_implementation` in
/// `src/tests/mechs.rs` uses) rather than the full `C_Initialize`/
/// `TestToken` harness: that harness's global, process-wide
/// `C_Initialize`/`C_Finalize` singleton (this module's `FINI`/`SYNC`/
/// `INIT` coordination, in `src/tests/mod.rs`) is designed for many tests
/// to *share* one module lifetime, not for a single test to close and
/// reopen it, and doing so races with concurrently-running tests in
/// practice. This logic is entirely backend-agnostic (it only calls
/// through `crate::token::Token` and the `Mechanism`/`Sign`/`Verify`
/// trait dispatch it exposes), so it belongs here rather than in any
/// single backend's own test module, and runs under both `ossl-backend`
/// and the AWS-LC backends' CI.
#[test]
#[serial]
#[cfg(feature = "sqlitedb")]
fn test_rsa_keypair_survives_token_close_and_reopen() {
    let dbtype = crate::storage::sqlite::DBINFO.dbtype();
    let dbargs =
        format!("{}/rsa_reload_test_{:x}.sql", TESTDIR, std::process::id());
    let _ = std::fs::remove_file(&dbargs);
    std::fs::create_dir_all(TESTDIR).unwrap();

    let so_pin = SO_PIN.as_bytes().to_vec();
    let user_pin = USER_PIN.as_bytes().to_vec();
    let mut label = b"RSA RELOAD TEST".to_vec();
    label.resize(32, 0x20);

    let ck_true: CK_BBOOL = CK_TRUE;
    let ck_false: CK_BBOOL = CK_FALSE;
    let bits: CK_ULONG = 2048;
    let pubkey_template = [
        make_attribute!(
            CKA_MODULUS_BITS,
            &bits as *const CK_ULONG,
            CK_ULONG_SIZE
        ),
        make_attribute!(CKA_VERIFY, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
    ];
    let prikey_template = [
        make_attribute!(CKA_SIGN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
        make_attribute!(
            CKA_SENSITIVE,
            &ck_false as *const CK_BBOOL,
            CK_BBOOL_SIZE
        ),
    ];
    let mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let expected_modulus: Vec<u8>;
    {
        let mut token =
            Token::new(dbtype, Some(dbargs.clone())).expect("Token::new");
        token.initialize(&so_pin, &label).expect("initialize");
        token.login(CKU_SO, &so_pin);
        token
            .set_pin(CKU_USER, &user_pin, &Vec::new())
            .expect("set_pin");
        token.logout();
        token.login(CKU_USER, &user_pin);

        let entry = token
            .get_mechanisms()
            .get(CKM_RSA_PKCS_KEY_PAIR_GEN)
            .unwrap();
        let (pubkey, privkey) = entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair");
        expected_modulus =
            pubkey.get_attr_as_bytes(CKA_MODULUS).unwrap().clone();

        token
            .insert_object(CK_INVALID_HANDLE, pubkey)
            .expect("insert pubkey");
        token
            .insert_object(CK_INVALID_HANDLE, privkey)
            .expect("insert privkey");
        /* `token` is dropped here, closing this phase's connection to
         * the on-disk database before it's reopened below. */
    }

    let mut token =
        Token::new(dbtype, Some(dbargs.clone())).expect("Token::new (reopen)");
    assert!(token.is_initialized());
    token.login(CKU_USER, &user_pin);

    let priv_handles = token
        .search_objects(&[make_attribute!(
            CKA_CLASS,
            &CKO_PRIVATE_KEY as *const CK_OBJECT_CLASS,
            CK_ULONG_SIZE
        )])
        .expect("search private key");
    assert_eq!(
        priv_handles.len(),
        1,
        "private key did not survive the reload"
    );
    let privkey = token
        .get_object_by_handle(priv_handles[0])
        .expect("fetch reloaded privkey");

    let pub_handles = token
        .search_objects(&[make_attribute!(
            CKA_CLASS,
            &CKO_PUBLIC_KEY as *const CK_OBJECT_CLASS,
            CK_ULONG_SIZE
        )])
        .expect("search public key");
    assert_eq!(
        pub_handles.len(),
        1,
        "public key did not survive the reload"
    );
    let pubkey = token
        .get_object_by_handle(pub_handles[0])
        .expect("fetch reloaded pubkey");
    assert_eq!(
        pubkey.get_attr_as_bytes(CKA_MODULUS).unwrap(),
        &expected_modulus
    );

    /* The reloaded key pair must still be fully usable, not just present
     * as inert stored bytes. */
    let sign_mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let sign_entry = token.get_mechanisms().get(CKM_RSA_PKCS).unwrap();
    let digest = [0x24u8; 32];
    let mut sig_op = sign_entry
        .sign_new(&sign_mech, &privkey)
        .expect("sign_new on reloaded key");
    let mut signature = vec![0u8; 256];
    sig_op
        .sign(&digest, &mut signature)
        .expect("sign on reloaded key");

    let mut verify_op = sign_entry
        .verify_new(&sign_mech, &pubkey)
        .expect("verify_new on reloaded key");
    verify_op.verify(&digest, &signature).expect("verify");

    drop(token);
    let _ = std::fs::remove_file(&dbargs);
}

/// Storage-persistence regression test for ML-KEM's seed-based private-key
/// encoding: `crate::awslc::mlkem::generate_keypair` (see
/// `src/awslc/mlkem.rs`) stores *both* `CKA_VALUE` (the full expanded
/// decapsulation key) and `CKA_SEED` (the 64-byte `d‖z` seed it was
/// derived from) on the private key object -- a shape the plain RSA
/// persistence test above can't exercise at all (RSA has no seed
/// encoding). Both attributes must survive a close/reopen cycle
/// byte-for-byte, and the reloaded private key must still decapsulate a
/// ciphertext produced against the reloaded public key. See
/// `test_rsa_keypair_survives_token_close_and_reopen` above for why this
/// drives `crate::token::Token` directly rather than the `TestToken`/
/// `C_Initialize` harness.
#[test]
#[serial]
#[cfg(all(feature = "sqlitedb", feature = "mlkem"))]
fn test_mlkem_keypair_survives_token_close_and_reopen() {
    let dbtype = crate::storage::sqlite::DBINFO.dbtype();
    let dbargs =
        format!("{}/mlkem_reload_test_{:x}.sql", TESTDIR, std::process::id());
    let _ = std::fs::remove_file(&dbargs);
    std::fs::create_dir_all(TESTDIR).unwrap();

    let so_pin = SO_PIN.as_bytes().to_vec();
    let user_pin = USER_PIN.as_bytes().to_vec();
    let mut label = b"MLKEM RELOAD TEST".to_vec();
    label.resize(32, 0x20);

    let ck_true: CK_BBOOL = CK_TRUE;
    let paramset: CK_ML_KEM_PARAMETER_SET_TYPE = CKP_ML_KEM_768;
    let pubkey_template = [
        make_attribute!(
            CKA_PARAMETER_SET,
            &paramset as *const CK_ML_KEM_PARAMETER_SET_TYPE,
            CK_ULONG_SIZE
        ),
        make_attribute!(
            CKA_ENCAPSULATE,
            &ck_true as *const CK_BBOOL,
            CK_BBOOL_SIZE
        ),
        make_attribute!(CKA_TOKEN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
    ];
    let prikey_template = [
        make_attribute!(
            CKA_DECAPSULATE,
            &ck_true as *const CK_BBOOL,
            CK_BBOOL_SIZE
        ),
        make_attribute!(CKA_TOKEN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
    ];
    let mech = CK_MECHANISM {
        mechanism: CKM_ML_KEM_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let key_type: CK_ULONG = CKK_GENERIC_SECRET;
    let secret_template = [
        make_attribute!(
            CKA_CLASS,
            &CKO_SECRET_KEY as *const CK_OBJECT_CLASS,
            CK_ULONG_SIZE
        ),
        make_attribute!(
            CKA_KEY_TYPE,
            &key_type as *const CK_ULONG,
            CK_ULONG_SIZE
        ),
        make_attribute!(
            CKA_SENSITIVE,
            &CK_FALSE as *const CK_BBOOL,
            CK_BBOOL_SIZE
        ),
        make_attribute!(
            CKA_EXTRACTABLE,
            &ck_true as *const CK_BBOOL,
            CK_BBOOL_SIZE
        ),
    ];

    let expected_pub_value: Vec<u8>;
    let expected_priv_value: Vec<u8>;
    let expected_seed: Vec<u8>;
    {
        let mut token =
            Token::new(dbtype, Some(dbargs.clone())).expect("Token::new");
        token.initialize(&so_pin, &label).expect("initialize");
        token.login(CKU_SO, &so_pin);
        token
            .set_pin(CKU_USER, &user_pin, &Vec::new())
            .expect("set_pin");
        token.logout();
        token.login(CKU_USER, &user_pin);

        let entry =
            token.get_mechanisms().get(CKM_ML_KEM_KEY_PAIR_GEN).unwrap();
        let (pubkey, privkey) = entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair");
        expected_pub_value =
            pubkey.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        expected_priv_value =
            privkey.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        expected_seed = privkey.get_attr_as_bytes(CKA_SEED).unwrap().clone();

        token
            .insert_object(CK_INVALID_HANDLE, pubkey)
            .expect("insert pubkey");
        token
            .insert_object(CK_INVALID_HANDLE, privkey)
            .expect("insert privkey");
        /* `token` is dropped here, closing this phase's connection to
         * the on-disk database before it's reopened below. */
    }

    let mut token =
        Token::new(dbtype, Some(dbargs.clone())).expect("Token::new (reopen)");
    assert!(token.is_initialized());
    token.login(CKU_USER, &user_pin);

    let priv_handles = token
        .search_objects(&[
            make_attribute!(
                CKA_CLASS,
                &CKO_PRIVATE_KEY as *const CK_OBJECT_CLASS,
                CK_ULONG_SIZE
            ),
            make_attribute!(
                CKA_KEY_TYPE,
                &CKK_ML_KEM as *const CK_KEY_TYPE,
                CK_ULONG_SIZE
            ),
        ])
        .expect("search private key");
    assert_eq!(
        priv_handles.len(),
        1,
        "private key did not survive the reload"
    );
    let privkey = token
        .get_object_by_handle(priv_handles[0])
        .expect("fetch reloaded privkey");
    assert_eq!(
        privkey.get_attr_as_bytes(CKA_VALUE).unwrap(),
        &expected_priv_value
    );
    assert_eq!(
        privkey.get_attr_as_bytes(CKA_SEED).unwrap(),
        &expected_seed,
        "CKA_SEED did not survive the reload byte-for-byte"
    );

    let pub_handles = token
        .search_objects(&[
            make_attribute!(
                CKA_CLASS,
                &CKO_PUBLIC_KEY as *const CK_OBJECT_CLASS,
                CK_ULONG_SIZE
            ),
            make_attribute!(
                CKA_KEY_TYPE,
                &CKK_ML_KEM as *const CK_KEY_TYPE,
                CK_ULONG_SIZE
            ),
        ])
        .expect("search public key");
    assert_eq!(
        pub_handles.len(),
        1,
        "public key did not survive the reload"
    );
    let pubkey = token
        .get_object_by_handle(pub_handles[0])
        .expect("fetch reloaded pubkey");
    assert_eq!(
        pubkey.get_attr_as_bytes(CKA_VALUE).unwrap(),
        &expected_pub_value
    );

    /* The reloaded key pair must still be fully usable, not just present
     * as inert stored bytes. */
    let factory = token
        .get_object_factories()
        .get_obj_factory_from_key_template(&secret_template)
        .expect("generic-secret factory must be registered");
    let no_param_mech = CK_MECHANISM {
        mechanism: CKM_ML_KEM,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mech_entry = token.get_mechanisms().get(CKM_ML_KEM).unwrap();
    let ct_len = mech_entry.encapsulate_ciphertext_len(&pubkey).unwrap();
    let mut ciphertext = vec![0u8; ct_len];
    let (enc_obj, outlen) = mech_entry
        .encapsulate(
            &no_param_mech,
            &pubkey,
            &factory,
            &secret_template,
            &mut ciphertext,
        )
        .expect("encapsulate on reloaded key");
    assert_eq!(outlen, ct_len);

    let dec_obj = mech_entry
        .decapsulate(
            &no_param_mech,
            &privkey,
            &factory,
            &secret_template,
            &ciphertext,
        )
        .expect("decapsulate on reloaded key");
    assert_eq!(
        enc_obj.get_attr_as_bytes(CKA_VALUE).unwrap(),
        dec_obj.get_attr_as_bytes(CKA_VALUE).unwrap()
    );

    drop(token);
    let _ = std::fs::remove_file(&dbargs);
}

/// Storage-persistence regression test for ML-DSA's seed-based private-key
/// encoding, mirroring `test_mlkem_keypair_survives_token_close_and_reopen`
/// above: `crate::awslc::mldsa::generate_keypair` (see
/// `src/awslc/mldsa.rs`) stores both `CKA_VALUE` and `CKA_SEED` on the
/// private key, and both must survive a close/reopen cycle, with the
/// reloaded key pair still able to sign/verify. Excluded under
/// `awslc-fips` for the same reason `src/enabled.rs` excludes the whole
/// `mldsa` module there: AWS-LC-FIPS's validated boundary doesn't publicly
/// confirm ML-DSA support as of this writing.
#[test]
#[serial]
#[cfg(all(
    feature = "sqlitedb",
    feature = "mldsa",
    not(feature = "awslc-fips")
))]
fn test_mldsa_keypair_survives_token_close_and_reopen() {
    let dbtype = crate::storage::sqlite::DBINFO.dbtype();
    let dbargs =
        format!("{}/mldsa_reload_test_{:x}.sql", TESTDIR, std::process::id());
    let _ = std::fs::remove_file(&dbargs);
    std::fs::create_dir_all(TESTDIR).unwrap();

    let so_pin = SO_PIN.as_bytes().to_vec();
    let user_pin = USER_PIN.as_bytes().to_vec();
    let mut label = b"MLDSA RELOAD TEST".to_vec();
    label.resize(32, 0x20);

    let ck_true: CK_BBOOL = CK_TRUE;
    let paramset: CK_ML_DSA_PARAMETER_SET_TYPE = CKP_ML_DSA_65;
    let pubkey_template = [
        make_attribute!(
            CKA_PARAMETER_SET,
            &paramset as *const CK_ML_DSA_PARAMETER_SET_TYPE,
            CK_ULONG_SIZE
        ),
        make_attribute!(CKA_VERIFY, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
    ];
    let prikey_template = [
        make_attribute!(CKA_SIGN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
        make_attribute!(CKA_TOKEN, &ck_true as *const CK_BBOOL, CK_BBOOL_SIZE),
    ];
    let mech = CK_MECHANISM {
        mechanism: CKM_ML_DSA_KEY_PAIR_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    let expected_pub_value: Vec<u8>;
    let expected_priv_value: Vec<u8>;
    let expected_seed: Vec<u8>;
    {
        let mut token =
            Token::new(dbtype, Some(dbargs.clone())).expect("Token::new");
        token.initialize(&so_pin, &label).expect("initialize");
        token.login(CKU_SO, &so_pin);
        token
            .set_pin(CKU_USER, &user_pin, &Vec::new())
            .expect("set_pin");
        token.logout();
        token.login(CKU_USER, &user_pin);

        let entry =
            token.get_mechanisms().get(CKM_ML_DSA_KEY_PAIR_GEN).unwrap();
        let (pubkey, privkey) = entry
            .generate_keypair(&mech, &pubkey_template, &prikey_template)
            .expect("generate_keypair");
        expected_pub_value =
            pubkey.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        expected_priv_value =
            privkey.get_attr_as_bytes(CKA_VALUE).unwrap().clone();
        expected_seed = privkey.get_attr_as_bytes(CKA_SEED).unwrap().clone();

        token
            .insert_object(CK_INVALID_HANDLE, pubkey)
            .expect("insert pubkey");
        token
            .insert_object(CK_INVALID_HANDLE, privkey)
            .expect("insert privkey");
        /* `token` is dropped here, closing this phase's connection to
         * the on-disk database before it's reopened below. */
    }

    let mut token =
        Token::new(dbtype, Some(dbargs.clone())).expect("Token::new (reopen)");
    assert!(token.is_initialized());
    token.login(CKU_USER, &user_pin);

    let priv_handles = token
        .search_objects(&[
            make_attribute!(
                CKA_CLASS,
                &CKO_PRIVATE_KEY as *const CK_OBJECT_CLASS,
                CK_ULONG_SIZE
            ),
            make_attribute!(
                CKA_KEY_TYPE,
                &CKK_ML_DSA as *const CK_KEY_TYPE,
                CK_ULONG_SIZE
            ),
        ])
        .expect("search private key");
    assert_eq!(
        priv_handles.len(),
        1,
        "private key did not survive the reload"
    );
    let privkey = token
        .get_object_by_handle(priv_handles[0])
        .expect("fetch reloaded privkey");
    assert_eq!(
        privkey.get_attr_as_bytes(CKA_VALUE).unwrap(),
        &expected_priv_value
    );
    assert_eq!(
        privkey.get_attr_as_bytes(CKA_SEED).unwrap(),
        &expected_seed,
        "CKA_SEED did not survive the reload byte-for-byte"
    );

    let pub_handles = token
        .search_objects(&[
            make_attribute!(
                CKA_CLASS,
                &CKO_PUBLIC_KEY as *const CK_OBJECT_CLASS,
                CK_ULONG_SIZE
            ),
            make_attribute!(
                CKA_KEY_TYPE,
                &CKK_ML_DSA as *const CK_KEY_TYPE,
                CK_ULONG_SIZE
            ),
        ])
        .expect("search public key");
    assert_eq!(
        pub_handles.len(),
        1,
        "public key did not survive the reload"
    );
    let pubkey = token
        .get_object_by_handle(pub_handles[0])
        .expect("fetch reloaded pubkey");
    assert_eq!(
        pubkey.get_attr_as_bytes(CKA_VALUE).unwrap(),
        &expected_pub_value
    );

    /* The reloaded key pair must still be fully usable, not just present
     * as inert stored bytes. */
    let sign_mech = CK_MECHANISM {
        mechanism: CKM_ML_DSA,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let sign_entry = token.get_mechanisms().get(CKM_ML_DSA).unwrap();
    let msg = b"reloaded key round trip message";
    let mut sign_op = sign_entry
        .sign_new(&sign_mech, &privkey)
        .expect("sign_new on reloaded key");
    let siglen = sign_op.signature_len().unwrap();
    let mut signature = vec![0u8; siglen];
    sign_op
        .sign(msg, &mut signature)
        .expect("sign on reloaded key");

    let mut verify_op = sign_entry
        .verify_new(&sign_mech, &pubkey)
        .expect("verify_new on reloaded key");
    verify_op.verify(msg, &signature).expect("verify");

    drop(token);
    let _ = std::fs::remove_file(&dbargs);
}

#[test]
#[serial]
#[cfg(any(feature = "sqlitedb", feature = "nssdb"))]
fn test_config_multiple_tokens() {
    let name = String::from("test_config_multiple");
    let confname = format!("{}/{}.conf", TESTDIR, name);
    let dbs = [
        #[cfg(feature = "sqlitedb")]
        (
            "sqlite",
            format!("{}/{}.sql", TESTDIR, name),
            "TOKEN SQLITEDB",
        ),
        #[cfg(feature = "nssdb")]
        (
            "nssdb",
            format!("configDir={}/{}", TESTDIR, name),
            "TOKEN NSSDB",
        ),
    ];
    let mut config = String::new();
    let mut tokens = Vec::<TestToken>::new();
    for db in &dbs {
        let mut token =
            TestToken::new_type(String::from(db.0), db.1.clone(), name.clone());
        token.setup_db(None);
        /* here we hand code a config file.
         * to ensure changes in the toml crate do not break the format */
        write!(
            &mut config,
            "[[slots]]\nslot = {}\ndbtype = \"{}\"\ndbargs = \"{}\"\ndescription = \"{}\"\n",
            token.get_slot(),
            db.0,
            db.1,
            db.2
        )
        .unwrap();
        tokens.push(token);
    }

    /* write out the config */
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&confname)
        .unwrap();
    file.write(config.as_bytes()).unwrap();

    /* try to init this token now */
    let mut args = TestToken::make_init_args(None);
    let args_ptr = &mut args as *mut CK_C_INITIALIZE_ARGS;
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { env::set_var("KRYOPTIC_CONF", confname) };
    let ret = force_load_config();
    assert_eq!(ret, CKR_OK);
    let ret = fn_initialize(args_ptr as *mut std::ffi::c_void);
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { env::remove_var("KRYOPTIC_CONF") };
    assert_in!(ret, [CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED]);

    /* check slots and tokens */
    for tok in &tokens {
        let mut info = CK_SLOT_INFO::default();
        let ret =
            fn_get_slot_info(tok.get_slot(), &mut info as CK_SLOT_INFO_PTR);
        assert_eq!(ret, CKR_OK);
        let desc = std::str::from_utf8(&info.slotDescription).unwrap();
        assert_eq!(desc.starts_with("TOKEN "), true);
    }
}
